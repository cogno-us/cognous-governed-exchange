"""Hardening from the 2026-10 security review (neutral): per-message processing lease, insert-once checkpoint and workflow
writes, strict source verification beyond ``git status``, and bounded rejection acknowledgements.

What this proves: the lease and the insert-once rules at the store, the refusal of index flags and content that differs from
the revision's blob, and that a rejection acknowledgement stores bounded values. What it does not prove: end-to-end
exactly-once dispatch across processes (the destination's effect dedupe remains the final guard).
"""
from __future__ import annotations

import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

import pytest

from experiments.governed_message_transport.transport import (
    ACK_KIND_TERMINAL_REJECTION,
    MAX_ACK_FIELD_CHARS,
    MAX_ACK_REASON_CHARS,
)
from experiments.odex_gax_imx_reference import gax_ref_runtime as runtime
from experiments.odex_gax_imx_reference.gax_ref_runtime import TransactionalExchangeStore

from test_exchange_input_and_source_repairs import _git, _planted, fake_checkouts  # noqa: F401
from test_governed_message_transport import DurableFixtureHandler, message, queue, route_table, transport, make_transport_envelope, NOW


def msg(i="m1", digest="d1"):
    return {"message_id": i, "message_digest": digest, "conversation_id": "c"}


# ---------------------------------------------------------------- processing lease
def test_second_holder_for_the_same_message_gets_a_hold(tmp_path):
    store = TransactionalExchangeStore(tmp_path / "s.sqlite")
    assert store.claim_effect(msg(), "e", "holder-a") is None
    assert store.claim_effect(msg(), "e", "holder-b") == store.LEASE_HELD


def test_same_holder_may_claim_again_and_release_frees_the_lease(tmp_path):
    store = TransactionalExchangeStore(tmp_path / "s.sqlite")
    assert store.claim_effect(msg(), "e", "a") is None
    assert store.claim_effect(msg(), "e", "a") is None
    store.release_lease(msg(), "b")  # another holder's release changes nothing
    assert store.claim_effect(msg(), "e", "b") == store.LEASE_HELD
    store.release_lease(msg(), "a")
    assert store.claim_effect(msg(), "e", "b") is None


def test_lease_is_taken_in_one_transaction_so_concurrent_holders_get_exactly_one_winner(tmp_path):
    path = tmp_path / "s.sqlite"
    TransactionalExchangeStore(path)
    def attempt(n):
        return TransactionalExchangeStore(path).claim_effect(msg(), "e", f"holder-{n}")
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(attempt, range(8)))
    assert results.count(None) == 1
    assert results.count(TransactionalExchangeStore.LEASE_HELD) == 7


def test_lease_does_not_hide_an_effect_owned_by_another_message(tmp_path):
    store = TransactionalExchangeStore(tmp_path / "s.sqlite")
    assert store.claim_effect(msg("m1", "d1"), "e", "a") is None
    assert store.claim_effect(msg("m2", "d2"), "e", "b") == "m1"
    # the refused message took no lease
    with sqlite3.connect(tmp_path / "s.sqlite") as con:
        assert con.execute("SELECT count(*) FROM message_leases WHERE message_id='m2'").fetchone()[0] == 0


def test_claim_without_holder_keeps_the_effect_ownership_behaviour(tmp_path):
    store = TransactionalExchangeStore(tmp_path / "s.sqlite")
    assert store.claim_effect(msg(), "e") is None
    assert store.claim_effect(msg(), "e", "a") is None  # no lease existed to conflict with


def test_a_lease_hold_is_reported_as_a_hold_without_dispatch():
    class Decision:
        effect_id = "e"
    out = runtime._finish_exchange(msg(), {"errors": []}, None, "h", lambda: {"status": "hold", "fault": "message_processing_lease_held", "decision": Decision()})
    assert out["execution"]["attempted"] is False and out["execution"]["attempt_status"] == "hold"
    assert out["execution"]["reason"] == "message_processing_lease_held"


# ---------------------------------------------------------------- insert-once checkpoint and workflow
def _artifacts(status="bound", result=None, cp="cp-1"):
    out = {"status": status, "proposal_record": {"p": 1}, "decision": {"decision_id": "d", "effect_id": "e", "result": "authorized"},
           "request": {"operation": {"proposal_commitment": "pc"}}, "cp_record": {"v": cp}}
    if result is not None:
        out["result"] = result
    return out


RESULT = {"status": "executed", "decision_id": "d", "effect_id": "e", "attempt_id": "a"}


@pytest.fixture
def store(tmp_path):
    s = TransactionalExchangeStore(tmp_path / "s.sqlite")
    s.record_message(msg())
    return s


def _checkpoint(store):
    with sqlite3.connect(store.path) as con:
        return con.execute("SELECT state,cp_record_json,result_json FROM dispatch_checkpoints WHERE message_id='m1'").fetchone()


def test_checkpoint_advances_from_bound_to_dispatched_once(store):
    store.record_dispatch_checkpoint(msg(), _artifacts())
    store.record_dispatch_checkpoint(msg(), _artifacts("executed", RESULT, cp="cp-2"))
    state, cp, result = _checkpoint(store)
    assert state == "dispatched" and '"cp-2"' in cp and result is not None


def test_a_repeated_bound_write_keeps_the_first(store):
    store.record_dispatch_checkpoint(msg(), _artifacts(cp="first"))
    store.record_dispatch_checkpoint(msg(), _artifacts(cp="second"))
    assert '"first"' in _checkpoint(store)[1]


def test_a_dispatched_checkpoint_cannot_be_replaced_or_moved_back(store):
    store.record_dispatch_checkpoint(msg(), _artifacts())
    store.record_dispatch_checkpoint(msg(), _artifacts("executed", RESULT))
    with pytest.raises(RuntimeError, match="cannot be replaced"):
        store.record_dispatch_checkpoint(msg(), _artifacts("executed", dict(RESULT, attempt_id="other")))
    with pytest.raises(RuntimeError, match="cannot be replaced"):
        store.record_dispatch_checkpoint(msg(), _artifacts())
    store.record_dispatch_checkpoint(msg(), _artifacts("executed", RESULT))  # the identical record is accepted
    assert _checkpoint(store)[0] == "dispatched"


EXPORT = {"export_profile": "p", "export_version": "1", "state": "original_complete"}


def _workflow_artifacts(status="executed", export=EXPORT):
    out = _artifacts(status, RESULT)
    out["artifact_export"] = dict(export)
    return out


@pytest.fixture
def workflow_store(store, monkeypatch):
    monkeypatch.setattr(runtime, "_validate_retained_artifact_export", lambda value: None)
    return store


def test_workflow_is_written_once_and_identical_repeats_are_accepted(workflow_store):
    workflow_store.record_workflow(msg(), _workflow_artifacts())
    workflow_store.record_workflow(msg(), _workflow_artifacts())
    with sqlite3.connect(workflow_store.path) as con:
        assert con.execute("SELECT count(*) FROM message_workflows").fetchone()[0] == 1
        assert con.execute("SELECT count(*) FROM artifact_exports").fetchone()[0] == 1


def test_a_different_workflow_or_export_for_the_same_message_is_refused_and_the_first_stands(workflow_store):
    workflow_store.record_workflow(msg(), _workflow_artifacts())
    with pytest.raises(RuntimeError, match="cannot be replaced"):
        workflow_store.record_workflow(msg(), _workflow_artifacts(status="reconciled"))
    with pytest.raises(RuntimeError, match="cannot be replaced"):
        workflow_store.record_workflow(msg(), _workflow_artifacts(export=dict(EXPORT, state="regenerated_derivative")))
    with sqlite3.connect(workflow_store.path) as con:
        assert con.execute("SELECT status FROM message_workflows").fetchone()[0] == "executed"
        assert con.execute("SELECT state FROM artifact_exports").fetchone()[0] == "original_complete"


def test_no_insert_or_replace_remains_for_checkpoints_workflows_or_recipient_results():
    import inspect
    from experiments.governed_message_transport import transport as t
    text = inspect.getsource(t) + inspect.getsource(runtime)
    for table in ("recipient_results", "dispatch_checkpoints", "message_workflows", "artifact_exports"):
        assert f"INSERT OR REPLACE INTO {table}" not in text


def test_recipient_outcome_is_recorded_once_and_a_different_one_is_refused(tmp_path):
    from experiments.governed_message_transport import RecipientOutcome
    handler = DurableFixtureHandler(tmp_path / "effects.sqlite")
    t = transport(tmp_path, handler)
    item = message()
    queue(t, item)
    t.deliver(item["message_id"], now=NOW)
    first = t.recipient_store.prior_outcome(item["message_id"])
    assert first is not None
    same = RecipientOutcome(assessment=first.assessment, execution=first.execution, producer_refs=first.producer_refs,
                            result_state=first.result_state, artifact_export=first.artifact_export)
    t.recipient_store.record_recipient_outcome(item["message_id"], same)
    changed = RecipientOutcome(assessment=first.assessment, execution={"attempted": False, "reason": "other"},
                               producer_refs=first.producer_refs, result_state=first.result_state, artifact_export=first.artifact_export)
    with pytest.raises(ValueError, match="cannot be replaced"):
        t.recipient_store.record_recipient_outcome(item["message_id"], changed)
    assert t.recipient_store.prior_outcome(item["message_id"]).execution == first.execution


# ---------------------------------------------------------------- strict source verification
def test_assume_unchanged_modification_is_refused_before_it_executes(fake_checkouts):  # noqa: F811
    roots, marker = fake_checkouts
    target = "src/agent_replay_bundle/importers.py"
    _git(roots["replay"], "update-index", "--assume-unchanged", target)
    (roots["replay"] / target).write_text(_planted(marker))
    assert _git(roots["replay"], "status", "--porcelain", "--untracked-files=no") == ""  # git status is blind to it
    with pytest.raises(RuntimeError, match="candidate source identity mismatch: agent_replay_bundle.importers"):
        runtime.load_executor_runtime()
    assert not marker.exists()
    assert "agent_replay_bundle.importers" not in sys.modules


def test_skip_worktree_modification_is_refused_before_it_executes(fake_checkouts):  # noqa: F811
    roots, marker = fake_checkouts
    target = "src/odes/exporter.py"
    _git(roots["odes"], "update-index", "--skip-worktree", target)
    (roots["odes"] / target).write_text(_planted(marker))
    with pytest.raises(RuntimeError, match="candidate source identity mismatch: odes.exporter"):
        runtime.load_executor_runtime()
    assert not marker.exists()


def test_assume_unchanged_flag_alone_is_refused_even_without_a_modification(fake_checkouts):  # noqa: F811
    roots, marker = fake_checkouts
    _git(roots["pack"], "update-index", "--assume-unchanged", "src/agent_governance_evidence_pack/importer.py")
    with pytest.raises(RuntimeError, match="candidate source identity mismatch"):
        runtime.load_executor_runtime()


def test_content_differing_from_the_head_blob_is_reported_by_the_hash_comparison(fake_checkouts):  # noqa: F811
    roots, marker = fake_checkouts
    path = roots["replay"] / "src/agent_replay_bundle/importers.py"
    assert runtime._executed_file_problems([path]) == []
    path.write_text(_planted(marker))
    assert runtime._executed_file_problems([path]) == ["content differs from the revision: src/agent_replay_bundle/importers.py"]


def test_change_between_verification_and_import_is_refused(fake_checkouts, monkeypatch):  # noqa: F811
    roots, marker = fake_checkouts
    path = roots["replay"] / "src/agent_replay_bundle/importers.py"
    original = runtime._locate_without_import
    state = {"calls": 0}

    def locate(name, expected):
        out = original(name, expected)
        if name == "agent_replay_bundle.importers":
            state["calls"] += 1
            if state["calls"] == 2:  # after the first verification pass, before the import
                path.write_text(_planted(marker))
        return out

    monkeypatch.setattr(runtime, "_locate_without_import", locate)
    with pytest.raises(RuntimeError, match="candidate source identity mismatch: agent_replay_bundle.importers"):
        runtime.load_executor_runtime()
    assert not marker.exists()


# ---------------------------------------------------------------- bounded rejection acknowledgements
def _envelope(**override):
    item = message()
    env = make_transport_envelope(governed_message=item, route=route_table().resolve("local-a-b"),
                                  delivery_attempt_id="external-1", correlation_id="c", created_at=NOW)
    env.update(override)
    return env


@pytest.mark.parametrize("field", ["message_id", "delivery_attempt_id", "content_commitment", "recipient_endpoint_ref"])
def test_oversized_envelope_identifiers_are_stored_as_bounded_markers(tmp_path, field):
    t = transport(tmp_path, DurableFixtureHandler(tmp_path / "effects.sqlite"))
    ack = t.receive_envelope(_envelope(transport_version="x", **{field: "A" * 1_000_000}), now=NOW)
    assert ack["acknowledgement_kind"] == ACK_KIND_TERMINAL_REJECTION
    assert ack[field].startswith("unbounded:str:sha256:") and len(ack[field]) < 100
    with sqlite3.connect(tmp_path / "recipient.sqlite") as con:
        size = con.execute("SELECT sum(length(message_id)+length(attempt_id)+length(content_commitment)+length(recipient_endpoint_ref)+length(detail_json)) FROM acknowledgements").fetchone()[0]
    assert size < 2000


def test_non_string_envelope_values_and_long_reasons_are_bounded(tmp_path):
    t = transport(tmp_path, DurableFixtureHandler(tmp_path / "effects.sqlite"))
    ack = t.receive_envelope(_envelope(transport_version="x", message_id={"a": ["b"] * 10_000}), now=NOW)
    assert ack["message_id"].startswith("unbounded:dict:sha256:")
    long_reason = t._recipient_reject(_envelope(), now=NOW, reason="r" * 100_000)
    assert len(long_reason["detail"]["reason"]) < MAX_ACK_REASON_CHARS + 60
    assert long_reason["detail"]["reason"].endswith("characters]")


def test_ordinary_identifiers_are_stored_unchanged(tmp_path):
    t = transport(tmp_path, DurableFixtureHandler(tmp_path / "effects.sqlite"))
    ack = t.receive_envelope(_envelope(transport_version="x"), now=NOW)
    assert ack["message_id"] == "msg-1" and len(ack["delivery_attempt_id"]) <= MAX_ACK_FIELD_CHARS
