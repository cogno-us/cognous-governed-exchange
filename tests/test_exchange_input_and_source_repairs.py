"""Component-local regressions for F5b exchange repairs.

These run without sibling component checkouts: dependency packages are tiny
throwaway Git repositories and the proposal model is stubbed where a test only
needs the assessment stages before Control Plane evaluation.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from experiments.odex_gax_imx_reference import gax_ref as base
from experiments.odex_gax_imx_reference import gax_ref_runtime as runtime


EVAL = "2026-08-08T01:00:00Z"
PROPOSAL = {
    "action_id": "refund_issue_routine", "target": "urn:t", "payload": {"x": 1},
    "amount": 1.0, "unit": "USD", "actor": "urn:a", "principal": "urn:p",
    "adapter_id": "adapter", "requested_permissions": ["refund.issue.routine"],
    "authority_context_ref": base.PROFILE_AUTH_CONTEXT,
}


class _Proposal:
    def model_dump(self, **_):
        return dict(PROPOSAL)


@pytest.fixture
def stub_proposal(monkeypatch):
    monkeypatch.setattr(base, "runtime_proposal_model", lambda bundle: _Proposal())
    monkeypatch.setattr(base, "proposal_commitment", lambda proposal=None, *, model=None: "sha256:" + "2" * 64)
    monkeypatch.setattr(base, "operation_commitment", lambda proposal=None, *, model=None: "sha256:" + "1" * 64)


def governed(message_id: str, *, sender: str = "refund-sender", note: str = "n") -> dict:
    content = {"summary": "synthetic", "note": note}
    msg = {
        "message_id": message_id, "conversation_id": "conv-refund-001",
        "profile": base.PROFILE, "protocol_version": base.PROTOCOL_VERSION,
        "message_type": "PROPOSE", "created_at": "2026-08-08T00:00:00Z",
        "expires_at": "2026-08-09T00:00:00Z", "sender": sender,
        "recipient": "refund-recipient", "purpose": "refund_execution_assessment",
        "requested_action": {k: v for k, v in PROPOSAL.items() if k != "authority_context_ref"},
        "operation_commitment": "sha256:" + "1" * 64,
        "proposal_commitment": "sha256:" + "2" * 64,
        "authority_refs": [{"type": "authority_context", "ref": base.PROFILE_AUTH_CONTEXT}],
        "evidence_refs": [], "content": content, "content_digest": base.digest(content),
        "acknowledgement_requested": True,
    }
    msg["message_digest"] = base.digest({k: v for k, v in msg.items() if k != "message_digest"})
    return msg


def registry():
    return base.LocalRegistry({"refund-sender"}, {"refund-recipient"}, "refund-recipient")


def exchange(msg, store_path):
    return runtime.run_exchange(msg, {}, registry(), None, evaluation_time=EVAL,
                                manifest={}, store_path=store_path)


# csf_77af39dec07a3500c0e2930c -------------------------------------------------

@pytest.mark.parametrize("message_id", [
    "../escape", "a/../../escape", "nested/escape", "back\\slash", "nul\x00byte",
    ".hidden", "a..b", "", "/abs",
])
def test_unsafe_message_id_is_not_understood_and_creates_no_file(tmp_path, message_id):
    root = tmp_path / "root"
    store_path = root / "exchange" / "exchange.sqlite"
    msg = governed(message_id)
    assessment = base.assess_message(msg, {}, registry(), evaluation_time=EVAL)
    assert assessment["permitted_handling"] == "NOT_UNDERSTOOD"
    assert assessment["errors"] == ["GAX-SCHEMA-MESSAGE-ID-UNSAFE"]
    result = exchange(msg, store_path)
    assert result["assessment"]["permitted_handling"] == "NOT_UNDERSTOOD"
    assert result["execution"]["attempted"] is False
    outside = [p for p in root.rglob("*") if p.is_file() and p.parent != store_path.parent]
    assert outside == []
    assert runtime.TransactionalExchangeStore(store_path).seen_messages() == {}


@pytest.mark.parametrize("message_id", [
    "msg-refund-001", "m1", "m-lost-ack", "fixture-restart_reconciliation",
    "authority-applied-revocation", "recovery-separation-absent-expiry",
    "repair-evidence_failure", "transport-gax-1", "s1-owner", "second-owner",
    "late-commit-partial", "original-unresolved",
])
def test_existing_fixture_message_ids_remain_understood(message_id):
    assert base.message_id_is_safe(message_id)


# csf_4e9a3d79c6bf349c5859768c -------------------------------------------------

def test_rejected_message_cannot_reserve_a_later_legitimate_message_id(tmp_path, stub_proposal):
    store_path = tmp_path / "exchange.sqlite"
    hostile = governed("msg-refund-001", sender="untrusted-sender", note="hostile")
    first = exchange(hostile, store_path)
    assert first["assessment"]["errors"] == ["GAX-IDENTITY-SENDER-UNTRUSTED"]
    assert runtime.TransactionalExchangeStore(store_path).seen_messages() == {}

    legitimate = governed("msg-refund-001")
    second = exchange(legitimate, store_path)
    assert "GAX-INTEGRITY-MESSAGE-ID-REUSE" not in second["assessment"]["errors"]
    assert second["assessment"]["permitted_handling"] == "ACCEPT_FOR_ASSESSMENT"
    assert second["execution"]["reason"] == "trusted_resolver_required"
    assert runtime.TransactionalExchangeStore(store_path).seen_messages() == {
        "msg-refund-001": legitimate["message_digest"]}

    # Accepted receipts still detect changed-content reuse of the same ID.
    changed = governed("msg-refund-001", note="changed")
    third = exchange(changed, store_path)
    assert third["assessment"]["errors"] == ["GAX-INTEGRITY-MESSAGE-ID-REUSE"]
    assert third["execution"]["attempted"] is False


# csf_2ed3468d5c2540e814f5640b -------------------------------------------------

def test_resume_original_rejects_tampered_message_with_copied_digest(tmp_path):
    original = governed("msg-refund-001")
    tampered = {**original, "content": {"summary": "tampered", "note": "n"}}
    store_path = tmp_path / "exchange.sqlite"
    with pytest.raises(ValueError, match="message_digest does not match"):
        runtime.resume_original_exchange(
            tampered, manifest={}, store_path=store_path, destination=None,
            resolver=None, execution_policy_factory=None, observation_policy=object(),
            evaluation_time=EVAL)
    assert list(tmp_path.glob("recovery-*.json")) == []
    assert not store_path.exists()


# csf_c6eda94b51d74aef50d8ec98 -------------------------------------------------

MODULES = {
    "control_plane": ("src/agent_control_plane", "bounded"),
    "runtime": ("engine", "producer_contract"),
    "replay": ("src/agent_replay_bundle", "importers"),
    "odes": ("src/odes", "exporter"),
    "pack": ("src/agent_governance_evidence_pack", "importer"),
}
TOP_LEVEL = ("agent_control_plane", "engine", "agent_replay_bundle", "odes", "agent_governance_evidence_pack")


def _git(path: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(path), *args], text=True).strip()


def _repo(path: Path, files: dict[str, str]) -> str:
    for name, text in files.items():
        target = path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
    _git(path.parent, "init", "-q", str(path))
    _git(path, "add", "-A")
    _git(path, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "-m", "fixture")
    return _git(path, "rev-parse", "HEAD")


@pytest.fixture
def fake_checkouts(tmp_path, monkeypatch):
    marker = tmp_path / "planted-code-ran"
    roots, revisions = {}, {}
    for key, (package, module) in MODULES.items():
        body = "PLANTED = False\n"
        if key == "runtime":
            body += ("EXECUTOR_PRODUCER_PROFILE_ID = 'urn:cognous:profiles:moltbot-safe-executor-producer'\n"
                     "EXECUTOR_PRODUCER_PROFILE_VERSION = '2.0.0'\n"
                     "PinnedControlPlaneExecutor = DurableRefundDestination = ExecutionEnvelope = None\n"
                     "ExecutionOperation = LocalExecutionPolicy = commitment = export_execution_artifacts = None\n")
        roots[key] = tmp_path / key
        revisions[key] = _repo(roots[key], {f"{package}/__init__.py": "", f"{package}/{module}.py": body})
    manifest_root = tmp_path / "manifest"
    revisions["manifest"] = _repo(manifest_root, {"examples/m.json": "{}"})

    for key in ("replay", "odes", "pack"):
        monkeypatch.syspath_prepend(str(roots[key] / "src"))
    monkeypatch.setattr(sys, "path", list(sys.path))
    for name in [m for m in sys.modules if m.split(".")[0] in TOP_LEVEL]:
        monkeypatch.delitem(sys.modules, name)
    monkeypatch.setattr(runtime, "RUNTIME_COMPATIBILITY_PROFILE", "typed-refusal-candidate-20261015")
    monkeypatch.setattr(runtime, "CP_REVISION", revisions["control_plane"])
    monkeypatch.setattr(runtime, "MOLTBOT_REVISION", revisions["runtime"])
    monkeypatch.setattr(runtime, "REPLAY_REVISION", revisions["replay"])
    monkeypatch.setattr(runtime, "ODES_REVISION", revisions["odes"])
    monkeypatch.setattr(runtime, "EVIDENCE_PACK_REVISION", revisions["pack"])
    monkeypatch.setattr(runtime, "MANIFEST_REVISION", revisions["manifest"])
    monkeypatch.setenv("MOLTBOT_SAFE_CONTROL_PLANE_ROOT", str(roots["control_plane"]))
    monkeypatch.setenv("MOLTBOT_SAFE_ROOT", str(roots["runtime"]))
    monkeypatch.setenv("UPSTREAM_MANIFEST_EXAMPLE", str(manifest_root / "examples/m.json"))
    yield roots, marker
    for name in [m for m in sys.modules if m.split(".")[0] in TOP_LEVEL]:
        sys.modules.pop(name, None)


def _planted(marker: Path) -> str:
    return f"from pathlib import Path\nPath({str(marker)!r}).write_text('ran')\nPLANTED = True\n"


def test_clean_candidate_sources_verify_then_import_from_verified_paths(fake_checkouts):
    roots, marker = fake_checkouts
    loaded = runtime.load_executor_runtime()
    assert Path(loaded["cp"].__file__).resolve() == (roots["control_plane"] / "src/agent_control_plane/bounded.py").resolve()
    assert Path(loaded["producer"].__file__).resolve() == (roots["runtime"] / "engine/producer_contract.py").resolve()
    assert not marker.exists()


def test_tampered_tracked_module_is_refused_before_it_executes(fake_checkouts):
    roots, marker = fake_checkouts
    (roots["replay"] / "src/agent_replay_bundle/importers.py").write_text(_planted(marker))
    with pytest.raises(RuntimeError, match="candidate source identity mismatch: agent_replay_bundle.importers"):
        runtime.load_executor_runtime()
    assert not marker.exists()
    assert "agent_replay_bundle.importers" not in sys.modules


def test_untracked_planted_package_is_refused_before_it_executes(fake_checkouts, tmp_path):
    roots, marker = fake_checkouts
    # An untracked package inside a pinned checkout shadows the tracked one.
    shadow = roots["odes"] / "shadow"
    (shadow / "odes").mkdir(parents=True)
    (shadow / "odes/__init__.py").write_text(_planted(marker))
    (shadow / "odes/exporter.py").write_text(_planted(marker))
    sys.path.insert(0, str(shadow))
    with pytest.raises(RuntimeError, match="candidate source identity mismatch: odes.exporter"):
        runtime.load_executor_runtime()
    assert not marker.exists()
    assert "odes" not in sys.modules
