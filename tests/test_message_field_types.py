"""Message field type validation: identifier members and created_at.

A message whose sender or recipient is not a string, or whose created_at is not
a timezone-aware timestamp string, is refused with an existing typed reason code
before any handler runs and before any exchange record is written.
"""
from __future__ import annotations

import pytest

from experiments.odex_gax_imx_reference import gax_ref as base
from experiments.odex_gax_imx_reference import gax_ref_runtime as runtime

EVAL = "2026-08-08T01:00:00Z"
CONTENT = {"summary": "synthetic", "note": "n"}


def registry():
    return base.LocalRegistry({"refund-sender"}, {"refund-recipient"}, "refund-recipient")


def signed(message_id="m-types", **change):
    msg = {
        "message_id": message_id, "conversation_id": "conv-refund-001",
        "profile": base.PROFILE, "protocol_version": base.PROTOCOL_VERSION,
        "message_type": "PROPOSE", "created_at": "2026-08-08T00:00:00Z",
        "expires_at": "2026-08-09T00:00:00Z", "sender": "refund-sender",
        "recipient": "refund-recipient", "purpose": "refund_execution_assessment",
        "requested_action": {"action_id": "a", "target": None, "payload": None, "amount": None, "unit": None,
                             "actor": None, "principal": None, "adapter_id": None, "requested_permissions": None},
        "operation_commitment": "sha256:" + "1" * 64,
        "proposal_commitment": "sha256:" + "2" * 64,
        "authority_refs": [{"type": "authority_context", "ref": base.PROFILE_AUTH_CONTEXT}],
        "evidence_refs": [], "content": CONTENT, "content_digest": base.digest(CONTENT),
        "acknowledgement_requested": True,
    }
    msg.update(change)
    msg["message_digest"] = base.digest({k: v for k, v in msg.items() if k != "message_digest"})
    return msg


NON_STRINGS = [["refund-sender"], 5, None, {"id": "x"}, True]


@pytest.mark.parametrize("value", NON_STRINGS)
def test_non_string_sender_is_refused_with_existing_code(value):
    out = base.assess_message(signed(sender=value), {}, registry(), evaluation_time=EVAL)
    assert out["permitted_handling"] == "REFUSE"
    assert out["errors"] == ["GAX-IDENTITY-SENDER-UNTRUSTED"]


@pytest.mark.parametrize("value", NON_STRINGS)
def test_non_string_recipient_is_refused_with_existing_code(value):
    out = base.assess_message(signed(recipient=value), {}, registry(), evaluation_time=EVAL)
    assert out["permitted_handling"] == "REFUSE"
    assert out["errors"] == ["GAX-IDENTITY-WRONG-RECIPIENT"]


@pytest.mark.parametrize("value", [5, 1.5, None, ["2026-08-08T00:00:00Z"], {}, "", "not-a-time", "2026-08-08T00:00:00"])
def test_invalid_created_at_is_not_understood_with_existing_code(value):
    out = base.assess_message(signed(created_at=value), {}, registry(), evaluation_time=EVAL)
    assert out["permitted_handling"] == "NOT_UNDERSTOOD"
    assert out["errors"] == ["GAX-SCHEMA-MISSING-REQUIRED"]


def test_valid_timestamp_forms_remain_accepted(monkeypatch):
    class _P:
        def model_dump(self, **_):
            return {"action_id": "a", "target": None, "payload": None, "amount": None, "unit": None,
                    "actor": None, "principal": None, "adapter_id": None, "requested_permissions": None,
                    "authority_context_ref": base.PROFILE_AUTH_CONTEXT}
    monkeypatch.setattr(base, "runtime_proposal_model", lambda bundle: _P())
    monkeypatch.setattr(base, "proposal_commitment", lambda proposal=None, *, model=None: "sha256:" + "2" * 64)
    monkeypatch.setattr(base, "operation_commitment", lambda proposal=None, *, model=None: "sha256:" + "1" * 64)
    for value in ("2026-08-08T00:00:00Z", "2026-08-08T00:00:00+00:00", "2026-08-08T02:00:00+02:00"):
        out = base.assess_message(signed(created_at=value), {}, registry(), evaluation_time=EVAL)
        assert out["errors"] != ["GAX-SCHEMA-MISSING-REQUIRED"], value


@pytest.mark.parametrize("change", [{"sender": ["refund-sender"]}, {"recipient": ["x"]}, {"created_at": 5}])
def test_exchange_refuses_before_any_record_or_effect(tmp_path, change):
    store_path = tmp_path / "exchange.sqlite"
    result = runtime.run_exchange(signed(**change), {}, registry(), None, evaluation_time=EVAL,
                                  manifest={}, store_path=store_path)
    assert result["assessment"]["permitted_handling"] in {"REFUSE", "NOT_UNDERSTOOD"}
    assert result["execution"]["attempted"] is False
    assert runtime.TransactionalExchangeStore(store_path).seen_messages() == {}


@pytest.mark.parametrize("value", [5, 1.5, None, ["2026-08-09T00:00:00Z"], {}, "", "not-a-time", "2026-08-09T00:00:00"])
def test_invalid_expires_at_is_not_understood_with_existing_code(value):
    out = base.assess_message(signed(expires_at=value), {}, registry(), evaluation_time=EVAL)
    assert out["permitted_handling"] == "NOT_UNDERSTOOD"
    assert out["errors"] == ["GAX-SCHEMA-MISSING-REQUIRED"]


def test_exchange_refuses_invalid_expires_at_before_any_record(tmp_path):
    store_path = tmp_path / "exchange.sqlite"
    result = runtime.run_exchange(signed(expires_at=5), {}, registry(), None, evaluation_time=EVAL,
                                  manifest={}, store_path=store_path)
    assert result["assessment"]["permitted_handling"] == "NOT_UNDERSTOOD"
    assert result["execution"]["attempted"] is False
    assert runtime.TransactionalExchangeStore(store_path).seen_messages() == {}


def _stub(monkeypatch):
    class _P:
        def model_dump(self, **_):
            return {"action_id": "a", "target": None, "payload": None, "amount": None, "unit": None,
                    "actor": None, "principal": None, "adapter_id": None, "requested_permissions": None,
                    "authority_context_ref": base.PROFILE_AUTH_CONTEXT}
    monkeypatch.setattr(base, "runtime_proposal_model", lambda bundle: _P())
    monkeypatch.setattr(base, "proposal_commitment", lambda proposal=None, *, model=None: "sha256:" + "2" * 64)
    monkeypatch.setattr(base, "operation_commitment", lambda proposal=None, *, model=None: "sha256:" + "1" * 64)


@pytest.fixture(autouse=True)
def _stubbed_proposal(monkeypatch):
    _stub(monkeypatch)


@pytest.mark.parametrize("value", [["PROPOSE"], {"t": "PROPOSE"}, 5, None])
def test_non_string_message_type_is_not_understood_with_existing_code(value):
    out = base.assess_message(signed(message_type=value), {}, registry(), evaluation_time=EVAL)
    assert out["permitted_handling"] == "NOT_UNDERSTOOD"
    assert out["errors"] == ["GAX-PROFILE-UNSUPPORTED-OR-DOWNGRADE"]


@pytest.mark.parametrize("member,value", [
    ("authority_refs", 5), ("authority_refs", None), ("authority_refs", True), ("authority_refs", 1.5),
    ("authority_refs", {"type": "authority_context"}), ("authority_refs", ["x"]), ("authority_refs", [5, None]),
    ("evidence_refs", 5), ("evidence_refs", None), ("evidence_refs", True), ("evidence_refs", 1.5),
    ("evidence_refs", {"type": "replay_bundle"}),
])
def test_malformed_reference_lists_are_not_understood_with_existing_code(member, value):
    out = base.assess_message(signed(**{member: value}), {}, registry(), evaluation_time=EVAL)
    assert out["permitted_handling"] == "NOT_UNDERSTOOD"
    assert out["errors"] == ["GAX-SCHEMA-MISSING-REQUIRED"]


def test_well_formed_reference_lists_remain_accepted(monkeypatch):
    _stub(monkeypatch)
    out = base.assess_message(signed(), {}, registry(), evaluation_time=EVAL)
    assert out["permitted_handling"] == "ACCEPT_FOR_ASSESSMENT"


@pytest.mark.parametrize("value", [["m-1"], {"id": "m-1"}, 5, None])
def test_exchange_non_string_message_id_is_refused_before_any_record(tmp_path, value):
    store_path = tmp_path / "exchange.sqlite"
    result = runtime.run_exchange(signed(message_id=value), {}, registry(), None, evaluation_time=EVAL,
                                  manifest={}, store_path=store_path)
    assert result["assessment"]["permitted_handling"] == "NOT_UNDERSTOOD"
    assert result["assessment"]["errors"] == ["GAX-SCHEMA-MESSAGE-ID-UNSAFE"]
    assert result["execution"]["attempted"] is False
    assert runtime.TransactionalExchangeStore(store_path).seen_messages() == {}


@pytest.mark.parametrize("change", [{"message_type": ["PROPOSE"]}, {"authority_refs": 5}, {"authority_refs": {"a": 1}},
                                    {"evidence_refs": None}])
def test_exchange_refuses_malformed_members_before_any_record(tmp_path, change):
    store_path = tmp_path / "exchange.sqlite"
    result = runtime.run_exchange(signed(**change), {}, registry(), None, evaluation_time=EVAL,
                                  manifest={}, store_path=store_path)
    assert result["assessment"]["permitted_handling"] == "NOT_UNDERSTOOD"
    assert result["execution"]["attempted"] is False
    assert runtime.TransactionalExchangeStore(store_path).seen_messages() == {}
