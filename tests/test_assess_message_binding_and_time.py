"""assess_message: type-exact requested_action binding and created_at bounds (B-F5, B-F7).

Python equality treats True == 1 and 1.0 == 1, so a requested_action carrying a bool or float amount matched an
integer amount. The binding is now compared on canonical JSON bytes. created_at must not follow expires_at or the
supplied evaluation_time, and a timestamp that overflows on UTC conversion is a typed structure refusal.
"""
from __future__ import annotations

import pytest

from experiments.odex_gax_imx_reference import gax_ref as base

EVAL = "2026-08-08T01:00:00Z"
PROPOSAL = {"action_id": "refund_issue_routine", "target": "urn:t", "payload": {"x": 1}, "amount": 1, "unit": "USD",
            "actor": "urn:a", "principal": "urn:p", "adapter_id": "adapter",
            "requested_permissions": ["refund.issue.routine"], "authority_context_ref": base.PROFILE_AUTH_CONTEXT}


class _Proposal:
    def model_dump(self, **_):
        return dict(PROPOSAL)


@pytest.fixture(autouse=True)
def stub_proposal(monkeypatch):
    monkeypatch.setattr(base, "runtime_proposal_model", lambda bundle: _Proposal())
    monkeypatch.setattr(base, "proposal_commitment", lambda proposal=None, *, model=None: "sha256:" + "2" * 64)
    monkeypatch.setattr(base, "operation_commitment", lambda proposal=None, *, model=None: "sha256:" + "1" * 64)


def msg(**over):
    content = {"summary": "s"}
    m = {"message_id": "m1", "conversation_id": "c", "profile": base.PROFILE,
         "protocol_version": base.PROTOCOL_VERSION, "message_type": "PROPOSE",
         "created_at": "2026-08-08T00:00:00Z", "expires_at": "2026-08-09T00:00:00Z", "sender": "s", "recipient": "r",
         "purpose": "refund_execution_assessment",
         "requested_action": {k: v for k, v in PROPOSAL.items() if k != "authority_context_ref"},
         "operation_commitment": "sha256:" + "1" * 64, "proposal_commitment": "sha256:" + "2" * 64,
         "authority_refs": [{"type": "authority_context", "ref": base.PROFILE_AUTH_CONTEXT}], "evidence_refs": [],
         "content": content, "content_digest": base.digest(content)}
    m.update(over)
    m["message_digest"] = base.digest({k: v for k, v in m.items() if k != "message_digest"})
    return m


def assess(m):
    return base.assess_message(m, {}, base.LocalRegistry({"s"}, {"r"}, "r"), evaluation_time=EVAL)


def test_baseline_is_accepted():
    assert assess(msg())["permitted_handling"] == "ACCEPT_FOR_ASSESSMENT"


@pytest.mark.parametrize("amount", [True, 1.0])
def test_requested_action_amount_must_match_type_exactly(amount):
    ra = dict(msg()["requested_action"])
    ra["amount"] = amount
    out = assess(msg(requested_action=ra))
    assert out["permitted_handling"] == "REFUSE"
    assert out["errors"] == ["GAX-REFERENCE-OPERATION-BINDING-MISMATCH"]


def test_created_at_after_expires_at_is_refused():
    out = assess(msg(created_at="2026-08-10T00:00:00Z"))
    assert out["permitted_handling"] == "REFUSE"
    assert out["errors"] == ["GAX-FRESHNESS-CREATED-AFTER-EXPIRY"]


def test_created_at_after_evaluation_time_is_refused():
    out = assess(msg(created_at="2026-08-08T12:00:00Z"))
    assert out["permitted_handling"] == "REFUSE"
    assert out["errors"] == ["GAX-FRESHNESS-CREATED-IN-FUTURE"]


@pytest.mark.parametrize("member", ["created_at", "expires_at"])
def test_overflowing_timestamp_is_a_typed_refusal(member):
    out = assess(msg(**{member: "9999-12-31T23:59:59-01:00"}))
    assert out["permitted_handling"] == "NOT_UNDERSTOOD"
    assert out["errors"] == ["GAX-SCHEMA-MISSING-REQUIRED"]
