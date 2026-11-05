"""AcceptedGaxRecipientAdapter and the trusted ``runtime_authority_profile`` (security-runtime-p2-20261018).

Component-local and stub-based: the Control Plane ``RuntimeAuthorityProfile`` model is replaced by a small stand-in that
refuses unknown keys, so these tests pin what the ADAPTER does (where the profile comes from, when it is validated, that it
is forwarded identically from handle, recover and resume_original, that nothing else can supply it). Whether a profile is
authoritative, expired or revoked is decided by the real Control Plane and is exercised by the Qualification suites.
"""
from __future__ import annotations

import copy
import sys
import types

import pytest

from experiments.governed_message_transport import RecipientOutcome
from experiments.governed_message_transport.transport import AcceptedGaxRecipientAdapter, DeliveryClockPolicy
from experiments.odex_gax_imx_reference import gax_ref_runtime as rt
from tests.test_governed_message_transport import LATER, NOW, message, queue, transport

P2 = "security-runtime-p2-20261018"
P1_PROFILE = "security-runtime-p1-20261105"
HISTORICAL = ["persistence-v1", "merged-producers-v1", "typed-refusal-candidate-20261015"]
GOOD = {"catalogue_version": "c1", "actions": {"refund_issue_routine": {"class_id": "k"}}}
OTHER = {"catalogue_version": "c2", "actions": {"refund_issue_routine": {"class_id": "k"}}}
ACCEPT = {"permitted_handling": "ACCEPT_FOR_ASSESSMENT"}


class FakeProfile:
    """Stand-in for agent_control_plane.runtime_authority.RuntimeAuthorityProfile (extra=forbid, required fields)."""
    FIELDS = {"version", "catalogue_version", "actions", "producer_keys", "allow_synthetic_resolver"}

    def __init__(self, data):
        self.data = data

    @classmethod
    def model_validate(cls, value):
        if isinstance(value, cls):
            return value
        if (not isinstance(value, dict) or not set(value) <= cls.FIELDS
                or not isinstance(value.get("catalogue_version"), str) or not isinstance(value.get("actions"), dict)):
            raise ValueError("invalid runtime authority profile")
        return cls(copy.deepcopy(value))

    def snapshot(self):
        return FakeProfile(copy.deepcopy(self.data))

    def __eq__(self, other):
        return isinstance(other, FakeProfile) and self.data == other.data

    __hash__ = None

    @property
    def allow_synthetic_resolver(self):
        return bool(self.data.get("allow_synthetic_resolver", False))


@pytest.fixture(params=[P2, P1_PROFILE])
def set_profile(request, monkeypatch):
    parent = types.ModuleType("agent_control_plane")
    parent.__path__ = []
    mod = types.ModuleType("agent_control_plane.runtime_authority")
    mod.RuntimeAuthorityProfile = FakeProfile
    monkeypatch.setitem(sys.modules, "agent_control_plane", parent)
    monkeypatch.setitem(sys.modules, "agent_control_plane.runtime_authority", mod)
    monkeypatch.setattr(rt, "load_executor_runtime", lambda: {})
    monkeypatch.setenv("GAX_RUNTIME_COMPATIBILITY_PROFILE", "persistence-v1")  # ambient value must never matter

    def use(name):
        monkeypatch.setattr(rt, "RUNTIME_COMPATIBILITY_PROFILE", name)
    use(request.param)
    return use


class Spy:
    def __init__(self, result=None):
        self.calls = []
        self.result = result if result is not None else {
            "assessment": ACCEPT, "execution": {"attempted": True, "effect_id": "e1", "decision_id": "d1", "attempt_id": "a1"},
            "artifact_export": {"state": "complete", "producer_refs": {}}}

    def __call__(self, *args, **kwargs):
        self.calls.append(kwargs)
        return copy.deepcopy(self.result)


def build(tmp_path, spy=None, **kw):
    adapter = AcceptedGaxRecipientAdapter(
        bundle={}, registry=None, manifest={}, exchange_store_path=tmp_path / "ex.sqlite", resolver=object(),
        destination=object(), execution_policy_factory=lambda o: o, observation_policy=object(), **kw)
    adapter._assess_message = lambda *a, **k: dict(ACCEPT)
    adapter._run_exchange = spy if spy is not None else Spy()
    return adapter


def spy_resume(monkeypatch):
    spy = Spy(result={"resumed": True})
    monkeypatch.setattr(rt, "resume_original_exchange", spy)
    return spy


def msg(**kw):
    return message(**kw)


# ---------------------------------------------------------------- positive ----------------------------------------

def test_p2_handle_recover_resume_forward_the_constructor_profile_identically(set_profile, tmp_path, monkeypatch):
    spy = Spy()
    resume = spy_resume(monkeypatch)
    adapter = build(tmp_path, spy, runtime_authority_profile=GOOD, allow_test_time=True)
    adapter.handle(msg(), delivery_time=NOW)
    adapter.recover(msg(), delivery_time=NOW)
    adapter.resume_original(msg(), delivery_time=NOW)
    seen = spy.calls + resume.calls
    assert len(seen) == 3
    for kwargs in seen:
        assert kwargs["runtime_authority_profile"] == FakeProfile(GOOD)
        assert kwargs["allow_test_time"] is True
    assert spy.calls[0]["runtime_authority_profile"] == spy.calls[1]["runtime_authority_profile"]
    # the handle call is otherwise the historical call
    assert set(spy.calls[0]) == {"evaluation_time", "manifest", "store_path", "resolver", "execution_policy_factory",
                                 "observation_policy", "observation_clock", "runtime_authority_profile", "allow_test_time"}


def test_allow_test_time_defaults_to_false_and_is_only_forwarded_from_the_constructor(set_profile, tmp_path):
    spy = Spy()
    build(tmp_path, spy, runtime_authority_profile=GOOD).handle(msg(), delivery_time=NOW)
    assert spy.calls[0]["allow_test_time"] is False


def test_transport_route_uses_the_profile_for_handle_and_for_recover(set_profile, tmp_path):
    pending = Spy(result={"assessment": ACCEPT, "execution": {"attempted": True, "effect_id": "e1"},
                          "artifact_export": {"state": "recovery_required", "producer_refs": {}}})
    adapter = build(tmp_path, pending, runtime_authority_profile=GOOD)
    t = transport(tmp_path, adapter)
    item = msg()
    queue(t, item)
    t.deliver(item["message_id"], now=NOW)
    pending.result = {"assessment": ACCEPT, "execution": {"attempted": False, "effect_id": "e1"},
                      "artifact_export": {"state": "complete", "producer_refs": {}}}
    t.deliver(item["message_id"], now=LATER)
    assert len(pending.calls) == 2, "handle then recover must both reach run_exchange"
    assert all(c["runtime_authority_profile"] == FakeProfile(GOOD) for c in pending.calls)


def test_duplicate_redelivery_does_not_call_the_adapter_again(set_profile, tmp_path):
    spy = Spy()
    t = transport(tmp_path, build(tmp_path, spy, runtime_authority_profile=GOOD))
    item = msg()
    queue(t, item)
    t.deliver(item["message_id"], now=NOW)
    t.deliver(item["message_id"], now=LATER)
    assert len(spy.calls) == 1


@pytest.mark.parametrize("name", HISTORICAL)
def test_historical_profiles_are_unchanged_no_new_keyword_is_passed(set_profile, tmp_path, monkeypatch, name):
    set_profile(name)
    spy = Spy()
    resume = spy_resume(monkeypatch)
    adapter = build(tmp_path, spy)
    assert adapter._authority_kwargs() == {}
    adapter.handle(msg(), delivery_time=NOW)
    adapter.recover(msg(), delivery_time=NOW)
    adapter.resume_original(msg(), delivery_time=NOW)
    for kwargs in spy.calls + resume.calls:
        assert "runtime_authority_profile" not in kwargs and "allow_test_time" not in kwargs
    assert set(spy.calls[0]) == {"evaluation_time", "manifest", "store_path", "resolver", "execution_policy_factory",
                                 "observation_policy", "observation_clock"}


def test_profile_is_not_serialised_into_the_outcome(set_profile, tmp_path):
    out = build(tmp_path, runtime_authority_profile=GOOD).handle(msg(), delivery_time=NOW)
    assert isinstance(out, RecipientOutcome)
    assert "catalogue_version" not in repr(out) and "runtime_authority" not in repr(out)


@pytest.mark.parametrize("kind", ["REPORT", "REFUSE", "NOT_UNDERSTOOD"])
def test_informational_types_need_and_use_no_profile(set_profile, tmp_path, kind):
    results = []
    for kw in ({}, {"runtime_authority_profile": GOOD}):
        if not kw:
            adapter = object.__new__(AcceptedGaxRecipientAdapter)   # even an unconfigured adapter must not need one
            adapter.bundle = adapter.registry = None
            adapter.clock_policy = DeliveryClockPolicy()
            adapter._assess_message = lambda *a, **k: dict(ACCEPT)
            adapter._run_exchange = Spy()
        else:
            adapter = build(tmp_path, **kw)
        out = adapter.handle(msg(message_type=kind), delivery_time=NOW)
        assert adapter._run_exchange.calls == []
        results.append(out.execution)
    assert results[0] == results[1]


def test_ineligible_assessment_consumes_no_profile(set_profile, tmp_path):
    adapter = build(tmp_path, runtime_authority_profile=GOOD)
    adapter._assess_message = lambda *a, **k: {"permitted_handling": "REFUSE"}
    out = adapter.handle(msg(), delivery_time=NOW)
    assert out.execution["reason"] == "recipient_assessment_not_eligible" and adapter._run_exchange.calls == []


# ------------------------------------------------------------- adversarial ----------------------------------------

@pytest.mark.parametrize("kw", [{}, {"runtime_authority_profile": None}, {"allow_test_time": True}])
def test_missing_profile_under_p2_is_refused_at_construction_and_touches_nothing(set_profile, tmp_path, kw):
    with pytest.raises(ValueError, match="requires trusted runtime_authority_profile"):
        build(tmp_path, **kw)
    assert not (tmp_path / "ex.sqlite").exists()


@pytest.mark.parametrize("bad", ["profile", "", [], [GOOD], 5, 1.5, True, object(), b"x", {}, {"x": 1},
                                 {"catalogue_version": "c"}, {"actions": {}},
                                 {**GOOD, "unknown_key": 1}, {**GOOD, "catalogue_version": 7}, {**GOOD, "actions": []}])
def test_malformed_or_untrusted_profile_is_refused_before_any_store_write(set_profile, tmp_path, bad):
    with pytest.raises((ValueError, TypeError)):
        build(tmp_path, runtime_authority_profile=bad)
    assert not (tmp_path / "ex.sqlite").exists()
    assert list(tmp_path.iterdir()) == []
    # a later correct adapter is not poisoned: the message id was never reserved
    spy = Spy()
    build(tmp_path, spy, runtime_authority_profile=GOOD).handle(msg(), delivery_time=NOW)
    assert len(spy.calls) == 1


@pytest.mark.parametrize("bad", [1, 0, "yes", None, [True]])
def test_allow_test_time_must_be_a_real_bool(set_profile, tmp_path, bad):
    with pytest.raises(TypeError):
        build(tmp_path, runtime_authority_profile=GOOD, allow_test_time=bad)


@pytest.mark.parametrize("name", HISTORICAL)
@pytest.mark.parametrize("kw", [{"runtime_authority_profile": GOOD}, {"runtime_authority_profile": object()},
                                {"allow_test_time": True}, {"runtime_authority_profile": GOOD, "allow_test_time": True}])
def test_profile_under_a_historical_profile_raises_and_cannot_elevate(set_profile, tmp_path, name, kw):
    set_profile(name)
    with pytest.raises(ValueError, match="require the explicit security-runtime profile"):
        build(tmp_path, **kw)
    assert not (tmp_path / "ex.sqlite").exists()


def test_no_ambient_or_default_fallback_for_an_unconfigured_adapter(set_profile, tmp_path):
    configured = build(tmp_path, runtime_authority_profile=GOOD, allow_test_time=True)
    configured.handle(msg(), delivery_time=NOW)
    # an adapter that was never configured (bypassing the constructor) does not inherit anything from the configured one,
    # the module, the environment or a previous call: the REAL run_exchange refuses before it opens a store
    bare = object.__new__(AcceptedGaxRecipientAdapter)
    bare.bundle, bare.registry, bare.manifest = {}, None, {}
    bare.exchange_store_path = tmp_path / "bare.sqlite"
    bare.resolver = bare.destination = bare.observation_policy = object()
    bare.observation_clock = None
    bare.execution_policy_factory = lambda o: o
    bare.clock_policy = configured.clock_policy
    bare._assess_message = lambda *a, **k: dict(ACCEPT)
    bare._run_exchange = rt.run_exchange
    assert bare._authority_kwargs() == {}
    with pytest.raises(ValueError, match="requires trusted runtime_authority_profile"):
        bare.handle(msg(), delivery_time=NOW)
    with pytest.raises(ValueError, match="requires trusted runtime_authority_profile"):
        bare.recover(msg(), delivery_time=NOW)
    assert not (tmp_path / "bare.sqlite").exists()


def test_message_borne_profile_and_flags_are_inert(set_profile, tmp_path):
    spy = Spy()
    adapter = build(tmp_path, spy, runtime_authority_profile=GOOD)
    hostile = msg()
    hostile.update({"runtime_authority_profile": OTHER, "allow_test_time": True, "runtime_authority": OTHER})
    hostile["content"] = {"runtime_authority_profile": OTHER, "allow_test_time": True}
    adapter.handle(hostile, delivery_time=NOW)
    adapter.recover(hostile, delivery_time=NOW)
    assert all(c["runtime_authority_profile"] == FakeProfile(GOOD) and c["allow_test_time"] is False for c in spy.calls)
    # a message cannot supply one to an unconfigured adapter either: construction under p2 is refused outright
    with pytest.raises(ValueError, match="requires trusted"):
        build(tmp_path)


@pytest.mark.parametrize("method", ["handle", "recover", "resume_original"])
@pytest.mark.parametrize("extra", ["runtime_authority_profile", "allow_test_time"])
def test_there_is_no_per_call_interface(set_profile, tmp_path, method, extra):
    adapter = build(tmp_path, runtime_authority_profile=GOOD)
    with pytest.raises(TypeError):
        getattr(adapter, method)(msg(), delivery_time=NOW, **{extra: OTHER if extra.startswith("r") else True})


@pytest.mark.parametrize("order", [("A", "B", "B", "A"), ("B", "A", "A", "B"), ("A", "A", "B", "B")])
def test_profile_substitution_between_calls_and_adapters_never_crosses(set_profile, tmp_path, order):
    spy_a, spy_b = Spy(), Spy()
    a = build(tmp_path, spy_a, runtime_authority_profile=GOOD)
    b = build(tmp_path, spy_b, runtime_authority_profile=OTHER, allow_test_time=True)
    for step, which in enumerate(order):
        adapter = a if which == "A" else b
        (adapter.handle if step % 2 == 0 else adapter.recover)(msg(message_id=f"m{step}"), delivery_time=NOW)
    assert all(c["runtime_authority_profile"] == FakeProfile(GOOD) and c["allow_test_time"] is False for c in spy_a.calls)
    assert all(c["runtime_authority_profile"] == FakeProfile(OTHER) and c["allow_test_time"] is True for c in spy_b.calls)
    assert len(spy_a.calls) + len(spy_b.calls) == 4


def test_profile_is_detached_at_construction_and_per_call(set_profile, tmp_path):
    profile = copy.deepcopy(GOOD)
    spy = Spy()
    adapter = build(tmp_path, spy, runtime_authority_profile=profile)
    profile["actions"]["refund_issue_routine"]["class_id"] = "WIDENED"
    profile["catalogue_version"] = "tampered"
    adapter.handle(msg(), delivery_time=NOW)
    spy.calls[0]["runtime_authority_profile"].data["actions"]["x"] = {"class_id": "callee-mutation"}
    adapter.recover(msg(), delivery_time=NOW)
    assert spy.calls[1]["runtime_authority_profile"] == FakeProfile(GOOD)
    assert spy.calls[0]["runtime_authority_profile"] is not spy.calls[1]["runtime_authority_profile"]


def test_p2_profile_does_not_alter_p2_refusal_of_the_real_runtime_without_it(set_profile, tmp_path):
    """The existing rule is untouched: the real run_exchange still refuses a missing profile before opening any store."""
    with pytest.raises(ValueError, match="requires trusted runtime_authority_profile"):
        rt.run_exchange(msg(), {}, None, None, evaluation_time=NOW, manifest={}, store_path=tmp_path / "s.sqlite")
    assert not (tmp_path / "s.sqlite").exists()


def test_authenticated_loader_runs_before_the_model_is_imported_and_its_failure_propagates(set_profile, tmp_path, monkeypatch):
    order = []
    mod = sys.modules["agent_control_plane.runtime_authority"]
    parent = sys.modules["agent_control_plane"]
    monkeypatch.delitem(sys.modules, "agent_control_plane.runtime_authority")
    monkeypatch.delitem(sys.modules, "agent_control_plane")

    def loader():
        order.append("load")                       # the real loader is what makes the authenticated package importable
        sys.modules["agent_control_plane"] = parent
        sys.modules["agent_control_plane.runtime_authority"] = mod
        return {}
    monkeypatch.setattr(rt, "load_executor_runtime", loader)
    try:
        build(tmp_path, runtime_authority_profile=GOOD)
        assert order == ["load"]
    finally:
        sys.modules.pop("agent_control_plane.runtime_authority", None)
        sys.modules.pop("agent_control_plane", None)

    def failing():
        raise RuntimeError("candidate source identity mismatch")
    monkeypatch.setattr(rt, "load_executor_runtime", failing)
    with pytest.raises(RuntimeError, match="identity mismatch"):
        build(tmp_path, runtime_authority_profile=GOOD)
    assert list(tmp_path.iterdir()) == []


def test_synthetic_resolver_profile_without_test_clock_is_refused_at_construction(set_profile, tmp_path):
    synthetic = {**GOOD, "allow_synthetic_resolver": True}
    with pytest.raises(ValueError, match="synthetic authority profile requires explicit test clock"):
        build(tmp_path, runtime_authority_profile=synthetic)
    assert list(tmp_path.iterdir()) == []
    spy = Spy()
    build(tmp_path, spy, runtime_authority_profile=synthetic, allow_test_time=True).handle(msg(), delivery_time=NOW)
    assert spy.calls[0]["allow_test_time"] is True
    build(tmp_path, runtime_authority_profile={**GOOD, "allow_synthetic_resolver": False})
