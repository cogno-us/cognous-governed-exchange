"""ODES reliance gate (development contract gax-odes-reliance-gate/0.1.0-dev): S1 negative-control and logic tests.

DEVELOPMENT ONLY, UNQUALIFIED, NOT ADOPTED. Everything here is SYNTHETIC / NONPRODUCTION: keys, policies, packages and
digests live only in this module. A GRANT is evidence-reliance only, never Control Plane authorization.

KEY FINDING (recorded so nobody mistakes a logic test for a native pass): a package produced by the REAL ODES exporter from a
CP2 bundle CANNOT reach native final ``pass`` at the pinned ODES. The CP2 proposal carries ``risk_metadata == {}``, so the
exporter sets ``restricted_use_flag``/``prohibited_use_flag`` True and jurisdiction ``unknown``, and the record's metadata
freshness is fixed ``unknown``. Hence ``consumption_conditions`` and ``authority_status_and_freshness`` block. A native positive
(SP1-native) is therefore NOT REACHABLE with the real stack, and Tier 2 asserts the observed BLOCKED outcome as evidence of
the blocker, not as a pass.

Two tiers
---------
Tier 1 (always runs, offline, in-process): the stub strict world of ``authenticated_world.py`` with a FAKE ``odes``
``evaluate_recipient_package`` (controllable result), so every gate branch is exercised. The Tier-1 positive is GATE-LOGIC ONLY,
evaluator stubbed, NOT a native ODES pass.

Tier 2 (opt-in): the REAL pinned ODES reached through GAX's authenticated loader, one fresh subprocess per scenario, profile
``security-runtime-p1-20261105``. Skipped unless both are set:
  GAX_RELIANCE_REAL_STACK_ROOT   dir with control_plane runtime replay odes evidence_pack manifest (as test_real_pinned_stack.py)
  GAX_RELIANCE_CP2_BUNDLE        path to a CP2 Replay (reconstruction) bundle json
  GAX_RELIANCE_MANIFEST          optional; Manifest json for the bundle (default: stack/manifest/examples/refund_integration_v1_1.manifest.json)
Nothing under the stack root is written; subprocesses set PYTHONDONTWRITEBYTECODE=1. If a scenario's export step fails the test
is skipped with the exact reason (BLOCKED) rather than substituted.
"""
from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from experiments.odex_gax_imx_reference import gax_ref_runtime as runtime
from authenticated_world import *  # noqa: F401,F403  (fixtures and helpers)
from authenticated_world import _world  # noqa: F401

CONTRACT = "gax-odes-reliance-gate/0.1.0-dev"
NOW = "2026-11-07T00:00:00Z"
EVALUATED_AT = "2026-11-06T23:58:00Z"          # status age 120 s, max age 300 s -> status limit 00:03:00Z
EXPIRES_AT = "2027-01-01T00:00:00Z"
MAX_GRANT = 3600
DEFAULT_VALID_UNTIL = "2026-11-07T00:03:00Z"
RP, PURPOSE, PROFILE = "recipient.example.org", "audit", "synthetic-nonproduction-profile"
PKG_DIGEST = "sha256:" + "1" * 64
OTHER_DIGEST = "sha256:" + "2" * 64
ISSUER = {"organization_id": "synthetic-org", "system_id": "synthetic-system"}


def passing_result(recomputed: str = PKG_DIGEST) -> dict:
    return {"recipient_reliance_decision": {"status": "pass", "evidence": {}},
            "declared_profile_conformance": {"status": "pass"},
            "package_content_integrity": {"status": "pass", "evidence": {"package_digest": recomputed}},
            "replay_semantic_consistency": {"status": "pass"}}


def failing_result(layers: dict | None = None) -> dict:
    return {"recipient_reliance_decision": {"status": "fail", "evidence": {"blocking_layers": layers or {"replay_semantic_consistency": ["synthetic"]}}},
            "declared_profile_conformance": {"status": "pass"},
            "package_content_integrity": {"status": "pass", "evidence": {"package_digest": PKG_DIGEST}},
            "replay_semantic_consistency": {"status": "fail"}}


class FakeEvaluator:
    """SYNTHETIC stand-in for odes.evaluate_recipient_package. Records calls; result and exception are controllable."""

    def __init__(self):
        self.calls, self.result, self.exc = [], passing_result(), None

    def __call__(self, package, policy):
        self.calls.append((copy.deepcopy(package), copy.deepcopy(policy)))
        if self.exc is not None:
            raise self.exc
        return copy.deepcopy(self.result)


class Gate:
    def __init__(self, world, evaluator):
        self.world, self.evaluator = world, evaluator

    def package(self, **over) -> dict:
        pinned = {"control_plane": runtime.CP_REVISION, "replay": runtime.REPLAY_REVISION,
                  "manifest": runtime.MANIFEST_REVISION, "moltbot_safe": runtime.MOLTBOT_REVISION}
        package = {"package_digest": PKG_DIGEST, "profile": {"implementation_profile": PROFILE},
                   "record": {"consumption_conditions": {"expires_at": EXPIRES_AT}},
                   "provenance": {"pinned_revisions": pinned,
                                  "source_artifacts": {"manifest_digest": runtime.authenticated_manifest().digest}}}
        package.update(over)
        return package

    def policy(self, **over) -> dict:
        # The signature envelope and key are inert placeholders: the fake evaluator never verifies anything.
        policy = {"now": NOW, "purpose": PURPOSE, "relying_party": RP, "jurisdiction": "synthetic-jurisdiction",
                  "supported_profiles": [PROFILE], "evaluation_scope": "audit", "status_max_age_seconds": 300,
                  "trusted_issuer": ISSUER, "trusted_digests": [PKG_DIGEST], "trusted_key_refs": [],
                  "status_inputs": {"evaluated_at": EVALUATED_AT, "evidence_freshness": "current", "freshness": "current"},
                  "detached_authentication": {"envelope": {"payloadType": "SYNTHETIC", "signatures": []},
                                              "trusted_keys": [{"keyid": "synthetic-nonproduction", "algorithm": "ed25519", "public_key": "SYNTHETIC"}]}}
        policy.update(over)
        return policy

    def consume(self, package=None, **over) -> dict:
        """``package=None`` means the default synthetic package; use ``raw`` to pass a literal value."""
        return self.raw(self.package() if package is None else package, **over)

    def raw(self, package, **over) -> dict:
        kwargs = dict(policy=self.policy(), policy_id="synthetic-policy", policy_version="0.0.1", expected_package_digest=PKG_DIGEST,
                      expected_relying_party=RP, expected_purpose=PURPOSE, expected_profile=PROFILE, now=NOW, max_grant_seconds=MAX_GRANT)
        kwargs.update(over)
        return runtime.consume_odes_reliance(package, **kwargs)


@pytest.fixture
def gate(world, monkeypatch):
    runtime.load_executor_runtime()
    evaluator = FakeEvaluator()
    monkeypatch.setattr(sys.modules["odes"], "evaluate_recipient_package", evaluator, raising=False)
    return Gate(world, evaluator)


def assert_refused(record, reason, *, called=None, gate_=None):
    assert record["contract"] == CONTRACT
    assert record["verdict"] == "REFUSE" and record["reason"] == reason, record
    assert "grant" in record and record["grant"] is None
    if called is not None:
        assert (len(gate_.evaluator.calls) > 0) is called


# =====================================================================================================================
# Tier 1: gate logic, evaluator STUBBED (not a native ODES pass)
# =====================================================================================================================
def test_sp1_logic_synthetic_positive_evaluator_stubbed(gate):
    """GATE-LOGIC ONLY, evaluator stubbed, NOT a native ODES pass, SYNTHETIC / NONPRODUCTION.

    Shows only that when the (fake) evaluator says pass AND every GAX binding holds, the gate returns a GRANT carrying the
    bindings the contract promises. A native pass is unreachable with the real exporter (see module docstring).
    """
    policy, package = gate.policy(), gate.package()
    before = (copy.deepcopy(policy), copy.deepcopy(package))
    record = gate.consume(package, policy=policy)
    assert record["verdict"] == "GRANT" and record["reason"] is None and record["contract"] == CONTRACT
    grant = record["grant"]
    assert grant["odes_package_digest"] == PKG_DIGEST and grant["profile"] == PROFILE
    assert grant["policy"]["id"] == "synthetic-policy" and grant["policy"]["version"] == "0.0.1"
    assert grant["policy"]["digest"] == runtime.digest(policy)
    assert grant["relying_party"] == RP and grant["purpose"] == PURPOSE
    assert grant["evaluated_at"] == NOW and grant["valid_until"] == DEFAULT_VALID_UNTIL
    assert grant["fresh_validation_digest"] == runtime.digest(passing_result())
    assert grant["source"] == {"control_plane": runtime.CP_REVISION, "replay": runtime.REPLAY_REVISION, "manifest": runtime.MANIFEST_REVISION,
                               "moltbot_safe": runtime.MOLTBOT_REVISION, "manifest_digest": runtime.authenticated_manifest().digest,
                               "odes_evaluator_revision": runtime.ODES_REVISION, "gax_compatibility_profile": runtime.RUNTIME_COMPATIBILITY_PROFILE}
    assert len(gate.evaluator.calls) == 1                                  # evaluated freshly, once, at consumption time
    assert (policy, package) == before                                     # inputs not mutated


@pytest.mark.parametrize("case, expected", [
    ("caller_cap", "2026-11-07T00:01:00Z"),                                  # now + max_grant_seconds is the minimum
    ("status_age", "2026-11-07T00:03:00Z"),                                  # status evaluated_at + max age is the minimum
    ("record_expiry", "2026-11-07T00:02:00Z"),                               # record expires_at is the minimum
])
def test_valid_until_is_the_minimum_of_the_three_limits(gate, case, expected):
    kwargs, package = {}, gate.package()
    if case == "caller_cap":
        kwargs["max_grant_seconds"] = 60
    if case == "record_expiry":
        package["record"]["consumption_conditions"]["expires_at"] = "2026-11-07T00:02:00Z"
    record = gate.consume(package, **kwargs)
    assert record["verdict"] == "GRANT" and record["grant"]["valid_until"] == expected


def test_gate_persists_nothing_and_refusals_are_dicts_without_a_grant(gate):
    before = sorted(str(p) for p in gate.world["tmp"].rglob("*"))
    granted, refused = gate.consume(), gate.consume(policy=None)
    assert sorted(str(p) for p in gate.world["tmp"].rglob("*")) == before        # no file, store or sqlite written
    assert not list(gate.world["tmp"].rglob("*.sqlite"))
    assert isinstance(refused, dict) and refused["grant"] is None and "valid_until" not in refused
    assert granted["verdict"] == "GRANT" and refused["verdict"] == "REFUSE"


def test_nc1_n5b_shaped_replay_semantic_fail_with_declared_and_integrity_pass_is_refused(gate):
    """Declared profile PASS + content integrity PASS + replay semantics FAIL => final fail => REFUSE (layers surfaced)."""
    gate.evaluator.result = failing_result({"replay_semantic_consistency": ["package semantics differ from accepted Replay-derived transformation"]})
    record = gate.consume()
    assert_refused(record, "GAX-RELIANCE-ODES-FAIL", called=True, gate_=gate)
    assert set(record["blocking_layers"]) == {"replay_semantic_consistency"}
    assert gate.evaluator.result["declared_profile_conformance"]["status"] == "pass" == gate.evaluator.result["package_content_integrity"]["status"]


@pytest.mark.parametrize("key", ["control_plane", "replay", "manifest", "moltbot_safe"])
def test_nc2_valid_foreign_generation_tuple_is_refused_even_when_odes_says_pass(gate, key):
    package = gate.package()
    package["provenance"]["pinned_revisions"][key] = "0" * 40
    assert_refused(gate.consume(package), "GAX-RELIANCE-SOURCE-MISMATCH", called=False, gate_=gate)


def test_nc2_foreign_manifest_digest_and_missing_pins_are_refused(gate):
    package = gate.package()
    package["provenance"]["source_artifacts"]["manifest_digest"] = OTHER_DIGEST
    assert_refused(gate.consume(package), "GAX-RELIANCE-SOURCE-MISMATCH", called=False, gate_=gate)
    package = gate.package()
    del package["provenance"]["pinned_revisions"]
    assert_refused(gate.consume(package), "GAX-RELIANCE-SOURCE-MISMATCH", called=False, gate_=gate)


def test_nc3_substituted_package_is_refused_against_the_independently_supplied_digest(gate):
    record = gate.consume(gate.package(package_digest=OTHER_DIGEST))          # internally "valid" package, but not the expected one
    assert_refused(record, "GAX-RELIANCE-BINDING-MISMATCH", called=False, gate_=gate)
    assert "package_digest differs" in record["detail"]


def test_nc3_evaluator_recomputed_digest_must_also_equal_the_expected_digest(gate):
    gate.evaluator.result = passing_result(recomputed=OTHER_DIGEST)
    assert_refused(gate.consume(), "GAX-RELIANCE-BINDING-MISMATCH", called=True, gate_=gate)


def test_nc4_stored_pass_is_resealable_but_the_gate_ignores_it_and_reevaluates(gate):
    """A retained export carrying a forged recipient_validation 'pass' (commitments recomputed) still validates, yet the gate
    only trusts a fresh evaluation, which here is FAIL."""
    artifacts = {"reconstruction_bundle": {"bundle_id": "synthetic"},
                 "odes_reference": {"odes_package": gate.package(), "recipient_validation": passing_result(), "exchange_metadata": {}},
                 "producer_identity_refs": {}}
    retained = runtime._retained_artifact_export(artifacts, state="original_complete")
    assert runtime._validate_retained_artifact_export(retained) is None                      # forged pass is storable and valid
    assert retained["odes"]["recipient_validation"]["recipient_reliance_decision"]["status"] == "pass"
    gate.evaluator.result = failing_result()                                                 # the fresh native verdict
    assert_refused(gate.consume(retained["odes"]["odes_package"]), "GAX-RELIANCE-ODES-FAIL", called=True, gate_=gate)


def test_nc8_retaining_a_failed_package_is_valid_but_is_not_a_grant(gate):
    artifacts = {"reconstruction_bundle": {"bundle_id": "synthetic"},
                 "odes_reference": {"odes_package": gate.package(), "recipient_validation": failing_result(), "exchange_metadata": {}},
                 "producer_identity_refs": {}}
    retained = runtime._retained_artifact_export(artifacts, state="original_complete")
    assert runtime._validate_retained_artifact_export(retained) is None
    assert "grant" not in retained and CONTRACT not in json.dumps(retained)                  # retention carries no reliance record
    gate.evaluator.result = failing_result()
    assert_refused(gate.consume(retained["odes"]["odes_package"]), "GAX-RELIANCE-ODES-FAIL", called=True, gate_=gate)


@pytest.mark.parametrize("policy", [None, {}, "policy", []])
def test_missing_or_non_object_recipient_policy_is_refused(gate, policy):
    assert_refused(gate.consume(policy=policy), "GAX-RELIANCE-POLICY-MISSING", called=False, gate_=gate)


@pytest.mark.parametrize("digest", [None, "", "abc", "sha256:" + "1" * 63, "sha256:" + "G" * 64, "SHA256:" + "1" * 64, 7])
def test_missing_or_invalid_expected_digest_is_refused(gate, digest):
    assert_refused(gate.consume(expected_package_digest=digest), "GAX-RELIANCE-ANCHOR-MISSING", called=False, gate_=gate)


def test_expected_digest_must_be_in_policy_trusted_digests(gate):
    assert_refused(gate.consume(policy=gate.policy(trusted_digests=[OTHER_DIGEST])), "GAX-RELIANCE-ANCHOR-MISSING", called=False, gate_=gate)
    assert_refused(gate.consume(policy=gate.policy(trusted_digests=[])), "GAX-RELIANCE-ANCHOR-MISSING", called=False, gate_=gate)


def test_informational_only_is_not_reliance(gate):
    gate.evaluator.result = {**passing_result(), "recipient_reliance_decision": {"status": "informational_only"}}
    assert_refused(gate.consume(), "GAX-RELIANCE-INFORMATIONAL-ONLY", called=True, gate_=gate)


@pytest.mark.parametrize("result", [{"recipient_reliance_decision": {"status": "maybe"}}, {"recipient_reliance_decision": {}}, {}, [], None,
                                    {"recipient_reliance_decision": {"status": "unavailable"}}])
def test_unknown_or_absent_final_status_is_indeterminate(gate, result):
    gate.evaluator.result = result
    assert_refused(gate.consume(), "GAX-RELIANCE-INDETERMINATE", called=True, gate_=gate)


@pytest.mark.parametrize("value", ["1", "true", "yes"])
def test_unverified_replay_bypass_flag_refuses(gate, monkeypatch, value):
    monkeypatch.setenv("ODES_ALLOW_UNVERIFIED_REPLAY", value)
    assert_refused(gate.consume(), "GAX-RELIANCE-REPLAY-BYPASS-ENABLED", called=False, gate_=gate)
    monkeypatch.setenv("ODES_ALLOW_UNVERIFIED_REPLAY", "0")
    assert gate.consume()["verdict"] == "GRANT"                                            # "0" (or empty) is the only disabled spelling


def test_non_strict_profile_cannot_authenticate_the_evaluator(gate, monkeypatch):
    package = gate.package()  # built under the strict world first: the fixture itself needs the authenticated manifest
    monkeypatch.setattr(runtime, "RUNTIME_COMPATIBILITY_PROFILE", "persistence-v1")
    assert_refused(gate.consume(package), "GAX-RELIANCE-UNAVAILABLE", called=False, gate_=gate)


def test_missing_evaluator_on_the_authenticated_module_is_unavailable(gate, monkeypatch):
    monkeypatch.delattr(sys.modules["odes"], "evaluate_recipient_package")
    assert_refused(gate.consume(), "GAX-RELIANCE-UNAVAILABLE")


def test_relying_party_purpose_and_profile_mismatches_are_refused(gate):
    assert_refused(gate.consume(expected_relying_party="other.example.org"), "GAX-RELIANCE-BINDING-MISMATCH", called=False, gate_=gate)
    assert_refused(gate.consume(expected_purpose="marketing"), "GAX-RELIANCE-BINDING-MISMATCH", called=False, gate_=gate)
    assert_refused(gate.consume(policy=gate.policy(relying_party="other.example.org")), "GAX-RELIANCE-BINDING-MISMATCH", called=False, gate_=gate)
    assert_refused(gate.consume(policy=gate.policy(purpose="marketing")), "GAX-RELIANCE-BINDING-MISMATCH", called=False, gate_=gate)
    assert_refused(gate.consume(expected_profile="other-profile"), "GAX-RELIANCE-POLICY-INVALID", called=False, gate_=gate)
    package = gate.package(profile={"implementation_profile": "other-profile"})
    assert_refused(gate.consume(package), "GAX-RELIANCE-BINDING-MISMATCH", called=False, gate_=gate)


@pytest.mark.parametrize("name", ["supported_profiles", "detached_authentication", "status_inputs", "trusted_issuer", "jurisdiction", "evaluation_scope"])
def test_policy_without_explicit_anchors_is_refused_not_defaulted(gate, name):
    policy = gate.policy()
    del policy[name]
    assert_refused(gate.consume(policy=policy), "GAX-RELIANCE-POLICY-INVALID", called=False, gate_=gate)


def test_policy_now_must_equal_the_trusted_time_and_empty_trust_anchors_are_not_authentication(gate):
    assert_refused(gate.consume(policy=gate.policy(now="2026-11-06T00:00:00Z")), "GAX-RELIANCE-POLICY-INVALID", called=False, gate_=gate)
    empty = gate.policy(detached_authentication={"envelope": {"signatures": []}, "trusted_keys": []})
    assert_refused(gate.consume(policy=empty), "GAX-RELIANCE-POLICY-INVALID", called=False, gate_=gate)


@pytest.mark.parametrize("bad", [None, "", "2026-11-07T00:00:00", "not-a-time", 5])
def test_invalid_trusted_time_is_refused(gate, bad):
    assert_refused(gate.consume(now=bad), "GAX-RELIANCE-TIME-INVALID", called=False, gate_=gate)


@pytest.mark.parametrize("bad", [0, -1, 1.5, True, "60", None])
def test_invalid_max_grant_seconds_is_refused(gate, bad):
    assert_refused(gate.consume(max_grant_seconds=bad), "GAX-RELIANCE-TIME-INVALID", called=False, gate_=gate)


def test_stale_when_no_positive_validity_interval_remains(gate):
    expired = gate.package()
    expired["record"]["consumption_conditions"]["expires_at"] = NOW                              # expires exactly now
    assert_refused(gate.consume(expired), "GAX-RELIANCE-STALE", called=True, gate_=gate)
    old_status = gate.policy(status_inputs={"evaluated_at": "2026-11-06T23:00:00Z"})             # older than status_max_age_seconds
    assert_refused(gate.consume(policy=old_status), "GAX-RELIANCE-STALE")
    no_expiry = gate.package(record={"consumption_conditions": {}})
    assert_refused(gate.consume(no_expiry), "GAX-RELIANCE-TIME-INVALID")                         # no interval can be derived: refuse


def test_replay_layer_absent_or_not_pass_refuses_even_when_odes_says_pass(gate):
    result = passing_result()
    del result["replay_semantic_consistency"]
    gate.evaluator.result = result
    assert_refused(gate.consume(), "GAX-RELIANCE-INDETERMINATE", called=True, gate_=gate)
    gate.evaluator.result = {**passing_result(), "replay_semantic_consistency": {"status": "not_applicable"}}
    assert_refused(gate.consume(), "GAX-RELIANCE-INDETERMINATE")


def test_exception_inside_the_evaluator_is_a_typed_refusal_not_a_grant(gate):
    gate.evaluator.exc = RuntimeError("synthetic evaluator crash")
    record = gate.consume()
    assert_refused(record, "GAX-RELIANCE-INDETERMINATE", called=True, gate_=gate)
    assert "RuntimeError" in record["detail"]


@pytest.mark.parametrize("bad", [None, [], "package", {}])
def test_package_that_is_not_a_non_empty_object_is_refused(gate, bad):
    assert_refused(gate.raw(bad), "GAX-RELIANCE-INDETERMINATE", called=False, gate_=gate)


# =====================================================================================================================
# Tier 2 (opt-in): REAL pinned ODES via the authenticated loader, fresh subprocess per scenario. SYNTHETIC / NONPRODUCTION keys.
# =====================================================================================================================
REAL_ROOT = os.environ.get("GAX_RELIANCE_REAL_STACK_ROOT")
CP2_BUNDLE = os.environ.get("GAX_RELIANCE_CP2_BUNDLE")
REAL_PROFILE = "security-runtime-p1-20261105"
REPO = Path(__file__).resolve().parents[1]
real_stack = pytest.mark.skipif(not (REAL_ROOT and CP2_BUNDLE), reason="GAX_RELIANCE_REAL_STACK_ROOT and GAX_RELIANCE_CP2_BUNDLE not both set")

SCRIPT = textwrap.dedent('''
    import base64, copy, json, os, sys
    from pathlib import Path
    stack = Path(os.environ["STACK"])
    for p in (stack / "replay/src", stack / "odes/src", stack / "evidence_pack/src", os.environ["EXCHANGE"]):
        sys.path.insert(0, str(p))
    from experiments.odex_gax_imx_reference import gax_ref_runtime as rt
    rt.load_executor_runtime()
    odes = rt.pinned_module("odes")
    from odes import signatures
    from odes.canonicalization import digest_for
    from odes.recipient_validator import _material_package_content, _package_core
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    NOW, EVALUATED_AT = "2026-10-06T00:00:00Z", "2026-10-05T23:59:00Z"
    KEY = Ed25519PrivateKey.generate()          # SYNTHETIC / NONPRODUCTION ephemeral key, never persisted
    PUB = base64.b64encode(KEY.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
    MANIFEST = json.loads(Path(os.environ["MANIFEST"]).read_text())
    load = lambda path: json.loads(Path(path).read_text())
    out = {}

    def blocked(reason):
        print("RESULT" + json.dumps({"blocked": reason}))
        raise SystemExit(0)

    def reseal(pkg):
        canon = pkg["integrity"]["canonicalization_profile"]
        pkg["integrity"]["value"] = digest_for(canon, _package_core(pkg))
        pkg["package_digest"] = digest_for(canon, _material_package_content(pkg))
        return pkg

    def policy_for(pkg, trusted):
        rec = pkg["record"]
        return {"now": NOW, "purpose": "audit", "relying_party": "recipient.example.org", "jurisdiction": "example-jurisdiction",
                "supported_profiles": [pkg["profile"]["implementation_profile"]], "evaluation_scope": "audit", "status_max_age_seconds": 300,
                "trusted_issuer": rec["issuer"], "trusted_digests": [trusted], "trusted_key_refs": [],
                "status_inputs": {"issuer": rec["issuer"], "record_id": rec["decision_id"], "authority_basis": rec["authority"]["authority_basis"],
                                  "evaluation_scope": "audit", "authority_valid_at_decision_verified": True, "evaluated_at": EVALUATED_AT,
                                  "evidence_freshness": "current", "freshness": "current", "revoked": False, "superseded": False},
                "detached_authentication": {"envelope": signatures.sign_package(pkg, KEY, "synthetic-nonproduction-key"),
                                            "trusted_keys": [{"keyid": "synthetic-nonproduction-key", "algorithm": "ed25519", "public_key": PUB}]}}

    def consume(pkg, expected):
        pol = policy_for(pkg, expected)
        rec = rt.consume_odes_reliance(pkg, policy=pol, policy_id="synthetic-nonproduction-policy", policy_version="0", expected_package_digest=expected,
                                       expected_relying_party="recipient.example.org", expected_purpose="audit",
                                       expected_profile=pkg["profile"]["implementation_profile"], now=NOW, max_grant_seconds=3600)
        return rec, pol

    def statuses(result):
        return {k: v.get("status") for k, v in result.items() if isinstance(v, dict) and "status" in v}

    scenario = os.environ["SCENARIO"]
    try:
        cp2_ref = rt.export_odes_reference(MANIFEST, load(os.environ["CP2_BUNDLE"]))
        cp2 = cp2_ref["odes_package"]
    except Exception as exc:
        blocked("CP2 bundle export failed: " + type(exc).__name__ + ": " + str(exc)[:400])

    if scenario == "sp1":
        rec, pol = consume(cp2, cp2["package_digest"])
        out.update(verdict=rec["verdict"], reason=rec["reason"], grant=rec["grant"], detail=rec.get("detail"),
                   blocking_layers=sorted(rec.get("blocking_layers") or {}), raw=statuses(odes.evaluate_recipient_package(cp2, pol)))
    elif scenario == "nc1":
        pkg = copy.deepcopy(cp2)
        forged = "f" * 40
        pkg["provenance"]["pinned_revisions"]["replay"] = forged
        if "selected_revisions" in pkg["provenance"]:
            pkg["provenance"]["selected_revisions"]["replay"] = forged
        reseal(pkg)
        rec, pol = consume(pkg, pkg["package_digest"])
        out.update(verdict=rec["verdict"], reason=rec["reason"], grant=rec["grant"], raw=statuses(odes.evaluate_recipient_package(pkg, pol)),
                   differs_from_original=pkg["package_digest"] != cp2["package_digest"])
    elif scenario in ("nc2", "nc3"):
        try:
            foreign = rt.export_odes_reference(MANIFEST, load(os.environ["FOREIGN_BUNDLE"]))["odes_package"]
        except Exception as exc:
            blocked("foreign (historical) bundle export failed: " + type(exc).__name__ + ": " + str(exc)[:400])
        if scenario == "nc2":
            rec, pol = consume(foreign, foreign["package_digest"])
            out["raw"] = statuses(odes.evaluate_recipient_package(foreign, pol))
        else:
            rec, pol = consume(foreign, cp2["package_digest"])          # CP2 digest is the independent anchor; the foreign package is substituted
        out.update(verdict=rec["verdict"], reason=rec["reason"], grant=rec["grant"], detail=rec.get("detail"),
                   profiles=[foreign["profile"]["implementation_profile"], cp2["profile"]["implementation_profile"]])
    elif scenario in ("nc4", "nc8"):
        ref = copy.deepcopy(cp2_ref)
        if scenario == "nc4":
            ref["recipient_validation"]["recipient_reliance_decision"] = {"status": "pass", "reasons": ["SYNTHETIC FORGERY"], "evidence": {}}
        artifacts = {"reconstruction_bundle": load(os.environ["CP2_BUNDLE"]), "odes_reference": ref, "producer_identity_refs": {}}
        retained = rt._retained_artifact_export(artifacts, state="original_complete")      # recomputes every commitment over the (forged) content
        package = retained["odes"]["odes_package"]
        rec, _ = consume(package, package["package_digest"])
        out.update(genuine_stored_status=cp2_ref["recipient_validation"]["recipient_reliance_decision"]["status"],
                   stored_status=retained["odes"]["recipient_validation"]["recipient_reliance_decision"]["status"],
                   validate=rt._validate_retained_artifact_export(retained), verdict=rec["verdict"], reason=rec["reason"], grant=rec["grant"],
                   export_mentions_gate="gax-odes-reliance-gate" in json.dumps(retained), export_has_grant="grant" in retained)
    print("RESULT" + json.dumps(out))
''')


def run_real(scenario: str) -> dict:
    stack = Path(REAL_ROOT)
    manifest = str(stack / "manifest/examples/refund_integration_v1_1.manifest.json")
    env = {**os.environ, "STACK": str(stack), "EXCHANGE": str(REPO), "SCENARIO": scenario, "GAX_RUNTIME_COMPATIBILITY_PROFILE": REAL_PROFILE,
           "PYTHONDONTWRITEBYTECODE": "1", "MOLTBOT_SAFE_CONTROL_PLANE_ROOT": str(stack / "control_plane"), "MOLTBOT_SAFE_ROOT": str(stack / "runtime"),
           "UPSTREAM_MANIFEST_EXAMPLE": manifest, "MANIFEST": os.environ.get("GAX_RELIANCE_MANIFEST", manifest),
           "CP2_BUNDLE": CP2_BUNDLE, "FOREIGN_BUNDLE": str(stack / "replay/examples/bounded_success_reconstruction_v0_2.json")}
    env.pop("ODES_ALLOW_UNVERIFIED_REPLAY", None)
    done = subprocess.run([sys.executable, "-c", SCRIPT], env=env, capture_output=True, text=True, timeout=900, cwd=str(REPO))
    assert done.returncode == 0, done.stderr[-3000:]
    out = json.loads(done.stdout.rsplit("RESULT", 1)[1])
    if "blocked" in out:
        pytest.skip("BLOCKED: " + out["blocked"])
    return out


@real_stack
def test_sp1_native_blocked_expected_native_pass_unreachable():
    """SP1 native: BLOCKED. A real-ODES package from the CP2 bundle, signed with a SYNTHETIC key, full synthetic policy, trusted
    digest and fixed clock, is REFUSED with GAX-RELIANCE-ODES-FAIL: risk_metadata {} makes restricted/prohibited True and
    jurisdiction unknown, and metadata freshness is fixed unknown, so authority_status_and_freshness and consumption_conditions
    block. This is evidence of the blocker, NOT a pass and NOT a native positive."""
    out = run_real("sp1")
    assert out["verdict"] == "REFUSE" and out["reason"] == "GAX-RELIANCE-ODES-FAIL" and out["grant"] is None, out
    assert out["blocking_layers"] == ["authority_status_and_freshness", "consumption_conditions"], out
    assert out["raw"]["recipient_reliance_decision"] == "fail"


@real_stack
def test_nc1_n5b_shaped_resealed_replay_pin_passes_declared_and_integrity_but_fails_replay_semantics():
    out = run_real("nc1")
    assert out["differs_from_original"]
    assert out["raw"]["declared_profile_conformance"] == "pass" and out["raw"]["package_content_integrity"] == "pass", out["raw"]
    assert out["raw"]["replay_semantic_consistency"] == "fail" and out["raw"]["recipient_reliance_decision"] == "fail", out["raw"]
    assert out["verdict"] == "REFUSE" and out["reason"] in {"GAX-RELIANCE-SOURCE-MISMATCH", "GAX-RELIANCE-ODES-FAIL"} and out["grant"] is None


@real_stack
def test_nc2_foreign_generation_package_from_the_pinned_replay_example_is_refused():
    out = run_real("nc2")
    assert out["profiles"][0] != out["profiles"][1], out["profiles"]                  # a different generation/profile than the CP2 package
    assert out["raw"]["package_content_integrity"] == "pass", out["raw"]              # the foreign package is internally valid
    assert out["verdict"] == "REFUSE" and out["reason"] == "GAX-RELIANCE-SOURCE-MISMATCH" and out["grant"] is None, out


@real_stack
def test_nc3_substituted_package_is_refused_against_the_cp2_expected_digest():
    out = run_real("nc3")
    assert out["verdict"] == "REFUSE" and out["reason"] == "GAX-RELIANCE-BINDING-MISMATCH" and out["grant"] is None, out
    assert "package_digest differs" in out["detail"]


@real_stack
def test_nc4_resealed_stored_pass_is_accepted_by_retention_but_the_gate_reevaluates_and_refuses():
    out = run_real("nc4")
    assert out["genuine_stored_status"] != "pass"                                      # the real stored verdict is not a pass
    assert out["stored_status"] == "pass" and out["validate"] is None                  # forged stored pass: retention validation ACCEPTS it
    assert out["verdict"] == "REFUSE" and out["grant"] is None and out["reason"] == "GAX-RELIANCE-ODES-FAIL", out


@real_stack
def test_nc8_retaining_a_failed_package_is_valid_and_yields_no_grant():
    out = run_real("nc8")
    assert out["stored_status"] != "pass" and out["validate"] is None
    assert not out["export_has_grant"] and not out["export_mentions_gate"]
    assert out["verdict"] == "REFUSE" and out["grant"] is None


@pytest.mark.parametrize("extra", [{"allow_unauthenticated_informational_inspection": True}, {"trusted_package_digests": [PKG_DIGEST]},
                                   {"unreviewed_future_key": True}])
def test_policy_keys_outside_the_reviewed_allowlist_are_refused(gate, extra):
    """Added after the builder-lineage code review (not part of the frozen pre-run battery): ODES ignores unknown keys silently."""
    assert_refused(gate.consume(policy=gate.policy(**extra)), "GAX-RELIANCE-POLICY-INVALID", called=False, gate_=gate)
