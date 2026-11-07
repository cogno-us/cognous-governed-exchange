"""S1G: native ODES lifecycle-profile -> GAX reliance GRANT (six selected test groups). DEVELOPMENT ONLY, SYNTHETIC / NONPRODUCTION, UNQUALIFIED.

Real pinned Control Plane (484fdbd2) -> Replay (93a76e28) -> ODES exporter + native evaluator at the DRAFT head cafec03f (ODES PR #146, loaded
through GAX's authenticated loader under the new profile ``security-runtime-p1-lifecycle-20261107``) -> ``consume_odes_reliance``. No evaluator
result is mocked. A GRANT is reliance evidence only: no effect, no Control Plane authority, no institutional permission.

Needs two stack roots (dirs holding control_plane runtime replay odes evidence_pack manifest as in test_real_pinned_stack.py):
  GAX_S1G_STACK_ROOT      odes checked out at cafec03f71d0f822b783f7463fcd8144c90829d5 (clean, detached)
  GAX_S1G_OLD_STACK_ROOT  odes checked out at 1e2261289e8ff8e862b697f5c7afcf7007453787 (P1 stack)
GAX_S1G_REQUIRE=1 turns a missing root into a failure instead of a skip. Skips are NOT passes. Nothing under a stack root is written.
The Control Plane fixtures are read from the authenticated ODES checkout (sha256-pinned in FIXTURE_HASHES.json). A fresh pinned-Replay import stamps a random
bundle_id/generated_at, so expected digests cannot be committed. Each module run does: produce (producer process) -> record_anchor (recipient preparation; sees only
digests.json, never a package) -> consumption processes that read the untrusted package file plus the recorded anchor. Same-author synthetic separation (PROVENANCE.md).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
DATA = REPO / "tests" / "data" / "s1g_lifecycle"
WORKER = REPO / "tests" / "s1g_lifecycle_worker.py"
RUNTIME_SRC = REPO / "experiments" / "odex_gax_imx_reference" / "gax_ref_runtime.py"
NEW_ROOT, OLD_ROOT = os.environ.get("GAX_S1G_STACK_ROOT"), os.environ.get("GAX_S1G_OLD_STACK_ROOT")
NEW_PROFILE, P1_PROFILE = "security-runtime-p1-lifecycle-20261107", "security-runtime-p1-20261105"
LIFECYCLE_ID = "odes_cognous_stack_export_0_2_restrictions_lifecycle_0_1"
ODES_DRAFT, ODES_OLD = "cafec03f71d0f822b783f7463fcd8144c90829d5", "1e2261289e8ff8e862b697f5c7afcf7007453787"
P1 = {"CP_REVISION": "484fdbd297235dd24148ddb0703f2055a31eabff", "MOLTBOT_REVISION": "f7a55e2a8494801e49193f9f46935f0a971c248d",
      "MANIFEST_REVISION": "fa170815ef96a54c233d0dd9da821b60debabf8b", "REPLAY_REVISION": "93a76e281fcae6a65d2cd1d35376f87442dafb95",
      "ODES_REVISION": ODES_OLD, "EVIDENCE_PACK_REVISION": "065150852cc2a8abeb748777bb69d72ccd0e03d8"}
LAYERS = ("schema_validity", "replay_semantic_consistency", "declared_profile_conformance", "package_content_integrity",
          "integrity_authentication_checks", "historical_authority_assertions", "authority_status_and_freshness", "consumption_conditions",
          "recipient_reliance_decision")
FIXTURE_HASHES = json.loads((DATA / "FIXTURE_HASHES.json").read_text())


def _need(root, name):
    if root and (Path(root) / "odes").is_dir():
        return
    if os.environ.get("GAX_S1G_REQUIRE") == "1":
        pytest.fail(f"GAX_S1G_REQUIRE=1 but {name} is not set to a stack root")
    pytest.skip(f"{name} not set")


def run(scenario: str, root: str, profile: str, tmp: Path, **extra) -> dict:
    stack = Path(root)
    fixdir = Path(NEW_ROOT) / "odes" / "tests" / "data" / "lifecycle_generation"
    manifest = str(stack / "manifest/examples/refund_integration_v1_1.manifest.json")
    env = {**os.environ, "STACK": str(stack), "EXCHANGE": str(REPO), "DATA": str(DATA), "FIXDIR": str(fixdir), "OUT": str(tmp),
           "PROD": str(tmp / "prod"), "RECIP": str(tmp / "recip"), "SCENARIO": scenario, "MANIFEST": manifest,
           "GAX_RUNTIME_COMPATIBILITY_PROFILE": profile, "PYTHONDONTWRITEBYTECODE": "1", "MOLTBOT_SAFE_CONTROL_PLANE_ROOT": str(stack / "control_plane"),
           "MOLTBOT_SAFE_ROOT": str(stack / "runtime"), "UPSTREAM_MANIFEST_EXAMPLE": manifest, **extra}
    env.pop("ODES_ALLOW_UNVERIFIED_REPLAY", None)
    done = subprocess.run([sys.executable, "-B", str(WORKER)], env=env, capture_output=True, text=True, timeout=900, cwd=str(REPO))
    assert done.returncode == 0, done.stderr[-3000:]
    return json.loads(done.stdout.rsplit("RESULT", 1)[1])


@pytest.fixture(scope="module")
def new_root():
    _need(NEW_ROOT, "GAX_S1G_STACK_ROOT")
    return NEW_ROOT


@pytest.fixture(scope="module")
def old_root():
    _need(OLD_ROOT, "GAX_S1G_OLD_STACK_ROOT")
    return OLD_ROOT


@pytest.fixture(scope="module")
def prepared(new_root, tmp_path_factory):
    """Ordered preparation: produce (producer) then record_anchor (recipient prep). Returns the shared work dir and the recorded anchor."""
    fixdir = Path(new_root) / "odes" / "tests" / "data" / "lifecycle_generation"
    for name in ("lifecycle_proposal.json", "lifecycle_control_plane_run.json"):
        assert hashlib.sha256((fixdir / name).read_bytes()).hexdigest() == FIXTURE_HASHES[name], name
    work = tmp_path_factory.mktemp("s1g")
    (work / "prod").mkdir()
    (work / "recip").mkdir()
    produced = run("produce", new_root, NEW_PROFILE, work)
    assert produced["profile"] == LIFECYCLE_ID
    assert not (work / "recip" / "anchor.json").exists()
    recorded = run("record_anchor", new_root, NEW_PROFILE, work)
    assert recorded["recorded"] == ["current", "stale"]
    anchor = json.loads((work / "recip" / "anchor.json").read_text())["expected_package_digests"]
    assert anchor["current"] != anchor["stale"]
    return work, anchor


def test_fixture_hashes_and_public_key_file_are_pinned():
    pinned = FIXTURE_HASHES
    assert pinned["odes_revision"] == ODES_DRAFT and len(pinned["lifecycle_proposal.json"]) == 64 and len(pinned["lifecycle_control_plane_run.json"]) == 64
    key = json.loads((DATA / "synthetic_issuer_public_key.json").read_text())
    assert key["algorithm"] == "ed25519" and key["keyid"] == "synthetic-issuer-key-nonproduction"


# ===================================================================================================== T1
def test_t1_native_positive_cp_replay_odes_gax_grant(new_root, prepared):
    tmp_path, ANCHOR = prepared
    o = run("t1", new_root, NEW_PROFILE, tmp_path)
    s = o["sources"]
    assert (s["odes_commit"], s["odes_revision_constant"], s["gax_profile"]) == (ODES_DRAFT, ODES_DRAFT, NEW_PROFILE)
    assert (s["cp"], s["replay"], s["manifest"], s["moltbot"]) == (P1["CP_REVISION"], P1["REPLAY_REVISION"], P1["MANIFEST_REVISION"], P1["MOLTBOT_REVISION"])
    assert sorted(o["live_vs_persisted_bundle_diff"]) == ["/bundle_id", "/generated_at"], o["live_vs_persisted_bundle_diff"]   # fresh pinned-Replay import == persisted bundle
    assert o["risk_in_bundle"]["jurisdiction"] == "SYNTHETIC-JURISDICTION-NONPRODUCTION" and o["risk_in_bundle"]["restricted_use_flag"] is False
    assert o["profile"] == LIFECYCLE_ID and o["has_lifecycle"] and o["package_digest"] == ANCHOR["current"]
    assert o["record_status"] == {"freshness": "current", "superseded": False, "revoked": False}
    assert o["layers"] == {name: "pass" for name in LAYERS} and o["final"] == "pass", o["layers"]
    assert o["verdict"] == "GRANT" and o["reason"] is None, o
    g = o["grant"]
    assert g["odes_package_digest"] == ANCHOR["current"] and g["profile"] == LIFECYCLE_ID and g["valid_until"] == "2026-10-06T00:04:00Z"
    assert g["source"]["odes_evaluator_revision"] == ODES_DRAFT and g["source"]["gax_compatibility_profile"] == NEW_PROFILE
    assert o["rec_keys"] == ["contract", "grant", "notice", "reason", "verdict"]
    assert not [k for k in o["grant_keys"] if re.search("effect|dispatch|authoriz|permit", k)], o["grant_keys"]


# ===================================================================================================== T2
def test_t2_rewritten_resealed_resigned_package_refuses_against_recorded_anchor(new_root, prepared):
    tmp_path, ANCHOR = prepared
    o = run("t2", new_root, NEW_PROFILE, tmp_path)
    assert set(o["variants"]) == {"reexport_rewrite", "inplace_edit_resealed"}
    for name, v in o["variants"].items():
        assert v["differs"], name
        assert v["verdict"] == "REFUSE" and v["reason"] == "GAX-RELIANCE-BINDING-MISMATCH" and v["grant"] is None, (name, v)
        assert v["raw"]["package_content_integrity"] != "pass" and v["raw"]["recipient_reliance_decision"] != "pass", (name, v["raw"])


# ===================================================================================================== T3
def test_t3_recipient_revoked_status_refuses(new_root, prepared):
    tmp_path, ANCHOR = prepared
    o = run("t3", new_root, NEW_PROFILE, tmp_path)
    assert o["package_digest"] == ANCHOR["current"]
    assert o["verdict"] == "REFUSE" and o["reason"] == "GAX-RELIANCE-ODES-FAIL" and o["grant"] is None, o
    assert o["blocking_layers"] == ["authority_status_and_freshness"] and o["raw"]["authority_status_and_freshness"] == "fail", o
    assert all(v == "pass" for k, v in o["raw"].items() if k not in ("authority_status_and_freshness", "recipient_reliance_decision")), o["raw"]


# ===================================================================================================== T4
def test_t4_stale_record_side_lifecycle_refuses_despite_favorable_recipient_inputs(new_root, prepared):
    tmp_path, ANCHOR = prepared
    o = run("t4", new_root, NEW_PROFILE, tmp_path)
    assert o["package_digest"] == ANCHOR["stale"] and o["record_status"]["freshness"] == "stale"
    assert o["recipient_status"]["freshness"] == "current" and o["recipient_status"]["revoked"] is False
    assert o["verdict"] == "REFUSE" and o["reason"] == "GAX-RELIANCE-ODES-FAIL" and o["grant"] is None, o
    assert o["blocking_layers"] == ["authority_status_and_freshness"] and o["raw"]["authority_status_and_freshness"] == "fail", o
    assert all(v == "pass" for k, v in o["raw"].items() if k not in ("authority_status_and_freshness", "recipient_reliance_decision")), o["raw"]


# ===================================================================================================== T5
def _profile_block(text: str, name: str) -> dict[str, str]:
    block = re.search(r'^elif RUNTIME_COMPATIBILITY_PROFILE == "%s":\n(.*?)(?=^elif |^# )' % re.escape(name), text, re.S | re.M).group(1)
    return dict(re.findall(r'^    ([A-Z_]+_REVISION) = "([0-9a-f]{40})"', block, re.M))


def test_t5_source_p1_block_unchanged_and_new_profile_differs_only_in_odes():
    text = RUNTIME_SRC.read_text()
    assert _profile_block(text, P1_PROFILE) == P1
    assert _profile_block(text, NEW_PROFILE) == {**P1, "ODES_REVISION": ODES_DRAFT}
    base = subprocess.run(["git", "show", "74bd7a9758f3afe1275b8a4b9e5d8601b3468045:experiments/odex_gax_imx_reference/gax_ref_runtime.py"],
                          capture_output=True, text=True, cwd=str(REPO))
    if base.returncode == 0:      # the P1 block is byte-identical to the base head's
        old = re.search(r'^elif RUNTIME_COMPATIBILITY_PROFILE == "%s":\n.*?(?=^elif )' % re.escape(P1_PROFILE), base.stdout, re.S | re.M).group(0)
        assert old in text


def test_t5_legacy_and_restrictions_profiles_retain_outcomes_and_source_bindings(new_root, old_root, prepared):
    tmp_path, _anchor = prepared
    new = run("t5", new_root, NEW_PROFILE, tmp_path)
    old = run("t5", old_root, P1_PROFILE, tmp_path)
    assert new["sources"]["odes_commit"] == ODES_DRAFT and old["sources"]["odes_commit"] == ODES_OLD and old["sources"]["gax_profile"] == P1_PROFILE
    assert set(new["modes"]) == set(old["modes"]) == {"legacy", "explicit"}
    for mode in ("legacy", "explicit"):
        n, p = new["modes"][mode], old["modes"][mode]
        for key in ("profile", "version", "package_digest", "pinned", "manifest_digest_pkg", "verdict", "reason", "blocking_layers", "raw", "has_lifecycle"):
            assert n[key] == p[key], (mode, key, n[key], p[key])
        assert n["profile"] != LIFECYCLE_ID and not n["has_lifecycle"]
        assert n["verdict"] == "REFUSE" and n["reason"] == "GAX-RELIANCE-ODES-FAIL" and n["grant"] is None, (mode, n["verdict"], n["reason"])
        assert {k: n["pinned"][k] for k in ("control_plane", "replay", "manifest", "moltbot_safe")} == {
            "control_plane": P1["CP_REVISION"], "replay": P1["REPLAY_REVISION"], "manifest": P1["MANIFEST_REVISION"], "moltbot_safe": P1["MOLTBOT_REVISION"]}
    assert new["modes"]["legacy"]["profile"] != new["modes"]["explicit"]["profile"]


# ===================================================================================================== T6
def test_t6_old_odes_pin_cannot_grant_for_the_lifecycle_package(new_root, old_root, prepared):
    tmp_path, ANCHOR = prepared
    made = run("t1", new_root, NEW_PROFILE, tmp_path)
    assert made["verdict"] == "GRANT"          # precondition: the package is genuinely GRANT-able under the new pin
    o = run("t6", old_root, P1_PROFILE, tmp_path)
    assert o["sources"]["odes_commit"] == ODES_OLD and o["sources"]["gax_profile"] == P1_PROFILE
    assert o["profile"] == LIFECYCLE_ID and o["package_digest"] == ANCHOR["current"]
    assert o["verdict"] == "REFUSE" and o["grant"] is None and o["reason"] in {"GAX-RELIANCE-ODES-FAIL", "GAX-RELIANCE-INDETERMINATE"}, o
    # ITERATION 4 (post-hoc, openly): iteration 3 wrongly predicted the old evaluator rejects the unknown id. Observed: 1e226128 does NOT recognize the profile (no
    # replay_semantic_consistency layer is produced) yet its final native status is pass when the policy lists the id. The refusal comes from the GAX gate's own requirement
    # that replay_semantic_consistency be present and pass. That requirement is therefore load-bearing for old-pin safety.
    assert "replay_semantic_consistency" not in o["raw"], o["raw"]
    assert o["reason"] == "GAX-RELIANCE-INDETERMINATE" and "replay_semantic_consistency" in o["detail"], o
