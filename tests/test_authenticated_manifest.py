"""P1 Exchange-1 item 4 (csf_60ebe90ffb63af98a867e323): authoritative manifest. Stub-based; see authenticated_world.py."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from experiments.odex_gax_imx_reference import authenticated_source as auth
from experiments.odex_gax_imx_reference import gax_ref as base
from experiments.odex_gax_imx_reference import gax_ref_runtime as runtime
from authenticated_world import *  # noqa: F401,F403  (fixtures and helpers)
from authenticated_world import _world  # noqa: F401

# =====================================================================================================================
# Item 4 (csf_60ebe90f): authoritative manifest
# =====================================================================================================================
def test_valid_immutable_positive(world):
    loaded = runtime.load_executor_runtime()
    assert loaded
    m = runtime.authenticated_manifest()
    assert m.value["manifest"] == "verified-good"
    with pytest.raises(TypeError):
        m.value["manifest"] = "x"                                   # read-only view
    with pytest.raises(AttributeError):
        m.digest = "sha256:0"                                       # immutable object
    first, second = m.to_dict(), m.to_dict()
    first["manifest"] = "mutated"
    assert second == GOOD and m.to_dict() == GOOD                   # every consumer gets an independent copy
    assert m.sha256 == "sha256:" + __import__("hashlib").sha256(GOOD_MANIFEST.encode()).hexdigest()
    assert m.digest == base.digest(GOOD)                            # same canonical digest the Exchange uses everywhere
    assert m.source_revision == world["revs"]["manifest"] and m.path == "examples/m.json"
    assert m.blob_id == git(world["mroot"], "rev-parse", "HEAD:examples/m.json")
    assert runtime.bind_manifest(GOOD) == GOOD and runtime.bind_manifest(None) == GOOD
    assert runtime.bind_manifest(GOOD) is not GOOD


def test_qualification_style_call_with_the_json_loaded_example_stays_green(world):
    """tests in the qualification repo do: manifest = json.loads(UPSTREAM_MANIFEST_EXAMPLE); run_exchange(manifest=manifest)."""
    manifest = json.loads(Path(os.environ["UPSTREAM_MANIFEST_EXAMPLE"]).read_text(encoding="utf-8"))
    msg = base.make_message(BUNDLE)
    kind, seen = consumed_by_workflow(lambda: runtime.run_exchange(msg, BUNDLE, registry(), object(), **exchange_kwargs(world, manifest)))
    assert kind == "consumed" and seen == GOOD and seen is not manifest


@pytest.mark.parametrize("caller", [EVIL, {}, {"manifest": "verified-good"}, {"manifest": "verified-good", "n": 1, "x": 1},
                                    {"manifest": "verified-good", "n": 1.0}, {"manifest": "verified-good", "n": True},
                                    {"manifest": "verified-good", "n": "1"}, {"manifest": "verified-good", "n": [1]}, [1]])
def test_caller_manifest_mismatch_is_refused_not_preferred(world, caller):
    msg = base.make_message(BUNDLE)
    kind, val = consumed_by_workflow(lambda: runtime.run_exchange(msg, BUNDLE, registry(), object(), **exchange_kwargs(world, caller)))
    assert kind == "refused" and isinstance(val, auth.ManifestMismatchError), (kind, val)


def test_caller_manifest_that_is_not_json_is_refused(world2):
    runtime.load_executor_runtime()
    for bad in (float("nan"), object(), {"manifest": "verified-good", "n": float("inf")}, {1: 2}):
        with pytest.raises(auth.ManifestMismatchError):
            runtime.bind_manifest(bad if isinstance(bad, dict) else {"x": bad})


def test_semantic_equality_and_digest_equality_are_both_required(world2):
    runtime.load_executor_runtime()
    m = runtime.authenticated_manifest()
    reordered = {"n": 1, "manifest": "verified-good"}               # same canonical form, different key order: accepted
    m.require_caller_manifest(reordered)
    class Trap(dict):                                               # == the authenticated value but a different type
        pass
    with pytest.raises(auth.ManifestMismatchError, match="semantically"):
        m.require_caller_manifest(Trap(GOOD))
    # digest equality is checked independently of semantic equality: force a canonical-digest disagreement
    fake = auth.AuthenticatedManifest(source_revision=m.source_revision, repo=m.repo, path=m.path, blob_id=m.blob_id, raw=m.raw)
    object.__setattr__(fake, "digest", "sha256:" + "0" * 64)
    with pytest.raises(auth.ManifestMismatchError, match="digest differs"):
        fake.require_caller_manifest(dict(GOOD))


def test_wrong_digest_binding_is_refused_and_the_right_one_accepted(world2, monkeypatch):
    good = "sha256:" + __import__("hashlib").sha256(GOOD_MANIFEST.encode()).hexdigest()
    monkeypatch.setenv("GAX_AUTHENTICATED_MANIFEST_SHA256", "sha256:" + "0" * 64)
    with pytest.raises(RuntimeError, match="candidate source identity mismatch: manifest"):
        runtime.load_executor_runtime()
    monkeypatch.setenv("GAX_AUTHENTICATED_MANIFEST_SHA256", good)
    runtime.load_executor_runtime()
    assert runtime.authenticated_manifest().sha256 == good


def test_manifest_at_another_revision_or_path_not_in_the_revision_is_refused(world2, monkeypatch):
    other = make_repo(world2["tmp"] / "m2", {"examples/m.json": EVIL_MANIFEST})
    monkeypatch.setattr(runtime, "MANIFEST_REVISION", other)           # revision of a different history
    with pytest.raises(RuntimeError, match="candidate source identity mismatch: manifest"):
        runtime.load_executor_runtime()
    monkeypatch.setattr(runtime, "MANIFEST_REVISION", world2["revs"]["manifest"])
    new = world2["mroot"] / "examples/untracked-but-present.json"
    new.write_text(GOOD_MANIFEST)
    monkeypatch.setenv("UPSTREAM_MANIFEST_EXAMPLE", str(new))
    with pytest.raises(RuntimeError, match="candidate source identity mismatch: manifest"):
        runtime.load_executor_runtime()                              # present on disk, not in the pinned revision


def test_dirty_manifest_is_refused(world):
    world["manifest_file"].write_text(EVIL_MANIFEST)
    with pytest.raises(RuntimeError, match="candidate source identity mismatch: manifest"):
        runtime.load_executor_runtime()


@pytest.mark.parametrize("flag", ["--assume-unchanged", "--skip-worktree"])
def test_index_flag_hiding_a_modified_manifest_is_refused(world2, flag):
    git(world2["mroot"], "update-index", flag, "examples/m.json")
    world2["manifest_file"].write_text(EVIL_MANIFEST)
    assert git(world2["mroot"], "status", "--porcelain", "--untracked-files=no") == ""
    with pytest.raises(RuntimeError, match="candidate source identity mismatch: manifest"):
        runtime.load_executor_runtime()


def test_equivalent_looking_but_byte_different_manifest_is_refused(world2):
    world2["manifest_file"].write_text(json.dumps(GOOD, indent=2) + "\n")        # same semantics, different bytes
    assert json.loads(world2["manifest_file"].read_text()) == GOOD
    with pytest.raises(RuntimeError, match="candidate source identity mismatch: manifest"):
        runtime.load_executor_runtime()
    world2["manifest_file"].write_bytes(GOOD_MANIFEST.encode().replace(b"\n", b"\r\n"))
    with pytest.raises(RuntimeError, match="candidate source identity mismatch: manifest"):
        runtime.load_executor_runtime()                              # no line-ending leniency for the manifest


def test_manifest_with_duplicate_keys_or_nonfinite_numbers_is_refused(world2):
    for text in ('{"a": 1, "a": 2}\n', '{"a": NaN}\n', '{"a": 1e999}\n', '[1]\n'):
        sub = world2["tmp"] / ("m-" + str(abs(hash(text))))
        rev = make_repo(sub, {"examples/m.json": text})
        os.environ["UPSTREAM_MANIFEST_EXAMPLE"] = str(sub / "examples/m.json")
        runtime.MANIFEST_REVISION = rev
        with pytest.raises(RuntimeError, match="candidate source identity mismatch: manifest"):
            runtime.load_executor_runtime()


@pytest.mark.parametrize("mode", ["mutate_in_place", "rename_swap", "symlink_retarget"])
def test_manifest_mutated_swapped_or_retargeted_after_verification_is_never_consumed(world2, monkeypatch, mode):
    mf = world2["manifest_file"]
    link = world2["tmp"] / "link.json"
    if mode == "symlink_retarget":
        link.symlink_to(mf)
        monkeypatch.setenv("UPSTREAM_MANIFEST_EXAMPLE", str(link))     # symlinked path: resolved once, at verification
    runtime.load_executor_runtime()                                    # verification passes on the clean pinned file
    if mode == "mutate_in_place":
        mf.write_text(EVIL_MANIFEST)
    elif mode == "rename_swap":
        tmp_file = world2["tmp"] / "evil.json"
        tmp_file.write_text(EVIL_MANIFEST)
        os.replace(tmp_file, mf)
    else:
        evil = world2["tmp"] / "evil.json"
        evil.write_text(EVIL_MANIFEST)
        link.unlink()
        link.symlink_to(evil)
    seen = {}
    monkeypatch.setattr(runtime, "export_odes_reference", lambda manifest, bundle: seen.setdefault("m", manifest) and {"odes_package": {}})
    runtime.execution_facts({})                                        # public helper that used to reopen the mutable path
    assert seen["m"] == GOOD, f"consumed {seen['m']!r}"
    assert runtime._manifest() == GOOD
    if mode != "symlink_retarget":
        with pytest.raises(RuntimeError, match="candidate source identity mismatch: manifest"):
            runtime.load_executor_runtime()                            # the next authentication refuses the changed file
    else:
        with pytest.raises(RuntimeError, match="candidate source identity mismatch: manifest"):
            runtime.load_executor_runtime()                            # retargeted to a path outside any pinned checkout


def test_symlinked_manifest_path_to_a_file_outside_a_checkout_is_refused(world2, monkeypatch):
    evil = world2["tmp"] / "evil.json"
    evil.write_text(EVIL_MANIFEST)
    link = world2["mroot"] / "examples" / "link.json"
    link.symlink_to(evil)
    monkeypatch.setenv("UPSTREAM_MANIFEST_EXAMPLE", str(link))
    with pytest.raises(RuntimeError, match="candidate source identity mismatch: manifest"):
        runtime.load_executor_runtime()


def test_execution_receives_the_authenticated_manifest_not_the_caller_object(world2):
    msg = base.make_message(BUNDLE)
    caller = json.loads(GOOD_MANIFEST)
    kind, seen = consumed_by_workflow(lambda: runtime.run_exchange(msg, BUNDLE, registry(), object(), **exchange_kwargs(world2, caller)))
    assert kind == "consumed" and seen == GOOD and seen is not caller
    assert base.digest(seen) == runtime.authenticated_manifest().digest


def test_run_exchange_with_no_caller_manifest_uses_the_authenticated_one(world2):
    msg = base.make_message(BUNDLE)
    kind, seen = consumed_by_workflow(lambda: runtime.run_exchange(msg, BUNDLE, registry(), object(), **exchange_kwargs(world2, None)))
    assert kind == "consumed" and seen == GOOD


def test_run_actual_outcome_reads_no_manifest_before_verification(world, monkeypatch):
    """Base read the path first and verified afterwards; a file restored in between authorized with the dirty read."""
    if world["profile"] != TYPED:
        pytest.skip("run_actual_outcome calls run_exchange without runtime_authority_profile: usable only under the typed-refusal profile")
    mf = world["manifest_file"]
    bundle_file = world["tmp"] / "bundle.json"
    bundle_file.write_text(json.dumps(BUNDLE))
    monkeypatch.setenv("UPSTREAM_REPLAY_SUCCESS_EXAMPLE", str(bundle_file))
    mf.write_text(EVIL_MANIFEST)
    real = base.runtime_proposal_model

    def restore_then_proceed(bundle):
        git(world["mroot"], "checkout", "--", ".")
        return real(bundle)

    monkeypatch.setattr(runtime, "runtime_proposal_model", restore_then_proceed)
    kind, val = consumed_by_workflow(lambda: runtime.run_actual_outcome(world["tmp"], "success"))
    assert kind == "refused" and "candidate source identity mismatch" in str(val)   # the dirty file is refused up front


def test_run_demo_manifest_argument_is_only_a_compatibility_input(world):
    if world["profile"] != TYPED:
        pytest.skip("run_demo calls run_exchange without runtime_authority_profile: usable only under the typed-refusal profile")
    other = world["tmp"] / "other-manifest.json"
    other.write_text(EVIL_MANIFEST)
    bundle_file = world["tmp"] / "bundle.json"
    bundle_file.write_text(json.dumps(BUNDLE))
    kind, val = consumed_by_workflow(lambda: runtime.run_demo(str(other), str(bundle_file), str(world["tmp"] / "out.json")))
    assert kind == "refused" and isinstance(val, auth.ManifestMismatchError)
    equal = world["tmp"] / "equal-manifest.json"                       # not in any git repository, but equal: accepted
    equal.write_text(json.dumps(GOOD))
    kind, val = consumed_by_workflow(lambda: runtime.run_demo(str(equal), str(bundle_file), str(world["tmp"] / "out.json")))
    assert kind == "consumed" and val == GOOD


def test_resume_original_exchange_binds_the_manifest_before_reading_the_store(world2):
    msg = base.make_message(BUNDLE)
    security = world2["profile"] in runtime.SECURITY_RUNTIME_PROFILES
    with pytest.raises(auth.ManifestMismatchError):
        runtime.resume_original_exchange(
            msg, manifest=EVIL, store_path=world2["tmp"] / "r.sqlite", destination=None, resolver=None,
            execution_policy_factory=None, observation_policy=object(), evaluation_time=base.EVAL,
            runtime_authority_profile=object() if security else None)
    assert not (world2["tmp"] / "r.sqlite").exists()


def test_odes_export_helper_refuses_a_foreign_manifest(world2, monkeypatch):
    """export_odes_reference is public: under a strict profile it, too, accepts only the authenticated manifest."""
    runtime.load_executor_runtime()
    odes = sys.modules["odes"]
    odes.evaluate_recipient_package = lambda package, policy: {"ok": True}
    odes.export_cognous_stack_package = lambda manifest, bundle, **kw: {"profile": {"implementation_profile": "p"}, "seen": manifest}
    with pytest.raises(auth.ManifestMismatchError):
        runtime.export_odes_reference(EVIL, {})
    exported = runtime.export_odes_reference(dict(GOOD), {})
    assert exported["odes_package"]["seen"] == GOOD
