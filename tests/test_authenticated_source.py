"""P1 Exchange-1 item 5 (csf_756af34ecc888ea2498a506c): authenticated source and loader ordering. Stub-based; see authenticated_world.py."""
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
# Item 5 (csf_756af34e): authenticated source, loader ordering, every entry point
# =====================================================================================================================
def dirty_cp(world):
    f = world["roots"]["control_plane"] / "src/agent_control_plane/bounded.py"
    f.write_text(plant(world["marker"]) + f.read_text())


def test_positive_imports_come_from_a_private_readonly_copy_of_the_authenticated_bytes(world):
    loaded = runtime.load_executor_runtime()
    cp_file = Path(loaded["cp"].__file__).resolve()
    live = world["roots"]["control_plane"] / "src/agent_control_plane/bounded.py"
    assert cp_file != live.resolve() and cp_file.read_bytes() == live.read_bytes()
    root = auth.verified_root("agent_control_plane")
    assert cp_file.is_relative_to(root)
    assert cp_file.stat().st_mode & 0o222 == 0                     # read-only (mode bits; root bypasses os.access)
    private = root.parent                                           # the per-process private root
    assert (private.stat().st_mode & 0o777) == 0o700
    for top in TOP:                                                # every pinned module lives under its detached copy
        for name, module in list(sys.modules.items()):
            if name == top or name.startswith(top + "."):
                assert Path(module.__file__).resolve().is_relative_to(auth.verified_root(top))
    detached = [i for i, p in enumerate(sys.path) if p.startswith(str(private))]
    live = [i for i, p in enumerate(sys.path) if any(p.startswith(str(world["roots"][k])) for k in world["roots"])]
    assert len(detached) == 5 and (not live or max(detached) < min(live))   # authenticated roots shadow any ambient checkout
    assert str(world["roots"]["control_plane"] / "src") not in sys.path and str(world["roots"]["runtime"]) not in sys.path
    assert sys.pycache_prefix is None or "gax-pycache" not in str(sys.pycache_prefix)   # the private prefix is scoped to the import


def test_loader_starts_no_git_process_and_no_repository_controlled_helper(world2, monkeypatch):
    marker = world2["marker"]
    for key in ("control_plane", "replay"):                         # hostile repository configuration, hooks and filters
        root = world2["roots"][key]
        helper = f"sh -c 'echo ran > {marker}'"
        git(root, "config", "core.fsmonitor", helper)
        git(root, "config", "filter.x.clean", helper)
        git(root, "config", "filter.x.smudge", helper)
        git(root, "config", "core.hooksPath", str(world2["tmp"] / "hooks"))
        git(root, "config", "diff.external", helper)
        (root / ".git" / "objects" / "info" / "alternates").write_text(str(world2["tmp"] / "nonexistent") + "\n")
    calls = []
    real_run, real_popen = subprocess.run, subprocess.Popen
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: calls.append(a) or real_run(*a, **k))
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: calls.append(a) or real_popen(*a, **k))
    monkeypatch.setattr(subprocess, "check_output", lambda *a, **k: calls.append(a) or pytest.fail("git process"))
    runtime.load_executor_runtime()
    assert calls == [] and not marker.exists()


def test_wrong_revision_is_refused_before_anything_executes(world):
    sys.modules.pop("agent_control_plane", None)
    runtime.CP_REVISION = "0" * 40
    with pytest.raises(RuntimeError, match="candidate source identity mismatch: agent_control_plane.bounded"):
        runtime.load_executor_runtime()
    assert not world["marker"].exists() and "agent_control_plane" not in sys.modules


def test_dirty_checkout_is_refused_before_it_executes(world):
    dirty_cp(world)
    with pytest.raises(RuntimeError, match="candidate source identity mismatch: agent_control_plane.bounded"):
        runtime.load_executor_runtime()
    assert not world["marker"].exists() and "agent_control_plane" not in sys.modules


@pytest.mark.parametrize("flag", ["--assume-unchanged", "--skip-worktree"])
def test_index_flags_cannot_hide_a_modified_source_file(world2, flag):
    git(world2["roots"]["replay"], "update-index", flag, "src/agent_replay_bundle/importers.py")
    (world2["roots"]["replay"] / "src/agent_replay_bundle/importers.py").write_text(plant(world2["marker"]))
    assert git(world2["roots"]["replay"], "status", "--porcelain", "--untracked-files=no") == ""
    with pytest.raises(RuntimeError, match="candidate source identity mismatch: agent_replay_bundle.importers"):
        runtime.load_executor_runtime()
    assert not world2["marker"].exists()


def test_shadow_import_is_never_executed_and_the_authenticated_module_wins(world):
    """A planted package of a pinned name, earlier on the ambient path than anything else, never runs: Control Plane and
    runtime are located by their configured roots, and every pinned import is served from the authenticated copy that is
    first on sys.path."""
    shadow = world["tmp"] / "shadow"
    (shadow / "agent_control_plane").mkdir(parents=True)
    (shadow / "engine").mkdir()
    for pkg, mod in (("agent_control_plane", "bounded"), ("engine", "producer_contract")):
        (shadow / pkg / "__init__.py").write_text(plant(world["marker"]))
        (shadow / pkg / f"{mod}.py").write_text(plant(world["marker"]))
    sys.path.insert(0, str(shadow))
    loaded = runtime.load_executor_runtime()
    assert not world["marker"].exists()
    assert loaded["cp"].MARK == "stub-control-plane"
    for name in ("agent_control_plane.bounded", "engine.producer_contract"):
        assert Path(sys.modules[name].__file__).resolve().is_relative_to(auth.verified_root(name.split(".")[0]))


def test_ambient_shadow_of_a_located_package_is_refused_not_executed(world2):
    """Replay/ODES/Pack are located through the ambient finders; a shadow that wins the lookup is not a pinned checkout."""
    shadow = world2["tmp"] / "shadow"
    (shadow / "odes").mkdir(parents=True)
    (shadow / "odes/__init__.py").write_text(plant(world2["marker"]))
    (shadow / "odes/exporter.py").write_text(plant(world2["marker"]))
    sys.path.insert(0, str(shadow))
    with pytest.raises(RuntimeError, match="candidate source identity mismatch: odes.exporter"):
        runtime.load_executor_runtime()
    assert not world2["marker"].exists() and "odes" not in sys.modules


def test_preloaded_unverified_pinned_module_is_refused_without_executing_anything_else(world):
    """sys.modules poisoning: a pinned top-level name already imported from anywhere unverified is refused."""
    dirty_cp(world)
    sys.path.insert(0, str(world["roots"]["control_plane"] / "src"))
    sys.modules.pop("agent_control_plane", None)
    __import__("agent_control_plane.bounded")                       # the attacker/ambient import executes the marker...
    assert world["marker"].exists()
    world["marker"].unlink()
    git(world["roots"]["control_plane"], "checkout", "--", ".")     # ...then the checkout is restored to the pinned bytes
    assert "agent_control_plane" in sys.modules                    # but the poisoned module object is still loaded
    with pytest.raises(RuntimeError, match="candidate source identity mismatch: agent_control_plane.bounded"):
        runtime.load_executor_runtime()
    with pytest.raises(RuntimeError, match="candidate source identity mismatch"):
        base.make_message(BUNDLE)                                   # the ambient accessor cannot reach it either
    assert not world["marker"].exists()


def test_replaced_sys_modules_entry_after_a_good_load_is_refused(world2):
    runtime.load_executor_runtime()
    import types
    sys.modules["odes"] = types.ModuleType("odes")                 # poisoned object, no __file__
    with pytest.raises(RuntimeError, match="candidate source identity mismatch: odes.exporter"):
        runtime.load_executor_runtime()


def test_module_loaded_from_outside_the_authenticated_copy_is_refused(world2):
    runtime.load_executor_runtime()
    sub = sys.modules["agent_replay_bundle.importers"]
    live = world2["roots"]["replay"] / "src/agent_replay_bundle/importers.py"
    sub.__file__ = str(live)
    with pytest.raises(RuntimeError, match="candidate source identity mismatch: agent_replay_bundle.importers"):
        runtime.load_executor_runtime()


@pytest.mark.parametrize("entry", ["make_message", "assess_message", "runtime_proposal_model", "build_resolver",
                                   "run_exchange", "run_exchange_legacy", "resume_original_exchange", "run_actual_outcome",
                                   "run_demo", "synthetic_policy", "synthetic_observation_policy"])
def test_import_marker_never_executes_before_verification_at_any_entry_point(world, entry, monkeypatch):
    """Every entry point goes through the authenticated loader first: a dirty Control Plane on the ambient path never runs."""
    msg = base.make_message(BUNDLE)                                  # built from the clean authenticated stub
    sys.modules.pop("agent_control_plane", None)
    for n in [m for m in sys.modules if m.split(".")[0] in TOP]:
        sys.modules.pop(n)
    auth.forget_verified("agent_control_plane")
    sys.path.insert(0, str(world["roots"]["control_plane"] / "src"))   # ambient exposure of the mutable checkout
    dirty_cp(world)
    bundle_file = world["tmp"] / "bundle.json"
    bundle_file.write_text(json.dumps(BUNDLE))
    monkeypatch.setenv("UPSTREAM_REPLAY_SUCCESS_EXAMPLE", str(bundle_file))      # restored at teardown
    calls = {
        "make_message": lambda: base.make_message(BUNDLE),
        "assess_message": lambda: base.assess_message(msg, BUNDLE, registry(), evaluation_time=base.EVAL),
        "runtime_proposal_model": lambda: base.runtime_proposal_model(BUNDLE),
        "build_resolver": lambda: base._build_resolver(object()),
        "run_exchange": lambda: runtime.run_exchange(msg, BUNDLE, registry(), object(), **exchange_kwargs(world, GOOD)),
        "run_exchange_legacy": lambda: base.run_exchange(msg, BUNDLE, registry(), object(), evaluation_time=base.EVAL,
                                                         manifest=GOOD, store_path=world["tmp"] / "legacy.sqlite", resolver=object()),
        "resume_original_exchange": lambda: runtime.resume_original_exchange(
            msg, manifest=GOOD, store_path=world["tmp"] / "r.sqlite", destination=None, resolver=None,
            execution_policy_factory=None, observation_policy=object(), evaluation_time=base.EVAL,
            runtime_authority_profile=object() if world["profile"] in runtime.SECURITY_RUNTIME_PROFILES else None),
        "run_actual_outcome": lambda: runtime.run_actual_outcome(world["tmp"], "success"),
        "run_demo": lambda: runtime.run_demo(str(world["manifest_file"]), str(bundle_file), str(world["tmp"] / "out.json")),
        "synthetic_policy": lambda: __import__("experiments.odex_gax_imx_reference.synthetic_fixture", fromlist=["x"]).synthetic_refund_policy(None),
        "synthetic_observation_policy": lambda: __import__("experiments.odex_gax_imx_reference.synthetic_fixture", fromlist=["x"]).synthetic_observation_policy(),
    }
    with pytest.raises(Exception) as caught:
        calls[entry]()
    assert not world["marker"].exists(), f"{entry}: dirty Control Plane executed before verification"
    assert isinstance(caught.value, (RuntimeError, ValueError)), repr(caught.value)


def test_make_message_alone_executes_only_the_authenticated_stub(world2):
    dirty_cp(world2)
    sys.path.insert(0, str(world2["roots"]["control_plane"] / "src"))
    with pytest.raises(RuntimeError, match="candidate source identity mismatch"):
        base.make_message(BUNDLE)
    assert not world2["marker"].exists()


def test_module_executed_while_dirty_cannot_be_laundered_by_restoring_the_file(world2):
    """The pre-P1 gap: dirty code stayed in sys.modules and passed once the file was restored."""
    f = world2["roots"]["control_plane"] / "src/agent_control_plane/bounded.py"
    clean = f.read_text()
    sys.path.insert(0, str(f.parent.parent))
    f.write_text(plant(world2["marker"]) + "POISONED = True\n" + clean)
    with pytest.raises(RuntimeError):
        base.make_message(BUNDLE)                                   # never imports the dirty file
    assert not world2["marker"].exists()
    f.write_text(clean)
    git(world2["roots"]["control_plane"], "checkout", "--", ".")
    loaded = runtime.load_executor_runtime()
    assert not hasattr(loaded["cp"], "POISONED") and loaded["cp"].MARK == "stub-control-plane"


def test_downstream_git_view_of_the_authenticated_copy_is_the_pinned_revision_and_clean(world2):
    """ODES and the Evidence Pack qualify the Replay copy with git at its import location; the copy must look pinned+clean."""
    runtime.load_executor_runtime()
    for top, key in (("agent_replay_bundle", "replay"), ("agent_control_plane", "control_plane"), ("odes", "odes")):
        package_dir = Path(sys.modules[top].__file__).parent
        assert git(package_dir, "rev-parse", "HEAD") == world2["revs"][key]
        assert git(package_dir, "status", "--porcelain", "--untracked-files=no") == ""
        assert git(package_dir, "rev-parse", "--is-inside-work-tree") == "true"


def test_repeated_loads_reuse_the_authenticated_copy(world2):
    first = runtime.load_executor_runtime()["cp"]
    second = runtime.load_executor_runtime()["cp"]
    assert first is second and runtime.pinned_module("agent_control_plane.bounded") is first


def test_default_profile_keeps_ambient_import_and_mutable_checkout_path(monkeypatch, tmp_path):
    """Compatibility: outside strict profiles nothing changes (no authentication, ambient import, caller manifest used)."""
    monkeypatch.setattr(runtime, "RUNTIME_COMPATIBILITY_PROFILE", "persistence-v1")
    caller = {"anything": [1, 2]}
    assert runtime.bind_manifest(caller) is caller
    with pytest.raises(RuntimeError, match="only under a strict"):
        runtime.authenticated_manifest()
    assert runtime.pinned_module("json") is sys.modules["json"]


# ---- the reader itself ------------------------------------------------------------------------------------------------
def test_reader_authenticates_packed_and_delta_compressed_repositories(tmp_path):
    files = {f"f{i}.txt": ("line %d\n" % i) * 50 + "shared text\n" * 400 for i in range(12)}
    rev = make_repo(tmp_path / "r", files)
    (tmp_path / "r/f1.txt").write_text(files["f1.txt"] + "changed\n")
    rev = commit_all(tmp_path / "r")
    git(tmp_path / "r", "gc", "--aggressive", "--prune=now", "-q")
    assert not any((tmp_path / "r/.git/objects").glob("??/*"))      # everything is in packs now
    authenticated = auth.authenticate_commit(tmp_path / "r", rev)
    got = {rel: auth._ObjectStore(tmp_path / "r").read(blob, "blob") for _m, rel, blob in authenticated.entries}
    assert got["f1.txt"] == (files["f1.txt"] + "changed\n").encode() and set(got) == set(files)
    assert [e[1] for e in authenticated.entries] == sorted(files)


def test_reader_refuses_a_tampered_missing_or_foreign_object(tmp_path):
    rev = make_repo(tmp_path / "r", {"a.py": "x = 1\n"})
    blob = git(tmp_path / "r", "rev-parse", "HEAD:a.py")
    path = tmp_path / "r/.git/objects" / blob[:2] / blob[2:]
    os.chmod(path, 0o644)
    import zlib
    path.write_bytes(zlib.compress(b"blob 6\0x = 2\n"))             # valid zlib, wrong content for the id
    with pytest.raises(ValueError, match="not authentic"):
        auth.materialize(tmp_path / "r", rev)
    path.unlink()
    with pytest.raises(ValueError, match="missing"):
        auth.materialize(tmp_path / "r", rev)
    with pytest.raises(ValueError):
        auth.authenticate_commit(tmp_path / "r", "1" * 40)           # a commit the database does not hold
    with pytest.raises(ValueError):
        auth.authenticate_commit(tmp_path / "r", "HEAD")             # names are not revisions


def test_reader_refuses_gitfiles_alternates_submodules_and_symlinked_git_dirs(tmp_path):
    rev = make_repo(tmp_path / "r", {"a.py": "x = 1\n"})
    wt = tmp_path / "wt"
    wt.mkdir()
    (wt / ".git").write_text(f"gitdir: {tmp_path / 'r/.git'}\n")
    with pytest.raises(auth.SourceAuthenticationError, match="not a plain git directory"):
        auth.find_git_root(wt)
    clone = tmp_path / "clone"
    subprocess.check_call(["git", "clone", "-q", "--shared", str(tmp_path / "r"), str(clone)])
    with pytest.raises(ValueError, match="missing"):                 # objects only reachable through alternates are not read
        auth.materialize(clone, rev)
    sub = make_repo(tmp_path / "s", {"a.py": "x = 1\n"})
    git(tmp_path / "s", "update-index", "--add", "--cacheinfo", f"160000,{sub},vendored")
    git(tmp_path / "s", "-c", "user.name=t", "-c", "user.email=t@e.i", "commit", "-q", "-m", "gitlink")
    with pytest.raises(ValueError, match="mode 160000"):
        auth.authenticate_commit(tmp_path / "s", git(tmp_path / "s", "rev-parse", "HEAD"))


def test_reader_bounds_refuse_an_oversized_object(tmp_path, monkeypatch):
    rev = make_repo(tmp_path / "r", {"big.bin": "x" * 5000})
    monkeypatch.setattr(auth, "MAX_OBJECT_SIZE", 1000)
    with pytest.raises(ValueError):
        auth.materialize(tmp_path / "r", rev)


def test_index_flag_parser_matches_git(tmp_path):
    make_repo(tmp_path / "r", {"a.py": "1\n", "b/c.py": "2\n", "d.py": "3\n"})
    assert auth.index_flag_problems(tmp_path / "r") == []
    git(tmp_path / "r", "update-index", "--assume-unchanged", "a.py")
    git(tmp_path / "r", "update-index", "--skip-worktree", "b/c.py")
    got = sorted(auth.index_flag_problems(tmp_path / "r"))
    assert got == ["index flag hides modifications: a.py", "index flag hides modifications: b/c.py"]
    for version in ("4", "3"):
        git(tmp_path / "r", "update-index", "--index-version", version)
        assert sorted(auth.index_flag_problems(tmp_path / "r")) == got
    (tmp_path / "r/.git/index").write_bytes(b"garbage")
    assert auth.index_flag_problems(tmp_path / "r")


def test_synthesized_index_is_read_by_git_as_clean(tmp_path):
    rev = make_repo(tmp_path / "r", {"a.py": "1\n", "sub/b.py": "2\n", "run.sh": "#!/bin/sh\n"})
    os.symlink("a.py", tmp_path / "r/link.py")                      # git re-reads a racily clean symlink from its blob
    os.chmod(tmp_path / "r/run.sh", 0o755)
    git(tmp_path / "r", "update-index", "--chmod=+x", "run.sh")
    rev = commit_all(tmp_path / "r", "exec")
    copy = auth.materialize(tmp_path / "r", rev).path
    assert git(copy, "rev-parse", "HEAD") == rev
    assert git(copy, "status", "--porcelain") == ""
    assert git(copy, "ls-files", "-s").count("\n") == 3 and (copy / "link.py").is_symlink()
    assert (copy / "run.sh").stat().st_mode & 0o111 and not (copy / "a.py").stat().st_mode & 0o111


def test_identical_directories_share_one_tree_object_and_still_authenticate(tmp_path):
    """B1: two directories with identical content are ONE git tree object; that is a legitimate pinned commit."""
    rev = make_repo(tmp_path / "r", {"a/__init__.py": "", "b/__init__.py": "", "c/x/__init__.py": "", "c/y/__init__.py": ""})
    commit = auth.authenticate_commit(tmp_path / "r", rev)
    assert [e[1] for e in commit.entries] == ["a/__init__.py", "b/__init__.py", "c/x/__init__.py", "c/y/__init__.py"]
    assert (auth.materialize(tmp_path / "r", rev).path / "b/__init__.py").is_file()


def test_shared_subtree_bomb_is_still_bounded(tmp_path, monkeypatch):
    rev = make_repo(tmp_path / "r", {f"d{i}/f.py": "" for i in range(12)})
    monkeypatch.setattr(auth, "MAX_FILES", 5)
    with pytest.raises(ValueError, match="too many files"):
        auth.authenticate_commit(tmp_path / "r", rev)
    monkeypatch.setattr(auth, "MAX_FILES", 10_000)
    monkeypatch.setattr(auth, "MAX_TOTAL_TREE_ENTRIES", 8)
    with pytest.raises(ValueError, match="too many entries"):
        auth.authenticate_commit(tmp_path / "r", rev)


def test_refusal_message_carries_the_cause(world2, monkeypatch):
    def boom(*a, **k):
        raise ValueError("object missing or not authentic as a blob: deadbeef")
    monkeypatch.setattr(auth, "materialize", boom)
    with pytest.raises(RuntimeError, match=r"candidate source identity mismatch: .*\(ValueError: object missing"):
        runtime.load_executor_runtime()


def test_forked_child_exit_does_not_delete_the_parents_authenticated_copy(tmp_path):
    rev = make_repo(tmp_path / "r", {"a.py": "1\n"})
    copy = auth.materialize(tmp_path / "r", rev).path
    pid = os.fork()
    if pid == 0:
        try:
            auth._cleanup()
        finally:
            os._exit(0)
    os.waitpid(pid, 0)
    assert (copy / "a.py").is_file()
