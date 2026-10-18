"""Strict source check: every tracked file of a checked checkout is compared with its revision, not only the entry modules.

A module that an entry module imports is code that runs. The loader therefore compares every tracked file of each checked
checkout with the blob recorded at its revision and refuses index flags that hide differences from ``git status``
(assume-unchanged, skip-worktree). Anything it cannot compare is refused. Clean checkouts, with or without sibling
modules, still load.
"""
import subprocess
import sys

import pytest

from test_exchange_input_and_source_repairs import _git, _planted, fake_checkouts, runtime  # noqa: F401

SIBLING = "src/agent_replay_bundle/helper_module.py"
OUTSIDE = "tools/helper_script.py"


def _commit_siblings(roots):
    """Add a tracked sibling module imported by the replay entry module, and a tracked file outside the package."""
    repo = roots["replay"]
    pkg = repo / "src/agent_replay_bundle"
    (pkg / "helper_module.py").write_text("SAFE = True\n")
    entry = pkg / "importers.py"
    entry.write_text("from . import helper_module\n" + entry.read_text())
    (repo / "tools").mkdir()
    (repo / OUTSIDE).write_text("SAFE = True\n")
    _git(repo, "add", "-A")
    _git(repo, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "-m", "siblings")
    runtime.REPLAY_REVISION = _git(repo, "rev-parse", "HEAD")


def test_clean_checkout_with_sibling_modules_loads(fake_checkouts, monkeypatch):
    roots, marker = fake_checkouts
    monkeypatch.setattr(runtime, "REPLAY_REVISION", runtime.REPLAY_REVISION)
    _commit_siblings(roots)
    runtime.load_executor_runtime()
    assert "agent_replay_bundle.helper_module" in sys.modules
    assert not marker.exists()


def test_modified_sibling_module_is_refused(fake_checkouts, monkeypatch):
    roots, marker = fake_checkouts
    monkeypatch.setattr(runtime, "REPLAY_REVISION", runtime.REPLAY_REVISION)
    _commit_siblings(roots)
    (roots["replay"] / SIBLING).write_text(_planted(marker))
    with pytest.raises(RuntimeError, match="candidate source identity mismatch"):
        runtime.load_executor_runtime()
    assert not marker.exists()


@pytest.mark.parametrize("flag", ["--assume-unchanged", "--skip-worktree"])
@pytest.mark.parametrize("target", [SIBLING, OUTSIDE])
def test_flagged_modified_file_is_refused_before_it_runs(fake_checkouts, monkeypatch, flag, target):
    roots, marker = fake_checkouts
    monkeypatch.setattr(runtime, "REPLAY_REVISION", runtime.REPLAY_REVISION)
    _commit_siblings(roots)
    _git(roots["replay"], "update-index", flag, target)
    (roots["replay"] / target).write_text(_planted(marker))
    assert _git(roots["replay"], "status", "--porcelain", "--untracked-files=no") == ""
    with pytest.raises(RuntimeError, match="candidate source identity mismatch"):
        runtime.load_executor_runtime()
    assert not marker.exists()
    assert "agent_replay_bundle.helper_module" not in sys.modules


def test_flagged_unmodified_file_is_refused(fake_checkouts, monkeypatch):
    roots, _marker = fake_checkouts
    monkeypatch.setattr(runtime, "REPLAY_REVISION", runtime.REPLAY_REVISION)
    _commit_siblings(roots)
    _git(roots["replay"], "update-index", "--assume-unchanged", SIBLING)
    with pytest.raises(RuntimeError, match="candidate source identity mismatch"):
        runtime.load_executor_runtime()


def test_deleted_flagged_sibling_is_refused(fake_checkouts, monkeypatch):
    roots, _marker = fake_checkouts
    monkeypatch.setattr(runtime, "REPLAY_REVISION", runtime.REPLAY_REVISION)
    _commit_siblings(roots)
    _git(roots["replay"], "update-index", "--assume-unchanged", SIBLING)
    (roots["replay"] / SIBLING).unlink()
    with pytest.raises(RuntimeError, match="candidate source identity mismatch"):
        runtime.load_executor_runtime()


def test_file_the_check_cannot_compare_is_refused(fake_checkouts, monkeypatch):
    roots, _marker = fake_checkouts
    monkeypatch.setattr(runtime, "REPLAY_REVISION", runtime.REPLAY_REVISION)
    _commit_siblings(roots)
    repo = roots["replay"]
    _git(repo, "update-index", "--add", "--cacheinfo", "160000," + _git(repo, "rev-parse", "HEAD") + ",vendored")
    _git(repo, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "-m", "gitlink")
    runtime.REPLAY_REVISION = _git(repo, "rev-parse", "HEAD")
    with pytest.raises(RuntimeError, match="candidate source identity mismatch"):
        runtime.load_executor_runtime()
