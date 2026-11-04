"""Opt-in: the authenticated loader against the REAL pinned stack (no stubs).

Set ``GAX_REAL_STACK_ROOT`` to a directory holding clean checkouts ``control_plane``, ``runtime``, ``replay``, ``odes``,
``evidence_pack`` and ``manifest`` at the revisions of ``GAX_REAL_STACK_PROFILE`` (default
``security-runtime-current-20261031-r2``). Skipped otherwise. The checkouts are copied (``control_plane`` and ``manifest``)
or only read (the others); nothing in the given directory is modified. Each scenario runs in a fresh interpreter because the
profile is selected at import time.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = os.environ.get("GAX_REAL_STACK_ROOT")
PROFILE = os.environ.get("GAX_REAL_STACK_PROFILE", "security-runtime-current-20261031-r2")
REPO = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(not ROOT, reason="GAX_REAL_STACK_ROOT not set (real pinned checkouts unavailable)")

SCRIPT = textwrap.dedent('''
    import json, os, subprocess, sys
    from pathlib import Path
    stack = Path(os.environ["STACK"])
    for p in (stack / "replay/src", stack / "odes/src", stack / "evidence_pack/src", os.environ["EXCHANGE"]):
        sys.path.insert(0, str(p))
    from experiments.odex_gax_imx_reference import gax_ref_runtime as rt, gax_ref as base, authenticated_source as auth
    out = {}
    scenario = os.environ["SCENARIO"]
    if scenario == "positive":
        rt.load_executor_runtime()
        out["files"] = {top: sys.modules[top].__file__ for top in rt._TOP_LEVEL}
        out["heads"] = {top: subprocess.check_output(["git", "-C", os.path.dirname(sys.modules[top].__file__), "rev-parse", "HEAD"], text=True).strip() for top in rt._TOP_LEVEL}
        out["dirty"] = {top: subprocess.check_output(["git", "-C", os.path.dirname(sys.modules[top].__file__), "status", "--porcelain", "--untracked-files=no"], text=True).strip() for top in rt._TOP_LEVEL}
        from odes.common import installed_replay_revision, installed_replay_checkout_dirty
        out["replay_seen_by_odes"] = installed_replay_revision()
        out["replay_dirty_seen_by_odes"] = installed_replay_checkout_dirty()
        caller = json.loads(Path(os.environ["UPSTREAM_MANIFEST_EXAMPLE"]).read_text())
        out["bound_equals_caller"] = rt.bind_manifest(caller) == caller
        bundle = json.loads(Path(os.environ["UPSTREAM_REPLAY_SUCCESS_EXAMPLE"]).read_text())
        package = rt.export_odes_reference(caller, bundle)["odes_package"]       # real ODES export, qualifies Replay through git
        out["odes_package_profile"] = bool(package.get("profile"))
        out["make_message"] = base.make_message(bundle)["message_id"]
        try:
            rt.bind_manifest({**caller, "extra": 1})
            out["foreign_manifest"] = "accepted"
        except auth.ManifestMismatchError:
            out["foreign_manifest"] = "refused"
        out["manifest"] = rt.authenticated_manifest().identity()
    elif scenario == "dirty_cp":
        try:
            rt.load_executor_runtime()
            out["result"] = "accepted"
        except RuntimeError as exc:
            out["result"] = str(exc)
        out["marker"] = os.path.exists(os.environ["MARKER"])
        out["cp_loaded"] = "agent_control_plane" in sys.modules
    print("RESULT" + json.dumps(out))
''')


def run(scenario: str, stack: Path, **extra):
    env = {**os.environ, "STACK": str(stack), "EXCHANGE": str(REPO), "SCENARIO": scenario,
           "GAX_RUNTIME_COMPATIBILITY_PROFILE": PROFILE, "PYTHONDONTWRITEBYTECODE": "1",
           "MOLTBOT_SAFE_CONTROL_PLANE_ROOT": str(stack / "control_plane"), "MOLTBOT_SAFE_ROOT": str(stack / "runtime"),
           "UPSTREAM_MANIFEST_EXAMPLE": str(stack / "manifest/examples/refund_integration_v1_1.manifest.json"),
           "UPSTREAM_REPLAY_SUCCESS_EXAMPLE": str(stack / "replay/examples/bounded_success_reconstruction_v0_2.json"), **extra}
    done = subprocess.run([sys.executable, "-c", SCRIPT], env=env, capture_output=True, text=True, timeout=900, cwd=str(REPO))
    assert done.returncode == 0, done.stderr[-3000:]
    return json.loads(done.stdout.rsplit("RESULT", 1)[1])


def test_real_stack_loads_from_authenticated_copies_and_downstream_components_see_pinned_clean_git():
    stack = Path(ROOT)
    out = run("positive", stack)
    for top, file in out["files"].items():
        assert file.startswith(("/tmp/", os.environ.get("TMPDIR", "/tmp"))) and "gax-authenticated-" in file
        assert not Path(file).resolve().is_relative_to(stack.resolve())
    assert all(v == "" for v in out["dirty"].values()), out["dirty"]
    assert out["replay_seen_by_odes"] == out["heads"]["agent_replay_bundle"] and out["replay_dirty_seen_by_odes"] is False
    assert out["bound_equals_caller"] and out["odes_package_profile"] and out["foreign_manifest"] == "refused"
    assert out["manifest"]["path"] == "examples/refund_integration_v1_1.manifest.json"


def test_real_stack_dirty_control_plane_is_refused_before_it_executes(tmp_path):
    stack = tmp_path / "stack"
    stack.mkdir()
    for name in ("control_plane", "manifest"):
        shutil.copytree(Path(ROOT) / name, stack / name, symlinks=True)
    for name in ("runtime", "replay", "odes", "evidence_pack"):
        (stack / name).symlink_to(Path(ROOT) / name)
    marker = tmp_path / "marker"
    target = stack / "control_plane/src/agent_control_plane/bounded.py"
    target.write_text(f"from pathlib import Path\nPath({str(marker)!r}).write_text('ran')\n" + target.read_text())
    out = run("dirty_cp", stack, MARKER=str(marker))
    assert out["result"].startswith("candidate source identity mismatch: agent_control_plane.bounded")
    assert out["marker"] is False and out["cp_loaded"] is False
