"""Shared fixtures for the authenticated-source (Exchange-1, item 5) and authoritative-manifest (item 4) tests.

STUB-BASED: the pinned packages are tiny throwaway Git repositories whose Control Plane stub captures the manifest it is given.
The real pinned stack is exercised separately in ``test_real_pinned_stack.py`` (opt-in, needs the checkouts).
"""
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

TOP = ("agent_control_plane", "engine", "agent_replay_bundle", "odes", "agent_governance_evidence_pack")
GOOD_MANIFEST = '{"manifest": "verified-good", "n": 1}\n'
EVIL_MANIFEST = '{"manifest": "ATTACKER-DIFFERENT", "n": 1}\n'
TYPED = "typed-refusal-candidate-20261015"

CP_STUB = '''
class Captured(Exception):
    def __init__(self, manifest): self.manifest = manifest
class _K:
    def __init__(self, *a, **k): self.args = a; self.__dict__.update(k)
class RuntimeProposal(_K):
    @classmethod
    def model_validate(cls, raw):
        o = cls(**raw); o._raw = dict(raw); return o
    def model_dump(self, mode="json", exclude_none=False): return dict(self._raw)
ApprovalStatus = ConflictStatus = EffectObservation = EvidenceStatus = GrantStatus = IdentityStatus = _K
MandateStatus = PolicyStatus = RoleMappingStatus = SyntheticResolver = ObservationPolicy = _K
import json, hashlib
def commitment(v): return "sha256:" + hashlib.sha256(json.dumps(v, sort_keys=True, default=str).encode()).hexdigest()
class BoundedRecordStore(_K): pass
class LocalRefundDestination(_K): pass
class BoundedAuthorizationWorkflow:
    def __init__(self, **kw): raise Captured(kw.get("manifest"))
MARK = "stub-control-plane"
'''
RT_STUB = '''
EXECUTOR_PRODUCER_PROFILE_ID = 'urn:cognous:profiles:moltbot-safe-executor-producer'
EXECUTOR_PRODUCER_PROFILE_VERSION = '2.0.0'
class _K:
    def __init__(self, *a, **k): self.root = a[0] if a else None
class LocalExecutionPolicy(_K): pass
PinnedControlPlaneExecutor = DurableRefundDestination = ExecutionEnvelope = ExecutionOperation = _K
def commitment(v): return 'x'
def export_execution_artifacts(*a, **k): return {}
'''
MODULES = {
    "control_plane": ("src/agent_control_plane", "bounded", CP_STUB),
    "runtime": ("engine", "producer_contract", RT_STUB),
    "replay": ("src/agent_replay_bundle", "importers", "PLANTED = False\n"),
    "odes": ("src/odes", "exporter", "PLANTED = False\n"),
    "pack": ("src/agent_governance_evidence_pack", "importer", "PLANTED = False\n"),
}
BUNDLE = {"run_id": "run-1", "records": [{"record_type": "runtime_proposal", "data": {
    "action_id": "refund.issue", "target": "urn:cognous:synthetic-account:customer-001", "payload": {"a": 1},
    "amount": 10.0, "unit": "USD", "actor": "a", "principal": "p", "adapter_id": "ad", "requested_permissions": ["x"],
    "authority_context_ref": "urn:ctx", "requirement_id": "r", "evidence_refs": [], "effects": 1, "run_id": "run-1",
    "manifest_id": "m", "manifest_version": "1", "manifest_digest": "d"}}]}


def git(path, *args, env=None):
    return subprocess.check_output(["git", "-C", str(path), *args], text=True, env=env).strip()


def commit_all(path, msg="fixture"):
    git(path, "add", "-A")
    git(path, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "-m", msg)
    return git(path, "rev-parse", "HEAD")


def make_repo(path, files):
    for name, text in files.items():
        target = path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
    subprocess.check_call(["git", "init", "-q", str(path)])
    return commit_all(path)


def plant(marker):
    return f"from pathlib import Path\nPath({str(marker)!r}).write_text('ran-at-import')\n"


def registry():
    return base.LocalRegistry({"refund-sender"}, {"refund-recipient"}, "refund-recipient")


def _purge():
    for name in [m for m in sys.modules if m.split(".")[0] in TOP]:
        sys.modules.pop(name, None)


def _world(profile, tmp_path, monkeypatch):
    roots, revs = {}, {}
    for key, (pkg, mod, body) in MODULES.items():
        roots[key] = tmp_path / key
        revs[key] = make_repo(roots[key], {f"{pkg}/__init__.py": "", f"{pkg}/{mod}.py": body})
    mroot = tmp_path / "manifest"
    revs["manifest"] = make_repo(mroot, {"examples/m.json": GOOD_MANIFEST, "examples/other.json": '{"other": true}\n'})
    for key in ("replay", "odes", "pack"):
        monkeypatch.syspath_prepend(str(roots[key] / "src"))   # ambient, mutable checkouts on the path (PYTHONPATH-style)
    monkeypatch.setattr(sys, "path", list(sys.path))
    _purge()
    monkeypatch.setattr(runtime, "RUNTIME_COMPATIBILITY_PROFILE", profile)
    for attr, key in (("CP_REVISION", "control_plane"), ("MOLTBOT_REVISION", "runtime"), ("REPLAY_REVISION", "replay"),
                      ("ODES_REVISION", "odes"), ("EVIDENCE_PACK_REVISION", "pack"), ("MANIFEST_REVISION", "manifest")):
        monkeypatch.setattr(runtime, attr, revs[key])
    monkeypatch.setenv("MOLTBOT_SAFE_CONTROL_PLANE_ROOT", str(roots["control_plane"]))
    monkeypatch.setenv("MOLTBOT_SAFE_ROOT", str(roots["runtime"]))
    monkeypatch.setenv("UPSTREAM_MANIFEST_EXAMPLE", str(mroot / "examples/m.json"))
    monkeypatch.delenv("GAX_AUTHENTICATED_MANIFEST_SHA256", raising=False)
    yield {"roots": roots, "revs": revs, "mroot": mroot, "manifest_file": mroot / "examples/m.json", "tmp": tmp_path,
           "profile": profile, "marker": tmp_path / "marker"}
    _purge()


@pytest.fixture(params=sorted(runtime.STRICT_SOURCE_PROFILES))
def world(request, tmp_path, monkeypatch):
    """Every strict profile (the security-critical scenarios)."""
    yield from _world(request.param, tmp_path, monkeypatch)


@pytest.fixture(params=[TYPED, "security-runtime-current-20261031-r3"])
def world2(request, tmp_path, monkeypatch):
    """The non-security strict profile and the newest security profile (secondary scenarios; the code path is shared)."""
    yield from _world(request.param, tmp_path, monkeypatch)


def exchange_kwargs(world, manifest):
    security = world["profile"] in runtime.SECURITY_RUNTIME_PROFILES
    return dict(evaluation_time=base.EVAL, manifest=manifest, store_path=world["tmp"] / "ex.sqlite", resolver=object(),
                execution_policy_factory=lambda o: o, observation_policy=object(),
                runtime_authority_profile=object() if security else None)


def consumed_by_workflow(fn):
    """('consumed', manifest) if the stub workflow was built, ('refused', exc) if the Exchange refused, else ('ran', None)."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        if type(exc).__name__ == "Captured":
            return "consumed", exc.manifest
        return "refused", exc
    return "ran", None


GOOD = json.loads(GOOD_MANIFEST)
EVIL = json.loads(EVIL_MANIFEST)
