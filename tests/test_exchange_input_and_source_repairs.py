"""Component-local regressions for F5b exchange repairs.

These run without sibling component checkouts: dependency packages are tiny
throwaway Git repositories and the proposal model is stubbed where a test only
needs the assessment stages before Control Plane evaluation.
"""
from __future__ import annotations

import importlib.machinery
import importlib.util
import py_compile
import subprocess
import sys
from pathlib import Path

import pytest

from experiments.odex_gax_imx_reference import gax_ref as base
from experiments.odex_gax_imx_reference import gax_ref_runtime as runtime


EVAL = "2026-08-08T01:00:00Z"
PROPOSAL = {
    "action_id": "refund_issue_routine", "target": "urn:t", "payload": {"x": 1},
    "amount": 1.0, "unit": "USD", "actor": "urn:a", "principal": "urn:p",
    "adapter_id": "adapter", "requested_permissions": ["refund.issue.routine"],
    "authority_context_ref": base.PROFILE_AUTH_CONTEXT,
}


class _Proposal:
    def model_dump(self, **_):
        return dict(PROPOSAL)


@pytest.fixture
def stub_proposal(monkeypatch):
    monkeypatch.setattr(base, "runtime_proposal_model", lambda bundle: _Proposal())
    monkeypatch.setattr(base, "proposal_commitment", lambda proposal=None, *, model=None: "sha256:" + "2" * 64)
    monkeypatch.setattr(base, "operation_commitment", lambda proposal=None, *, model=None: "sha256:" + "1" * 64)


def governed(message_id: str, *, sender: str = "refund-sender", note: str = "n") -> dict:
    content = {"summary": "synthetic", "note": note}
    msg = {
        "message_id": message_id, "conversation_id": "conv-refund-001",
        "profile": base.PROFILE, "protocol_version": base.PROTOCOL_VERSION,
        "message_type": "PROPOSE", "created_at": "2026-08-08T00:00:00Z",
        "expires_at": "2026-08-09T00:00:00Z", "sender": sender,
        "recipient": "refund-recipient", "purpose": "refund_execution_assessment",
        "requested_action": {k: v for k, v in PROPOSAL.items() if k != "authority_context_ref"},
        "operation_commitment": "sha256:" + "1" * 64,
        "proposal_commitment": "sha256:" + "2" * 64,
        "authority_refs": [{"type": "authority_context", "ref": base.PROFILE_AUTH_CONTEXT}],
        "evidence_refs": [], "content": content, "content_digest": base.digest(content),
        "acknowledgement_requested": True,
    }
    msg["message_digest"] = base.digest({k: v for k, v in msg.items() if k != "message_digest"})
    return msg


def registry():
    return base.LocalRegistry({"refund-sender"}, {"refund-recipient"}, "refund-recipient")


def exchange(msg, store_path):
    return runtime.run_exchange(msg, {}, registry(), None, evaluation_time=EVAL,
                                manifest={}, store_path=store_path)


# csf_77af39dec07a3500c0e2930c -------------------------------------------------

@pytest.mark.parametrize("message_id", [
    "../escape", "a/../../escape", "nested/escape", "back\\slash", "nul\x00byte",
    ".hidden", "a..b", "", "/abs",
])
def test_unsafe_message_id_is_not_understood_and_creates_no_file(tmp_path, message_id):
    root = tmp_path / "root"
    store_path = root / "exchange" / "exchange.sqlite"
    msg = governed(message_id)
    assessment = base.assess_message(msg, {}, registry(), evaluation_time=EVAL)
    assert assessment["permitted_handling"] == "NOT_UNDERSTOOD"
    assert assessment["errors"] == ["GAX-SCHEMA-MESSAGE-ID-UNSAFE"]
    result = exchange(msg, store_path)
    assert result["assessment"]["permitted_handling"] == "NOT_UNDERSTOOD"
    assert result["execution"]["attempted"] is False
    outside = [p for p in root.rglob("*") if p.is_file() and p.parent != store_path.parent]
    assert outside == []
    assert runtime.TransactionalExchangeStore(store_path).seen_messages() == {}


@pytest.mark.parametrize("message_id", [
    "msg-refund-001", "m1", "m-lost-ack", "fixture-restart_reconciliation",
    "authority-applied-revocation", "recovery-separation-absent-expiry",
    "repair-evidence_failure", "transport-gax-1", "s1-owner", "second-owner",
    "late-commit-partial", "original-unresolved",
])
def test_existing_fixture_message_ids_remain_understood(message_id):
    assert base.message_id_is_safe(message_id)


# csf_4e9a3d79c6bf349c5859768c -------------------------------------------------

def test_rejected_message_cannot_reserve_a_later_legitimate_message_id(tmp_path, stub_proposal):
    store_path = tmp_path / "exchange.sqlite"
    hostile = governed("msg-refund-001", sender="untrusted-sender", note="hostile")
    first = exchange(hostile, store_path)
    assert first["assessment"]["errors"] == ["GAX-IDENTITY-SENDER-UNTRUSTED"]
    assert runtime.TransactionalExchangeStore(store_path).seen_messages() == {}

    legitimate = governed("msg-refund-001")
    second = exchange(legitimate, store_path)
    assert "GAX-INTEGRITY-MESSAGE-ID-REUSE" not in second["assessment"]["errors"]
    assert second["assessment"]["permitted_handling"] == "ACCEPT_FOR_ASSESSMENT"
    assert second["execution"]["reason"] == "trusted_resolver_required"
    assert runtime.TransactionalExchangeStore(store_path).seen_messages() == {
        "msg-refund-001": legitimate["message_digest"]}

    # Accepted receipts still detect changed-content reuse of the same ID.
    changed = governed("msg-refund-001", note="changed")
    third = exchange(changed, store_path)
    assert third["assessment"]["errors"] == ["GAX-INTEGRITY-MESSAGE-ID-REUSE"]
    assert third["execution"]["attempted"] is False


# csf_2ed3468d5c2540e814f5640b -------------------------------------------------

def test_resume_original_rejects_tampered_message_with_copied_digest(tmp_path):
    original = governed("msg-refund-001")
    tampered = {**original, "content": {"summary": "tampered", "note": "n"}}
    store_path = tmp_path / "exchange.sqlite"
    with pytest.raises(ValueError, match="message_digest does not match"):
        runtime.resume_original_exchange(
            tampered, manifest={}, store_path=store_path, destination=None,
            resolver=None, execution_policy_factory=None, observation_policy=object(),
            evaluation_time=EVAL)
    assert list(tmp_path.glob("recovery-*.json")) == []
    assert not store_path.exists()


# csf_c6eda94b51d74aef50d8ec98 -------------------------------------------------

MODULES = {
    "control_plane": ("src/agent_control_plane", "bounded"),
    "runtime": ("engine", "producer_contract"),
    "replay": ("src/agent_replay_bundle", "importers"),
    "odes": ("src/odes", "exporter"),
    "pack": ("src/agent_governance_evidence_pack", "importer"),
}
TOP_LEVEL = ("agent_control_plane", "engine", "agent_replay_bundle", "odes", "agent_governance_evidence_pack")


def _git(path: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(path), *args], text=True).strip()


def _repo(path: Path, files: dict[str, str]) -> str:
    for name, text in files.items():
        target = path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
    _git(path.parent, "init", "-q", str(path))
    _git(path, "add", "-A")
    _git(path, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "-m", "fixture")
    return _git(path, "rev-parse", "HEAD")


@pytest.fixture(params=sorted(runtime.STRICT_SOURCE_PROFILES))
def fake_checkouts(request, tmp_path, monkeypatch):
    marker = tmp_path / "planted-code-ran"
    roots, revisions = {}, {}
    for key, (package, module) in MODULES.items():
        body = "import colorsys\nPLANTED = False\n"
        if key == "runtime":
            body += ("EXECUTOR_PRODUCER_PROFILE_ID = 'urn:cognous:profiles:moltbot-safe-executor-producer'\n"
                     "EXECUTOR_PRODUCER_PROFILE_VERSION = '2.0.0'\n"
                     "PinnedControlPlaneExecutor = DurableRefundDestination = ExecutionEnvelope = None\n"
                     "ExecutionOperation = LocalExecutionPolicy = commitment = export_execution_artifacts = None\n")
        roots[key] = tmp_path / key
        revisions[key] = _repo(roots[key], {f"{package}/__init__.py": "", f"{package}/{module}.py": body})
    manifest_root = tmp_path / "manifest"
    revisions["manifest"] = _repo(manifest_root, {"examples/m.json": "{}"})

    for key in ("replay", "odes", "pack"):
        monkeypatch.syspath_prepend(str(roots[key] / "src"))
    monkeypatch.setattr(sys, "path", list(sys.path))
    for name in [m for m in sys.modules if m.split(".")[0] in TOP_LEVEL]:
        monkeypatch.delitem(sys.modules, name)
    monkeypatch.setattr(runtime, "RUNTIME_COMPATIBILITY_PROFILE", request.param)
    monkeypatch.setattr(runtime, "CP_REVISION", revisions["control_plane"])
    monkeypatch.setattr(runtime, "MOLTBOT_REVISION", revisions["runtime"])
    monkeypatch.setattr(runtime, "REPLAY_REVISION", revisions["replay"])
    monkeypatch.setattr(runtime, "ODES_REVISION", revisions["odes"])
    monkeypatch.setattr(runtime, "EVIDENCE_PACK_REVISION", revisions["pack"])
    monkeypatch.setattr(runtime, "MANIFEST_REVISION", revisions["manifest"])
    monkeypatch.setenv("MOLTBOT_SAFE_CONTROL_PLANE_ROOT", str(roots["control_plane"]))
    monkeypatch.setenv("MOLTBOT_SAFE_ROOT", str(roots["runtime"]))
    monkeypatch.setenv("UPSTREAM_MANIFEST_EXAMPLE", str(manifest_root / "examples/m.json"))
    yield roots, marker
    for name in [m for m in sys.modules if m.split(".")[0] in TOP_LEVEL]:
        sys.modules.pop(name, None)


def _planted(marker: Path) -> str:
    return f"from pathlib import Path\nPath({str(marker)!r}).write_text('ran')\nPLANTED = True\n"


def test_clean_candidate_sources_verify_then_import_from_verified_paths(fake_checkouts):
    roots, marker = fake_checkouts
    loaded = runtime.load_executor_runtime()
    assert Path(loaded["cp"].__file__).resolve() == (roots["control_plane"] / "src/agent_control_plane/bounded.py").resolve()
    assert Path(loaded["producer"].__file__).resolve() == (roots["runtime"] / "engine/producer_contract.py").resolve()
    assert not marker.exists()


def test_tampered_tracked_module_is_refused_before_it_executes(fake_checkouts):
    roots, marker = fake_checkouts
    (roots["replay"] / "src/agent_replay_bundle/importers.py").write_text(_planted(marker))
    with pytest.raises(RuntimeError, match="candidate source identity mismatch: agent_replay_bundle.importers"):
        runtime.load_executor_runtime()
    assert not marker.exists()
    assert "agent_replay_bundle.importers" not in sys.modules


def test_untracked_planted_package_is_refused_before_it_executes(fake_checkouts, tmp_path):
    roots, marker = fake_checkouts
    # An untracked package inside a pinned checkout shadows the tracked one.
    shadow = roots["odes"] / "shadow"
    (shadow / "odes").mkdir(parents=True)
    (shadow / "odes/__init__.py").write_text(_planted(marker))
    (shadow / "odes/exporter.py").write_text(_planted(marker))
    sys.path.insert(0, str(shadow))
    with pytest.raises(RuntimeError, match="candidate source identity mismatch: odes.exporter"):
        runtime.load_executor_runtime()
    assert not marker.exists()
    assert "odes" not in sys.modules


def test_untracked_package_directory_shadowing_tracked_module_is_refused_before_it_executes(fake_checkouts):
    roots, marker = fake_checkouts
    # The import system prefers a package directory over a same-named .py file.
    shadow = roots["replay"] / "src/agent_replay_bundle/importers"
    shadow.mkdir()
    (shadow / "__init__.py").write_text(_planted(marker))
    with pytest.raises(RuntimeError, match="candidate source identity mismatch: agent_replay_bundle.importers"):
        runtime.load_executor_runtime()
    assert not marker.exists()
    assert "agent_replay_bundle" not in sys.modules


def test_stray_extension_module_beside_tracked_module_is_refused(fake_checkouts):
    roots, marker = fake_checkouts
    # Extension modules are found before source files of the same name.
    stray = roots["odes"] / ("src/odes/exporter" + importlib.machinery.EXTENSION_SUFFIXES[0])
    stray.write_bytes(b"not a real extension")
    with pytest.raises(RuntimeError, match="candidate source identity mismatch: odes.exporter"):
        runtime.load_executor_runtime()
    assert not marker.exists()
    assert "odes" not in sys.modules


def test_planted_unchecked_bytecode_for_tracked_module_is_refused(fake_checkouts, tmp_path):
    roots, marker = fake_checkouts
    # Unchecked-hash bytecode in __pycache__ would run instead of the verified source.
    tracked = roots["pack"] / "src/agent_governance_evidence_pack/importer.py"
    planted = tmp_path / "planted_source.py"
    planted.write_text(_planted(marker))
    py_compile.compile(str(planted), cfile=importlib.util.cache_from_source(str(tracked)),
                       invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH, doraise=True)
    with pytest.raises(RuntimeError, match="candidate source identity mismatch: agent_governance_evidence_pack.importer"):
        runtime.load_executor_runtime()
    assert not marker.exists()
    assert "agent_governance_evidence_pack" not in sys.modules


@pytest.mark.parametrize("key, root, entry", [
    ("replay", "src", "colorsys.py"),
    ("control_plane", "src", "colorsys.py"),
    ("runtime", "", "colorsys.py"),
    ("odes", "src", "colorsys/__init__.py"),
    ("pack", "src", "colorsys/helper.py"),
])
def test_untracked_top_level_module_at_checkout_path_root_is_refused(fake_checkouts, key, root, entry):
    roots, marker = fake_checkouts
    # A checkout's sys.path root is searched before the stdlib, so an untracked
    # top-level module there shadows a dependency the tracked code imports.
    sys.modules.pop("colorsys", None)
    target = roots[key] / root / entry
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(_planted(marker))
    with pytest.raises(RuntimeError, match="untracked or ignored importable file"):
        runtime.load_executor_runtime()
    assert not marker.exists()


def test_ignored_non_importable_entries_at_path_root_are_accepted(fake_checkouts):
    roots, marker = fake_checkouts
    for name in ("pkg.egg-info", ".venv", "build-output"):
        (roots["replay"] / "src" / name).mkdir()
        (roots["replay"] / "src" / name / "PKG-INFO").write_text("x")
    runtime.load_executor_runtime()
    assert not marker.exists()


def test_bytecode_cache_refusal_names_the_offending_file(fake_checkouts):
    roots, marker = fake_checkouts
    cache = roots["odes"] / "src/odes/__pycache__"
    cache.mkdir()
    (cache / "exporter.cpython-312.pyc").write_bytes(b"")
    with pytest.raises(RuntimeError, match=r"__pycache__.*PYTHONDONTWRITEBYTECODE=1"):
        runtime.load_executor_runtime()


# F3R: F5b security-runtime generation ---------------------------------------

def _load_with_profile(monkeypatch, profile):
    """Execute a fresh copy of gax_ref_runtime under one compatibility profile."""
    monkeypatch.setenv("GAX_RUNTIME_COMPATIBILITY_PROFILE", profile)
    name = "experiments.odex_gax_imx_reference._profile_probe"
    spec = importlib.util.spec_from_file_location(name, runtime.__file__)
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, module)
    spec.loader.exec_module(module)
    return module


PINS = ("CP_REVISION", "MOLTBOT_REVISION", "MANIFEST_REVISION", "REPLAY_REVISION", "ODES_REVISION",
        "EVIDENCE_PACK_REVISION")
F5B_PINS = {
    "CP_REVISION": "a34c3dc26f84a767a55f9d5c89dc0b53e63fefa5",
    "MOLTBOT_REVISION": "4a83b175d2ef0e65a7ee22a0513bb94a5fdf3a6f",
    "MANIFEST_REVISION": "2c36bcd0b620dbfe7ad924bc7196a3f0c04c5c5e",
    "REPLAY_REVISION": "def0ee0f3af713283ea3cd13f0caf79e1607b651",
    "ODES_REVISION": "5675f1b96d95ba69510656bf73b1006110ef5b57",
    "EVIDENCE_PACK_REVISION": "505a3590114705b7ebf736b92dd189f338134635",
}
P4_PINS = {
    "CP_REVISION": "26a7e6594eb535827ccc248cbca36a7d119d613b",
    "MOLTBOT_REVISION": "3024ef6e6ecf7da22e5f4fdf90d873f93b2a55c9",
    "MANIFEST_REVISION": "2c36bcd0b620dbfe7ad924bc7196a3f0c04c5c5e",
    "REPLAY_REVISION": "9aab3f6c34d2721ef1be3f6468b71dc3bad99a2a",
    "ODES_REVISION": "c5f4e2d0015ccdc94127a4025a6b605fc7fbdcbd",
    "EVIDENCE_PACK_REVISION": "54df6984dd418e2e0a09f89e54f281493475831c",
}
P2_PINS = {
    "CP_REVISION": "0a41faa972699f7ec3063967a14cd9bdd3e67d27",
    "MOLTBOT_REVISION": "ec728da6dc301a664b331ac8986afd6e850a1273",
    "MANIFEST_REVISION": "fa170815ef96a54c233d0dd9da821b60debabf8b",
    "REPLAY_REVISION": "028f63d1c001f99580583888fa4b4e46d77a267b",
    "ODES_REVISION": "e86a25a1d660e74533337d38744e2934200a50ae",
    "EVIDENCE_PACK_REVISION": "a3ebbb90559a44a88855139a182649d3792bb1ca",
}
P2_PREVIOUS_PINS = {
    "CP_REVISION": "e77fe0ee8714617899592528e660a80fbb2e864a",
    "MOLTBOT_REVISION": "cab4d9abc651c7efbafb429798d2c908f048bf5c",
    "REPLAY_REVISION": "53c0cd60d565ea1797ed0be87a2310c5b68b24f6",
    "ODES_REVISION": "dc5cf19d405ce885b287cde2f78519d3109b9ae6",
    "EVIDENCE_PACK_REVISION": "99ba3211450b25a18007b4b62907b072fe05c964",
}
RETAINED_SECURITY_PINS = {
    "CP_REVISION": "996baeb476c8745b1a58ddc968b9eecc6a39b76b",
    "MOLTBOT_REVISION": "fd6b76fa0e85feb5b67324114bf790d3a12fdaf1",
    "MANIFEST_REVISION": "e385f8c19b4444817a8b84b72ed6edbc37deb807",
    "REPLAY_REVISION": "3601fb218d5c02f5d86e55d2cf33983e5e130ac3",
    "ODES_REVISION": "dd2dc7e8f3fe74263917a0c67a40875daf3b0ce0",
    "EVIDENCE_PACK_REVISION": "8aba5a106ad119330950ccff97c55fa8492bc287",
}


@pytest.mark.parametrize("profile, pins", [
    ("security-runtime-f5b-20261016", F5B_PINS),
    ("security-runtime-p4-20261017", P4_PINS),
    ("security-runtime-p2-20261018", P2_PINS),
    ("security-runtime-candidate-20261016", RETAINED_SECURITY_PINS),
])
def test_security_runtime_generations_select_exact_separate_pins(monkeypatch, profile, pins):
    module = _load_with_profile(monkeypatch, profile)
    assert {name: getattr(module, name) for name in PINS} == pins
    assert not set(F5B_PINS.values()) & set(RETAINED_SECURITY_PINS.values())
    # P4 keeps the F5b Manifest and nothing else from F5b or the retained generation.
    assert {k: v for k, v in P4_PINS.items() if v in set(F5B_PINS.values()) | set(RETAINED_SECURITY_PINS.values())} == {
        "MANIFEST_REVISION": P4_PINS["MANIFEST_REVISION"]}


@pytest.mark.parametrize("name, old", sorted(P2_PREVIOUS_PINS.items()))
def test_p2_previous_ties_are_replaced_not_kept(monkeypatch, name, old):
    module = _load_with_profile(monkeypatch, "security-runtime-p2-20261018")
    assert getattr(module, name) != old
    assert old not in {getattr(module, n) for n in PINS}
    assert old not in P2_PINS.values()


@pytest.mark.parametrize("profile", ["security-runtime-f5b-20261016", "security-runtime-p4-20261017",
                                     "security-runtime-p2-20261018", "security-runtime-candidate-20261016"])
def test_security_runtime_generations_require_trusted_configuration(monkeypatch, profile):
    module = _load_with_profile(monkeypatch, profile)
    assert profile in module.SECURITY_RUNTIME_PROFILES and profile in module.STRICT_SOURCE_PROFILES
    with pytest.raises(ValueError, match="requires trusted runtime_authority_profile"):
        module._workflow_options(None)
    sentinel = object()
    assert module._workflow_options(sentinel, True) == {"runtime_authority_profile": sentinel, "allow_test_time": True}


def test_historical_profiles_reject_runtime_authority_options(monkeypatch):
    for profile in ("persistence-v1", "merged-producers-v1", "typed-refusal-candidate-20261015"):
        module = _load_with_profile(monkeypatch, profile)
        assert module.RUNTIME_COMPATIBILITY_PROFILE not in module.SECURITY_RUNTIME_PROFILES
        with pytest.raises(ValueError, match="explicit security-runtime profile"):
            module._workflow_options(object())


def test_unknown_profile_still_refused(monkeypatch):
    with pytest.raises(RuntimeError, match="unsupported GAX runtime compatibility profile"):
        _load_with_profile(monkeypatch, "security-runtime-p2-20261019")


# evidence_refs replay-bundle digest binding (issue #30) ---------------------------------------

def _bound(message, bundle):
    msg = dict(message)
    msg["evidence_refs"] = [{"type": "replay_bundle", "ref": bundle["bundle_id"], "digest": base.digest(bundle)}]
    msg["message_digest"] = base.digest({k: v for k, v in msg.items() if k != "message_digest"})
    return msg


@pytest.mark.parametrize("variant", ["extra_field", "identifier_changed"])
def test_substituted_replay_bundle_is_rejected_by_evidence_digest(stub_proposal, variant):
    bundle = {"bundle_id": "b-1", "run_id": "r-1"}
    msg = _bound(governed("m-sub-" + variant), bundle)
    substituted = dict(bundle)
    if variant == "extra_field":
        substituted["substituted_marker"] = "x"
    else:
        substituted["bundle_id"] = "b-1-substituted"
    out = base.assess_message(msg, substituted, registry(), evaluation_time=EVAL)
    assert out["permitted_handling"] == "REFUSE"
    assert "GAX-EVIDENCE-DIGEST-MISMATCH" in out["errors"]
    assert out["stages"]["evidence_digest"] == "failed"


def test_matching_replay_bundle_digest_is_verified(stub_proposal):
    bundle = {"bundle_id": "b-1", "run_id": "r-1"}
    out = base.assess_message(_bound(governed("m-ok"), bundle), bundle, registry(), evaluation_time=EVAL)
    assert out["permitted_handling"] == "ACCEPT_FOR_ASSESSMENT"
    assert out["stages"]["evidence_digest"] == "verified"


def test_absent_replay_bundle_digest_is_disclosed_as_not_verified(stub_proposal):
    out = base.assess_message(governed("m-none"), {}, registry(), evaluation_time=EVAL)
    assert out["stages"]["evidence_digest"].startswith("not_verified")


# OCS-SECURITY-EXCHANGE-01: current-stack compatibility profile ------------------------------------------------------------
# Additions only: no existing assertion above is changed. The profile names the exact tuple the strict source-identity check
# accepts; it changes no enforcement logic, no default, and certifies nothing.

CURRENT_PROFILE = "security-runtime-current-20261031"
CURRENT_PINS = {
    "CP_REVISION": "b19c47ddd020409d24e52e70b11359c46265edbb",
    "MOLTBOT_REVISION": "f7a55e2a8494801e49193f9f46935f0a971c248d",
    "MANIFEST_REVISION": "fa170815ef96a54c233d0dd9da821b60debabf8b",
    "REPLAY_REVISION": "40012b8c174c6f25685bd5d9bc93ff46cc9a5842",
    "ODES_REVISION": "1a5e1d300250d832e611633f0bf8f762e398c0ec",
    "EVIDENCE_PACK_REVISION": "7b9511f2c6d56d424f17b078826594abd29f6c96",
}
HISTORICAL_PROFILES = {
    "security-runtime-candidate-20261016": RETAINED_SECURITY_PINS,
    "security-runtime-f5b-20261016": F5B_PINS,
    "security-runtime-p4-20261017": P4_PINS,
    "security-runtime-p2-20261018": P2_PINS,
}


def test_current_profile_selects_the_exact_tuple_and_requires_trusted_configuration(monkeypatch):
    module = _load_with_profile(monkeypatch, CURRENT_PROFILE)
    assert {name: getattr(module, name) for name in PINS} == CURRENT_PINS
    assert all(len(v) == 40 and set(v) <= set("0123456789abcdef") for v in CURRENT_PINS.values())  # exact commits, no ranges or wildcards
    assert CURRENT_PROFILE in module.SECURITY_RUNTIME_PROFILES and CURRENT_PROFILE in module.STRICT_SOURCE_PROFILES
    with pytest.raises(ValueError, match="requires trusted runtime_authority_profile"):
        module._workflow_options(None)


@pytest.mark.parametrize("profile, pins", sorted(HISTORICAL_PROFILES.items()))
def test_historical_profiles_keep_their_original_pins_and_do_not_accept_the_current_tuple(monkeypatch, profile, pins):
    module = _load_with_profile(monkeypatch, profile)
    assert {name: getattr(module, name) for name in PINS} == pins
    for name in ("CP_REVISION", "MOLTBOT_REVISION", "REPLAY_REVISION", "ODES_REVISION", "EVIDENCE_PACK_REVISION"):
        assert getattr(module, name) != CURRENT_PINS[name]  # a historical profile is never silently re-tied to the current heads


def test_default_profile_is_unchanged_and_not_the_current_profile(monkeypatch):
    monkeypatch.delenv("GAX_RUNTIME_COMPATIBILITY_PROFILE", raising=False)
    spec = importlib.util.spec_from_file_location("experiments.odex_gax_imx_reference._default_probe", runtime.__file__)
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, "experiments.odex_gax_imx_reference._default_probe", module)
    spec.loader.exec_module(module)
    assert module.RUNTIME_COMPATIBILITY_PROFILE == "persistence-v1"
    assert module.RUNTIME_COMPATIBILITY_PROFILE not in module.STRICT_SOURCE_PROFILES
    assert CURRENT_PROFILE in module.STRICT_SOURCE_PROFILES  # selectable only by explicit name


@pytest.mark.parametrize("profile", [CURRENT_PROFILE + "x", "security-runtime-current-20261101", "security-runtime-current-*",
                                     "security-runtime-*", "*", "", CURRENT_PROFILE.upper(), " " + CURRENT_PROFILE])
def test_unknown_or_wildcard_profile_names_are_refused(monkeypatch, profile):
    with pytest.raises(RuntimeError, match="unsupported GAX runtime compatibility profile"):
        _load_with_profile(monkeypatch, profile)


@pytest.fixture
def current_checkouts(tmp_path, monkeypatch):
    """Throwaway checkouts selected under the CURRENT profile; the pinned constants are the fixture's own commits, so the
    check is exercised exactly as for any strict profile (the fake_checkouts fixture runs the same machinery for every profile)."""
    marker = tmp_path / "planted-code-ran"
    roots, revisions = {}, {}
    for key, (package, module) in MODULES.items():
        body = "import colorsys\nPLANTED = False\n"
        if key == "runtime":
            body += ("EXECUTOR_PRODUCER_PROFILE_ID = 'urn:cognous:profiles:moltbot-safe-executor-producer'\n"
                     "EXECUTOR_PRODUCER_PROFILE_VERSION = '2.0.0'\n"
                     "PinnedControlPlaneExecutor = DurableRefundDestination = ExecutionEnvelope = None\n"
                     "ExecutionOperation = LocalExecutionPolicy = commitment = export_execution_artifacts = None\n")
        roots[key] = tmp_path / key
        revisions[key] = _repo(roots[key], {f"{package}/__init__.py": "", f"{package}/{module}.py": body})
    manifest_root = tmp_path / "manifest"
    revisions["manifest"] = _repo(manifest_root, {"examples/m.json": "{}"})
    for key in ("replay", "odes", "pack"):
        monkeypatch.syspath_prepend(str(roots[key] / "src"))
    monkeypatch.setattr(sys, "path", list(sys.path))
    for name in [m for m in sys.modules if m.split(".")[0] in TOP_LEVEL]:
        monkeypatch.delitem(sys.modules, name)
    monkeypatch.setattr(runtime, "RUNTIME_COMPATIBILITY_PROFILE", CURRENT_PROFILE)
    for const, key in (("CP_REVISION", "control_plane"), ("MOLTBOT_REVISION", "runtime"), ("REPLAY_REVISION", "replay"),
                       ("ODES_REVISION", "odes"), ("EVIDENCE_PACK_REVISION", "pack"), ("MANIFEST_REVISION", "manifest")):
        monkeypatch.setattr(runtime, const, revisions[key])
    monkeypatch.setenv("MOLTBOT_SAFE_CONTROL_PLANE_ROOT", str(roots["control_plane"]))
    monkeypatch.setenv("MOLTBOT_SAFE_ROOT", str(roots["runtime"]))
    monkeypatch.setenv("UPSTREAM_MANIFEST_EXAMPLE", str(manifest_root / "examples/m.json"))
    yield roots, revisions, marker
    for name in [m for m in sys.modules if m.split(".")[0] in TOP_LEVEL]:
        sys.modules.pop(name, None)


def test_current_profile_accepts_the_correct_tuple(current_checkouts):
    roots, _, marker = current_checkouts
    loaded = runtime.load_executor_runtime()
    assert Path(loaded["cp"].__file__).resolve() == (roots["control_plane"] / "src/agent_control_plane/bounded.py").resolve()
    assert not marker.exists()


@pytest.mark.parametrize("const, module_name", [("CP_REVISION", "agent_control_plane.bounded"),
                                                ("REPLAY_REVISION", "agent_replay_bundle.importers"),
                                                ("ODES_REVISION", "odes.exporter"),
                                                ("EVIDENCE_PACK_REVISION", "agent_governance_evidence_pack.importer")])
def test_current_profile_refuses_a_mixed_tuple(current_checkouts, monkeypatch, const, module_name):
    # one component at another profile's revision while the rest match: refused, naming the mismatched module
    monkeypatch.setattr(runtime, const, HISTORICAL_PROFILES["security-runtime-p2-20261018"][const])
    with pytest.raises(RuntimeError, match=f"candidate source identity mismatch: {module_name}"):
        runtime.load_executor_runtime()


@pytest.mark.parametrize("missing", ["", None])
def test_current_profile_refuses_a_missing_identity(current_checkouts, monkeypatch, missing):
    monkeypatch.setattr(runtime, "CP_REVISION", missing)
    with pytest.raises(RuntimeError, match="candidate source identity mismatch: agent_control_plane.bounded"):
        runtime.load_executor_runtime()


def test_current_profile_refuses_a_substituted_revision(current_checkouts):
    roots, _, _ = current_checkouts
    # the checkout moves to a different commit than the pinned one (a substituted, even newer, revision)
    (roots["odes"] / "src/odes/extra.py").write_text("X = 1\n")
    _git(roots["odes"], "add", "-A")
    _git(roots["odes"], "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "-m", "newer")
    with pytest.raises(RuntimeError, match="candidate source identity mismatch: odes.exporter"):
        runtime.load_executor_runtime()


def test_current_profile_refuses_a_tampered_identity(current_checkouts):
    roots, _, marker = current_checkouts
    (roots["replay"] / "src/agent_replay_bundle/importers.py").write_text(_planted(marker))
    with pytest.raises(RuntimeError, match="candidate source identity mismatch: agent_replay_bundle.importers"):
        runtime.load_executor_runtime()
    assert not marker.exists()  # refused before the tampered module executed


def test_current_profile_refuses_a_manifest_at_another_revision(current_checkouts):
    _, revisions, _ = current_checkouts
    runtime.MANIFEST_REVISION = HISTORICAL_PROFILES["security-runtime-f5b-20261016"]["MANIFEST_REVISION"]  # monkeypatch undoes it
    with pytest.raises(RuntimeError, match="candidate source identity mismatch"):
        runtime.load_executor_runtime()


# S2 prep (Issue #254): real-module hardening of the current-profile tests -------------------------------------------------
# Tests only. The fixtures above monkeypatch the pins on the already-imported module, so they pass even if the profile branch,
# the frozenset entries or the literal pins were wrong. These load a fresh copy of the real gax_ref_runtime under the
# profile (the `_load_with_profile` mechanism), assert the gates, spy that the strict check really runs, and read every
# expected pin from the single CURRENT_PINS table (a re-cut edits that table and the six module constants only).

@pytest.fixture
def current_module(current_checkouts, monkeypatch):
    roots, revisions, marker = current_checkouts
    module = _load_with_profile(monkeypatch, CURRENT_PROFILE)  # raises if the profile name is no longer recognised
    for const, key in (("CP_REVISION", "control_plane"), ("MOLTBOT_REVISION", "runtime"), ("REPLAY_REVISION", "replay"),
                       ("ODES_REVISION", "odes"), ("EVIDENCE_PACK_REVISION", "pack"), ("MANIFEST_REVISION", "manifest")):
        monkeypatch.setattr(module, const, revisions[key])
    calls = []
    real_verify = module._verify_refusal_profile_sources

    def spy(*args, **kwargs):
        calls.append(args)
        return real_verify(*args, **kwargs)

    monkeypatch.setattr(module, "_verify_refusal_profile_sources", spy)
    return module, roots, revisions, marker, calls


@pytest.mark.parametrize("const", PINS)
def test_current_profile_pin_is_the_exact_table_value(monkeypatch, const):
    module = _load_with_profile(monkeypatch, CURRENT_PROFILE)
    value = getattr(module, const)
    assert value == CURRENT_PINS[const]
    assert len(value) == 40 and set(value) <= set("0123456789abcdef")


def test_current_profile_table_covers_exactly_the_six_pins():
    assert set(CURRENT_PINS) == set(PINS) and len(set(CURRENT_PINS.values())) == len(PINS)


def test_current_profile_is_gated_by_both_frozensets_on_the_real_module(monkeypatch):
    module = _load_with_profile(monkeypatch, CURRENT_PROFILE)
    assert module.RUNTIME_COMPATIBILITY_PROFILE == CURRENT_PROFILE
    assert CURRENT_PROFILE in module.SECURITY_RUNTIME_PROFILES
    assert CURRENT_PROFILE in module.STRICT_SOURCE_PROFILES


def test_real_module_runs_the_strict_check_and_accepts_the_correct_tuple(current_module):
    module, roots, _, marker, calls = current_module
    loaded = module.load_executor_runtime()
    assert len(calls) == 1  # the strict source-identity check actually ran (not silently skipped)
    assert Path(loaded["cp"].__file__).resolve() == (roots["control_plane"] / "src/agent_control_plane/bounded.py").resolve()
    assert not marker.exists()


@pytest.mark.parametrize("const, module_name", [("CP_REVISION", "agent_control_plane.bounded"),
                                                ("REPLAY_REVISION", "agent_replay_bundle.importers"),
                                                ("ODES_REVISION", "odes.exporter"),
                                                ("EVIDENCE_PACK_REVISION", "agent_governance_evidence_pack.importer")])
def test_real_module_raises_from_the_strict_check_on_a_mismatched_revision(current_module, monkeypatch, const, module_name):
    module, _, _, _, calls = current_module
    monkeypatch.setattr(module, const, CURRENT_PINS[const])  # the real current pin is not the fixture's checkout commit
    with pytest.raises(RuntimeError, match=f"candidate source identity mismatch: {module_name}"):
        module.load_executor_runtime()
    assert len(calls) == 1


def test_real_module_refuses_a_manifest_at_another_revision(current_module, monkeypatch):
    module, _, _, _, calls = current_module
    monkeypatch.setattr(module, "MANIFEST_REVISION", CURRENT_PINS["MANIFEST_REVISION"])
    with pytest.raises(RuntimeError, match="candidate source identity mismatch"):
        module.load_executor_runtime()
    assert len(calls) == 1


def test_real_module_refuses_a_tampered_checkout(current_module):
    module, roots, _, marker, _ = current_module
    (roots["replay"] / "src/agent_replay_bundle/importers.py").write_text(_planted(marker))
    with pytest.raises(RuntimeError, match="candidate source identity mismatch: agent_replay_bundle.importers"):
        module.load_executor_runtime()
    assert not marker.exists()


# S2 r2 PREP (Issue #254; NOT FOR MERGE until ODES #142 / Pack #65 are final) ------------------------------------------------
# New profile `security-runtime-current-20261031-r2`, registered BESIDE the original `security-runtime-current-20261031`
# (kept untouched). Controls A-P. ODES/Pack are explicit UNRESOLVED placeholders that can never equal a commit id, so the strict
# check refuses the profile until they are replaced. Every control reads R2_PINS (the single table); the final re-cut edits one
# constant per component in the module and the matching R2_PINS row, and the tests adapt: "unresolved" controls apply while a
# row is a placeholder, "resolved" controls apply once it is a 40-hex commit id.

R2_PROFILE = "security-runtime-current-20261031-r2"
R2_PINS = {
    "CP_REVISION": "b19c47ddd020409d24e52e70b11359c46265edbb",
    "MOLTBOT_REVISION": "f7a55e2a8494801e49193f9f46935f0a971c248d",
    "MANIFEST_REVISION": "fa170815ef96a54c233d0dd9da821b60debabf8b",
    "REPLAY_REVISION": "d395e37c443fedf1bf6b9a4651338b7b7de4a553",
    "ODES_REVISION": "UNRESOLVED-ODES-142-FINAL-MERGE-SHA",
    "EVIDENCE_PACK_REVISION": "UNRESOLVED-PACK-65-FINAL-MERGE-SHA",
}
ORIGINAL_BLOCK_SHA256 = "e734dadbf1a54cb05e8e434b8555b72b307513860a0d10931664e1b3318da4c7"  # lines of the original profile's elif block at 05ba99ba
ORIGINAL_PR62_HEAD = "05ba99ba5458d5b03da36c1a8a20f239f6fbf8b6"
R2_MODULES = {"CP_REVISION": "agent_control_plane.bounded", "REPLAY_REVISION": "agent_replay_bundle.importers",
              "ODES_REVISION": "odes.exporter", "EVIDENCE_PACK_REVISION": "agent_governance_evidence_pack.importer"}
ALL_OTHER_PROFILES = {**HISTORICAL_PROFILES, CURRENT_PROFILE: CURRENT_PINS}
# CP, Runtime and Manifest are intentionally the same commits as the original current profile (r2 re-cuts only Replay/ODES/Pack);
# a "mixed generation" or "different from" control is only meaningful where the other profile holds a different value.
SHARED_WITH_OTHER = {(o, c) for o, pins in ALL_OTHER_PROFILES.items() for c in PINS if pins[c] == R2_PINS[c]}


def _is_commit_id(value):
    return isinstance(value, str) and len(value) == 40 and set(value) <= set("0123456789abcdef")


R2_UNRESOLVED = sorted(k for k, v in R2_PINS.items() if not _is_commit_id(v))
R2_RESOLVED = sorted(k for k, v in R2_PINS.items() if _is_commit_id(v))
RUNTIME_SOURCE = Path(runtime.__file__).read_text()


def _load_source(monkeypatch, source, profile=R2_PROFILE):
    """Execute (possibly mutated) runtime SOURCE TEXT as a package-relative module under one profile."""
    monkeypatch.setenv("GAX_RUNTIME_COMPATIBILITY_PROFILE", profile)
    name = "experiments.odex_gax_imx_reference._r2_probe"
    spec = importlib.util.spec_from_file_location(name, runtime.__file__)
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, module)
    exec(compile(source, runtime.__file__, "exec"), module.__dict__)
    return module


def _registration_problems(module):
    """What a correct r2 registration must satisfy on a loaded module (profile table, gate sets, pin table)."""
    problems = []
    if module.RUNTIME_COMPATIBILITY_PROFILE != R2_PROFILE:
        problems.append("profile not selected")
    if R2_PROFILE not in module.SECURITY_RUNTIME_PROFILES:
        problems.append("missing SECURITY_RUNTIME_PROFILES membership")
    if R2_PROFILE not in module.STRICT_SOURCE_PROFILES:
        problems.append("missing STRICT_SOURCE_PROFILES membership")
    for name in PINS:
        if getattr(module, name) != R2_PINS[name]:
            problems.append(f"pin differs from table: {name}")
    return problems


@pytest.fixture
def r2_module(current_checkouts, monkeypatch):
    """Real module under the r2 profile. Resolved components are aligned to the fixture's throwaway commits (the same device the
    current-profile fixtures use); UNRESOLVED components are left exactly as the profile ships them."""
    roots, revisions, marker = current_checkouts
    module = _load_with_profile(monkeypatch, R2_PROFILE)
    keymap = (("CP_REVISION", "control_plane"), ("MOLTBOT_REVISION", "runtime"), ("REPLAY_REVISION", "replay"),
              ("ODES_REVISION", "odes"), ("EVIDENCE_PACK_REVISION", "pack"), ("MANIFEST_REVISION", "manifest"))
    for const, key in keymap:
        if const not in R2_UNRESOLVED:
            monkeypatch.setattr(module, const, revisions[key])
    calls = []
    real_verify = module._verify_refusal_profile_sources
    monkeypatch.setattr(module, "_verify_refusal_profile_sources", lambda *a, **k: (calls.append(a), real_verify(*a, **k))[1])

    def align_all():  # what the final re-cut makes true: every pin resolved
        for const, key in keymap:
            monkeypatch.setattr(module, const, revisions[key])
    return module, roots, revisions, marker, calls, keymap, align_all


# A: missing profile registration
def test_r2_A_missing_profile_registration_is_refused(monkeypatch):
    start = RUNTIME_SOURCE.index('elif RUNTIME_COMPATIBILITY_PROFILE == "security-runtime-current-20261031-r2":')
    end = RUNTIME_SOURCE.index('elif RUNTIME_COMPATIBILITY_PROFILE != "persistence-v1":')
    assert start < end
    with pytest.raises(RuntimeError, match="unsupported GAX runtime compatibility profile"):
        _load_source(monkeypatch, RUNTIME_SOURCE[:start] + RUNTIME_SOURCE[end:])


# B: missing strict-profile membership (both gate sets are individually required)
@pytest.mark.parametrize("gate", ["SECURITY_RUNTIME_PROFILES", "STRICT_SOURCE_PROFILES"])
def test_r2_B_missing_gate_membership_is_detected(monkeypatch, gate):
    entry = ', "security-runtime-current-20261031-r2"'
    assert RUNTIME_SOURCE.count(entry) == 1
    mutated = RUNTIME_SOURCE.replace(entry, "")  # drops it from SECURITY_RUNTIME_PROFILES (STRICT derives from it)
    module = _load_source(monkeypatch, mutated)
    problems = _registration_problems(module)
    assert "missing SECURITY_RUNTIME_PROFILES membership" in problems
    assert "missing STRICT_SOURCE_PROFILES membership" in problems
    assert _registration_problems(_load_with_profile(monkeypatch, R2_PROFILE)) == []  # the shipped module is clean
    assert gate in ("SECURITY_RUNTIME_PROFILES", "STRICT_SOURCE_PROFILES")


def test_r2_B_strict_membership_alone_is_not_enough_for_security_options(monkeypatch):
    module = _load_with_profile(monkeypatch, R2_PROFILE)
    assert R2_PROFILE in module.STRICT_SOURCE_PROFILES
    with pytest.raises(ValueError, match="requires trusted runtime_authority_profile"):
        module._workflow_options(None)


# C/D/E: wrong name, unknown profile, wildcard
@pytest.mark.parametrize("name", [R2_PROFILE.upper(), R2_PROFILE.replace("-r2", "-R2"), R2_PROFILE.replace("-r2", "r2"),
                                  R2_PROFILE.replace("-r2", "-r3"), R2_PROFILE.replace("-r2", "_r2"), " " + R2_PROFILE,
                                  R2_PROFILE + " ", "security-runtime-current-20261101-r2", "security-runtime-r2"])
def test_r2_C_wrong_profile_name_is_refused(monkeypatch, name):
    with pytest.raises(RuntimeError, match="unsupported GAX runtime compatibility profile"):
        _load_with_profile(monkeypatch, name)


@pytest.mark.parametrize("name", [R2_PROFILE + "x", R2_PROFILE + "-r2", R2_PROFILE + "\n", "security-runtime-current-20261031-r1",
                                  "security-runtime-current-20261031-r2-latest", "latest", "r2"])
def test_r2_D_unknown_profile_is_refused(monkeypatch, name):
    with pytest.raises(RuntimeError, match="unsupported GAX runtime compatibility profile"):
        _load_with_profile(monkeypatch, name)


@pytest.mark.parametrize("name", ["security-runtime-current-20261031-*", "security-runtime-current-*-r2", "security-runtime-current-20261031-r?",
                                  "security-runtime-*", "*-r2", "*", "security-runtime-current-20261031-r[0-9]"])
def test_r2_E_wildcard_profile_is_refused(monkeypatch, name):
    with pytest.raises(RuntimeError, match="unsupported GAX runtime compatibility profile"):
        _load_with_profile(monkeypatch, name)


# Table and placeholder fail-closed (supports F-K)
@pytest.mark.parametrize("const", PINS)
def test_r2_pin_matches_table_or_is_an_explicit_placeholder(monkeypatch, const):
    value = getattr(_load_with_profile(monkeypatch, R2_PROFILE), const)
    assert value == R2_PINS[const]
    if const in R2_UNRESOLVED:
        assert value.startswith("UNRESOLVED-") and not _is_commit_id(value)
    else:
        assert _is_commit_id(value)


def test_r2_table_covers_exactly_the_six_pins_and_all_values_are_distinct():
    assert set(R2_PINS) == set(PINS) and len(set(R2_PINS.values())) == len(PINS)


def test_r2_state_unresolved_components_are_exactly_odes_and_pack_until_the_recut():
    # tripwire documenting the prep state: once a component is resolved this list shrinks; it must never contain CP/Runtime/Manifest/Replay
    assert set(R2_UNRESOLVED) <= {"ODES_REVISION", "EVIDENCE_PACK_REVISION"}


@pytest.mark.skipif(not R2_UNRESOLVED, reason="all r2 pins are resolved")
def test_r2_unresolved_placeholder_makes_the_profile_refuse_fail_closed(r2_module):
    module, _, _, marker, calls, _, _ = r2_module
    first = next(c for c in ("CP_REVISION", "REPLAY_REVISION", "ODES_REVISION", "EVIDENCE_PACK_REVISION") if c in R2_UNRESOLVED)
    with pytest.raises(RuntimeError, match=f"candidate source identity mismatch: {R2_MODULES[first]}"):
        module.load_executor_runtime()
    assert len(calls) == 1 and not marker.exists()  # strict check ran; nothing executed


@pytest.mark.skipif(not R2_UNRESOLVED, reason="all r2 pins are resolved")
@pytest.mark.parametrize("const", sorted(R2_MODULES))
def test_r2_each_unresolved_component_alone_blocks_load(r2_module, monkeypatch, const):
    module, _, _, _, _, _, align_all = r2_module
    if const not in R2_UNRESOLVED:
        pytest.skip("component resolved")
    align_all()
    monkeypatch.setattr(module, const, R2_PINS[const])  # restore the shipped placeholder for this one component only
    with pytest.raises(RuntimeError, match=f"candidate source identity mismatch: {R2_MODULES[const]}"):
        module.load_executor_runtime()


def test_r2_a_placeholder_never_matches_a_real_commit(current_checkouts):
    _, revisions, _ = current_checkouts
    for placeholder in (R2_PINS[c] for c in R2_UNRESOLVED):
        assert placeholder not in revisions.values() and not _is_commit_id(placeholder)


def test_r2_positive_control_the_correct_tuple_is_accepted_once_every_pin_matches(r2_module):
    module, roots, _, marker, calls, _, align_all = r2_module
    align_all()  # stands in for the final resolved pins: same machinery, fixture commits
    loaded = module.load_executor_runtime()
    assert len(calls) == 1 and not marker.exists()
    assert Path(loaded["cp"].__file__).resolve() == (roots["control_plane"] / "src/agent_control_plane/bounded.py").resolve()


# F-K: changed Replay / Control Plane / Runtime / ODES / Pack / Manifest SHA (one-hex-digit change of the otherwise-correct pin)
_CHANGED = [("REPLAY_REVISION", "agent_replay_bundle.importers"), ("CP_REVISION", "agent_control_plane.bounded"),
            ("MOLTBOT_REVISION", "engine.producer_contract"), ("ODES_REVISION", "odes.exporter"),
            ("EVIDENCE_PACK_REVISION", "agent_governance_evidence_pack.importer"), ("MANIFEST_REVISION", "manifest")]


@pytest.mark.parametrize("const, module_name", _CHANGED)
def test_r2_FK_changed_component_sha_is_refused(r2_module, monkeypatch, const, module_name):
    module, _, revisions, _, calls, keymap, align_all = r2_module
    align_all()
    key = dict(keymap)[const]
    good = revisions[key]
    monkeypatch.setattr(module, const, good[:-1] + ("0" if good[-1] != "0" else "1"))
    with pytest.raises(RuntimeError, match=f"candidate source identity mismatch: {module_name}"):
        module.load_executor_runtime()
    assert len(calls) == 1


@pytest.mark.parametrize("const", PINS)
def test_r2_FK_changed_shipped_pin_differs_from_every_other_profile_pin_for_that_component(monkeypatch, const):
    # parametric on the table: whichever value R2_PINS holds, no other profile may hold it for a different generation
    module = _load_with_profile(monkeypatch, R2_PROFILE)
    for other, pins in ALL_OTHER_PROFILES.items():
        if (other, const) in SHARED_WITH_OTHER:
            assert other in (CURRENT_PROFILE, "security-runtime-p2-20261018") and const in ("CP_REVISION", "MOLTBOT_REVISION", "MANIFEST_REVISION")
            continue  # legitimately shared (see SHARED_WITH_OTHER); Replay/ODES/Pack are never shared once resolved
        assert getattr(module, const) != pins[const], (other, const)


# L: mixed generations (each component taken from another generation while the rest match)
@pytest.mark.parametrize("other", sorted(ALL_OTHER_PROFILES))
@pytest.mark.parametrize("const, module_name", [c for c in _CHANGED if c[0] != "MANIFEST_REVISION"])
def test_r2_L_mixed_generation_is_refused(r2_module, monkeypatch, other, const, module_name):
    module, _, _, _, calls, _, align_all = r2_module
    if (other, const) in SHARED_WITH_OTHER:
        pytest.skip("same commit in both generations: not a substitution")
    align_all()
    monkeypatch.setattr(module, const, ALL_OTHER_PROFILES[other][const])
    with pytest.raises(RuntimeError, match=f"candidate source identity mismatch: {module_name}"):
        module.load_executor_runtime()
    assert len(calls) == 1


# M: missing source identity
@pytest.mark.parametrize("missing", ["", None, "   "])
@pytest.mark.parametrize("const, module_name", _CHANGED)
def test_r2_M_missing_source_identity_is_refused(r2_module, monkeypatch, const, module_name, missing):
    module, _, _, _, _, _, align_all = r2_module
    align_all()
    monkeypatch.setattr(module, const, missing)
    with pytest.raises(RuntimeError, match="candidate source identity mismatch"):
        module.load_executor_runtime()


def test_r2_M_missing_pin_constant_is_refused(r2_module, monkeypatch):
    module, _, _, _, _, _, align_all = r2_module
    align_all()
    monkeypatch.delattr(module, "ODES_REVISION")
    with pytest.raises(NameError):
        module.load_executor_runtime()  # an absent constant is an error, never a silent pass


# N: tampered profile contents (the source text of the profile block, and the checkout contents)
@pytest.mark.parametrize("const", PINS)
def test_r2_N_tampered_profile_pin_in_source_is_detected_against_the_table(monkeypatch, const):
    start = RUNTIME_SOURCE.index('elif RUNTIME_COMPATIBILITY_PROFILE == "security-runtime-current-20261031-r2":')
    end = RUNTIME_SOURCE.index('elif RUNTIME_COMPATIBILITY_PROFILE != "persistence-v1":')
    block = RUNTIME_SOURCE[start:end]
    line = next(l for l in block.splitlines() if l.strip().startswith(const + " = "))
    assert R2_PINS[const] in line and block.count(line) == 1
    tampered_value = "0" * 40
    module = _load_source(monkeypatch, RUNTIME_SOURCE[:start] + block.replace(line, line.replace(R2_PINS[const], tampered_value)) + RUNTIME_SOURCE[end:])
    assert getattr(module, const) == tampered_value
    assert f"pin differs from table: {const}" in _registration_problems(module)


@pytest.mark.parametrize("target", ["replay", "odes", "pack", "control_plane"])
def test_r2_N_tampered_checkout_is_refused_before_execution(r2_module, target):
    module, roots, _, marker, _, _, align_all = r2_module
    align_all()
    package, name = MODULES[target]
    (roots[target] / package / f"{name}.py").write_text(_planted(marker))
    with pytest.raises(RuntimeError, match="candidate source identity mismatch"):
        module.load_executor_runtime()
    assert not marker.exists()


# O: every historical profile (including the original current profile) refuses the r2 tuple and is not re-tied to it
@pytest.mark.parametrize("profile", sorted(ALL_OTHER_PROFILES))
def test_r2_O_historical_profile_does_not_carry_the_r2_tuple(monkeypatch, profile):
    module = _load_with_profile(monkeypatch, profile)
    assert module.RUNTIME_COMPATIBILITY_PROFILE != R2_PROFILE
    for name in ("CP_REVISION", "MOLTBOT_REVISION", "REPLAY_REVISION", "ODES_REVISION", "EVIDENCE_PACK_REVISION"):
        if (profile, name) in SHARED_WITH_OTHER:
            continue
        assert getattr(module, name) != R2_PINS[name], (profile, name)
    for name in ("REPLAY_REVISION", "ODES_REVISION", "EVIDENCE_PACK_REVISION"):
        assert getattr(module, name) != R2_PINS[name], (profile, name)  # the re-cut components never coincide with any historical profile
    assert {n: getattr(module, n) for n in PINS} == ALL_OTHER_PROFILES[profile]  # unchanged table row


@pytest.mark.parametrize("profile", sorted(ALL_OTHER_PROFILES))
@pytest.mark.parametrize("const", ["REPLAY_REVISION", "ODES_REVISION", "EVIDENCE_PACK_REVISION"])
def test_r2_O_historical_profile_refuses_a_checkout_at_the_r2_revision(monkeypatch, profile, const):
    # a checkout whose identity is the r2 revision is a mismatch under the historical pin (name-only selection does not substitute)
    module = _load_with_profile(monkeypatch, profile)
    assert getattr(module, const) != R2_PINS[const]


# P: r2 refuses historical substitutes in every slot; the shipped r2 constants are never a historical value
@pytest.mark.parametrize("other", sorted(ALL_OTHER_PROFILES))
@pytest.mark.parametrize("const, module_name", [c for c in _CHANGED if c[0] != "MANIFEST_REVISION"])
def test_r2_P_r2_refuses_a_historical_substitute(r2_module, monkeypatch, other, const, module_name):
    module, _, _, _, _, _, align_all = r2_module
    if (other, const) in SHARED_WITH_OTHER:
        pytest.skip("same commit in both generations: not a substitution")
    align_all()
    monkeypatch.setattr(module, const, ALL_OTHER_PROFILES[other][const])
    with pytest.raises(RuntimeError, match=f"candidate source identity mismatch: {module_name}"):
        module.load_executor_runtime()
    assert R2_PINS[const] != ALL_OTHER_PROFILES[other][const]


def test_r2_P_r2_manifest_substitute_from_another_generation_is_refused(r2_module, monkeypatch):
    module, _, _, _, _, _, align_all = r2_module
    align_all()
    monkeypatch.setattr(module, "MANIFEST_REVISION", HISTORICAL_PROFILES["security-runtime-f5b-20261016"]["MANIFEST_REVISION"])
    with pytest.raises(RuntimeError, match="candidate source identity mismatch: manifest"):
        module.load_executor_runtime()


# Original profile untouched (byte-identical block; row identical to PR #62 head 05ba99ba)
def _original_block(source):
    lines = source.splitlines(keepends=True)
    start = next(i for i, l in enumerate(lines) if l.startswith('elif RUNTIME_COMPATIBILITY_PROFILE == "security-runtime-current-20261031":'))
    end = next(i for i in range(start + 1, len(lines)) if lines[i].startswith("elif "))
    return "".join(lines[start:end])


def test_r2_original_profile_block_is_byte_identical_to_the_pinned_digest():
    import hashlib
    block = _original_block(RUNTIME_SOURCE)
    # the digest covers the block as it stood at 05ba99ba (13 lines: elif .. EVIDENCE_PACK_REVISION)
    assert hashlib.sha256(block.encode()).hexdigest() == ORIGINAL_BLOCK_SHA256
    for old in ("40012b8c174c6f25685bd5d9bc93ff46cc9a5842", "1a5e1d300250d832e611633f0bf8f762e398c0ec", "7b9511f2c6d56d424f17b078826594abd29f6c96"):
        assert old in block  # still the original generation, not re-tied


def test_r2_original_profile_block_equals_pr62_head_when_the_object_is_available():
    repo = Path(runtime.__file__).resolve().parents[2]
    try:
        old = subprocess.check_output(["git", "-C", str(repo), "show", f"{ORIGINAL_PR62_HEAD}:experiments/odex_gax_imx_reference/gax_ref_runtime.py"],
                                      text=True, stderr=subprocess.DEVNULL)
    except (subprocess.CalledProcessError, OSError):
        pytest.skip("PR #62 head object not present in this checkout (shallow clone)")
    assert _original_block(old) == _original_block(RUNTIME_SOURCE)


def test_r2_original_profile_row_is_unchanged_and_selectable_beside_r2(monkeypatch):
    module = _load_with_profile(monkeypatch, CURRENT_PROFILE)
    assert {n: getattr(module, n) for n in PINS} == CURRENT_PINS
    assert {CURRENT_PROFILE, R2_PROFILE} <= module.STRICT_SOURCE_PROFILES
    assert CURRENT_PINS != R2_PINS and CURRENT_PROFILE != R2_PROFILE


def test_r2_historical_profile_blocks_other_than_the_original_are_untouched_by_the_registration():
    # exactly two lines of the module differ from the prep base for registration: the new elif block and the frozenset entry
    for hist in ("security-runtime-p2-20261018", "security-runtime-p4-20261017", "security-runtime-f5b-20261016", "security-runtime-candidate-20261016"):
        assert RUNTIME_SOURCE.count(f'== "{hist}":') == 1
