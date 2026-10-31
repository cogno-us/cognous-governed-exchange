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
