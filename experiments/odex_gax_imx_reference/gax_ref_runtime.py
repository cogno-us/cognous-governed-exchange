from __future__ import annotations


import argparse
import dataclasses
import importlib
import importlib.machinery
import importlib.util
import json
import os
import sqlite3
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any

from .generation_fence import GenerationFenceClaim
from . import gax_ref as base

PROFILE = base.PROFILE
PROTOCOL_VERSION = base.PROTOCOL_VERSION
EVAL = base.EVAL

LocalRegistry = base.LocalRegistry
assess_message = base.assess_message
digest = base.digest
make_message = base.make_message
parse_time = base.parse_time
runtime_proposal_model = base.runtime_proposal_model

CP_REVISION = "248d899634d9db3518e831bc7ab568a48733f825"
MOLTBOT_REVISION = "177354e959cc78c59c1a776f018cfbfbf28c927b"  # accepted dependency
MANIFEST_REVISION = "46c950bed37fe3812000895430bc0312d29e37ce"
REPLAY_REVISION = "043830b56595cecddfa65c064afd1c0b95e64792"
ODES_REVISION = "0486b645e99c46d9cd16ca34b1ba7c653a6b3024"
EVIDENCE_PACK_REVISION = "de6b9e071df49fc3e0c1254d39b5c94cced554f0"
ALVORADA_REVISION = "fb3d97938969a89e149e8ff8db2756091d1233fc"
MOLTBOT_PRODUCER_PROFILE_ID = "urn:cognous:profiles:moltbot-safe-executor-producer"
MOLTBOT_PRODUCER_PROFILE_VERSION = "2.0.0"
GAX_ARTIFACT_EXPORT_PROFILE = "urn:cognous:profiles:gax-retained-artifacts"
GAX_ARTIFACT_EXPORT_VERSION = "1.1.0"


# Explicit opt-in compatibility selection; historical default remains intact.
# persistence-v1 and merged-producers-v1 stamp these configured constants into
# exported provenance without measuring the loaded source; they are labels,
# not source identity.
RUNTIME_COMPATIBILITY_PROFILE = os.environ.get("GAX_RUNTIME_COMPATIBILITY_PROFILE", "persistence-v1")
if RUNTIME_COMPATIBILITY_PROFILE == "merged-producers-v1":
    CP_REVISION = "d3dadee70bd319812b207389ab1e0f6efe511916"
    MOLTBOT_REVISION = "c3c3ee7188b9367cf70b08074b9c40a5c70c94ac"
    REPLAY_REVISION = "459e4ba62fca49364aebb0050cd5fb2dd5a71bfa"
    ODES_REVISION = "c5e9a0f3695ae836b803be06c46d2c669642ee03"
    EVIDENCE_PACK_REVISION = "b4baccd823d2a73be276c1de745b19cf7c56a0d6"
elif RUNTIME_COMPATIBILITY_PROFILE == "typed-refusal-candidate-20261015":
    CP_REVISION = "c7f122ba3a6e39f9268a7163c99be3ee514cd97e"
    MOLTBOT_REVISION = "309e194c1b0a3de23e11e20133e6eaf88875e48a"
    REPLAY_REVISION = "83fbaf2a0f6f071aca1ea0af859eb8fc6385c26a"
    ODES_REVISION = "25c7ad608c2e6fd9f450e075db6bbf3ee4091a49"
    EVIDENCE_PACK_REVISION = "1e789c7d67a897097445faef1813fb0cd22d55e5"
elif RUNTIME_COMPATIBILITY_PROFILE == "security-runtime-candidate-20261016":
    CP_REVISION = "996baeb476c8745b1a58ddc968b9eecc6a39b76b"
    MOLTBOT_REVISION = "fd6b76fa0e85feb5b67324114bf790d3a12fdaf1"
    MANIFEST_REVISION = "e385f8c19b4444817a8b84b72ed6edbc37deb807"
    REPLAY_REVISION = "3601fb218d5c02f5d86e55d2cf33983e5e130ac3"
    ODES_REVISION = "dd2dc7e8f3fe74263917a0c67a40875daf3b0ce0"
    EVIDENCE_PACK_REVISION = "8aba5a106ad119330950ccff97c55fa8492bc287"
elif RUNTIME_COMPATIBILITY_PROFILE == "security-runtime-f5b-20261016":
    # Separate F5b merged generation; the 996baeb4 profile above is kept so
    # retained evidence stays reproducible at its historical pins.
    CP_REVISION = "a34c3dc26f84a767a55f9d5c89dc0b53e63fefa5"
    MOLTBOT_REVISION = "4a83b175d2ef0e65a7ee22a0513bb94a5fdf3a6f"
    MANIFEST_REVISION = "2c36bcd0b620dbfe7ad924bc7196a3f0c04c5c5e"
    REPLAY_REVISION = "def0ee0f3af713283ea3cd13f0caf79e1607b651"
    ODES_REVISION = "5675f1b96d95ba69510656bf73b1006110ef5b57"
    EVIDENCE_PACK_REVISION = "505a3590114705b7ebf736b92dd189f338134635"
elif RUNTIME_COMPATIBILITY_PROFILE == "security-runtime-p4-20261017":
    # P4 generation (alpha decoupling, qualification P4): the producers after the execution-attempt lifecycle contract
    # work. Added beside F5b, which is kept so retained evidence stays reproducible. Alpha scaffolding, removed with
    # the other hard pins at end-of-alpha (P5).
    CP_REVISION = "26a7e6594eb535827ccc248cbca36a7d119d613b"
    MOLTBOT_REVISION = "3024ef6e6ecf7da22e5f4fdf90d873f93b2a55c9"
    MANIFEST_REVISION = "2c36bcd0b620dbfe7ad924bc7196a3f0c04c5c5e"
    REPLAY_REVISION = "9aab3f6c34d2721ef1be3f6468b71dc3bad99a2a"
    ODES_REVISION = "c5f4e2d0015ccdc94127a4025a6b605fc7fbdcbd"
    EVIDENCE_PACK_REVISION = "54df6984dd418e2e0a09f89e54f281493475831c"
elif RUNTIME_COMPATIBILITY_PROFILE == "security-runtime-p2-20261018":
    # Programme 2 generation (qualification p2): the producers after the Programme 2 hardening work. Added beside
    # P4 and F5b, which are kept unchanged so retained evidence stays reproducible. Alpha scaffolding, removed with
    # the other hard pins at end-of-alpha (P5).
    CP_REVISION = "6093aca7b945698e89c0d8ac7c75306375e1a298"
    MOLTBOT_REVISION = "62a5cc156ecb439b4103b757fd265f276bb30374"
    MANIFEST_REVISION = "f9ae8527326c07e3177b5f003e626b23758be3d0"
    REPLAY_REVISION = "c8e665bd1936e4da90f6a324b486a320934c4bff"
    ODES_REVISION = "bff8307cc437d16e977be4d5ff389f1dd3bf7991"
    EVIDENCE_PACK_REVISION = "cde3f1f1cf517d5663afb33ce88c123aae779757"
elif RUNTIME_COMPATIBILITY_PROFILE != "persistence-v1":
    raise RuntimeError("unsupported GAX runtime compatibility profile")

# Profiles that require trusted runtime-authority configuration.
SECURITY_RUNTIME_PROFILES = frozenset({"security-runtime-candidate-20261016", "security-runtime-f5b-20261016", "security-runtime-p4-20261017", "security-runtime-p2-20261018"})
# Profiles whose candidate sources are verified before import.
STRICT_SOURCE_PROFILES = frozenset({"typed-refusal-candidate-20261015", *SECURITY_RUNTIME_PROFILES})


def _repo_path(env_name: str, default: str) -> Path:
    return Path(os.environ.get(env_name, default)).resolve()


def _workflow_options(runtime_authority_profile, allow_test_time=False):
    """Configuration comes from the trusted caller, never the incoming message."""
    if RUNTIME_COMPATIBILITY_PROFILE in SECURITY_RUNTIME_PROFILES:
        if runtime_authority_profile is None:
            raise ValueError("security-runtime profile requires trusted runtime_authority_profile")
        return {"runtime_authority_profile": runtime_authority_profile, "allow_test_time": allow_test_time}
    if runtime_authority_profile is not None or allow_test_time:
        raise ValueError("runtime authority options require the explicit security-runtime profile")
    return {}


def _executed_file_problems(executed: list[Path]) -> list[str]:
    """Problems that make a verified entry file differ from the revision's blob, whatever ``git status`` says.

    ``git status`` trusts the index: a tracked file marked assume-unchanged or skip-worktree can be modified and still look
    clean. This step covers only the import chain of the verified entry modules (their package ``__init__.py`` files and
    the module itself); ``_checkout_source_problems`` is the separate step that covers every tracked file of each checked
    checkout. Each file in the chain is therefore (1) refused if its index entry carries either flag (``git ls-files -v`` shows
    lowercase for assume-unchanged and ``S`` for skip-worktree) and (2) hashed from disk (``git hash-object``) and compared
    with the blob recorded at HEAD.
    """
    problems = []
    for path in executed:
        path = Path(path).resolve()
        top = Path(subprocess.check_output(["git", "-C", str(path.parent), "rev-parse", "--show-toplevel"],
                                           text=True, timeout=10).strip()).resolve()
        rel = path.relative_to(top).as_posix()
        for line in subprocess.check_output(["git", "-C", str(top), "ls-files", "-v", "--", rel],
                                            text=True, timeout=10).splitlines():
            if line[:1].islower() or line[:1] == "S":
                problems.append(f"index flag hides modifications: {rel}")
        head_blob = subprocess.check_output(["git", "-C", str(top), "rev-parse", f"HEAD:{rel}"], text=True, timeout=10).strip()
        disk_blob = subprocess.check_output(["git", "-C", str(top), "hash-object", "--", rel], text=True, timeout=10).strip()
        if head_blob != disk_blob:
            problems.append(f"content differs from the revision: {rel}")
    return problems


def _checkout_source_problems(top: Path) -> list[str]:
    """Problems with any tracked file of a checkout, not only the entry modules.

    Modules that an entry module imports run as well. Every tracked file is therefore (1) refused if its index entry carries
    an assume-unchanged or skip-worktree flag, (2) required to exist and (3) hashed from disk and compared with the blob
    recorded at HEAD. A tracked entry that cannot be compared this way (a submodule, a path with a newline) is refused.
    """
    def git(*args, **kwargs):
        return subprocess.run(["git", "-C", str(top), *args], check=True, text=True, capture_output=True,
                              timeout=120, **kwargs).stdout

    problems = []
    for line in git("ls-files", "-v", "-z").split("\0"):
        if line and (line[0].islower() or line[0] == "S"):
            problems.append(f"index flag hides modifications: {line[2:]}")
    head = {}
    for entry in git("ls-tree", "-r", "-z", "HEAD").split("\0"):
        if entry:
            meta, rel = entry.split("\t", 1)
            mode, kind, blob = meta.split()
            head[rel] = (mode, kind, blob)
    disk = []
    for rel, (mode, kind, blob) in sorted(head.items()):
        path = top / rel
        if kind != "blob" or "\n" in rel:
            problems.append(f"cannot be compared with the revision: {rel}")
        elif mode == "120000":
            if not path.is_symlink() or git("hash-object", "--stdin", input=os.readlink(path)).strip() != blob:
                problems.append(f"content differs from the revision: {rel}")
        elif path.is_symlink() or not path.is_file():
            problems.append(f"content differs from the revision: {rel}")
        else:
            disk.append(rel)
    def hashes(paths, *flags):
        out = git("hash-object", *flags, "--stdin-paths", input="\n".join(paths) + "\n").split() if paths else []
        if len(out) != len(paths):
            raise ValueError("hash count mismatch")
        return out

    # Raw bytes equal to the blob are unmodified. A file that differs raw is accepted only when git's own line-ending
    # normalisation for its path yields the blob (the comparison git status makes); anything else differs.
    raw = hashes(disk, "--no-filters")
    rest = [rel for rel, digest in zip(disk, raw) if head[rel][2] != digest]
    for rel, digest in zip(rest, hashes(rest)):
        if head[rel][2] != digest:
            problems.append(f"content differs from the revision: {rel}")
    return problems


def _git_source_identity(directory: Path, tracked: list[Path]) -> tuple[str, str]:
    actual = subprocess.check_output(
        ["git", "-C", str(directory), "rev-parse", "HEAD"], text=True, timeout=10
    ).strip()
    changed = subprocess.check_output(
        ["git", "-C", str(directory), "status", "--porcelain", "--untracked-files=no"],
        text=True, timeout=10,
    ).strip()
    subprocess.run(["git", "-C", str(directory), "ls-files", "--error-unmatch", "--", *map(str, tracked)],
                   check=True, capture_output=True, timeout=10)
    problems = _executed_file_problems(tracked)
    if problems:
        changed = "\n".join(filter(None, [changed, *problems]))
    return actual, changed


def _untracked_in_package_tree(package_dir: Path) -> str:
    """List untracked files, ignored ones included, anywhere under a package.

    Any such file could be imported in place of tracked source: a sibling
    package or extension shadowing a module the package imports internally,
    or cached bytecode in ``__pycache__`` executed instead of the verified
    ``.py``. Candidate verification requires this list to be empty.
    """
    return subprocess.check_output(
        ["git", "-C", str(package_dir), "ls-files", "--others", "--", "."],
        text=True, timeout=10,
    ).strip()


def _refuse_untracked(name: str, paths: list[Path]) -> None:
    first = paths[0]
    hint = (" (normal bytecode caches also count; candidate profiles require PYTHONDONTWRITEBYTECODE=1"
            " and a checkout without __pycache__)") if "__pycache__" in first.parts else ""
    raise RuntimeError(f"candidate source identity mismatch: {name}: untracked or ignored importable file {first}{hint}")


def _importable_top_level_name(entry: Path) -> str | None:
    """The module name a sys.path-root entry would provide, if any."""
    if entry.is_dir():
        return entry.name if entry.name.isidentifier() else None
    for suffix in (*importlib.machinery.all_suffixes(), ".pyw"):
        if entry.name.endswith(suffix):
            stem = entry.name[: -len(suffix)]
            return stem if stem.isidentifier() else None
    return None


def _untracked_importable_at_roots(roots: set[Path]) -> list[Path]:
    """Untracked or ignored importable top-level entries at candidate sys.path roots.

    A root is a candidate checkout directory placed on ``sys.path``. Any
    untracked ``*.py``/``*.pyc``/extension module, package or namespace
    directory there shadows a module the tracked code imports (for example a
    planted ``src/pydantic.py``). Only importable names at the root are
    considered, so ignored ``*.egg-info`` or ``.venv`` directories are not.
    """
    found = []
    for root in sorted(roots):
        listed = subprocess.check_output(["git", "-C", str(root), "ls-files", "-z", "--", "."],
                                         text=True, timeout=30)
        tracked = {Path(item) for item in listed.split("\0") if item}
        tracked_tops = {item.parts[0] for item in tracked}
        for entry in sorted(root.iterdir()):
            if _importable_top_level_name(entry) is None:
                continue
            if entry.name not in tracked_tops:
                # A directory is importable as a regular package (__init__.py)
                # or as a namespace portion holding importable modules.
                if not entry.is_dir() or entry.name == "__pycache__" or any(
                        child.is_file() and _importable_top_level_name(child) for child in entry.iterdir()):
                    found.append(entry)
            elif entry.is_dir() and (entry / "__init__.py").exists() and Path(entry.name, "__init__.py") not in tracked:
                found.append(entry / "__init__.py")
    return found


def _source_origin(spec: Any, name: str, *, package: bool) -> Path:
    """Return the plain-source file a spec will execute, or refuse.

    Extension modules, sourceless bytecode, namespace packages and a package
    directory shadowing a same-named module all yield a different loader or
    origin and are refused here, before anything is executed.
    """
    if (spec is None or spec.origin is None or not spec.has_location
            or type(spec.loader) is not importlib.machinery.SourceFileLoader):
        raise RuntimeError(f"candidate source identity mismatch: {name}")
    origin = Path(spec.origin).resolve()
    is_package = spec.submodule_search_locations is not None
    if is_package != package or (package and origin.name != "__init__.py") or (not package and origin.suffix != ".py"):
        raise RuntimeError(f"candidate source identity mismatch: {name}")
    if not origin.is_file():
        raise RuntimeError(f"candidate source identity mismatch: {name}")
    return origin


def _locate_without_import(name: str, expected_package_dir: Path | None) -> tuple[Path, list[Path]]:
    """Resolve every file a later import of ``name`` will execute, without executing any.

    Each level is resolved with the import system's own finders: the top-level
    package with ``importlib.util.find_spec`` on its undotted name (honouring
    ``sys.meta_path``), and each lower level with
    ``importlib.machinery.PathFinder.find_spec(part, [parent_dir])``. Neither
    runs module code, and both return the origin the import system will pick,
    so a package directory or extension module shadowing the expected ``.py``
    file is detected before import. Returns the module file and the ordered
    chain of executed files (package ``__init__.py`` files, then the module).
    """
    importlib.invalidate_caches()
    parts = name.split(".")
    executed: list[Path] = []
    spec = importlib.util.find_spec(parts[0])
    for index, part in enumerate(parts):
        if index:
            spec = importlib.machinery.PathFinder.find_spec(part, [str(executed[-1].parent)])
        is_package = index < len(parts) - 1
        origin = _source_origin(spec, name, package=is_package)
        if is_package and [Path(p).resolve() for p in spec.submodule_search_locations] != [origin.parent]:
            raise RuntimeError(f"candidate source identity mismatch: {name}")
        if index == 0 and expected_package_dir is not None and origin.parent != expected_package_dir.resolve():
            raise RuntimeError(f"candidate source identity mismatch: {name}")
        if index and origin.parent != executed[-1].parent:
            raise RuntimeError(f"candidate source identity mismatch: {name}")
        loaded = sys.modules.get(".".join(parts[: index + 1]))
        if loaded is not None and Path(getattr(loaded, "__file__", "") or "").resolve() != origin:
            raise RuntimeError(f"candidate source identity mismatch: {name}")
        executed.append(origin)
    return executed[-1], executed


def _verify_refusal_profile_sources(cp_root: Path | None = None, molt_root: Path | None = None) -> None:
    """Refuse false candidate provenance; this is source identity, not trust.

    Each module's file path is resolved and its Git identity checked *before*
    the module is imported; the imported module must then come from that exact
    verified file. This in-process check is a provenance-consistency check,
    not a trust boundary: the fresh-checkout pre-check in the qualification
    harness is the gate against modified or shadowed dependency checkouts.
    """
    expected = {
        "agent_control_plane.bounded": (CP_REVISION, cp_root / "src" / "agent_control_plane" if cp_root else None),
        "engine.producer_contract": (MOLTBOT_REVISION, molt_root / "engine" if molt_root else None),
        "agent_replay_bundle.importers": (REPLAY_REVISION, None),
        "odes.exporter": (ODES_REVISION, None),
        "agent_governance_evidence_pack.importer": (EVIDENCE_PACK_REVISION, None),
    }
    verified = {}
    checkouts = {}
    for name, (revision, package_dir) in expected.items():
        module_file, executed = _locate_without_import(name, package_dir)
        directory = module_file.parent
        try:
            actual, changed = _git_source_identity(directory, executed)
            untracked = _untracked_in_package_tree(executed[0].parent)
            toplevel = Path(subprocess.check_output(
                ["git", "-C", str(directory), "rev-parse", "--show-toplevel"], text=True, timeout=10
            ).strip()).resolve()
        except (subprocess.CalledProcessError, OSError) as exc:
            raise RuntimeError(f"candidate source identity mismatch: {name}") from exc
        if actual != revision or changed:
            raise RuntimeError(f"candidate source identity mismatch: {name}")
        try:
            tree_problems = _checkout_source_problems(toplevel)
        except (subprocess.CalledProcessError, OSError, ValueError) as exc:
            raise RuntimeError(f"candidate source identity mismatch: {name}") from exc
        if tree_problems:
            raise RuntimeError(f"candidate source identity mismatch: {name}")
        if untracked:
            _refuse_untracked(name, [executed[0].parent / untracked.splitlines()[0]])
        verified[name] = (module_file, executed)
        checkouts[name] = (toplevel, executed[0].parent.parent)
    for name, (toplevel, package_root) in checkouts.items():
        roots = {package_root}
        for item in sys.path:
            try:
                path = Path(item or os.getcwd()).resolve()
            except OSError:
                continue
            if path.is_dir() and path.is_relative_to(toplevel):
                roots.add(path)
        try:
            shadows = _untracked_importable_at_roots(roots)
        except (subprocess.CalledProcessError, OSError) as exc:
            raise RuntimeError(f"candidate source identity mismatch: {name}") from exc
        if shadows:
            _refuse_untracked(name, shadows)
    manifest = Path(os.environ["UPSTREAM_MANIFEST_EXAMPLE"]).resolve()
    actual = subprocess.check_output(["git", "-C", str(manifest.parent), "rev-parse", "HEAD"],
                                     text=True, timeout=10).strip()
    changed = subprocess.check_output(["git", "-C", str(manifest.parent), "diff", "HEAD", "--", str(manifest)],
                                      text=True, timeout=10).strip()
    subprocess.run(["git", "-C", str(manifest.parent), "ls-files", "--error-unmatch", manifest.name],
                   check=True, capture_output=True, timeout=10)
    if actual != MANIFEST_REVISION or changed:
        raise RuntimeError("candidate source identity mismatch: manifest")
    # Nothing from any candidate package is imported until every origin in
    # every chain has been verified. Re-resolve immediately before import so a
    # change after verification is refused rather than executed.
    for name, (module_file, executed) in verified.items():
        if _locate_without_import(name, None) != (module_file, executed):
            raise RuntimeError(f"candidate source identity mismatch: {name}")
        try:
            rehash_problems = _executed_file_problems(executed) + _checkout_source_problems(checkouts[name][0])
        except (subprocess.CalledProcessError, OSError, ValueError) as exc:
            raise RuntimeError(f"candidate source identity mismatch: {name}") from exc
        if rehash_problems:
            raise RuntimeError(f"candidate source identity mismatch: {name}")
        module = importlib.import_module(name)
        if Path(module.__file__).resolve() != module_file:
            raise RuntimeError(f"candidate source identity mismatch: {name}")


def load_executor_runtime() -> dict[str, Any]:
    cp_root = _repo_path("MOLTBOT_SAFE_CONTROL_PLANE_ROOT", "upstream/control-plane")
    molt_root = _repo_path("MOLTBOT_SAFE_ROOT", "upstream/moltbot-safe")
    missing = [str(p) for p in (cp_root, molt_root) if not p.exists()]
    if missing:
        raise RuntimeError("pinned upstream checkout is unavailable: " + ", ".join(missing))
    for path in (str(cp_root / "src"), str(molt_root)):
        if path not in sys.path:
            sys.path.insert(0, path)

    if RUNTIME_COMPATIBILITY_PROFILE in STRICT_SOURCE_PROFILES:
        _verify_refusal_profile_sources(cp_root, molt_root)
    producer = importlib.import_module("engine.producer_contract")
    cp = importlib.import_module("agent_control_plane.bounded")
    if producer.EXECUTOR_PRODUCER_PROFILE_ID != MOLTBOT_PRODUCER_PROFILE_ID:
        raise RuntimeError("unsupported Moltbot executor producer profile id")
    if producer.EXECUTOR_PRODUCER_PROFILE_VERSION != MOLTBOT_PRODUCER_PROFILE_VERSION:
        raise RuntimeError("unsupported Moltbot executor producer profile version")
    return {
        "producer": producer,
        "cp": cp,
        "PinnedControlPlaneExecutor": producer.PinnedControlPlaneExecutor,
        "DurableRefundDestination": producer.DurableRefundDestination,
        "ExecutionEnvelope": producer.ExecutionEnvelope,
        "ExecutionOperation": producer.ExecutionOperation,
        "LocalExecutionPolicy": producer.LocalExecutionPolicy,
        "commitment": producer.commitment,
        "export_execution_artifacts": producer.export_execution_artifacts,
    }


def actual_executor_classes() -> dict[str, Any]:
    runtime = load_executor_runtime()
    return {
        key: runtime[key]
        for key in (
            "PinnedControlPlaneExecutor",
            "DurableRefundDestination",
            "ExecutionEnvelope",
            "ExecutionOperation",
            "LocalExecutionPolicy",
        )
    }

def _sqlite_rows(path: Path, table: str) -> list[dict[str, Any]]:
    with sqlite3.connect(path) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(row) for row in conn.execute(f"SELECT * FROM {table} ORDER BY rowid")]


def _effect_rows(destination: Any) -> list[dict[str, Any]]:
    return _sqlite_rows(Path(destination.path), "effects")


def _asdict(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if dataclasses.is_dataclass(value):
        return dataclasses.asdict(value)
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if isinstance(value, dict):
        return dict(value)
    return dict(value.__dict__)


def _json_dumps(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _json_loads(value: str | None) -> Any:
    return json.loads(value) if value else None


def _manifest() -> dict[str, Any]:
    path = _repo_path("UPSTREAM_MANIFEST_EXAMPLE", "upstream/manifest/examples/refund_integration_v1_1.manifest.json")
    return json.loads(path.read_text(encoding="utf-8"))


def _export_sources(
    workflow: Any,
    proposal: Any,
    request: Any,
    result: Any,
    destination: Any,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    runtime = load_executor_runtime()
    cp_record = workflow.records.load().model_dump(mode="json")
    producer_export = runtime["export_execution_artifacts"](
        request,
        result,
        destination,
        repository_revision=MOLTBOT_REVISION,
        source_asserted_provenance={
            "producer": "cogno-us/moltbot-safe",
            "consumer": "cogno-us/alvorada:gax_ref_runtime",
        },
    )
    return (
        cp_record,
        proposal.model_dump(mode="json", exclude_none=False),
        producer_export,
    )

def import_replay_bundle(cp_record: dict[str, Any], proposal: dict[str, Any] | None, moltbot: dict[str, Any] | None = None) -> Any:
    from agent_replay_bundle.importers import import_bounded_workflow

    return import_bounded_workflow(cp_record, proposal=proposal, moltbot_export=moltbot, control_plane_revision=CP_REVISION)


def reconstruction_dict(reconstructed: Any) -> dict[str, Any]:
    return reconstructed.model_dump(mode="json") if hasattr(reconstructed, "model_dump") else dict(reconstructed)


def export_odes_reference(manifest: dict[str, Any], reconstruction_bundle: dict[str, Any]) -> dict[str, Any]:
    from odes import evaluate_recipient_package, export_cognous_stack_package

    package = export_cognous_stack_package(
        manifest,
        reconstruction_bundle,
        relying_party="recipient.example.org",
        purpose="audit",
        expires_at="2027-01-01T00:00:00Z",
    )
    policy = {
        "now": "2026-10-06T00:00:00Z",
        "purpose": "audit",
        "relying_party": "recipient.example.org",
        "status_inputs": {},
        "supported_profiles": [package["profile"]["implementation_profile"]],
        "trusted_digests": [],
        "trusted_key_refs": [],
        "evaluation_scope": "audit",
        "status_max_age_seconds": 300,
        "allow_unauthenticated_informational_inspection": False,
    }
    validation = evaluate_recipient_package(package, policy)
    return {"odes_package": package, "recipient_validation": validation, "recipient_policy": policy, "exchange_metadata": {"note": "additional exchange metadata is outside the digest-covered ODES package"}}


def _artifact_facts(odes_reference: dict[str, Any]) -> dict[str, Any]:
    facts = dict(odes_reference["odes_package"].get("provenance", {}).get("execution_facts", {}))
    effects = facts.get("destination_effects") or []
    effect_ids = [item.get("effect_id") for item in effects if isinstance(item, dict) and item.get("effect_id")]
    destination = facts.get("destination_observed")
    # Pending identifies an attempted operation requiring reconciliation, not
    # proof of a destination effect. Fresh absence cannot establish that an
    # earlier in-flight request terminated. No finality contract is supplied by
    # this producer generation; do not infer one from absence or retry denial.
    attempted_ids = {
        item["effect_id"]
        for item in facts.get("control_plane_attempt_transitions", [])
        if isinstance(item, dict) and item.get("effect_id")
    }
    attempted_ids.update(
        item["effect_id"] for item in facts.get("execution_results", [])
        if isinstance(item, dict) and item.get("attempted") and item.get("effect_id")
    )
    histories = facts.get("effect_observation_history") or {}
    pending = []
    for effect_id in sorted(attempted_ids | set(effect_ids)):
        state = histories.get(effect_id, {}).get("latest_supported_destination_state", destination)
        if state != "applied":
            pending.append(effect_id)
    facts["pending_effects"] = pending
    facts["unresolved_delivery"] = bool(pending)
    return facts


def _pipeline(manifest: dict[str, Any], cp_record: dict[str, Any], proposal: dict[str, Any] | None, moltbot: dict[str, Any] | None, *, predecessor: dict[str, Any] | None = None, predecessor_packet_id: str | None = None, state_version: int = 1) -> dict[str, Any]:
    reconstructed = import_replay_bundle(cp_record, proposal, moltbot)
    bundle = reconstruction_dict(reconstructed)
    odes = export_odes_reference(manifest, bundle)
    facts = _artifact_facts(odes)
    successor = None
    if predecessor is not None:
        successor = make_successor_packet(predecessor, facts=facts, state_version=state_version, current_bundle=bundle, predecessor_packet_id=predecessor_packet_id)
    return {
        "reconstruction": reconstructed,
        "reconstruction_bundle": bundle,
        "odes_reference": odes,
        "successor_packet": successor,
        "execution_facts": facts,
        "producer_identity_refs": _producer_identity_refs(moltbot),
    }


def execution_facts(bundle: dict[str, Any]) -> dict[str, Any]:
    return dict(export_odes_reference(_manifest(), bundle)["odes_package"].get("provenance", {}).get("execution_facts", {}))


def _build_request_from_decision(runtime: dict[str, Any], proposal: Any, resolver: Any, decision: Any) -> Any:
    context = resolver.authority_context(proposal.authority_context_ref or "")
    institution = context.get("institution") if isinstance(context, dict) else {}
    binding = decision.binding
    if binding is None:
        raise ValueError("authorized execution requires a decision authorization binding")
    operation = runtime["ExecutionOperation"](
        actor=proposal.actor,
        principal=proposal.principal,
        institution_id=institution["institution_id"],
        authority_domain=institution["authority_domain"],
        manifest_id=proposal.manifest_id,
        manifest_version=proposal.manifest_version,
        manifest_digest=proposal.manifest_digest,
        proposal_commitment=runtime["commitment"](proposal.model_dump(mode="json", exclude_none=False)),
        action_id=proposal.action_id,
        adapter_id=proposal.adapter_id,
        target=proposal.target,
        payload=json.loads(json.dumps(proposal.payload)),
        payload_commitment=proposal.payload_commitment,
        requested_permissions=tuple(proposal.requested_permissions),
        amount=proposal.amount,
        unit=proposal.unit,
        effects=proposal.effects,
        authority_context_id=proposal.authority_context_ref,
        requirement_id=proposal.requirement_id,
        grant_id=binding.grant_id,
        grant_revision=binding.grant_revision,
        effective_max_effects=binding.effective_max_effects,
    )
    producer = runtime["producer"]
    return runtime["ExecutionEnvelope"](producer.EXECUTION_ENVELOPE_VERSION, decision.decision_id, decision.effect_id, operation)


class Obj:
    def __init__(self, values: dict[str, Any]):
        self.__dict__.update(values)


def _validate_bound_association(association: dict[str, Any]) -> str | None:
    proposal = association.get("proposal")
    decision_id = association.get("decision_id")
    effect_id = association.get("effect_id")
    if not proposal:
        return "stored_proposal_unavailable"
    moltbot = association.get("moltbot")
    if not moltbot:
        return None
    envelope = moltbot.get("execution_envelope") or {}
    result = moltbot.get("execution_result") or {}
    operation = envelope.get("operation") or {}
    if envelope.get("decision_id") != decision_id or envelope.get("effect_id") != effect_id:
        return "stored_envelope_identity_mismatch"
    if result.get("decision_id") != decision_id or result.get("effect_id") != effect_id:
        return "stored_result_identity_mismatch"
    runtime = load_executor_runtime()
    if operation.get("proposal_commitment") != runtime["commitment"](proposal):
        return "stored_operation_proposal_commitment_mismatch"
    for row in moltbot.get("effects") or []:
        if row.get("effect_id") != effect_id:
            return "stored_effect_identity_mismatch"
    for row in moltbot.get("attempts") or []:
        if row.get("effect_id") != effect_id or row.get("decision_id") != decision_id:
            return "stored_attempt_identity_mismatch"
    return None


def _producer_identity_refs(moltbot: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(moltbot, dict):
        return {}
    envelope = moltbot.get("execution_envelope") or {}
    result = moltbot.get("execution_result") or {}
    attempt_identity = moltbot.get("attempt_identity")
    executor_attempt_ids = [
        row.get("attempt_id")
        for row in (moltbot.get("attempts") or [])
        if isinstance(row, dict) and row.get("attempt_id")
    ]
    control_plane_attempt_ids = [
        row.get("attempt_id")
        for row in (moltbot.get("control_plane_attempts") or [])
        if isinstance(row, dict) and row.get("attempt_id")
    ]
    refs = {
        "decision_id": result.get("decision_id") or envelope.get("decision_id"),
        "effect_id": result.get("effect_id") or envelope.get("effect_id"),
        "attempt_identity": json.loads(_json_dumps(attempt_identity)) if isinstance(attempt_identity, dict) else None,
        "executor_attempt_ids": executor_attempt_ids,
        "control_plane_attempt_ids": control_plane_attempt_ids,
        "executor_producer_profile": json.loads(_json_dumps(moltbot.get("producer_profile"))) if isinstance(moltbot.get("producer_profile"), dict) else None,
        "executor_repository": json.loads(_json_dumps(moltbot.get("repository"))) if isinstance(moltbot.get("repository"), dict) else None,
    }
    return {k: v for k, v in refs.items() if v not in (None, [], {})}


def _retained_artifact_export(
    artifacts: dict[str, Any],
    *,
    state: str,
    lineage: dict[str, Any] | None = None,
) -> dict[str, Any]:
    reconstruction = copy_value = json.loads(_json_dumps(artifacts["reconstruction_bundle"]))
    odes_ref = artifacts["odes_reference"]
    odes_retained = {
        "odes_package": json.loads(_json_dumps(odes_ref.get("odes_package"))),
        "recipient_validation": json.loads(_json_dumps(odes_ref.get("recipient_validation"))),
        "exchange_metadata": json.loads(_json_dumps(odes_ref.get("exchange_metadata") or {})),
    }
    successor = json.loads(_json_dumps(artifacts.get("successor_packet"))) if artifacts.get("successor_packet") is not None else None
    refs = {
        **json.loads(_json_dumps(artifacts.get("producer_identity_refs") or {})),
        "reconstruction_bundle_id": reconstruction.get("bundle_id"),
        "reconstruction_digest": digest(reconstruction),
        "odes_package_digest": digest(odes_retained["odes_package"]) if odes_retained["odes_package"] is not None else None,
        "odes_validation_digest": digest(odes_retained["recipient_validation"]) if odes_retained["recipient_validation"] is not None else None,
        "successor_packet_id": successor.get("packet_id") if isinstance(successor, dict) else None,
        "successor_packet_digest": (
            successor.get("packet_digest") if isinstance(successor, dict) else None
        ),
    }
    commitments = {
        "reconstruction_bundle": refs.get("reconstruction_digest"),
        "odes_package": refs.get("odes_package_digest"),
        "recipient_validation": refs.get("odes_validation_digest"),
        "successor_packet": refs.get("successor_packet_digest"),
    }
    return {
        "export_profile": GAX_ARTIFACT_EXPORT_PROFILE,
        "export_version": GAX_ARTIFACT_EXPORT_VERSION,
        "state": state,
        "reconstruction_bundle": reconstruction,
        "odes": odes_retained,
        "successor_packet": successor,
        "producer_refs": refs,
        "content_commitments": {k: v for k, v in commitments.items() if v is not None},
        "lineage": json.loads(_json_dumps(lineage or {"relationship": "original"})),
    }


def _validate_retained_artifact_export(value: dict[str, Any]) -> str | None:
    if value.get("export_profile") != GAX_ARTIFACT_EXPORT_PROFILE:
        return "unsupported_artifact_export_profile"
    if value.get("export_version") not in {"1.0.0", GAX_ARTIFACT_EXPORT_VERSION}:
        return "unsupported_artifact_export_version"
    reconstruction = value.get("reconstruction_bundle")
    odes = value.get("odes") or {}
    successor = value.get("successor_packet")
    refs = value.get("producer_refs") or {}
    commitments = value.get("content_commitments") or {}
    if not isinstance(reconstruction, dict):
        return "retained_reconstruction_missing"
    if refs.get("reconstruction_bundle_id") != reconstruction.get("bundle_id"):
        return "retained_reconstruction_identity_mismatch"
    if refs.get("reconstruction_digest") != digest(reconstruction):
        return "retained_reconstruction_digest_mismatch"
    if commitments.get("reconstruction_bundle") != refs.get("reconstruction_digest"):
        return "retained_reconstruction_commitment_mismatch"
    package = odes.get("odes_package")
    validation = odes.get("recipient_validation")
    if package is not None and refs.get("odes_package_digest") != digest(package):
        return "retained_odes_package_digest_mismatch"
    if package is not None and commitments.get("odes_package") != refs.get("odes_package_digest"):
        return "retained_odes_package_commitment_mismatch"
    if validation is not None and refs.get("odes_validation_digest") != digest(validation):
        return "retained_odes_validation_digest_mismatch"
    if validation is not None and commitments.get("recipient_validation") != refs.get("odes_validation_digest"):
        return "retained_odes_validation_commitment_mismatch"
    if successor is not None:
        if refs.get("successor_packet_id") != successor.get("packet_id"):
            return "retained_successor_identity_mismatch"
        if refs.get("successor_packet_digest") != successor.get("packet_digest"):
            return "retained_successor_digest_mismatch"
        if successor.get("packet_digest") != digest({k: v for k, v in successor.items() if k != "packet_digest"}):
            return "retained_successor_content_digest_mismatch"
        if commitments.get("successor_packet") != refs.get("successor_packet_digest"):
            return "retained_successor_commitment_mismatch"
    return None


def _artifacts_from_retained_export(value: dict[str, Any]) -> dict[str, Any]:
    problem = _validate_retained_artifact_export(value)
    if problem:
        raise ValueError(problem)
    odes = value["odes"]
    facts = _artifact_facts({
        "odes_package": odes["odes_package"],
        "recipient_validation": odes.get("recipient_validation"),
    })
    return {
        "reconstruction_bundle": value["reconstruction_bundle"],
        "odes_reference": {
            "odes_package": odes["odes_package"],
            "recipient_validation": odes.get("recipient_validation"),
            "exchange_metadata": odes.get("exchange_metadata") or {},
        },
        "successor_packet": value.get("successor_packet"),
        "execution_facts": facts,
        # The retained export has already passed commitment/identity validation.
        # Preserve every producer reference actually present so a derivative
        # does not erase historical decision/effect/attempt provenance. The
        # artifact-specific references and commitments are recomputed normally
        # by _retained_artifact_export when the derivative is constructed.
        "producer_identity_refs": json.loads(_json_dumps(value.get("producer_refs") or {})),
        "artifact_export": value,
    }


def _execution_response(assessment: dict[str, Any], status: str, result: Any, decision: Any, artifacts: dict[str, Any], *, attempted_override: bool | None = None, newly_executed_override: bool | None = None) -> dict[str, Any]:
    assessment["stages"]["authority"] = "authorized" if status in {"executed", "unknown", "partial", "reconciled", "observed"} else status
    attempted = bool(getattr(result, "attempted", status == "executed"))
    newly_executed = bool(getattr(result, "newly_executed", False))
    if attempted_override is not None:
        attempted = attempted_override
    if newly_executed_override is not None:
        newly_executed = newly_executed_override
    return {
        "assessment": assessment,
        "execution": {
            "attempted": attempted,
            "attempt_status": status,
            "newly_executed": newly_executed,
            "destination_observed": getattr(result, "observed_state", artifacts["execution_facts"].get("destination_observed")),
            "effect_id": getattr(result, "effect_id", getattr(decision, "effect_id", None)),
            "decision_id": getattr(result, "decision_id", getattr(decision, "decision_id", None)),
            "attempt_id": getattr(result, "attempt_id", None),
            "acknowledged": getattr(result, "acknowledged", None),
            "observation": getattr(result, "observation", None),
            "control_plane_evidence": getattr(result, "control_plane_evidence", None),
        },
        "current_reconstruction_bundle": artifacts["reconstruction_bundle"],
        "odes_reference": artifacts["odes_reference"],
        "successor_packet": artifacts["successor_packet"],
        "execution_facts": artifacts["execution_facts"],
        "artifact_export": artifacts.get("artifact_export"),
    }


def _artifacts_from_association(manifest: dict[str, Any], message: dict[str, Any], association: dict[str, Any]) -> dict[str, Any]:
    retained = association.get("artifact_export")
    if not isinstance(retained, dict):
        raise LookupError("original_artifacts_unavailable")
    return _artifacts_from_retained_export(retained)


def _duplicate_redelivery_result(message: dict[str, Any], assessment: dict[str, Any], manifest: dict[str, Any], association: dict[str, Any]) -> dict[str, Any]:
    problem = _validate_bound_association(association)
    if problem:
        assessment["errors"].append("GAX-EXECUTION-STORED-WORKFLOW-INTEGRITY-FAILED")
        return {"assessment": assessment, "execution": {"attempted": False, "reason": problem, "attempt_status": "unresolved_duplicate"}, "successor_packet": None}
    try:
        artifacts = _artifacts_from_association(manifest, message, association)
    except (LookupError, ValueError) as exc:
        assessment["errors"].append("GAX-ARTIFACTS-UNAVAILABLE-OR-INVALID")
        return {
            "assessment": assessment,
            "execution": {
                "attempted": False,
                "reason": str(exc),
                "attempt_status": "unresolved_duplicate",
            },
            "successor_packet": None,
            "artifact_export": None,
        }
    result_data = association.get("result") or {}
    status = association.get("status") or result_data.get("status") or "unresolved"
    if status == "executed":
        status = "reconciled"
    result = Obj({**result_data, "status": status, "newly_executed": False}) if result_data else None
    decision = Obj({"decision_id": association.get("decision_id"), "effect_id": association.get("effect_id")})
    return _execution_response(assessment, status, result, decision, artifacts, attempted_override=False, newly_executed_override=False)


def _recover_checkpoint(message: dict[str, Any], assessment: dict[str, Any], manifest: dict[str, Any], store: "TransactionalExchangeStore", checkpoint: dict[str, Any], destination: Any | None) -> dict[str, Any]:
    problem = _validate_bound_association(checkpoint)
    if problem:
        assessment["errors"].append("GAX-EXECUTION-CHECKPOINT-INTEGRITY-FAILED")
        return {"assessment": assessment, "execution": {"attempted": False, "reason": problem, "attempt_status": "hold"}, "successor_packet": None}
    if checkpoint.get("moltbot") and checkpoint.get("result"):
        contract = checkpoint["moltbot"].get("producer_profile") or {}
        if contract.get("profile_version") != MOLTBOT_PRODUCER_PROFILE_VERSION:
            return {"assessment": assessment, "execution": {"attempted": False, "reason": "historical_generation_requires_revision_pinned_recovery"}, "successor_packet": None}
        pipe = _pipeline(
            manifest,
            checkpoint["cp_record"],
            checkpoint["proposal"],
            checkpoint.get("moltbot"),
            predecessor=message,
        )
        source_commitment = digest({
            "cp_record": checkpoint["cp_record"],
            "proposal": checkpoint["proposal"],
            "moltbot": checkpoint.get("moltbot"),
        })
        pipe["artifact_export"] = _retained_artifact_export(
            pipe,
            state="regenerated_derivative",
            lineage={
                "relationship": "regenerated_derivative",
                "original_artifacts": "unavailable",
                "source_checkpoint_commitment": source_commitment,
                "effect_reexecution": False,
            },
        )
        result_status = (checkpoint.get("result") or {}).get("status")
        status = result_status or checkpoint.get("status") or "reconciled"
        if status in {"executed", "dispatched", "bound"}:
            status = "reconciled"
        store.record_workflow(
            message,
            {
                "proposal_record": checkpoint["proposal"],
                "decision": checkpoint["decision"],
                "request": checkpoint.get("request"),
                "result": checkpoint.get("result"),
                "status": status,
                "cp_record": checkpoint["cp_record"],
                "moltbot_record": checkpoint.get("moltbot"),
                **pipe,
            },
        )
        result = Obj({**checkpoint["result"], "status": status, "newly_executed": False})
        decision = Obj({"decision_id": checkpoint.get("decision_id"), "effect_id": checkpoint.get("effect_id")})
        return _execution_response(
            assessment, status, result, decision, pipe,
            attempted_override=False, newly_executed_override=False,
        )
    if destination is not None:
        rows = [r for r in _effect_rows(destination) if r.get("effect_id") == checkpoint.get("effect_id")]
        if rows:
            assessment["errors"].append("GAX-EXECUTION-CHECKPOINT-DESTINATION-OBSERVED-WITHOUT-RETAINED-ATTEMPT")
            return {"assessment": assessment, "execution": {"attempted": False, "reason": "destination_observed_without_replayable_attempt", "attempt_status": "hold", "effect_id": checkpoint.get("effect_id"), "decision_id": checkpoint.get("decision_id")}, "successor_packet": None}
    assessment["errors"].append("GAX-EXECUTION-CHECKPOINT-UNRESOLVED")
    return {"assessment": assessment, "execution": {"attempted": False, "reason": "checkpoint_without_dispatch_evidence", "attempt_status": "hold", "effect_id": checkpoint.get("effect_id"), "decision_id": checkpoint.get("decision_id")}, "successor_packet": None}


def _run_current_request(*, message: dict[str, Any], bundle: dict[str, Any], manifest: dict[str, Any], destination: Any, store_path: Path, resolver: Any, evaluation_time: str, execution_policy_factory: Any, observation_policy: Any, observation_clock: Any = None, mutate_resolver_after_decision=None, lose_ack: bool = False, partial_delivery: bool = False, store: "TransactionalExchangeStore" | None = None, lease_holder: str | None = None, fault_after_dispatch: bool = False, fault_evidence_once: bool = False, generation_fence: Any = None, lineage_generation: int | None = None, runtime_authority_profile: Any = None, allow_test_time: bool = False) -> dict[str, Any]:
    runtime = load_executor_runtime()
    cp = runtime["cp"]
    now = parse_time(evaluation_time)
    proposal = runtime_proposal_model(bundle)
    record_suffix = digest({"message_id": message["message_id"], "message_digest": message.get("message_digest"), "evaluation_time": evaluation_time})[-16:]
    record_store = cp.BoundedRecordStore(store_path.parent / f"control-plane-{message['message_id']}-{record_suffix}.json", proposal.run_id or "run-gax-imx")
    cp_destination = cp.LocalRefundDestination(store_path.parent / f"cp-placeholder-{message['message_id']}-{record_suffix}.json")
    workflow = cp.BoundedAuthorizationWorkflow(manifest=manifest, resolver=resolver, destination=cp_destination, records=record_store, observation_policy=observation_policy, **_workflow_options(runtime_authority_profile, allow_test_time))
    decision = workflow.decide(proposal, now=now)
    proposal_record = proposal.model_dump(mode="json", exclude_none=False)
    cp_record = record_store.load().model_dump(mode="json")

    if decision.result != "authorized":
        pipe = _pipeline(manifest, cp_record, proposal_record, None, predecessor=message)
        pipe["artifact_export"] = _retained_artifact_export(
            pipe,
            state="original_complete",
            lineage={"relationship": "original", "effect_reexecution": False},
        )
        return {"status": decision.result, "decision": decision, "result": None, "destination_effects": {}, "proposal_record": proposal_record, "cp_record": cp_record, "moltbot_record": None, **pipe}

    if store is not None:
        owner=store.claim_effect(message,decision.effect_id,lease_holder)
        if owner == store.LEASE_HELD:
            return {"status":"hold","fault":"message_processing_lease_held",
                    "owner_message_id":message["message_id"],"decision":decision}
        if owner is not None:
            return {"status":"hold","fault":"effect_owned_by_another_message",
                    "owner_message_id":owner,"decision":decision}
    if mutate_resolver_after_decision:
        mutate_resolver_after_decision(resolver)

    request = _build_request_from_decision(runtime, proposal, resolver, decision)
    execution_destination = destination
    if (generation_fence is None) != (lineage_generation is None):
        raise ValueError("generation_fence and lineage_generation must be supplied together")
    if generation_fence is not None:
        claim = GenerationFenceClaim(
            conversation_id=message["conversation_id"],
            effect_id=decision.effect_id,
            generation=lineage_generation,
        )
        execution_destination = generation_fence.wrap_destination(destination, claim)
    if store is not None:
        store.record_dispatch_checkpoint(message, {"status": "bound", "proposal_record": proposal_record, "decision": _asdict(decision), "request": _asdict(request), "cp_record": cp_record})
    policy = execution_policy_factory(request.operation)
    if not isinstance(policy, runtime["LocalExecutionPolicy"]):
        raise TypeError("execution_policy_factory must return LocalExecutionPolicy")
    executor = runtime["PinnedControlPlaneExecutor"](
        workflow=workflow,
        destination=execution_destination,
        policy=policy,
        observation_clock=observation_clock,
    )
    simulate = "partial" if partial_delivery else ("lost_ack" if lose_ack else None)
    result = executor.execute(envelope=request, proposal=proposal, decision=decision, now=now, simulate=simulate)
    cp_record, p, moltbot = _export_sources(workflow, proposal, request, result, destination)
    checkpoint_payload = {"status": result.status, "proposal_record": p, "decision": _asdict(decision), "request": _asdict(request), "result": _asdict(result), "cp_record": cp_record, "moltbot_record": moltbot}
    if store is not None:
        store.record_dispatch_checkpoint(message, checkpoint_payload)
    if fault_after_dispatch:
        return {"status": "interrupted_after_dispatch", "result": result, "decision": decision, "request": request, "destination": destination, "destination_effects": {row["effect_id"]: row for row in _effect_rows(destination)}, "proposal_record": p, "cp_record": cp_record, "moltbot_record": moltbot, "fault": "after_dispatch_before_workflow_persistence"}
    if fault_evidence_once and store is not None and not store.consume_fault_once(message["message_id"], "evidence_export"):
        return {"status": "evidence_export_failed", "result": result, "decision": decision, "request": request, "destination": destination, "destination_effects": {row["effect_id"]: row for row in _effect_rows(destination)}, "proposal_record": p, "cp_record": cp_record, "moltbot_record": moltbot, "fault": "replay_odes_export_failed_after_dispatch"}
    pipe = _pipeline(manifest, cp_record, p, moltbot, predecessor=message)
    pipe["artifact_export"] = _retained_artifact_export(
        pipe,
        state="original_complete",
        lineage={"relationship": "original", "effect_reexecution": False},
    )
    return {"status": result.status, "result": result, "decision": decision, "request": request, "destination": destination, "destination_effects": {row["effect_id"]: row for row in _effect_rows(destination)}, "proposal_record": p, "cp_record": cp_record, "moltbot_record": moltbot, **pipe}


def run_exchange(message: dict[str, Any], bundle: dict[str, Any], registry: LocalRegistry, destination: Any, *, evaluation_time: str, manifest: dict[str, Any], store_path: str | Path, resolver: Any | None = None, execution_policy_factory: Any | None = None, observation_policy: Any | None = None, observation_clock: Any = None, mutate_resolver_after_decision=None, lose_ack: bool = False, partial_delivery: bool = False, fault_after_dispatch: bool = False, fault_evidence_once: bool = False, generation_fence: Any = None, lineage_generation: int | None = None, runtime_authority_profile: Any = None, allow_test_time: bool = False) -> dict[str, Any]:
    _workflow_options(runtime_authority_profile, allow_test_time)
    store_path = Path(store_path)
    store = TransactionalExchangeStore(store_path)
    # Look up the retained receipt without inserting: a message that is not
    # accepted must never reserve its message_id.
    seen_messages = store.seen_messages()
    prior_digest = seen_messages.get(message.get("message_id"))
    if prior_digest is not None and prior_digest != message.get("message_digest"):
        err = "GAX-INTEGRITY-MESSAGE-ID-REUSE"
        return {"assessment": {"permitted_handling": "REFUSE", "errors": [err], "stages": {"identity_binding": "failed"}}, "execution": {"attempted": False, "reason": err}, "successor_packet": None}
    if prior_digest is not None:
        seen_messages = {key: value for key, value in seen_messages.items() if key != message["message_id"]}
    assessment = assess_message(message, bundle, registry, evaluation_time=evaluation_time, seen_messages=seen_messages)
    if assessment["permitted_handling"] != "ACCEPT_FOR_ASSESSMENT":
        return {"assessment": assessment, "execution": {"attempted": False, "reason": "message_not_execution_eligible"}, "successor_packet": None}
    if lineage_generation is not None and (type(lineage_generation) is not int or lineage_generation < 0):
        assessment["errors"].append("GAX-EXECUTION-LINEAGE-GENERATION-INVALID")
        return {"assessment": assessment, "execution": {"attempted": False, "reason": "lineage_generation_invalid"}, "successor_packet": None}
    duplicate, err = store.record_message(message)
    if err:
        return {"assessment": {"permitted_handling": "REFUSE", "errors": [err], "stages": {"identity_binding": "failed"}}, "execution": {"attempted": False, "reason": err}, "successor_packet": None}

    association = store.workflow_for_message(message)
    if duplicate and association is not None:
        return _duplicate_redelivery_result(message, assessment, manifest, association)
    checkpoint = store.checkpoint_for_message(message)
    if duplicate and checkpoint is not None:
        return _recover_checkpoint(message, assessment, manifest, store, checkpoint, destination)
    if duplicate and (resolver is None or destination is None):
        assessment["errors"].append("GAX-EXECUTION-RECEIPT-WITHOUT-COMPLETED-WORKFLOW")
        return {"assessment": assessment, "execution": {"attempted": False, "reason": "receipt_without_completed_workflow", "attempt_status": "unresolved_duplicate"}, "successor_packet": None}
    if resolver is None:
        assessment["errors"].append("GAX-AUTHORITY-TRUSTED-RESOLVER-REQUIRED")
        return {"assessment": assessment, "execution": {"attempted": False, "reason": "trusted_resolver_required"}, "successor_packet": None}
    if destination is None:
        assessment["errors"].append("GAX-EXECUTION-DESTINATION-REQUIRED")
        return {"assessment": assessment, "execution": {"attempted": False, "reason": "destination_required"}, "successor_packet": None}

    if execution_policy_factory is None:
        assessment["errors"].append("GAX-EXECUTION-POLICY-REQUIRED")
        return {"assessment": assessment, "execution": {"attempted": False, "reason": "execution_policy_factory_required"}, "successor_packet": None}
    if observation_policy is None:
        return {"assessment": assessment, "execution": {"attempted": False, "reason": "observation_policy_required"}, "successor_packet": None}
    lease_holder = uuid.uuid4().hex
    try:
        return _finish_exchange(message, assessment, store, lease_holder, lambda: _run_current_request(message=message, bundle=bundle, manifest=manifest, destination=destination, store_path=store_path, resolver=resolver, evaluation_time=evaluation_time, execution_policy_factory=execution_policy_factory, observation_policy=observation_policy, observation_clock=observation_clock, mutate_resolver_after_decision=mutate_resolver_after_decision, lose_ack=lose_ack, partial_delivery=partial_delivery, store=store, lease_holder=lease_holder, fault_after_dispatch=fault_after_dispatch, fault_evidence_once=fault_evidence_once, generation_fence=generation_fence, lineage_generation=lineage_generation, runtime_authority_profile=runtime_authority_profile, allow_test_time=allow_test_time))
    finally:
        store.release_lease(message, lease_holder)


def _finish_exchange(message, assessment, store, lease_holder, run_current):
    artifacts = run_current()
    if artifacts.get("fault")=="message_processing_lease_held":
        return {"assessment":assessment,"execution":{"attempted":False,"newly_executed":False,"attempt_status":"hold",
            "reason":"message_processing_lease_held","effect_id":artifacts["decision"].effect_id,
            "retry_eligible":False,"recovery_route":"resume_original_exchange"},"successor_packet":None}
    if artifacts.get("fault")=="effect_owned_by_another_message":
        return {"assessment":assessment,"execution":{"attempted":False,"newly_executed":False,"attempt_status":"hold",
            "reason":"effect_owned_by_another_message","effect_id":artifacts["decision"].effect_id,
            "owner_message_id":artifacts["owner_message_id"],"retry_eligible":False,
            "recovery_route":"resume_original_exchange"},"successor_packet":None}
    result = artifacts.get("result")
    status = artifacts["status"]
    if artifacts.get("fault") == "after_dispatch_before_workflow_persistence":
        return {"assessment": assessment, "execution": {"attempted": True, "attempt_status": "interrupted_after_dispatch", "newly_executed": getattr(result, "newly_executed", False), "effect_id": getattr(result, "effect_id", None), "decision_id": getattr(result, "decision_id", None), "attempt_id": getattr(result, "attempt_id", None), "reason": artifacts["fault"]}, "successor_packet": None}
    if artifacts.get("fault") == "replay_odes_export_failed_after_dispatch":
        return {"assessment": assessment, "execution": {"attempted": True, "attempt_status": "evidence_export_failed", "newly_executed": getattr(result, "newly_executed", False), "effect_id": getattr(result, "effect_id", None), "decision_id": getattr(result, "decision_id", None), "attempt_id": getattr(result, "attempt_id", None), "reason": artifacts["fault"]}, "successor_packet": None}
    store.record_workflow(message, artifacts)
    return _execution_response(assessment, status, result, artifacts["decision"], artifacts)


def resume_original_exchange(message: dict[str, Any], *, manifest: dict[str, Any],
        store_path: str | Path, destination: Any, resolver: Any,
        execution_policy_factory: Any, observation_policy: Any,
        evaluation_time: str, observation_clock: Any = None, runtime_authority_profile: Any = None, allow_test_time: bool = False) -> dict[str, Any]:
    """Explicit current observation of the original attempted effect, not redelivery.

    Keeps original exports immutable. The accepted executor must see the owning
    prior attempt; absence cannot become a replacement dispatch. A new recovery
    artifact is saved separately. Reconciliation adds CP evidence, unlike an
    evidence-only read/export, which must leave CP records unchanged.
    """
    _workflow_options(runtime_authority_profile, allow_test_time)
    if observation_policy is None:
        raise ValueError("observation_policy is required")
    # The supplied message becomes the recovery predecessor; its claimed digest
    # must commit to its actual content before it selects a retained workflow.
    claimed_digest = message.get("message_digest")
    if not isinstance(claimed_digest, str) or claimed_digest != digest({k: v for k, v in message.items() if k != "message_digest"}):
        raise ValueError("message_digest does not match the supplied original message")
    now = parse_time(evaluation_time)
    store_path = Path(store_path)
    store = TransactionalExchangeStore(store_path)
    association = store.workflow_for_message(message) or store.checkpoint_for_message(message)
    if not association or _validate_bound_association(association):
        raise ValueError("intact original workflow association required")
    contract = (association.get("moltbot") or {}).get("producer_profile") or {}
    if contract.get("profile_version") != MOLTBOT_PRODUCER_PROFILE_VERSION:
        raise ValueError("historical producer generation requires its revision-pinned recovery path")
    original = association["cp_record"]
    if not any(a.get("effect_id") == association["effect_id"] for a in original.get("attempts", [])):
        raise ValueError("retained owning prior attempt required; recovery cannot dispatch")
    candidates = []
    for path in store_path.parent.glob("control-plane-*.json"):
        data = json.loads(path.read_text())
        if data.get("run_id") != original.get("run_id") or data.get("decisions") != original.get("decisions"):
            continue
        if all(data.get(k, [])[:len(original.get(k, []))] == original.get(k, [])
               for k in ("attempts", "observations", "reconciliations")):
            candidates.append(path)
    if len(candidates) != 1:
        raise ValueError("owning Control Plane store unavailable or ambiguous")
    runtime = load_executor_runtime(); cp = runtime["cp"]
    proposal = cp.RuntimeProposal.model_validate(association["proposal"])
    decision = cp.RuntimeDecision.model_validate(association["decision"])
    request_data = dict(association["request"])
    request_data["operation"] = runtime["ExecutionOperation"](**request_data["operation"])
    request = runtime["ExecutionEnvelope"](**request_data)
    workflow = cp.BoundedAuthorizationWorkflow(manifest=manifest, resolver=resolver,
        destination=cp.LocalRefundDestination(store_path.parent / "recovery-placeholder.json"),
        records=cp.BoundedRecordStore(candidates[0], proposal.run_id),
        observation_policy=observation_policy, **_workflow_options(runtime_authority_profile, allow_test_time))
    executor = runtime["PinnedControlPlaneExecutor"](workflow=workflow, destination=destination,
        policy=execution_policy_factory(request.operation), observation_clock=observation_clock)
    result = executor.execute(envelope=request, proposal=proposal, decision=decision, now=now)
    if result.newly_executed:
        raise RuntimeError("upstream invariant failure: recovery dispatched an effect")

    # A current recovery denial is a new authority fact about this recovery
    # request, not a revision of the historical execution that produced (or did
    # not produce) the original effect.  Re-exporting the denied executor result
    # together with retained historical destination rows would collapse those
    # two episodes and correctly trigger Replay's denied/effect contradiction.
    # Preserve the accepted historical reconstruction unchanged and express the
    # recovery denial only in derivative lineage and the returned execution
    # surface.  No fresh destination observation is claimed on this path.
    recovery_result = _asdict(result)
    recovery_evidence = recovery_result.get("control_plane_evidence") or {}
    recovery_reconciliation = (
        recovery_evidence.get("reconciliation")
        if isinstance(recovery_evidence, dict) else None
    )
    if result.status == "denied" and not recovery_reconciliation:
        pipe = _artifacts_from_association(manifest, message, association)
        original_export = association.get("artifact_export")
        pipe["artifact_export"] = _retained_artifact_export(
            pipe,
            state="recovery_denied_derivative",
            lineage={
                "relationship": "recovery_denial_derivative",
                "original_artifacts": "retained" if original_export else "unavailable",
                "source_checkpoint_commitment": digest(original),
                "source_artifact_commitment": digest(original_export) if isinstance(original_export, dict) else None,
                "effect_reexecution": False,
                "recovery_evaluated_at": evaluation_time,
                "recovery_scope": "current_authority_revalidation_before_destination_observation",
                "recovery_status": "denied",
                "recovery_reason": recovery_result.get("error"),
                "recovery_result": recovery_result,
                "destination_observation_performed": False,
                "replacement_dispatch_performed": False,
                "renewed_authorization": False,
            },
        )
        path = store_path.parent / ("recovery-" + digest(pipe["artifact_export"])[7:] + ".json")
        path.write_text(_json_dumps(pipe["artifact_export"]) + "\n")
        return _execution_response(
            {"stages": {}, "errors": []},
            result.status,
            result,
            decision,
            pipe,
            attempted_override=False,
            newly_executed_override=False,
        )

    cp_record, p, producer = _export_sources(workflow, proposal, request, result, destination)
    pipe = _pipeline(manifest, cp_record, p, producer, predecessor=message,
        state_version=len(cp_record.get("reconciliations", [])) + 1)
    pipe["artifact_export"] = _retained_artifact_export(pipe,
        state="reconciled_derivative", lineage={
            "relationship": "observation_reconciliation_derivative",
            "original_artifacts": "retained" if association.get("artifact_export") else "unavailable",
            "source_checkpoint_commitment": digest(original), "effect_reexecution": False})
    path = store_path.parent / ("recovery-" + digest(pipe["artifact_export"])[7:] + ".json")
    path.write_text(_json_dumps(pipe["artifact_export"]) + "\n")
    return _execution_response({"stages": {}, "errors": []}, result.status, result,
        decision, pipe, attempted_override=False, newly_executed_override=False)


class TransactionalExchangeStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.path) as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS effect_owners(effect_id TEXT PRIMARY KEY,message_id TEXT NOT NULL,message_digest TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS message_leases(message_id TEXT PRIMARY KEY,message_digest TEXT NOT NULL,holder TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS effect_claim_refusals(effect_id TEXT NOT NULL,message_id TEXT NOT NULL,message_digest TEXT NOT NULL,owner_message_id TEXT NOT NULL,reason TEXT NOT NULL,PRIMARY KEY(effect_id,message_id,message_digest));
                CREATE TABLE IF NOT EXISTS messages(message_id TEXT PRIMARY KEY, message_digest TEXT NOT NULL, conversation_id TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS message_workflows(message_id TEXT PRIMARY KEY,message_digest TEXT NOT NULL,conversation_id TEXT NOT NULL,status TEXT NOT NULL,proposal_commitment TEXT,decision_id TEXT,effect_id TEXT,attempt_id TEXT,proposal_json TEXT NOT NULL,decision_json TEXT NOT NULL,request_json TEXT,result_json TEXT,cp_record_json TEXT NOT NULL,moltbot_json TEXT);
                CREATE TABLE IF NOT EXISTS dispatch_checkpoints(message_id TEXT PRIMARY KEY,message_digest TEXT NOT NULL,conversation_id TEXT NOT NULL,state TEXT NOT NULL,proposal_commitment TEXT,decision_id TEXT,effect_id TEXT,attempt_id TEXT,proposal_json TEXT NOT NULL,decision_json TEXT NOT NULL,request_json TEXT,result_json TEXT,cp_record_json TEXT NOT NULL,moltbot_json TEXT,faults_json TEXT);
                CREATE TABLE IF NOT EXISTS artifact_exports(message_id TEXT PRIMARY KEY,message_digest TEXT NOT NULL,conversation_id TEXT NOT NULL,export_profile TEXT NOT NULL,export_version TEXT NOT NULL,state TEXT NOT NULL,artifact_json TEXT NOT NULL,artifact_digest TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS lineage(packet_id TEXT PRIMARY KEY, packet_digest TEXT NOT NULL, conversation_id TEXT NOT NULL, parent_packet_id TEXT, state_version INTEGER NOT NULL, source_packet_id TEXT NOT NULL, source_commitment TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS heads(conversation_id TEXT PRIMARY KEY, packet_id TEXT NOT NULL, packet_digest TEXT NOT NULL, state_version INTEGER NOT NULL);
                """
            )

            # Adopt retained associations on upgrade; the first owner remains the
            # reconciliation route. Never use a fresh message to clear this barrier.
            for table in ("dispatch_checkpoints", "message_workflows"):
                conn.execute(f"INSERT OR IGNORE INTO effect_owners SELECT effect_id,message_id,message_digest FROM {table} WHERE effect_id IS NOT NULL ORDER BY message_id")

    LEASE_HELD = "message_processing_lease_held"

    def claim_effect(self, message: dict[str, Any], effect_id: str, holder: str | None = None) -> str | None:
        """Claim one effect before dispatch; return its existing owner on conflict.

        With a ``holder`` the same transaction also takes the message's processing lease: a second holder for the same message
        gets ``LEASE_HELD`` (a hold, no dispatch) until the first releases it. Without a holder the behaviour is the
        effect-ownership claim only.
        """
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("INSERT OR IGNORE INTO effect_owners VALUES(?,?,?)",
                         (effect_id,message["message_id"],message["message_digest"]))
            row=conn.execute("SELECT message_id,message_digest FROM effect_owners WHERE effect_id=?",(effect_id,)).fetchone()
            conflict=(row["message_id"],row["message_digest"]) != (message["message_id"],message["message_digest"])
            if conflict:
                conn.execute("INSERT OR IGNORE INTO effect_claim_refusals VALUES(?,?,?,?,?)",
                    (effect_id,message["message_id"],message["message_digest"],row["message_id"],"effect_owned_by_another_message"))
                conn.execute("COMMIT")
                return row["message_id"]
            if holder is not None:
                conn.execute("INSERT OR IGNORE INTO message_leases VALUES(?,?,?)",
                             (message["message_id"],message["message_digest"],holder))
                lease=conn.execute("SELECT message_digest,holder FROM message_leases WHERE message_id=?",(message["message_id"],)).fetchone()
                if (lease["message_digest"],lease["holder"]) != (message["message_digest"],holder):
                    conn.execute("COMMIT")
                    return self.LEASE_HELD
            conn.execute("COMMIT")
            return None

    def release_lease(self, message: dict[str, Any], holder: str) -> None:
        """Release the processing lease this holder took; another holder's lease is never touched."""
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("DELETE FROM message_leases WHERE message_id=? AND holder=?",(message["message_id"],holder))
            conn.execute("COMMIT")

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        conn.row_factory = sqlite3.Row
        return conn

    def seen_messages(self) -> dict[str, str]:
        with self._connect() as conn:
            return {row["message_id"]: row["message_digest"] for row in conn.execute("SELECT message_id,message_digest FROM messages")}

    def record_message(self, message: dict[str, Any]) -> tuple[bool, str | None]:
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT message_digest FROM messages WHERE message_id=?", (message["message_id"],)).fetchone()
            if row and row["message_digest"] != message["message_digest"]:
                conn.execute("ROLLBACK")
                return False, "GAX-INTEGRITY-MESSAGE-ID-REUSE"
            if row:
                conn.execute("COMMIT")
                return True, None
            conn.execute("INSERT INTO messages VALUES(?,?,?)", (message["message_id"], message["message_digest"], message["conversation_id"]))
            conn.execute("COMMIT")
            return False, None

    def _association_payload(self, row: sqlite3.Row) -> dict[str, Any]:
        return {"status": row["status"] if "status" in row.keys() else row["state"], "proposal_commitment": row["proposal_commitment"], "decision_id": row["decision_id"], "effect_id": row["effect_id"], "attempt_id": row["attempt_id"], "proposal": _json_loads(row["proposal_json"]), "decision": _json_loads(row["decision_json"]), "request": _json_loads(row["request_json"]), "result": _json_loads(row["result_json"]), "cp_record": _json_loads(row["cp_record_json"]), "moltbot": _json_loads(row["moltbot_json"])}

    def record_dispatch_checkpoint(self, message: dict[str, Any], artifacts: dict[str, Any]) -> None:
        proposal = artifacts["proposal_record"]
        decision = _asdict(artifacts.get("decision"))
        request = _asdict(artifacts.get("request")) if artifacts.get("request") is not None else None
        result = _asdict(artifacts.get("result")) if artifacts.get("result") is not None else None
        state = "dispatched" if result else "bound"
        status = artifacts.get("status") or (result or {}).get("status") or decision.get("result") or state
        decision_id = (result or {}).get("decision_id") or decision.get("decision_id")
        effect_id = (result or {}).get("effect_id") or decision.get("effect_id")
        attempt_id = (result or {}).get("attempt_id")
        proposal_commitment = (request or {}).get("operation", {}).get("proposal_commitment")
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT message_digest FROM messages WHERE message_id=?", (message["message_id"],)).fetchone()
            if row is None or row["message_digest"] != message["message_digest"]:
                conn.execute("ROLLBACK")
                raise RuntimeError("message receipt must be recorded before dispatch checkpoint")
            prior = conn.execute("SELECT state,decision_id,effect_id,proposal_commitment,result_json FROM dispatch_checkpoints WHERE message_id=?", (message["message_id"],)).fetchone()
            if prior and (prior["decision_id"] != decision_id or prior["effect_id"] != effect_id or prior["proposal_commitment"] != proposal_commitment):
                conn.execute("ROLLBACK")
                raise RuntimeError("dispatch checkpoint identity cannot be replaced")
            values = (state, proposal_commitment, decision_id, effect_id, attempt_id, _json_dumps(proposal), _json_dumps(decision), _json_dumps(request) if request is not None else None, _json_dumps(result) if result is not None else None, _json_dumps(artifacts["cp_record"]), _json_dumps(artifacts.get("moltbot_record")) if artifacts.get("moltbot_record") is not None else None)
            if prior is None:
                conn.execute("""INSERT INTO dispatch_checkpoints(message_id,message_digest,conversation_id,state,proposal_commitment,decision_id,effect_id,attempt_id,proposal_json,decision_json,request_json,result_json,cp_record_json,moltbot_json,faults_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,'{}')""", (message["message_id"], message["message_digest"], message["conversation_id"], *values))
            elif prior["state"] == "bound" and state == "dispatched":
                # The one allowed advance: the bound checkpoint becomes dispatched, once.
                conn.execute("""UPDATE dispatch_checkpoints SET state=?,proposal_commitment=?,decision_id=?,effect_id=?,attempt_id=?,proposal_json=?,decision_json=?,request_json=?,result_json=?,cp_record_json=?,moltbot_json=? WHERE message_id=? AND state='bound'""", (*values, message["message_id"]))
            elif prior["state"] == "bound" and state == "bound":
                pass  # a repeated bound write keeps the first
            elif prior["state"] == "dispatched" and state == "dispatched" and prior["result_json"] == values[8]:
                pass  # the same dispatched record again
            else:
                conn.execute("ROLLBACK")
                raise RuntimeError("dispatch checkpoint cannot be replaced or moved back")
            conn.execute("COMMIT")

    def checkpoint_for_message(self, message: dict[str, Any]) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM dispatch_checkpoints WHERE message_id=?", (message["message_id"],)).fetchone()
        if row is None or row["message_digest"] != message["message_digest"] or row["conversation_id"] != message["conversation_id"]:
            return None
        out = self._association_payload(row)
        out["state"] = row["state"]
        return out

    def consume_fault_once(self, message_id: str, fault_name: str) -> bool:
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT faults_json FROM dispatch_checkpoints WHERE message_id=?", (message_id,)).fetchone()
            faults = _json_loads(row["faults_json"]) if row and row["faults_json"] else {}
            already = bool(faults.get(fault_name))
            if not already:
                faults[fault_name] = True
                conn.execute("UPDATE dispatch_checkpoints SET faults_json=? WHERE message_id=?", (_json_dumps(faults), message_id))
            conn.execute("COMMIT")
            return already

    def artifact_export_for_message(self, message: dict[str, Any]) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM artifact_exports WHERE message_id=?",
                (message["message_id"],),
            ).fetchone()
        if row is None:
            return None
        if row["message_digest"] != message["message_digest"] or row["conversation_id"] != message["conversation_id"]:
            return None
        value = _json_loads(row["artifact_json"])
        if row["artifact_digest"] != digest(value):
            raise ValueError("retained_artifact_row_digest_mismatch")
        problem = _validate_retained_artifact_export(value)
        if problem:
            raise ValueError(problem)
        return value

    def record_workflow(self, message: dict[str, Any], artifacts: dict[str, Any]) -> None:
        proposal = artifacts["proposal_record"]
        decision = _asdict(artifacts.get("decision"))
        request = _asdict(artifacts.get("request")) if artifacts.get("request") is not None else None
        result = _asdict(artifacts.get("result")) if artifacts.get("result") is not None else None
        status = artifacts.get("status") or (result or {}).get("status") or decision.get("result") or "unresolved"
        decision_id = (result or {}).get("decision_id") or decision.get("decision_id")
        effect_id = (result or {}).get("effect_id") or decision.get("effect_id")
        attempt_id = (result or {}).get("attempt_id")
        proposal_commitment = (request or {}).get("operation", {}).get("proposal_commitment")
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT message_digest FROM messages WHERE message_id=?", (message["message_id"],)).fetchone()
            if row is None or row["message_digest"] != message["message_digest"]:
                conn.execute("ROLLBACK")
                raise RuntimeError("message receipt must be recorded before workflow association")
            artifact_export = artifacts.get("artifact_export")
            if not isinstance(artifact_export, dict):
                conn.execute("ROLLBACK")
                raise RuntimeError("workflow completion requires a retained artifact export")
            problem = _validate_retained_artifact_export(artifact_export)
            if problem:
                conn.execute("ROLLBACK")
                raise RuntimeError(problem)
            encoded_export = _json_dumps(artifact_export)
            workflow_values = (message["message_id"], message["message_digest"], message["conversation_id"], status, proposal_commitment, decision_id, effect_id, attempt_id, _json_dumps(proposal), _json_dumps(decision), _json_dumps(request) if request is not None else None, _json_dumps(result) if result is not None else None, _json_dumps(artifacts["cp_record"]), _json_dumps(artifacts.get("moltbot_record")) if artifacts.get("moltbot_record") is not None else None)
            prior = conn.execute("SELECT * FROM message_workflows WHERE message_id=?", (message["message_id"],)).fetchone()
            if prior is not None:
                prior_export = conn.execute("SELECT artifact_digest FROM artifact_exports WHERE message_id=?", (message["message_id"],)).fetchone()
                same = (tuple(prior[k] for k in ("message_id","message_digest","conversation_id","status","proposal_commitment","decision_id","effect_id","attempt_id","proposal_json","decision_json","request_json","result_json","cp_record_json","moltbot_json")) == tuple(workflow_values)
                        and prior_export is not None and prior_export["artifact_digest"] == digest(artifact_export))
                conn.execute("ROLLBACK" if not same else "COMMIT")
                if not same:
                    raise RuntimeError("workflow association is already recorded and cannot be replaced")
                return
            conn.execute("""INSERT INTO message_workflows(message_id,message_digest,conversation_id,status,proposal_commitment,decision_id,effect_id,attempt_id,proposal_json,decision_json,request_json,result_json,cp_record_json,moltbot_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", workflow_values)
            conn.execute(
                """INSERT INTO artifact_exports(message_id,message_digest,conversation_id,export_profile,export_version,state,artifact_json,artifact_digest) VALUES(?,?,?,?,?,?,?,?)""",
                (
                    message["message_id"], message["message_digest"], message["conversation_id"],
                    artifact_export["export_profile"], artifact_export["export_version"],
                    artifact_export["state"], encoded_export, digest(artifact_export),
                ),
            )
            conn.execute("COMMIT")

    def workflow_for_message(self, message: dict[str, Any]) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM message_workflows WHERE message_id=?", (message["message_id"],)).fetchone()
        if row is None or row["message_digest"] != message["message_digest"] or row["conversation_id"] != message["conversation_id"]:
            return None
        out = self._association_payload(row)
        out["artifact_export"] = self.artifact_export_for_message(message)
        return out

    @staticmethod
    def _material_digest(packet: dict[str, Any]) -> str:
        return digest({k: v for k, v in packet.items() if k != "packet_digest"})

    def accept_successor(self, packet: dict[str, Any], predecessor: dict[str, Any]) -> dict[str, Any]:
        """Load a successor packet for reconciliation only; never an effect or grant.

        Limitation: with no stored head for the conversation, the first packet is
        checked only for self-consistency against the caller-supplied
        predecessor. That caller-supplied predecessor is trusted; any caller with
        store access can initialise a conversation head.
        """
        if packet.get("packet_digest") != self._material_digest(packet):
            return {"loaded": False, "effect_created": False, "status": "packet_digest_mismatch"}
        if packet.get("profile") != PROFILE or packet.get("schema_version") != PROTOCOL_VERSION:
            return {"loaded": False, "effect_created": False, "status": "unsupported_profile_or_schema"}
        if packet.get("conversation_id") != predecessor.get("conversation_id"):
            return {"loaded": False, "effect_created": False, "status": "conversation_mismatch"}
        if packet.get("source_packet_id") not in {predecessor.get("message_id"), predecessor.get("packet_id")}:
            return {"loaded": False, "effect_created": False, "status": "source_identity_mismatch"}
        predecessor_material_digest = self._material_digest(predecessor)
        supplied_predecessor_digest = predecessor.get("packet_digest")
        predecessor_digest = supplied_predecessor_digest or predecessor_material_digest
        if packet.get("source_commitment") != predecessor_material_digest:
            return {"loaded": False, "effect_created": False, "status": "source_commitment_mismatch"}
        try:
            version = int(str(packet.get("state_version", "")).split("-")[-1])
        except Exception:
            return {"loaded": False, "effect_created": False, "status": "unsupported_state_version"}
        conversation_id = packet["conversation_id"]
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            head = conn.execute("SELECT packet_id,packet_digest,state_version FROM heads WHERE conversation_id=?", (conversation_id,)).fetchone()
            parent = packet.get("predecessor_packet_id")
            if head is not None:
                if not parent:
                    conn.execute("ROLLBACK")
                    return {"loaded": False, "effect_created": False, "status": "missing_predecessor_packet_id"}
                if parent != head["packet_id"]:
                    conn.execute("ROLLBACK")
                    return {"loaded": False, "effect_created": False, "status": "divergent_branch"}
                if packet.get("source_packet_id") != head["packet_id"]:
                    conn.execute("ROLLBACK")
                    return {"loaded": False, "effect_created": False, "status": "source_not_accepted_head"}
                if supplied_predecessor_digest and supplied_predecessor_digest != predecessor_material_digest:
                    conn.execute("ROLLBACK")
                    return {"loaded": False, "effect_created": False, "status": "predecessor_digest_mismatch"}
                if predecessor_digest != head["packet_digest"]:
                    conn.execute("ROLLBACK")
                    return {"loaded": False, "effect_created": False, "status": "predecessor_content_not_accepted_head"}
                if version <= int(head["state_version"]):
                    conn.execute("ROLLBACK")
                    return {"loaded": False, "effect_created": False, "status": "stale_or_rollback"}
            elif parent:
                parent_row = conn.execute("SELECT conversation_id FROM lineage WHERE packet_id=?", (parent,)).fetchone()
                conn.execute("ROLLBACK")
                if parent_row and parent_row["conversation_id"] != conversation_id:
                    return {"loaded": False, "effect_created": False, "status": "conversation_mismatch"}
                return {"loaded": False, "effect_created": False, "status": "unknown_predecessor"}
            existing = conn.execute("SELECT packet_digest FROM lineage WHERE packet_id=?", (packet["packet_id"],)).fetchone()
            if existing and existing["packet_digest"] != packet["packet_digest"]:
                conn.execute("ROLLBACK")
                return {"loaded": False, "effect_created": False, "status": "divergent_history"}
            conn.execute("INSERT OR IGNORE INTO lineage VALUES(?,?,?,?,?,?,?)", (packet["packet_id"], packet["packet_digest"], conversation_id, parent, version, packet["source_packet_id"], packet["source_commitment"]))
            conn.execute("INSERT OR REPLACE INTO heads VALUES(?,?,?,?)", (conversation_id, packet["packet_id"], packet["packet_digest"], version))
            conn.execute("COMMIT")
            return {"loaded": True, "effect_created": False, "status": "loaded_for_reconciliation"}

DurableExchangeStore = TransactionalExchangeStore


def make_successor_packet(predecessor: dict[str, Any], *, facts: dict[str, Any], state_version: int = 1, current_bundle: dict[str, Any] | None = None, predecessor_packet_id: str | None = None) -> dict[str, Any]:
    source_id = predecessor.get("packet_id") or predecessor.get("message_id")
    source_commitment = digest({k: v for k, v in predecessor.items() if k != "packet_digest"})
    packet = {"packet_id": f"succ-{source_id}-{state_version}", "profile": PROFILE, "schema_version": PROTOCOL_VERSION, "conversation_id": predecessor.get("conversation_id"), "source_packet_id": source_id, "source_commitment": source_commitment, "predecessor_packet_id": predecessor_packet_id, "state_version": f"state-{state_version}", "relevant_decisions": [facts.get("decision_id")], "pending_effects": facts.get("pending_effects", []), "attempts": facts.get("attempts", {}), "unresolved_delivery": facts.get("unresolved_delivery"), "missing_evidence": [] if current_bundle else ["current_bundle_unavailable"], "next_proposed_work": "reconcile before any further execution"}
    packet["packet_digest"] = digest({k: v for k, v in packet.items() if k != "packet_digest"})
    return packet


def load_successor_packet(packet: dict[str, Any], destination: Any, *, predecessor: dict[str, Any], store_path: str | Path) -> dict[str, Any]:
    return TransactionalExchangeStore(store_path).accept_successor(packet, predecessor)


def run_actual_outcome(tmp_path: Path, outcome: str) -> dict[str, Any]:
    from .synthetic_fixture import build_synthetic_resolver, synthetic_refund_policy, synthetic_observation_policy, synthetic_observation_clock

    manifest = _manifest()
    bundle = json.loads(
        Path(os.environ["UPSTREAM_REPLAY_SUCCESS_EXAMPLE"]).read_text(encoding="utf-8")
    )
    message = make_message(bundle, message_id=f"fixture-{outcome}")
    proposal = runtime_proposal_model(bundle)
    resolver = build_synthetic_resolver(proposal, now=parse_time(EVAL))
    runtime = load_executor_runtime()
    destination = runtime["DurableRefundDestination"](tmp_path / "moltbot-state")
    store_path = tmp_path / "exchange.sqlite"

    mutate = None
    lose_ack = outcome == "lost_ack"
    partial = outcome == "partial"
    if outcome == "hold":
        grant = resolver.contexts[base.PROFILE_AUTH_CONTEXT]["grant"]
        resolver.statuses[grant["grant_id"]].status = "revoked"
    elif outcome == "denied_after_decision":
        def mutate(current):
            grant = current.contexts[base.PROFILE_AUTH_CONTEXT]["grant"]
            current.statuses[grant["grant_id"]].status = "revoked"
    elif outcome not in {"success", "restart_reconciliation", "duplicate_delivery", "lost_ack", "partial"}:
        raise ValueError(f"unsupported outcome: {outcome}")

    first = run_exchange(
        message,
        bundle,
        LocalRegistry({"refund-sender"}, {"refund-recipient"}, "refund-recipient"),
        destination,
        evaluation_time=EVAL,
        manifest=manifest,
        store_path=store_path,
        resolver=resolver,
        execution_policy_factory=synthetic_refund_policy,
        observation_policy=synthetic_observation_policy(),
        observation_clock=synthetic_observation_clock,
        mutate_resolver_after_decision=mutate,
        lose_ack=lose_ack,
        partial_delivery=partial,
    )
    if outcome in {"restart_reconciliation", "duplicate_delivery"}:
        if outcome == "restart_reconciliation":
            destination = runtime["DurableRefundDestination"](destination.root)
        return run_exchange(
            message,
            bundle,
            LocalRegistry({"refund-sender"}, {"refund-recipient"}, "refund-recipient"),
            destination,
            evaluation_time=EVAL,
            manifest=manifest,
            store_path=store_path,
            resolver=resolver,
            execution_policy_factory=synthetic_refund_policy,
        observation_policy=synthetic_observation_policy(),
        observation_clock=synthetic_observation_clock,
        )
    return first

def run_demo(manifest_path: str, replay_path: str, out_path: str) -> dict[str, Any]:
    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    bundle = json.loads(Path(replay_path).read_text(encoding="utf-8"))
    tmp = Path(out_path).parent
    from .synthetic_fixture import build_synthetic_resolver, synthetic_refund_policy, synthetic_observation_policy, synthetic_observation_clock

    proposal = runtime_proposal_model(bundle)
    resolver = build_synthetic_resolver(proposal, now=parse_time(EVAL))
    runtime = load_executor_runtime()
    destination = runtime["DurableRefundDestination"](tmp / "demo-moltbot-state")
    result = run_exchange(
        make_message(bundle),
        bundle,
        LocalRegistry({"refund-sender"}, {"refund-recipient"}, "refund-recipient"),
        destination,
        evaluation_time=EVAL,
        manifest=manifest,
        store_path=tmp / "demo_exchange.sqlite",
        resolver=resolver,
        execution_policy_factory=synthetic_refund_policy,
        observation_policy=synthetic_observation_policy(),
        observation_clock=synthetic_observation_clock,
    )
    Path(out_path).write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--replay", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    run_demo(args.manifest, args.replay, args.out)
    return 0
