"""Authenticated pinned source for the Exchange's strict profiles (P1 Exchange-1, csf_756af34ecc888ea2498a506c and
csf_60ebe90ffb63af98a867e323).

A strict profile names exact commit ids for the packages it executes and for the Manifest it authorizes with. This module
turns "this checkout says it is that commit" into "these bytes are that commit":

1. A bounded, **in-process** Git object reader (loose zlib objects and pack/idx v2, OFS/REF delta) re-hashes the commit, every
   tree and every blob against the id that names it, starting from the pinned commit id (SHA-1 object identity is the trust
   anchor, exactly as in Git itself). No ``git`` process is started and nothing a checkout controls takes part: not its
   configuration, filters, attributes, hooks, promisor/partial-clone settings, ``objects/info/alternates``, refs, ``HEAD``,
   ``refs/replace``, grafts or ``shallow`` file, nor any ``GIT_*`` variable. A missing or non-matching object is an error.
   The reader is an adaptation of the Evidence Registry BitRep reader (cogno-us/cognous-evidence-registry
   ``chain/python/bitrep_checkout.py``, R1-B3) with bounds sized for the Exchange's pinned components.
2. ``materialize`` writes the authenticated bytes into a private (0700) directory outside the checkout, read-only, with a
   minimal self-made ``.git`` (detached HEAD at the pinned commit, the commit and tree objects, an index) so that components
   that look at their own import location with Git (ODES and the Evidence Pack qualify the Replay checkout that way) see the
   pinned revision as a clean checkout. Only that copy is ever put on ``sys.path``.
3. ``worktree_problems`` / ``untracked_problems`` compare the live checkout, byte for byte and without any git filter, with the
   authenticated blobs. This is a policy refusal of dirty or shadowed sources; it is NOT what makes execution safe (the code
   that runs comes from step 2, never from the live checkout) and it does not read the index, so ``assume-unchanged`` /
   ``skip-worktree`` flags cannot hide anything from it.
4. ``AuthenticatedManifest`` is the authenticated Manifest: the exact bytes of one blob of the pinned Manifest revision, an
   immutable parsed value, its raw and canonical digests. Consumers receive fresh copies parsed from those bytes; the mutable
   path is never reopened for security-critical use.

Residual trust (documented in docs/authenticated-source.md): the Python interpreter, the standard library and ambient
third-party dependencies (pydantic, jsonschema, cryptography, ...) are not authenticated here; SHA-1 object identity is the
anchor; the operating-system account running the process can alter anything it owns.

This module has no import-time side effects and never imports a candidate package.
"""

from __future__ import annotations

import atexit
import hashlib
import importlib.machinery
import json
import math
import os
import re
import shutil
import stat
import struct
import tempfile
import threading
import types
import zlib
from pathlib import Path
from typing import Any, NamedTuple


class SourceAuthenticationError(ValueError):
    """Pinned source or manifest bytes could not be authenticated."""


# ---------------------------------------------------------------------------------------------------------------------
# Bounds. Sized from the real pinned components (largest: ODES, ~1.5k files / ~20 MiB / largest blob ~150 KiB) with
# headroom; they are limits on hostile object databases, not Git's own limits.
# ---------------------------------------------------------------------------------------------------------------------
MAX_OBJECT_SIZE = 8 * 1024 * 1024   # largest r2-tuple blob is ~150 KB; the typed-refusal runtime blob exceeded 1 MiB (size unmeasured)
MAX_COMPRESSED = MAX_OBJECT_SIZE + 256 * 1024
MAX_TOTAL_BYTES = 192 * 1024 * 1024
MAX_WORK_BYTES = 256 * 1024 * 1024
MAX_OBJECTS = 20_000
MAX_TREE_ENTRIES = 4096
MAX_TOTAL_TREE_ENTRIES = 20_000
MAX_TREES = 4000
MAX_FILES = 10_000
MAX_DELTA_DEPTH = 50
MAX_PACKS = 32
MAX_BASE_CACHE = 48 * 1024 * 1024
MAX_PACK_OBJECTS = 500_000
MAX_MANIFEST_BYTES = 1024 * 1024
_CHUNK = 8192
GIT_LOOKUP_LEVELS = 12

_SHA1_ID = re.compile(r"^[0-9a-f]{40}$")
_TYPES = {1: "commit", 2: "tree", 3: "blob"}
_OPEN_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
_IMPORTABLE_SUFFIXES = (*importlib.machinery.all_suffixes(), ".pyw", ".pyd")


def _open_regular(path: str) -> tuple[int, int]:
    """Open an existing regular file without following a final symlink or blocking on a FIFO; return (fd, size)."""
    fd = os.open(path, _OPEN_FLAGS)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError(f"not a regular file: {path}")
        return fd, info.st_size
    except BaseException:
        os.close(fd)
        raise


def _pread_exact(fd: int, size: int, offset: int, length: int) -> bytes:
    if offset < 0 or length < 0 or offset + length > size:
        raise ValueError("read outside the file")
    data = os.pread(fd, length, offset)
    if len(data) != length:
        raise ValueError("short read")
    return data


class _Inflater:
    """Inflate one zlib stream from ``read(n)`` chunks with hard caps on input and output (a bomb is refused early)."""

    def __init__(self, read, expected: int, max_input: int):
        self.read, self.expected, self.max_input = read, expected, max_input

    def run(self) -> bytes:
        engine, out, fed, pending = zlib.decompressobj(), bytearray(), 0, b""
        try:
            while not engine.eof:
                if not pending:
                    pending = self.read(_CHUNK)
                    fed += len(pending)
                    if not pending:
                        raise ValueError("truncated zlib stream")
                    if fed > self.max_input:
                        raise ValueError("compressed object exceeds the input bound")
                before = len(pending)
                out += engine.decompress(pending, self.expected - len(out) + 1)
                if len(out) > self.expected:
                    raise ValueError("object inflates beyond its declared size")
                pending = engine.unconsumed_tail
                if len(pending) == before and not engine.eof:
                    raise ValueError("zlib stream makes no progress")
        except zlib.error as exc:
            raise ValueError(f"corrupt zlib stream: {exc}") from exc
        if len(out) != self.expected:
            raise ValueError("object size does not match its declared size")
        return bytes(out)


def _apply_delta(base: bytes, delta: bytes) -> bytes:
    """Apply a git delta to ``base`` with every offset, length and the result size checked."""
    pos = 0

    def varint() -> int:
        nonlocal pos
        value = shift = 0
        while True:
            if pos >= len(delta) or shift > 28:
                raise ValueError("malformed delta header")
            byte = delta[pos]
            pos += 1
            value |= (byte & 0x7F) << shift
            shift += 7
            if not byte & 0x80:
                return value

    if varint() != len(base):
        raise ValueError("delta base size mismatch")
    want = varint()
    if want > MAX_OBJECT_SIZE:
        raise ValueError("delta result exceeds the object size bound")
    parts: list[bytes] = []
    produced = 0
    end = len(delta)
    while pos < end:
        op = delta[pos]
        pos += 1
        if op & 0x80:
            offset = length = 0
            for bit in range(4):
                if op & (1 << bit):
                    if pos >= end:
                        raise ValueError("truncated delta copy")
                    offset |= delta[pos] << (8 * bit)
                    pos += 1
            for bit in range(3):
                if op & (0x10 << bit):
                    if pos >= end:
                        raise ValueError("truncated delta copy")
                    length |= delta[pos] << (8 * bit)
                    pos += 1
            length = length or 0x10000
            if offset + length > len(base):
                raise ValueError("delta copy outside its base")
            parts.append(base[offset:offset + length])
            produced += length
        elif op:
            if pos + op > end:
                raise ValueError("truncated delta insert")
            parts.append(delta[pos:pos + op])
            pos += op
            produced += op
        else:
            raise ValueError("reserved delta opcode")
        if produced > want:
            raise ValueError("delta produces more than its declared result")
    if produced != want:
        raise ValueError("delta result size mismatch")
    return b"".join(parts)


class _Pack:
    """One ``pack-<sha1>.idx`` / ``.pack`` pair, read lazily and only for explicit object-id lookups."""

    def __init__(self, store: "_ObjectStore", idx_path: str, pack_path: str):
        self.store = store
        self.idx_fd = self.pack_fd = -1
        try:
            self.idx_fd, self.idx_size = _open_regular(idx_path)
            self.pack_fd, self.pack_size = _open_regular(pack_path)
            head = _pread_exact(self.idx_fd, self.idx_size, 0, 8) if self.idx_size >= 8 + 1024 + 40 else b""
            if head != b"\xfftOc\0\0\0\2":
                raise ValueError("unsupported or malformed pack index (version 2 required)")
            fanout = struct.unpack(">256I", _pread_exact(self.idx_fd, self.idx_size, 8, 1024))
            if any(b < a for a, b in zip(fanout, fanout[1:])):
                raise ValueError("pack index fanout is not monotonic")
            self.count = fanout[255]
            if self.count > MAX_PACK_OBJECTS:
                raise ValueError("pack index declares too many objects")
            self.fanout = fanout
            self.names = 8 + 1024
            self.crcs = self.names + 20 * self.count
            self.offsets = self.crcs + 4 * self.count
            self.large = self.offsets + 4 * self.count
            spare = self.idx_size - self.large - 40
            if spare < 0 or spare % 8 or spare > 8 * self.count:
                raise ValueError("pack index size is inconsistent with its object count")
            self.large_count = spare // 8
            if self.pack_size < 12 + 20:
                raise ValueError("pack file too small")
            magic, version, count = struct.unpack(">4sII", _pread_exact(self.pack_fd, self.pack_size, 0, 12))
            if magic != b"PACK" or version not in (2, 3) or count != self.count:
                raise ValueError("pack header does not match its index")
            self.end = self.pack_size - 20
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        for fd in (self.idx_fd, self.pack_fd):
            if fd >= 0:
                os.close(fd)
        self.idx_fd = self.pack_fd = -1

    def find(self, oid: str) -> int | None:
        """Pack offset of ``oid`` or None (binary search over the sorted names; every probe is a bounded pread)."""
        want = bytes.fromhex(oid)
        first = want[0]
        lo, hi = (self.fanout[first - 1] if first else 0), self.fanout[first]
        while lo < hi:
            mid = (lo + hi) // 2
            name = _pread_exact(self.idx_fd, self.idx_size, self.names + 20 * mid, 20)
            if name[0] != first:
                raise ValueError("pack index names are outside their fanout bucket")
            if name == want:
                return self._offset(mid)
            if name < want:
                lo = mid + 1
            else:
                hi = mid
        return None

    def _offset(self, index: int) -> int:
        (value,) = struct.unpack(">I", _pread_exact(self.idx_fd, self.idx_size, self.offsets + 4 * index, 4))
        if value & 0x80000000:
            slot = value & 0x7FFFFFFF
            if slot >= self.large_count:
                raise ValueError("pack index large offset is outside its table")
            (value,) = struct.unpack(">Q", _pread_exact(self.idx_fd, self.idx_size, self.large + 8 * slot, 8))
        if not 12 <= value < self.end:
            raise ValueError("pack index offset is outside the pack")
        return value

    def _stream(self, pos: int, expected: int) -> bytes:
        if expected > MAX_OBJECT_SIZE:
            raise ValueError(f"object exceeds the size bound ({expected} > {MAX_OBJECT_SIZE})")
        self.store.charge_work(expected)
        cursor = [pos]

        def read(n: int) -> bytes:
            n = min(n, self.end - cursor[0])
            if n <= 0:
                return b""
            data = _pread_exact(self.pack_fd, self.pack_size, cursor[0], n)
            cursor[0] += n
            return data

        return _Inflater(read, expected, MAX_COMPRESSED).run()

    def read(self, offset: int) -> tuple[str, bytes]:
        """Resolve the object at ``offset`` (OFS_DELTA and REF_DELTA inside this pack) to ``(type, raw bytes)``.

        Resolved bases are memoised per store (bounded) so a delta chain shared by many objects is applied once.
        """
        chain: list[tuple[int, bytes]] = []
        seen: set[int] = set()
        cache = self.store.bases
        while True:
            hit = cache.get((id(self), offset))
            if hit is not None:
                kind_name, data = hit
                break
            if offset in seen or len(chain) > MAX_DELTA_DEPTH:
                raise ValueError("delta chain is cyclic or too deep")
            seen.add(offset)
            head = _pread_exact(self.pack_fd, self.pack_size, offset, min(32, self.end - offset))
            byte, kind, size, shift, used = head[0], (head[0] >> 4) & 7, head[0] & 15, 4, 1
            while byte & 0x80:
                if used >= len(head) or shift > 28:
                    raise ValueError("malformed pack object header")
                byte = head[used]
                used += 1
                size |= (byte & 0x7F) << shift
                shift += 7
            if size > MAX_OBJECT_SIZE:
                raise ValueError(f"pack object declares a size above the bound ({size} > {MAX_OBJECT_SIZE})")
            if kind in _TYPES:
                data = self._stream(offset + used, size)
                kind_name = _TYPES[kind]
                self.store.remember((id(self), offset), kind_name, data)
                break
            if kind == 6:
                if used >= len(head):
                    raise ValueError("malformed OFS_DELTA header")
                byte = head[used]
                used += 1
                rel = byte & 0x7F
                while byte & 0x80:
                    if used >= len(head) or used > 12:
                        raise ValueError("malformed OFS_DELTA offset")
                    byte = head[used]
                    used += 1
                    rel = ((rel + 1) << 7) | (byte & 0x7F)
                base = offset - rel
                if rel <= 0 or base < 12:
                    raise ValueError("OFS_DELTA base is outside the pack")
            elif kind == 7:
                if used + 20 > len(head):
                    raise ValueError("malformed REF_DELTA header")
                found = self.find(head[used:used + 20].hex())
                used += 20
                if found is None:
                    raise ValueError("REF_DELTA base is not in the same pack")
                base = found
            else:
                raise ValueError(f"unsupported pack object type {kind}")
            chain.append((offset, self._stream(offset + used, size)))
            offset = base
        for at, delta in reversed(chain):
            data = _apply_delta(data, delta)
            self.store.charge_work(len(data))
            self.store.remember((id(self), at), kind_name, data)
        return kind_name, data


class _ObjectStore:
    """Bounded, git-free reader over ``<root>/.git/objects`` that returns only bytes hashing to the requested id."""

    def __init__(self, root: Path):
        self.objects = os.path.join(os.fspath(root), ".git", "objects")
        self.work = self.total = self.count = 0
        self.cache: dict[tuple[str, str], bytes] = {}
        self.bases: dict[tuple[int, int], tuple[str, bytes]] = {}
        self._base_bytes = 0
        self._packs: list[_Pack] | None = None

    def __enter__(self) -> "_ObjectStore":
        return self

    def __exit__(self, *exc) -> None:
        for pack in self._packs or []:
            pack.close()
        self._packs = None

    def charge_work(self, n: int) -> None:
        self.work += n
        if self.work > MAX_WORK_BYTES:
            raise ValueError("trusted object reads exceed the work bound")

    def remember(self, key: tuple[int, int], kind: str, data: bytes) -> None:
        """Memoise a resolved pack object as a delta base while the memo stays under MAX_BASE_CACHE bytes."""
        if self._base_bytes + len(data) <= MAX_BASE_CACHE:
            self.bases[key] = (kind, data)
            self._base_bytes += len(data)

    def packs(self) -> list[_Pack]:
        if self._packs is None:
            self._packs = []
            directory = os.path.join(self.objects, "pack")
            try:
                names = sorted(e.name for e in os.scandir(directory) if re.fullmatch(r"pack-[0-9a-f]{40}\.idx", e.name))
            except OSError:
                names = []
            if len(names) > MAX_PACKS:
                raise ValueError("too many pack files")
            for name in names:
                try:
                    self._packs.append(_Pack(self, os.path.join(directory, name), os.path.join(directory, name[:-4] + ".pack")))
                except (ValueError, OSError):
                    continue  # an unusable pack is skipped; the object is then missing unless another source authenticates it
        return self._packs

    def _loose(self, oid: str) -> tuple[str, bytes] | None:
        try:
            fd, size = _open_regular(os.path.join(self.objects, oid[:2], oid[2:]))
        except FileNotFoundError:
            return None
        except (OSError, ValueError):
            raise ValueError("loose object is unreadable")
        try:
            if size > MAX_COMPRESSED:
                raise ValueError("loose object exceeds the compressed input bound")
            raw = os.pread(fd, MAX_COMPRESSED + 1, 0)
        finally:
            os.close(fd)
        limit = MAX_OBJECT_SIZE + 32
        engine = zlib.decompressobj()
        try:
            data = engine.decompress(raw, limit + 1)
        except zlib.error as exc:
            raise ValueError(f"corrupt loose object: {exc}") from exc
        if len(data) > limit or not engine.eof or engine.unused_data:
            raise ValueError("loose object is truncated, oversized or has trailing data")
        nul = data.find(b"\0", 0, 32)
        head = data[:nul].split(b" ") if nul > 0 else []
        if len(head) != 2 or not head[1].isdigit() or len(head[1]) > 7 or head[1] != b"%d" % int(head[1]):
            raise ValueError("malformed loose object header")
        if int(head[1]) > MAX_OBJECT_SIZE or int(head[1]) != len(data) - nul - 1:
            raise ValueError("loose object size is out of bounds or does not match its header")
        self.charge_work(len(data))
        return head[0].decode("ascii", "replace"), data[nul + 1:]

    def read(self, oid: str, kind: str, *, keep: bool = True) -> bytes:
        """Raw bytes of the ``kind`` object ``oid``; accepted only if ``sha1("<kind> <len>\\0" + bytes) == oid``."""
        if not _SHA1_ID.match(oid):
            raise ValueError(f"not a full lowercase sha1 object id: {oid!r}")
        if kind not in ("commit", "tree", "blob"):
            raise ValueError(f"object type not allowed: {kind}")
        if (kind, oid) in self.cache:
            return self.cache[(kind, oid)]
        if self.count >= MAX_OBJECTS:
            raise ValueError("too many objects")
        failures: list[str] = []

        def candidates():
            try:
                found = self._loose(oid)
            except ValueError as exc:
                failures.append(str(exc))
                found = None
            if found:
                yield found
            for pack in self.packs():
                try:
                    offset = pack.find(oid)
                    if offset is not None:
                        yield pack.read(offset)
                except ValueError as exc:
                    failures.append(str(exc))

        for actual, payload in candidates():
            if actual == kind and hashlib.sha1(actual.encode() + b" %d\0" % len(payload) + payload).hexdigest() == oid:
                if self.total + len(payload) > MAX_TOTAL_BYTES:
                    raise ValueError("authenticated objects exceed the total byte bound")
                self.total += len(payload)
                self.count += 1
                if keep:
                    self.cache[(kind, oid)] = payload
                return payload
            failures.append(f"candidate is not the {kind} {oid}")
        raise ValueError(f"object missing or not authentic as a {kind}: {oid}" + (f" ({failures[0]})" if failures else ""))


def find_git_root(path: os.PathLike | str) -> Path:
    """Nearest ancestor (or ``path`` itself) whose ``.git`` is a real directory. Gitfiles (worktrees, submodules) are refused."""
    here = Path(os.path.realpath(path))
    for candidate in [here, *list(here.parents)[:GIT_LOOKUP_LEVELS]]:
        dot = candidate / ".git"
        try:
            info = os.lstat(dot)
        except (FileNotFoundError, NotADirectoryError):
            continue
        except OSError as exc:
            raise SourceAuthenticationError(f"cannot inspect {dot}: {exc}") from exc
        if stat.S_ISDIR(info.st_mode):
            return candidate
        raise SourceAuthenticationError(f"{dot} is not a plain git directory (gitfile indirection and symlinks are not read)")
    raise SourceAuthenticationError(f"no git checkout found at or above {path}")


def verify_commit(store: _ObjectStore, commit: str) -> str:
    """Hash the raw commit object against ``commit`` and return the root tree id it names (verified, not resolved)."""
    payload = store.read(commit, "commit")
    parts = payload.split(b"\n", 1)[0].decode("ascii", "replace").split(" ")
    if len(parts) != 2 or parts[0] != "tree" or not _SHA1_ID.match(parts[1]):
        raise ValueError("commit object does not start with a tree line")
    return parts[1]


_FILE_MODES = ("100644", "100755", "120000")


def _parse_tree(data: bytes) -> list[tuple[str, str, str]]:
    entries, pos = [], 0
    while pos < len(data):
        sp = data.index(b" ", pos)
        nul = data.index(b"\0", sp)
        mode, name = data[pos:sp].decode("ascii"), os.fsdecode(data[sp + 1:nul])
        child = data[nul + 1:nul + 21].hex()
        if len(child) != 40:
            raise ValueError("truncated tree entry")
        pos = nul + 21
        if not name or "/" in name or name in (".", "..") or "\0" in name:
            raise ValueError(f"unsafe tree entry name: {name!r}")
        entries.append((mode, name, child))
    return entries


class AuthenticatedCommit(NamedTuple):
    commit: str
    tree: str
    commit_payload: bytes
    tree_payloads: dict            # tree id -> raw tree bytes (all authenticated)
    entries: tuple                 # sorted (mode, path, blob id) of every file; symlinks included, submodules refused


def authenticate_commit(root: Path, commit: str, *, _store: _ObjectStore | None = None) -> AuthenticatedCommit:
    """Authenticate ``commit`` and every tree below it (not the blobs); return the flat, verified file list."""
    if _store is None:
        with _ObjectStore(Path(root)) as store:
            return authenticate_commit(root, commit, _store=store)
    if not isinstance(commit, str) or not _SHA1_ID.match(commit):
        raise ValueError("a pinned revision must be a full lowercase sha1 commit id")
    tree = verify_commit(_store, commit)
    payloads: dict[str, bytes] = {}
    flat: list[tuple[str, str, str]] = []
    pending: list[tuple[str, str]] = [("", tree)]
    total_entries = 0
    while pending:
        prefix, oid = pending.pop()
        if oid in payloads:
            data = payloads[oid]          # identical directories share one tree object; every visit is still counted
        else:
            if len(payloads) >= MAX_TREES:
                raise ValueError("tree is too large")
            data = _store.read(oid, "tree")
            payloads[oid] = data
        entries = _parse_tree(data)
        total_entries += len(entries)
        if len(entries) > MAX_TREE_ENTRIES or total_entries > MAX_TOTAL_TREE_ENTRIES:
            raise ValueError("tree has too many entries")
        for mode, name, child in entries:
            rel = prefix + name
            if mode == "40000":
                pending.append((rel + "/", child))
            elif mode in _FILE_MODES:
                flat.append((mode, rel, child))
            else:
                raise ValueError(f"cannot authenticate pinned entry: {rel!r} (mode {mode})")
        if len(flat) > MAX_FILES:
            raise ValueError("tree has too many files")
    flat.sort(key=lambda e: e[1])
    if len({e[1] for e in flat}) != len(flat):
        raise ValueError("duplicate path in tree")
    return AuthenticatedCommit(commit, tree, _store.read(commit, "commit"), payloads, tuple(flat))


def read_blob_at(root: Path, commit: str, rel: str, *, max_bytes: int = MAX_MANIFEST_BYTES) -> tuple[str, str, bytes]:
    """Authenticate ``commit`` -> trees along ``rel`` -> blob; return ``(mode, blob id, exact bytes)``.

    Only the objects on the path are read. Symlinks, submodules and directories at ``rel`` are refused.
    """
    parts = rel.split("/")
    if not rel or any(p in ("", ".", "..") for p in parts):
        raise ValueError(f"unsafe path: {rel!r}")
    with _ObjectStore(Path(root)) as store:
        if not isinstance(commit, str) or not _SHA1_ID.match(commit):
            raise ValueError("a pinned revision must be a full lowercase sha1 commit id")
        oid = verify_commit(store, commit)
        for index, part in enumerate(parts):
            entries = {name: (mode, child) for mode, name, child in _parse_tree(store.read(oid, "tree"))}
            if part not in entries:
                raise ValueError(f"{rel!r} is not in the pinned revision")
            mode, oid = entries[part]
            last = index == len(parts) - 1
            if last and mode not in ("100644", "100755"):
                raise ValueError(f"{rel!r} is not a regular file of the pinned revision (mode {mode})")
            if not last and mode != "40000":
                raise ValueError(f"{rel!r} passes through a non-directory")
        blob = store.read(oid, "blob", keep=False)
        if len(blob) > max_bytes:
            raise ValueError(f"{rel!r} exceeds the {max_bytes} byte bound")
        return mode, oid, blob


# ---------------------------------------------------------------------------------------------------------------------
# Materialization
# ---------------------------------------------------------------------------------------------------------------------
class Materialized(NamedTuple):
    path: Path           # worktree root of the detached, authenticated copy
    commit: str
    tree: str
    entries: tuple


_LOCK = threading.RLock()
_ROOT: list[Path] = []
_BY_COMMIT: dict[str, Materialized] = {}
_OWNER_PID = os.getpid()


def _cleanup() -> None:
    if os.getpid() != _OWNER_PID:      # a forked child must not delete the parent's authenticated copy
        return
    for path in _ROOT:
        for here, dirnames, _ in os.walk(path):
            for name in dirnames:
                try:
                    os.chmod(os.path.join(here, name), 0o700)
                except OSError:
                    pass
        try:
            os.chmod(path, 0o700)
        except OSError:
            pass
        shutil.rmtree(path, ignore_errors=True)


atexit.register(_cleanup)


def _private_root() -> Path:
    if not _ROOT:
        _ROOT.append(Path(tempfile.mkdtemp(prefix="gax-authenticated-")).resolve())
        os.chmod(_ROOT[0], 0o700)
    return _ROOT[0]


def private_scratch_dir(prefix: str) -> Path:
    """A new private (0700) directory under the process's authenticated-source root, removed at interpreter exit."""
    with _LOCK:
        path = Path(tempfile.mkdtemp(prefix=prefix, dir=_private_root())).resolve()
        os.chmod(path, 0o700)
        return path


def _safe_relative(rel: str) -> bool:
    parts = rel.split("/")
    return bool(rel) and not rel.startswith("/") and "\\" not in rel and "\0" not in rel and all(
        p not in ("", ".", "..") and p.lower() != ".git" and ":" not in p for p in parts)


def _loose_write(objects: str, kind: str, payload: bytes, oid: str) -> None:
    directory = os.path.join(objects, oid[:2])
    os.makedirs(directory, exist_ok=True)
    target = os.path.join(directory, oid[2:])
    with open(target, "wb") as handle:
        handle.write(zlib.compress(kind.encode() + b" %d\0" % len(payload) + payload, 1))
    os.chmod(target, 0o444)


def _index_bytes(entries: list[tuple[str, str, os.stat_result, str]]) -> bytes:
    """Git index v2 for ``entries`` (path, blob id, lstat of the written file, git mode) so ``git status`` reads it as clean."""
    out = bytearray(b"DIRC" + struct.pack(">II", 2, len(entries)))
    for rel, blob, info, mode in sorted(entries, key=lambda e: e[0].encode()):
        name = rel.encode()
        fixed = struct.pack(
            ">10I", info.st_ctime_ns // 1_000_000_000 & 0xFFFFFFFF, info.st_ctime_ns % 1_000_000_000,
            info.st_mtime_ns // 1_000_000_000 & 0xFFFFFFFF, info.st_mtime_ns % 1_000_000_000,
            info.st_dev & 0xFFFFFFFF, info.st_ino & 0xFFFFFFFF, int(mode, 8), info.st_uid & 0xFFFFFFFF,
            info.st_gid & 0xFFFFFFFF, info.st_size & 0xFFFFFFFF)
        record = fixed + bytes.fromhex(blob) + struct.pack(">H", min(len(name), 0xFFF)) + name
        record += b"\0" * (8 - len(record) % 8 if len(record) % 8 else 8)
        # entry length is padded to a multiple of 8 with 1 to 8 NUL bytes (the name's own terminator included)
        out += record
    out += hashlib.sha1(bytes(out)).digest()
    return bytes(out)


def materialize(root: Path, commit: str, *, label: str = "src") -> Materialized:
    """Authenticate ``commit`` in the object database of ``root`` and write it to a private, read-only directory.

    The result is memoised per commit id (content-addressed, so the source repository does not matter). The copy holds
    exactly the tracked files with their modes, plus a minimal ``.git`` that names the commit (see the module docstring).
    """
    with _LOCK:
        cached = _BY_COMMIT.get(commit)
        if cached is not None:
            return cached
        root = Path(root).resolve()
        with _ObjectStore(root) as store:
            auth = authenticate_commit(root, commit, _store=store)
            seen: set[str] = set()
            for mode, rel, _ in auth.entries:
                if not _safe_relative(rel):
                    raise ValueError(f"cannot materialize pinned entry: {rel!r}")
                folded = rel.casefold()
                if folded in seen:
                    raise ValueError(f"case-colliding pinned path: {rel!r}")
                seen.add(folded)
            out = Path(tempfile.mkdtemp(prefix=f"{label}-", dir=_private_root())).resolve()
            os.chmod(out, 0o700)
            index_entries = []
            link_blobs = []
            resolved_root = str(out)
            for mode, rel, blob in auth.entries:
                data = store.read(blob, "blob", keep=False)
                target = out.joinpath(*rel.split("/"))
                target.parent.mkdir(parents=True, exist_ok=True)
                if mode == "120000":
                    link = os.fsdecode(data)
                    resolved = os.path.normpath(os.path.join(str(target.parent), link))
                    if os.path.isabs(link) or not (resolved == resolved_root or resolved.startswith(resolved_root + os.sep)):
                        raise ValueError(f"symlink escapes the pinned tree: {rel!r}")
                    os.symlink(link, target)
                    link_blobs.append((blob, data))
                else:
                    target.write_bytes(data)
                    os.chmod(target, 0o555 if mode == "100755" else 0o444)
                index_entries.append((rel, blob, os.lstat(target), mode))
        git = out / ".git"
        for sub in ("objects/info", "objects/pack", "refs/heads", "refs/tags"):
            (git / sub).mkdir(parents=True, exist_ok=True)
        objects = str(git / "objects")
        _loose_write(objects, "commit", auth.commit_payload, commit)
        for oid, payload in auth.tree_payloads.items():
            _loose_write(objects, "tree", payload, oid)
        for oid, payload in link_blobs:      # git compares a racily-clean symlink entry with the stored blob
            _loose_write(objects, "blob", payload, oid)
        (git / "HEAD").write_text(commit + "\n")
        (git / "shallow").write_text(commit + "\n")
        (git / "config").write_text("[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n")
        (git / "index").write_bytes(_index_bytes(index_entries))
        for here, dirnames, _ in os.walk(out, topdown=False):
            for name in dirnames:
                os.chmod(os.path.join(here, name), 0o555)
        os.chmod(out, 0o555)
        result = Materialized(out, commit, auth.tree, auth.entries)
        _BY_COMMIT[commit] = result
        return result


# ---------------------------------------------------------------------------------------------------------------------
# Live-checkout policy checks (not what makes execution safe: the authenticated copy is what runs)
# ---------------------------------------------------------------------------------------------------------------------
_STAT_OK: dict[tuple[str, str], tuple] = {}


def _blob_id(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def _signature(info: os.stat_result) -> tuple:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_mode)


MAX_INDEX_BYTES = 32 * 1024 * 1024


def index_flag_problems(root: Path) -> list[str]:
    """Entries of ``.git/index`` flagged assume-unchanged (assume-valid) or skip-worktree, parsed in-process (v2, v3, v4).

    ``git status`` trusts the index, so a flagged file can be edited and still look clean. The comparison with the blobs does
    not read the index and is not fooled; the flags are still refused as policy (a flagged tracked file is a deliberate
    attempt to hide state) and an index that cannot be parsed is refused. An absent index is not a problem.
    """
    path = os.path.join(root, ".git", "index")
    try:
        fd, size = _open_regular(path)
    except FileNotFoundError:
        return []
    except (OSError, ValueError):
        return ["index cannot be inspected"]
    try:
        if size > MAX_INDEX_BYTES:
            return ["index exceeds the inspection bound"]
        data = os.pread(fd, size, 0)
    finally:
        os.close(fd)
    problems: list[str] = []
    try:
        if len(data) < 32 or hashlib.sha1(data[:-20]).digest() != data[-20:]:
            return ["index cannot be inspected (checksum mismatch)"]
        signature, version, count = struct.unpack(">4sII", data[:12])
        if signature != b"DIRC" or version not in (2, 3, 4):
            return ["index cannot be inspected (unsupported format)"]
        pos, previous = 12, b""
        for _ in range(count):
            start = pos
            (flags,) = struct.unpack(">H", data[pos + 60:pos + 62])
            pos += 62
            extra = 0
            if flags & 0x4000:
                if version < 3:
                    return ["index cannot be inspected (extended flags in a v2 index)"]
                (extra,) = struct.unpack(">H", data[pos:pos + 2])
                pos += 2
            if version == 4:
                byte = data[pos]
                pos += 1
                strip = byte & 0x7F
                while byte & 0x80:
                    byte = data[pos]
                    pos += 1
                    strip = ((strip + 1) << 7) | (byte & 0x7F)
                end = data.index(b"\0", pos)
                if strip > len(previous):
                    return ["index cannot be inspected (bad path compression)"]
                name = previous[:len(previous) - strip] + data[pos:end]
                pos = end + 1
                previous = name
            else:
                length = flags & 0xFFF
                end = pos + length if length < 0xFFF else data.index(b"\0", pos)
                name = data[pos:end]
                pos = start + ((62 + (2 if flags & 0x4000 else 0) + len(name) + 8) & ~7)
            if flags & 0x8000 or extra & 0x4000:
                problems.append(f"index flag hides modifications: {os.fsdecode(name)}")
    except (struct.error, ValueError, IndexError):
        return ["index cannot be inspected (malformed)"]
    return problems


def worktree_problems(root: Path, entries, *, allow_eol: bool = True) -> list[str]:
    """Reasons the live checkout at ``root`` is not byte-identical to the authenticated ``entries``.

    Raw bytes against the blobs: no git filter, attribute or helper is consulted, so a repository-controlled filter can
    neither run nor make a different file look like the blob, and the comparison does not read the index, so
    ``assume-unchanged`` / ``skip-worktree`` cannot hide a modification (the flags themselves are refused as well, see
    ``index_flag_problems``). ``allow_eol`` tolerates a file whose only difference is CRLF where the blob has LF (a checkout
    with line-ending conversion); this is harmless because this comparison never decides what executes. Symlink entries must
    be symlinks with the authenticated target.
    """
    root = Path(root)
    problems: list[str] = index_flag_problems(root)
    replace = root / ".git" / "refs" / "replace"
    try:
        if replace.is_dir() and any(replace.iterdir()):
            problems.append("replace refs (refs/replace) present: a replaced commit or tree would stand in for the revision")
        packed = root / ".git" / "packed-refs"
        if packed.is_file() and b"refs/replace/" in packed.read_bytes()[:MAX_OBJECT_SIZE]:
            problems.append("replace refs (refs/replace) present: a replaced commit or tree would stand in for the revision")
    except OSError:
        problems.append("replace refs could not be inspected")
    for mode, rel, blob in entries:
        path = os.path.join(root, *rel.split("/"))
        try:
            info = os.lstat(path)
        except OSError:
            problems.append(f"content differs from the revision: {rel}")
            continue
        key = (os.fspath(root), rel)
        if mode == "120000":
            if not stat.S_ISLNK(info.st_mode) or _blob_id(os.fsencode(os.readlink(path))) != blob:
                problems.append(f"content differs from the revision: {rel}")
            continue
        if not stat.S_ISREG(info.st_mode):
            problems.append(f"content differs from the revision: {rel}")
            continue
        signature = (_signature(info), blob)
        if _STAT_OK.get(key) == signature:
            continue
        try:
            fd, size = _open_regular(path)
            try:
                if size > MAX_OBJECT_SIZE:
                    raise ValueError("too large")
                data = os.pread(fd, size + 1, 0)
            finally:
                os.close(fd)
        except (OSError, ValueError):
            problems.append(f"content differs from the revision: {rel}")
            continue
        if _blob_id(data) == blob or (allow_eol and b"\r\n" in data and _blob_id(data.replace(b"\r\n", b"\n")) == blob):
            _STAT_OK[key] = signature
        else:
            problems.append(f"content differs from the revision: {rel}")
    return problems


def untracked_problems(root: Path, tracked: set[str]) -> list[str]:
    """Untracked or ignored importable files, symlinks and nested repositories anywhere in the live checkout.

    The tree is walked directly (symlinks not followed; nested ``.git`` directories included). Any importable suffix is
    refused, bytecode under ``__pycache__`` included: nothing there may stand in for a tracked module. Non-importable
    leftovers (``*.egg-info``, ``.venv`` without importable files at its top, build output) are accepted.
    """
    found: list[str] = []
    root = Path(root)

    def fail(error: OSError) -> None:
        raise error

    for here, dirnames, filenames in os.walk(root, followlinks=False, onerror=fail):
        base = Path(here)
        relbase = base.relative_to(root)
        if relbase == Path("."):
            dirnames[:] = [d for d in dirnames if d != ".git"]
            filenames[:] = [f for f in filenames if f != ".git"]
        for name in sorted(dirnames + filenames):
            rel = (relbase / name).as_posix()
            if rel in tracked:
                continue
            path = base / name
            if path.is_symlink():
                found.append(rel)
            elif name == ".git":
                found.append(rel)
            elif name in filenames and name.endswith(_IMPORTABLE_SUFFIXES):
                found.append(rel)
    return found


# ---------------------------------------------------------------------------------------------------------------------
# Verified-module registry (process-wide: every copy of the runtime module consults the same one)
# ---------------------------------------------------------------------------------------------------------------------
_VERIFIED: dict[str, tuple[types.ModuleType, Path]] = {}


def register_verified(top_level: str, module: types.ModuleType, detached_root: Path) -> None:
    with _LOCK:
        _VERIFIED[top_level] = (module, Path(detached_root))


def forget_verified(top_level: str) -> None:
    with _LOCK:
        _VERIFIED.pop(top_level, None)


def verified_root(top_level: str) -> Path | None:
    entry = _VERIFIED.get(top_level)
    return entry[1] if entry else None


def module_problems(top_level: str, detached_root: Path) -> list[str]:
    """Problems with every ``sys.modules`` entry of ``top_level`` (the package and its submodules).

    A pinned module is acceptable only if it is the object registered when the authenticated copy was imported (identity,
    not name) or a lazily imported submodule of it, and its ``__file__`` (and every ``__path__`` entry) lies under the
    authenticated copy. Anything else was executed from, or can redirect to, unverified source.
    """
    import sys

    problems = []
    registered = _VERIFIED.get(top_level)
    for name, module in list(sys.modules.items()):
        if name != top_level and not name.startswith(top_level + "."):
            continue
        if module is None:
            problems.append(f"{name}: placeholder entry in sys.modules")
            continue
        if registered is None or registered[1] != Path(detached_root):
            problems.append(f"{name}: not imported from the authenticated copy")
            continue
        if name == top_level and module is not registered[0]:
            problems.append(f"{name}: a different object than the authenticated import")
        origin = getattr(module, "__file__", None)
        if not origin or not _inside(origin, detached_root):
            problems.append(f"{name}: __file__ {origin!r} is outside the authenticated copy")
        for entry in getattr(module, "__path__", None) or ():
            if not _inside(entry, detached_root):
                problems.append(f"{name}: __path__ entry {entry!r} is outside the authenticated copy")
    return problems


def is_loaded_verified(top_level: str, detached_root: Path) -> bool:
    """True if ``sys.modules`` holds exactly the registered authenticated import of ``top_level`` from ``detached_root``."""
    import sys

    registered = _VERIFIED.get(top_level)
    return bool(registered and registered[1] == Path(detached_root) and sys.modules.get(top_level) is registered[0])


def _inside(candidate: str, root: Path) -> bool:
    try:
        return Path(os.path.realpath(candidate)).is_relative_to(Path(os.path.realpath(root)))
    except (OSError, ValueError):
        return False


# ---------------------------------------------------------------------------------------------------------------------
# Authenticated Manifest
# ---------------------------------------------------------------------------------------------------------------------
def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def canonical_digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def strict_loads(raw: bytes) -> Any:
    """Parse UTF-8 JSON, refusing duplicate object keys and non-finite numbers (no value may mean two things)."""
    def pairs(items):
        out: dict = {}
        for key, value in items:
            if key in out:
                raise ValueError(f"duplicate object key {key!r}")
            out[key] = value
        return out

    def constant(name):
        raise ValueError(f"non-finite number {name}")

    def real(text):
        value = float(text)
        if not math.isfinite(value):
            raise ValueError("non-finite number")
        return value

    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant, parse_float=real)


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return types.MappingProxyType({k: _freeze(v) for k, v in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(v) for v in value)
    return value


def typed_equal(left: Any, right: Any) -> bool:
    """Semantic JSON equality that never conflates types: 1 / 1.0 / True / "1" differ, key sets and arrays must match."""
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(typed_equal(left[k], right[k]) for k in left)
    if isinstance(left, list):
        return len(left) == len(right) and all(typed_equal(a, b) for a, b in zip(left, right))
    if isinstance(left, float):
        return repr(left) == repr(right)
    return left == right


class ManifestMismatchError(RuntimeError):
    """The caller's manifest is not the authenticated manifest (semantic equality and digest equality are both required)."""


class AuthenticatedManifest:
    """The authenticated Manifest: exact blob bytes of one path of the pinned Manifest revision, parsed once, immutable.

    ``value`` is a read-only deep view; ``to_dict()`` returns a fresh mutable copy parsed from the authenticated bytes, so
    one consumer cannot alter what another sees. ``sha256`` is the digest of the raw bytes, ``digest`` the canonical-JSON
    digest (the same function as ``gax_ref.digest``) that identifies the manifest content in authorization and execution.
    """

    __slots__ = ("source_revision", "repo", "path", "blob_id", "sha256", "digest", "_raw", "_value", "_canonical")

    def __init__(self, *, source_revision: str, repo: str, path: str, blob_id: str, raw: bytes):
        parsed = strict_loads(raw)
        if not isinstance(parsed, dict):
            raise SourceAuthenticationError("an authenticated manifest must be a JSON object")
        canonical = canonical_bytes(parsed)
        object.__setattr__(self, "source_revision", source_revision)
        object.__setattr__(self, "repo", repo)
        object.__setattr__(self, "path", path)
        object.__setattr__(self, "blob_id", blob_id)
        object.__setattr__(self, "sha256", "sha256:" + hashlib.sha256(raw).hexdigest())
        object.__setattr__(self, "digest", "sha256:" + hashlib.sha256(canonical).hexdigest())
        object.__setattr__(self, "_raw", bytes(raw))
        object.__setattr__(self, "_value", _freeze(parsed))
        object.__setattr__(self, "_canonical", canonical)

    def __setattr__(self, name, value):
        raise AttributeError("AuthenticatedManifest is immutable")

    __delattr__ = __setattr__

    @property
    def value(self):
        return self._value

    @property
    def raw(self) -> bytes:
        return self._raw

    def to_dict(self) -> dict:
        """A fresh, independent, mutable copy parsed from the authenticated bytes."""
        return strict_loads(self._raw)

    def identity(self) -> dict:
        return {"source_revision": self.source_revision, "path": self.path, "blob_id": self.blob_id,
                "sha256": self.sha256, "digest": self.digest}

    def require_caller_manifest(self, caller: Any) -> None:
        """Refuse unless ``caller`` is semantically equal to AND has the same canonical digest as this manifest."""
        try:
            caller_bytes = canonical_bytes(caller)
        except (TypeError, ValueError, RecursionError, OverflowError) as exc:
            raise ManifestMismatchError("caller manifest is not canonical JSON; it cannot equal the authenticated manifest") from exc
        if not typed_equal(caller, strict_loads(self._raw)):
            raise ManifestMismatchError(
                f"caller manifest is not semantically equal to the authenticated manifest {self.digest} ({self.path})")
        if "sha256:" + hashlib.sha256(caller_bytes).hexdigest() != self.digest:
            raise ManifestMismatchError(
                f"caller manifest digest differs from the authenticated manifest digest {self.digest} ({self.path})")


def read_checkout_file(path: os.PathLike | str, limit: int = MAX_MANIFEST_BYTES) -> bytes:
    """Exact bytes of one regular file, opened without following a final symlink, bounded, read through one descriptor."""
    fd, size = _open_regular(os.fspath(path))
    try:
        if size > limit:
            raise ValueError(f"{path} exceeds the {limit} byte bound")
        data = os.pread(fd, limit + 1, 0)
    finally:
        os.close(fd)
    if len(data) > limit:
        raise ValueError(f"{path} exceeds the {limit} byte bound")
    return data


def authenticate_manifest(path: os.PathLike | str, revision: str, *, expected_sha256: str | None = None) -> AuthenticatedManifest:
    """Authenticate the manifest file at ``path`` against ``revision`` of its checkout.

    The bytes come from the Git object database (commit -> trees -> blob, re-hashed in-process); the live file at ``path``
    must equal them byte for byte (a modified, replaced, symlinked or merely re-formatted file is refused, whatever the index
    says) but is not the source of the returned object. ``expected_sha256`` (``sha256:<hex>`` of the raw bytes), when given,
    is an additional deployment binding.
    """
    lexical = Path(os.path.abspath(path))
    root = None
    for candidate in [lexical, *list(lexical.parents)[:GIT_LOOKUP_LEVELS]]:
        if (candidate / ".git").exists() or (candidate / ".git").is_symlink():
            root = candidate
            break
    if root is not None:
        # The configured path is inside a checkout: no component below the checkout root may be a symlink, so a link
        # retargeted to another tracked file cannot be accepted under that other file's name.
        current = root
        for part in lexical.relative_to(root).parts:
            current = current / part
            if stat.S_ISLNK(os.lstat(current).st_mode):
                raise SourceAuthenticationError(f"manifest path {current} is a symlink inside the checkout")
        rel = lexical.relative_to(root).as_posix()
        real = lexical
        root = find_git_root(root)
    else:
        # Reached through a link outside any checkout: resolve once. The digest binding is the real pin in that layout.
        real = Path(os.path.realpath(path))
        root = find_git_root(real)
        rel = real.relative_to(root).as_posix()
    _mode, blob_id, raw = read_blob_at(root, revision, rel)
    if expected_sha256 is not None and expected_sha256 != "sha256:" + hashlib.sha256(raw).hexdigest():
        raise SourceAuthenticationError("authenticated manifest bytes do not match the expected digest")
    try:
        live = read_checkout_file(real)
    except (OSError, ValueError) as exc:
        raise SourceAuthenticationError(f"live manifest file cannot be read as a regular file: {exc}") from exc
    if live != raw:
        raise SourceAuthenticationError("live manifest file differs from the authenticated manifest bytes")
    return AuthenticatedManifest(source_revision=revision, repo=str(root), path=rel, blob_id=blob_id, raw=raw)
