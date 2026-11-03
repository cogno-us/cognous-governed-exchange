# Authenticated source (strict profiles)

Applies to every strict-source profile: `typed-refusal-candidate-20261015` and the seven security runtime profiles.
Non-strict profiles keep the ambient import and the caller manifest unchanged.

## What is authenticated

For each pinned component (control plane, runtime, Replay bundle, ODES, Evidence Pack) the loader:

1. finds the checkout without importing it (never `import` to locate or verify),
2. reads the pinned commit, its tree and every blob with a bounded in-process git object reader
   (`authenticated_source.py`, adapted from the Evidence Registry `bitrep_checkout.py`): loose zlib objects and
   pack/idx v2 (OFS and REF deltas), each object re-hashed (SHA-1 identity commit -> tree -> blob) and size, count and
   work bounded. No `git` subprocess is started; config, filters, hooks, refs, `refs/replace`, alternates, shallow
   files, promisor remotes and `GIT_*` environment are never consulted,
3. materializes the authenticated tree into a private, detached, 0700 directory (read-only files) together with a
   minimal synthesized `.git` (detached HEAD at the pin, commit and tree objects, an index, `shallow`, `config`),
   so downstream components that run `git rev-parse HEAD` / `git status` on their own import location (ODES, Evidence
   Pack, the qualification conftest) see the pinned revision and a clean tree,
4. imports only from that copy (detached roots first on `sys.path`; the live CP and runtime checkouts are not put on
   `sys.path`), with a private `sys.pycache_prefix` and bytecode writing disabled while importing,
5. refuses pinned modules already in `sys.modules` that are not the registered, verified objects, and any module whose
   `__file__` / `__path__` is not under the detached copy.

The live checkout is still compared with the authenticated tree as a policy check (raw bytes, `.git/index`
assume-unchanged / skip-worktree flags, untracked / ignored importable files, symlinks, nested `.git`, replace refs).
That comparison explains refusals; it is not the security boundary. The imported bytes are always the authenticated ones.

Entry points: `gax_ref._cp()` (ambient import), `run_exchange`, `resume_original_exchange`, `run_actual_outcome`,
`run_demo`, the legacy `gax_ref.run_exchange` / `run_demo`, and `export_odes_reference`. Each authenticates before
anything pinned is imported or executed.

## Residual trust (out of scope, not removed)

- The Python interpreter, the standard library and ambient third-party dependencies (pydantic, jsonschema,
  cryptography, ...) are imported from the environment and are not authenticated here.
- The anchor is SHA-1 object identity (git). A SHA-1 collision attack on git objects is not addressed.
- An attacker running as the same uid can alter the interpreter, the detached directory while it is being used, or the
  process itself.
- Downstream git subprocesses (run by ODES, Evidence Pack, qualification) execute in the synthesized repository, not
  the live one.
- The `pinned_module()` fast path does not re-read the checkouts after the first successful strict load in a process.
- Mixed line endings: the live-checkout policy comparison tolerates CRLF vs LF for source trees (never for the
  manifest); the imported bytes are still the authenticated ones.

## Layout limits and behaviour changes

- Checkouts using a gitfile (`.git` file), linked worktrees, alternates or submodule layouts are refused rather than
  interpreted.
- Bounds: object 1 MiB, total 128 MiB, 10,000 files per tree, delta base cache 48 MiB.
- The first strict load costs several seconds (ODES alone about 6 s on a loaded machine); later loads reuse the copy.
- Module `__file__` for pinned components is now under a `gax-authenticated-*` temporary directory, not the live
  checkout. Tests that pinned the old location now assert the detached copy.
