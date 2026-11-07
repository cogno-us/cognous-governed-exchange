# S1G lifecycle test inputs — SYNTHETIC / NONPRODUCTION / DEVELOPMENT ONLY / UNQUALIFIED

- The Control Plane fixtures (`lifecycle_proposal.json`, `lifecycle_control_plane_run.json`) are read from the authenticated ODES draft checkout
  (cafec03f…, `tests/data/lifecycle_generation/`, produced by the real pinned Control Plane 484fdbd2 with risk metadata supplied before commitment) and their
  sha256 are pinned in `FIXTURE_HASHES.json`. They are deliberately NOT copied here (iteration 2 copied them; the existing P1 invariant test
  `test_p1_gax_remains_tenantless_no_gax_side_effect_identity` then failed; see PR evidence).
- `synthetic_issuer_public_key.json`: public half of the SYNTHETIC key derived from the constant seed `bytes(range(32))` (the producer's signing key in
  `s1g_lifecycle_worker.py`). The recipient policy takes `trusted_keys` from this committed file, never from a package.
- Expected package digests are NOT committed: a fresh pinned-Replay import stamps a random bundle_id/generated_at, so no digest is reproducible across imports
  (iteration 1 failed 5 of 8 tests on exactly this). Instead the test run performs an explicit three-step sequence in separate processes:
  1. `produce` (producer): live Control Plane fixtures -> real pinned Replay -> ODES exporter; persists the bundle, the packages and `digests.json`.
  2. `record_anchor` (recipient preparation): reads ONLY `digests.json` (never a package) and records `anchor.json`.
  3. consumption scenarios read the untrusted package file plus `anchor.json`; the consumer never takes a digest from the package it evaluates.
  This is same-author, same-run synthetic separation, NOT independently established organizational trust; anchor holder, rotation and key custody are UNASSIGNED.
