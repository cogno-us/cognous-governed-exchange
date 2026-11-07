# S1G: ODES lifecycle profile -> GAX reliance GRANT (development)

DEVELOPMENT ONLY, SYNTHETIC / NONPRODUCTION, UNQUALIFIED, NOT ADOPTED, HOLD. Builder-lineage evidence only; no independent qualification. A GRANT is reliance evidence only
(no effect, no Control Plane authority, no institutional permission).

## Change
One new explicitly selected profile `security-runtime-p1-lifecycle-20261107` in `experiments/odex_gax_imx_reference/gax_ref_runtime.py`: the P1 tuple except
`ODES_REVISION = cafec03f71d0f822b783f7463fcd8144c90829d5` (ODES draft PR #146, provisional, exists only on a draft branch). The P1 block, `consume_odes_reliance` and every
other profile are unchanged. Selected only through `GAX_RUNTIME_COMPATIBILITY_PROFILE`.

## Tests (`tests/test_odes_lifecycle_reliance.py`, worker `tests/s1g_lifecycle_worker.py`)
Opt-in via `GAX_S1G_STACK_ROOT` (odes @ cafec03f) and `GAX_S1G_OLD_STACK_ROOT` (P1 stack, odes @ 1e226128); `GAX_S1G_REQUIRE=1` makes a missing root a failure. T1 native positive,
T2 rewritten/resealed/re-signed package, T3 revoked status, T4 stale lifecycle, T5 legacy/restrictions compatibility, T6 old-pin refusal. See `docs/s1g-evidence/` for every
run, including the adverse ones (iteration 1: 5 failed; iteration 3: 1 failed), and `tests/data/s1g_lifecycle/PROVENANCE.md` for the anchor sequence and its limits.

## Findings and residuals
- `test_p1_registration_in_both_gate_sets_and_beside_r3` asserted exactly 8 security runtime profiles and failed (9) after registration (also reproduced by CI on head 2e4285b8). Closeout
  replaced the obsolete count with an exact nine-profile set assertion (Architect-approved); the P1 profile and every other expectation are unchanged.
- The old ODES evaluator (1e226128) does not recognize the lifecycle profile id, produces no `replay_semantic_consistency` layer and returns native final pass when the policy lists the id. Only the
  gate's requirement that the layer be present and pass prevents a GRANT. That requirement is load-bearing.
- Anchor separation is same-author and same-run (synthetic), not independent organizational trust. Fresh Replay imports are not digest-reproducible (random bundle_id/generated_at).
- The ODES exporter's future-timestamp check reads the machine clock; status inputs, key custody and policy ownership remain unassigned. Reached through a draft-only ODES pin: if PR #146 merges at a
  different revision a new profile must be added.

## Rollback
Revert the commit; P1 and all other profiles are unchanged; no data or format migration.
