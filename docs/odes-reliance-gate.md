# ODES reliance gate (development contract)

Contract id: `gax-odes-reliance-gate/0.1.0-dev`. Entry point: `consume_odes_reliance` in `experiments/odex_gax_imx_reference/gax_ref_runtime.py`.

Status: DEVELOPMENT ONLY, UNQUALIFIED, NOT ADOPTED, NON-RELEASE, NON-PRODUCTION. Review is builder-lineage only; there is no independent qualification. Basis: Architect S1 authorization (VNext S0 packet #273, #281 v0.2), which accepts the S0 design as a development proposal only. Nothing here is a certification, clearance or production-readiness claim.

## Purpose and non-goals

The function re-evaluates an ODES package at consumption time and returns a versioned GRANT or REFUSE record.

- A GRANT is reliance evidence only. It is not Control Plane authorization, institutional authority or Runtime effect permission.
- Nothing is persisted. The function writes no store, calls no workflow and has no effect.
- It is not wired into `assess_message`, receipts, retention/store contracts, `run_exchange`, `resume_original_exchange` or the transport. No downstream consumer of a grant exists; GAX execution is not reliance-gated by this change.
- It does not select or change compatibility profiles and does not change source authentication.

## Signature

```python
consume_odes_reliance(package, *, policy, policy_id, policy_version, expected_package_digest,
                      expected_relying_party, expected_purpose, expected_profile, now, max_grant_seconds)
```

Every input is required and keyword-only (except `package`); none has a default and none is derived from the package. Why:

- `policy`: recipient-supplied ODES policy. GAX's own supported-profile list is never trusted.
- `policy_id`, `policy_version`: labels recorded in the result. They are unauthenticated; the policy digest is what binds content.
- `expected_package_digest`: must come from a separate trust or assessment input, not from the submitted package or producer-resealable storage.
- `expected_relying_party`, `expected_purpose`, `expected_profile`: the recipient's own expectation, compared with policy and package.
- `now`: trusted evaluation time (timezone-aware ISO-8601). A policy `now` that differs is refused.
- `max_grant_seconds`: positive int; caps the grant lifetime.

## Evaluation rules

1. Strict source profile required. The ODES evaluator must be the authenticated pinned copy of `ODES_REVISION` (loaded-verified, no module problems). No fallback to an ambient module.
2. The policy is deep-copied; `now` is forced to the trusted value. It must carry explicit `supported_profiles` containing the expected profile, `relying_party`/`purpose` equal to the expectations, `trusted_digests` containing the expected digest, `detached_authentication` with envelope and `trusted_keys`, non-empty `status_inputs`, `trusted_issuer`, `jurisdiction`, `evaluation_scope`, and integer `status_max_age_seconds >= 0`.
3. The evaluator is run fresh. Stored verdicts, GAX self-listed policy and intermediate layer results are never trusted.
4. GRANT requires native final `recipient_reliance_decision.status == "pass"` AND all GAX-side bindings:
   - package `package_digest` == expected digest == ODES-recomputed digest (`package_content_integrity.evidence.package_digest`);
   - declared profile == expected profile; relying party and purpose as above;
   - package `provenance.pinned_revisions` `control_plane`/`replay`/`manifest`/`moltbot_safe` equal the GAX tuple constants;
   - package `provenance.source_artifacts.manifest_digest` == authenticated manifest digest (open #280 basis is not normalized);
   - `replay_semantic_consistency` present with status `pass`;
   - validity interval = min(`now + max_grant_seconds`, status `evaluated_at` + `status_max_age_seconds`, record `expires_at`), which must be after `now`.
5. Absent Pack/ODES source fields are not invented; unprovable identity refuses.

## Result record

Always: `contract`, `notice`, `verdict` (`GRANT`/`REFUSE`), `reason` (null on GRANT), `grant`. On REFUSE also `detail` and `grant: null`. On GRANT, `grant` holds: `odes_package_digest`, `odes_package_digest_note`, `fresh_validation_digest`, `profile`, `policy` (`id`, `version`, `digest`, `note`), `relying_party`, `purpose`, `evaluated_at`, `valid_until`, `source` (bound revisions, `manifest_digest`, `odes_evaluator_revision`, `gax_compatibility_profile`).

## Typed refusals

| Code | Produced when |
| --- | --- |
| `GAX-RELIANCE-UNAVAILABLE` | not a strict profile; ODES not the authenticated pinned copy; evaluator missing or loader failure |
| `GAX-RELIANCE-POLICY-MISSING` | policy not a non-empty dict |
| `GAX-RELIANCE-POLICY-INVALID` | policy contains any key outside the reviewed allowlist (so `allow_unauthenticated_informational_inspection` and the `trusted_package_digests` alias are refused); policy `now` differs; `supported_profiles` missing or lacking the expected profile (also the outcome when `expected_profile` is not listed); `supported_profiles` missing or lacking profile; no usable `detached_authentication`, `status_inputs`, issuer, jurisdiction or scope; bad `status_max_age_seconds`; empty `policy_id`/`policy_version` |
| `GAX-RELIANCE-ANCHOR-MISSING` | expected digest not `sha256:<64 hex>`; not in policy `trusted_digests` |
| `GAX-RELIANCE-TIME-INVALID` | `now`, `status_inputs.evaluated_at` or record `expires_at` missing/unparseable/naive; `max_grant_seconds` not a positive int |
| `GAX-RELIANCE-REPLAY-BYPASS-ENABLED` | `ODES_ALLOW_UNVERIFIED_REPLAY` set to anything other than empty or `0` |
| `GAX-RELIANCE-BINDING-MISMATCH` | expected party/purpose/profile missing or differing from policy/package; package digest differs from expected; ODES-recomputed digest differs |
| `GAX-RELIANCE-SOURCE-MISMATCH` | no `pinned_revisions`; any of the four revisions differs from the GAX tuple; `manifest_digest` differs |
| `GAX-RELIANCE-ODES-FAIL` | native final status `fail`; carries `blocking_layers` when ODES supplies them |
| `GAX-RELIANCE-INFORMATIONAL-ONLY` | native final status `informational_only` |
| `GAX-RELIANCE-STALE` | computed validity interval is empty or already past |
| `GAX-RELIANCE-INDETERMINATE` | package not a non-empty dict; no recognizable final status; replay layer absent or not `pass`; any unexpected exception |

## Digest distinctions

- ODES `package_digest`: native digest of the ODES package; the only digest the grant anchors on.
- GAX retained-artifact digest (`odes_package_digest` in retained artifacts): a GAX storage digest, producer-resealable, never used as the anchor.
- Stored `odes_validation_digest`: digest of a past validation. The grant instead carries `fresh_validation_digest`, computed over the fresh evaluation result.

## Trust boundary and known limitations

- Recipient policy owner, real relying party and key custodian are UNASSIGNED. The Architect is design authority for the synthetic interface only. No real reliance is possible.
- `policy_id`/`policy_version` are unauthenticated labels. No authenticated status source exists, so `status_inputs` trust is not demonstrated.
- TOCTOU: the `ODES_ALLOW_UNVERIFIED_REPLAY` check runs immediately before evaluation, and a forked validator inherits the environment; the value is not re-checked inside the evaluator.
- Unknown ODES policy keys are silently ignored by ODES; the gate therefore passes only an allowlist of reviewed keys and refuses the rest.
- Only `pinned_revisions.{control_plane,replay,manifest,moltbot_safe}` and the manifest digest are bound by the gate; other package provenance (`selected_revisions`, extra pins) is covered by ODES's own checks only.
- `now` is a caller-supplied trusted time; the gate does not read a clock. Policy id/version are unauthenticated labels.
- The gate requires `replay_semantic_consistency` to be present and `pass`, so packages of non-Replay-bound profiles (e.g. the generic recipient profile) are unreachable (INDETERMINATE).
- ODES `informational_only` edge, `recipient_validator.py:565-568` (the test is only that authentication is the sole non-pass layer, not which status it has): the gate refuses `informational_only` regardless.
- Unchanged and not repaired: N5b original FAIL, open #280, the ODES 0_1/0_2 profile mismatch and the 24 predecessor FAILs.
- FINDING: a package exported by the pinned ODES from a CP2 bundle cannot reach native final `pass` (empty `risk_metadata` leaves restriction flags and jurisdiction unknown; metadata freshness is `unknown`). The synthetic positive test is therefore a gate-logic test with a stubbed evaluator. The native positive is BLOCKED pending producer-side changes outside this repository.
- Synthetic fixtures (test keys, policy, clock, status data) are test-only and must not enter default trusted configuration or any real reliance path.

## Rollback

Revert the additive commit. No data, profile or stored-format migration is involved.
