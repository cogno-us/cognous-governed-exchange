## Scan 4 input-validation fixes (22 October 2026)

- Experimental exchange, input validation only, no contract or pin change. (GX-1) A message whose `message_type` is not a string (for example a list) passed `queue()` and the receipt, then `AcceptedGaxRecipientAdapter.handle` raised `TypeError` on the set membership tests, leaving the outbox `IN_FLIGHT` with a receipt and no outcome. The recipient now refuses it before any receipt with a typed `TERMINAL_REJECTION` (reason `unsupported_message_type`), and `handle` checks the type first (`unsupported_execution_message_type`, not attempted). (GX-2) A message carrying `NaN` or `Infinity` (accepted by `json.loads`) made `assess_message` raise `ValueError`; it now returns `NOT_UNDERSTOOD` with the existing code `GAX-INTEGRITY-DIGEST`, and the transport commitment check refuses it as `governed message not canonicalizable`. (Authority reference) `RuntimeProposal.authority_context_ref` is optional in the control plane, so a proposal without one matched an `authority_refs` entry without a `ref` (`None == None`); assessment now requires a non-empty string proposal reference and refuses otherwise with `GAX-AUTHORITY-REFERENCE-MISMATCH`. Non-authorizing: assessment still grants nothing.

## Programme 2 source tuple re-tied after the scan-3 fixes (22 October 2026)

- Experimental exchange, no behaviour change. The Programme 2 compatibility profile `security-runtime-p2-20261018` keeps its name and now selects control plane `5c474ba8`, runtime `79f39166`, manifest `8b016916`, Replay `d268b1ea`, ODES `79df173d`, evidence pack `50803840` (was `2bac7875` / `6b16962d` / `ff549082` / `6a6a4774` / `2893d935` / `fd030615`). The strict source check still compares each checkout's Git HEAD to these strings exactly. P4, F5b and the earlier profiles are unchanged. This selects revisions for a compatibility check only: it is non-authorizing, creates no production grant and claims no certification or production readiness.

## Programme 2 source tuple moved to current mains (19 October 2026)

- Experimental exchange, no behaviour change. The Programme 2 compatibility profile `security-runtime-p2-20261018` keeps its name and now selects the current mains: control plane `2bac7875`, runtime `6b16962d`, manifest `ff549082`, Replay `6a6a4774`, ODES `2893d935`, evidence pack `fd030615` (was `6093aca7` / `62a5cc15` / `f9ae8527` / `c8e665bd` / `bff8307c` / `cde3f1f1`; an earlier selection on the same date named runtime `c4a05883`, Replay `2a7963b1`, ODES `4bf12128` and evidence pack `80e24650`). The strict source check still compares each checkout's Git HEAD to these strings exactly. P4, F5b and the earlier profiles are unchanged.

## Generation type check (19 October 2026)

- Experimental exchange, no contract change and no pin change. Input validation: the lineage generation must be a plain `int` (at least 0). The fence claim refuses a float (integral or not), a `bool` or an `int` subclass, and `run_exchange` returns `lineage_generation_invalid` before recording the message instead of truncating with `int()`. Valid integer generations behave as before.

## Source check covers the whole checkout (19 October 2026)

- Experimental exchange, no contract change and no pin change. The strict source check now compares every tracked file of each checked checkout with its recorded revision and refuses assume-unchanged or skip-worktree index entries anywhere in it, so a module imported by one of the verified entry modules is covered as well. A tracked entry that cannot be compared (submodule, missing file) is refused. Clean checkouts load as before.

## Security-review hardening (18 October 2026)

- Programme-2 compatibility profile `security-runtime-p2-20261018` re-tied (final pin round, no behaviour change) to the final revisions: control plane `6093aca7`, runtime `62a5cc15`, manifest `f9ae8527`, Replay `c8e665bd`, ODES `bff8307c`, evidence pack `cde3f1f1` (was `3cd17ead` / `11de097c` / `2c36bcd0` / `46e8bd7c` / `cdf704c8` / `4fbbd344`). The strict source check compares each checkout's Git HEAD to these strings exactly. P4, F5b and the earlier profiles are unchanged.
- Experimental exchange, no contract change and no pin change. A per-message processing lease is taken in the same `BEGIN IMMEDIATE` transaction as the effect claim: a second holder for the same message gets a hold with reason `message_processing_lease_held` and no dispatch. The lease is released when the exchange call ends; a crashed holder leaves it in place until an operator releases it, so a redelivery is held rather than dispatched twice. Dispatch checkpoints and workflow and artifact-export rows are insert-once (the one allowed advance is bound to dispatched; a repeat of the same record is a no-op; a different record for the same message is refused), and the transport records a recipient outcome once. Strict source verification compares `git hash-object` of each verified entry module and its package `__init__.py` files with their blobs at HEAD, refuses those files if their index entry is assume-unchanged or skip-worktree, and re-hashes them immediately before import (the whole-checkout step added on 19 October 2026 now covers every tracked file; see the entry at the top of this file). Rejection acknowledgements store envelope-supplied identifiers as bounded markers (256 characters) and reasons truncated to 512 characters.

## Programme 2 profile: ODES pin aligned to cdf704c8 (18 October 2026)

- The `security-runtime-p2-20261018` profile now pins ODES `cdf704c88bb6542e3f1121a5ceb6cb03fc7d6a52`, a docs-only ODES change (README wording, conformance tables and decision-log notes) on top of `e2cbc0dc`. The ODES source modules, schemas, validators and fixtures are unchanged; the exact-revision check compares the checkout's Git identity, so the pin follows the ODES `main` revision that qualification r8 names. No identity check changed. The P4 and F5b profiles are unchanged.

## Programme 2 profile: ODES pin aligned to e2cbc0dc (18 October 2026)

- The `security-runtime-p2-20261018` profile now pins ODES `e2cbc0dc`, the docs-only ODES change (names the P4 and P2 export profile versions as non-selected candidates) on top of `81979784`. The ODES source modules are unchanged; the exact-revision check compares the checkout's Git identity, so the pin follows the ODES `main` revision that qualification r7 names. No identity check changed. The P4 and F5b profiles are unchanged.

# CHANGELOG

## Programme 2 profile: ODES pin corrected to 81979784 (18 October 2026)

- The `security-runtime-p2-20261018` profile now pins ODES `81979784` (the commit that carries the Programme 2 compatibility tuple) instead of `0663d5a2`, which lacks it. No identity check changed; the profile is simply pinned to the ODES revision that matches the other four peers. The P4 and F5b profiles are unchanged.

## Programme 2 compatibility profile security-runtime-p2-20261018 (18 October 2026)

- Added the runtime compatibility profile `security-runtime-p2-20261018` beside `security-runtime-p4-20261017` and `security-runtime-f5b-20261016` (both unchanged, so retained evidence stays reproducible): Control Plane `3cd17ead`, runtime `11de097c`, Manifest `2c36bcd0` (unchanged), Replay `46e8bd7c`, ODES `0663d5a2` and Evidence Pack `4fbbd344`. Strict source verification compares the checkouts to these constants exactly as for the other profiles; no identity check was loosened. Alpha scaffolding, removed with the other hard pins at end-of-alpha (P5).

## P4 compatibility profile security-runtime-p4-20261017 (17 October 2026)

- Added the runtime compatibility profile `security-runtime-p4-20261017` beside `security-runtime-f5b-20261016` (kept, so retained evidence stays reproducible): Control Plane `26a7e659`, runtime `3024ef6e`, Manifest `2c36bcd0`, Replay `9aab3f6c` (step B), ODES `c5f4e2d0` and Evidence Pack `54df6984`. Strict source verification compares the checkouts to these constants as for the other profiles. Alpha scaffolding (qualification P4 of cogno-us/cognous-control-plane#38), removed with the other hard pins at end-of-alpha (P5).

## F5b peer repin to Replay def0ee0f, ODES 5675f1b9 and Evidence Pack 505a3590 (17 October 2026)

- Repinned the hard-coded `security-runtime-f5b-20261016` peers again: Replay `def0ee0f`, ODES `5675f1b9` and Evidence Pack `505a3590`. Runtime `4a83b175`, Control Plane `a34c3dc2` and Manifest `2c36bcd0` are unchanged. Older generations and earlier changelog entries are left as they were. The source-identity check compares the pinned constants, so no code beyond the literals changed.

## F5b remediated peer repin (17 October 2026)

- Repinned the hard-coded `security-runtime-f5b-20261016` peers to the remediated tuple: runtime `4a83b175`, Replay `0cfe7a63`, ODES `4e6d1169` and Evidence Pack `683246e0`. Control Plane `a34c3dc2` and Manifest `2c36bcd0` are unchanged.

## Generation fence F5b effective-grant forwarding (F-17)

- Fixed `LineageGenerationFence.commit_if_current` and `_FencedDestination.commit` to accept and forward `expected_effective_grant_digest` and `effective_grant_derivation_version` to the destination. Previously `run_exchange(generation_fence=...)` on the F5b path raised `TypeError` on every commit, so even the current generation could not commit and no refusal row was persisted (runtime issue cognous-execution-runtime#99, 5a).
- Fence semantics are unchanged: a superseded generation is refused with a persisted refusal and no effect; the current generation commits. The arguments are forwarded only when supplied, so destinations without F5b support are unaffected.
- Added regression tests in `tests/test_generation_fence.py`.

## Unreleased

- Security-review hardening of the experimental exchange (no contract change): a per-message processing lease is taken in the same `BEGIN IMMEDIATE` transaction as the effect claim (a second holder for the same message gets a hold with reason `message_processing_lease_held`, no dispatch; the lease is released when the exchange call ends, and a crashed holder leaves it in place until an operator releases it, so redelivery is held rather than dispatched twice); dispatch checkpoints and workflow/artifact-export rows are insert-once (the one allowed advance is bound to dispatched; a repeat of the same record is a no-op; a different record for the same message is refused); the transport records a recipient outcome once; strict source verification now compares `git hash-object` of each verified entry module and its package `__init__.py` files with their blobs at HEAD, refuses those files if their index entry is assume-unchanged or skip-worktree, and re-hashes them immediately before import (the whole-checkout step added on 19 October 2026 now covers every tracked file; see the entry at the top of this file); rejection acknowledgements store envelope-supplied identifiers as bounded markers (256 characters) and reasons truncated to 512 characters.

- Fixed (issue #30): `assess_message` now compares each `evidence_refs` entry of type `replay_bundle` to the digest of the supplied bundle. A mismatch is refused with `GAX-EVIDENCE-DIGEST-MISMATCH` (stage `evidence_digest: failed`) and nothing is dispatched. Behaviour change: previously a substituted bundle that derived the same proposal was accepted and executed.
- A message carrying no `replay_bundle` digest in `evidence_refs` is still accepted, but the assessment now discloses `stages.evidence_digest = not_verified_no_replay_bundle_digest_in_evidence_refs`.

## 0.1.0 — Worker 13 review candidate

- Added separately versioned governed-message transport envelope.
- Added explicit trusted local route configuration with non-cryptographic identity status.
- Added durable SQLite outbox/inbox/attempt/acknowledgement stores.
- Added duplicate suppression, conflicting message-ID rejection, expiry, bounded retry/backoff, lost-ack recovery and unresolved-delivery state.
- Added accepted GAX recipient adapter while retaining Control Plane/executor effect boundaries.
- Added traceable transport evidence with producer-reference namespace separation.
- Added acceptance and integration tests for delivery, rejection, recovery, informational acts, recipient hold/deny and no-second-effect redelivery.


## Control Plane persistence adoption preparation

- Selected accepted Control Plane persistence repair `248d899634d9db3518e831bc7ab568a48733f825`.
- Selected accepted Replay compatibility `043830b56595cecddfa65c064afd1c0b95e64792`.
- Preserved executor producer profile 2.0.0 at `177354e959cc78c59c1a776f018cfbfbf28c927b`.
- Added stage-level same-host store/restart and Replay revision-attribution checks.
- Kept ODES/Evidence Pack consumer pins unchanged pending accepted persistence-compatibility merges.
- Preserved retained-artifact version 1.1.0 and historical dependency mappings without relabeling.


## Control Plane persistence adoption Phase B

- Advanced current ODES selection to `0486b645e99c46d9cd16ca34b1ba7c653a6b3024`.
- Advanced current Evidence Pack selection to `de6b9e071df49fc3e0c1254d39b5c94cced554f0`.
- Preserved earlier ODES/Evidence Pack revisions as historical qualification combinations.
- Added focused public-path qualification before the complete CI suite.

## F5b security repairs (candidate, 2026-10-16)

- Candidate source verification locates and Git-checks each module before importing it, then requires the import to resolve to the verified file. Documented as a provenance-consistency check, not a trust boundary.
- Unsafe governed `message_id` values are `NOT_UNDERSTOOD` at the structure stage.
- `run_exchange` records a message receipt only after the message is accepted for assessment.
- `resume_original_exchange` rejects a supplied message whose `message_digest` does not match its content.
- Pinned generation-fence workflow actions to full SHAs and disabled persisted checkout credentials.
- Documented unmeasured historical revision labels, the historical legacy continuity loader, first-head predecessor trust and transport-adapter incompatibility with the V1 security profile.
- No component revision constants changed. Requires requalification; no release or production authorization.


## F3R F5b security-runtime generation (16 October 2026)

- Added separate opt-in profile `security-runtime-f5b-20261016` pinning CP `a34c3dc2`, runtime `e20f92e1`, Manifest `2c36bcd0`, Replay `79ba16d4`, ODES `eb83220c` and Evidence Pack `893aca8d`.
- `security-runtime-candidate-20261016` and all historical profiles are unchanged.
- The new profile requires trusted runtime-authority configuration and uses the F5b verify-before-import source checks; the source-identity tests now run under every strict profile.
- Candidate component revision; requires F3 requalification, refreeze and re-review. No release or production authorization.
