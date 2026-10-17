# CHANGELOG

## F5b peer repin to Replay def0ee0f, ODES 5675f1b9 and Evidence Pack 505a3590 (17 October 2026)

- Repinned the hard-coded `security-runtime-f5b-20261016` peers again: Replay `def0ee0f`, ODES `5675f1b9` and Evidence Pack `505a3590`. Runtime `4a83b175`, Control Plane `a34c3dc2` and Manifest `2c36bcd0` are unchanged. Older generations and earlier changelog entries are left as they were. The source-identity check compares the pinned constants, so no code beyond the literals changed.

## F5b remediated peer repin (17 October 2026)

- Repinned the hard-coded `security-runtime-f5b-20261016` peers to the remediated tuple: runtime `4a83b175`, Replay `0cfe7a63`, ODES `4e6d1169` and Evidence Pack `683246e0`. Control Plane `a34c3dc2` and Manifest `2c36bcd0` are unchanged.

## Generation fence F5b effective-grant forwarding (F-17)

- Fixed `LineageGenerationFence.commit_if_current` and `_FencedDestination.commit` to accept and forward `expected_effective_grant_digest` and `effective_grant_derivation_version` to the destination. Previously `run_exchange(generation_fence=...)` on the F5b path raised `TypeError` on every commit, so even the current generation could not commit and no refusal row was persisted (runtime issue cognous-execution-runtime#99, 5a).
- Fence semantics are unchanged: a superseded generation is refused with a persisted refusal and no effect; the current generation commits. The arguments are forwarded only when supplied, so destinations without F5b support are unaffected.
- Added regression tests in `tests/test_generation_fence.py`.

## Unreleased

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
