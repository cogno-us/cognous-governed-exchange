# CHANGELOG

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
