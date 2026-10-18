# Optional lineage-generation effect fence

Status: experimental, opt-in GAX reference profile.

Profile: `urn:cognous:profiles:gax-lineage-generation-fence` version `0.1.0`.

## Boundary

The fence binds one already-authorized local effect claim to the integer
`state_version` of the accepted GAX/IMX lineage head for the same conversation.
Immediately at the local destination commit boundary it opens
`BEGIN IMMEDIATE` on the exchange SQLite store, reads the authoritative head,
and calls the destination commit only while that write lock is held.

The refusal reason (`superseded_lineage_generation`) is retained in the fence's
refusal record. With the runtime revision pinned by the current profile, the
executor result for a refused claim carries the class name
`GenerationFenceRefusal` as its error text (status `failed`) rather than the
typed reason.

A v3 effect claim therefore fails closed if v4 is already authoritative. A head
update that acquires the same SQLite write lock first is observed before effect
commit. A head update that waits behind an in-progress accepted effect can become
authoritative only after that local commit completes.

This is a bounded same-store serialization property. It is **not** distributed
destination atomicity, institutional authority, a production effect guarantee,
or protection against a writer that bypasses the accepted exchange store.

## Refusal evidence and flood behavior

Before a superseded, missing-generation, or wrong-effect refusal returns, the
fence durably updates a fixed-size per-conversation counter row. Up to the
configured refusal cap it also appends minimal refusal rows containing only:

- refusal/profile identifiers;
- conversation and effect identifiers;
- claimed and authoritative generations;
- reason and timestamp.

Raw governed-message content, operation payloads and refused payload bytes are
not stored in these refusal records.

After the detail-row cap, refusal evidence is aggregated into the bounded
counter row. Counters saturate at a configured maximum rather than growing
without bound. Both detail rows and counters survive process restart.

If refusal persistence is disabled or cannot be verified, the fence raises (a
persistence error, or the underlying SQLite error when the write itself fails)
and still does not call the destination.

## Runtime opt-in

`run_exchange(..., generation_fence=fence, lineage_generation=N)` wraps the
existing destination only for that call. Supplying one option without the other
is an error. Omitting both preserves the accepted default runtime path.

The fence does not create, refresh or reinterpret an institutional grant. The
existing Control Plane decision and effect identity remain authoritative for
permission; the generation fence is an additional local supersession guard.

## Scope of the fence

The fence wraps `commit()` only; any other destination method is forwarded
unchanged, and `commit()` takes no operation id. `run_exchange` uses the
route-A destination, so an atomic destination (`execute_claim_atomic`) or the
operation-identity profile is not supported behind the fence. `generation` is
documented as a non-negative integer; the fence and `run_exchange` currently
also accept a float with an integral value (`5.0` matches head 5), and
`run_exchange` truncates a non-integral float with `int()`. Callers should pass
an `int`.

## F5b effective-grant arguments

On the F5b path the executor passes `expected_effective_grant_digest` and
`effective_grant_derivation_version` to the destination commit. The fence
forwards both unchanged, inside the same write lock and only after the
generation check passes. When they are not supplied the destination is called
exactly as before. A refused claim never reaches the destination, so the
effective-grant check is not evaluated for a superseded generation.
