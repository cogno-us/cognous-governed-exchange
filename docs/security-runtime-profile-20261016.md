# Repaired runtime Exchange profile — 16 October 2026

`security-runtime-candidate-20261016` is a separate opt-in profile with exact actual merged CP, executor, Manifest, Replay, ODES and Evidence Pack revisions. Existing profiles remain unchanged. Loaded source identities and tracked source bytes are checked before using the executor; source identity is not independent institutional trust.

The trusted Python caller must supply `runtime_authority_profile` to `run_exchange` and `resume_original_exchange`. Missing configuration fails before opening the exchange store. The profile is never obtained from an incoming message. The existing Control Plane validates and freezes this configuration; synthetic fixtures must additionally opt into `allow_test_time`. No default execution profile is activated or institution adopted by this API change.

The reference retains actual runtime-authority journals, typed refusals, original effect ownership, acknowledgements, unknown outcomes and derivative recovery evidence through the strict migrated consumers. A retained failure-record identifier is not proof of its row's independent durability. Historical records require their original revision-pinned recovery path; the new profile does not relabel old evidence.

Scenario tests and results are maintained in the central qualification repository, `suites/security-runtime`. No selected lock/profile, production action or publication acceptance changes.
