# Truthful opt-in typed refusal provenance

`typed-refusal-candidate-20261015` is a separate explicit opt-in profile.
Historical default `persistence-v1` and `merged-producers-v1` keep their original
pins. The candidate verifies all five loaded component modules' actual Git heads,
tracked source membership and absence of tracked changes, plus the exact Manifest
commit/file, before accepting its source labels. It rejects mismatches even when
producer interface version 2.0.0 is shared. This verifies source identity, not
independent authentication or authority. The S1 harness additionally rejects
untracked import shadows in all seven component checkouts.

F5b correction: module files are now located and Git-checked before they are
imported, and each imported module must resolve to the verified file. Earlier
revisions imported each module first, so planted import-time code could run
before the check. The in-process Git check remains a provenance-consistency
check, not a trust boundary; the harness fresh-checkout pre-check is the gate.

Actual merged predecessors are runtime #86 at
`309e194c1b0a3de23e11e20133e6eaf88875e48a`, Replay #25 at
`83fbaf2a0f6f071aca1ea0af859eb8fc6385c26a`, ODES #33 at
`25c7ad608c2e6fd9f450e075db6bbf3ee4091a49`, Evidence Pack #25 at
`1e789c7d67a897097445faef1813fb0cd22d55e5`, CP
`c7f122ba3a6e39f9268a7163c99be3ee514cd97e` and Manifest
`46c950bed37fe3812000895430bc0312d29e37ce`. The exact-source gate executes
against those actual merge commits. Eight stage-level cases qualify pin attribution, persistence, Replay
selection/rejection, bad source claim and historical default/merged behavior.
Full effect/ownership recovery qualification remains the separate 23-case twice
S1 gate at actual final merged pins. No ownership/dispatch/retry code is changed.

Candidate remains nonselected. Both authorizations false. Operational trust,
publication and production HOLD. C0 check-to-commit limitations and optional
same-host cooperative C1 only; no C2/C3 or real settlement. Updating this profile
does not change the frozen hub package or complete any PV acceptance gate.

The first hosted candidate run rejected rewritten tracked Replay egg-info after
editable dependency installation (eight setup errors, not test passes; Python
3.11 companion cancelled). The corrected workflow imports exact clean source via
PYTHONPATH and installs only pinned external test dependencies. The source gate
remains intact; hosted qualification must be rerun at the corrected head.

Migration is explicit source/profile selection, not checkpoint relabeling. Preserve
existing effect ownership, unresolved checkpoints and retained source bindings.
Historical unresolved work requires its original revision-pinned recovery path;
no cross-generation recovery or in-place production-store migration is qualified
by these tests. Synthetic S1 stores are isolated test fixtures. Do not reset an
ownership store to make a new profile accept historical work.
