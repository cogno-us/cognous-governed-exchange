# Truthful opt-in typed refusal provenance

`typed-refusal-candidate-20261015` is a separate explicit opt-in profile.
Historical default `persistence-v1` and `merged-producers-v1` keep their original
pins. The candidate verifies all five loaded component modules' actual Git heads,
tracked source membership and absence of tracked changes, plus the exact Manifest
commit/file, before accepting its source labels. It rejects mismatches even when
producer interface version 2.0.0 is shared. This verifies source identity, not
independent authentication or authority. The S1 harness additionally rejects
untracked import shadows in all seven component checkouts.

Draft exact dependencies are runtime PR #86 head 63bd4d8d, Replay PR #25 head
24fa9571, ODES PR #33 head da4f1976 and Evidence Pack PR #25 head 74cd70aa, with
CP c7f122ba and Manifest 46c950be. Replace these by actual serial merge SHAs and
rerun this gate before integration; never interpret draft-pin tests as a merged
chain. Eight stage-level cases qualify pin attribution, persistence, Replay
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
