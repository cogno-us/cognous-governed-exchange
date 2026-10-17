# F5b repaired runtime Exchange profile — 16 October 2026

`security-runtime-f5b-20261016` is a separate opt-in profile for the merged revisions after the F5b security repairs:

| Component | `security-runtime-candidate-20261016` (kept) | `security-runtime-f5b-20261016` (added) |
|---|---|---|
| Control Plane | `996baeb476c8745b1a58ddc968b9eecc6a39b76b` | `a34c3dc26f84a767a55f9d5c89dc0b53e63fefa5` |
| Execution runtime | `fd6b76fa0e85feb5b67324114bf790d3a12fdaf1` | `4a83b175d2ef0e65a7ee22a0513bb94a5fdf3a6f` |
| Action Manifest | `e385f8c19b4444817a8b84b72ed6edbc37deb807` | `2c36bcd0b620dbfe7ad924bc7196a3f0c04c5c5e` |
| Replay | `3601fb218d5c02f5d86e55d2cf33983e5e130ac3` | `0cfe7a6319930bccad3e9027a1dfbe3d6e29d657` |
| ODES | `dd2dc7e8f3fe74263917a0c67a40875daf3b0ce0` | `4e6d11691b9dea56a70026b6519159cf0e0ffd8b` |
| Evidence Pack | `8aba5a106ad119330950ccff97c55fa8492bc287` | `683246e05d291308211778ec48045df65466461f` |

It follows the additive pattern of the [repaired runtime profile](security-runtime-profile-20261016.md) and of the matching Replay, ODES and Evidence Pack F5b generations. The earlier profile and every historical profile are unchanged, so retained evidence remains reproducible at its original pins.

The new profile has the same behaviour as `security-runtime-candidate-20261016`:
- the trusted Python caller must supply `runtime_authority_profile`; without it the exchange fails before opening the exchange store;
- candidate sources are located and their Git identity verified before import, with the same untracked-file, shadowing and bytecode refusals; `PYTHONDONTWRITEBYTECODE=1` and checkouts without `__pycache__` are required.

The in-process Git check remains a provenance-consistency check, not a trust boundary. The qualification harness selects this generation by setting `GAX_RUNTIME_COMPATIBILITY_PROFILE=security-runtime-f5b-20261016`. Cross-component cases and results belong to `cognous-stack-qualification/suites/security-runtime`.

The transport adapter limitation described in `experiments/governed_message_transport/profile.md` applies to this profile as well.

Changes candidate component revision; requires F3 requalification, refreeze and re-review before acceptance. No release or production authorization. C0 and deployment limits remain.
