<!-- cognous-banner:start -->

Cross-component test commands below now run in a disposable checkout assembled by the [qualification workflows](CROSS_COMPONENT_TESTS.md). Plain local test discovery covers the component-local tests retained here. Historical reports and dependency pins keep their original scope.
```text
──────────────────────────────────────────────────
   __________  _______   ______  __  _______
  / ____/ __ \/ ____/ | / / __ \/ / / / ___/
 / /   / / / / / __/  |/ / / / / / / /\__ \
/ /___/ /_/ / /_/ / /|  / /_/ / /_/ /___/ /
\____/\____/\____/_/ |_/\____/\____//____/
            COGNOUS GOVERNED EXCHANGE
       g o v e r n e d   b y   d e s i g n
  github.com/cogno-us/cognous-open-control-stack
──────────────────────────────────────────────────
```
<!-- cognous-banner:end -->

# Cognous Governed Exchange

**Governed exchange and continuity for a bounded synthetic workflow.**

**Status:** selected, as lock entry `gax_imx_transport` (GAX retained artifacts 1.1.0; `merged-producers-v1` opt-in compatibility). Experimental reference; deployment trust remains [HOLD](https://github.com/cogno-us/cognous-stack-orchestrator/issues/30). **Stack role:** cross-cutting exchange, connecting the five hub groups through governed messages, recipient assessment and continuity. See [where it fits](#cognous-stack-components) and the hub [stack map](https://github.com/cogno-us/cognous-open-control-stack/blob/main/docs/stack-map.md). Display name "Governed Exchange (GAX/IMX)"; Python package `alvorada-gax-imx-reference`, import package `experiments` (the former repository name was `alvorada`; see [naming](https://github.com/cogno-us/cognous-open-control-stack/blob/main/docs/naming.md)).

Status labels used on this page: **merged**, **selected**, **known limit**, **proposed** (defined in the hub [stack map](https://github.com/cogno-us/cognous-open-control-stack/blob/main/docs/stack-map.md#status-labels)).

## What it is, who it is for, what it does not do

- **What it is.** An experimental GAX/IMX reference that connects governed messages, recipient assessment, bounded execution and retained evidence. It implements exchange behavior and a local durable transport for a bounded synthetic refund workflow.
- **Who it is for.** Engineers who want to inspect the reference contracts, profiles and examples; enterprise architecture, security and governance reviewers who want to examine the boundary and evidence. Evaluate it for its named responsibility, not as a complete governance platform.
- **What it does not do.** It is not an institution or a constitution (that is [Institutional Governance](https://github.com/cogno-us/cognous-institutional-governance)), not full GAX conformance, not a production network and not institutional authentication. Message receipt, understanding, acceptance, authorization and execution are different events; message ids and receipt do not authorize actions. A valid signature, chain inclusion, message receipt, reasoning instruction or evidence-package digest does not authorize execution. Institutional authority must be supplied and evaluated through the appropriate trusted boundary.

## How it works

LocalDurableTransport delivers a synthetic refund message to AcceptedGaxRecipientAdapter. GAX assesses the message and routes the Manifest-bound proposal through the trusted runtime. Redelivery returns the retained original artifacts when available. If evidence was never retained after an effect, evidence-only recovery creates an explicitly derived record without issuing a replacement effect.

## Quick start

There is **no standalone quick start that produces output from a clean checkout**. The exchange demo and the compatibility profiles need checkouts of other components at exact revisions (a directory `upstream/` with the Control Plane and the Execution Runtime, plus the Manifest and Replay examples); without them the demo stops with a missing-file error or `RuntimeError: pinned upstream checkout is unavailable`. For the complete reproduction use the [hub developer quickstart](https://github.com/cogno-us/cognous-open-control-stack/blob/main/docs/quickstart.md) and the [qualification workflows](CROSS_COMPONENT_TESTS.md).

What you can run from a clean checkout is the component-local test suite. It needs Python 3.11 or later, has no runtime dependencies and uses no network:

```bash
git clone https://github.com/cogno-us/cognous-governed-exchange
cd cognous-governed-exchange
python -m venv .venv && . .venv/bin/activate
python -m pip install -e '.[dev]'
python -m pytest -q tests/test_generation_fence.py tests/test_generation_type_check.py   # quick check, a few seconds
python -m pytest -q tests                                                                 # full local suite, about 6 minutes
```

Expected output of the quick check, and the last line of the full run:

```text
27 passed in 3.44s
252 passed in 372.18s (0:06:12)
```

<!-- pin-round: refresh the two counts above if the tests change -->

The elapsed time varies. A passing local run does not show compatibility with a Control Plane or runtime revision, effect-producing behavior or deployment readiness; that evidence is in the qualification repository (see [compatibility](#compatibility-and-selection)).

## What ships

| Item | Where | Purpose | Default or optional | Label |
|---|---|---|---|---|
| Refund exchange profile `urn:cognous:profiles:odex-gax-imx-refund-exchange:0.1.0` | [profile](experiments/odex_gax_imx_reference/profile.md), [mapping](experiments/odex_gax_imx_reference/mapping.md), [reference README](experiments/odex_gax_imx_reference/README.md) | Experimental implementation profile for a bounded synthetic refund exchange. | default | selected (experimental) |
| Message types | `PROPOSE`, `REQUEST`, `REPORT`, `REFUSE`, `NOT_UNDERSTOOD` | The implemented message types of the profile. | default | selected (experimental) |
| Recipient assessment stages | [gax_ref_runtime.py](experiments/odex_gax_imx_reference/gax_ref_runtime.py) | Structure, supported profile, identity binding through a local trusted registry, reference resolution, authority assessment from retained Control Plane decision facts, freshness and expiry, permitted handling. | default | selected (experimental) |
| Transactional runtime | `run_exchange`, `resume_original_exchange`, `TransactionalExchangeStore` in [gax_ref_runtime.py](experiments/odex_gax_imx_reference/gax_ref_runtime.py) | Supported runtime path: runs an exchange through the public Execution Runtime and Control Plane interfaces and persists checkpoints and outcomes. | default | selected |
| Processing lease and insert-once writes | same module | A second holder for the same message is held with `message_processing_lease_held`; checkpoints, workflow and artifact-export rows are insert-once. | default | merged |
| Retained artifacts, profile `urn:cognous:profiles:gax-retained-artifacts` 1.1.0 | [runtime and artifact interface](docs/gax-runtime-artifact-interface.md) | Original Replay, ODES and exchange artifacts exposed with identities and content commitments. | default | selected |
| IMX successor packets | same module (`make_successor_packet`, `load_successor_packet`) | Preserve predecessor identity and commitment; loading a successor creates no effect. | default | selected (experimental) |
| Governed message transport, profile `urn:cognous:profiles:governed-message-transport:0.1.0` | [profile](experiments/governed_message_transport/profile.md), [mapping](experiments/governed_message_transport/mapping.md), [transport.py](experiments/governed_message_transport/transport.py) | `LocalDurableTransport`, `AcceptedGaxRecipientAdapter`, `TransportStore`, `TrustedRouteTable` and `DeliveryClockPolicy`: queue, deliver and redeliver messages while retaining recipient outcomes. | default | selected (experimental) |
| Lineage-generation fence, profile `urn:cognous:profiles:gax-lineage-generation-fence` 0.1.0 | [generation-fence.md](docs/generation-fence.md), [generation_fence.py](experiments/odex_gax_imx_reference/generation_fence.py) | `LineageGenerationFence`: refuses a stale effect claim before the local commit. The generation must be a plain `int`; anything else is refused as `lineage_generation_invalid`. | optional (not enabled by the hub) | merged |
| Typed refusal provenance, `typed-refusal-candidate-20261015` | [typed-refusal-profile.md](docs/typed-refusal-profile.md) | Explicit opt-in profile that verifies loaded component sources before use. | optional | merged (candidate, not selected) |
| Merged producers, `merged-producers-v1` | [merged-consumer-chain.md](docs/merged-consumer-chain.md) | Opt-in profile qualified against the accepted newer Control Plane, runtime, Replay, Evidence Pack and ODES revisions. | optional | selected (opt-in compatibility) |
| Repaired runtime profiles: `security-runtime-candidate-20261016`, `security-runtime-f5b-20261016`, `security-runtime-p4-20261017`, `security-runtime-p2-20261018` | [candidate profile](docs/security-runtime-profile-20261016.md), [F5b profile](docs/security-runtime-f5b-profile-20261016.md); the P4 and P2 profiles are described in [CHANGELOG.md](CHANGELOG.md) | Separate opt-in profiles with exact revisions; sources are verified before use and the trusted caller must supply a runtime authority profile. Older profiles are kept so retained evidence stays reproducible. | optional | merged (not selected) |
| Historical default `persistence-v1` and `gax_ref.py` | [gax_ref.py](experiments/odex_gax_imx_reference/gax_ref.py) | Historical default selector and module. `gax_ref.load_successor_packet` and `gax_ref.TransactionalExchangeStore` are unsupported; use `gax_ref_runtime`. | default (historical) | known limit |
| Synthetic fixtures and demo | [synthetic_fixture.py](experiments/odex_gax_imx_reference/synthetic_fixture.py), [demo.py](experiments/odex_gax_imx_reference/demo.py) | Synthetic resolver, policy and clock; the demo writes one illustrative JSON file and needs the `upstream/` checkouts described above. | optional | known limit (needs checkouts) |

Profiles are selected by setting `GAX_RUNTIME_COMPATIBILITY_PROFILE` before importing the runtime; an unknown name fails at import. The selector is a compatibility contract, not an authorization input or an identity attestation. The P4 and P2 profiles are alpha scaffolding that is removed together with the other hard pins at the end of the alpha stage.

## Example: two generations and a late result

Suppose a synthetic refund conversation has an authoritative local lineage head **generation 5**, while a delayed worker still claims **generation 4**.

1. The optional `LineageGenerationFence` reads the authoritative local generation from the same SQLite lineage store under its local commit lock.
2. The version-4 effect is **refused before local commit** as `superseded_lineage_generation`; the typed reason is retained in the fence's refusal record. Under the runtime revision the current profile pins, the executor result for this refusal shows only the error class name `GenerationFenceRefusal` (`status` failed), not the typed reason. A minimal record binds the claimed effect, expected and authoritative generations, and refusal reason; ordinary refusal logs do not need the raw payload.
3. The persisted refusal counter survives restart. Once the configured record limit is reached, later refusals increment bounded suppression counters instead of expanding individual logs indefinitely.
4. A generation-5 claim may proceed to its **synthetic local destination** only if independently supplied institutional authorization and other execution prerequisites are satisfied. Matching a lineage generation does **not** grant those permissions.

The accepted source implementation is [`generation_fence.py`](experiments/odex_gax_imx_reference/generation_fence.py), with [source-owned negative tests](tests/test_generation_fence.py). The [O6-Q4 orchestration qualification](https://github.com/cogno-us/cognous-stack-orchestrator/blob/main/development/acceptance/o6-q4/README.md) exercises it alongside actual pinned synthetic Control Plane and Runtime interfaces, but does not establish distributed atomicity or production settlement. A stale message receipt cannot authorize a replacement refund, and a timeout or observed absence never makes a blind retry safe.

## Documentation index

Profiles and interfaces:

- [docs/gax-runtime-artifact-interface.md](docs/gax-runtime-artifact-interface.md): supported runtime boundary and retained-artifact interface.
- [experiments/odex_gax_imx_reference/README.md](experiments/odex_gax_imx_reference/README.md), [profile.md](experiments/odex_gax_imx_reference/profile.md) and [mapping.md](experiments/odex_gax_imx_reference/mapping.md): exchange profile, field mapping and loss register.
- [experiments/governed_message_transport/profile.md](experiments/governed_message_transport/profile.md) and [mapping.md](experiments/governed_message_transport/mapping.md): transport profile and handoff mapping.
- [docs/generation-fence.md](docs/generation-fence.md): optional lineage-generation fence.
- [docs/typed-refusal-profile.md](docs/typed-refusal-profile.md): typed refusal provenance candidate.
- [docs/merged-consumer-chain.md](docs/merged-consumer-chain.md): merged-producers profile, exact revisions and limits.
- [docs/security-runtime-profile-20261016.md](docs/security-runtime-profile-20261016.md) and [docs/security-runtime-f5b-profile-20261016.md](docs/security-runtime-f5b-profile-20261016.md): repaired runtime compatibility profiles.

Checkpoints and history (each keeps the status and scope of the work it recorded):

- [docs/workstreams/gax-control-plane-store-adoption-checkpoint.md](docs/workstreams/gax-control-plane-store-adoption-checkpoint.md)
- [docs/workstreams/gax-producer-v2-checkpoint.md](docs/workstreams/gax-producer-v2-checkpoint.md)
- [docs/workstreams/recovery-export-separation-checkpoint.md](docs/workstreams/recovery-export-separation-checkpoint.md)
- [docs/workstreams/gax-observation-repair-results.json](docs/workstreams/gax-observation-repair-results.json): retained results.
- [CHANGELOG.md](CHANGELOG.md), [CROSS_COMPONENT_TESTS.md](CROSS_COMPONENT_TESTS.md)

Overviews: the [business overview](collateral/business-collateral.md) and [one-page overview](collateral/one-page-overview.md) describe this component's role and evidence limits, not additional runtime features. Hub pages: [stack map](https://github.com/cogno-us/cognous-open-control-stack/blob/main/docs/stack-map.md), [profiles and tools](https://github.com/cogno-us/cognous-open-control-stack/blob/main/docs/profiles-and-tools.md), [documentation index](https://github.com/cogno-us/cognous-open-control-stack/blob/main/docs/README.md).

## Compatibility and selection

The [current hub component lock](https://github.com/cogno-us/cognous-open-control-stack/blob/main/component-lock.json) defines the selected revision (`gax_imx_transport`); optional generation-fence source is not automatically selected or enabled by the hub. Interfaces: bounded refund exchange 0.1.0, retained artifacts 1.1.0 and recipient result 1.0.0. The public runtime uses supported executor interfaces, not upstream test helpers. Authority Context comes from [the separate Institutional Governance repository](https://github.com/cogno-us/cognous-institutional-governance). <!-- pin-round: refresh when the lock pin for gax_imx_transport moves; main is ahead of the pin -->

Test results, run commentary and historical qualification records are in the [central test hub](https://github.com/cogno-us/cognous-stack-qualification/blob/main/results/readme-commentary/index.md). Read them against their recorded source revisions; source selection and deployment approval are separate decisions.

## Limits

- **Known limit:** this is a bounded refund profile, not full GAX conformance, a production network or institutional authentication.
- **Known limit:** current recovery can be denied while historical applied evidence remains true. A crashed holder leaves its processing lease in place until an operator releases it, so a redelivery is held rather than dispatched twice.
- **Known limit:** the first successor packet for a conversation has no stored head to check against; later packets are checked against the stored head. Loading a successor never creates an effect or grants authority.
- **Known limit:** the fence is a same-store serialization property, not distributed destination atomicity or protection against a writer that bypasses the exchange store.
- **Known limit:** deferred Alvorada PR #2 is excluded from the hub; no pending branch supplies supported behavior.
- Review original artifacts and their exact source revisions before extending a claim to a new environment. New dependencies, authority sources, destinations or enforcement mechanisms need their own compatibility and qualification. A passing reference case is not a certification of an enterprise deployment. Shared stack-level claims are in the hub [guarantees and limits](https://github.com/cogno-us/cognous-open-control-stack/blob/main/docs/guarantees-and-limits.md).

## Contributing and attribution

Propose focused changes through repository issues and pull requests. Keep evidence-linked claims, preserve historical records and separate proposed features from accepted implementation.

See [LICENSE](LICENSE) and [attribution](NOTICE) for the existing terms and third-party scope. Developed by [Cognous](https://cogno.us); no licensing change is part of this documentation update.

---

## Bibliography

Selected external sources from the October 2026 research review. These inform evaluation questions; they do not establish Cognous implementation, adoption, conformance or production qualification.

- [Alexander Barrett. *Boundary Blindness Under Artificial Intelligence: Early Cross-Industry Findings on the Missing Decision-Evidence Layer* (2026)](https://papers.ssrn.com/sol3/papers.cfm?abstract_id=7210798). Working paper on carrying the basis for reliance across organizational boundaries; proposed architecture, not a validated interoperability guarantee.
- Jonathan Chadbourne / JCEE Labs. *When a Timeout Is Not a Failure: Authority, Evidence, and Recovery in Consequential AI Execution*. Technical Note 001, public release v0.1.1 (6 October 2026). Technical note on uncertain outcomes and recovery. An original public URL has not been verified; no substitute or private copy is linked.
- [OWASP GenAI Security Project. *State of Agentic AI Security and Governance*, version 2.01 (June 2026)](https://genai.owasp.org/resource/state-of-agentic-ai-security-and-governance/). Security synthesis covering agent identity, delegated permissions, tool access and containment.

See the [research bibliography](https://github.com/cogno-us/cognous-open-control-stack/blob/main/docs/research-bibliography.md) for review scope and source-verification limits.

## Cognous stack components

The Open Control Stack organizes component responsibilities into five groups, one cross-cutting component and two side groups. The groups are a navigation map, not an execution sequence or a requirement to install every component. The [hub component lock](https://github.com/cogno-us/cognous-open-control-stack/blob/main/component-lock.json) defines the selected integration; [release status](https://github.com/cogno-us/cognous-open-control-stack/blob/main/docs/release-status.md) defines its evidence and limits. The [stack map](https://github.com/cogno-us/cognous-open-control-stack/blob/main/docs/stack-map.md) carries the full table with status labels (merged, selected, known limit, proposed); [naming](https://github.com/cogno-us/cognous-open-control-stack/blob/main/docs/naming.md) lists display names, packages and former names.

<!-- stack-map-block: last checked against component-lock.json at hub commit dcc9bd7533ef; refresh at the pin round -->
Last checked against the hub component lock at hub commit `dcc9bd7533ef`.

| Group | Components |
| --- | --- |
| **01 Knowledge & Provenance** | [Evidence Registry (The Index)](https://github.com/cogno-us/cognous-evidence-registry) · [Evidence Attestation (BitRep)](https://github.com/cogno-us/cognous-evidence-attestation) |
| **02 Institutional Governance** | [Institutional Governance (Alvorada)](https://github.com/cogno-us/cognous-institutional-governance) |
| **03 Declaration & Policy Control** | [Action Manifest](https://github.com/cogno-us/cognous-action-manifest) · [Control Plane](https://github.com/cogno-us/cognous-control-plane) |
| **04 Constrained Execution** | [Execution Runtime](https://github.com/cogno-us/cognous-execution-runtime) |
| **05 Replay & Evidence** | [Replay Bundle](https://github.com/cogno-us/cognous-replay-bundle) · [Governance Evidence Pack](https://github.com/cogno-us/cognous-governance-evidence-pack) · [ODES](https://github.com/cogno-us/open-decision-evidence-standard) |
| **Cross-cutting exchange** | [Governed Exchange (GAX/IMX)](https://github.com/cogno-us/cognous-governed-exchange) |
| **Optional reasoning protocols** (side group) | [PRP](https://github.com/cogno-us/portable-reasoning-protocol) · [Research Intelligence Protocol](https://github.com/cogno-us/research-intelligence-protocol) · [TFA Protocol](https://github.com/cogno-us/truth-freedom-agency-protocol) |
| **Tooling and qualification** (side group) | [Ergonomics (`cognous-ocs`)](https://github.com/cogno-us/cognous-open-control-stack-ergonomics) · [Verifier](https://github.com/cogno-us/cognous-open-control-stack-verifier) · [Orchestrator](https://github.com/cogno-us/cognous-stack-orchestrator) · [Qualification](https://github.com/cogno-us/cognous-stack-qualification) |

The hub itself is [cognous-open-control-stack](https://github.com/cogno-us/cognous-open-control-stack). Governed Exchange is separate from Institutional Governance's authority framework. The optional reasoning protocols are behavioral instructions: they do not enforce authorization or substitute for human oversight. A signature, registry entry, message receipt or evidence summary does not grant execution authority.

## Repository locations

See the [repository rename map and compatibility notes](https://github.com/cogno-us/cognous-open-control-stack/blob/main/docs/repository-renames.md) for current component URLs. Existing package names, schema identifiers and retained producer identities are unchanged.

## Merged producer and consumer compatibility

An explicit `merged-producers-v1` profile selects the accepted newer Control Plane, execution runtime, Replay, Evidence Pack and ODES revisions. The historical profile remains the default. See [exact revisions, qualification and limits](docs/merged-consumer-chain.md). This profile does not enable atomic-claim or refund-intent execution.

## Cross component qualification

Executable integration suites and harnesses moved to the [qualification repository](https://github.com/cogno-us/cognous-stack-qualification/tree/39f038435afdd71ba162860faa5718d90d7bde64/suites/cognous-governed-exchange). See [the path migration map](CROSS_COMPONENT_TESTS.md) for current commands and source identity rules. Component-local tests remain here; historical qualification results retain their original scope.

<!-- Retained anchors for existing documentation links. -->
<a id="evidence-and-supported-scope"></a>
