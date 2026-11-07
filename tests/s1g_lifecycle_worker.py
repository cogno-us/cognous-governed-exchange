"""S1G subprocess worker (DEVELOPMENT ONLY, SYNTHETIC / NONPRODUCTION, UNQUALIFIED). Run by tests/test_odes_lifecycle_reliance.py, one fresh
process per scenario, under an explicit GAX runtime compatibility profile and stack root. Real pinned Control Plane -> Replay -> ODES
exporter -> native ODES evaluator -> GAX consume_odes_reliance. No evaluator result is mocked. Writes only to the OUT directory.

The expected package digests are NEVER computed here for consumption: they are read from the anchor file written by the separate
``record_anchor`` (recipient-preparation) step, which sees only the producer's digests.json, never a package. Order: produce -> record_anchor -> consumption.
"""
import base64, copy, datetime, hashlib, json, os, sys
from pathlib import Path

STACK = Path(os.environ["STACK"])
for p in (STACK / "replay/src", STACK / "odes/src", STACK / "evidence_pack/src", os.environ["EXCHANGE"]):
    sys.path.insert(0, str(p))
from experiments.odex_gax_imx_reference import gax_ref_runtime as rt  # noqa: E402

rt.load_executor_runtime()
odes = rt.pinned_module("odes")
from odes import signatures  # noqa: E402
from odes.canonicalization import digest_for  # noqa: E402
from odes.recipient_validator import _material_package_content, _package_core  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

DATA = Path(os.environ["DATA"])                # committed: public key only
FIX = Path(os.environ["FIXDIR"])               # CP fixtures inside the pinned ODES draft checkout
OUT = Path(os.environ["OUT"])
PROD = Path(os.environ["PROD"])                # producer outputs (untrusted inputs to consumption)
RECIP = Path(os.environ["RECIP"])              # recipient-prepared anchor
NOW, EVALUATED_AT = "2026-10-06T00:00:00Z", "2026-10-05T23:59:00Z"
JURISDICTION = "SYNTHETIC-JURISDICTION-NONPRODUCTION"
LIFECYCLE_ID = "odes_cognous_stack_export_0_2_restrictions_lifecycle_0_1"
KEYID = "synthetic-issuer-key-nonproduction"
SEED = bytes(range(32))                         # SYNTHETIC / NONPRODUCTION; the producer's signing key only
KEY = Ed25519PrivateKey.from_private_bytes(SEED)
MANIFEST = rt.bind_manifest(json.loads(Path(os.environ["MANIFEST"]).read_text()))
CP_RUN = json.loads((FIX / "lifecycle_control_plane_run.json").read_text())
PROPOSAL = json.loads((FIX / "lifecycle_proposal.json").read_text())


def live_bundle():
    """A FRESH import through the real pinned Replay. Replay stamps a random bundle_id and a generated_at on every import, so the
    package digest of an export from a fresh import is not reproducible; digests are therefore recorded against the persisted bundle."""
    return rt.reconstruction_dict(rt.import_replay_bundle(CP_RUN, PROPOSAL, None))


def persisted_bundle():
    return json.loads((PROD / "bundle.json").read_text())


def diff_paths(a, b, path=""):
    if isinstance(a, dict) and isinstance(b, dict):
        return [p for k in sorted(set(a) | set(b)) for p in diff_paths(a.get(k), b.get(k), f"{path}/{k}")]
    if isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        return [p for i, (x, y) in enumerate(zip(a, b)) for p in diff_paths(x, y, f"{path}[{i}]")]
    return [] if a == b else [path]


def decided_at(b):
    return next(r for r in b["records"] if r["record_type"] == "runtime_decision")["data"]["decided_at"]


def assertion(b, freshness="current", ref="urn:synthetic:nonproduction:lifecycle-assertion:1"):
    at = datetime.datetime.fromisoformat(decided_at(b).replace("Z", "+00:00")).replace(microsecond=0) + datetime.timedelta(minutes=1)
    return {"freshness": freshness, "asserted_by": {"organization_id": "cognous.synthetic.baseline", "system_id": "cognous-stack-exporter",
                                                    "actor_id": "synthetic-test-actor-nonproduction"},
            "asserted_at": at.isoformat().replace("+00:00", "Z"), "source": {"reference": ref}}


def export(b, mode, lifecycle=None):
    kw = {"restriction_semantics": mode}
    if lifecycle is not None:
        kw["lifecycle_assertion"] = lifecycle
    return odes.export_cognous_stack_package(MANIFEST, b, **kw)


def reseal(pkg):
    canon = pkg["integrity"]["canonicalization_profile"]
    pkg["integrity"]["value"] = digest_for(canon, _package_core(pkg))
    pkg["package_digest"] = digest_for(canon, _material_package_content(pkg))
    return pkg


def anchors():
    return json.loads((RECIP / "anchor.json").read_text())


def recipient_key():
    return json.loads((DATA / "synthetic_issuer_public_key.json").read_text())


def policy_for(pkg, trusted, *, revoked=False):
    rec = pkg["record"]
    return {"now": NOW, "purpose": "audit", "relying_party": "recipient.example.org", "jurisdiction": JURISDICTION,
            "supported_profiles": [pkg["profile"]["implementation_profile"]], "evaluation_scope": "audit", "status_max_age_seconds": 300,
            "trusted_issuer": rec["issuer"], "trusted_digests": [trusted], "trusted_key_refs": [],
            "status_inputs": {"issuer": rec["issuer"], "record_id": rec["decision_id"], "authority_basis": rec["authority"]["authority_basis"],
                              "evaluation_scope": "audit", "authority_valid_at_decision_verified": True, "evaluated_at": EVALUATED_AT,
                              "evidence_freshness": "current", "freshness": "current", "revoked": revoked, "superseded": False},
            "detached_authentication": {"envelope": signatures.sign_package(pkg, KEY, KEYID), "trusted_keys": [recipient_key()]}}


def consume(pkg, expected, *, revoked=False):
    pol = policy_for(pkg, expected, revoked=revoked)
    rec = rt.consume_odes_reliance(pkg, policy=pol, policy_id="synthetic-nonproduction-policy", policy_version="0", expected_package_digest=expected,
                                   expected_relying_party="recipient.example.org", expected_purpose="audit",
                                   expected_profile=pkg["profile"]["implementation_profile"], now=NOW, max_grant_seconds=3600)
    return rec, pol


def statuses(result):
    return {k: v.get("status") for k, v in result.items() if isinstance(v, dict) and "status" in v}


def summary(rec, pol, pkg):
    return {"verdict": rec["verdict"], "reason": rec["reason"], "detail": rec.get("detail"), "grant": rec["grant"],
            "blocking_layers": sorted(rec.get("blocking_layers") or {}), "raw": statuses(odes.evaluate_recipient_package(pkg, pol)),
            "profile": pkg["profile"]["implementation_profile"], "package_digest": pkg["package_digest"]}


def sources():
    s = rt._SOURCES["odes"]
    return {"odes_commit": s.materialized.commit, "odes_revision_constant": rt.ODES_REVISION, "gax_profile": rt.RUNTIME_COMPATIBILITY_PROFILE,
            "cp": rt.CP_REVISION, "replay": rt.REPLAY_REVISION, "manifest": rt.MANIFEST_REVISION, "moltbot": rt.MOLTBOT_REVISION,
            "manifest_digest": rt.authenticated_manifest().digest}


scenario = os.environ["SCENARIO"]
out = {"scenario": scenario, "sources": sources()}
if scenario in ("produce", "record_anchor"):
    b, A = None, {}
else:
    b = persisted_bundle()
    A = anchors()["expected_package_digests"] if scenario not in ("t5",) else {}


def load_pkg(name):
    return json.loads((PROD / name).read_text())


if scenario == "produce":
    b = live_bundle()
    (PROD / "bundle.json").write_text(json.dumps(b, indent=1, sort_keys=True) + "\n")
    b = persisted_bundle()          # every export is made from the persisted bytes
    pk = export(b, "explicit", assertion(b))
    st = export(b, "explicit", assertion(b, "stale"))
    rw = export(b, "explicit", assertion(b, ref="urn:synthetic:nonproduction:lifecycle-assertion:2"))
    for name, pkg in (("package_current.json", pk), ("package_stale.json", st), ("package_rewritten.json", rw)):
        (PROD / name).write_text(json.dumps(pkg))
    (PROD / "digests.json").write_text(json.dumps({"current": pk["package_digest"], "stale": st["package_digest"]}))
    out.update(decided_at=decided_at(b), asserted_at=assertion(b)["asserted_at"], profile=pk["profile"]["implementation_profile"])
elif scenario == "record_anchor":
    # Recipient preparation: sees ONLY digests.json (no package), records the anchor before any consumption.
    d = json.loads((PROD / "digests.json").read_text())
    (RECIP / "anchor.json").write_text(json.dumps({"expected_package_digests": d, "source": "digests.json recorded by the producer step; read before consumption",
                                                    "digests_json_sha256": hashlib.sha256((PROD / "digests.json").read_bytes()).hexdigest()}))
    out["recorded"] = sorted(d)
elif scenario == "t1":
    pkg = load_pkg("package_current.json")
    raw = odes.evaluate_recipient_package(pkg, policy_for(pkg, A["current"]))
    rec, pol = consume(pkg, A["current"])
    out.update(summary(rec, pol, pkg), layers=statuses(raw), final=raw["recipient_reliance_decision"]["status"], risk=pkg["record"]["risk_coordinates"],
               record_status=pkg["record"]["status"], has_lifecycle=("lifecycle_semantics" in pkg["provenance"]),
               pinned=pkg["provenance"]["pinned_revisions"], manifest_digest_pkg=pkg["provenance"]["source_artifacts"]["manifest_digest"],
               n_records=len(b["records"]), live_vs_persisted_bundle_diff=diff_paths(live_bundle(), b),
               risk_in_bundle=next(r for r in b["records"] if r["record_type"] == "runtime_proposal")["data"]["risk_metadata"],
               grant_keys=sorted(rec["grant"] or {}), rec_keys=sorted(rec))
elif scenario == "t2":
    variants = {}
    rw = load_pkg("package_rewritten.json")
    ed = load_pkg("package_current.json")
    ed["provenance"]["lifecycle_semantics"]["source"]["reference"] = "urn:synthetic:nonproduction:lifecycle-assertion:2"
    reseal(ed)
    for name, pkg in (("reexport_rewrite", rw), ("inplace_edit_resealed", ed)):
        rec, pol = consume(pkg, A["current"])
        variants[name] = dict(summary(rec, pol, pkg), differs=pkg["package_digest"] != A["current"])
    out["variants"] = variants
elif scenario == "t3":
    pkg = load_pkg("package_current.json")
    rec, pol = consume(pkg, A["current"], revoked=True)
    out.update(summary(rec, pol, pkg))
elif scenario == "t4":
    pkg = load_pkg("package_stale.json")
    rec, pol = consume(pkg, A["stale"])
    out.update(summary(rec, pol, pkg), record_status=pkg["record"]["status"], recipient_status=pol["status_inputs"])
elif scenario == "t5":
    # Engine-behaviour comparison across ODES revisions: each legacy/explicit package is consumed against its OWN digest (NOT an anchoring test).
    res = {}
    for mode in ("legacy", "explicit"):
        pkg = export(b, mode)
        rec, pol = consume(pkg, pkg["package_digest"])
        res[mode] = dict(summary(rec, pol, pkg), pinned=pkg["provenance"]["pinned_revisions"],
                         manifest_digest_pkg=pkg["provenance"]["source_artifacts"]["manifest_digest"],
                         has_lifecycle=("lifecycle_semantics" in pkg["provenance"]), version=pkg["profile"]["implementation_profile_version"])
    out["modes"] = res
elif scenario == "t6":
    pkg = load_pkg("package_current.json")
    rec, pol = consume(pkg, A["current"])
    out.update(summary(rec, pol, pkg))
print("RESULT" + json.dumps(out, default=str))
