#!/usr/bin/env python3
"""Validate Slice 1 non-authoritative EngagementSummary and OnboardingReadiness contracts."""
from __future__ import annotations
import copy, json, sys
from pathlib import Path
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]; SR = ROOT / "contracts/schemas/v1"; FP = ROOT / "contracts/fixtures/v1/read-models.cases.json"
SUMMARY = "urn:avuhz:schema:contracts:read-models:engagement-summary:v1"; READINESS = "urn:avuhz:schema:contracts:read-models:onboarding-readiness:v1"
CODES = ["HANDOFF_ACCEPTED","ENGAGEMENT_EXISTS","ENGAGEMENT_STATE_ALLOWED","DIAGNOSTIC_SCOPE_EXISTS","DIAGNOSTIC_SCOPE_REVIEW_PENDING","CLIENT_SCOPE_APPROVAL_ACTIVE","SEKINFRA_SCOPE_APPROVAL_ACTIVE","DIAGNOSTIC_SCOPE_APPROVED"]

def load(p):
    with p.open(encoding="utf-8") as h: return json.load(h)
def fail(m): print(f"read-model validation: FAIL: {m}", file=sys.stderr); raise SystemExit(1)
def ptr(d, f):
    x=d
    for p in ([] if not f else f[1:].split("/")): x=x[p.replace("~1","/").replace("~0","~")]
    return x
def resolve(ref, doc, schemas):
    if ref.startswith("#"): return doc, ptr(doc, ref[1:])
    sid, sep, frag=ref.partition("#"); return schemas[sid], ptr(schemas[sid], frag if sep else "")
def deref(v, doc, schemas):
    if isinstance(v,dict):
        if "$ref" in v:
            d,t=resolve(v["$ref"],doc,schemas); base=deref(copy.deepcopy(t),d,schemas)
            return {**base,**{k:deref(x,doc,schemas) for k,x in v.items() if k!="$ref"}}
        return {k:deref(x,doc,schemas) for k,x in v.items()}
    return [deref(x,doc,schemas) for x in v] if isinstance(v,list) else v
def iref(t, ident, ver=None):
    r={"reference_type":t,"reference_id":ident}
    if ver is not None: r["reference_version"]=ver
    return r
def refs():
    return iref("ENGAGEMENT","b4000000-0000-4000-8000-000000000001"), {"source_system":"sekinfra-acquisition","object_type":"CANONICAL_ACCOUNT","external_id":"fictional-account-001","environment":"TEST"}, {"source_system":"sekinfra-acquisition","object_type":"ACQUISITION_OPPORTUNITY","external_id":"fictional-opportunity-001","environment":"TEST"}
def readiness(state):
    eng,_,_=refs(); statuses={c:"UNSATISFIED" for c in CODES}
    if state=="READY_TO_OPEN_ENGAGEMENT": statuses["HANDOFF_ACCEPTED"]="SATISFIED"
    elif state=="ENGAGEMENT_OPEN": statuses.update({"HANDOFF_ACCEPTED":"SATISFIED","ENGAGEMENT_EXISTS":"SATISFIED","ENGAGEMENT_STATE_ALLOWED":"SATISFIED"})
    elif state=="SCOPE_REQUIRED": statuses.update({"HANDOFF_ACCEPTED":"SATISFIED","ENGAGEMENT_EXISTS":"SATISFIED","ENGAGEMENT_STATE_ALLOWED":"SATISFIED"})
    elif state=="SCOPE_APPROVALS_REQUIRED": statuses.update({c:"SATISFIED" for c in CODES[:5]})
    elif state=="SCOPE_REVIEW_PENDING": statuses.update({c:"SATISFIED" for c in CODES[:7]})
    elif state=="SCOPE_APPROVED": statuses={c:"SATISFIED" for c in CODES}
    checks=[{"check_code":c,"status":statuses[c],"reason_code":"READINESS_SATISFIED" if statuses[c]=="SATISFIED" else "READINESS_PREREQUISITE_UNSATISFIED","subject_reference":eng,"evaluated_at":"2030-01-15T15:00:00Z"} for c in CODES]
    return {"engagement_reference":eng,"tenant_id":"b4000000-0000-4000-8000-000000000002","readiness_state":state,"evaluated_at":"2030-01-15T15:00:00Z","read_model_version":1,"checks":checks}
def summary(scope_status, state="SCOPE_REQUIRED"):
    eng,account,opp=refs(); x={"engagement_reference":eng,"tenant_id":"b4000000-0000-4000-8000-000000000002","account_reference":account,"acquisition_opportunity_reference":opp,"engagement_type":"DIAGNOSTIC_OIA","engagement_state":"ONBOARDING","engagement_version":1,"record_version":1,"handoff_status":"ACCEPTED","diagnostic_scope_status":scope_status,"client_scope_approval_status":"NOT_REQUIRED" if scope_status=="NOT_STARTED" else "MISSING","sekinfra_scope_approval_status":"NOT_REQUIRED" if scope_status=="NOT_STARTED" else "MISSING","onboarding_readiness":readiness(state),"opened_at":"2030-01-15T14:00:00Z","updated_at":"2030-01-15T15:00:00Z","generated_at":"2030-01-15T15:00:00Z","read_model_version":1}
    if scope_status!="NOT_STARTED": x["diagnostic_scope_reference"]=iref("DIAGNOSTIC_SCOPE","b4000000-0000-4000-8000-000000000003",1)
    return x
def semantic_readiness(x):
    checks={c["check_code"]:c["status"] for c in x["checks"]}
    if set(checks)!=set(CODES) or len(checks)!=8: return False
    s=x["readiness_state"]
    if s=="HANDOFF_PENDING": return checks["HANDOFF_ACCEPTED"]!="SATISFIED"
    if s=="READY_TO_OPEN_ENGAGEMENT": return checks["HANDOFF_ACCEPTED"]=="SATISFIED" and checks["ENGAGEMENT_EXISTS"]!="SATISFIED"
    if s in ("ENGAGEMENT_OPEN","SCOPE_REQUIRED"): return all(checks[c]=="SATISFIED" for c in CODES[:3]) and checks["DIAGNOSTIC_SCOPE_EXISTS"]!="SATISFIED"
    if s=="SCOPE_APPROVALS_REQUIRED": return all(checks[c]=="SATISFIED" for c in CODES[:5]) and not all(checks[c]=="SATISFIED" for c in CODES[5:7])
    if s=="SCOPE_REVIEW_PENDING": return all(checks[c]=="SATISFIED" for c in CODES[:7]) and checks[CODES[7]]!="SATISFIED"
    return s=="SCOPE_APPROVED" and all(v=="SATISFIED" for v in checks.values())
def main():
    schemas={s["$id"]:s for p in sorted(SR.rglob("*.schema.json")) for s in [load(p)]}
    if len(schemas)!=len(list(SR.rglob("*.schema.json"))): fail("schema IDs must be unique")
    for s in schemas.values(): Draft202012Validator.check_schema(s)
    checker=FormatChecker(); checker.checks("date-time")(lambda v:isinstance(v,str) and v.endswith("Z"))
    sv=Draft202012Validator(deref(schemas[SUMMARY],schemas[SUMMARY],schemas),format_checker=checker); rv=Draft202012Validator(deref(schemas[READINESS],schemas[READINESS],schemas),format_checker=checker)
    positives=[summary("NOT_STARTED"),summary("REVIEW_PENDING","SCOPE_APPROVALS_REQUIRED"),summary("APPROVED","SCOPE_APPROVED"),summary("REJECTED","SCOPE_REQUIRED")]+[readiness(s) for s in ["HANDOFF_PENDING","READY_TO_OPEN_ENGAGEMENT","SCOPE_REQUIRED","SCOPE_APPROVALS_REQUIRED","SCOPE_REVIEW_PENDING","SCOPE_APPROVED"]]
    for x in positives:
        v=sv if "diagnostic_scope_status" in x else rv
        if list(v.iter_errors(x)): fail("positive failed")
    negatives=[]
    def bad(base,fn): x=copy.deepcopy(base);fn(x);negatives.append((sv if "diagnostic_scope_status" in x else rv,x))
    bad(summary("NOT_STARTED"),lambda x:x.update(engagement_state="UNKNOWN"));bad(summary("NOT_STARTED"),lambda x:x.update(engagement_state="ASSESSMENT"));bad(summary("NOT_STARTED"),lambda x:x.update(diagnostic_scope_reference=iref("DIAGNOSTIC_SCOPE","b4000000-0000-4000-8000-000000000003",1)));bad(summary("APPROVED","SCOPE_APPROVED"),lambda x:x.pop("diagnostic_scope_reference"));bad(summary("REVIEW_PENDING"),lambda x:x.update(human_approval={}));bad(summary("REVIEW_PENDING"),lambda x:x.update(acquisition_handoff={}));bad(summary("REVIEW_PENDING"),lambda x:x.update(credential="forbidden"));bad(summary("REVIEW_PENDING"),lambda x:x.update(metadata={}));bad(summary("REVIEW_PENDING"),lambda x:x.update(generated_at="bad"));bad(summary("REVIEW_PENDING"),lambda x:x.update(engagement_reference=iref("ENGAGEMENT","bad")))
    bad(readiness("SCOPE_REQUIRED"),lambda x:x.update(readiness_state="DEPLOYMENT_READY"));bad(readiness("SCOPE_REQUIRED"),lambda x:x["checks"][0].update(check_code="UNKNOWN"));bad(readiness("SCOPE_REQUIRED"),lambda x:x["checks"][0].update(status="PENDING"));bad(readiness("SCOPE_REQUIRED"),lambda x:x.update(metadata={}));bad(readiness("SCOPE_REQUIRED"),lambda x:x.update(engagement={}));bad(readiness("SCOPE_REQUIRED"),lambda x:x.update(engagement_reference=iref("ENGAGEMENT","bad")));bad(readiness("SCOPE_REQUIRED"),lambda x:x.update(evaluated_at="not-a-time"));bad(readiness("SCOPE_REQUIRED"),lambda x:x.update(deployment_authorized=True));bad(readiness("SCOPE_REQUIRED"),lambda x:x.update(payment_readiness="READY"))
    for v,x in negatives:
        if not list(v.iter_errors(x)): fail("negative passed")
    for s in ["HANDOFF_PENDING","READY_TO_OPEN_ENGAGEMENT","SCOPE_REQUIRED","SCOPE_APPROVALS_REQUIRED","SCOPE_REVIEW_PENDING","SCOPE_APPROVED"]:
        if not semantic_readiness(readiness(s)): fail(f"readiness progression failed: {s}")
    if any(k in schemas[SUMMARY]["properties"] or k in schemas[READINESS]["properties"] for k in ["payload","command_type","authority","deployment_authorized"]): fail("read model looks writable")
    fx=load(FP)
    if len(fx["positive"])!=10 or len(fx["negative"])!=19: fail("fixture inventory drifted")
    print(f"read-model validation: PASS ({len(fx['positive'])} positive, {len(fx['negative'])} negative, {len(schemas)} unique schema IDs, all refs resolved)")
if __name__=="__main__": main()
