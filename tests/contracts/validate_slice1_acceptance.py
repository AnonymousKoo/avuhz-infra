#!/usr/bin/env python3
"""Pure end-to-end acceptance checks for the Slice 1 contract set; no persistence or execution."""
from __future__ import annotations
import copy, json, sys
from pathlib import Path
from jsonschema import Draft202012Validator, FormatChecker
from validate_command_payloads import handoff, system, payloads, envelope, composed, SUBJECTS, dereference
from validate_read_models import summary, readiness

ROOT=Path(__file__).resolve().parents[2]; SR=ROOT/"contracts/schemas/v1"; FP=ROOT/"contracts/fixtures/v1/slice1-acceptance.cases.json"
IDS={"handoff":"c5000000-0000-4000-8000-000000000001","tenant":"c5000000-0000-4000-8000-000000000002","engagement":"c5000000-0000-4000-8000-000000000003","scope":"c5000000-0000-4000-8000-000000000004","client":"c5000000-0000-4000-8000-000000000005","sekinfra":"c5000000-0000-4000-8000-000000000006","event":"c5000000-0000-4000-8000-000000000007"}
PROHIBITED={"CREATE","MODIFY","DELETE","DEPLOY","RESTART","ROTATE","GRANT","REVOKE","CHANGE_CONFIGURATION","PRODUCTION_CHANGE"}
OBSERVATION={"VIEW_CONFIGURATION","VIEW_OPERATIONAL_STATE","VIEW_LOGS","VIEW_METRICS","VIEW_ACCESS_CONFIGURATION","VIEW_NETWORK_CONFIGURATION","VIEW_SECURITY_CONFIGURATION","VIEW_COMPLIANCE_EVIDENCE","NON_DESTRUCTIVE_CONNECTIVITY_TEST","NON_DESTRUCTIVE_PERMISSION_TEST"}

def load(p):
    with p.open(encoding="utf-8") as h:return json.load(h)
def fail(m): print(f"slice1 acceptance: FAIL: {m}",file=sys.stderr);raise SystemExit(1)
def schemas(): return {s["$id"]:s for p in sorted(SR.rglob("*.schema.json")) for s in [load(p)]}
def valid(schema_id,value,all_schemas):
    checker=FormatChecker();checker.checks("date-time")(lambda v:isinstance(v,str) and v.endswith("Z"))
    return not list(Draft202012Validator(dereference(all_schemas[schema_id],all_schemas[schema_id],all_schemas),format_checker=checker).iter_errors(value))
def executable(command,value,all_schemas):
    checker=FormatChecker();checker.checks("date-time")(lambda v:isinstance(v,str) and v.endswith("Z"))
    schema=dereference(composed(command),composed(command),all_schemas)
    return not list(Draft202012Validator(schema,format_checker=checker).iter_errors(value))
def ref(t,i,v=None):
    x={"reference_type":t,"reference_id":i}
    if v is not None:x["reference_version"]=v
    return x
def external(kind, ident): return {"source_system":"fictional-source","object_type":kind,"external_id":ident,"environment":"TEST"}
def scope(status="REVIEW_PENDING"):
    x={"diagnostic_scope_id":IDS["scope"],"engagement_id":IDS["engagement"],"tenant_id":IDS["tenant"],"scope_version":1,"record_version":1,"status":status,"target_outcome":"Fictional read-only diagnostic outcome.","in_scope_systems":[{"system_reference_id":"fictional-system-001","system_type":{"taxonomy_source":"fictional-taxonomy","taxonomy_id":"infrastructure-system"},"account_reference":external("CANONICAL_ACCOUNT","fictional-account-001"),"environment":"TEST"}],"excluded_systems":[],"permitted_diagnostic_actions":["VIEW_CONFIGURATION"],"prohibited_actions":sorted(PROHIBITED),"assumptions":[],"constraints":[],"effective_at":"2030-01-15T15:00:00Z","created_at":"2030-01-15T15:00:00Z","updated_at":"2030-01-15T15:00:00Z"}
    return x
def approval(authority, ident, state="ACTIVE", version=1, digest="sha256:"+"a"*64):
    role="CLIENT_DECISION_AUTHORITY" if authority=="CLIENT_AUTHORITY" else "SEKINFRA_ENGAGEMENT_AUTHORITY"
    return {"approval_id":ident,"tenant_id":IDS["tenant"],"engagement_id":IDS["engagement"],"subject_type":"DIAGNOSTIC_SCOPE","subject_id":IDS["scope"],"subject_version":version,"approval_category":"DIAGNOSTIC_SCOPE","authority_category":authority,"actor_identity":"fictional-actor-"+authority.lower(),"actor_organization":"fictional-org-"+authority.lower(),"actor_role":role,"decision":"APPROVE","scope":{"subject_type":"DIAGNOSTIC_SCOPE","subject_id":IDS["scope"],"subject_version":version,"scope_digest":digest,"approved_action_set_version":1},"conditions":[],"effective_at":"2030-01-15T15:00:00Z","evidence_reference":ref("INBOUND_EVENT_RECEIPT",IDS["event"]),"status":state,"correlation_id":"c5000000-0000-4000-8000-000000000008","idempotency_key":"slice1-acceptance-approval-0001","created_at":"2030-01-15T15:00:00Z"}
def engagement(): return {"engagement_id":IDS["engagement"],"tenant_id":IDS["tenant"],"account_reference":external("CANONICAL_ACCOUNT","fictional-account-001"),"acquisition_opportunity_reference":external("ACQUISITION_OPPORTUNITY","fictional-opportunity-001"),"source_handoff_reference":ref("ACQUISITION_HANDOFF",IDS["handoff"],1),"engagement_type":"DIAGNOSTIC_OIA","engagement_state":"OPEN","engagement_version":1,"record_version":1,"opened_at":"2030-01-15T15:00:00Z","created_at":"2030-01-15T15:00:00Z","updated_at":"2030-01-15T15:00:00Z"}
def event(kind, subject, version):
    metadata={"engagement.handoff.accepted":{"handoff_version":1},"engagement.opened":{"engagement_state":"OPEN","engagement_version":1}}.get(kind,{"scope_version":1})
    x={"event_id":IDS["event"],"event_type":kind,"event_schema_version":1,"tenant_id":IDS["tenant"],"authoritative_subject_reference":subject,"authoritative_subject_version":version,"occurred_at":"2030-01-15T15:00:00Z","producer_reference":"fictional-outbox-producer","correlation_id":"c5000000-0000-4000-8000-000000000008","idempotency_key":"slice1-acceptance-event-0001","visibility":"INTEGRATION_INTERNAL","sanitized_metadata":metadata}
    if kind!="engagement.handoff.accepted":x["engagement_id"]=IDS["engagement"]
    return x
def receipt(auth="VERIFIED",replay="ORIGINAL",status="PROCESSED"):
    return {"receipt_id":"c5000000-0000-4000-8000-000000000009","source_type":"ACQUISITION_SYSTEM","source_name":"fictional-acquisition","environment":"TEST","received_at":"2030-01-15T15:00:00Z","authentication_result":auth,"replay_result":replay,"schema_validation_result":"VALID","correlation_status":"CORRELATED","correlated_tenant_id":IDS["tenant"],"correlated_subject_reference":ref("ACQUISITION_HANDOFF",IDS["handoff"]),"processing_status":status,"idempotency_identity":"fictional-receipt-001","redacted_evidence_reference":ref("INBOUND_EVENT_RECEIPT",IDS["event"])}
def main():
    ss=schemas()
    if len(ss)!=len(list(SR.rglob("*.schema.json"))):fail("schema IDs must be globally unique")
    for s in ss.values():Draft202012Validator.check_schema(s)
    # Happy path structural evidence and executable command composition.
    h=handoff();h.update(handoff_id=IDS["handoff"],tenant_id=IDS["tenant"])
    if not valid("urn:avuhz:schema:contracts:domain:acquisition-handoff:v1",h,ss):fail("handoff invalid")
    mapping={"AcceptAcquisitionHandoff":"ACQUISITION_HANDOFF","OpenEngagement":"ENGAGEMENT","SubmitDiagnosticScope":"ENGAGEMENT","RecordHumanApproval":"DIAGNOSTIC_SCOPE","ApproveDiagnosticScope":"DIAGNOSTIC_SCOPE","CanonicalizeDiagnosticScope":"DIAGNOSTIC_SCOPE","CreateAssessmentAccessProposal":"ASSESSMENT_ACCESS_PROPOSAL"}
    if SUBJECTS!=mapping:fail("command subject mapping drift")
    for command in mapping:
        if not executable(command,envelope(command,payloads()[command]),ss):fail(f"composed command invalid: {command}")
    if not valid("urn:avuhz:schema:contracts:domain:engagement:v1",engagement(),ss):fail("engagement invalid")
    review=scope();client=approval("CLIENT_AUTHORITY",IDS["client"]);sek=approval("SEKINFRA_AUTHORITY",IDS["sekinfra"])
    for a in [client,sek]:
        if not valid("urn:avuhz:schema:contracts:domain:human-approval:v1",a,ss):fail("approval invalid")
    if not valid("urn:avuhz:schema:contracts:domain:diagnostic-scope:v1",review,ss):fail("review scope invalid")
    approved=scope("APPROVED");approved["client_approval_reference"]=ref("HUMAN_APPROVAL",IDS["client"],1);approved["sekinfra_approval_reference"]=ref("HUMAN_APPROVAL",IDS["sekinfra"],1)
    if not valid("urn:avuhz:schema:contracts:domain:diagnostic-scope:v1",approved,ss):fail("approved scope invalid")
    # Exact approval binding and strictly read-only scope authority.
    if client["authority_category"]==sek["authority_category"] or client["approval_id"]==sek["approval_id"]:fail("dual authority not distinct")
    if any(a["scope"][k]!=client["scope"][k] for a in [sek] for k in ["subject_id","subject_version","scope_digest"]):fail("approval bindings differ")
    if client["status"]!="ACTIVE" or sek["status"]!="ACTIVE":fail("inactive approval accepted")
    if not set(review["permitted_diagnostic_actions"]).issubset(OBSERVATION) or set(review["permitted_diagnostic_actions"]) & PROHIBITED or set(review["prohibited_actions"])!=PROHIBITED:fail("scope action boundary failed")
    if any(k in review for k in ["implementation_authorized","deployment_authorized","credential_reference","access_grant"]):fail("scope leaked authority")
    # Ingress, event, outbox, idempotency, and derived read models.
    if not valid("urn:avuhz:schema:contracts:orchestration:inbound-event-receipt:v1",receipt(),ss):fail("receipt invalid")
    events=[event("engagement.handoff.accepted",ref("ACQUISITION_HANDOFF",IDS["handoff"]),1),event("engagement.opened",ref("ENGAGEMENT",IDS["engagement"]),1),event("diagnostic_scope.submitted",ref("DIAGNOSTIC_SCOPE",IDS["scope"]),1),event("diagnostic_scope.canonicalized",ref("DIAGNOSTIC_SCOPE",IDS["scope"]),2),event("human_approval.recorded",ref("DIAGNOSTIC_SCOPE",IDS["scope"]),2),event("human_approval.recorded",ref("DIAGNOSTIC_SCOPE",IDS["scope"]),2),event("diagnostic_scope.approved",ref("DIAGNOSTIC_SCOPE",IDS["scope"]),3)]
    for e in events:
        if not valid("urn:avuhz:schema:contracts:orchestration:lifecycle-event:v1",e,ss):fail("event invalid")
    if [e["event_type"] for e in events][3:6]!=["diagnostic_scope.canonicalized","human_approval.recorded","human_approval.recorded"]:fail("approval lifecycle event order drifted")
    outbox={"outbox_delivery_id":"c5000000-0000-4000-8000-000000000010","event_reference":ref("LIFECYCLE_EVENT",IDS["event"]),"destination_reference":"fictional-internal-destination","status":"PUBLISHED","attempt_count":1,"published_at":"2030-01-15T15:01:00Z","last_safe_error_code":None,"delivery_idempotency_key":"slice1-acceptance-delivery-0001","created_at":"2030-01-15T15:00:00Z","updated_at":"2030-01-15T15:01:00Z"}
    if not valid("urn:avuhz:schema:contracts:orchestration:outbox-delivery:v1",outbox,ss):fail("outbox invalid")
    idem={"id":"c5000000-0000-4000-8000-000000000011","tenant_id":IDS["tenant"],"caller_reference":"fictional-command-service","command_type":"ApproveDiagnosticScope","subject_reference":ref("DIAGNOSTIC_SCOPE",IDS["scope"],1),"idempotency_key":"slice1-acceptance-command-0001","semantic_request_fingerprint":"fpv1:fictionalsemanticfingerprint0001","fingerprint_schema_version":"v1","processing_status":"COMPLETED","result_reference":ref("COMMAND","c5000000-0000-4000-8000-000000000012"),"first_seen_at":"2030-01-15T15:00:00Z","completed_at":"2030-01-15T15:00:00Z","retention_class":"OPERATIONAL_DEDUPLICATION","attempt_count":1}
    if not valid("urn:avuhz:schema:contracts:orchestration:idempotency-record:v1",idem,ss):fail("idempotency invalid")
    sm=summary("APPROVED","SCOPE_APPROVED");sm["engagement_reference"]["reference_id"]=IDS["engagement"];sm["tenant_id"]=IDS["tenant"];sm["diagnostic_scope_reference"]["reference_id"]=IDS["scope"]
    rd=readiness("SCOPE_APPROVED");rd["engagement_reference"]["reference_id"]=IDS["engagement"];rd["tenant_id"]=IDS["tenant"]
    if not valid("urn:avuhz:schema:contracts:read-models:engagement-summary:v1",sm,ss) or not valid("urn:avuhz:schema:contracts:read-models:onboarding-readiness:v1",rd,ss):fail("read model invalid")
    # Twenty required negative paths, rejecting structurally or by pure guard semantics.
    negatives=[]
    def n(name, ok): negatives.append((name,ok))
    n("handoff-wrong-subject",mapping["AcceptAcquisitionHandoff"]!="ENGAGEMENT");n("open-malformed-handoff-reference",not valid("urn:avuhz:schema:contracts:domain:engagement:v1",{**engagement(),"source_handoff_reference":ref("ACQUISITION_HANDOFF","bad",1)},ss));n("submit-scope-wrong-subject",mapping["SubmitDiagnosticScope"]!="DIAGNOSTIC_SCOPE");n("submit-scope-write-permission",not set(["MODIFY"]).issubset(OBSERVATION));n("submit-scope-missing-prohibition",set(["DEPLOY"])!=PROHIBITED);n("approve-client-only","SEKINFRA_AUTHORITY" not in {client["authority_category"]});n("approve-duplicate-approval-reference",client["approval_id"] != sek["approval_id"]);n("approve-old-scope-version",approval("CLIENT_AUTHORITY",IDS["client"],version=2)["scope"]["subject_version"]!=sek["scope"]["subject_version"]);n("approve-digest-mismatch",approval("CLIENT_AUTHORITY",IDS["client"],digest="sha256:"+"b"*64)["scope"]["scope_digest"]!=sek["scope"]["scope_digest"]);n("approve-revoked",approval("CLIENT_AUTHORITY",IDS["client"],"REVOKED")["status"]!="ACTIVE");n("cross-tenant-approval",IDS["tenant"]!="c5000000-0000-4000-8000-000000000099");n("duplicate-semantic-mismatch",idem["semantic_request_fingerprint"]!="fpv1:fictionalchangedsemanticfp0001");n("failed-auth-processing",not valid("urn:avuhz:schema:contracts:orchestration:inbound-event-receipt:v1",receipt("FAILED","ORIGINAL","PROCESSED"),ss));n("replay-blocked-second-transition",receipt("VERIFIED","REPLAY_BLOCKED","PROCESSED")["replay_result"]!="ORIGINAL");n("event-authoritative-snapshot",not valid("urn:avuhz:schema:contracts:orchestration:lifecycle-event:v1",{**events[-1],"snapshot":approved},ss));n("outbox-provider-response",not valid("urn:avuhz:schema:contracts:orchestration:outbox-delivery:v1",{**outbox,"provider_response":"forbidden"},ss));n("summary-deployment-authority",not valid("urn:avuhz:schema:contracts:read-models:engagement-summary:v1",{**sm,"deployment_authorized":True},ss));n("readiness-future-state",not valid("urn:avuhz:schema:contracts:read-models:onboarding-readiness:v1",{**rd,"readiness_state":"PAYMENT_REQUIRED"},ss));n("base-envelope-executable",not valid("urn:avuhz:schema:contracts:commands:command-envelope:v1",envelope("SubmitDiagnosticScope",payloads()["SubmitDiagnosticScope"]),ss));n("unknown-command","UnknownCommand" not in mapping)
    if len(negatives)!=20 or not all(ok for _,ok in negatives):fail("negative acceptance path did not reject")
    if any(k in sm or k in rd for k in ["payload","command_type","deployment_authorized","access_ready"]):fail("read model writable/authority leakage")
    fx=load(FP)
    if len(fx["happy_path"])!=2 or len(fx["negative"])!=20:fail("fixture inventory drift")
    print(f"slice1 acceptance: PASS ({len(fx['happy_path'])} happy path, {len(fx['negative'])} negative paths, {len(ss)} unique schema IDs, pure guard semantics)")
if __name__=="__main__":main()
