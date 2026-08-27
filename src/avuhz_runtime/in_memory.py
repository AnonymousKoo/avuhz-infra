"""Development-only in-memory repositories and atomic Slice 1 executor; never production persistence."""
from __future__ import annotations
import copy, hashlib, json, uuid
from dataclasses import dataclass, field
from .guards import AuthoritativeSubjectSnapshot
from .models import ValidationFailure
from .canonical_scope import compute_canonical_scope_digest
from .assessment_access_proposal import CreateAssessmentAccessProposalHandler
from .issue_assessment_access_grant import IssueAssessmentAccessGrantHandler
from .assessment_access_approval import RecordAssessmentAccessApprovalHandler
from .verify_assessment_access import VerifyAssessmentAccessHandler
from .assessment_access_verification import InMemoryAssessmentAccessVerifier
from .assessment_access_terminal import AssessmentAccessTerminalHandler
from .commercial_ingress import DiagnosticCommercialIngressHandler
from .oia_assessment import OpenOIAAssessmentHandler
from .oia_evidence import RecordOIAEvidenceHandler
from .oia_assessment_plan import OIAAssessmentPlanHandler, TrustedMethodologyCatalog
from .oia_inspection_item import OIAInspectionItemHandler, derive_assessment_coverage
from .oia_observation import OIAObservationHandler
from .oia_root_cause import OIARootCauseHandler
from .oia_finding import OIAFindingHandler

class CanonicalScopeDigestConflict(ValueError): pass
from .runtime import prepare_and_guard_command

COMMAND_SCOPED_IDEMPOTENCY_COMMANDS=frozenset(("CreateAssessmentAccessProposal","RecordAssessmentAccessApproval","IssueAssessmentAccessGrant","VerifyAssessmentAccess","ExpireAssessmentAccess","RevokeAssessmentAccess","CloseAssessmentAccessForAgreementEnd","RecordDiagnosticAgreementAuthority","RecordDiagnosticPaymentVerification","InvalidateDiagnosticPaymentVerification","OpenOIAAssessment","RecordOIAEvidence","RecordOIAObservation","SupersedeOIAObservation","RecordOIARootCause","CreateOIAFinding","UpdateOIAFindingAnalysis","FinalizeOIAFinding","CreateOIAAssessmentPlan","ReviseOIAAssessmentPlan","ReviewOIAAssessmentPlan","ApproveOIAAssessmentPlan","CreateOIAInspectionItem","UpdateOIAInspectionItem","MarkOIAInspectionItemBlocked"))
def idempotency_scope(command): return "COMMAND" if command.command_type in COMMAND_SCOPED_IDEMPOTENCY_COMMANDS else "SUBJECT:"+command.subject_id

def fingerprint(command):
    value={k:command[k] for k in ("tenant_id","command_type","subject_type","subject_id","engagement_id","expected_record_version","payload") if k in command}
    if command.get("command_type")=="CreateAssessmentAccessProposal":
        payload=copy.deepcopy(value["payload"])
        payload["target_system_references"]=sorted(payload["target_system_references"],key=lambda item:item["system_reference_id"])
        payload["permitted_actions"]=sorted(payload["permitted_actions"])
        value["payload"]=payload
    if command.get("command_type")=="RecordAssessmentAccessApproval":
        value={"command_type":command["command_type"],"payload":{"assessment_access_proposal_id":command["payload"]["assessment_access_proposal_id"],"authority_role":command["payload"]["authority_role"]}}
    if command.get("command_type")=="IssueAssessmentAccessGrant":
        value={"command_type":command["command_type"],"payload":{"assessment_access_grant_id":command["payload"]["assessment_access_grant_id"],"assessment_access_proposal_id":command["payload"]["assessment_access_proposal_id"]}}
    if command.get("command_type")=="VerifyAssessmentAccess":
        value={"command_type":command["command_type"],"payload":{"assessment_access_grant_id":command["payload"]["assessment_access_grant_id"]}}
    if command.get("command_type") in ("ExpireAssessmentAccess","RevokeAssessmentAccess","CloseAssessmentAccessForAgreementEnd"):
        value={"command_type":command["command_type"],"payload":{"assessment_access_grant_id":command["payload"]["assessment_access_grant_id"]}}
    if command.get("command_type") in ("RecordDiagnosticAgreementAuthority","RecordDiagnosticPaymentVerification","InvalidateDiagnosticPaymentVerification"):
        value={"command_type":command["command_type"],"payload":command["payload"]}
    if command.get("command_type")=="OpenOIAAssessment":
        value={"command_type":command["command_type"],"payload":command["payload"]}
    if command.get("command_type")=="RecordOIAEvidence":
        value={"command_type":command["command_type"],"engagement_id":command.get("engagement_id"),"payload":command["payload"]}
    return "fpv1:"+hashlib.sha256(json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()).hexdigest()
@dataclass
class MemoryStore:
    handoffs:dict=field(default_factory=dict); engagements:dict=field(default_factory=dict); scopes:dict=field(default_factory=dict); approvals:dict=field(default_factory=dict); proposals:dict=field(default_factory=dict); grants:dict=field(default_factory=dict); agreements:dict=field(default_factory=dict); payments:dict=field(default_factory=dict); oia_assessments:dict=field(default_factory=dict); oia_evidence_items:dict=field(default_factory=dict); oia_assessment_plans:dict=field(default_factory=dict); oia_inspection_items:dict=field(default_factory=dict); oia_observations:dict=field(default_factory=dict); oia_root_causes:dict=field(default_factory=dict); oia_findings:dict=field(default_factory=dict); idempotency:dict=field(default_factory=dict); events:list=field(default_factory=list); outbox:list=field(default_factory=list)
    fail_stage:str|None=None
    def _current_plan(self,tenant_id,plan_id):
        candidates=[value for (record_tenant,record_plan_id,_),value in self.oia_assessment_plans.items() if record_tenant==tenant_id and record_plan_id==plan_id and value.get("state")!="SUPERSEDED"]
        return copy.deepcopy(max(candidates,key=lambda value:value["plan_version"])) if candidates else None
    def _current_finding(self,tenant_id,finding_id):
        candidates=[value for (record_tenant,record_finding_id,_),value in self.oia_findings.items() if record_tenant==tenant_id and record_finding_id==finding_id and value.get("state")!="SUPERSEDED"]
        return copy.deepcopy(max(candidates,key=lambda value:value["finding_revision"])) if candidates else None
    def snapshot(self,command,trusted_context=None):
        records={"ACQUISITION_HANDOFF":self.handoffs,"ENGAGEMENT":self.engagements,"DIAGNOSTIC_SCOPE":self.scopes,"DIAGNOSTIC_AGREEMENT_AUTHORITY":self.agreements,"DIAGNOSTIC_PAYMENT_VERIFICATION":self.payments}.get(command.subject_type)
        r=self.proposals.get((command.tenant_id,command.subject_id)) if command.subject_type=="ASSESSMENT_ACCESS_PROPOSAL" else self.grants.get((command.tenant_id,command.subject_id)) if command.subject_type=="ASSESSMENT_ACCESS_GRANT" else self.oia_assessments.get((command.tenant_id,command.subject_id)) if command.subject_type=="OIA_ASSESSMENT" else self.oia_evidence_items.get((command.tenant_id,command.subject_id)) if command.subject_type=="OIA_EVIDENCE_ITEM" else self._current_plan(command.tenant_id,command.subject_id) if command.subject_type=="OIA_ASSESSMENT_PLAN" else self.oia_inspection_items.get((command.tenant_id,command.subject_id)) if command.subject_type=="OIA_INSPECTION_ITEM" else self.oia_observations.get((command.tenant_id,command.subject_id)) if command.subject_type=="OIA_OBSERVATION" else self.oia_root_causes.get((command.tenant_id,command.subject_id)) if command.subject_type=="OIA_ROOT_CAUSE" else self._current_finding(command.tenant_id,command.subject_id) if command.subject_type=="OIA_FINDING" else (records or {}).get(command.subject_id)
        engagement_id=r.get("engagement_id") if r else None
        if r and command.subject_type=="OIA_EVIDENCE_ITEM":
            assessment=self.oia_assessments.get((command.tenant_id,r["oia_assessment_id"]));engagement_id=(assessment or {}).get("engagement_id")
        if r and command.subject_type in ("OIA_OBSERVATION","OIA_ROOT_CAUSE","OIA_FINDING"):
            assessment=self.oia_assessments.get((command.tenant_id,r["oia_assessment_id"]));engagement_id=(assessment or {}).get("engagement_id")
        return None if not r else AuthoritativeSubjectSnapshot(command.subject_type,command.subject_id,r["tenant_id"],r.get("record_version",r.get("finding_revision",1)),True,engagement_id,r.get("status") or r.get("engagement_state") or r.get("state") or r.get("confidence"))
class _TenantRepo:
    def __init__(self,u,name):self.u=u;self.data=getattr(u.working,name)
    def get(self,tenant_id,record_id):
        r=self.data.get(record_id);return r if r and r.get("tenant_id")==tenant_id else None
    def save(self,record):self.u.failpoint("AUTHORITATIVE_WRITE");self.data[record.get("handoff_id") or record.get("engagement_id") or record.get("diagnostic_scope_id") or record.get("approval_id")]=record
class AcquisitionHandoffMemoryRepository(_TenantRepo):
    def __init__(self,u):super().__init__(u,"handoffs")
    def save_accepted(self,record):self.u.failpoint("AUTHORITATIVE_WRITE");record["accepted"]=True
class EngagementMemoryRepository(_TenantRepo):
    def __init__(self,u):super().__init__(u,"engagements")
    def exists(self,tenant_id,record_id):return self.get(tenant_id,record_id) is not None
class DiagnosticScopeMemoryRepository(_TenantRepo):
    def __init__(self,u):super().__init__(u,"scopes")
    def save(self,record):self.u.failpoint("AUTHORITATIVE_WRITE");self.data[record["diagnostic_scope_id"]]=record
    def mark_approved(self,record):self.u.failpoint("AUTHORITATIVE_WRITE");record["status"]="APPROVED"
    def set_canonical_scope_digest(self,tenant_id,scope_id,scope_version,expected_record_version,digest):
        record=self.get(tenant_id,scope_id)
        if not record or record.get("scope_version")!=scope_version or record.get("record_version")!=expected_record_version:raise ValueError()
        if record.get("canonical_scope_digest") is not None:return record["canonical_scope_digest"]
        self.u.failpoint("AUTHORITATIVE_WRITE");record["canonical_scope_digest"]=digest;record["record_version"]+=1;return digest
class DiagnosticAgreementAuthorityMemoryRepository(_TenantRepo):
    def __init__(self,u):super().__init__(u,"agreements")
    def save(self,record):self.data[record["diagnostic_agreement_authority_id"]]=record
    def create(self,record):
        key=record["diagnostic_agreement_authority_id"];existing=self.data.get(key)
        if existing:
            if existing!=record:raise ValueError("diagnostic agreement authority identity conflicts")
            return copy.deepcopy(existing)
        self.u.failpoint("AUTHORITATIVE_WRITE");self.data[key]=copy.deepcopy(record);return copy.deepcopy(record)
class DiagnosticPaymentVerificationMemoryRepository(_TenantRepo):
    def __init__(self,u):super().__init__(u,"payments")
    def save(self,record):self.data[record["diagnostic_payment_verification_id"]]=record
    def create(self,record):
        key=record["diagnostic_payment_verification_id"];existing=self.data.get(key)
        if existing:
            if existing!=record:raise ValueError("diagnostic payment verification identity conflicts")
            return copy.deepcopy(existing)
        self.u.failpoint("AUTHORITATIVE_WRITE");self.data[key]=copy.deepcopy(record);return copy.deepcopy(record)
    def invalidate(self,tenant_id,payment_id,invalidated_at):
        payment=self.get(tenant_id,payment_id)
        if not payment or payment.get("verification_status")!="VERIFIED":raise ValueError("payment is not invalidatable")
        self.u.failpoint("AUTHORITATIVE_WRITE");stored=self.data[payment_id];stored["verification_status"]="INVALIDATED";stored["invalidated_at"]=invalidated_at;stored["record_version"]=stored.get("record_version",1)+1
        return copy.deepcopy(stored)
class AssessmentAccessProposalMemoryRepository(_TenantRepo):
    def __init__(self,u):super().__init__(u,"proposals")
    def get(self,tenant_id,assessment_access_proposal_id):
        record=self.data.get((tenant_id,assessment_access_proposal_id))
        return copy.deepcopy(record) if record else None
    def create(self,proposal):
        tenant_id=proposal["tenant_id"];proposal_id=proposal["assessment_access_proposal_id"];key=(tenant_id,proposal_id);existing=self.data.get(key)
        if existing:
            if existing!=proposal:raise ValueError("assessment access proposal identity conflicts")
            return copy.deepcopy(existing)
        self.u.failpoint("AUTHORITATIVE_WRITE")
        self.data[key]=copy.deepcopy(proposal)
        return copy.deepcopy(proposal)
    def consume(self,tenant_id,proposal_id,digest,consumed_at):
        key=(tenant_id,proposal_id); proposal=self.data.get(key)
        if not proposal or proposal.get("status")!="OPEN" or proposal.get("assessment_access_authority_digest")!=digest:raise ValueError("proposal is not consumable")
        self.u.failpoint("AUTHORITATIVE_WRITE"); proposal["status"]="CONSUMED";proposal["consumed_at"]=consumed_at;proposal["record_version"]=proposal.get("record_version",1)+1
        return copy.deepcopy(proposal)

class AssessmentAccessGrantMemoryRepository(_TenantRepo):
    def __init__(self,u):super().__init__(u,"grants")
    def get(self,tenant_id,grant_id):
        record=self.data.get((tenant_id,grant_id));return copy.deepcopy(record) if record else None
    def create(self,grant):
        key=(grant["tenant_id"],grant["assessment_access_grant_id"]);existing=self.data.get(key)
        if existing:
            if existing!=grant:raise ValueError("assessment access grant identity conflicts")
            return copy.deepcopy(existing)
        source=grant["source_assessment_access_proposal_reference"]["reference_id"]
        if any(value.get("tenant_id")==grant["tenant_id"] and value.get("source_assessment_access_proposal_reference",{}).get("reference_id")==source for value in self.data.values()):raise ValueError("assessment access proposal already issued a grant")
        self.u.failpoint("AUTHORITATIVE_WRITE");self.data[key]=copy.deepcopy(grant);return copy.deepcopy(grant)

    def activate(self,tenant_id,grant_id,digest,verified_at,expires_at):
        key=(tenant_id,grant_id); grant=self.data.get(key)
        if not grant or grant.get("status")!="APPROVED" or grant.get("assessment_access_authority_digest")!=digest:raise ValueError("grant is not activatable")
        self.u.failpoint("AUTHORITATIVE_WRITE")
        grant["status"]="ACTIVE";grant["verified_at"]=verified_at;grant["active_from"]=verified_at;grant["expires_at"]=expires_at;grant["record_version"]=grant.get("record_version",1)+1
        return copy.deepcopy(grant)

    def expire(self,tenant_id,grant_id,trusted_now):
        grant=self.data.get((tenant_id,grant_id))
        if not grant or grant.get("status")!="ACTIVE" or trusted_now<grant.get("expires_at",""):raise ValueError("grant is not expirable")
        self.u.failpoint("AUTHORITATIVE_WRITE");grant["status"]="EXPIRED";grant["record_version"]+=1;return copy.deepcopy(grant)
    def revoke(self,tenant_id,grant_id,trusted_now):
        grant=self.data.get((tenant_id,grant_id))
        if not grant or grant.get("status") not in ("APPROVED","ACTIVE"):raise ValueError("grant is not revocable")
        self.u.failpoint("AUTHORITATIVE_WRITE");grant["status"]="REVOKED";grant["revoked_at"]=trusted_now;grant["record_version"]+=1;return copy.deepcopy(grant)
    def close_for_agreement_end(self,tenant_id,grant_id,trusted_now):
        grant=self.data.get((tenant_id,grant_id))
        if not grant or grant.get("status") not in ("APPROVED","ACTIVE"):raise ValueError("grant is not closable")
        self.u.failpoint("AUTHORITATIVE_WRITE");grant["status"]="CLOSED";grant["closed_at"]=trusted_now;grant["closure_reason"]="AGREEMENT_ENDED";grant["record_version"]+=1;return copy.deepcopy(grant)
class OIAAssessmentMemoryRepository(_TenantRepo):
    def __init__(self,u):super().__init__(u,"oia_assessments")
    def get(self,tenant_id,oia_assessment_id):
        record=self.data.get((tenant_id,oia_assessment_id));return copy.deepcopy(record) if record else None
    def find_by_assessment_access_grant(self,tenant_id,assessment_access_grant_id):
        return next((copy.deepcopy(record) for (record_tenant,_),record in self.data.items() if record_tenant==tenant_id and record.get("assessment_access_grant_id")==assessment_access_grant_id),None)
    def create(self,assessment):
        key=(assessment["tenant_id"],assessment["oia_assessment_id"])
        if key in self.data:raise ValueError("OIA assessment identity already exists")
        if self.find_by_assessment_access_grant(assessment["tenant_id"],assessment["assessment_access_grant_id"]):raise ValueError("assessment access grant already has an OIA assessment")
        self.u.failpoint("AUTHORITATIVE_WRITE");self.data[key]=copy.deepcopy(assessment);return copy.deepcopy(assessment)
class OIAEvidenceMemoryRepository(_TenantRepo):
    def __init__(self,u):super().__init__(u,"oia_evidence_items")
    def get(self,tenant_id,oia_evidence_id):
        record=self.data.get((tenant_id,oia_evidence_id));return copy.deepcopy(record) if record else None
    def create(self,evidence):
        key=(evidence["tenant_id"],evidence["oia_evidence_id"])
        if key in self.data:raise ValueError("OIA evidence identity already exists")
        self.u.failpoint("AUTHORITATIVE_WRITE");self.data[key]=copy.deepcopy(evidence);return copy.deepcopy(evidence)
class OIAAssessmentPlanMemoryRepository(_TenantRepo):
    def __init__(self,u):super().__init__(u,"oia_assessment_plans")
    def get_version(self,tenant_id,plan_id,plan_version):
        record=self.data.get((tenant_id,plan_id,plan_version));return copy.deepcopy(record) if record else None
    def list_versions(self,tenant_id,plan_id):
        return tuple(copy.deepcopy(value) for (record_tenant,record_plan_id,_),value in sorted(self.data.items(),key=lambda item:item[0][2]) if record_tenant==tenant_id and record_plan_id==plan_id)
    def get_current(self,tenant_id,plan_id):
        versions=[value for value in self.list_versions(tenant_id,plan_id) if value.get("state")!="SUPERSEDED"]
        return copy.deepcopy(max(versions,key=lambda value:value["plan_version"])) if versions else None
    def find_current_by_assessment(self,tenant_id,assessment_id):
        candidates=[copy.deepcopy(value) for (record_tenant,_,_),value in self.data.items() if record_tenant==tenant_id and value.get("oia_assessment_id")==assessment_id and value.get("state")!="SUPERSEDED"]
        return max(candidates,key=lambda value:value["plan_version"]) if candidates else None
    def create_initial(self,plan):
        key=(plan["tenant_id"],plan["oia_assessment_plan_id"],plan["plan_version"])
        if key in self.data or any(record_tenant==plan["tenant_id"] and value.get("oia_assessment_id")==plan["oia_assessment_id"] for (record_tenant,_,_),value in self.data.items()):raise ValueError("OIA assessment already has a plan lineage")
        self.u.failpoint("AUTHORITATIVE_WRITE");self.data[key]=copy.deepcopy(plan);return copy.deepcopy(plan)
    def revise(self,current,replacement,revised_at):
        key=(current["tenant_id"],current["oia_assessment_plan_id"],current["plan_version"]);stored=self.data.get(key)
        replacement_key=(replacement["tenant_id"],replacement["oia_assessment_plan_id"],replacement["plan_version"])
        if stored!=current or stored.get("state")=="SUPERSEDED" or replacement_key in self.data:raise ValueError("plan revision conflict")
        self.u.failpoint("AUTHORITATIVE_WRITE");superseded=copy.deepcopy(stored);superseded["state"]="SUPERSEDED";superseded["record_version"]+=1;superseded["updated_at"]=revised_at;self.data[key]=superseded;self.data[replacement_key]=copy.deepcopy(replacement);return copy.deepcopy(replacement)
    def review(self,current,reviewed_by,reviewed_at):
        key=(current["tenant_id"],current["oia_assessment_plan_id"],current["plan_version"]);stored=self.data.get(key)
        if stored!=current or stored.get("state")!="DRAFT":raise ValueError("plan review conflict")
        self.u.failpoint("AUTHORITATIVE_WRITE");stored["state"]="REVIEWED";stored["reviewed_by"]=reviewed_by;stored["reviewed_at"]=reviewed_at;stored["updated_at"]=reviewed_at;stored["record_version"]+=1;return copy.deepcopy(stored)
    def approve(self,current,approved_by,approved_at):
        key=(current["tenant_id"],current["oia_assessment_plan_id"],current["plan_version"]);stored=self.data.get(key)
        if stored!=current or stored.get("state")!="REVIEWED":raise ValueError("plan approval conflict")
        self.u.failpoint("AUTHORITATIVE_WRITE");stored["state"]="APPROVED";stored["approved_by"]=approved_by;stored["approved_at"]=approved_at;stored["updated_at"]=approved_at;stored["record_version"]+=1;return copy.deepcopy(stored)

class OIAInspectionItemMemoryRepository(_TenantRepo):
    def __init__(self,u):super().__init__(u,"oia_inspection_items")
    def get(self,tenant_id,item_id):
        record=self.data.get((tenant_id,item_id));return copy.deepcopy(record) if record else None
    def list_by_plan(self,tenant_id,plan_id,plan_version):
        return tuple(copy.deepcopy(value) for (record_tenant,_),value in self.data.items() if record_tenant==tenant_id and value.get("oia_assessment_plan_id")==plan_id and value.get("plan_version")==plan_version)
    def list_by_assessment(self,tenant_id,assessment_id):
        return tuple(copy.deepcopy(value) for (record_tenant,_),value in self.data.items() if record_tenant==tenant_id and value.get("oia_assessment_id")==assessment_id)
    def create(self,item):
        key=(item["tenant_id"],item["oia_inspection_item_id"])
        if key in self.data:raise ValueError("OIA inspection item identity already exists")
        self.u.failpoint("AUTHORITATIVE_WRITE");self.data[key]=copy.deepcopy(item);return copy.deepcopy(item)
    def update(self,current,payload,updated_by,updated_at):
        key=(current["tenant_id"],current["oia_inspection_item_id"]);stored=self.data.get(key)
        if stored!=current:raise ValueError("inspection item update conflict")
        self.u.failpoint("AUTHORITATIVE_WRITE");updated=copy.deepcopy(stored)
        for name in ("coverage_state","sufficiency_evaluation","limitations","linked_evidence_ids","stop_reason","stop_rationale","intervention_class","assessor_notes"):
            if name in payload:updated[name]=copy.deepcopy(payload[name])
            elif name in ("stop_reason","stop_rationale","intervention_class"):updated.pop(name,None)
        updated.pop("blocked_reason",None);updated.pop("blocked_explanation",None);updated["updated_by"]=updated_by;updated["updated_at"]=updated_at;updated["record_version"]+=1;self.data[key]=updated;return copy.deepcopy(updated)
    def block(self,current,payload,updated_by,updated_at,stop_reason):
        key=(current["tenant_id"],current["oia_inspection_item_id"]);stored=self.data.get(key)
        if stored!=current:raise ValueError("inspection item block conflict")
        self.u.failpoint("AUTHORITATIVE_WRITE");updated=copy.deepcopy(stored);updated["coverage_state"]="BLOCKED";updated["blocked_reason"]=payload["blocked_reason"];updated["blocked_explanation"]=payload["blocked_explanation"];updated["limitations"]=copy.deepcopy(stored["limitations"])
        for limitation in payload["limitations"]:
            if limitation not in updated["limitations"]:updated["limitations"].append(copy.deepcopy(limitation))
        if updated["sufficiency_evaluation"]["state"]=="NOT_EVALUATED":
            updated["sufficiency_evaluation"].update(state="INSUFFICIENT",missing_material_evidence=True,confidence="LOW",rationale=payload["blocked_explanation"][:1000])
        if stop_reason:updated["stop_reason"]=stop_reason;updated["stop_rationale"]=payload["blocked_explanation"]
        else:updated.pop("stop_reason",None);updated.pop("stop_rationale",None)
        updated.pop("intervention_class",None);updated["updated_by"]=updated_by;updated["updated_at"]=updated_at;updated["record_version"]+=1;self.data[key]=updated;return copy.deepcopy(updated)
    def coverage_for_plan(self,tenant_id,plan_id,plan_version):
        return derive_assessment_coverage(self.list_by_plan(tenant_id,plan_id,plan_version))
    def coverage_for_current_assessment(self,tenant_id,assessment_id):
        plan=self.u.oia_assessment_plans.find_current_by_assessment(tenant_id,assessment_id)
        if not plan or plan.get("state")!="APPROVED":return None
        coverage=self.coverage_for_plan(tenant_id,plan["oia_assessment_plan_id"],plan["plan_version"])
        return {"oia_assessment_id":assessment_id,"oia_assessment_plan_id":plan["oia_assessment_plan_id"],"plan_version":plan["plan_version"],**coverage}

class OIAObservationMemoryRepository(_TenantRepo):
    def __init__(self,u):super().__init__(u,"oia_observations")
    def get(self,tenant_id,observation_id):
        record=self.data.get((tenant_id,observation_id));return copy.deepcopy(record) if record else None
    def list_by_assessment(self,tenant_id,assessment_id):
        return tuple(copy.deepcopy(value) for (record_tenant,_),value in self.data.items() if record_tenant==tenant_id and value.get("oia_assessment_id")==assessment_id)
    def list_current_by_assessment(self,tenant_id,assessment_id):
        return tuple(value for value in self.list_by_assessment(tenant_id,assessment_id) if value.get("state")=="RECORDED")
    def resolve_current(self,tenant_id,observation_id):
        current=self.get(tenant_id,observation_id);seen=set()
        while current and current.get("state")=="SUPERSEDED":
            if current["oia_observation_id"] in seen:return None
            seen.add(current["oia_observation_id"]);current=self.get(tenant_id,current["superseded_by_observation_id"])
        return current
    def create(self,observation):
        key=(observation["tenant_id"],observation["oia_observation_id"])
        if key in self.data:raise ValueError("OIA observation identity already exists")
        self.u.failpoint("AUTHORITATIVE_WRITE");self.data[key]=copy.deepcopy(observation);return copy.deepcopy(observation)
    def supersede(self,original,replacement,superseded_at):
        key=(original["tenant_id"],original["oia_observation_id"]);stored=self.data.get(key)
        if stored!=original or stored.get("state")!="RECORDED":raise ValueError("observation supersession conflict")
        if any(value.get("superseded_by_observation_id")==replacement["oia_observation_id"] for value in self.data.values()):raise ValueError("replacement observation is already in a supersession lineage")
        self.u.failpoint("AUTHORITATIVE_WRITE");updated=copy.deepcopy(stored);updated["state"]="SUPERSEDED";updated["superseded_by_observation_id"]=replacement["oia_observation_id"];updated["record_version"]+=1;updated["updated_at"]=superseded_at;self.data[key]=updated;return copy.deepcopy(updated)

class OIARootCauseMemoryRepository(_TenantRepo):
    def __init__(self,u):super().__init__(u,"oia_root_causes")
    def get(self,tenant_id,root_cause_id):
        record=self.data.get((tenant_id,root_cause_id));return copy.deepcopy(record) if record else None
    def list_by_assessment(self,tenant_id,assessment_id):
        return tuple(copy.deepcopy(value) for (record_tenant,_),value in self.data.items() if record_tenant==tenant_id and value.get("oia_assessment_id")==assessment_id)
    def create(self,root_cause):
        key=(root_cause["tenant_id"],root_cause["oia_root_cause_id"])
        if key in self.data:raise ValueError("OIA root-cause identity already exists")
        self.u.failpoint("AUTHORITATIVE_WRITE");self.data[key]=copy.deepcopy(root_cause);return copy.deepcopy(root_cause)
    def transition(self,current,payload,updated_at):
        key=(current["tenant_id"],current["oia_root_cause_id"]);stored=self.data.get(key)
        if stored!=current:raise ValueError("root-cause transition conflict")
        self.u.failpoint("AUTHORITATIVE_WRITE");updated=copy.deepcopy(stored);updated["confidence"]=payload["confidence"];updated["supporting_observation_ids"]=copy.deepcopy(payload["supporting_observation_ids"]);updated["supporting_evidence_ids"]=copy.deepcopy(payload["supporting_evidence_ids"]);updated["record_version"]+=1;updated["updated_at"]=updated_at;self.data[key]=updated;return copy.deepcopy(updated)

class OIAFindingMemoryRepository(_TenantRepo):
    def __init__(self,u):super().__init__(u,"oia_findings")
    def get_revision(self,tenant_id,finding_id,finding_revision):
        record=self.data.get((tenant_id,finding_id,finding_revision));return copy.deepcopy(record) if record else None
    def get(self,tenant_id,finding_id):
        candidates=[value for (record_tenant,record_finding_id,_),value in self.data.items() if record_tenant==tenant_id and record_finding_id==finding_id and value.get("state")!="SUPERSEDED"]
        return copy.deepcopy(max(candidates,key=lambda value:value["finding_revision"])) if candidates else None
    def list_by_assessment(self,tenant_id,assessment_id):
        return tuple(copy.deepcopy(value) for (record_tenant,_,_),value in sorted(self.data.items(),key=lambda item:(item[0][1],item[0][2])) if record_tenant==tenant_id and value.get("oia_assessment_id")==assessment_id)
    def list_current_by_assessment(self,tenant_id,assessment_id):
        identities={finding_id for (record_tenant,finding_id,_),value in self.data.items() if record_tenant==tenant_id and value.get("oia_assessment_id")==assessment_id}
        return tuple(self.get(tenant_id,finding_id) for finding_id in sorted(identities))
    def create(self,finding):
        tenant_id=finding["tenant_id"];finding_id=finding["oia_finding_id"]
        if any(record_tenant==tenant_id and record_finding_id==finding_id for record_tenant,record_finding_id,_ in self.data):raise ValueError("OIA Finding identity already exists")
        self.u.failpoint("AUTHORITATIVE_WRITE");self.data[(tenant_id,finding_id,finding["finding_revision"])]=copy.deepcopy(finding);return copy.deepcopy(finding)
    def revise(self,current,replacement,content_digest,updated_at):
        key=(current["tenant_id"],current["oia_finding_id"],current["finding_revision"]);stored=self.data.get(key);replacement_key=(replacement["tenant_id"],replacement["oia_finding_id"],replacement["finding_revision"])
        if stored!=current or stored.get("state")!="DRAFT" or replacement_key in self.data:raise ValueError("Finding revision conflict")
        self.u.failpoint("AUTHORITATIVE_WRITE");superseded=copy.deepcopy(stored);superseded["state"]="SUPERSEDED";superseded["content_digest"]=content_digest;superseded["updated_at"]=updated_at;self.data[key]=superseded;self.data[replacement_key]=copy.deepcopy(replacement);return copy.deepcopy(replacement)
    def finalize(self,current,final):
        key=(current["tenant_id"],current["oia_finding_id"],current["finding_revision"]);stored=self.data.get(key)
        if stored!=current or stored.get("state")!="DRAFT" or final.get("state")!="FINAL":raise ValueError("Finding finalization conflict")
        self.u.failpoint("AUTHORITATIVE_WRITE");self.data[key]=copy.deepcopy(final);return copy.deepcopy(final)
    def summary_by_assessment(self,tenant_id,assessment_id,generated_at):
        finals=[finding for finding in self.list_current_by_assessment(tenant_id,assessment_id) if finding.get("state")=="FINAL"]
        return {"tenant_id":tenant_id,"oia_assessment_id":assessment_id,"finalized_finding_count":len(finals),"priority_counts":[{"priority":priority,"count":sum(finding["priority"]==priority for finding in finals)} for priority in ("CRITICAL","HIGH","MEDIUM","LOW")],"generated_at":generated_at}

class HumanApprovalMemoryRepository(_TenantRepo):
    def __init__(self,u):super().__init__(u,"approvals")
    def save(self,record):
        self.u.failpoint("AUTHORITATIVE_WRITE")
        if self.get(record["tenant_id"],record["approval_id"]):raise ValueError("approval already exists")
        self.data[record["approval_id"]]=record
    def find_active_assessment_access_binding(self,tenant_id,proposal_id,digest,authority_role):
        return next((copy.deepcopy(approval) for approval in self.data.values() if approval.get("tenant_id")==tenant_id and approval.get("subject_type")=="ASSESSMENT_ACCESS_PROPOSAL" and approval.get("subject_id")==proposal_id and approval.get("assessment_access",{}).get("assessment_access_authority_digest")==digest and approval.get("actor_role")==authority_role and approval.get("status")=="ACTIVE"),None)
    def list_active_assessment_access_bindings(self,tenant_id,proposal_id,digest,authority_role):
        return tuple(copy.deepcopy(approval) for approval in self.data.values() if approval.get("tenant_id")==tenant_id and approval.get("subject_type")=="ASSESSMENT_ACCESS_PROPOSAL" and approval.get("subject_id")==proposal_id and approval.get("assessment_access",{}).get("assessment_access_authority_digest")==digest and approval.get("actor_role")==authority_role and approval.get("status")=="ACTIVE")
    def record_assessment_access(self,record):
        binding=record["assessment_access"]
        if self.find_active_assessment_access_binding(record["tenant_id"],record["subject_id"],binding["assessment_access_authority_digest"],record["actor_role"]):raise ValueError("duplicate active assessment access authority")
        self.save(record)
    def find_active_binding(self,tenant_id,scope_id,scope_version,authority_role,digest,action_set_version):
        return next((a for a in self.data.values() if a.get("tenant_id")==tenant_id and a.get("subject_id")==scope_id and a.get("subject_version")==scope_version and a.get("authority_role")==authority_role and a.get("canonical_scope_digest")==digest and a.get("action_set_version")==action_set_version and a.get("status")=="ACTIVE"),None)
class IdempotencyMemoryRepository:
    def __init__(self,u):self.u=u;self.data=u.working.idempotency
    def get(self,key):return self.data.get(key)
    def reserve(self,key,*_):self.u.failpoint("IDEMPOTENCY_RESERVE")
    def save_result(self,key,result):self.u.failpoint("IDEMPOTENCY_COMPLETE");self.data[key]=result
class LifecycleEventMemoryRepository:
    def __init__(self,u):self.u=u
    def append(self,event):self.u.failpoint("LIFECYCLE_EVENT_APPEND");self.u.working.events.append(event)
    def list(self):return tuple(self.u.working.events)
class OutboxMemoryRepository:
    def __init__(self,u):self.u=u
    def append(self,intent):self.u.failpoint("OUTBOX_APPEND");self.u.working.outbox.append(intent)
    def list(self):return tuple(self.u.working.outbox)
class UnitOfWork:
    def __init__(self,store):
        self.store=store;self.working=copy.deepcopy(store)
        self.handoffs=AcquisitionHandoffMemoryRepository(self);self.engagements=EngagementMemoryRepository(self);self.diagnostic_scopes=DiagnosticScopeMemoryRepository(self);self.diagnostic_agreement_authorities=DiagnosticAgreementAuthorityMemoryRepository(self);self.diagnostic_payment_verifications=DiagnosticPaymentVerificationMemoryRepository(self);self.assessment_access_proposals=AssessmentAccessProposalMemoryRepository(self);self.assessment_access_grants=AssessmentAccessGrantMemoryRepository(self);self.oia_assessments=OIAAssessmentMemoryRepository(self);self.oia_evidence_items=OIAEvidenceMemoryRepository(self);self.oia_assessment_plans=OIAAssessmentPlanMemoryRepository(self);self.oia_inspection_items=OIAInspectionItemMemoryRepository(self);self.oia_observations=OIAObservationMemoryRepository(self);self.oia_root_causes=OIARootCauseMemoryRepository(self);self.oia_findings=OIAFindingMemoryRepository(self);self.human_approvals=HumanApprovalMemoryRepository(self);self.idempotency=IdempotencyMemoryRepository(self);self.lifecycle_events=LifecycleEventMemoryRepository(self);self.outbox=OutboxMemoryRepository(self)
    def failpoint(self,name):
        if self.working.fail_stage==name: raise RuntimeError("injected failpoint")
    def commit(self):
        self.failpoint("COMMIT")
        self.store.__dict__.update(self.working.__dict__)
class Executor:
    def __init__(self,validator,pipeline,store,clock=lambda:"2030-01-15T15:00:00Z",ids=lambda:str(uuid.uuid4()),uow_factory=UnitOfWork,assessment_access_verifier=None,methodology_catalog=None):self.validator=validator;self.pipeline=pipeline;self.store=store;self.clock=clock;self.ids=ids;self.uow_factory=uow_factory;self.assessment_access_verifier=assessment_access_verifier or InMemoryAssessmentAccessVerifier();self.methodology_catalog=methodology_catalog or TrustedMethodologyCatalog()
    def execute(self,raw,context):
        first=self.validator.prepare(raw)
        if isinstance(first,ValidationFailure):return {"result":"VALIDATION_FAILED","reason_code":first.reason.value}
        p=first.prepared
        try:
            u=self.uow_factory(self.store)
            bind_context=getattr(u,"bind_trusted_context",None)
            if bind_context: bind_context(context)
        except (ValueError, RuntimeError):
            getattr(locals().get("u"),"rollback",lambda:None)();getattr(locals().get("u"),"close",lambda:None)()
            return {"result":"REJECTED","reason_code":"PREREQUISITE_STATE_INVALID"}
        scope=idempotency_scope(p)
        key=(p.tenant_id,context.principal_id,p.command_type,p.subject_type,scope,p.idempotency_key); fp=fingerprint(raw); prior=u.idempotency.get(key)
        if prior:getattr(u,"rollback",lambda:None)();getattr(u,"close",lambda:None)();return {"result":"DUPLICATE","reason_code":"DUPLICATE_REQUEST","prior_result_reference":prior["command_id"]} if prior["fingerprint"]==fp else {"result":"CONFLICT","reason_code":"IDEMPOTENCY_SEMANTIC_MISMATCH"}
        guarded=prepare_and_guard_command(self.validator,self.pipeline,raw,context,self.store.snapshot(p,context),self.clock())
        if not hasattr(guarded,"guarded"):getattr(u,"rollback",lambda:None)();getattr(u,"close",lambda:None)();return {"result":"REJECTED","reason_code":guarded.reason.value}
        if p.command_type in ("RecordHumanApproval","RecordAssessmentAccessApproval"):
            authority=self.pipeline.human_approval_authority(context,p.payload["authority_role"])
            if authority:
                getattr(u,"rollback",lambda:None)();getattr(u,"close",lambda:None)();return {"result":"REJECTED","reason_code":authority.reason.value}
        try:
            race=u.idempotency.reserve(key,fp,p)
            if race:getattr(u,"rollback",lambda:None)();getattr(u,"close",lambda:None)();return {"result":"DUPLICATE","reason_code":"DUPLICATE_REQUEST","prior_result_reference":race["command_id"]} if race["fingerprint"]==fp else {"result":"CONFLICT","reason_code":"IDEMPOTENCY_SEMANTIC_MISMATCH"}
            u.failpoint("AUTHORITATIVE_WRITE");self._handle(u,p,raw,context); event=self._event(p,u);u.lifecycle_events.append(event);u.outbox.append({"event_id":event["event_id"],"status":"PENDING"});u.idempotency.save_result(key,{"fingerprint":fp,"command_id":p.command_id});u.commit();getattr(u,"close",lambda:None)()
        except CanonicalScopeDigestConflict:getattr(u,"rollback",lambda:None)();getattr(u,"close",lambda:None)();return {"result":"CONFLICT","reason_code":"INTERNAL_INVARIANT_VIOLATION"}
        except (ValueError,RuntimeError) as error:getattr(u,"rollback",lambda:None)();getattr(u,"close",lambda:None)();return {"result":"REJECTED","reason_code":"PREREQUISITE_STATE_INVALID"}
        return {"result":"ACCEPTED","reason_code":"COMMAND_ACCEPTED","authoritative_record_reference":p.subject_id}
    def _handle(self,u,p,raw,raw_context=None):
        now=self.clock(); payload=p.payload
        if p.command_type=="AcceptAcquisitionHandoff":
            r=u.handoffs.get(p.tenant_id,p.subject_id)
            if not r or r.get("accepted"):raise ValueError()
            r["accepted_at"]=now;u.handoffs.save_accepted(r)
        elif p.command_type=="OpenEngagement":
            h=payload["accepted_handoff_reference"];source=u.handoffs.get(p.tenant_id,h["reference_id"])
            if not source or not source.get("accepted") or h["reference_version"]!=source["handoff_version"] or u.engagements.exists(p.tenant_id,p.subject_id):raise ValueError()
            if payload["canonical_account_reference"]!=source["canonical_account_reference"] or payload["acquisition_opportunity_reference"]!=source["acquisition_opportunity_reference"]:raise ValueError()
            u.engagements.save({"engagement_id":p.subject_id,"tenant_id":p.tenant_id,"engagement_state":"OPEN","record_version":1,"engagement_version":1,"opened_at":now,**payload})
        elif p.command_type=="SubmitDiagnosticScope":
            e=u.engagements.get(p.tenant_id,p.subject_id);sid=payload["proposed_diagnostic_scope_id"]
            if not e or e["engagement_state"] not in ("OPEN","ONBOARDING") or u.diagnostic_scopes.get(p.tenant_id,sid):raise ValueError()
            u.diagnostic_scopes.save({"diagnostic_scope_id":sid,"engagement_id":p.subject_id,"tenant_id":p.tenant_id,"scope_version":payload["scope_version"],"record_version":1,"status":"REVIEW_PENDING","action_set_version":1,**payload})
        elif p.command_type=="IssueAssessmentAccessGrant":
            IssueAssessmentAccessGrantHandler(u).issue(raw_context,payload,now)
        elif p.command_type=="RecordDiagnosticAgreementAuthority":
            DiagnosticCommercialIngressHandler(u).record_agreement(raw_context,payload,now)
        elif p.command_type=="RecordDiagnosticPaymentVerification":
            DiagnosticCommercialIngressHandler(u).record_payment(raw_context,payload,now)
        elif p.command_type=="InvalidateDiagnosticPaymentVerification":
            DiagnosticCommercialIngressHandler(u).invalidate_payment(raw_context,payload,now)
        elif p.command_type=="CreateAssessmentAccessProposal":
            CreateAssessmentAccessProposalHandler(u).create(raw_context,payload,now)
        elif p.command_type=="OpenOIAAssessment":
            OpenOIAAssessmentHandler(u).open(raw_context,payload,now)
        elif p.command_type=="VerifyAssessmentAccess":
            VerifyAssessmentAccessHandler(u,self.assessment_access_verifier).verify(raw_context,payload,now)
        elif p.command_type=="RecordOIAEvidence":
            RecordOIAEvidenceHandler(u).record(raw_context,payload,p.engagement_id,now)
        elif p.command_type in ("CreateOIAAssessmentPlan","ReviseOIAAssessmentPlan","ReviewOIAAssessmentPlan","ApproveOIAAssessmentPlan"):
            handler=OIAAssessmentPlanHandler(u,self.methodology_catalog)
            if p.command_type=="CreateOIAAssessmentPlan":handler.create(raw_context,payload,now)
            elif p.command_type=="ReviseOIAAssessmentPlan":handler.revise(raw_context,payload,p.expected_record_version,now)
            elif p.command_type=="ReviewOIAAssessmentPlan":handler.review(raw_context,payload,p.expected_record_version,now)
            else:handler.approve(raw_context,payload,p.expected_record_version,now)
        elif p.command_type in ("CreateOIAInspectionItem","UpdateOIAInspectionItem","MarkOIAInspectionItemBlocked"):
            handler=OIAInspectionItemHandler(u)
            if p.command_type=="CreateOIAInspectionItem":handler.create(raw_context,payload,now)
            elif p.command_type=="UpdateOIAInspectionItem":handler.update(raw_context,payload,p.expected_record_version,now)
            else:handler.block(raw_context,payload,p.expected_record_version,now)
        elif p.command_type in ("RecordOIAObservation","SupersedeOIAObservation"):
            handler=OIAObservationHandler(u)
            if p.command_type=="RecordOIAObservation":handler.record(raw_context,payload,p.engagement_id,now)
            else:handler.supersede(raw_context,payload,p.engagement_id,p.expected_record_version,now)
        elif p.command_type=="RecordOIARootCause":
            OIARootCauseHandler(u).record(raw_context,payload,p.engagement_id,p.expected_record_version,now)
        elif p.command_type in ("CreateOIAFinding","UpdateOIAFindingAnalysis","FinalizeOIAFinding"):
            handler=OIAFindingHandler(u)
            if p.command_type=="CreateOIAFinding":handler.create(raw_context,payload,p.engagement_id,now)
            elif p.command_type=="UpdateOIAFindingAnalysis":handler.update(raw_context,payload,p.engagement_id,p.expected_record_version,now)
            else:handler.finalize(raw_context,payload,p.engagement_id,p.expected_record_version,now)
        elif p.command_type=="CanonicalizeDiagnosticScope":
            s=u.diagnostic_scopes.get(p.tenant_id,p.subject_id)
            if not s or payload["diagnostic_scope_id"]!=p.subject_id or payload["scope_version"]!=s.get("scope_version") or s.get("status")!="REVIEW_PENDING":raise ValueError()
            digest=compute_canonical_scope_digest(s);existing=s.get("canonical_scope_digest")
            if existing is None:u.diagnostic_scopes.set_canonical_scope_digest(p.tenant_id,p.subject_id,payload["scope_version"],p.expected_record_version,digest)
            elif existing!=digest:raise CanonicalScopeDigestConflict()
        elif p.command_type=="ExpireAssessmentAccess":
            AssessmentAccessTerminalHandler(u).expire(raw_context,payload,now)
        elif p.command_type=="RevokeAssessmentAccess":
            AssessmentAccessTerminalHandler(u).revoke(raw_context,payload,now)
        elif p.command_type=="CloseAssessmentAccessForAgreementEnd":
            AssessmentAccessTerminalHandler(u).close_for_agreement_end(raw_context,payload,now)
        elif p.command_type=="RecordAssessmentAccessApproval":
            RecordAssessmentAccessApprovalHandler(u,self.pipeline).record(raw_context,payload,now,p.command_id,p.correlation_id,p.idempotency_key)
        elif p.command_type=="RecordHumanApproval":
            s=u.diagnostic_scopes.get(p.tenant_id,p.subject_id); role=payload["authority_role"]
            if not s or payload["diagnostic_scope_id"]!=p.subject_id or s.get("status")!="REVIEW_PENDING" or payload["scope_version"]!=s.get("scope_version") or payload["action_set_version"]!=s.get("action_set_version") or not s.get("canonical_scope_digest"):raise ValueError()
            if u.human_approvals.find_active_binding(p.tenant_id,p.subject_id,payload["scope_version"],role,s["canonical_scope_digest"],payload["action_set_version"]):raise ValueError("duplicate active authority")
            category="CLIENT_AUTHORITY" if role=="CLIENT_DECISION_AUTHORITY" else "SEKINFRA_AUTHORITY"
            u.human_approvals.save({"approval_id":p.command_id,"tenant_id":p.tenant_id,"engagement_id":s["engagement_id"],"subject_id":p.subject_id,"subject_version":s["scope_version"],"authority_role":role,"authority_category":category,"approving_principal_reference":raw_context.human_principal_reference,"approving_organization_reference":raw_context.human_organization_reference,"canonical_scope_digest":s["canonical_scope_digest"],"action_set_version":s["action_set_version"],"decision":"APPROVE","status":"ACTIVE","conditions":[],"effective_at":now,"correlation_id":p.correlation_id,"idempotency_key":p.idempotency_key})
        else:
            s=u.diagnostic_scopes.get(p.tenant_id,p.subject_id);a=payload["client_approval_reference"];b=payload["sekinfra_approval_reference"];x=u.human_approvals.get(p.tenant_id,a["reference_id"]);y=u.human_approvals.get(p.tenant_id,b["reference_id"])
            if not s or not s.get("canonical_scope_digest") or s["status"]!="REVIEW_PENDING" or not x or not y or x.get("authority_role")!="CLIENT_DECISION_AUTHORITY" or y.get("authority_role")!="SEKINFRA_ENGAGEMENT_AUTHORITY":raise ValueError()
            for z in (x,y):
                if z.get("status")!="ACTIVE" or z.get("subject_id")!=p.subject_id or z.get("subject_version")!=payload["scope_version"] or z.get("canonical_scope_digest")!=s["canonical_scope_digest"] or z.get("action_set_version")!=s.get("action_set_version"):raise ValueError()
            if payload["scope_content_digest"]!=s["canonical_scope_digest"]:raise ValueError()
            s.update(client_approval_reference=a,sekinfra_approval_reference=b,effective_at=now,record_version=s["record_version"]+1);u.diagnostic_scopes.mark_approved(s)
    def _event(self,p,u=None):
        typ={"AcceptAcquisitionHandoff":"engagement.handoff.accepted","OpenEngagement":"engagement.opened","SubmitDiagnosticScope":"diagnostic_scope.submitted","RecordHumanApproval":"human_approval.recorded","ApproveDiagnosticScope":"diagnostic_scope.approved","CanonicalizeDiagnosticScope":"diagnostic_scope.canonicalized","CreateAssessmentAccessProposal":"assessment_access.proposal_created","RecordAssessmentAccessApproval":"assessment_access.approval_recorded","IssueAssessmentAccessGrant":"assessment_access.grant_issued","VerifyAssessmentAccess":"assessment_access.verified_and_activated","ExpireAssessmentAccess":"assessment_access.expired","RevokeAssessmentAccess":"assessment_access.revoked","CloseAssessmentAccessForAgreementEnd":"assessment_access.closed","RecordDiagnosticAgreementAuthority":"diagnostic_agreement.authority_recorded","RecordDiagnosticPaymentVerification":"diagnostic_payment.verified","InvalidateDiagnosticPaymentVerification":"diagnostic_payment.invalidated","OpenOIAAssessment":"oia.assessment_opened","RecordOIAEvidence":"oia.evidence_recorded","RecordOIAObservation":"oia.observation_recorded","SupersedeOIAObservation":"oia.observation_superseded","RecordOIARootCause":"oia.root_cause_recorded","CreateOIAFinding":"oia.finding_created","UpdateOIAFindingAnalysis":"oia.finding_updated","FinalizeOIAFinding":"oia.finding_finalized","CreateOIAAssessmentPlan":"oia.assessment_plan_created","ReviseOIAAssessmentPlan":"oia.assessment_plan_revised","ReviewOIAAssessmentPlan":"oia.assessment_plan_reviewed","ApproveOIAAssessmentPlan":"oia.assessment_plan_approved","CreateOIAInspectionItem":"oia.inspection_item_created","UpdateOIAInspectionItem":"oia.inspection_item_progressed","MarkOIAInspectionItemBlocked":"oia.inspection_item_blocked"}[p.command_type]
        if p.command_type in ("RecordDiagnosticAgreementAuthority","RecordDiagnosticPaymentVerification","InvalidateDiagnosticPaymentVerification"):
            record=(u.diagnostic_agreement_authorities if p.command_type=="RecordDiagnosticAgreementAuthority" else u.diagnostic_payment_verifications).get(p.tenant_id,p.subject_id)
            meta={"commercial_authority_id":p.subject_id,"commercial_state":record.get("status",record.get("verification_status"))}
            return {"event_id":self.ids(),"event_type":typ,"event_schema_version":1,"tenant_id":p.tenant_id,"engagement_id":record["engagement_id"],"authoritative_subject_reference":{"reference_type":p.subject_type,"reference_id":p.subject_id},"authoritative_subject_version":record["record_version"],"occurred_at":self.clock(),"producer_reference":"command.service-01","correlation_id":p.correlation_id,"command_id":p.command_id,"subject_id":p.subject_id,"idempotency_key":p.idempotency_key,"visibility":"TENANT_OPERATIONAL","sanitized_metadata":meta}
        if p.command_type=="CreateAssessmentAccessProposal":
            return {"event_id":self.ids(),"event_type":typ,"event_schema_version":1,"tenant_id":p.tenant_id,"engagement_id":p.engagement_id,"authoritative_subject_reference":{"reference_type":"ASSESSMENT_ACCESS_PROPOSAL","reference_id":p.subject_id},"authoritative_subject_version":1,"occurred_at":self.clock(),"producer_reference":"command.service-01","correlation_id":p.correlation_id,"command_id":p.command_id,"subject_id":p.subject_id,"idempotency_key":p.idempotency_key,"visibility":"TENANT_OPERATIONAL","sanitized_metadata":{"assessment_access_proposal_id":p.subject_id}}
        if p.command_type in ("CreateOIAAssessmentPlan","ReviseOIAAssessmentPlan","ReviewOIAAssessmentPlan","ApproveOIAAssessmentPlan"):
            plan=u.oia_assessment_plans.get_current(p.tenant_id,p.subject_id)
            return {"event_id":self.ids(),"event_type":typ,"event_schema_version":1,"tenant_id":p.tenant_id,"engagement_id":plan["engagement_id"],"authoritative_subject_reference":{"reference_type":"OIA_ASSESSMENT_PLAN","reference_id":p.subject_id},"authoritative_subject_version":plan["record_version"],"occurred_at":self.clock(),"producer_reference":"command.service-01","correlation_id":p.correlation_id,"command_id":p.command_id,"subject_id":p.subject_id,"idempotency_key":p.idempotency_key,"visibility":"TENANT_OPERATIONAL","sanitized_metadata":{"oia_assessment_id":plan["oia_assessment_id"],"oia_assessment_plan_id":p.subject_id,"plan_version":plan["plan_version"]}}
        if p.command_type in ("CreateOIAInspectionItem","UpdateOIAInspectionItem","MarkOIAInspectionItemBlocked"):
            item=u.oia_inspection_items.get(p.tenant_id,p.subject_id)
            return {"event_id":self.ids(),"event_type":typ,"event_schema_version":1,"tenant_id":p.tenant_id,"engagement_id":item["engagement_id"],"authoritative_subject_reference":{"reference_type":"OIA_INSPECTION_ITEM","reference_id":p.subject_id},"authoritative_subject_version":item["record_version"],"occurred_at":self.clock(),"producer_reference":"command.service-01","correlation_id":p.correlation_id,"command_id":p.command_id,"subject_id":p.subject_id,"idempotency_key":p.idempotency_key,"visibility":"TENANT_OPERATIONAL","sanitized_metadata":{"oia_assessment_id":item["oia_assessment_id"],"oia_assessment_plan_id":item["oia_assessment_plan_id"],"oia_inspection_item_id":p.subject_id,"plan_version":item["plan_version"],"coverage_state":item["coverage_state"],"record_version":item["record_version"]}}
        if p.command_type in ("RecordOIAObservation","SupersedeOIAObservation"):
            observation=u.oia_observations.get(p.tenant_id,p.subject_id);assessment=u.oia_assessments.get(p.tenant_id,observation["oia_assessment_id"])
            return {"event_id":self.ids(),"event_type":typ,"event_schema_version":1,"tenant_id":p.tenant_id,"engagement_id":assessment["engagement_id"],"authoritative_subject_reference":{"reference_type":"OIA_OBSERVATION","reference_id":p.subject_id},"authoritative_subject_version":observation["record_version"],"occurred_at":self.clock(),"producer_reference":"command.service-01","correlation_id":p.correlation_id,"command_id":p.command_id,"subject_id":p.subject_id,"idempotency_key":p.idempotency_key,"visibility":"TENANT_OPERATIONAL","sanitized_metadata":{"oia_assessment_id":observation["oia_assessment_id"],"oia_observation_id":p.subject_id,"record_version":observation["record_version"]}}
        if p.command_type=="RecordOIARootCause":
            root_cause=u.oia_root_causes.get(p.tenant_id,p.subject_id);assessment=u.oia_assessments.get(p.tenant_id,root_cause["oia_assessment_id"])
            return {"event_id":self.ids(),"event_type":typ,"event_schema_version":1,"tenant_id":p.tenant_id,"engagement_id":assessment["engagement_id"],"authoritative_subject_reference":{"reference_type":"OIA_ROOT_CAUSE","reference_id":p.subject_id},"authoritative_subject_version":root_cause["record_version"],"occurred_at":self.clock(),"producer_reference":"command.service-01","correlation_id":p.correlation_id,"command_id":p.command_id,"subject_id":p.subject_id,"idempotency_key":p.idempotency_key,"visibility":"TENANT_OPERATIONAL","sanitized_metadata":{"oia_assessment_id":root_cause["oia_assessment_id"],"oia_root_cause_id":p.subject_id,"record_version":root_cause["record_version"]}}
        if p.command_type in ("CreateOIAFinding","UpdateOIAFindingAnalysis","FinalizeOIAFinding"):
            finding=u.oia_findings.get(p.tenant_id,p.subject_id);assessment=u.oia_assessments.get(p.tenant_id,finding["oia_assessment_id"])
            return {"event_id":self.ids(),"event_type":typ,"event_schema_version":1,"tenant_id":p.tenant_id,"engagement_id":assessment["engagement_id"],"authoritative_subject_reference":{"reference_type":"OIA_FINDING","reference_id":p.subject_id},"authoritative_subject_version":finding["finding_revision"],"occurred_at":self.clock(),"producer_reference":"command.service-01","correlation_id":p.correlation_id,"command_id":p.command_id,"subject_id":p.subject_id,"idempotency_key":p.idempotency_key,"visibility":"TENANT_OPERATIONAL","sanitized_metadata":{"oia_assessment_id":finding["oia_assessment_id"],"oia_finding_id":p.subject_id,"record_version":finding["finding_revision"]}}
        if p.command_type=="OpenOIAAssessment":
            assessment=u.oia_assessments.get(p.tenant_id,p.subject_id)
            return {"event_id":self.ids(),"event_type":typ,"event_schema_version":1,"tenant_id":p.tenant_id,"engagement_id":assessment["engagement_id"],"authoritative_subject_reference":{"reference_type":"OIA_ASSESSMENT","reference_id":p.subject_id},"authoritative_subject_version":assessment["record_version"],"occurred_at":self.clock(),"producer_reference":"command.service-01","correlation_id":p.correlation_id,"command_id":p.command_id,"subject_id":p.subject_id,"idempotency_key":p.idempotency_key,"visibility":"TENANT_OPERATIONAL","sanitized_metadata":{"oia_assessment_id":p.subject_id,"record_version":assessment["record_version"]}}
        if p.command_type=="IssueAssessmentAccessGrant":
            return {"event_id":self.ids(),"event_type":typ,"event_schema_version":1,"tenant_id":p.tenant_id,"engagement_id":p.engagement_id,"authoritative_subject_reference":{"reference_type":"ASSESSMENT_ACCESS_GRANT","reference_id":p.subject_id},"authoritative_subject_version":1,"occurred_at":self.clock(),"producer_reference":"command.service-01","correlation_id":p.correlation_id,"command_id":p.command_id,"subject_id":p.subject_id,"idempotency_key":p.idempotency_key,"visibility":"TENANT_OPERATIONAL","sanitized_metadata":{"assessment_access_grant_id":p.subject_id,"assessment_access_proposal_id":p.payload["assessment_access_proposal_id"]}}
        if p.command_type=="RecordOIAEvidence":
            evidence=u.oia_evidence_items.get(p.tenant_id,p.subject_id);assessment=u.oia_assessments.get(p.tenant_id,evidence["oia_assessment_id"])
            return {"event_id":self.ids(),"event_type":typ,"event_schema_version":1,"tenant_id":p.tenant_id,"engagement_id":assessment["engagement_id"],"authoritative_subject_reference":{"reference_type":"OIA_EVIDENCE_ITEM","reference_id":p.subject_id},"authoritative_subject_version":1,"occurred_at":self.clock(),"producer_reference":"command.service-01","correlation_id":p.correlation_id,"command_id":p.command_id,"subject_id":p.subject_id,"idempotency_key":p.idempotency_key,"visibility":"TENANT_OPERATIONAL","sanitized_metadata":{"oia_assessment_id":assessment["oia_assessment_id"],"oia_evidence_id":p.subject_id}}
        if p.command_type in ("ExpireAssessmentAccess","RevokeAssessmentAccess","CloseAssessmentAccessForAgreementEnd"):
            grant=u.assessment_access_grants.get(p.tenant_id,p.subject_id); metadata={"assessment_access_grant_id":p.subject_id,"terminal_state":grant["status"]}
            if p.command_type=="CloseAssessmentAccessForAgreementEnd":metadata["closure_cause"]="AGREEMENT_ENDED"
            return {"event_id":self.ids(),"event_type":typ,"event_schema_version":1,"tenant_id":p.tenant_id,"engagement_id":grant["engagement_id"],"authoritative_subject_reference":{"reference_type":"ASSESSMENT_ACCESS_GRANT","reference_id":p.subject_id},"authoritative_subject_version":grant["record_version"],"occurred_at":self.clock(),"producer_reference":"command.service-01","correlation_id":p.correlation_id,"command_id":p.command_id,"subject_id":p.subject_id,"idempotency_key":p.idempotency_key,"visibility":"TENANT_OPERATIONAL","sanitized_metadata":metadata}
        if p.command_type=="RecordAssessmentAccessApproval":
            return {"event_id":self.ids(),"event_type":typ,"event_schema_version":1,"tenant_id":p.tenant_id,"engagement_id":p.engagement_id,"authoritative_subject_reference":{"reference_type":"ASSESSMENT_ACCESS_PROPOSAL","reference_id":p.subject_id},"authoritative_subject_version":p.expected_record_version,"occurred_at":self.clock(),"producer_reference":"command.service-01","correlation_id":p.correlation_id,"command_id":p.command_id,"subject_id":p.subject_id,"idempotency_key":p.idempotency_key,"visibility":"TENANT_OPERATIONAL","sanitized_metadata":{"assessment_access_proposal_id":p.subject_id,"authority_role":p.payload["authority_role"],"approval_id":p.command_id}}
        if p.command_type=="VerifyAssessmentAccess":
            grant=u.assessment_access_grants.get(p.tenant_id,p.subject_id); proposal=grant["source_assessment_access_proposal_reference"]["reference_id"]
            return {"event_id":self.ids(),"event_type":typ,"event_schema_version":1,"tenant_id":p.tenant_id,"engagement_id":grant["engagement_id"],"authoritative_subject_reference":{"reference_type":"ASSESSMENT_ACCESS_GRANT","reference_id":p.subject_id},"authoritative_subject_version":grant["record_version"],"occurred_at":self.clock(),"producer_reference":"command.service-01","correlation_id":p.correlation_id,"command_id":p.command_id,"subject_id":p.subject_id,"idempotency_key":p.idempotency_key,"visibility":"TENANT_OPERATIONAL","sanitized_metadata":{"assessment_access_grant_id":p.subject_id,"assessment_access_proposal_id":proposal,"verified_at":grant["verified_at"],"active_from":grant["active_from"],"expires_at":grant["expires_at"]}}
        return {"event_id":self.ids(),"event_type":typ,"subject_id":p.subject_id,"tenant_id":p.tenant_id,"idempotency_key":p.idempotency_key}
