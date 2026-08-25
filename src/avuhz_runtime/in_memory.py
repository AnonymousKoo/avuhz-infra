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

class CanonicalScopeDigestConflict(ValueError): pass
from .runtime import prepare_and_guard_command

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
    return "fpv1:"+hashlib.sha256(json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()).hexdigest()
@dataclass
class MemoryStore:
    handoffs:dict=field(default_factory=dict); engagements:dict=field(default_factory=dict); scopes:dict=field(default_factory=dict); approvals:dict=field(default_factory=dict); proposals:dict=field(default_factory=dict); grants:dict=field(default_factory=dict); agreements:dict=field(default_factory=dict); payments:dict=field(default_factory=dict); idempotency:dict=field(default_factory=dict); events:list=field(default_factory=list); outbox:list=field(default_factory=list)
    fail_stage:str|None=None
    def snapshot(self,command):
        records={"ACQUISITION_HANDOFF":self.handoffs,"ENGAGEMENT":self.engagements,"DIAGNOSTIC_SCOPE":self.scopes}.get(command.subject_type)
        r=self.proposals.get((command.tenant_id,command.subject_id)) if command.subject_type=="ASSESSMENT_ACCESS_PROPOSAL" else self.grants.get((command.tenant_id,command.subject_id)) if command.subject_type=="ASSESSMENT_ACCESS_GRANT" else (records or {}).get(command.subject_id)
        return None if not r else AuthoritativeSubjectSnapshot(command.subject_type,command.subject_id,r["tenant_id"],r.get("record_version",1),True,r.get("engagement_id"),r.get("status") or r.get("engagement_state"))
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
class DiagnosticPaymentVerificationMemoryRepository(_TenantRepo):
    def __init__(self,u):super().__init__(u,"payments")
    def save(self,record):self.data[record["diagnostic_payment_verification_id"]]=record

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
        self.handoffs=AcquisitionHandoffMemoryRepository(self);self.engagements=EngagementMemoryRepository(self);self.diagnostic_scopes=DiagnosticScopeMemoryRepository(self);self.diagnostic_agreement_authorities=DiagnosticAgreementAuthorityMemoryRepository(self);self.diagnostic_payment_verifications=DiagnosticPaymentVerificationMemoryRepository(self);self.assessment_access_proposals=AssessmentAccessProposalMemoryRepository(self);self.assessment_access_grants=AssessmentAccessGrantMemoryRepository(self);self.human_approvals=HumanApprovalMemoryRepository(self);self.idempotency=IdempotencyMemoryRepository(self);self.lifecycle_events=LifecycleEventMemoryRepository(self);self.outbox=OutboxMemoryRepository(self)
    def failpoint(self,name):
        if self.working.fail_stage==name: raise RuntimeError("injected failpoint")
    def commit(self):
        self.failpoint("COMMIT")
        self.store.__dict__.update(self.working.__dict__)
class Executor:
    def __init__(self,validator,pipeline,store,clock=lambda:"2030-01-15T15:00:00Z",ids=lambda:str(uuid.uuid4()),uow_factory=UnitOfWork,assessment_access_verifier=None):self.validator=validator;self.pipeline=pipeline;self.store=store;self.clock=clock;self.ids=ids;self.uow_factory=uow_factory;self.assessment_access_verifier=assessment_access_verifier or InMemoryAssessmentAccessVerifier()
    def execute(self,raw,context):
        first=self.validator.prepare(raw)
        if isinstance(first,ValidationFailure):return {"result":"VALIDATION_FAILED","reason_code":first.reason.value}
        p=first.prepared; u=self.uow_factory(self.store); key=(p.tenant_id,context.principal_id,p.command_type,p.subject_type,p.subject_id,p.idempotency_key); fp=fingerprint(raw); prior=u.idempotency.get(key)
        if prior:getattr(u,"rollback",lambda:None)();getattr(u,"close",lambda:None)();return {"result":"DUPLICATE","reason_code":"DUPLICATE_REQUEST","prior_result_reference":prior["command_id"]} if prior["fingerprint"]==fp else {"result":"CONFLICT","reason_code":"IDEMPOTENCY_SEMANTIC_MISMATCH"}
        guarded=prepare_and_guard_command(self.validator,self.pipeline,raw,context,self.store.snapshot(p),self.clock())
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
        elif p.command_type=="CreateAssessmentAccessProposal":
            CreateAssessmentAccessProposalHandler(u).create(raw_context,payload,now)
        elif p.command_type=="VerifyAssessmentAccess":
            VerifyAssessmentAccessHandler(u,self.assessment_access_verifier).verify(raw_context,payload,now)
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
        typ={"AcceptAcquisitionHandoff":"engagement.handoff.accepted","OpenEngagement":"engagement.opened","SubmitDiagnosticScope":"diagnostic_scope.submitted","RecordHumanApproval":"human_approval.recorded","ApproveDiagnosticScope":"diagnostic_scope.approved","CanonicalizeDiagnosticScope":"diagnostic_scope.canonicalized","CreateAssessmentAccessProposal":"assessment_access.proposal_created","RecordAssessmentAccessApproval":"assessment_access.approval_recorded","IssueAssessmentAccessGrant":"assessment_access.grant_issued","VerifyAssessmentAccess":"assessment_access.verified_and_activated","ExpireAssessmentAccess":"assessment_access.expired","RevokeAssessmentAccess":"assessment_access.revoked","CloseAssessmentAccessForAgreementEnd":"assessment_access.closed"}[p.command_type]
        if p.command_type=="CreateAssessmentAccessProposal":
            return {"event_id":self.ids(),"event_type":typ,"event_schema_version":1,"tenant_id":p.tenant_id,"engagement_id":p.engagement_id,"authoritative_subject_reference":{"reference_type":"ASSESSMENT_ACCESS_PROPOSAL","reference_id":p.subject_id},"authoritative_subject_version":1,"occurred_at":self.clock(),"producer_reference":"command.service-01","correlation_id":p.correlation_id,"command_id":p.command_id,"subject_id":p.subject_id,"idempotency_key":p.idempotency_key,"visibility":"TENANT_OPERATIONAL","sanitized_metadata":{"assessment_access_proposal_id":p.subject_id}}
        if p.command_type=="IssueAssessmentAccessGrant":
            return {"event_id":self.ids(),"event_type":typ,"event_schema_version":1,"tenant_id":p.tenant_id,"engagement_id":p.engagement_id,"authoritative_subject_reference":{"reference_type":"ASSESSMENT_ACCESS_GRANT","reference_id":p.subject_id},"authoritative_subject_version":1,"occurred_at":self.clock(),"producer_reference":"command.service-01","correlation_id":p.correlation_id,"command_id":p.command_id,"subject_id":p.subject_id,"idempotency_key":p.idempotency_key,"visibility":"TENANT_OPERATIONAL","sanitized_metadata":{"assessment_access_grant_id":p.subject_id,"assessment_access_proposal_id":p.payload["assessment_access_proposal_id"]}}
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
