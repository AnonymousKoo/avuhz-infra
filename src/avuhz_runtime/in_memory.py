"""Development-only in-memory repositories and atomic Slice 1 executor; never production persistence."""
from __future__ import annotations
import copy, hashlib, json, uuid
from dataclasses import dataclass, field
from .guards import AuthoritativeSubjectSnapshot
from .models import ValidationFailure
from .runtime import prepare_and_guard_command

def fingerprint(command):
    value={k:command[k] for k in ("tenant_id","command_type","subject_type","subject_id","engagement_id","expected_record_version","payload") if k in command}
    return "fpv1:"+hashlib.sha256(json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()).hexdigest()
@dataclass
class MemoryStore:
    handoffs:dict=field(default_factory=dict); engagements:dict=field(default_factory=dict); scopes:dict=field(default_factory=dict); approvals:dict=field(default_factory=dict); idempotency:dict=field(default_factory=dict); events:list=field(default_factory=list); outbox:list=field(default_factory=list)
    fail_stage:str|None=None
    def snapshot(self,command):
        r={"ACQUISITION_HANDOFF":self.handoffs,"ENGAGEMENT":self.engagements,"DIAGNOSTIC_SCOPE":self.scopes}.get(command.subject_type,{ }).get(command.subject_id)
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
    def mark_approved(self,record):self.u.failpoint("AUTHORITATIVE_WRITE");record["status"]="APPROVED"
class HumanApprovalMemoryRepository(_TenantRepo):
    def __init__(self,u):super().__init__(u,"approvals")
class IdempotencyMemoryRepository:
    def __init__(self,u):self.u=u;self.data=u.working.idempotency
    def get(self,key):return self.data.get(key)
    def reserve(self,key):self.u.failpoint("IDEMPOTENCY_RESERVE")
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
        self.handoffs=AcquisitionHandoffMemoryRepository(self);self.engagements=EngagementMemoryRepository(self);self.diagnostic_scopes=DiagnosticScopeMemoryRepository(self);self.human_approvals=HumanApprovalMemoryRepository(self);self.idempotency=IdempotencyMemoryRepository(self);self.lifecycle_events=LifecycleEventMemoryRepository(self);self.outbox=OutboxMemoryRepository(self)
    def failpoint(self,name):
        if self.working.fail_stage==name: raise RuntimeError("injected failpoint")
    def commit(self):
        self.failpoint("COMMIT")
        self.store.__dict__.update(self.working.__dict__)
class Executor:
    def __init__(self,validator,pipeline,store,clock=lambda:"2030-01-15T15:00:00Z",ids=lambda:str(uuid.uuid4()),uow_factory=UnitOfWork):self.validator=validator;self.pipeline=pipeline;self.store=store;self.clock=clock;self.ids=ids;self.uow_factory=uow_factory
    def execute(self,raw,context):
        first=self.validator.prepare(raw)
        if isinstance(first,ValidationFailure):return {"result":"VALIDATION_FAILED","reason_code":first.reason.value}
        p=first.prepared; u=self.uow_factory(self.store); key=(p.tenant_id,context.principal_id,p.command_type,p.subject_type,p.subject_id,p.idempotency_key); fp=fingerprint(raw); prior=u.idempotency.get(key)
        if prior:return {"result":"DUPLICATE","reason_code":"DUPLICATE_REQUEST","prior_result_reference":prior["command_id"]} if prior["fingerprint"]==fp else {"result":"CONFLICT","reason_code":"IDEMPOTENCY_SEMANTIC_MISMATCH"}
        guarded=prepare_and_guard_command(self.validator,self.pipeline,raw,context,self.store.snapshot(p),self.clock())
        if not hasattr(guarded,"guarded"):return {"result":"REJECTED","reason_code":guarded.reason.value}
        try:
            u.idempotency.reserve(key);u.failpoint("AUTHORITATIVE_WRITE");self._handle(u,p,raw); event=self._event(p);u.lifecycle_events.append(event);u.outbox.append({"event_id":event["event_id"],"status":"PENDING"});u.idempotency.save_result(key,{"fingerprint":fp,"command_id":p.command_id});u.commit()
        except (ValueError,RuntimeError) as error:return {"result":"REJECTED","reason_code":"PREREQUISITE_STATE_INVALID"}
        return {"result":"ACCEPTED","reason_code":"COMMAND_ACCEPTED","authoritative_record_reference":p.subject_id}
    def _handle(self,u,p,raw):
        w=u.working; now=self.clock(); payload=p.payload
        if p.command_type=="AcceptAcquisitionHandoff":
            r=w.handoffs.get(p.subject_id)
            if not r or r.get("accepted"):raise ValueError()
            r["accepted"]=True;r["accepted_at"]=now
        elif p.command_type=="OpenEngagement":
            h=payload["accepted_handoff_reference"]; source=w.handoffs.get(h["reference_id"])
            if not source or not source.get("accepted") or h["reference_version"]!=source["handoff_version"]:raise ValueError()
            if p.subject_id in w.engagements or payload["canonical_account_reference"]!=source["canonical_account_reference"] or payload["acquisition_opportunity_reference"]!=source["acquisition_opportunity_reference"]:raise ValueError()
            w.engagements[p.subject_id]={"engagement_id":p.subject_id,"tenant_id":p.tenant_id,"engagement_state":"OPEN","record_version":1,"engagement_version":1,"opened_at":now,**payload}
        elif p.command_type=="SubmitDiagnosticScope":
            e=w.engagements.get(p.subject_id);sid=payload["proposed_diagnostic_scope_id"]
            if not e or e["engagement_state"] not in ("OPEN","ONBOARDING") or sid in w.scopes:raise ValueError()
            w.scopes[sid]={"diagnostic_scope_id":sid,"engagement_id":p.subject_id,"tenant_id":p.tenant_id,"scope_version":payload["scope_version"],"record_version":1,"status":"REVIEW_PENDING",**payload}
        else:
            s=w.scopes.get(p.subject_id);a=payload["client_approval_reference"];b=payload["sekinfra_approval_reference"];x=w.approvals.get(a["reference_id"]);y=w.approvals.get(b["reference_id"])
            if not s or s["status"]!="REVIEW_PENDING" or not x or not y or x.get("authority_category")!="CLIENT_AUTHORITY" or y.get("authority_category")!="SEKINFRA_AUTHORITY":raise ValueError()
            for z in (x,y):
                if z.get("status")!="ACTIVE" or z.get("tenant_id")!=p.tenant_id or z.get("subject_id")!=p.subject_id or z.get("subject_version")!=payload["scope_version"] or z["scope"]["scope_digest"]!=payload["scope_content_digest"]:raise ValueError()
            s.update(status="APPROVED",client_approval_reference=a,sekinfra_approval_reference=b,effective_at=now,record_version=s["record_version"]+1)
    def _event(self,p):
        typ={"AcceptAcquisitionHandoff":"engagement.handoff.accepted","OpenEngagement":"engagement.opened","SubmitDiagnosticScope":"diagnostic_scope.submitted","ApproveDiagnosticScope":"diagnostic_scope.approved"}[p.command_type]
        return {"event_id":self.ids(),"event_type":typ,"subject_id":p.subject_id,"tenant_id":p.tenant_id,"idempotency_key":p.idempotency_key}
