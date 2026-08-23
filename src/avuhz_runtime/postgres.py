"""PostgreSQL persistence adapter for Slice 1; connection details are injected."""
from __future__ import annotations
import json, os, uuid
import psycopg
from psycopg.rows import dict_row
from .guards import AuthoritativeSubjectSnapshot

def connection_factory_from_environment(name="AVUHZ_POSTGRES_DSN"):
    def factory():
        dsn = os.environ.get(name)
        if not dsn: raise RuntimeError("Postgres connection configuration is required")
        return psycopg.connect(dsn, autocommit=False, row_factory=dict_row)
    return factory

def _json(value): return json.dumps(value, separators=(",", ":"), sort_keys=True) if isinstance(value, (dict, list)) else value
def _load(value): return json.loads(value) if isinstance(value, str) and value[:1] in "[{" else value

class PostgresStore:
    def __init__(self, connection_factory): self.connection_factory = connection_factory
    def snapshot(self, command):
        queries = {"ACQUISITION_HANDOFF": ("select tenant_id, 1 as record_version, null::uuid as engagement_id, accepted_at from public.avuhz_acquisition_handoffs where tenant_id = %s and handoff_id = %s", "accepted_at"), "ENGAGEMENT": ("select tenant_id, record_version, null::uuid as engagement_id, engagement_state from public.avuhz_engagements where tenant_id = %s and engagement_id = %s", "engagement_state"), "DIAGNOSTIC_SCOPE": ("select tenant_id, record_version, engagement_id, status from public.avuhz_diagnostic_scopes where tenant_id = %s and diagnostic_scope_id = %s", "status")}
        query = queries.get(command.subject_type)
        if not query: return None
        sql, state = query
        conn = self.connection_factory()
        try:
            row = conn.execute(sql, (command.tenant_id, command.subject_id)).fetchone()
            if not row: return None
            return AuthoritativeSubjectSnapshot(command.subject_type, command.subject_id, str(row["tenant_id"]), row.get("record_version", 1), True, str(row["engagement_id"]) if row.get("engagement_id") else None, "ACCEPTED" if state == "accepted_at" and row[state] else row[state])
        finally: conn.close()

class _TenantRepository:
    table = ""; identifier = ""; columns = ""
    def __init__(self, uow): self.uow = uow
    def _one(self, sql, params): return self.uow.connection.execute(sql, params).fetchone()
    def get(self, tenant_id, record_id):
        row = self._one(f"select {self.columns} from public.{self.table} where tenant_id = %s and {self.identifier} = %s", (tenant_id, record_id))
        return self.map_row(row) if row else None

class AcquisitionHandoffPostgresRepository(_TenantRepository):
    table="avuhz_acquisition_handoffs"; identifier="handoff_id"; columns="tenant_id,handoff_id,handoff_version,canonical_account_reference,acquisition_opportunity_reference,accepted_at"
    def map_row(self, r):
        return {"handoff_id":str(r["handoff_id"]),"handoff_version":r["handoff_version"],"tenant_id":str(r["tenant_id"]),"canonical_account_reference":_load(r["canonical_account_reference"]),"acquisition_opportunity_reference":_load(r["acquisition_opportunity_reference"]),"accepted":r["accepted_at"] is not None,"accepted_at":r["accepted_at"],"record_version":1}
    def save_accepted(self, record):
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        cur=self.uow.connection.execute("update public.avuhz_acquisition_handoffs set accepted_at = %s where tenant_id = %s and handoff_id = %s and handoff_version = %s and accepted_at is null", (record["accepted_at"],record["tenant_id"],record["handoff_id"],record["handoff_version"]))
        if cur.rowcount != 1: raise ValueError("handoff acceptance conflict")

class EngagementPostgresRepository(_TenantRepository):
    table="avuhz_engagements"; identifier="engagement_id"; columns="tenant_id,engagement_id,engagement_state,record_version,engagement_version,opened_at"
    def map_row(self,r):
        return {"engagement_id":str(r["engagement_id"]),"tenant_id":str(r["tenant_id"]),"engagement_state":r["engagement_state"],"record_version":r["record_version"],"engagement_version":r["engagement_version"],"opened_at":r["opened_at"]}
    def exists(self, tenant_id, record_id): return self.get(tenant_id,record_id) is not None
    def save(self, record):
        self.uow.failpoint("AUTHORITATIVE_WRITE"); h=record["accepted_handoff_reference"]
        self.uow.connection.execute("insert into public.avuhz_engagements (engagement_id,tenant_id,acquisition_handoff_id,acquisition_handoff_version,account_reference,acquisition_opportunity_reference,engagement_type,engagement_state,engagement_version,record_version,opened_at) values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)", (record["engagement_id"],record["tenant_id"],h["reference_id"],h["reference_version"],_json(record["canonical_account_reference"]),_json(record["acquisition_opportunity_reference"]),record["engagement_type"],record["engagement_state"],record["engagement_version"],record["record_version"],record["opened_at"]))

class DiagnosticScopePostgresRepository(_TenantRepository):
    table="avuhz_diagnostic_scopes"; identifier="diagnostic_scope_id"; columns="tenant_id,diagnostic_scope_id,engagement_id,scope_version,record_version,status,canonical_scope_digest,action_set_version,target_outcome,in_scope_systems,excluded_systems,permitted_actions,prohibited_actions,assumptions,constraint_references"
    def map_row(self,r):
        return {"diagnostic_scope_id":str(r["diagnostic_scope_id"]),"engagement_id":str(r["engagement_id"]),"tenant_id":str(r["tenant_id"]),"scope_version":r["scope_version"],"record_version":r["record_version"],"status":r["status"],"canonical_scope_digest":r["canonical_scope_digest"],"action_set_version":r["action_set_version"],"target_outcome":r["target_outcome"],"in_scope_systems":_load(r["in_scope_systems"]),"excluded_systems":_load(r["excluded_systems"]),"permitted_diagnostic_actions":r["permitted_actions"],"prohibited_actions":r["prohibited_actions"],"assumptions":_load(r["assumptions"]),"constraints":_load(r["constraint_references"])}
    def save(self, record):
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        self.uow.connection.execute("insert into public.avuhz_diagnostic_scopes (diagnostic_scope_id,tenant_id,engagement_id,scope_version,record_version,status,canonical_scope_digest,action_set_version,target_outcome,in_scope_systems,excluded_systems,permitted_actions,prohibited_actions,assumptions,constraint_references,effective_at) values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,now())", (record["diagnostic_scope_id"],record["tenant_id"],record["engagement_id"],record["scope_version"],record["record_version"],record["status"],record.get("canonical_scope_digest"),record.get("action_set_version",1),record["target_outcome"],_json(record["in_scope_systems"]),_json(record["excluded_systems"]),record["permitted_diagnostic_actions"],record["prohibited_actions"],_json(record["assumptions"]),_json(record["constraints"])))
    def mark_approved(self, record):
        self.uow.failpoint("AUTHORITATIVE_WRITE"); expected=record["record_version"]-1
        cur=self.uow.connection.execute("update public.avuhz_diagnostic_scopes set status = 'APPROVED', effective_at = %s, record_version = %s, updated_at = now() where tenant_id = %s and diagnostic_scope_id = %s and record_version = %s", (record["effective_at"],record["record_version"],record["tenant_id"],record["diagnostic_scope_id"],expected))
        if cur.rowcount != 1: raise ValueError("scope concurrency conflict")
    def set_canonical_scope_digest(self, tenant_id, scope_id, scope_version, expected_record_version, digest):
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        cur=self.uow.connection.execute("update public.avuhz_diagnostic_scopes set canonical_scope_digest = %s, record_version = record_version + 1, updated_at = now() where tenant_id = %s and diagnostic_scope_id = %s and scope_version = %s and record_version = %s and canonical_scope_digest is null", (digest,tenant_id,scope_id,scope_version,expected_record_version))
        if cur.rowcount != 1: raise ValueError("scope canonicalization concurrency conflict")
        return digest

class HumanApprovalPostgresRepository(_TenantRepository):
    table="avuhz_human_approvals"; identifier="approval_id"; columns="tenant_id,approval_id,engagement_id,approval_role,authority_category,status,diagnostic_scope_id,approved_scope_version,canonical_scope_digest,action_set_version,approving_principal_reference,approving_organization_reference,decision"
    def map_row(self,r):
        return {"approval_id":str(r["approval_id"]),"tenant_id":str(r["tenant_id"]),"engagement_id":str(r["engagement_id"]),"authority_role":r["approval_role"],"authority_category":r["authority_category"],"status":r["status"],"subject_id":str(r["diagnostic_scope_id"]),"subject_version":r["approved_scope_version"],"canonical_scope_digest":r["canonical_scope_digest"],"action_set_version":r["action_set_version"],"approving_principal_reference":r["approving_principal_reference"],"approving_organization_reference":r["approving_organization_reference"],"decision":r["decision"]}
    def find_active_binding(self,tenant_id,scope_id,scope_version,authority_role,digest,action_set_version):
        row=self._one("select a.tenant_id,a.approval_id,a.engagement_id,a.approval_role,a.authority_category,a.status,a.diagnostic_scope_id,a.approved_scope_version,a.canonical_scope_digest,a.action_set_version,a.approving_principal_reference,a.approving_organization_reference,a.decision from public.avuhz_diagnostic_scopes s left join public.avuhz_human_approvals a on a.tenant_id=s.tenant_id and a.diagnostic_scope_id=s.diagnostic_scope_id and a.approved_scope_version=s.scope_version and a.approval_role=%s and a.canonical_scope_digest=%s and a.action_set_version=%s and a.status='ACTIVE' where s.tenant_id=%s and s.diagnostic_scope_id=%s and s.scope_version=%s for update of s",(authority_role,digest,action_set_version,tenant_id,scope_id,scope_version))
        return self.map_row(row) if row and row["approval_id"] else None
    def save(self,record):
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        self.uow.connection.execute("insert into public.avuhz_human_approvals (approval_id,tenant_id,engagement_id,diagnostic_scope_id,approved_scope_version,approval_role,authority_category,approving_principal_reference,approving_organization_reference,canonical_scope_digest,action_set_version,decision,status,conditions,effective_at,correlation_id,idempotency_key) values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",(record["approval_id"],record["tenant_id"],record["engagement_id"],record["subject_id"],record["subject_version"],record["authority_role"],record["authority_category"],record["approving_principal_reference"],record["approving_organization_reference"],record["canonical_scope_digest"],record["action_set_version"],record["decision"],record["status"],_json(record["conditions"]),record["effective_at"],record["correlation_id"],record["idempotency_key"]))

class IdempotencyPostgresRepository:
    def __init__(self,uow): self.uow=uow
    def get(self,key):
        r=self.uow.connection.execute("select semantic_request_fingerprint,result_reference from public.avuhz_idempotency_records where tenant_id=%s and trusted_principal_id=%s and command_type=%s and subject_type=%s and subject_id=%s and idempotency_key=%s",key).fetchone()
        return None if not r else {"fingerprint":r["semantic_request_fingerprint"],"command_id":r["result_reference"]}
    def reserve(self,key,fingerprint,prepared=None):
        self.uow.failpoint("IDEMPOTENCY_RESERVE"); tenant,principal,command,subject_type,subject_id,idem=key; version=getattr(prepared,"expected_record_version",None) or 1
        cur=self.uow.connection.execute("insert into public.avuhz_idempotency_records (id,tenant_id,trusted_principal_id,command_type,subject_type,subject_id,subject_version,idempotency_key,semantic_request_fingerprint,fingerprint_schema_version,processing_status,retention_class,attempt_count) values (%s,%s,%s,%s,%s,%s,%s,%s,%s,'v1','RESERVED','OPERATIONAL_DEDUPLICATION',0) on conflict (tenant_id,trusted_principal_id,command_type,subject_type,subject_id,idempotency_key) do nothing returning id",(str(uuid.uuid4()),tenant,principal,command,subject_type,subject_id,version,idem,fingerprint))
        if cur.fetchone(): return None
        return self.get(key)
    def save_result(self,key,result):
        self.uow.failpoint("IDEMPOTENCY_COMPLETE"); cur=self.uow.connection.execute("update public.avuhz_idempotency_records set processing_status='COMPLETED', result_reference=%s, completed_at=now(), record_version=record_version+1 where tenant_id=%s and trusted_principal_id=%s and command_type=%s and subject_type=%s and subject_id=%s and idempotency_key=%s",(result["command_id"],*key))
        if cur.rowcount != 1: raise ValueError("idempotency completion conflict")

class LifecycleEventPostgresRepository:
    def __init__(self,uow): self.uow=uow
    def append(self,event):
        self.uow.failpoint("LIFECYCLE_EVENT_APPEND"); self.uow.connection.execute("insert into public.avuhz_lifecycle_events (lifecycle_event_id,tenant_id,event_type,authoritative_subject_id,idempotency_key) values (%s,%s,%s,%s,%s)",(event["event_id"],event["tenant_id"],event["event_type"],event["subject_id"],event["idempotency_key"]))

class OutboxPostgresRepository:
    def __init__(self,uow): self.uow=uow
    def append(self,intent):
        self.uow.failpoint("OUTBOX_APPEND"); cur=self.uow.connection.execute("insert into public.avuhz_outbox_deliveries (tenant_id,lifecycle_event_id,status) select tenant_id,%s,%s from public.avuhz_lifecycle_events where lifecycle_event_id=%s",(intent["event_id"],intent["status"],intent["event_id"]))
        if cur.rowcount != 1: raise ValueError("outbox event missing")

class PostgresUnitOfWork:
    def __init__(self,store):
        self.store=store; self.connection=store.connection_factory(); self.connection.autocommit=False; self.fail_stage=getattr(store,"fail_stage",None)
        self.handoffs=AcquisitionHandoffPostgresRepository(self); self.engagements=EngagementPostgresRepository(self); self.diagnostic_scopes=DiagnosticScopePostgresRepository(self); self.human_approvals=HumanApprovalPostgresRepository(self); self.idempotency=IdempotencyPostgresRepository(self); self.lifecycle_events=LifecycleEventPostgresRepository(self); self.outbox=OutboxPostgresRepository(self)
    def failpoint(self,name):
        if self.fail_stage==name: raise RuntimeError("injected failpoint")
    def commit(self): self.failpoint("COMMIT"); self.connection.commit()
    def rollback(self): self.connection.rollback()
    def close(self): self.connection.close()
