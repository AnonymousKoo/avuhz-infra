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
        queries = {"ACQUISITION_HANDOFF": ("select tenant_id, 1 as record_version, null::uuid as engagement_id, accepted_at from public.avuhz_acquisition_handoffs where tenant_id = %s and handoff_id = %s", "accepted_at"), "ENGAGEMENT": ("select tenant_id, record_version, null::uuid as engagement_id, engagement_state from public.avuhz_engagements where tenant_id = %s and engagement_id = %s", "engagement_state"), "DIAGNOSTIC_SCOPE": ("select tenant_id, record_version, engagement_id, status from public.avuhz_diagnostic_scopes where tenant_id = %s and diagnostic_scope_id = %s", "status"), "DIAGNOSTIC_AGREEMENT_AUTHORITY": ("select tenant_id, record_version, engagement_id, status from public.avuhz_diagnostic_agreement_authorities where tenant_id = %s and diagnostic_agreement_authority_id = %s", "status"), "DIAGNOSTIC_PAYMENT_VERIFICATION": ("select tenant_id, record_version, engagement_id, verification_status as status from public.avuhz_diagnostic_payment_verifications where tenant_id = %s and diagnostic_payment_verification_id = %s", "status"), "ASSESSMENT_ACCESS_PROPOSAL": ("select tenant_id, record_version, engagement_id, status from public.avuhz_assessment_access_proposals where tenant_id = %s and assessment_access_proposal_id = %s", "status"), "ASSESSMENT_ACCESS_GRANT": ("select tenant_id, record_version, engagement_id, status from public.avuhz_assessment_access_grants where tenant_id = %s and assessment_access_grant_id = %s", "status")}
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

    def find_active_assessment_access_binding(self,tenant_id,proposal_id,digest,authority_role):
        rows=self.list_active_assessment_access_bindings(tenant_id,proposal_id,digest,authority_role);return rows[0] if rows else None
    def list_active_assessment_access_bindings(self,tenant_id,proposal_id,digest,authority_role):
        rows=self.uow.connection.execute("select * from public.avuhz_human_approvals where tenant_id=%s and subject_type='ASSESSMENT_ACCESS_PROPOSAL' and assessment_access_proposal_id=%s and assessment_access_authority_digest=%s and actor_role=%s and status='ACTIVE'",(tenant_id,proposal_id,digest,authority_role)).fetchall()
        return tuple(self._assessment(row) for row in rows)
    def _assessment(self,r):
        return {"approval_id":str(r["approval_id"]),"tenant_id":str(r["tenant_id"]),"engagement_id":str(r["engagement_id"]),"subject_type":r["subject_type"],"subject_id":str(r["subject_id"]),"approval_category":r["approval_category"],"authority_category":r["authority_category"],"actor_identity":r["actor_identity"],"actor_organization":r["actor_organization"],"actor_role":r["actor_role"],"decision":r["decision"],"status":r["status"],"assessment_access":{"assessment_access_proposal_id":str(r["assessment_access_proposal_id"]),"assessment_access_authority_digest":r["assessment_access_authority_digest"]},"conditions":[],"effective_at":r["effective_at"],"correlation_id":r["correlation_id"],"idempotency_key":r["idempotency_key"]}
    def record_assessment_access(self,record):
        self.uow.failpoint("AUTHORITATIVE_WRITE");a=record["assessment_access"]
        cur=self.uow.connection.execute("insert into public.avuhz_human_approvals (approval_id,tenant_id,engagement_id,approval_role,authority_category,status,subject_type,subject_id,approval_category,assessment_access_proposal_id,assessment_access_authority_digest,actor_identity,actor_organization,actor_role,decision,conditions,effective_at,correlation_id,idempotency_key) values (%s,%s,%s,%s,%s,%s,'ASSESSMENT_ACCESS_PROPOSAL',%s,'ASSESSMENT_ACCESS',%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) on conflict do nothing returning approval_id",(record["approval_id"],record["tenant_id"],record["engagement_id"],record["actor_role"],record["authority_category"],record["status"],record["subject_id"],a["assessment_access_proposal_id"],a["assessment_access_authority_digest"],record["actor_identity"],record["actor_organization"],record["actor_role"],record["decision"],_json(record["conditions"]),record["effective_at"],record["correlation_id"],record["idempotency_key"]))
        if not cur.fetchone():raise ValueError("duplicate active assessment access authority")

def _time(v):return v.isoformat().replace("+00:00","Z") if hasattr(v,"isoformat") else v

class DiagnosticAgreementAuthorityPostgresRepository(_TenantRepository):
    table="avuhz_diagnostic_agreement_authorities";identifier="diagnostic_agreement_authority_id";columns="tenant_id,diagnostic_agreement_authority_id,engagement_id,agreement_type,agreement_reference,status,diagnostic_scope_id,scope_version,canonical_scope_digest,effective_at,ends_at,verified_at,recorded_at,record_version"
    def map_row(self,r):
        return {"diagnostic_agreement_authority_id":str(r["diagnostic_agreement_authority_id"]),"tenant_id":str(r["tenant_id"]),"engagement_id":str(r["engagement_id"]),"agreement_type":r["agreement_type"],"agreement_reference":r["agreement_reference"],"status":r["status"],"scope_reference":{"reference_type":"DIAGNOSTIC_SCOPE","reference_id":str(r["diagnostic_scope_id"]),"reference_version":r["scope_version"]},"canonical_scope_digest":r["canonical_scope_digest"],"effective_at":_time(r["effective_at"]),"verified_at":_time(r["verified_at"]),"recorded_at":_time(r["recorded_at"]),"record_version":r["record_version"],**({"ends_at":_time(r["ends_at"])} if r["ends_at"] else {})}
    def create(self,x):
        self.uow.failpoint("AUTHORITATIVE_WRITE");s=x["scope_reference"];cur=self.uow.connection.execute("insert into public.avuhz_diagnostic_agreement_authorities (diagnostic_agreement_authority_id,tenant_id,engagement_id,agreement_type,agreement_reference,status,diagnostic_scope_id,scope_version,canonical_scope_digest,effective_at,ends_at,verified_at,recorded_at,record_version) values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) on conflict do nothing returning diagnostic_agreement_authority_id",(x["diagnostic_agreement_authority_id"],x["tenant_id"],x["engagement_id"],x["agreement_type"],x["agreement_reference"],x["status"],s["reference_id"],s["reference_version"],x["canonical_scope_digest"],x["effective_at"],x.get("ends_at"),x["verified_at"],x["recorded_at"],x["record_version"]))
        if not cur.fetchone():raise ValueError("diagnostic agreement authority identity conflicts")
        return x.copy()

class DiagnosticPaymentVerificationPostgresRepository(_TenantRepository):
    table="avuhz_diagnostic_payment_verifications";identifier="diagnostic_payment_verification_id";columns="tenant_id,diagnostic_payment_verification_id,engagement_id,diagnostic_agreement_authority_id,diagnostic_agreement_authority_version,payment_purpose,verification_status,provider_reference,amount_minor,currency,verified_at,invalidated_at,record_version"
    def map_row(self,r):
        return {"diagnostic_payment_verification_id":str(r["diagnostic_payment_verification_id"]),"tenant_id":str(r["tenant_id"]),"engagement_id":str(r["engagement_id"]),"diagnostic_agreement_authority_reference":{"reference_type":"DIAGNOSTIC_AGREEMENT_AUTHORITY","reference_id":str(r["diagnostic_agreement_authority_id"]),"reference_version":r["diagnostic_agreement_authority_version"]},"payment_purpose":r["payment_purpose"],"verification_status":r["verification_status"],"provider_reference":r["provider_reference"],"amount_minor":r["amount_minor"],"currency":r["currency"],"verified_at":_time(r["verified_at"]),"record_version":r["record_version"],**({"invalidated_at":_time(r["invalidated_at"])} if r["invalidated_at"] else {})}
    def create(self,x):
        self.uow.failpoint("AUTHORITATIVE_WRITE");a=x["diagnostic_agreement_authority_reference"];cur=self.uow.connection.execute("insert into public.avuhz_diagnostic_payment_verifications (diagnostic_payment_verification_id,tenant_id,engagement_id,diagnostic_agreement_authority_id,diagnostic_agreement_authority_version,payment_purpose,verification_status,provider_reference,amount_minor,currency,verified_at,record_version) values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) on conflict do nothing returning diagnostic_payment_verification_id",(x["diagnostic_payment_verification_id"],x["tenant_id"],x["engagement_id"],a["reference_id"],a["reference_version"],x["payment_purpose"],x["verification_status"],x["provider_reference"],x["amount_minor"],x["currency"],x["verified_at"],x["record_version"]))
        if not cur.fetchone():raise ValueError("diagnostic payment verification identity conflicts")
        return x.copy()
    def invalidate(self,t,i,at):
        x=self.get(t,i)
        if not x or x["verification_status"]!="VERIFIED":raise ValueError("payment is not invalidatable")
        self.uow.failpoint("AUTHORITATIVE_WRITE");cur=self.uow.connection.execute("update public.avuhz_diagnostic_payment_verifications set verification_status='INVALIDATED',invalidated_at=%s,record_version=record_version+1 where tenant_id=%s and diagnostic_payment_verification_id=%s and verification_status='VERIFIED' and record_version=%s",(at,t,i,x["record_version"]))
        if cur.rowcount!=1:raise ValueError("payment invalidation conflict")
        return self.get(t,i)

class AssessmentAccessProposalPostgresRepository(_TenantRepository):
    table="avuhz_assessment_access_proposals";identifier="assessment_access_proposal_id";columns="tenant_id,assessment_access_proposal_id,engagement_id,diagnostic_scope_id,scope_version,canonical_scope_digest,assessment_access_authority_digest,action_set_version,diagnostic_agreement_authority_id,diagnostic_agreement_authority_version,diagnostic_payment_verification_id,diagnostic_payment_verification_version,target_system_references,permitted_actions,status,consumed_at,record_version,created_at"
    def map_row(self,r):
        return _proposal_row(r)
    def create(self,x):
        self.uow.failpoint("AUTHORITATIVE_WRITE");_insert_proposal(self.uow.connection,x)
        return x.copy()
    def consume(self,t,i,d,at):
        x=self.get(t,i)
        if not x or x["status"]!="OPEN" or x["assessment_access_authority_digest"]!=d:raise ValueError("proposal is not consumable")
        self.uow.failpoint("AUTHORITATIVE_WRITE");cur=self.uow.connection.execute("update public.avuhz_assessment_access_proposals set status='CONSUMED',consumed_at=%s,record_version=record_version+1 where tenant_id=%s and assessment_access_proposal_id=%s and status='OPEN' and record_version=%s and assessment_access_authority_digest=%s",(at,t,i,x["record_version"],d))
        if cur.rowcount!=1:raise ValueError("proposal consumption conflict")
        return self.get(t,i)

def _proposal_row(r):
    return {"assessment_access_proposal_id":str(r["assessment_access_proposal_id"]),"tenant_id":str(r["tenant_id"]),"engagement_id":str(r["engagement_id"]),"diagnostic_scope_reference":{"reference_type":"DIAGNOSTIC_SCOPE","reference_id":str(r["diagnostic_scope_id"]),"reference_version":r["scope_version"]},"canonical_scope_digest":r["canonical_scope_digest"],"assessment_access_authority_digest":r["assessment_access_authority_digest"],"action_set_version":r["action_set_version"],"diagnostic_agreement_authority_reference":{"reference_type":"DIAGNOSTIC_AGREEMENT_AUTHORITY","reference_id":str(r["diagnostic_agreement_authority_id"]),"reference_version":r["diagnostic_agreement_authority_version"]},"diagnostic_payment_verification_reference":{"reference_type":"DIAGNOSTIC_PAYMENT_VERIFICATION","reference_id":str(r["diagnostic_payment_verification_id"]),"reference_version":r["diagnostic_payment_verification_version"]},"target_system_references":_load(r["target_system_references"]),"permitted_actions":list(r["permitted_actions"]),"status":r["status"],"record_version":r["record_version"],"created_at":_time(r["created_at"]),**({"consumed_at":_time(r["consumed_at"])} if r["consumed_at"] else {})}
def _insert_proposal(c,x):
    s=x["diagnostic_scope_reference"];a=x["diagnostic_agreement_authority_reference"];p=x["diagnostic_payment_verification_reference"];cur=c.execute("insert into public.avuhz_assessment_access_proposals (assessment_access_proposal_id,tenant_id,engagement_id,diagnostic_scope_id,scope_version,canonical_scope_digest,assessment_access_authority_digest,action_set_version,diagnostic_agreement_authority_id,diagnostic_agreement_authority_version,diagnostic_payment_verification_id,diagnostic_payment_verification_version,target_system_references,permitted_actions,status,consumed_at,record_version,created_at) values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) on conflict do nothing returning assessment_access_proposal_id",(x["assessment_access_proposal_id"],x["tenant_id"],x["engagement_id"],s["reference_id"],s["reference_version"],x["canonical_scope_digest"],x["assessment_access_authority_digest"],x["action_set_version"],a["reference_id"],a["reference_version"],p["reference_id"],p["reference_version"],_json(x["target_system_references"]),x["permitted_actions"],x["status"],x.get("consumed_at"),x["record_version"],x["created_at"]))
    if not cur.fetchone():raise ValueError("assessment access proposal identity conflicts")

class AssessmentAccessGrantPostgresRepository(_TenantRepository):
    table="avuhz_assessment_access_grants";identifier="assessment_access_grant_id";columns="tenant_id,assessment_access_grant_id,engagement_id,source_assessment_access_proposal_id,source_assessment_access_proposal_version,diagnostic_scope_id,scope_version,canonical_scope_digest,assessment_access_authority_digest,action_set_version,diagnostic_agreement_authority_id,diagnostic_agreement_authority_version,diagnostic_payment_verification_id,diagnostic_payment_verification_version,target_system_references,permitted_actions,status,approved_at,verified_at,active_from,expires_at,revoked_at,closed_at,closure_reason,record_version"
    def map_row(self,r):return _grant_row(r)
    def create(self,x):
        self.uow.failpoint("AUTHORITATIVE_WRITE");s=x["diagnostic_scope_reference"];q=x["source_assessment_access_proposal_reference"];a=x["diagnostic_agreement_authority_reference"];p=x["diagnostic_payment_verification_reference"];cur=self.uow.connection.execute("insert into public.avuhz_assessment_access_grants (assessment_access_grant_id,tenant_id,engagement_id,source_assessment_access_proposal_id,source_assessment_access_proposal_version,diagnostic_scope_id,scope_version,canonical_scope_digest,assessment_access_authority_digest,action_set_version,diagnostic_agreement_authority_id,diagnostic_agreement_authority_version,diagnostic_payment_verification_id,diagnostic_payment_verification_version,target_system_references,permitted_actions,status,approved_at,record_version) values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'APPROVED',%s,%s) on conflict do nothing returning assessment_access_grant_id",(x["assessment_access_grant_id"],x["tenant_id"],x["engagement_id"],q["reference_id"],q["reference_version"],s["reference_id"],s["reference_version"],x["canonical_scope_digest"],x["assessment_access_authority_digest"],x["action_set_version"],a["reference_id"],a["reference_version"],p["reference_id"],p["reference_version"],_json(x["target_system_references"]),x["permitted_actions"],x["approved_at"],x["record_version"]))
        if not cur.fetchone():raise ValueError("assessment access grant identity or source conflicts")
        return x.copy()
    def activate(self,t,i,d,v,e):
        x=self.get(t,i)
        if not x or x["status"]!="APPROVED" or x["assessment_access_authority_digest"]!=d:raise ValueError("grant is not activatable")
        return self._transition(t,i,x,"ACTIVE","verified_at=%s,active_from=%s,expires_at=%s",(v,v,e))
    def expire(self,t,i,now):
        x=self.get(t,i)
        if not x or x["status"]!="ACTIVE" or now<x["expires_at"]:raise ValueError("grant is not expirable")
        return self._transition(t,i,x,"EXPIRED","",())
    def revoke(self,t,i,now):
        x=self.get(t,i)
        if not x or x["status"] not in ("APPROVED","ACTIVE"):raise ValueError("grant is not revocable")
        return self._transition(t,i,x,"REVOKED","revoked_at=%s",(now,))
    def close_for_agreement_end(self,t,i,now):
        x=self.get(t,i)
        if not x or x["status"] not in ("APPROVED","ACTIVE"):raise ValueError("grant is not closable")
        return self._transition(t,i,x,"CLOSED","closed_at=%s,closure_reason='AGREEMENT_ENDED'",(now,))
    def _transition(self,t,i,x,status,fields,values):
        self.uow.failpoint("AUTHORITATIVE_WRITE"); assignments="status=%s" + ("," + fields if fields else "") + ",record_version=record_version+1";cur=self.uow.connection.execute(f"update public.avuhz_assessment_access_grants set {assignments} where tenant_id=%s and assessment_access_grant_id=%s and status=%s and record_version=%s",(status,*values,t,i,x["status"],x["record_version"]))
        if cur.rowcount!=1:raise ValueError("grant transition conflict")
        return self.get(t,i)

def _grant_row(r):
    x={"assessment_access_grant_id":str(r["assessment_access_grant_id"]),"tenant_id":str(r["tenant_id"]),"engagement_id":str(r["engagement_id"]),"source_assessment_access_proposal_reference":{"reference_type":"ASSESSMENT_ACCESS_PROPOSAL","reference_id":str(r["source_assessment_access_proposal_id"]),"reference_version":r["source_assessment_access_proposal_version"]},"diagnostic_scope_reference":{"reference_type":"DIAGNOSTIC_SCOPE","reference_id":str(r["diagnostic_scope_id"]),"reference_version":r["scope_version"]},"canonical_scope_digest":r["canonical_scope_digest"],"assessment_access_authority_digest":r["assessment_access_authority_digest"],"action_set_version":r["action_set_version"],"diagnostic_agreement_authority_reference":{"reference_type":"DIAGNOSTIC_AGREEMENT_AUTHORITY","reference_id":str(r["diagnostic_agreement_authority_id"]),"reference_version":r["diagnostic_agreement_authority_version"]},"diagnostic_payment_verification_reference":{"reference_type":"DIAGNOSTIC_PAYMENT_VERIFICATION","reference_id":str(r["diagnostic_payment_verification_id"]),"reference_version":r["diagnostic_payment_verification_version"]},"target_system_references":_load(r["target_system_references"]),"permitted_actions":list(r["permitted_actions"]),"status":r["status"],"approved_at":_time(r["approved_at"]),"record_version":r["record_version"]}
    for k in ("verified_at","active_from","expires_at","revoked_at","closed_at","closure_reason"):
        if r[k] is not None:x[k]=_time(r[k])
    return x

class IdempotencyPostgresRepository:
    def __init__(self,uow): self.uow=uow
    def _scope_key(self,key):
        tenant,principal,command,subject_type,scope,idem=key
        return key if scope == "COMMAND" or str(scope).startswith("SUBJECT:") else (tenant,principal,command,subject_type,"SUBJECT:"+str(scope),idem)
    def get(self,key):
        key=self._scope_key(key)
        r=self.uow.connection.execute("select semantic_request_fingerprint,result_reference from public.avuhz_idempotency_records where tenant_id=%s and trusted_principal_id=%s and command_type=%s and subject_type=%s and idempotency_scope=%s and idempotency_key=%s",key).fetchone()
        return None if not r else {"fingerprint":r["semantic_request_fingerprint"],"command_id":r["result_reference"]}
    def reserve(self,key,fingerprint,prepared=None):
        key=self._scope_key(key)
        self.uow.failpoint("IDEMPOTENCY_RESERVE"); tenant,principal,command,subject_type,scope,idem=key; version=getattr(prepared,"expected_record_version",None) or 1
        cur=self.uow.connection.execute("insert into public.avuhz_idempotency_records (id,tenant_id,trusted_principal_id,command_type,subject_type,subject_id,subject_version,idempotency_key,semantic_request_fingerprint,fingerprint_schema_version,processing_status,retention_class,attempt_count) values (%s,%s,%s,%s,%s,%s,%s,%s,%s,'v1','RESERVED','OPERATIONAL_DEDUPLICATION',0) on conflict (tenant_id,trusted_principal_id,command_type,subject_type,idempotency_scope,idempotency_key) do nothing returning id",(str(uuid.uuid4()),tenant,principal,command,subject_type,prepared.subject_id,version,idem,fingerprint))
        if cur.fetchone(): return None
        return self.get(key)
    def save_result(self,key,result):
        key=self._scope_key(key)
        self.uow.failpoint("IDEMPOTENCY_COMPLETE"); cur=self.uow.connection.execute("update public.avuhz_idempotency_records set processing_status='COMPLETED', result_reference=%s, completed_at=now(), record_version=record_version+1 where tenant_id=%s and trusted_principal_id=%s and command_type=%s and subject_type=%s and idempotency_scope=%s and idempotency_key=%s",(result["command_id"],*key))
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
    def __init__(self,store,trusted_context=None):
        self.store=store; self.connection=store.connection_factory(); self.connection.autocommit=False; self.fail_stage=getattr(store,"fail_stage",None); self.trusted_tenant_id=None
        if trusted_context is not None:self.bind_trusted_context(trusted_context)
        self.handoffs=AcquisitionHandoffPostgresRepository(self); self.engagements=EngagementPostgresRepository(self); self.diagnostic_scopes=DiagnosticScopePostgresRepository(self); self.diagnostic_agreement_authorities=DiagnosticAgreementAuthorityPostgresRepository(self); self.diagnostic_payment_verifications=DiagnosticPaymentVerificationPostgresRepository(self); self.assessment_access_proposals=AssessmentAccessProposalPostgresRepository(self); self.assessment_access_grants=AssessmentAccessGrantPostgresRepository(self); self.human_approvals=HumanApprovalPostgresRepository(self); self.idempotency=IdempotencyPostgresRepository(self); self.lifecycle_events=LifecycleEventPostgresRepository(self); self.outbox=OutboxPostgresRepository(self)
    def bind_trusted_context(self,context):
        if not getattr(context,"authenticated",False) or not getattr(context,"tenant_id",None):raise ValueError("trusted tenant context is required")
        tenant=str(uuid.UUID(str(context.tenant_id)))
        self.connection.execute("select set_config('avuhz.tenant_id',%s,true)",(tenant,));self.trusted_tenant_id=tenant
    def failpoint(self,name):
        if self.fail_stage==name: raise RuntimeError("injected failpoint")
    def commit(self): self.failpoint("COMMIT"); self.connection.commit()
    def rollback(self): self.connection.rollback()
    def close(self): self.connection.close()
