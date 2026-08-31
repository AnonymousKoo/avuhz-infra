"""PostgreSQL persistence adapter for Slice 1; connection details are injected."""
from __future__ import annotations
import copy, json, os, uuid
import psycopg
from psycopg.rows import dict_row
from .guards import AuthoritativeSubjectSnapshot
from .postgres_phase5d_brief import ImplementationBriefPostgresRepository
from .postgres_phase5d_authorization import ImplementationAuthorizationPostgresRepository
from .postgres_phase5d_package import CodexBuildPackagePostgresRepository
from .postgres_phase5d_build_execution import BuildExecutionResultPostgresRepository
from .postgres_phase5d_qa_result import QAResultPostgresRepository

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
    def snapshot(self, command, trusted_context=None):
        queries = {
            "ACQUISITION_HANDOFF": ("select tenant_id,1 as record_version,null::uuid as engagement_id,accepted_at from public.avuhz_acquisition_handoffs where tenant_id=%s and handoff_id=%s", "accepted_at"),
            "ENGAGEMENT": ("select tenant_id,record_version,null::uuid as engagement_id,engagement_state from public.avuhz_engagements where tenant_id=%s and engagement_id=%s", "engagement_state"),
            "IMPLEMENTATION_BRIEF": ("select tenant_id,record_version,engagement_id,state from public.avuhz_implementation_briefs where tenant_id=%s and implementation_brief_id=%s and state<>'SUPERSEDED' order by implementation_brief_version desc limit 1", "state"),
            "IMPLEMENTATION_AUTHORIZATION": ("select tenant_id,record_version,engagement_id,state from public.avuhz_implementation_authorizations where tenant_id=%s and implementation_authorization_id=%s and state<>'SUPERSEDED' order by authorization_version desc limit 1", "state"),
            "CODEX_BUILD_PACKAGE": ("select tenant_id,record_version,engagement_id,state from public.avuhz_codex_build_packages where tenant_id=%s and codex_build_package_id=%s and state<>'SUPERSEDED' order by package_version desc limit 1", "state"),
            "BUILD_EXECUTION_RESULT": ("select tenant_id,record_version,engagement_id,status as state from public.avuhz_build_execution_results where tenant_id=%s and build_execution_result_id=%s", "state"),
            "QA_RESULT": ("select tenant_id,record_version,engagement_id,overall_status as state from public.avuhz_qa_results where tenant_id=%s and qa_result_id=%s", "state"),
        }
        query = queries.get(command.subject_type)
        subject_id = command.subject_id
        if not query: return None
        sql, state = query
        conn = self.connection_factory()
        if conn.autocommit:
            conn.autocommit = False
        try:
            tenant = getattr(trusted_context, "tenant_id", None)
            if tenant:
                conn.execute("select set_config('avuhz.tenant_id',%s,true)", (str(uuid.UUID(str(tenant))),))
            row = conn.execute(sql, (command.tenant_id, subject_id)).fetchone()
            if not row: return None
            return AuthoritativeSubjectSnapshot(command.subject_type, command.subject_id, str(row["tenant_id"]), row.get("record_version", 1), True, str(row["engagement_id"]) if row.get("engagement_id") else None, "ACCEPTED" if state == "accepted_at" and row[state] else row[state])
        finally:
            conn.rollback()
            conn.close()

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


def _time(value):
    return value.isoformat().replace("+00:00", "Z") if hasattr(value, "isoformat") else value


class ImplementationHandoffPostgresRepository:
    def __init__(self, uow):
        self.uow = uow

    def get_version(self, tenant_id, handoff_id, handoff_version):
        row = self.uow.connection.execute(
            "select record from public.avuhz_implementation_handoffs "
            "where tenant_id=%s and implementation_handoff_id=%s and handoff_version=%s",
            (tenant_id, handoff_id, handoff_version),
        ).fetchone()
        return copy.deepcopy(_load(row["record"])) if row else None

    def list_versions(self, tenant_id, handoff_id):
        rows = self.uow.connection.execute(
            "select record from public.avuhz_implementation_handoffs "
            "where tenant_id=%s and implementation_handoff_id=%s order by handoff_version",
            (tenant_id, handoff_id),
        ).fetchall()
        return tuple(copy.deepcopy(_load(row["record"])) for row in rows)

    def get_current(self, tenant_id, handoff_id):
        values = self.list_versions(tenant_id, handoff_id)
        return max(values, key=lambda value: value["handoff_version"]) if values else None

    def create(self, record):
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        cur = self.uow.connection.execute(
            "insert into public.avuhz_implementation_handoffs "
            "(tenant_id,implementation_handoff_id,handoff_version,source_engagement_reference,"
            "handoff_digest,state,record,created_at) values (%s,%s,%s,%s,%s,%s,%s::jsonb,%s) "
            "on conflict do nothing returning implementation_handoff_id",
            (record["tenant_id"], record["implementation_handoff_id"], record["handoff_version"],
             record["source_engagement_reference"], record["handoff_digest"], record["state"],
             _json(record), record["created_at"]),
        )
        if not cur.fetchone():
            raise ValueError("ImplementationHandoff identity/version conflict")
        return copy.deepcopy(record)


class HumanApprovalPostgresRepository(_TenantRepository):
    table = "avuhz_human_approvals"
    identifier = "approval_id"
    columns = "*"

    @staticmethod
    def _phase5d(row):
        return {
            "approval_id": str(row["approval_id"]), "tenant_id": str(row["tenant_id"]),
            "engagement_id": str(row["engagement_id"]), "subject_type": row["subject_type"],
            "subject_id": str(row["subject_id"]), "subject_version": row["subject_version"],
            "approval_category": row["approval_category"], "authority_category": row["authority_category"],
            "actor_identity": row["actor_identity"], "actor_organization": row["actor_organization"],
            "actor_role": row["actor_role"], "decision": row["decision"],
            "phase5d_authority": {"subject_id": str(row["subject_id"]), "authority_digest": row["phase5d_authority_digest"]},
            "conditions": _load(row["conditions"]) or [], "effective_at": _time(row["effective_at"]),
            "evidence_reference": _load(row["evidence_reference"]), "status": row["status"],
            "correlation_id": str(row["correlation_id"]), "idempotency_key": row["idempotency_key"],
            "created_at": _time(row["created_at"]),
        }

    def get(self, tenant_id, approval_id):
        row = self.uow.connection.execute(
            "select * from public.avuhz_human_approvals where tenant_id=%s and approval_id=%s "
            "and subject_type in ('IMPLEMENTATION_BRIEF','IMPLEMENTATION_AUTHORIZATION','CODEX_BUILD_PACKAGE')",
            (tenant_id, approval_id),
        ).fetchone()
        return self._phase5d(row) if row else None

    def find_active_phase5d_binding(self, tenant_id, subject_type, subject_id, subject_version, digest, authority_role):
        row = self.uow.connection.execute(
            "select * from public.avuhz_human_approvals where tenant_id=%s and subject_type=%s "
            "and subject_id=%s and subject_version=%s and phase5d_authority_digest=%s "
            "and actor_role=%s and status='ACTIVE'",
            (tenant_id, subject_type, subject_id, subject_version, digest, authority_role),
        ).fetchone()
        return self._phase5d(row) if row else None

    def record_phase5d(self, record):
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        cur = self.uow.connection.execute(
            "insert into public.avuhz_human_approvals "
            "(approval_id,tenant_id,engagement_id,approval_role,authority_category,"
            "approving_principal_reference,approving_organization_reference,decision,status,conditions,"
            "effective_at,evidence_reference,correlation_id,idempotency_key,subject_type,subject_id,"
            "subject_version,approval_category,actor_identity,actor_organization,actor_role,"
            "phase5d_authority_digest,created_at) values "
            "(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) "
            "on conflict do nothing returning approval_id",
            (record["approval_id"], record["tenant_id"], record["engagement_id"], record["actor_role"],
             record["authority_category"], record["actor_identity"], record["actor_organization"],
             record["decision"], record["status"], _json(record["conditions"]), record["effective_at"],
             _json(record["evidence_reference"]), record["correlation_id"], record["idempotency_key"],
             record["subject_type"], record["subject_id"], record["subject_version"],
             record["approval_category"], record["actor_identity"], record["actor_organization"],
             record["actor_role"], record["phase5d_authority"]["authority_digest"], record["created_at"]),
        )
        if not cur.fetchone():
            raise ValueError("duplicate active Phase 5D authority")
        return copy.deepcopy(record)

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
        self.uow.failpoint("LIFECYCLE_EVENT_APPEND")
        subject=event.get("authoritative_subject_reference")
        if not subject:
            self.uow.connection.execute(
                "insert into public.avuhz_lifecycle_events "
                "(lifecycle_event_id,tenant_id,event_type,authoritative_subject_id,idempotency_key) "
                "values (%s,%s,%s,%s,%s)",
                (event["event_id"],event["tenant_id"],event["event_type"],event["subject_id"],event["idempotency_key"]),
            )
            return
        self.uow.connection.execute(
            "insert into public.avuhz_lifecycle_events "
            "(lifecycle_event_id,tenant_id,engagement_id,event_type,event_schema_version,authoritative_subject_type,authoritative_subject_id,authoritative_subject_version,occurred_at,producer_reference,correlation_id,causation_id,idempotency_key,visibility,sanitized_metadata) "
            "values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb)",
            (event["event_id"],event["tenant_id"],event.get("engagement_id"),event["event_type"],event["event_schema_version"],subject["reference_type"],subject["reference_id"],event["authoritative_subject_version"],event["occurred_at"],event["producer_reference"],event["correlation_id"],event.get("command_id"),event["idempotency_key"],event["visibility"],_json(event["sanitized_metadata"])),
        )

class OutboxPostgresRepository:
    def __init__(self,uow): self.uow=uow
    def append(self,intent):
        self.uow.failpoint("OUTBOX_APPEND"); cur=self.uow.connection.execute("insert into public.avuhz_outbox_deliveries (tenant_id,lifecycle_event_id,status) select tenant_id,%s,%s from public.avuhz_lifecycle_events where lifecycle_event_id=%s",(intent["event_id"],intent["status"],intent["event_id"]))
        if cur.rowcount != 1: raise ValueError("outbox event missing")

class PostgresUnitOfWork:
    def __init__(self,store,trusted_context=None):
        self.store=store
        self.connection=store.connection_factory()
        if self.connection.autocommit:self.connection.autocommit=False
        self.fail_stage=getattr(store,"fail_stage",None)
        self.trusted_tenant_id=None
        if trusted_context is not None:
            try:
                self.bind_trusted_context(trusted_context)
            except Exception:
                self.connection.close()
                raise
        self.handoffs = AcquisitionHandoffPostgresRepository(self)
        self.engagements = EngagementPostgresRepository(self)
        self.implementation_handoffs = ImplementationHandoffPostgresRepository(self)
        self.implementation_briefs = ImplementationBriefPostgresRepository(self)
        self.human_approvals = HumanApprovalPostgresRepository(self)
        self.idempotency = IdempotencyPostgresRepository(self)
        self.lifecycle_events = LifecycleEventPostgresRepository(self)
        self.outbox = OutboxPostgresRepository(self)
        self.implementation_authorizations=ImplementationAuthorizationPostgresRepository(self)
        self.codex_build_packages=CodexBuildPackagePostgresRepository(self)
        self.build_execution_results=BuildExecutionResultPostgresRepository(self)
        self.qa_results=QAResultPostgresRepository(self)
    def bind_trusted_context(self,context):
        if not getattr(context,"authenticated",False) or not getattr(context,"tenant_id",None):raise ValueError("trusted tenant context is required")
        tenant=str(uuid.UUID(str(context.tenant_id)))
        self.connection.execute("select set_config('avuhz.tenant_id',%s,true)",(tenant,));self.trusted_tenant_id=tenant
    def failpoint(self,name):
        if self.fail_stage==name: raise RuntimeError("injected failpoint")
    def commit(self): self.failpoint("COMMIT"); self.connection.commit()
    def rollback(self): self.connection.rollback()
    def close(self): self.connection.close()
