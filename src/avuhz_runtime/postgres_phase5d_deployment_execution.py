"""PostgreSQL repository for immutable DeploymentExecution attempt history."""
from __future__ import annotations

import copy
import json


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _record(row):
    if not row:
        return None
    value = row["record"]
    return copy.deepcopy(json.loads(value) if isinstance(value, str) else value)


class DeploymentExecutionPostgresRepository:
    def __init__(self, uow):
        self.uow = uow

    def get(self, tenant_id, execution_id):
        return _record(self.uow.connection.execute(
            "select record from public.avuhz_deployment_executions "
            "where tenant_id=%s and deployment_execution_id=%s",
            (tenant_id, execution_id),
        ).fetchone())

    def list_by_authorization(self, tenant_id, authorization_id, authorization_version):
        rows = self.uow.connection.execute(
            "select record from public.avuhz_deployment_executions "
            "where tenant_id=%s and deployment_authorization_id=%s and deployment_authorization_version=%s "
            "order by execution_attempt",
            (tenant_id, authorization_id, authorization_version),
        ).fetchall()
        return tuple(_record(row) for row in rows)

    def create(self, record):
        binding = record["authority_binding"]
        authority = binding["deployment_authorization_reference"]
        supersedes = record.get("supersedes_deployment_execution_reference")
        rollback_of = record.get("rollback_of_deployment_execution_reference")
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        cur = self.uow.connection.execute(
            "insert into public.avuhz_deployment_executions "
            "(tenant_id,deployment_execution_id,execution_attempt,engagement_id,"
            "deployment_authorization_id,deployment_authorization_version,deployment_authority_digest,"
            "supersedes_deployment_execution_id,supersedes_record_version,"
            "rollback_of_deployment_execution_id,rollback_of_record_version,execution_action,status,"
            "execution_fingerprint,execution_digest,record_version,record,started_at,created_at,updated_at) "
            "values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s,%s) "
            "on conflict do nothing returning deployment_execution_id",
            (
                record["tenant_id"], record["deployment_execution_id"], record["execution_attempt"],
                record["engagement_id"], authority["reference_id"], authority["reference_version"],
                binding["deployment_authority_digest"],
                supersedes["reference_id"] if supersedes else None,
                supersedes["reference_version"] if supersedes else None,
                rollback_of["reference_id"] if rollback_of else None,
                rollback_of["reference_version"] if rollback_of else None,
                record["execution_action"], record["status"], record["execution_fingerprint"], None,
                record["record_version"], _json(record), record["started_at"], record["created_at"],
                record["updated_at"],
            ),
        )
        if not cur.fetchone():
            raise ValueError("DeploymentExecution identity or attempt conflict")
        return copy.deepcopy(record)

    def complete(self, current, terminal):
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        cur = self.uow.connection.execute(
            "update public.avuhz_deployment_executions set "
            "status=%s,execution_digest=%s,record_version=%s,record=%s::jsonb,completed_at=%s,updated_at=%s "
            "where tenant_id=%s and deployment_execution_id=%s and status='IN_PROGRESS' and record_version=%s",
            (
                terminal["status"], terminal["execution_digest"], terminal["record_version"],
                _json(terminal), terminal["completed_at"], terminal["updated_at"],
                current["tenant_id"], current["deployment_execution_id"], current["record_version"],
            ),
        )
        if cur.rowcount != 1:
            raise ValueError("DeploymentExecution completion concurrency conflict")
        return copy.deepcopy(terminal)
