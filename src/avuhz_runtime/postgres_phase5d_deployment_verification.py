"""PostgreSQL repository for immutable DeploymentVerification history."""
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


class DeploymentVerificationPostgresRepository:
    def __init__(self, uow):
        self.uow = uow

    def get(self, tenant_id, verification_id):
        return _record(self.uow.connection.execute(
            "select record from public.avuhz_deployment_verifications "
            "where tenant_id=%s and deployment_verification_id=%s",
            (tenant_id, verification_id),
        ).fetchone())

    def list_by_execution(self, tenant_id, execution_id, execution_record_version):
        rows = self.uow.connection.execute(
            "select record from public.avuhz_deployment_verifications "
            "where tenant_id=%s and deployment_execution_id=%s and deployment_execution_record_version=%s "
            "order by verification_attempt",
            (tenant_id, execution_id, execution_record_version),
        ).fetchall()
        return tuple(_record(row) for row in rows)

    def create(self, record):
        execution = record["deployment_execution_reference"]
        authority = record["authority_binding"]["deployment_authorization_reference"]
        supersedes = record.get("supersedes_deployment_verification_reference")
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        cur = self.uow.connection.execute(
            "insert into public.avuhz_deployment_verifications "
            "(tenant_id,deployment_verification_id,verification_attempt,engagement_id,"
            "deployment_execution_id,deployment_execution_record_version,deployment_execution_digest,execution_status,"
            "deployment_authorization_id,deployment_authorization_version,deployment_authority_digest,"
            "overall_status,rollback_required,verification_digest,supersedes_deployment_verification_id,"
            "supersedes_record_version,record_version,record,recorded_at,created_at,updated_at) "
            "values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s,%s) "
            "on conflict do nothing returning deployment_verification_id",
            (
                record["tenant_id"], record["deployment_verification_id"], record["verification_attempt"],
                record["engagement_id"], execution["reference_id"], execution["reference_version"],
                record["deployment_execution_digest"], record["execution_status"],
                authority["reference_id"], authority["reference_version"],
                record["authority_binding"]["deployment_authority_digest"], record["overall_status"],
                record["rollback_required"], record["verification_digest"],
                supersedes["reference_id"] if supersedes else None,
                supersedes["reference_version"] if supersedes else None,
                record["record_version"], _json(record), record["recorded_at"], record["created_at"],
                record["updated_at"],
            ),
        )
        if not cur.fetchone():
            raise ValueError("DeploymentVerification identity or attempt conflict")
        return copy.deepcopy(record)
