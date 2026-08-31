"""PostgreSQL repository for immutable ClientAcceptance decision history."""
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


class ClientAcceptancePostgresRepository:
    def __init__(self, uow):
        self.uow = uow

    def get_version(self, tenant_id, client_acceptance_id, acceptance_version):
        return _record(self.uow.connection.execute(
            "select record from public.avuhz_client_acceptances "
            "where tenant_id=%s and client_acceptance_id=%s and acceptance_version=%s",
            (tenant_id, client_acceptance_id, acceptance_version),
        ).fetchone())

    def list_by_package(self, tenant_id, package_id, package_version):
        rows = self.uow.connection.execute(
            "select record from public.avuhz_client_acceptances "
            "where tenant_id=%s and codex_build_package_id=%s and package_version=%s "
            "order by acceptance_version",
            (tenant_id, package_id, package_version),
        ).fetchall()
        return tuple(_record(row) for row in rows)

    def create(self, record):
        package = record["codex_build_package_reference"]
        build = record["build_execution_reference"]
        qa = record["qa_result_reference"]
        artifact = record["artifact_reference"]
        supersedes = record.get("supersedes_client_acceptance_reference")
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        cur = self.uow.connection.execute(
            "insert into public.avuhz_client_acceptances "
            "(tenant_id,client_acceptance_id,acceptance_version,engagement_id,"
            "codex_build_package_id,package_version,package_digest,"
            "build_execution_result_id,build_record_version,build_execution_digest,"
            "qa_result_id,qa_record_version,qa_result_digest,"
            "artifact_reference_id,artifact_class,artifact_version,artifact_digest,"
            "decision,client_acceptance_digest,supersedes_client_acceptance_id,"
            "supersedes_acceptance_version,record_version,record,recorded_at,created_at,updated_at) "
            "values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s,%s) "
            "on conflict do nothing returning client_acceptance_id",
            (
                record["tenant_id"], record["client_acceptance_id"],
                record["acceptance_version"], record["engagement_id"],
                package["reference_id"], package["reference_version"],
                record["package_digest"], build["reference_id"],
                build["reference_version"], record["build_execution_digest"],
                qa["reference_id"], qa["reference_version"], record["qa_result_digest"],
                artifact["artifact_reference_id"], artifact["artifact_class"],
                artifact["artifact_version"], artifact["artifact_digest"],
                record["decision"], record["client_acceptance_digest"],
                supersedes["reference_id"] if supersedes else None,
                supersedes["reference_version"] if supersedes else None,
                record["record_version"], _json(record), record["recorded_at"],
                record["created_at"], record["updated_at"],
            ),
        )
        if not cur.fetchone():
            raise ValueError("ClientAcceptance identity or version conflict")
        return copy.deepcopy(record)
