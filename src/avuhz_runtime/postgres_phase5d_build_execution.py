"""PostgreSQL repository for immutable BuildExecutionResult attempt history."""
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


class BuildExecutionResultPostgresRepository:
    def __init__(self, uow):
        self.uow = uow

    def get(self, tenant_id, result_id):
        return _record(self.uow.connection.execute(
            "select record from public.avuhz_build_execution_results "
            "where tenant_id=%s and build_execution_result_id=%s",
            (tenant_id, result_id),
        ).fetchone())

    def list_by_package(self, tenant_id, package_id, package_version):
        rows = self.uow.connection.execute(
            "select record from public.avuhz_build_execution_results "
            "where tenant_id=%s and codex_build_package_id=%s and package_version=%s "
            "order by execution_attempt",
            (tenant_id, package_id, package_version),
        ).fetchall()
        return tuple(_record(row) for row in rows)

    def create(self, record):
        package = record["codex_build_package_reference"]
        authorization = record["implementation_authorization_reference"]
        supersedes = record.get("supersedes_build_execution_reference")
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        cur = self.uow.connection.execute(
            "insert into public.avuhz_build_execution_results "
            "(tenant_id,build_execution_result_id,execution_attempt,engagement_id,"
            "codex_build_package_id,package_version,package_digest,"
            "implementation_authorization_id,authorization_version,implementation_authority_digest,"
            "supersedes_build_execution_result_id,supersedes_record_version,status,"
            "execution_fingerprint,execution_digest,record_version,record,started_at,created_at,updated_at) "
            "values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s,%s) "
            "on conflict do nothing returning build_execution_result_id",
            (
                record["tenant_id"], record["build_execution_result_id"],
                record["execution_attempt"], record["engagement_id"],
                package["reference_id"], package["reference_version"], record["package_digest"],
                authorization["reference_id"], authorization["reference_version"],
                record["implementation_authority_digest"],
                supersedes["reference_id"] if supersedes else None,
                supersedes["reference_version"] if supersedes else None,
                record["status"], record["execution_fingerprint"], None,
                record["record_version"], _json(record), record["started_at"],
                record["created_at"], record["updated_at"],
            ),
        )
        if not cur.fetchone():
            raise ValueError("BuildExecutionResult identity or attempt conflict")
        return copy.deepcopy(record)

    def complete(self, current, terminal):
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        cur = self.uow.connection.execute(
            "update public.avuhz_build_execution_results set "
            "status=%s,execution_digest=%s,record_version=%s,record=%s::jsonb,"
            "completed_at=%s,updated_at=%s "
            "where tenant_id=%s and build_execution_result_id=%s "
            "and status='IN_PROGRESS' and record_version=%s",
            (
                terminal["status"], terminal["execution_digest"], terminal["record_version"],
                _json(terminal), terminal["completed_at"], terminal["updated_at"],
                current["tenant_id"], current["build_execution_result_id"],
                current["record_version"],
            ),
        )
        if cur.rowcount != 1:
            raise ValueError("BuildExecutionResult completion concurrency conflict")
        return copy.deepcopy(terminal)
