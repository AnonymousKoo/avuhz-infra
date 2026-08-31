"""PostgreSQL repository for immutable QAResult retest history."""
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


class QAResultPostgresRepository:
    def __init__(self, uow):
        self.uow = uow

    def get(self, tenant_id, qa_result_id):
        return _record(self.uow.connection.execute(
            "select record from public.avuhz_qa_results "
            "where tenant_id=%s and qa_result_id=%s",
            (tenant_id, qa_result_id),
        ).fetchone())

    def list_by_package(self, tenant_id, package_id, package_version):
        rows = self.uow.connection.execute(
            "select record from public.avuhz_qa_results "
            "where tenant_id=%s and codex_build_package_id=%s and package_version=%s "
            "order by qa_attempt",
            (tenant_id, package_id, package_version),
        ).fetchall()
        return tuple(_record(row) for row in rows)

    def create(self, record):
        build = record["build_execution_reference"]
        package = record["codex_build_package_reference"]
        supersedes = record.get("supersedes_qa_result_reference")
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        cur = self.uow.connection.execute(
            "insert into public.avuhz_qa_results "
            "(tenant_id,qa_result_id,qa_attempt,engagement_id,"
            "build_execution_result_id,build_record_version,build_execution_digest,"
            "codex_build_package_id,package_version,package_digest,"
            "supersedes_qa_result_id,supersedes_record_version,overall_status,"
            "qa_digest,record_version,record,recorded_at,created_at,updated_at) "
            "values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s,%s) "
            "on conflict do nothing returning qa_result_id",
            (
                record["tenant_id"], record["qa_result_id"], record["qa_attempt"],
                record["engagement_id"], build["reference_id"], build["reference_version"],
                record["build_execution_digest"], package["reference_id"],
                package["reference_version"], record["package_digest"],
                supersedes["reference_id"] if supersedes else None,
                supersedes["reference_version"] if supersedes else None,
                record["overall_status"], record["qa_digest"], record["record_version"],
                _json(record), record["recorded_at"], record["created_at"],
                record["updated_at"],
            ),
        )
        if not cur.fetchone():
            raise ValueError("QAResult identity or attempt conflict")
        return copy.deepcopy(record)
