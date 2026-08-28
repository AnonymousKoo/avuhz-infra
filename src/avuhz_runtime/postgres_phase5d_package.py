"""PostgreSQL repository for immutable CodexBuildPackage history."""
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


class CodexBuildPackagePostgresRepository:
    def __init__(self, uow):
        self.uow = uow

    def get_version(self, tenant_id, package_id, package_version):
        return _record(self.uow.connection.execute(
            "select record from public.avuhz_codex_build_packages "
            "where tenant_id=%s and codex_build_package_id=%s and package_version=%s",
            (tenant_id, package_id, package_version),
        ).fetchone())

    def list_versions(self, tenant_id, package_id):
        rows = self.uow.connection.execute(
            "select record from public.avuhz_codex_build_packages "
            "where tenant_id=%s and codex_build_package_id=%s order by package_version",
            (tenant_id, package_id),
        ).fetchall()
        return tuple(_record(row) for row in rows)

    def get_current(self, tenant_id, package_id):
        return _record(self.uow.connection.execute(
            "select record from public.avuhz_codex_build_packages "
            "where tenant_id=%s and codex_build_package_id=%s and state<>'SUPERSEDED' "
            "order by package_version desc limit 1",
            (tenant_id, package_id),
        ).fetchone())

    def _insert(self, record):
        brief = record["implementation_brief_reference"]
        implementation_authority = record["implementation_authorization_reference"]
        cur = self.uow.connection.execute(
            "insert into public.avuhz_codex_build_packages "
            "(tenant_id,codex_build_package_id,package_version,engagement_id,"
            "implementation_brief_id,implementation_brief_version,implementation_brief_digest,"
            "implementation_authorization_id,authorization_version,implementation_authority_digest,"
            "package_digest,state,record_version,record,created_at,updated_at) "
            "values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s) "
            "on conflict do nothing returning codex_build_package_id",
            (
                record["tenant_id"], record["codex_build_package_id"], record["package_version"],
                record["engagement_id"], brief["reference_id"], brief["reference_version"],
                record["implementation_brief_digest"], implementation_authority["reference_id"],
                implementation_authority["reference_version"], record["implementation_authority_digest"],
                record["package_digest"], record["state"], record["record_version"],
                _json(record), record["created_at"], record["updated_at"],
            ),
        )
        if not cur.fetchone():
            raise ValueError("CodexBuildPackage identity/version conflict")

    def create_initial(self, record):
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        self._insert(record)
        return copy.deepcopy(record)

    def revise(self, current, replacement, revised_at):
        superseded = copy.deepcopy(current)
        superseded.update(
            state="SUPERSEDED",
            record_version=current["record_version"] + 1,
            updated_at=revised_at,
        )
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        cur = self.uow.connection.execute(
            "update public.avuhz_codex_build_packages set state='SUPERSEDED',record_version=%s,"
            "record=%s::jsonb,updated_at=%s where tenant_id=%s and codex_build_package_id=%s "
            "and package_version=%s and state='RELEASED' and record_version=%s",
            (
                superseded["record_version"], _json(superseded), revised_at,
                current["tenant_id"], current["codex_build_package_id"],
                current["package_version"], current["record_version"],
            ),
        )
        if cur.rowcount != 1:
            raise ValueError("CodexBuildPackage revision concurrency conflict")
        self._insert(replacement)
        return copy.deepcopy(replacement)

    def release(self, current, client_approval_reference, sekinfra_approval_reference, released_at):
        updated = copy.deepcopy(current)
        updated.update(
            state="RELEASED",
            client_approval_reference=copy.deepcopy(client_approval_reference),
            sekinfra_approval_reference=copy.deepcopy(sekinfra_approval_reference),
            released_at=released_at,
            record_version=current["record_version"] + 1,
            updated_at=released_at,
        )
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        cur = self.uow.connection.execute(
            "update public.avuhz_codex_build_packages set state='RELEASED',record_version=%s,"
            "record=%s::jsonb,updated_at=%s where tenant_id=%s and codex_build_package_id=%s "
            "and package_version=%s and state='DRAFT' and record_version=%s",
            (
                updated["record_version"], _json(updated), released_at,
                current["tenant_id"], current["codex_build_package_id"],
                current["package_version"], current["record_version"],
            ),
        )
        if cur.rowcount != 1:
            raise ValueError("CodexBuildPackage release concurrency conflict")
        return copy.deepcopy(updated)
