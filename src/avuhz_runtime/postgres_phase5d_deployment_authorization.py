"""PostgreSQL repository for versioned DeploymentAuthorization history."""
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


class DeploymentAuthorizationPostgresRepository:
    def __init__(self, uow):
        self.uow = uow

    def get_version(self, tenant_id, authorization_id, authorization_version):
        return _record(self.uow.connection.execute(
            "select record from public.avuhz_deployment_authorizations "
            "where tenant_id=%s and deployment_authorization_id=%s "
            "and authorization_version=%s",
            (tenant_id, authorization_id, authorization_version),
        ).fetchone())

    def list_versions(self, tenant_id, authorization_id):
        rows = self.uow.connection.execute(
            "select record from public.avuhz_deployment_authorizations "
            "where tenant_id=%s and deployment_authorization_id=%s "
            "order by authorization_version",
            (tenant_id, authorization_id),
        ).fetchall()
        return tuple(_record(row) for row in rows)

    def get_current(self, tenant_id, authorization_id):
        return _record(self.uow.connection.execute(
            "select record from public.avuhz_deployment_authorizations "
            "where tenant_id=%s and deployment_authorization_id=%s "
            "and state<>'SUPERSEDED' order by authorization_version desc limit 1",
            (tenant_id, authorization_id),
        ).fetchone())

    def _insert(self, record):
        implementation = record["implementation_authorization_reference"]
        package = record["codex_build_package_reference"]
        build = record["build_execution_reference"]
        qa = record["qa_result_reference"]
        acceptance = record["client_acceptance_reference"]
        supersedes = record.get("supersedes_deployment_authorization_reference")
        cur = self.uow.connection.execute(
            "insert into public.avuhz_deployment_authorizations "
            "(tenant_id,deployment_authorization_id,authorization_version,engagement_id,"
            "implementation_authorization_id,implementation_authorization_version,implementation_authority_digest,"
            "codex_build_package_id,package_version,package_digest,"
            "build_execution_result_id,build_record_version,build_execution_digest,"
            "qa_result_id,qa_record_version,qa_result_digest,"
            "client_acceptance_id,acceptance_version,client_acceptance_digest,"
            "artifact_digest,target_environment,effective_at,expires_at,deployment_authority_digest,"
            "supersedes_deployment_authorization_id,supersedes_authorization_version,"
            "state,record_version,record,created_at,updated_at) "
            "values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s) "
            "on conflict do nothing returning deployment_authorization_id",
            (
                record["tenant_id"], record["deployment_authorization_id"],
                record["authorization_version"], record["engagement_id"],
                implementation["reference_id"], implementation["reference_version"],
                record["implementation_authority_digest"], package["reference_id"],
                package["reference_version"], record["package_digest"],
                build["reference_id"], build["reference_version"],
                record["build_execution_digest"], qa["reference_id"], qa["reference_version"],
                record["qa_result_digest"], acceptance["reference_id"],
                acceptance["reference_version"], record["client_acceptance_digest"],
                record["artifact_reference"]["artifact_digest"], record["target_environment"],
                record["effective_at"], record["expires_at"],
                record["deployment_authority_digest"],
                supersedes["reference_id"] if supersedes else None,
                supersedes["reference_version"] if supersedes else None,
                record["state"], record["record_version"], _json(record),
                record["created_at"], record["updated_at"],
            ),
        )
        if not cur.fetchone():
            raise ValueError("DeploymentAuthorization identity/version conflict")

    def create_initial(self, record):
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        self._insert(record)
        return copy.deepcopy(record)

    def revise(self, current, replacement, revised_at):
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        if current["state"] == "ACTIVE":
            superseded = copy.deepcopy(current)
            superseded.update(
                state="SUPERSEDED",
                record_version=current["record_version"] + 1,
                updated_at=revised_at,
            )
            cur = self.uow.connection.execute(
                "update public.avuhz_deployment_authorizations set state='SUPERSEDED',"
                "record_version=%s,record=%s::jsonb,updated_at=%s where tenant_id=%s "
                "and deployment_authorization_id=%s and authorization_version=%s "
                "and state='ACTIVE' and record_version=%s",
                (
                    superseded["record_version"], _json(superseded), revised_at,
                    current["tenant_id"], current["deployment_authorization_id"],
                    current["authorization_version"], current["record_version"],
                ),
            )
            if cur.rowcount != 1:
                raise ValueError("DeploymentAuthorization revision concurrency conflict")
        elif current["state"] != "REVOKED":
            raise ValueError("DeploymentAuthorization revision conflict")
        self._insert(replacement)
        return copy.deepcopy(replacement)

    def activate(self, current, client_reference, provider_reference, activated_at):
        updated = copy.deepcopy(current)
        updated.update(
            state="ACTIVE",
            client_approval_reference=copy.deepcopy(client_reference),
            provider_approval_reference=copy.deepcopy(provider_reference),
            activated_at=activated_at,
            record_version=current["record_version"] + 1,
            updated_at=activated_at,
        )
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        cur = self.uow.connection.execute(
            "update public.avuhz_deployment_authorizations set state='ACTIVE',"
            "record_version=%s,record=%s::jsonb,updated_at=%s where tenant_id=%s "
            "and deployment_authorization_id=%s and authorization_version=%s "
            "and state='PROPOSED' and record_version=%s",
            (
                updated["record_version"], _json(updated), activated_at,
                current["tenant_id"], current["deployment_authorization_id"],
                current["authorization_version"], current["record_version"],
            ),
        )
        if cur.rowcount != 1:
            raise ValueError("DeploymentAuthorization activation concurrency conflict")
        return copy.deepcopy(updated)

    def revoke(self, current, reason, revoked_at):
        updated = copy.deepcopy(current)
        updated.update(
            state="REVOKED",
            revoked_at=revoked_at,
            revocation_reason=reason,
            record_version=current["record_version"] + 1,
            updated_at=revoked_at,
        )
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        cur = self.uow.connection.execute(
            "update public.avuhz_deployment_authorizations set state='REVOKED',"
            "record_version=%s,record=%s::jsonb,updated_at=%s where tenant_id=%s "
            "and deployment_authorization_id=%s and authorization_version=%s "
            "and state in ('PROPOSED','ACTIVE') and record_version=%s",
            (
                updated["record_version"], _json(updated), revoked_at,
                current["tenant_id"], current["deployment_authorization_id"],
                current["authorization_version"], current["record_version"],
            ),
        )
        if cur.rowcount != 1:
            raise ValueError("DeploymentAuthorization revocation concurrency conflict")
        return copy.deepcopy(updated)
