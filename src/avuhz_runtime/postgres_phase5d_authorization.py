"""PostgreSQL repository for frozen ImplementationAuthorization history."""
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


class ImplementationAuthorizationPostgresRepository:
    def __init__(self, uow):
        self.uow = uow

    def get_version(self, tenant_id, authorization_id, authorization_version):
        return _record(self.uow.connection.execute(
            "select record from public.avuhz_implementation_authorizations "
            "where tenant_id=%s and implementation_authorization_id=%s "
            "and authorization_version=%s",
            (tenant_id, authorization_id, authorization_version),
        ).fetchone())

    def list_versions(self, tenant_id, authorization_id):
        rows = self.uow.connection.execute(
            "select record from public.avuhz_implementation_authorizations "
            "where tenant_id=%s and implementation_authorization_id=%s "
            "order by authorization_version",
            (tenant_id, authorization_id),
        ).fetchall()
        return tuple(_record(row) for row in rows)

    def get_current(self, tenant_id, authorization_id):
        return _record(self.uow.connection.execute(
            "select record from public.avuhz_implementation_authorizations "
            "where tenant_id=%s and implementation_authorization_id=%s "
            "and state<>'SUPERSEDED' order by authorization_version desc limit 1",
            (tenant_id, authorization_id),
        ).fetchone())

    def _insert(self, record):
        brief = record["implementation_brief_reference"]
        conversion = record["source_conversion_decision_reference"]
        agreement = record["source_ongoing_agreement_reference"]
        payment = record["source_ongoing_payment_reference"]
        access = record["source_ongoing_access_reference"]
        cur = self.uow.connection.execute(
            "insert into public.avuhz_implementation_authorizations "
            "(tenant_id,implementation_authorization_id,authorization_version,engagement_id,"
            "implementation_brief_id,implementation_brief_version,implementation_brief_digest,"
            "oia_conversion_decision_id,decision_version,ongoing_agreement_authority_id,agreement_version,"
            "ongoing_payment_verification_id,payment_record_version,ongoing_access_grant_id,access_record_version,"
            "authorized_scope_digest,implementation_authority_digest,effective_at,expires_at,state,"
            "record_version,record,created_at,updated_at) "
            "values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s) "
            "on conflict do nothing returning implementation_authorization_id",
            (
                record["tenant_id"], record["implementation_authorization_id"],
                record["authorization_version"], record["engagement_id"],
                brief["reference_id"], brief["reference_version"],
                record["implementation_brief_digest"], conversion["reference_id"],
                conversion["reference_version"], agreement["reference_id"],
                agreement["reference_version"], payment["reference_id"],
                payment["reference_version"], access["reference_id"],
                access["reference_version"], record["authorized_scope_digest"],
                record["implementation_authority_digest"], record["effective_at"],
                record["expires_at"], record["state"], record["record_version"],
                _json(record), record["created_at"], record["updated_at"],
            ),
        )
        if not cur.fetchone():
            raise ValueError("ImplementationAuthorization identity/version conflict")

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
            "update public.avuhz_implementation_authorizations set state='SUPERSEDED',"
            "record_version=%s,record=%s::jsonb,updated_at=%s where tenant_id=%s "
            "and implementation_authorization_id=%s and authorization_version=%s "
            "and state='ACTIVE' and record_version=%s",
            (
                superseded["record_version"], _json(superseded), revised_at,
                current["tenant_id"], current["implementation_authorization_id"],
                current["authorization_version"], current["record_version"],
            ),
        )
        if cur.rowcount != 1:
            raise ValueError("ImplementationAuthorization revision concurrency conflict")
        self._insert(replacement)
        return copy.deepcopy(replacement)

    def activate(
        self,
        current,
        client_approval_reference,
        sekinfra_approval_reference,
        activated_at,
    ):
        updated = copy.deepcopy(current)
        updated.update(
            state="ACTIVE",
            client_approval_reference=copy.deepcopy(client_approval_reference),
            sekinfra_approval_reference=copy.deepcopy(sekinfra_approval_reference),
            activated_at=activated_at,
            record_version=current["record_version"] + 1,
            updated_at=activated_at,
        )
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        cur = self.uow.connection.execute(
            "update public.avuhz_implementation_authorizations set state='ACTIVE',"
            "record_version=%s,record=%s::jsonb,updated_at=%s where tenant_id=%s "
            "and implementation_authorization_id=%s and authorization_version=%s "
            "and state='PROPOSED' and record_version=%s",
            (
                updated["record_version"], _json(updated), activated_at,
                current["tenant_id"], current["implementation_authorization_id"],
                current["authorization_version"], current["record_version"],
            ),
        )
        if cur.rowcount != 1:
            raise ValueError("ImplementationAuthorization activation concurrency conflict")
        return copy.deepcopy(updated)

    def revoke(self, current, revocation_reason, revoked_at):
        updated = copy.deepcopy(current)
        updated.update(
            state="REVOKED",
            revoked_at=revoked_at,
            revocation_reason=revocation_reason,
            record_version=current["record_version"] + 1,
            updated_at=revoked_at,
        )
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        cur = self.uow.connection.execute(
            "update public.avuhz_implementation_authorizations set state='REVOKED',"
            "record_version=%s,record=%s::jsonb,updated_at=%s where tenant_id=%s "
            "and implementation_authorization_id=%s and authorization_version=%s "
            "and state in ('PROPOSED','ACTIVE') and record_version=%s",
            (
                updated["record_version"], _json(updated), revoked_at,
                current["tenant_id"], current["implementation_authorization_id"],
                current["authorization_version"], current["record_version"],
            ),
        )
        if cur.rowcount != 1:
            raise ValueError("ImplementationAuthorization revocation concurrency conflict")
        return copy.deepcopy(updated)
