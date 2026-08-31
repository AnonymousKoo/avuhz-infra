"""In-memory repository for versioned DeploymentAuthorization history."""
from __future__ import annotations

import copy


class DeploymentAuthorizationMemoryRepository:
    def __init__(self, uow):
        self.uow = uow
        self.data = uow.working.deployment_authorizations

    def get_version(self, tenant_id, authorization_id, authorization_version):
        value = self.data.get((tenant_id, authorization_id, authorization_version))
        return copy.deepcopy(value) if value else None

    def list_versions(self, tenant_id, authorization_id):
        return tuple(
            copy.deepcopy(value)
            for (record_tenant, record_id, _), value in sorted(
                self.data.items(), key=lambda item: item[0][2]
            )
            if record_tenant == tenant_id and record_id == authorization_id
        )

    def get_current(self, tenant_id, authorization_id):
        values = [
            value for value in self.list_versions(tenant_id, authorization_id)
            if value.get("state") != "SUPERSEDED"
        ]
        return max(values, key=lambda value: value["authorization_version"]) if values else None

    def create_initial(self, record):
        key = (
            record["tenant_id"], record["deployment_authorization_id"],
            record["authorization_version"],
        )
        if key in self.data or self.list_versions(
            record["tenant_id"], record["deployment_authorization_id"]
        ):
            raise ValueError("DeploymentAuthorization identity already exists")
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        self.data[key] = copy.deepcopy(record)
        return copy.deepcopy(record)

    def revise(self, current, replacement, revised_at):
        key = (
            current["tenant_id"], current["deployment_authorization_id"],
            current["authorization_version"],
        )
        replacement_key = (
            replacement["tenant_id"], replacement["deployment_authorization_id"],
            replacement["authorization_version"],
        )
        stored = self.data.get(key)
        if stored != current or stored.get("state") not in {"ACTIVE", "REVOKED"}:
            raise ValueError("DeploymentAuthorization revision conflict")
        if replacement_key in self.data:
            raise ValueError("DeploymentAuthorization replacement exists")
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        if stored["state"] == "ACTIVE":
            superseded = copy.deepcopy(stored)
            superseded.update(
                state="SUPERSEDED",
                record_version=stored["record_version"] + 1,
                updated_at=revised_at,
            )
            self.data[key] = superseded
        self.data[replacement_key] = copy.deepcopy(replacement)
        return copy.deepcopy(replacement)

    def activate(self, current, client_reference, provider_reference, activated_at):
        key = (
            current["tenant_id"], current["deployment_authorization_id"],
            current["authorization_version"],
        )
        stored = self.data.get(key)
        if stored != current or stored.get("state") != "PROPOSED":
            raise ValueError("DeploymentAuthorization activation conflict")
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        updated = copy.deepcopy(stored)
        updated.update(
            state="ACTIVE",
            client_approval_reference=copy.deepcopy(client_reference),
            provider_approval_reference=copy.deepcopy(provider_reference),
            activated_at=activated_at,
            record_version=stored["record_version"] + 1,
            updated_at=activated_at,
        )
        self.data[key] = updated
        return copy.deepcopy(updated)

    def revoke(self, current, reason, revoked_at):
        key = (
            current["tenant_id"], current["deployment_authorization_id"],
            current["authorization_version"],
        )
        stored = self.data.get(key)
        if stored != current or stored.get("state") not in {"PROPOSED", "ACTIVE"}:
            raise ValueError("DeploymentAuthorization revocation conflict")
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        updated = copy.deepcopy(stored)
        updated.update(
            state="REVOKED",
            revoked_at=revoked_at,
            revocation_reason=reason,
            record_version=stored["record_version"] + 1,
            updated_at=revoked_at,
        )
        self.data[key] = updated
        return copy.deepcopy(updated)
