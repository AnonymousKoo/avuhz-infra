"""In-memory repository adapter for immutable CodexBuildPackage history."""
from __future__ import annotations

import copy


class CodexBuildPackageMemoryRepository:
    def __init__(self, uow):
        self.uow = uow
        self.data = uow.working.codex_build_packages

    def get_version(self, tenant_id, package_id, package_version):
        value = self.data.get((tenant_id, package_id, package_version))
        return copy.deepcopy(value) if value else None

    def list_versions(self, tenant_id, package_id):
        return tuple(
            copy.deepcopy(value)
            for (record_tenant, record_id, _), value in sorted(
                self.data.items(), key=lambda item: item[0][2]
            )
            if record_tenant == tenant_id and record_id == package_id
        )

    def get_current(self, tenant_id, package_id):
        values = [
            value for value in self.list_versions(tenant_id, package_id)
            if value.get("state") != "SUPERSEDED"
        ]
        return copy.deepcopy(max(values, key=lambda value: value["package_version"])) if values else None

    def create_initial(self, record):
        key = (record["tenant_id"], record["codex_build_package_id"], record["package_version"])
        if key in self.data or self.list_versions(record["tenant_id"], record["codex_build_package_id"]):
            raise ValueError("CodexBuildPackage identity already exists")
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        self.data[key] = copy.deepcopy(record)
        return copy.deepcopy(record)

    def revise(self, current, replacement, revised_at):
        key = (current["tenant_id"], current["codex_build_package_id"], current["package_version"])
        replacement_key = (
            replacement["tenant_id"], replacement["codex_build_package_id"], replacement["package_version"]
        )
        stored = self.data.get(key)
        if stored != current or stored.get("state") != "RELEASED" or replacement_key in self.data:
            raise ValueError("CodexBuildPackage revision conflict")
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        superseded = copy.deepcopy(stored)
        superseded.update(
            state="SUPERSEDED",
            record_version=stored["record_version"] + 1,
            updated_at=revised_at,
        )
        self.data[key] = superseded
        self.data[replacement_key] = copy.deepcopy(replacement)
        return copy.deepcopy(replacement)

    def release(self, current, client_approval_reference, provider_approval_reference, released_at):
        key = (current["tenant_id"], current["codex_build_package_id"], current["package_version"])
        stored = self.data.get(key)
        if stored != current or stored.get("state") != "DRAFT":
            raise ValueError("CodexBuildPackage release conflict")
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        updated = copy.deepcopy(stored)
        updated.update(
            state="RELEASED",
            client_approval_reference=copy.deepcopy(client_approval_reference),
            provider_approval_reference=copy.deepcopy(provider_approval_reference),
            released_at=released_at,
            record_version=stored["record_version"] + 1,
            updated_at=released_at,
        )
        self.data[key] = updated
        return copy.deepcopy(updated)
