"""In-memory repository for immutable ClientAcceptance decision history."""
from __future__ import annotations

import copy


class ClientAcceptanceMemoryRepository:
    def __init__(self, uow):
        self.uow = uow
        self.data = uow.working.client_acceptances

    def get_version(self, tenant_id, client_acceptance_id, acceptance_version):
        value = self.data.get((tenant_id, client_acceptance_id, acceptance_version))
        return copy.deepcopy(value) if value else None

    def list_by_package(self, tenant_id, package_id, package_version):
        return tuple(
            copy.deepcopy(value)
            for (record_tenant, _, _), value in sorted(
                self.data.items(), key=lambda item: item[1]["acceptance_version"]
            )
            if record_tenant == tenant_id
            and value["codex_build_package_reference"]["reference_id"] == package_id
            and value["codex_build_package_reference"]["reference_version"] == package_version
        )

    def create(self, record):
        key = (
            record["tenant_id"], record["client_acceptance_id"],
            record["acceptance_version"],
        )
        history = self.list_by_package(
            record["tenant_id"],
            record["codex_build_package_reference"]["reference_id"],
            record["codex_build_package_reference"]["reference_version"],
        )
        if key in self.data or any(
            item["acceptance_version"] == record["acceptance_version"] for item in history
        ):
            raise ValueError("ClientAcceptance identity or version already exists")
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        self.data[key] = copy.deepcopy(record)
        return copy.deepcopy(record)
