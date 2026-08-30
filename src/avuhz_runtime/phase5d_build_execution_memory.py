"""In-memory repository for immutable BuildExecutionResult attempt history."""
from __future__ import annotations

import copy


class BuildExecutionResultMemoryRepository:
    def __init__(self, uow):
        self.uow = uow
        self.data = uow.working.build_execution_results

    def get(self, tenant_id, result_id):
        value = self.data.get((tenant_id, result_id))
        return copy.deepcopy(value) if value else None

    def list_by_package(self, tenant_id, package_id, package_version):
        return tuple(
            copy.deepcopy(value)
            for (record_tenant, _), value in sorted(
                self.data.items(), key=lambda item: item[1]["execution_attempt"]
            )
            if record_tenant == tenant_id
            and value["codex_build_package_reference"]["reference_id"] == package_id
            and value["codex_build_package_reference"]["reference_version"] == package_version
        )

    def create(self, record):
        key = (record["tenant_id"], record["build_execution_result_id"])
        attempts = self.list_by_package(
            record["tenant_id"],
            record["codex_build_package_reference"]["reference_id"],
            record["codex_build_package_reference"]["reference_version"],
        )
        if key in self.data or any(
            value["execution_attempt"] == record["execution_attempt"] for value in attempts
        ):
            raise ValueError("BuildExecutionResult identity or attempt already exists")
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        self.data[key] = copy.deepcopy(record)
        return copy.deepcopy(record)

    def complete(self, current, terminal):
        key = (current["tenant_id"], current["build_execution_result_id"])
        stored = self.data.get(key)
        if stored != current or stored.get("status") != "IN_PROGRESS":
            raise ValueError("BuildExecutionResult completion conflict")
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        self.data[key] = copy.deepcopy(terminal)
        return copy.deepcopy(terminal)
