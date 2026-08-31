"""In-memory repository for immutable DeploymentExecution attempt history."""
from __future__ import annotations

import copy


class DeploymentExecutionMemoryRepository:
    def __init__(self, uow):
        self.uow = uow
        self.data = uow.working.deployment_executions

    def get(self, tenant_id, execution_id):
        value = self.data.get((tenant_id, execution_id))
        return copy.deepcopy(value) if value else None

    def list_by_authorization(self, tenant_id, authorization_id, authorization_version):
        return tuple(
            copy.deepcopy(value)
            for (record_tenant, _), value in sorted(
                self.data.items(), key=lambda item: item[1]["execution_attempt"]
            )
            if record_tenant == tenant_id
            and value["authority_binding"]["deployment_authorization_reference"]["reference_id"] == authorization_id
            and value["authority_binding"]["deployment_authorization_reference"]["reference_version"] == authorization_version
        )

    def create(self, record):
        key = (record["tenant_id"], record["deployment_execution_id"])
        authority = record["authority_binding"]["deployment_authorization_reference"]
        attempts = self.list_by_authorization(
            record["tenant_id"], authority["reference_id"], authority["reference_version"]
        )
        if key in self.data or any(item["execution_attempt"] == record["execution_attempt"] for item in attempts):
            raise ValueError("DeploymentExecution identity or attempt already exists")
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        self.data[key] = copy.deepcopy(record)
        return copy.deepcopy(record)

    def complete(self, current, terminal):
        key = (current["tenant_id"], current["deployment_execution_id"])
        stored = self.data.get(key)
        if stored != current or stored.get("status") != "IN_PROGRESS":
            raise ValueError("DeploymentExecution completion conflict")
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        self.data[key] = copy.deepcopy(terminal)
        return copy.deepcopy(terminal)
