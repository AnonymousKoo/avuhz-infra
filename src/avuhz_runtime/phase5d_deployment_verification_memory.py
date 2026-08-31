"""In-memory repository for immutable DeploymentVerification history."""
from __future__ import annotations

import copy


class DeploymentVerificationMemoryRepository:
    def __init__(self, uow):
        self.uow = uow
        self.data = uow.working.deployment_verifications

    def get(self, tenant_id, verification_id):
        value = self.data.get((tenant_id, verification_id))
        return copy.deepcopy(value) if value else None

    def list_by_execution(self, tenant_id, execution_id, execution_record_version):
        return tuple(
            copy.deepcopy(value)
            for (record_tenant, _), value in sorted(
                self.data.items(), key=lambda item: item[1]["verification_attempt"]
            )
            if record_tenant == tenant_id
            and value["deployment_execution_reference"]["reference_id"] == execution_id
            and value["deployment_execution_reference"]["reference_version"] == execution_record_version
        )

    def create(self, record):
        key = (record["tenant_id"], record["deployment_verification_id"])
        execution = record["deployment_execution_reference"]
        attempts = self.list_by_execution(
            record["tenant_id"], execution["reference_id"], execution["reference_version"]
        )
        if key in self.data or any(item["verification_attempt"] == record["verification_attempt"] for item in attempts):
            raise ValueError("DeploymentVerification identity or attempt already exists")
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        self.data[key] = copy.deepcopy(record)
        return copy.deepcopy(record)
