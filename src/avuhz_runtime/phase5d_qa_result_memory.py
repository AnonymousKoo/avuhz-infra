"""In-memory repository for immutable QAResult retest history."""
from __future__ import annotations

import copy


class QAResultMemoryRepository:
    def __init__(self, uow):
        self.uow = uow
        self.data = uow.working.qa_results

    def get(self, tenant_id, qa_result_id):
        value = self.data.get((tenant_id, qa_result_id))
        return copy.deepcopy(value) if value else None

    def list_by_package(self, tenant_id, package_id, package_version):
        return tuple(
            copy.deepcopy(value)
            for (record_tenant, _), value in sorted(
                self.data.items(), key=lambda item: item[1]["qa_attempt"]
            )
            if record_tenant == tenant_id
            and value["codex_build_package_reference"]["reference_id"] == package_id
            and value["codex_build_package_reference"]["reference_version"] == package_version
        )

    def create(self, record):
        key = (record["tenant_id"], record["qa_result_id"])
        history = self.list_by_package(
            record["tenant_id"],
            record["codex_build_package_reference"]["reference_id"],
            record["codex_build_package_reference"]["reference_version"],
        )
        if key in self.data or any(
            value["qa_attempt"] == record["qa_attempt"] for value in history
        ):
            raise ValueError("QAResult identity or attempt already exists")
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        self.data[key] = copy.deepcopy(record)
        return copy.deepcopy(record)
