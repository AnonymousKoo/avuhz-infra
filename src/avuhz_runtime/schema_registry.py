"""Fixed local schema catalog with no remote resolution or request-controlled paths."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any


SCHEMA_FILES = (
    "common/identifiers.schema.json", "common/timestamps.schema.json", "common/environment.schema.json", "common/references.schema.json",
    "identity/caller-type.schema.json", "identity/capability.schema.json", "identity/caller-identity.schema.json",
    "commands/reason-code.schema.json", "commands/command-result.schema.json", "commands/command-envelope.schema.json",
    "commands/accept-acquisition-handoff.payload.schema.json", "commands/open-engagement.payload.schema.json", "commands/submit-diagnostic-scope.payload.schema.json", "commands/record-human-approval.payload.schema.json", "commands/record-assessment-access-approval.payload.schema.json", "commands/create-assessment-access-proposal.payload.schema.json", "commands/issue-assessment-access-grant.payload.schema.json", "commands/verify-assessment-access.payload.schema.json", "commands/expire-assessment-access.payload.schema.json", "commands/revoke-assessment-access.payload.schema.json", "commands/close-assessment-access-for-agreement-end.payload.schema.json", "commands/record-diagnostic-agreement-authority.payload.schema.json", "commands/record-diagnostic-payment-verification.payload.schema.json", "commands/invalidate-diagnostic-payment-verification.payload.schema.json", "commands/approve-diagnostic-scope.payload.schema.json", "commands/canonicalize-diagnostic-scope.payload.schema.json", "commands/open-oia-assessment.payload.schema.json", "commands/record-oia-evidence.payload.schema.json", "commands/create-oia-assessment-plan.payload.schema.json", "commands/revise-oia-assessment-plan.payload.schema.json", "commands/review-oia-assessment-plan.payload.schema.json", "commands/approve-oia-assessment-plan.payload.schema.json",
    "domain/acquisition-handoff.schema.json", "domain/engagement.schema.json", "domain/human-approval.schema.json", "domain/diagnostic-scope.schema.json", "domain/diagnostic-agreement-authority.schema.json", "domain/diagnostic-payment-verification.schema.json", "domain/assessment-access-grant.schema.json", "domain/assessment-access-proposal.schema.json", "domain/oia-common.schema.json", "domain/oia-assessment.schema.json", "domain/oia-evidence-item.schema.json", "domain/oia-methodology-common.schema.json", "domain/oia-assessment-plan.schema.json",
    "orchestration/inbound-event-receipt.schema.json", "orchestration/idempotency-record.schema.json", "orchestration/lifecycle-event.schema.json", "orchestration/outbox-delivery.schema.json",
    "read-models/engagement-summary.schema.json", "read-models/onboarding-readiness.schema.json",
)


class SchemaRegistry:
    def __init__(self, schema_root: Path):
        self._root = schema_root.resolve()
        self._schemas: dict[str, dict[str, Any]] = {}
        for relative in SCHEMA_FILES:
            path = (self._root / relative).resolve()
            if self._root not in path.parents or not path.is_file():
                raise RuntimeError("approved local schema catalog is incomplete")
            with path.open(encoding="utf-8") as handle:
                schema = json.load(handle)
            schema_id = schema.get("$id")
            if not isinstance(schema_id, str) or schema_id in self._schemas:
                raise RuntimeError("approved local schema catalog is invalid")
            self._schemas[schema_id] = schema

    @property
    def schema_ids(self) -> frozenset[str]:
        return frozenset(self._schemas)

    def resolve(self, schema_id: str) -> dict[str, Any]:
        if schema_id not in self._schemas:
            raise KeyError("schema is not in the approved local catalog")
        return self._schemas[schema_id]

    def expanded(self, schema_id: str) -> dict[str, Any]:
        document = self.resolve(schema_id)
        return self._dereference(copy.deepcopy(document), document)

    def _dereference(self, value: Any, document: dict[str, Any]) -> Any:
        if isinstance(value, dict):
            if "$ref" in value:
                ref = value["$ref"]
                if not isinstance(ref, str) or ref.startswith(("http:", "https:")):
                    raise KeyError("remote or invalid schema reference is prohibited")
                target_document, target = self._resolve_ref(ref, document)
                expanded = self._dereference(copy.deepcopy(target), target_document)
                return {**expanded, **{key: self._dereference(child, document) for key, child in value.items() if key != "$ref"}}
            return {key: self._dereference(child, document) for key, child in value.items()}
        if isinstance(value, list):
            return [self._dereference(child, document) for child in value]
        return value

    def _resolve_ref(self, reference: str, document: dict[str, Any]) -> tuple[dict[str, Any], Any]:
        if reference.startswith("#"):
            target_document, fragment = document, reference[1:]
        else:
            schema_id, separator, fragment = reference.partition("#")
            target_document = self.resolve(schema_id)
            fragment = fragment if separator else ""
        target: Any = target_document
        for part in ([] if not fragment else fragment[1:].split("/")):
            target = target[part.replace("~1", "/").replace("~0", "~")]
        return target_document, target
