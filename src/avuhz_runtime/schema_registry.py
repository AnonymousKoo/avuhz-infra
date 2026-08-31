"""Fixed local schema catalog with no remote resolution or request-controlled paths."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any


SCHEMA_FILES = (
    'public/implementation-handoff.schema.json',
    'common/identifiers.schema.json',
    'common/timestamps.schema.json',
    'common/environment.schema.json',
    'common/references.schema.json',
    'identity/caller-type.schema.json',
    'identity/capability.schema.json',
    'identity/caller-identity.schema.json',
    'commands/reason-code.schema.json',
    'commands/command-result.schema.json',
    'commands/command-envelope.schema.json',
    'commands/accept-acquisition-handoff.payload.schema.json',
    'commands/open-engagement.payload.schema.json',
    'commands/draft-implementation-brief.payload.schema.json',
    'commands/revise-implementation-brief.payload.schema.json',
    'commands/record-implementation-brief-approval.payload.schema.json',
    'commands/approve-implementation-brief.payload.schema.json',
    'commands/propose-implementation-authorization.payload.schema.json',
    'commands/revise-implementation-authorization.payload.schema.json',
    'commands/record-implementation-authorization-approval.payload.schema.json',
    'commands/activate-implementation-authorization.payload.schema.json',
    'commands/revoke-implementation-authorization.payload.schema.json',
    'commands/draft-codex-build-package.payload.schema.json',
    'commands/revise-codex-build-package.payload.schema.json',
    'commands/record-codex-build-package-approval.payload.schema.json',
    'commands/release-codex-build-package.payload.schema.json',
    'commands/start-build-execution.payload.schema.json',
    'commands/complete-build-execution.payload.schema.json',
    'commands/record-qa-result.payload.schema.json',
    'commands/record-client-acceptance.payload.schema.json',
    'commands/propose-deployment-authorization.payload.schema.json',
    'commands/revise-deployment-authorization.payload.schema.json',
    'commands/record-deployment-authorization-approval.payload.schema.json',
    'commands/activate-deployment-authorization.payload.schema.json',
    'commands/revoke-deployment-authorization.payload.schema.json',
    'domain/acquisition-handoff.schema.json',
    'domain/engagement.schema.json',
    'domain/human-approval.schema.json',
    'domain/phase5d-common.schema.json',
    'domain/implementation-brief.schema.json',
    'domain/implementation-authorization.schema.json',
    'domain/codex-build-package.schema.json',
    'domain/phase5d-delivery-common.schema.json',
    'domain/build-execution-result.schema.json',
    'domain/qa-result.schema.json',
    'domain/client-acceptance.schema.json',
    'domain/deployment-authorization.schema.json',
    'orchestration/inbound-event-receipt.schema.json',
    'orchestration/idempotency-record.schema.json',
    'orchestration/lifecycle-event.schema.json',
    'orchestration/outbox-delivery.schema.json',
    'read-models/engagement-summary.schema.json',
    'read-models/onboarding-readiness.schema.json',
    'read-models/implementation-brief-readiness-view.schema.json',
    'read-models/implementation-authorization-status-view.schema.json',
    'read-models/codex-build-package-readiness-view.schema.json',
    'read-models/build-execution-status-view.schema.json',
    'read-models/qa-result-status-view.schema.json',
    'read-models/client-acceptance-status-view.schema.json',
    'read-models/deployment-authorization-status-view.schema.json',
    'read-models/phase5d-authority-progression-view.schema.json',
    'read-models/phase5d-delivery-progression-view.schema.json',
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
