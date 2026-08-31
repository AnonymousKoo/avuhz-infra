"""Pure command schema and static-structure validation; authentication stays external."""
from __future__ import annotations
from pathlib import Path
from typing import Any
from jsonschema import Draft202012Validator, FormatChecker

from .command_registry import CommandDefinition, resolve_command
from .errors import RuntimeReason
from .models import PreparedCommand, ValidationFailure, ValidationResult, ValidationSuccess
from .schema_registry import SchemaRegistry

ENVELOPE_ID = "urn:avuhz:schema:contracts:commands:command-envelope:v1"


class CommandValidator:
    def __init__(self, schema_root: Path):
        self.schemas = SchemaRegistry(schema_root); self._format_checker = FormatChecker()
        self._format_checker.checks("date-time")(lambda value: isinstance(value, str) and value.endswith("Z"))
    def prepare(self, raw: object) -> ValidationResult:
        if not isinstance(raw, dict): return self._failure(RuntimeReason.PAYLOAD_INVALID, "command request must be an object")
        definition = resolve_command(raw.get("command_type"))
        if definition is None: return self._failure(RuntimeReason.SCHEMA_UNSUPPORTED, "command type is not registered")
        if raw.get("command_schema_version") != definition.envelope_version or raw.get("payload_schema") != definition.payload_schema_id or raw.get("payload_version") != definition.payload_version:
            return self._failure(RuntimeReason.SCHEMA_UNSUPPORTED, "registered command schema or version does not match")
        errors = list(self._validator(self._composed_schema(definition)).iter_errors(raw))
        if errors: return self._failure(self._reason_for(errors[0]), "command does not satisfy its registered contract")
        semantic = self._semantic_failure(raw, definition)
        if semantic: return semantic
        return ValidationSuccess(PreparedCommand(
            command_type=definition.command_type, command_id=raw["command_id"], tenant_id=raw["tenant_id"], subject_type=raw["subject_type"], subject_id=raw["subject_id"], caller_identity_claim=dict(raw["caller_identity"]), correlation_id=raw["correlation_id"], idempotency_key=raw["idempotency_key"], environment=raw["environment"], payload=dict(raw["payload"]), payload_schema=raw["payload_schema"], payload_version=raw["payload_version"], engagement_id=raw.get("engagement_id"), expected_record_version=raw.get("expected_record_version"), causation_id=raw.get("causation_id"),
        ))
    def _composed_schema(self, definition: CommandDefinition):
        constraints = {"type": "object", "properties": {"command_type": {"const": definition.command_type}, "subject_type": {"const": definition.subject_type}, "payload_schema": {"const": definition.payload_schema_id}}, "required": ["payload"]}
        creations = {"AcceptAcquisitionHandoff", "OpenEngagement", "DraftImplementationBrief", "ProposeImplementationAuthorization", "DraftCodexBuildPackage", "StartBuildExecution", "RecordQAResult", "RecordClientAcceptance", "ProposeDeploymentAuthorization", "StartDeploymentExecution", "RecordDeploymentVerification"}
        if definition.command_type == "AcceptAcquisitionHandoff": constraints["not"] = {"anyOf": [{"required": ["engagement_id"]}, {"required": ["expected_record_version"]}]}
        elif definition.command_type in creations:
            constraints["not"] = {"required": ["expected_record_version"]}; constraints["required"].append("engagement_id")
        else: constraints["required"] += ["engagement_id", "expected_record_version"]
        return {"allOf": [{"$ref": ENVELOPE_ID + "#/$defs/envelopeCore"}, {"type": "object", "required": ["payload"], "properties": {"payload": {"$ref": definition.payload_schema_id}}}, constraints], "unevaluatedProperties": False}
    def _validator(self, schema): return Draft202012Validator(self.schemas._dereference(schema, schema), format_checker=self._format_checker)
    def _semantic_failure(self, raw, definition):
        command = definition.command_type; payload = raw["payload"]
        if raw["subject_type"] != definition.subject_type: return self._failure(RuntimeReason.PAYLOAD_INVALID, "command subject does not match registration")
        if command == "AcceptAcquisitionHandoff" and "engagement_id" in raw: return self._failure(RuntimeReason.FIELD_FORBIDDEN, "engagement context is not permitted for handoff acceptance")
        identity_fields = {
            "DraftImplementationBrief": "implementation_brief_id", "ReviseImplementationBrief": "implementation_brief_id", "ApproveImplementationBrief": "implementation_brief_id",
            "ProposeImplementationAuthorization": "implementation_authorization_id", "ReviseImplementationAuthorization": "implementation_authorization_id", "ActivateImplementationAuthorization": "implementation_authorization_id", "RevokeImplementationAuthorization": "implementation_authorization_id",
            "DraftCodexBuildPackage": "codex_build_package_id", "ReviseCodexBuildPackage": "codex_build_package_id", "ReleaseCodexBuildPackage": "codex_build_package_id",
            "StartBuildExecution": "build_execution_result_id", "CompleteBuildExecution": "build_execution_result_id", "RecordQAResult": "qa_result_id", "RecordClientAcceptance": "client_acceptance_id",
            "ProposeDeploymentAuthorization": "deployment_authorization_id", "ReviseDeploymentAuthorization": "deployment_authorization_id", "ActivateDeploymentAuthorization": "deployment_authorization_id", "RevokeDeploymentAuthorization": "deployment_authorization_id",
        }
        field = identity_fields.get(command)
        if field and payload[field] != raw["subject_id"]: return self._failure(RuntimeReason.PAYLOAD_INVALID, "payload must identify the command subject")
        if command in {"ApproveImplementationBrief", "ActivateImplementationAuthorization", "ReleaseCodexBuildPackage", "ActivateDeploymentAuthorization"} and payload["client_approval_reference"] == payload["provider_approval_reference"]:
            return self._failure(RuntimeReason.PAYLOAD_INVALID, "approval references must be distinct")
        return None
    @staticmethod
    def _reason_for(error: Any):
        path = "/".join(str(part) for part in error.path)
        if "caller_identity" in path: return RuntimeReason.AUTH_INVALID
        if error.validator == "required" and "expected_record_version" in str(error.message): return RuntimeReason.VERSION_REQUIRED
        if error.validator in ("additionalProperties", "unevaluatedProperties"): return RuntimeReason.FIELD_FORBIDDEN
        return RuntimeReason.PAYLOAD_INVALID
    @staticmethod
    def _failure(reason, message): return ValidationFailure(reason, message)
