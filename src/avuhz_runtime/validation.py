"""Pure command schema and static-structure validation; no authentication or execution."""

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
        self.schemas = SchemaRegistry(schema_root)
        self._format_checker = FormatChecker()
        self._format_checker.checks("date-time")(lambda value: isinstance(value, str) and value.endswith("Z"))

    def prepare(self, raw: object) -> ValidationResult:
        if not isinstance(raw, dict):
            return self._failure(RuntimeReason.PAYLOAD_INVALID, "command request must be an object")
        definition = resolve_command(raw.get("command_type"))
        if definition is None:
            return self._failure(RuntimeReason.SCHEMA_UNSUPPORTED, "command type is not registered")
        if raw.get("command_schema_version") != definition.envelope_version or raw.get("payload_schema") != definition.payload_schema_id or raw.get("payload_version") != definition.payload_version:
            return self._failure(RuntimeReason.SCHEMA_UNSUPPORTED, "registered command schema or version does not match")
        errors = list(self._validator(self._composed_schema(definition)).iter_errors(raw))
        if errors:
            return self._failure(self._reason_for(errors[0]), "command does not satisfy its registered contract")
        semantic = self._semantic_failure(raw, definition)
        if semantic:
            return semantic
        return ValidationSuccess(PreparedCommand(
            command_type=definition.command_type, command_id=raw["command_id"], tenant_id=raw["tenant_id"],
            subject_type=raw["subject_type"], subject_id=raw["subject_id"], caller_identity_claim=dict(raw["caller_identity"]),
            correlation_id=raw["correlation_id"], idempotency_key=raw["idempotency_key"], environment=raw["environment"],
            payload=dict(raw["payload"]), payload_schema=raw["payload_schema"], payload_version=raw["payload_version"],
            engagement_id=raw.get("engagement_id"), expected_record_version=raw.get("expected_record_version"), causation_id=raw.get("causation_id"),
        ))

    def _composed_schema(self, definition: CommandDefinition) -> dict[str, Any]:
        constraints: dict[str, Any] = {"type": "object", "properties": {"command_type": {"const": definition.command_type}, "subject_type": {"const": definition.subject_type}, "payload_schema": {"const": definition.payload_schema_id}}, "required": ["payload"]}
        if definition.command_type == "AcceptAcquisitionHandoff": constraints["not"] = {"anyOf": [{"required": ["engagement_id"]}, {"required": ["expected_record_version"]}]}
        elif definition.command_type == "RecordOIARootCause":
            constraints["required"] += ["engagement_id"]
        elif definition.command_type in ("OpenEngagement", "OpenOIAAssessment", "RecordOIAEvidence", "RecordOIAObservation", "CreateOIAAssessmentPlan", "CreateOIAInspectionItem"):
            constraints["not"] = {"required": ["expected_record_version"]}
            if definition.command_type in ("OpenOIAAssessment", "RecordOIAEvidence", "RecordOIAObservation", "CreateOIAAssessmentPlan", "CreateOIAInspectionItem"): constraints["required"] += ["engagement_id"]
        else: constraints["required"] += ["engagement_id", "expected_record_version"]
        return {"allOf": [{"$ref": ENVELOPE_ID + "#/$defs/envelopeCore"}, {"type": "object", "required": ["payload"], "properties": {"payload": {"$ref": definition.payload_schema_id}}}, constraints], "unevaluatedProperties": False}

    def _validator(self, schema: dict[str, Any]) -> Draft202012Validator:
        return Draft202012Validator(self.schemas._dereference(schema, schema), format_checker=self._format_checker)

    def _semantic_failure(self, raw: dict[str, Any], definition: CommandDefinition) -> ValidationFailure | None:
        if raw["subject_type"] != definition.subject_type:
            return self._failure(RuntimeReason.PAYLOAD_INVALID, "command subject does not match registration")
        if definition.command_type in ("AcceptAcquisitionHandoff", "OpenEngagement", "OpenOIAAssessment", "RecordOIAEvidence", "RecordOIAObservation", "CreateOIAAssessmentPlan", "CreateOIAInspectionItem") and "expected_record_version" in raw:
            return self._failure(RuntimeReason.VERSION_REQUIRED, "expected version is not permitted for this command")
        if definition.command_type == "AcceptAcquisitionHandoff" and "engagement_id" in raw:
            return self._failure(RuntimeReason.FIELD_FORBIDDEN, "engagement context is not permitted for handoff acceptance")
        identity_field = {"RecordDiagnosticAgreementAuthority": "diagnostic_agreement_authority_id", "RecordDiagnosticPaymentVerification": "diagnostic_payment_verification_id", "InvalidateDiagnosticPaymentVerification": "diagnostic_payment_verification_id"}.get(definition.command_type)
        if identity_field and raw["payload"][identity_field] != raw["subject_id"]:
            return self._failure(RuntimeReason.PAYLOAD_INVALID, "commercial payload must identify the command subject")
        if definition.command_type == "RecordHumanApproval" and raw["payload"]["diagnostic_scope_id"] != raw["subject_id"]:
            return self._failure(RuntimeReason.PAYLOAD_INVALID, "approval payload must identify the command subject")
        if definition.command_type == "ApproveDiagnosticScope":
            payload = raw["payload"]
            if payload["client_approval_reference"] == payload["sekinfra_approval_reference"]:
                return self._failure(RuntimeReason.PAYLOAD_INVALID, "approval references must be distinct")
        if definition.command_type == "CanonicalizeDiagnosticScope" and raw["payload"]["diagnostic_scope_id"] != raw["subject_id"]:
            return self._failure(RuntimeReason.PAYLOAD_INVALID, "canonicalization payload must identify the command subject")
        if definition.command_type == "OpenOIAAssessment":
            payload = raw["payload"]
            if payload["oia_assessment_id"] != raw["subject_id"] or payload["engagement_id"] != raw.get("engagement_id"):
                return self._failure(RuntimeReason.PAYLOAD_INVALID, "OIA payload must identify the command subject and engagement")
        if definition.command_type == "RecordOIAEvidence" and raw["payload"]["oia_evidence_id"] != raw["subject_id"]:
            return self._failure(RuntimeReason.PAYLOAD_INVALID, "OIA evidence payload must identify the command subject")
        if definition.command_type in ("RecordOIAObservation", "SupersedeOIAObservation"):
            payload = raw["payload"]
            if payload["oia_observation_id"] != raw["subject_id"]:
                return self._failure(RuntimeReason.PAYLOAD_INVALID, "OIA observation payload must identify the command subject")
            if definition.command_type == "SupersedeOIAObservation" and payload["replacement_oia_observation_id"] == raw["subject_id"]:
                return self._failure(RuntimeReason.PAYLOAD_INVALID, "an observation cannot supersede itself")
        if definition.command_type == "RecordOIARootCause" and raw["payload"]["oia_root_cause_id"] != raw["subject_id"]:
            return self._failure(RuntimeReason.PAYLOAD_INVALID, "OIA root-cause payload must identify the command subject")
        if definition.command_type in ("CreateOIAAssessmentPlan", "ReviseOIAAssessmentPlan", "ReviewOIAAssessmentPlan", "ApproveOIAAssessmentPlan"):
            payload = raw["payload"]
            if payload["oia_assessment_plan_id"] != raw["subject_id"]:
                return self._failure(RuntimeReason.PAYLOAD_INVALID, "OIA plan payload must identify the command subject")
            if definition.command_type == "CreateOIAAssessmentPlan" and payload["engagement_id"] != raw.get("engagement_id"):
                return self._failure(RuntimeReason.PAYLOAD_INVALID, "OIA plan payload must identify the command engagement")
        if definition.command_type in ("CreateOIAInspectionItem", "UpdateOIAInspectionItem", "MarkOIAInspectionItemBlocked"):
            payload = raw["payload"]
            if payload["oia_inspection_item_id"] != raw["subject_id"]:
                return self._failure(RuntimeReason.PAYLOAD_INVALID, "OIA inspection payload must identify the command subject")
            if definition.command_type == "CreateOIAInspectionItem" and payload["engagement_id"] != raw.get("engagement_id"):
                return self._failure(RuntimeReason.PAYLOAD_INVALID, "OIA inspection payload must identify the command engagement")
        return None

    @staticmethod
    def _reason_for(error: Any) -> RuntimeReason:
        path = "/".join(str(part) for part in error.path)
        if "caller_identity" in path: return RuntimeReason.AUTH_INVALID
        if error.validator == "required" and "expected_record_version" in str(error.message): return RuntimeReason.VERSION_REQUIRED
        if error.validator in ("additionalProperties", "unevaluatedProperties"): return RuntimeReason.FIELD_FORBIDDEN
        return RuntimeReason.PAYLOAD_INVALID

    @staticmethod
    def _failure(reason: RuntimeReason, message: str) -> ValidationFailure:
        return ValidationFailure(reason, message)
