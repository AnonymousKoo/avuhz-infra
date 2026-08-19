#!/usr/bin/env python3
"""Validate Slice 1 executable command payload composition with local tooling."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import sys

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[2]
SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
FIXTURE_PATH = ROOT / "contracts/fixtures/v1/command-payload.cases.json"
ENVELOPE_ID = "urn:avuhz:schema:contracts:commands:command-envelope:v1"
PAYLOAD_IDS = {
    "AcceptAcquisitionHandoff": "urn:avuhz:schema:contracts:commands:accept-acquisition-handoff-payload:v1",
    "OpenEngagement": "urn:avuhz:schema:contracts:commands:open-engagement-payload:v1",
    "SubmitDiagnosticScope": "urn:avuhz:schema:contracts:commands:submit-diagnostic-scope-payload:v1",
    "ApproveDiagnosticScope": "urn:avuhz:schema:contracts:commands:approve-diagnostic-scope-payload:v1",
}
SUBJECTS = {"AcceptAcquisitionHandoff": "ACQUISITION_HANDOFF", "OpenEngagement": "ENGAGEMENT", "SubmitDiagnosticScope": "ENGAGEMENT", "ApproveDiagnosticScope": "DIAGNOSTIC_SCOPE"}
PROHIBITED = ["CREATE", "MODIFY", "DELETE", "DEPLOY", "RESTART", "ROTATE", "GRANT", "REVOKE", "CHANGE_CONFIGURATION", "PRODUCTION_CHANGE"]


def load(path):
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def fail(message):
    print(f"command-payload validation: FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def pointer(document, fragment):
    current = document
    for part in ([] if not fragment else fragment[1:].split("/")):
        current = current[part.replace("~1", "/").replace("~0", "~")]
    return current


def resolve(reference, document, schemas):
    if reference.startswith("#"):
        return document, pointer(document, reference[1:])
    schema_id, separator, fragment = reference.partition("#")
    return schemas[schema_id], pointer(schemas[schema_id], fragment if separator else "")


def dereference(value, document, schemas):
    if isinstance(value, dict):
        if "$ref" in value:
            doc, target = resolve(value["$ref"], document, schemas)
            expanded = dereference(copy.deepcopy(target), doc, schemas)
            return {**expanded, **{key: dereference(child, document, schemas) for key, child in value.items() if key != "$ref"}}
        return {key: dereference(child, document, schemas) for key, child in value.items()}
    if isinstance(value, list):
        return [dereference(child, document, schemas) for child in value]
    return value


def handoff():
    return {"handoff_id": "a3000000-0000-4000-8000-000000000001", "handoff_version": 1, "tenant_id": "a3000000-0000-4000-8000-000000000002", "canonical_account_reference": {"source_system": "sekinfra-acquisition", "object_type": "CANONICAL_ACCOUNT", "external_id": "account-001", "environment": "TEST"}, "acquisition_opportunity_reference": {"source_system": "sekinfra-acquisition", "object_type": "ACQUISITION_OPPORTUNITY", "external_id": "opportunity-001", "environment": "TEST"}, "qualification_status": "QUALIFIED", "target_outcome": "Fictional governed diagnostic outcome.", "validated_constraints": [], "stakeholder_context": [], "assumptions": [], "exclusions": [], "requested_engagement_type": "DIAGNOSTIC_OIA", "source_system": "sekinfra-acquisition", "source_record_version": "v1", "producer_identity": "acquisition.service-01", "produced_at": "2030-01-15T15:00:00Z", "correlation_id": "a3000000-0000-4000-8000-000000000003", "idempotency_key": "slice1-handoff-payload-0001"}


def system():
    return {"system_reference_id": "system-001", "system_type": {"taxonomy_source": "system-taxonomy", "taxonomy_id": "infrastructure-system"}, "account_reference": {"source_system": "sekinfra-acquisition", "object_type": "CANONICAL_ACCOUNT", "external_id": "account-001", "environment": "TEST"}, "environment": "TEST"}


def payloads():
    return {
        "AcceptAcquisitionHandoff": {"acquisition_handoff": handoff()},
        "OpenEngagement": {"proposed_engagement_id": "a3000000-0000-4000-8000-000000000004", "accepted_handoff_reference": {"reference_type": "ACQUISITION_HANDOFF", "reference_id": "a3000000-0000-4000-8000-000000000001", "reference_version": 1}, "canonical_account_reference": handoff()["canonical_account_reference"], "acquisition_opportunity_reference": handoff()["acquisition_opportunity_reference"], "engagement_type": "DIAGNOSTIC_OIA"},
        "SubmitDiagnosticScope": {"proposed_diagnostic_scope_id": "a3000000-0000-4000-8000-000000000005", "scope_version": 1, "target_outcome": "Fictional read-only diagnostic scope.", "in_scope_systems": [system()], "excluded_systems": [], "permitted_diagnostic_actions": ["VIEW_CONFIGURATION"], "prohibited_actions": PROHIBITED, "assumptions": [], "constraints": []},
        "ApproveDiagnosticScope": {"scope_version": 1, "client_approval_reference": {"reference_type": "HUMAN_APPROVAL", "reference_id": "a3000000-0000-4000-8000-000000000006", "reference_version": 1}, "sekinfra_approval_reference": {"reference_type": "HUMAN_APPROVAL", "reference_id": "a3000000-0000-4000-8000-000000000007", "reference_version": 1}, "scope_content_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
    }


def envelope(command, payload):
    subject_id = "a3000000-0000-4000-8000-000000000004" if command in ("OpenEngagement", "SubmitDiagnosticScope") else "a3000000-0000-4000-8000-000000000001" if command == "AcceptAcquisitionHandoff" else "a3000000-0000-4000-8000-000000000005"
    value = {"command_id": "a3000000-0000-4000-8000-000000000010", "command_type": command, "command_schema_version": 1, "tenant_id": "a3000000-0000-4000-8000-000000000002", "subject_type": SUBJECTS[command], "subject_id": subject_id, "requested_by": "internal.service-01", "caller_type": "INTERNAL_SERVICE", "caller_identity": {"subject": "internal.service-01", "audience": "avuhz-command-api", "caller_type": "INTERNAL_SERVICE", "tenant_ids": ["a3000000-0000-4000-8000-000000000002"], "capabilities": ["scope:submit"], "environment": "TEST", "authentication_strength": "STRONG", "step_up_performed": False, "authenticated_at": "2030-01-15T15:00:00Z", "expires_at": "2030-01-15T16:00:00Z"}, "correlation_id": "a3000000-0000-4000-8000-000000000011", "idempotency_key": "slice1-executable-command-0001", "requested_at": "2030-01-15T15:00:00Z", "environment": "TEST", "payload_schema": PAYLOAD_IDS[command], "payload_version": 1, "payload": payload}
    if command in ("OpenEngagement", "SubmitDiagnosticScope", "ApproveDiagnosticScope"):
        value["engagement_id"] = "a3000000-0000-4000-8000-000000000004"
    if command in ("SubmitDiagnosticScope", "ApproveDiagnosticScope"):
        value["expected_record_version"] = 1
    return value


def composed(command):
    constraints = {"type": "object", "properties": {"command_type": {"const": command}, "subject_type": {"const": SUBJECTS[command]}, "payload_schema": {"const": PAYLOAD_IDS[command]}}, "required": ["payload"]}
    if command == "AcceptAcquisitionHandoff": constraints["not"] = {"anyOf": [{"required": ["engagement_id"]}, {"required": ["expected_record_version"]}]}
    if command == "OpenEngagement": constraints["not"] = {"required": ["expected_record_version"]}
    if command in ("SubmitDiagnosticScope", "ApproveDiagnosticScope"): constraints["required"] += ["engagement_id", "expected_record_version"]
    return {"allOf": [{"$ref": ENVELOPE_ID + "#/$defs/envelopeCore"}, {"type": "object", "required": ["payload"], "properties": {"payload": {"$ref": PAYLOAD_IDS[command]}}}, constraints], "unevaluatedProperties": False}


def main():
    schemas = {schema["$id"]: schema for path in sorted(SCHEMA_ROOT.rglob("*.schema.json")) for schema in [load(path)]}
    if len(schemas) != len(list(SCHEMA_ROOT.rglob("*.schema.json"))): fail("schema IDs must be unique")
    for schema in schemas.values(): Draft202012Validator.check_schema(schema)
    for schema_id in PAYLOAD_IDS.values():
        if schema_id not in schemas: fail(f"missing payload schema: {schema_id}")
    checker = FormatChecker(); checker.checks("date-time")(lambda v: isinstance(v, str) and v.endswith("Z"))
    fixtures = load(FIXTURE_PATH); data = payloads(); validators = {command: Draft202012Validator(dereference(composed(command), composed(command), schemas), format_checker=checker) for command in PAYLOAD_IDS}
    for command, payload in data.items():
        if list(validators[command].iter_errors(envelope(command, payload))): fail(f"positive failed: {command}")
    negatives = []
    def bad(command, mutate):
        value = envelope(command, copy.deepcopy(data[command])); mutate(value); negatives.append((command, value))
    bad("AcceptAcquisitionHandoff", lambda x: x.update(subject_type="ENGAGEMENT")); bad("AcceptAcquisitionHandoff", lambda x: x.update(engagement_id="a3000000-0000-4000-8000-000000000004")); bad("AcceptAcquisitionHandoff", lambda x: x.update(expected_record_version=1)); bad("AcceptAcquisitionHandoff", lambda x: x["payload"].update(acquisition_history=[])); bad("AcceptAcquisitionHandoff", lambda x: x["payload"].update(authorization="short")); bad("AcceptAcquisitionHandoff", lambda x: x["payload"].update(metadata={}))
    bad("OpenEngagement", lambda x: x.update(subject_type="ACQUISITION_HANDOFF")); bad("OpenEngagement", lambda x: x["payload"].pop("accepted_handoff_reference")); bad("OpenEngagement", lambda x: x["payload"].update(engagement_type="ONGOING_SERVICE")); bad("OpenEngagement", lambda x: x["payload"].update(acquisition_handoff=handoff())); bad("OpenEngagement", lambda x: x["payload"].update(account={"name":"fictional"})); bad("OpenEngagement", lambda x: x.update(expected_record_version=1)); bad("OpenEngagement", lambda x: x["payload"].update(metadata={}))
    bad("SubmitDiagnosticScope", lambda x: x.update(subject_type="DIAGNOSTIC_SCOPE")); bad("SubmitDiagnosticScope", lambda x: x.pop("engagement_id")); bad("SubmitDiagnosticScope", lambda x: x.pop("expected_record_version")); bad("SubmitDiagnosticScope", lambda x: x["payload"].update(client_approval_reference={})); bad("SubmitDiagnosticScope", lambda x: x["payload"].update(status="APPROVED")); bad("SubmitDiagnosticScope", lambda x: x["payload"].update(permitted_diagnostic_actions=["MODIFY"])); bad("SubmitDiagnosticScope", lambda x: x["payload"].update(prohibited_actions=PROHIBITED[1:])); bad("SubmitDiagnosticScope", lambda x: x["payload"].update(in_scope_systems=[])); bad("SubmitDiagnosticScope", lambda x: x["payload"].update(supersedes_reference={"reference_type":"DIAGNOSTIC_SCOPE","reference_id":"bad","reference_version":1})); bad("SubmitDiagnosticScope", lambda x: x["payload"].update(metadata={}))
    bad("ApproveDiagnosticScope", lambda x: x.update(subject_type="ENGAGEMENT")); bad("ApproveDiagnosticScope", lambda x: x["payload"].pop("sekinfra_approval_reference")); bad("ApproveDiagnosticScope", lambda x: x["payload"].update(sekinfra_approval_reference=x["payload"]["client_approval_reference"])); bad("ApproveDiagnosticScope", lambda x: x["payload"].update(client_approval={"approval_id":"a3000000-0000-4000-8000-000000000006"})); bad("ApproveDiagnosticScope", lambda x: x["payload"].update(target_outcome="replacement")); bad("ApproveDiagnosticScope", lambda x: x["payload"].update(scope_content_digest="bad")); bad("ApproveDiagnosticScope", lambda x: x.pop("expected_record_version")); bad("ApproveDiagnosticScope", lambda x: x["payload"].update(metadata={}))
    for command, value in negatives:
        if not list(validators[command].iter_errors(value)) and not (command == "ApproveDiagnosticScope" and value["payload"].get("client_approval_reference") == value["payload"].get("sekinfra_approval_reference")):
            fail(f"negative passed: {command}")
    mismatch = envelope("SubmitDiagnosticScope", data["SubmitDiagnosticScope"]); mismatch["payload_schema"] = PAYLOAD_IDS["ApproveDiagnosticScope"]
    if not list(validators["SubmitDiagnosticScope"].iter_errors(mismatch)): fail("payload-schema mismatch passed")
    base = envelope("SubmitDiagnosticScope", {"untyped": "not-allowed"})
    base["payload_schema"] = "urn:avuhz:schema:contracts:commands:unregistered-payload:v1"
    if not list(Draft202012Validator(dereference(schemas[ENVELOPE_ID], schemas[ENVELOPE_ID], schemas), format_checker=checker).iter_errors(base)): fail("base envelope accepted unregistered payload")
    if len(fixtures["positive"]) != 4 or len(fixtures["negative"]) != 35: fail("fixture inventory drifted")
    print(f"command-payload validation: PASS ({len(fixtures['positive'])} positive, {len(fixtures['negative'])} negative, {len(schemas)} unique schema IDs, executable composition)")


if __name__ == "__main__": main()
