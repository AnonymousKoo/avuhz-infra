#!/usr/bin/env python3
"""Validate Slice 1 ingress, idempotency, lifecycle, and outbox contracts."""

from __future__ import annotations

import copy
from datetime import datetime
import json
from pathlib import Path
import sys

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[2]
SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
FIXTURE_PATH = ROOT / "contracts/fixtures/v1/orchestration-foundation.cases.json"
IDS = {
    "receipt": "urn:avuhz:schema:contracts:orchestration:inbound-event-receipt:v1",
    "idempotency": "urn:avuhz:schema:contracts:orchestration:idempotency-record:v1",
    "event": "urn:avuhz:schema:contracts:orchestration:lifecycle-event:v1",
    "outbox": "urn:avuhz:schema:contracts:orchestration:outbox-delivery:v1"
}


def load(path):
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def fail(message):
    print(f"orchestration-foundation validation: FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def pointer(document, fragment):
    current = document
    if not fragment:
        return current
    if not fragment.startswith("/"):
        raise KeyError(fragment)
    for part in fragment[1:].split("/"):
        current = current[part.replace("~1", "/").replace("~0", "~")]
    return current


def resolve(reference, document, schemas):
    if reference.startswith("#"):
        target_document, fragment = document, reference[1:]
    else:
        schema_id, separator, fragment = reference.partition("#")
        target_document = schemas[schema_id]
        fragment = fragment if separator else ""
    return target_document, pointer(target_document, fragment)


def dereference(value, document, schemas):
    if isinstance(value, dict):
        if "$ref" in value:
            target_document, target = resolve(value["$ref"], document, schemas)
            expanded = dereference(copy.deepcopy(target), target_document, schemas)
            siblings = {key: dereference(child, document, schemas) for key, child in value.items() if key != "$ref"}
            if not isinstance(expanded, dict):
                raise ValueError("reference target must be an object schema")
            return {**expanded, **siblings}
        return {key: dereference(child, document, schemas) for key, child in value.items()}
    if isinstance(value, list):
        return [dereference(child, document, schemas) for child in value]
    return value


def all_refs(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "$ref":
                yield child
            yield from all_refs(child)
    elif isinstance(value, list):
        for child in value:
            yield from all_refs(child)


def apply_mutation(value, mutation):
    copied = copy.deepcopy(value)
    for dotted_key, replacement in mutation.items():
        target = copied
        parts = dotted_key.split(".")
        for part in parts[:-1]:
            target = target[int(part)] if part.isdigit() else target[part]
        target[parts[-1] if not parts[-1].isdigit() else int(parts[-1])] = replacement
    return copied


def utc_datetime(value):
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("expected UTC Z timestamp")
    return datetime.fromisoformat(value[:-1] + "+00:00")


def receipt_semantics(value):
    if value["correlation_status"] == "CORRELATED" and ("correlated_tenant_id" not in value or "correlated_subject_reference" not in value):
        return False
    return not (value["authentication_result"] == "FAILED" and value["processing_status"] == "PROCESSED")


def idempotency_semantics(value):
    if value["processing_status"] == "COMPLETED" and "result_reference" not in value:
        return False
    if "completed_at" in value and utc_datetime(value["completed_at"]) < utc_datetime(value["first_seen_at"]):
        return False
    return True


def event_semantics(value):
    event_type = value["event_type"]
    metadata = value["sanitized_metadata"]
    if event_type == "assessment_access.approval_recorded": return set(metadata) == {"assessment_access_proposal_id", "authority_role", "approval_id"}
    expected = "handoff_version" if event_type == "engagement.handoff.accepted" else "engagement_version" if event_type == "engagement.opened" else "assessment_access_proposal_id" if event_type == "assessment_access.proposal_created" else "scope_version"
    return set(metadata) == ({"engagement_state", "engagement_version"} if expected == "engagement_version" else {expected})


def outbox_semantics(value):
    if value["status"] == "PUBLISHED" and "published_at" not in value:
        return False
    if value["status"] == "FAILED_RETRYABLE" and "next_attempt_at" not in value:
        return False
    if value["status"] == "FAILED_TERMINAL" and "next_attempt_at" in value:
        return False
    if "published_at" in value and utc_datetime(value["published_at"]) < utc_datetime(value["created_at"]):
        return False
    return value["event_reference"]["reference_id"] != value["outbox_delivery_id"]


def main():
    paths = sorted(SCHEMA_ROOT.rglob("*.schema.json"))
    schemas = {schema["$id"]: schema for path in paths for schema in [load(path)]}
    if len(schemas) != len(paths) or any(not schema_id for schema_id in schemas):
        fail("schema IDs must be present and globally unique")
    for schema in schemas.values():
        Draft202012Validator.check_schema(schema)
    for schema_id in IDS.values():
        for reference in all_refs(schemas[schema_id]):
            try:
                resolve(reference, schemas[schema_id], schemas)
            except (KeyError, TypeError):
                fail(f"unresolved reference: {reference}")
    if schemas[IDS["receipt"]]["properties"]["source_type"]["enum"] != ["ACQUISITION_SYSTEM", "PROVIDER", "INTERNAL_SERVICE"]:
        fail("receipt source vocabulary drifted")
    if schemas[IDS["idempotency"]]["properties"]["command_type"]["enum"] != ["AcceptAcquisitionHandoff", "OpenEngagement", "SubmitDiagnosticScope", "RecordHumanApproval", "ApproveDiagnosticScope", "CanonicalizeDiagnosticScope", "CreateAssessmentAccessProposal", "RecordAssessmentAccessApproval"]:
        fail("idempotency command vocabulary drifted")
    if schemas[IDS["event"]]["properties"]["event_type"]["enum"] != ["engagement.handoff.accepted", "engagement.opened", "diagnostic_scope.submitted", "diagnostic_scope.approved", "diagnostic_scope.rejected", "human_approval.recorded", "diagnostic_scope.canonicalized", "assessment_access.proposal_created", "assessment_access.approval_recorded"]:
        fail("event vocabulary drifted")
    for schema_id in IDS.values():
        if "metadata" in schemas[schema_id]["properties"]:
            fail("generic metadata escape hatch is forbidden")

    checker = FormatChecker()
    checker.checks("date-time")(lambda value: isinstance(value, str) and value.endswith("Z"))
    validators = {name: Draft202012Validator(dereference(schemas[schema_id], schemas[schema_id], schemas), format_checker=checker) for name, schema_id in IDS.items()}
    fixtures = load(FIXTURE_PATH)
    mappings = [("inbound_receipt", "receipt", receipt_semantics), ("idempotency", "idempotency", idempotency_semantics), ("lifecycle_event", "event", event_semantics), ("outbox_delivery", "outbox", outbox_semantics)]
    total_positive = total_negative = 0
    for fixture_key, validator_key, semantics in mappings:
        positives = fixtures[fixture_key]["positive"]
        for case in positives:
            if list(validators[validator_key].iter_errors(case["value"])) or not semantics(case["value"]):
                fail(f"{fixture_key} positive failed: {case['name']}")
        base = positives[0]["value"]
        for case in fixtures[fixture_key]["negative"]:
            source = positives[case.get("base", 0)]["value"]
            value = apply_mutation(source, case["mutate"])
            if not list(validators[validator_key].iter_errors(value)):
                fail(f"{fixture_key} negative passed schema: {case['name']}")
        total_positive += len(positives)
        total_negative += len(fixtures[fixture_key]["negative"])
    print(f"orchestration-foundation validation: PASS ({total_positive} positive, {total_negative} negative, {len(schemas)} unique schema IDs, all refs resolved)")


if __name__ == "__main__":
    main()
