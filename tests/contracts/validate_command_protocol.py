#!/usr/bin/env python3
"""Validate Slice 1 command-protocol schemas and fictional fixtures locally."""

from __future__ import annotations

import copy
from datetime import datetime
import json
from pathlib import Path
import sys

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[2]
SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
FIXTURE_PATH = ROOT / "contracts/fixtures/v1/command-protocol.cases.json"
REASON_ID = "urn:avuhz:schema:contracts:commands:reason-code:v1"
RESULT_ID = "urn:avuhz:schema:contracts:commands:command-result:v1"
ENVELOPE_ID = "urn:avuhz:schema:contracts:commands:command-envelope:v1"
EXPECTED_REASONS = [
    "COMMAND_ACCEPTED", "COMMAND_REJECTED", "AUTH_MISSING", "AUTH_INVALID", "AUTH_EXPIRED",
    "AUTH_AUDIENCE_INVALID", "AUTH_CAPABILITY_MISSING", "TENANT_CONTEXT_MISSING",
    "TENANT_ACCESS_DENIED", "TENANT_SUBJECT_MISMATCH", "SCHEMA_UNSUPPORTED", "PAYLOAD_INVALID",
    "FIELD_FORBIDDEN", "CONTENT_TYPE_INVALID", "VERSION_REQUIRED", "VERSION_STALE",
    "SUBJECT_VERSION_SUPERSEDED", "IDEMPOTENCY_KEY_MISSING", "IDEMPOTENCY_KEY_MISMATCH",
    "IDEMPOTENCY_SEMANTIC_MISMATCH", "DUPLICATE_REQUEST", "STATE_TRANSITION_INVALID",
    "PREREQUISITE_STATE_INVALID", "APPROVAL_REQUIRED_CLIENT", "APPROVAL_REQUIRED_SEKINFRA",
    "APPROVAL_SCOPE_MISMATCH", "APPROVAL_SUBJECT_VERSION_MISMATCH", "HANDOFF_UNTRUSTED",
    "HANDOFF_ALREADY_ACCEPTED", "HANDOFF_ACCOUNT_MISMATCH", "SCOPE_NOT_SUBMITTED",
    "SCOPE_VERSION_STALE", "PROVIDER_SIGNATURE_INVALID", "PROVIDER_EVENT_UNCORRELATED",
    "SECURITY_BLOCKED", "CROSS_TENANT_ATTEMPT", "INTERNAL_INVARIANT_VIOLATION", "OUTBOX_COMMIT_FAILED"
]
EXPECTED_RESULTS = ["ACCEPTED", "REJECTED", "CONFLICT", "DUPLICATE", "NOT_AUTHORIZED", "INVALID_STATE", "VALIDATION_FAILED", "SECURITY_BLOCKED"]
EXPECTED_RETRYABILITY = ["NOT_RETRYABLE", "RETRY_SAME_KEY", "RETRY_NEW_ATTEMPT", "HUMAN_REVIEW"]
EXPECTED_COMMANDS = ["AcceptAcquisitionHandoff", "OpenEngagement", "SubmitDiagnosticScope", "ApproveDiagnosticScope"]
EXPECTED_SUBJECTS = ["ACQUISITION_HANDOFF", "ENGAGEMENT", "DIAGNOSTIC_SCOPE"]


def load(path):
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def fail(message):
    print(f"command-protocol validation: FAIL: {message}", file=sys.stderr)
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
            target = target[part]
        target[parts[-1]] = replacement
    return copied


def utc_datetime(value):
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("expected UTC Z timestamp")
    return datetime.fromisoformat(value[:-1] + "+00:00")


def main():
    paths = sorted(SCHEMA_ROOT.rglob("*.schema.json"))
    schemas = {schema["$id"]: schema for path in paths for schema in [load(path)]}
    if len(schemas) != len(paths) or any(not schema_id for schema_id in schemas):
        fail("schema IDs must be present and globally unique")
    for schema in schemas.values():
        Draft202012Validator.check_schema(schema)
    for schema_id in (RESULT_ID, ENVELOPE_ID):
        for reference in all_refs(schemas[schema_id]):
            try:
                resolve(reference, schemas[schema_id], schemas)
            except (KeyError, TypeError):
                fail(f"unresolved reference: {reference}")

    reason_schema = schemas[REASON_ID]
    result_schema = dereference(schemas[RESULT_ID], schemas[RESULT_ID], schemas)
    envelope_schema = dereference(schemas[ENVELOPE_ID], schemas[ENVELOPE_ID], schemas)
    if reason_schema["enum"] != EXPECTED_REASONS:
        fail("reason-code vocabulary drifted")
    if schemas[RESULT_ID]["$defs"]["result"]["enum"] != EXPECTED_RESULTS:
        fail("result vocabulary drifted")
    if schemas[RESULT_ID]["$defs"]["retryability"]["enum"] != EXPECTED_RETRYABILITY:
        fail("retryability vocabulary drifted")
    if schemas[ENVELOPE_ID]["$defs"]["commandType"]["enum"] != EXPECTED_COMMANDS:
        fail("command vocabulary drifted")
    if schemas[ENVELOPE_ID]["$defs"]["subjectType"]["enum"] != EXPECTED_SUBJECTS:
        fail("subject vocabulary drifted")
    expected_bindings = {
        "AcceptAcquisitionHandoff": "ACQUISITION_HANDOFF",
        "OpenEngagement": "ENGAGEMENT",
        "SubmitDiagnosticScope": "ENGAGEMENT",
        "ApproveDiagnosticScope": "DIAGNOSTIC_SCOPE",
    }
    bindings = schemas[ENVELOPE_ID]["$defs"]["envelopeCore"]["allOf"]
    for binding in bindings:
        command_type = binding["if"]["properties"]["command_type"]["const"]
        subject_type = binding["then"]["properties"]["subject_type"]["const"]
        if expected_bindings.get(command_type) != subject_type:
            fail(f"command subject binding drifted: {command_type}")
    if schemas[ENVELOPE_ID]["allOf"][1]["properties"]["payload"]["maxProperties"] != 0:
        fail("base envelope payload must remain a strict placeholder")
    if "metadata" in schemas[RESULT_ID]["properties"] or "metadata" in schemas[ENVELOPE_ID]["$defs"]["envelopeCore"]["properties"]:
        fail("generic metadata escape hatch is forbidden")

    checker = FormatChecker()
    checker.checks("date-time")(lambda value: isinstance(value, str) and value.endswith("Z"))
    reason_validator = Draft202012Validator(reason_schema)
    result_validator = Draft202012Validator(result_schema, format_checker=checker)
    envelope_validator = Draft202012Validator(envelope_schema, format_checker=checker)
    fixtures = load(FIXTURE_PATH)
    for value in fixtures["reason_code"]["positive"]:
        if list(reason_validator.iter_errors(value)):
            fail(f"reason positive failed: {value}")
    for value in fixtures["reason_code"]["negative"]:
        if not list(reason_validator.iter_errors(value)):
            fail(f"reason negative passed: {value!r}")
    for case in fixtures["command_result"]["positive"]:
        if list(result_validator.iter_errors(case["value"])):
            fail(f"result positive failed: {case['name']}")
        utc_datetime(case["value"]["server_time"])
    for case in fixtures["command_result"]["negative"]:
        if not list(result_validator.iter_errors(case["value"])):
            fail(f"result negative passed: {case['name']}")
    positives = fixtures["command_envelope"]["positive"]
    for case in positives:
        value = case["value"]
        if list(envelope_validator.iter_errors(value)):
            fail(f"envelope positive failed: {case['name']}")
        if value["caller_type"] != value["caller_identity"]["caller_type"]:
            fail(f"caller type mismatch in positive: {case['name']}")
        utc_datetime(value["requested_at"])
    submit_scope = next(case["value"] for case in positives if case["value"]["command_type"] == "SubmitDiagnosticScope")
    if submit_scope["subject_type"] != "ENGAGEMENT" or submit_scope["subject_id"] != submit_scope["engagement_id"]:
        fail("scope submission must target its existing engagement subject")
    for invalid_subject in ("DIAGNOSTIC_SCOPE", "ACQUISITION_HANDOFF"):
        invalid_submit_scope = copy.deepcopy(submit_scope)
        invalid_submit_scope["subject_type"] = invalid_subject
        if not list(envelope_validator.iter_errors(invalid_submit_scope)):
            fail(f"scope submission accepted invalid subject: {invalid_subject}")
    base = positives[0]["value"]
    for case in fixtures["command_envelope"]["negative"]:
        value = apply_mutation(base, case["mutate"])
        errors = list(envelope_validator.iter_errors(value))
        if case.get("semantic_failure"):
            if value["caller_type"] == value["caller_identity"]["caller_type"]:
                fail(f"envelope semantic negative passed: {case['name']}")
        elif not errors:
            fail(f"envelope negative passed: {case['name']}")
    print(
        "command-protocol validation: PASS "
        f"({len(fixtures['reason_code']['positive']) + len(fixtures['command_result']['positive']) + len(positives)} positive, "
        f"{len(fixtures['reason_code']['negative']) + len(fixtures['command_result']['negative']) + len(fixtures['command_envelope']['negative'])} negative, "
        f"{len(schemas)} unique schema IDs, all refs resolved)"
    )


if __name__ == "__main__":
    main()
