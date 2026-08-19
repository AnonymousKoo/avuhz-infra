#!/usr/bin/env python3
"""Validate Slice 1 HumanApproval and DiagnosticScope contracts locally."""

from __future__ import annotations

import copy
from datetime import datetime
import json
from pathlib import Path
import sys

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[2]
SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
FIXTURE_PATH = ROOT / "contracts/fixtures/v1/approval-diagnostic-scope.cases.json"
APPROVAL_ID = "urn:avuhz:schema:contracts:domain:human-approval:v1"
SCOPE_ID = "urn:avuhz:schema:contracts:domain:diagnostic-scope:v1"
MANDATORY_PROHIBITIONS = {"CREATE", "MODIFY", "DELETE", "DEPLOY", "RESTART", "ROTATE", "GRANT", "REVOKE", "CHANGE_CONFIGURATION", "PRODUCTION_CHANGE"}


def load(path):
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def fail(message):
    print(f"approval-diagnostic-scope validation: FAIL: {message}", file=sys.stderr)
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


def make_scope_negative(base, case):
    value = apply_mutation(base, case.get("mutate", {}))
    if case.get("operation") == "missing_prohibition":
        value["prohibited_actions"] = value["prohibited_actions"][1:]
    if case.get("operation") == "oversize_target":
        value["target_outcome"] = "x" * 2001
    return value


def utc_datetime(value):
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("expected UTC Z timestamp")
    return datetime.fromisoformat(value[:-1] + "+00:00")


def approval_semantics(value):
    if value["authority_category"] == "CLIENT_AUTHORITY" and value["actor_role"] != "CLIENT_DECISION_AUTHORITY":
        return False
    if value["authority_category"] == "SEKINFRA_AUTHORITY" and value["actor_role"] != "SEKINFRA_ENGAGEMENT_AUTHORITY":
        return False
    if value["scope"]["subject_id"] != value["subject_id"] or value["scope"]["subject_version"] != value["subject_version"]:
        return False
    if "expires_at" in value and utc_datetime(value["expires_at"]) <= utc_datetime(value["effective_at"]):
        return False
    if "supersedes_reference" in value and value["supersedes_reference"]["reference_id"] == value["approval_id"]:
        return False
    return True


def scope_semantics(value):
    if not MANDATORY_PROHIBITIONS.issubset(set(value["prohibited_actions"])):
        return False
    if set(value["permitted_diagnostic_actions"]) & MANDATORY_PROHIBITIONS:
        return False
    if value["status"] == "APPROVED":
        if value["client_approval_reference"] == value["sekinfra_approval_reference"]:
            return False
    if "supersedes_reference" in value and value["supersedes_reference"]["reference_id"] == value["diagnostic_scope_id"]:
        return False
    return True


def main():
    paths = sorted(SCHEMA_ROOT.rglob("*.schema.json"))
    schemas = {schema["$id"]: schema for path in paths for schema in [load(path)]}
    if len(schemas) != len(paths) or any(not schema_id for schema_id in schemas):
        fail("schema IDs must be present and globally unique")
    for schema in schemas.values():
        Draft202012Validator.check_schema(schema)
    for schema_id in (APPROVAL_ID, SCOPE_ID):
        for reference in all_refs(schemas[schema_id]):
            try:
                resolve(reference, schemas[schema_id], schemas)
            except (KeyError, TypeError):
                fail(f"unresolved reference: {reference}")

    approval_schema = dereference(schemas[APPROVAL_ID], schemas[APPROVAL_ID], schemas)
    scope_schema = dereference(schemas[SCOPE_ID], schemas[SCOPE_ID], schemas)
    if schemas[APPROVAL_ID]["properties"]["authority_category"]["enum"] != ["CLIENT_AUTHORITY", "SEKINFRA_AUTHORITY"]:
        fail("approval authority vocabulary drifted")
    if "JOINT_AUTHORITY" in schemas[APPROVAL_ID]["properties"]["authority_category"]["enum"]:
        fail("joint authority must remain derived, not recorded")
    if schemas[SCOPE_ID]["properties"]["status"]["enum"] != ["DRAFT", "REVIEW_PENDING", "APPROVED", "REJECTED", "SUPERSEDED", "CANCELLED"]:
        fail("scope status vocabulary drifted")
    if "metadata" in schemas[APPROVAL_ID]["properties"] or "metadata" in schemas[SCOPE_ID]["properties"]:
        fail("metadata escape hatch is forbidden")

    checker = FormatChecker()
    checker.checks("date-time")(lambda value: isinstance(value, str) and value.endswith("Z"))
    approval_validator = Draft202012Validator(approval_schema, format_checker=checker)
    scope_validator = Draft202012Validator(scope_schema, format_checker=checker)
    fixtures = load(FIXTURE_PATH)
    approval_positive = fixtures["human_approval"]["positive"]
    for case in approval_positive:
        if list(approval_validator.iter_errors(case["value"])) or not approval_semantics(case["value"]):
            fail(f"approval positive failed: {case['name']}")
    approval_base = approval_positive[0]["value"]
    for case in fixtures["human_approval"]["negative"]:
        value = apply_mutation(approval_base, case["mutate"])
        errors = list(approval_validator.iter_errors(value))
        if case.get("semantic_failure"):
            if approval_semantics(value):
                fail(f"approval semantic negative passed: {case['name']}")
        elif not errors:
            fail(f"approval negative passed: {case['name']}")
    scope_positive = fixtures["diagnostic_scope"]["positive"]
    for case in scope_positive:
        if list(scope_validator.iter_errors(case["value"])) or not scope_semantics(case["value"]):
            fail(f"scope positive failed: {case['name']}")
    scope_base = scope_positive[0]["value"]
    for case in fixtures["diagnostic_scope"]["negative"]:
        value = make_scope_negative(scope_base, case)
        errors = list(scope_validator.iter_errors(value))
        if case.get("semantic_failure"):
            if scope_semantics(value):
                fail(f"scope semantic negative passed: {case['name']}")
        elif not errors:
            fail(f"scope negative passed: {case['name']}")
    print(
        "approval-diagnostic-scope validation: PASS "
        f"({len(approval_positive) + len(scope_positive)} positive, "
        f"{len(fixtures['human_approval']['negative']) + len(fixtures['diagnostic_scope']['negative'])} negative, "
        f"{len(schemas)} unique schema IDs, all refs resolved)"
    )


if __name__ == "__main__":
    main()
