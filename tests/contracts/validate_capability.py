#!/usr/bin/env python3
"""Validate the Slice 1 Capability contract using only local tooling."""

import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "contracts/schemas/v1/identity/capability.schema.json"
CALLER_TYPE_SCHEMA_PATH = ROOT / "contracts/schemas/v1/identity/caller-type.schema.json"
FIXTURE_PATH = ROOT / "contracts/fixtures/v1/capability.cases.json"
EXPECTED_ENUM = [
    "engagement:read",
    "engagement:accept_handoff",
    "engagement:open",
    "scope:read",
    "scope:submit",
    "scope:approve",
    "assessment_access:approve",
    "assessment_access:propose",
    "assessment_access:issue",
    "assessment_access:verify",
    "assessment_access:expire",
    "assessment_access:revoke",
    "assessment_access:close",
    "approval:create",
    "diagnostic_agreement:record",
    "diagnostic_payment:record",
    "diagnostic_payment:invalidate",
    "inbound_event:record",
    "event:publish_internal",
    "oia:open",
    "oia:evidence:record",
    "oia:observation:record",
    "oia:root_cause:record",
    "oia:finding:write",
    "oia:finding:finalize",
    "oia:assessment:review",
    "oia:findings:deliver",
    "oia:assessment:close",
]
EXPECTED_KEYS = {
    "$schema",
    "$id",
    "title",
    "description",
    "type",
    "minLength",
    "maxLength",
    "enum",
}


def load_json(path: Path):
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def fail(message: str):
    print(f"capability validation: FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def main():
    schema = load_json(SCHEMA_PATH)
    caller_type_schema = load_json(CALLER_TYPE_SCHEMA_PATH)
    fixtures = load_json(FIXTURE_PATH)

    for name, candidate_schema in (("capability", schema), ("caller type", caller_type_schema)):
        try:
            Draft202012Validator.check_schema(candidate_schema)
        except Exception as error:
            fail(f"{name} schema is invalid: {error}")

    if set(schema) != EXPECTED_KEYS:
        fail("schema contains unexpected or missing keywords")
    if schema["type"] != "string":
        fail("capability must be a string")
    if schema["enum"] != EXPECTED_ENUM:
        fail("capability enum differs from the approved closed vocabulary")
    if any("*" in value for value in schema["enum"]):
        fail("capability enum must not contain wildcard values")
    if schema["minLength"] != min(len(value) for value in EXPECTED_ENUM):
        fail("minLength is not bounded to the approved vocabulary")
    if schema["maxLength"] != max(len(value) for value in EXPECTED_ENUM):
        fail("maxLength is not bounded to the approved vocabulary")

    ids = []
    for candidate in sorted((ROOT / "contracts/schemas/v1").rglob("*.schema.json")):
        candidate_schema = load_json(candidate)
        try:
            Draft202012Validator.check_schema(candidate_schema)
        except Exception as error:
            fail(f"invalid schema {candidate.relative_to(ROOT)}: {error}")
        ids.append(candidate_schema.get("$id"))
    if any(not identifier for identifier in ids) or len(ids) != len(set(ids)):
        fail("schema $id values must be present and unique")

    validator = Draft202012Validator(schema)
    caller_type_validator = Draft202012Validator(caller_type_schema)
    for case in fixtures["positive"]:
        if list(validator.iter_errors(case["value"])):
            fail(f"positive fixture failed: {case['name']}")
        if not list(caller_type_validator.iter_errors(case["value"])):
            fail(f"capability accepted as caller type: {case['name']}")
    for case in fixtures["negative"]:
        if not list(validator.iter_errors(case["value"])):
            fail(f"negative fixture passed: {case['name']}")
    for caller_type in caller_type_schema["enum"]:
        if not list(validator.iter_errors(caller_type)):
            fail(f"caller type accepted as capability: {caller_type}")

    print(
        "capability validation: PASS "
        f"({len(fixtures['positive'])} positive, {len(fixtures['negative'])} negative, "
        f"{len(ids)} unique schema IDs)"
    )


if __name__ == "__main__":
    main()
