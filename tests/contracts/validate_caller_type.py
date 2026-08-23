#!/usr/bin/env python3
"""Validate the Slice 1 CallerType contract using only local tooling."""

import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "contracts/schemas/v1/identity/caller-type.schema.json"
FIXTURE_PATH = ROOT / "contracts/fixtures/v1/caller-type.cases.json"
EXPECTED_ENUM = [
    "HUMAN",
    "CLIENT_USER",
    "SEKINFRA_USER",
    "INTERNAL_SERVICE",
    "N8N_ORCHESTRATOR",
    "PROVIDER_ADAPTER",
    "SCHEDULED_AUTOMATION",
    "SECURITY_AUTOMATION",
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
    print(f"caller-type validation: FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def main():
    schema = load_json(SCHEMA_PATH)
    fixtures = load_json(FIXTURE_PATH)

    try:
        Draft202012Validator.check_schema(schema)
    except Exception as error:
        fail(f"schema is invalid: {error}")

    if set(schema) != EXPECTED_KEYS:
        fail("schema contains unexpected or missing keywords")
    if schema["type"] != "string":
        fail("caller type must be a string")
    if schema["enum"] != EXPECTED_ENUM:
        fail("caller-type enum differs from the approved closed vocabulary")
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
    for case in fixtures["positive"]:
        if list(validator.iter_errors(case["value"])):
            fail(f"positive fixture failed: {case['name']}")
    for case in fixtures["negative"]:
        if not list(validator.iter_errors(case["value"])):
            fail(f"negative fixture passed: {case['name']}")

    print(
        "caller-type validation: PASS "
        f"({len(fixtures['positive'])} positive, {len(fixtures['negative'])} negative, "
        f"{len(ids)} unique schema IDs)"
    )


if __name__ == "__main__":
    main()
