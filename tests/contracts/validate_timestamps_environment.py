#!/usr/bin/env python3
"""Validate timestamp/environment schemas and deterministic fictional fixtures."""

from __future__ import annotations

from datetime import datetime
import json
from pathlib import Path
import sys

from jsonschema import Draft202012Validator, FormatChecker


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_DIRECTORY = REPOSITORY_ROOT / "contracts/schemas/v1/common"
FIXTURE_PATH = REPOSITORY_ROOT / "contracts/fixtures/v1/timestamps-environment.cases.json"
SCHEMA_PATHS = {
    "timestamps": SCHEMA_DIRECTORY / "timestamps.schema.json",
    "environment": SCHEMA_DIRECTORY / "environment.schema.json",
}


def load_json(path: Path) -> object:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def is_rfc3339_datetime(value: object) -> bool:
    """Enforce calendar-valid UTC timestamps with local standard-library tooling."""
    if not isinstance(value, str) or not value.endswith("Z"):
        return False
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return False
    return True


def main() -> int:
    schemas = {name: load_json(path) for name, path in SCHEMA_PATHS.items()}
    fixtures = load_json(FIXTURE_PATH)
    failures: list[str] = []

    all_schema_paths = sorted(SCHEMA_DIRECTORY.glob("*.schema.json"))
    all_schema_ids: list[str] = []
    for path in all_schema_paths:
        schema = load_json(path)
        Draft202012Validator.check_schema(schema)
        all_schema_ids.append(schema["$id"])

    if len(all_schema_ids) != len(set(all_schema_ids)):
        failures.append("schema $id values must be unique")

    environment_values = schemas["environment"]["$defs"]["environment"]["enum"]
    expected_environments = ["LOCAL", "TEST", "DEVELOPMENT", "STAGING", "PRODUCTION"]
    if environment_values != expected_environments:
        failures.append("environment enum differs from the approved closed vocabulary")

    format_checker = FormatChecker()
    format_checker.checks("date-time")(is_rfc3339_datetime)
    for case in fixtures["positive"]:
        definition = schemas[case["schema"]]["$defs"][case["definition"]]
        errors = list(Draft202012Validator(definition, format_checker=format_checker).iter_errors(case["value"]))
        if errors:
            failures.append(f"positive fixture failed: {case['name']}")

    for case in fixtures["negative"]:
        definition = schemas[case["schema"]]["$defs"][case["definition"]]
        errors = list(Draft202012Validator(definition, format_checker=format_checker).iter_errors(case["value"]))
        if not errors:
            failures.append(f"negative fixture unexpectedly passed: {case['name']}")

    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1

    print(
        "timestamp/environment validation: PASS "
        f"({len(fixtures['positive'])} positive, {len(fixtures['negative'])} negative, "
        f"{len(all_schema_ids)} unique schema IDs)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
