#!/usr/bin/env python3
"""Validate the canonical identifiers schema and deterministic fictional fixtures."""

from __future__ import annotations

import json
from pathlib import Path
import sys

from jsonschema import Draft202012Validator, FormatChecker


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = REPOSITORY_ROOT / "contracts/schemas/v1/common/identifiers.schema.json"
FIXTURE_PATH = REPOSITORY_ROOT / "contracts/fixtures/v1/identifiers.cases.json"


def load_json(path: Path) -> object:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def main() -> int:
    schema = load_json(SCHEMA_PATH)
    fixtures = load_json(FIXTURE_PATH)

    Draft202012Validator.check_schema(schema)
    definitions = schema["$defs"]
    failures: list[str] = []

    for case in fixtures["positive"]:
        definition = case["definition"]
        validator = Draft202012Validator(definitions[definition], format_checker=FormatChecker())
        errors = list(validator.iter_errors(case["value"]))
        if errors:
            failures.append(f"positive fixture failed: {case['name']}")

    for case in fixtures["negative"]:
        definition = case["definition"]
        validator = Draft202012Validator(definitions[definition], format_checker=FormatChecker())
        errors = list(validator.iter_errors(case["value"]))
        if not errors:
            failures.append(f"negative fixture unexpectedly passed: {case['name']}")

    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1

    print(
        "identifiers validation: PASS "
        f"({len(fixtures['positive'])} positive, {len(fixtures['negative'])} negative)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
