#!/usr/bin/env python3
"""Validate typed-reference schemas and deterministic fictional fixtures."""

from __future__ import annotations

import json
from pathlib import Path
import sys
import warnings

from jsonschema import Draft202012Validator, FormatChecker, RefResolver


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_DIRECTORY = REPOSITORY_ROOT / "contracts/schemas/v1/common"
REFERENCE_SCHEMA_PATH = SCHEMA_DIRECTORY / "references.schema.json"
FIXTURE_PATH = REPOSITORY_ROOT / "contracts/fixtures/v1/references.cases.json"


def load_json(path: Path) -> object:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def iter_refs(value: object):
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "$ref" and isinstance(child, str):
                yield child
            else:
                yield from iter_refs(child)
    elif isinstance(value, list):
        for child in value:
            yield from iter_refs(child)


def resolve_pointer(document: object, fragment: str) -> object:
    current = document
    if not fragment:
        return current
    if not fragment.startswith("/"):
        raise KeyError(fragment)
    for raw_part in fragment[1:].split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        current = current[part]
    return current


def main() -> int:
    schema_paths = sorted(SCHEMA_DIRECTORY.glob("*.schema.json"))
    schemas = [load_json(path) for path in schema_paths]
    schema_by_id = {schema["$id"]: schema for schema in schemas}
    fixtures = load_json(FIXTURE_PATH)
    failures: list[str] = []

    for schema in schemas:
        Draft202012Validator.check_schema(schema)

    if len(schema_by_id) != len(schemas):
        failures.append("schema $id values must be unique")

    reference_schema = load_json(REFERENCE_SCHEMA_PATH)
    for ref in iter_refs(reference_schema):
        if ref.startswith("#"):
            target_document = reference_schema
            fragment = ref[1:]
        else:
            target_id, separator, fragment = ref.partition("#")
            if target_id not in schema_by_id:
                failures.append(f"unresolved schema ID: {target_id}")
                continue
            target_document = schema_by_id[target_id]
            fragment = fragment if separator else ""
        try:
            resolve_pointer(target_document, fragment)
        except (KeyError, TypeError):
            failures.append(f"unresolved schema pointer: {ref}")

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        resolver = RefResolver.from_schema(reference_schema, store=schema_by_id)

    format_checker = FormatChecker()
    for case in fixtures["positive"]:
        definition = reference_schema["$defs"][case["definition"]]
        validator = Draft202012Validator(
            definition,
            resolver=resolver,
            format_checker=format_checker,
        )
        errors = list(validator.iter_errors(case["value"]))
        if errors:
            failures.append(f"positive fixture failed: {case['name']}")

    for case in fixtures["negative"]:
        definition = reference_schema["$defs"][case["definition"]]
        validator = Draft202012Validator(
            definition,
            resolver=resolver,
            format_checker=format_checker,
        )
        errors = list(validator.iter_errors(case["value"]))
        if not errors:
            failures.append(f"negative fixture unexpectedly passed: {case['name']}")

    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1

    print(
        "typed-reference validation: PASS "
        f"({len(fixtures['positive'])} positive, {len(fixtures['negative'])} negative, "
        f"{len(schemas)} unique schema IDs, all refs resolved)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
