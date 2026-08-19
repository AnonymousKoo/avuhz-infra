#!/usr/bin/env python3
"""Validate the Slice 1 CallerIdentity contract with local tooling only."""

from __future__ import annotations

import copy
from datetime import datetime
import json
from pathlib import Path
import sys

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "contracts/schemas/v1/identity/caller-identity.schema.json"
FIXTURE_PATH = ROOT / "contracts/fixtures/v1/caller-identity.cases.json"
CALLER_TYPE_PATH = ROOT / "contracts/schemas/v1/identity/caller-type.schema.json"
CAPABILITY_PATH = ROOT / "contracts/schemas/v1/identity/capability.schema.json"


def load_json(path: Path):
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def iter_refs(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "$ref" and isinstance(child, str):
                yield child
            else:
                yield from iter_refs(child)
    elif isinstance(value, list):
        for child in value:
            yield from iter_refs(child)


def resolve_pointer(document, fragment):
    current = document
    if not fragment:
        return current
    if not fragment.startswith("/"):
        raise KeyError(fragment)
    for raw_part in fragment[1:].split("/"):
        current = current[raw_part.replace("~1", "/").replace("~0", "~")]
    return current


def resolve_reference(reference, current_document, schemas):
    if reference.startswith("#"):
        target_document = current_document
        fragment = reference[1:]
    else:
        target_id, separator, fragment = reference.partition("#")
        target_document = schemas.get(target_id)
        if target_document is None:
            raise KeyError(target_id)
        fragment = fragment if separator else ""
    return target_document, resolve_pointer(target_document, fragment)


def dereference(value, current_document, schemas):
    """Inline local refs, preserving supported sibling keywords, for local tests."""
    if isinstance(value, dict):
        if "$ref" in value:
            target_document, target = resolve_reference(value["$ref"], current_document, schemas)
            resolved_target = dereference(copy.deepcopy(target), target_document, schemas)
            siblings = {
                key: dereference(child, current_document, schemas)
                for key, child in value.items()
                if key != "$ref"
            }
            if not isinstance(resolved_target, dict):
                raise ValueError("Slice 1 reference target must be an object schema")
            return {**resolved_target, **siblings}
        return {
            key: dereference(child, current_document, schemas)
            for key, child in value.items()
        }
    if isinstance(value, list):
        return [dereference(child, current_document, schemas) for child in value]
    return value


def utc_datetime(value):
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("expected UTC Z timestamp")
    return datetime.fromisoformat(value[:-1] + "+00:00")


def fail(message: str):
    print(f"caller-identity validation: FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def main():
    schema_paths = sorted((ROOT / "contracts/schemas/v1").rglob("*.schema.json"))
    schemas = {schema["$id"]: schema for path in schema_paths for schema in [load_json(path)]}
    if len(schemas) != len(schema_paths):
        fail("schema $id values must be present and unique")
    for schema_id, schema in schemas.items():
        if not schema_id:
            fail("schema $id must be present")
        try:
            Draft202012Validator.check_schema(schema)
        except Exception as error:
            fail(f"invalid schema {schema_id}: {error}")

    identity_schema = load_json(SCHEMA_PATH)
    for reference in iter_refs(identity_schema):
        try:
            resolve_reference(reference, identity_schema, schemas)
        except (KeyError, TypeError):
            fail(f"unresolved schema pointer: {reference}")

    format_checker = FormatChecker()
    format_checker.checks("date-time")(lambda value: isinstance(value, str) and value.endswith("Z"))
    resolved_identity_schema = dereference(identity_schema, identity_schema, schemas)
    validator = Draft202012Validator(resolved_identity_schema, format_checker=format_checker)
    fixtures = load_json(FIXTURE_PATH)

    for case in fixtures["positive"]:
        if list(validator.iter_errors(case["value"])):
            fail(f"positive fixture failed schema validation: {case['name']}")
        if utc_datetime(case["value"]["expires_at"]) <= utc_datetime(case["value"]["authenticated_at"]):
            fail(f"positive fixture has invalid timestamp order: {case['name']}")

    for case in fixtures["negative"]:
        schema_errors = list(validator.iter_errors(case["value"]))
        semantic_failure = case.get("semantic_failure")
        if semantic_failure:
            try:
                semantic_failed = utc_datetime(case["value"]["expires_at"]) <= utc_datetime(case["value"]["authenticated_at"])
            except (KeyError, TypeError, ValueError):
                semantic_failed = True
            if not semantic_failed:
                fail(f"negative semantic fixture passed: {case['name']}")
        elif not schema_errors:
            fail(f"negative fixture passed schema validation: {case['name']}")

    capability_schema = load_json(CAPABILITY_PATH)
    caller_type_schema = load_json(CALLER_TYPE_PATH)
    capability_validator = Draft202012Validator(capability_schema)
    caller_type_validator = Draft202012Validator(caller_type_schema)
    for value in capability_schema["enum"]:
        if not list(caller_type_validator.iter_errors(value)):
            fail(f"capability accepted as caller type: {value}")
    for value in caller_type_schema["enum"]:
        if not list(capability_validator.iter_errors(value)):
            fail(f"caller type accepted as capability: {value}")

    if identity_schema["properties"]["capabilities"]["minItems"] != 0:
        fail("capability list must permit non-command identities with zero capabilities")
    print(
        "caller-identity validation: PASS "
        f"({len(fixtures['positive'])} positive, {len(fixtures['negative'])} negative, "
        f"{len(schemas)} unique schema IDs, all refs resolved)"
    )


if __name__ == "__main__":
    main()
