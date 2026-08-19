#!/usr/bin/env python3
"""Validate Slice 1 AcquisitionHandoff and Engagement contracts locally."""

from __future__ import annotations

import copy
from datetime import datetime
import json
from pathlib import Path
import sys

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[2]
SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
FIXTURE_PATH = ROOT / "contracts/fixtures/v1/handoff-engagement.cases.json"
HANDOFF_ID = "urn:avuhz:schema:contracts:domain:acquisition-handoff:v1"
ENGAGEMENT_ID = "urn:avuhz:schema:contracts:domain:engagement:v1"


def load(path):
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def fail(message):
    print(f"handoff-engagement validation: FAIL: {message}", file=sys.stderr)
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


def apply_mutation(value, mutation):
    copied = copy.deepcopy(value)
    for dotted_key, replacement in mutation.items():
        target = copied
        parts = dotted_key.split(".")
        for part in parts[:-1]:
            target = target[part]
        target[parts[-1]] = replacement
    return copied


def make_negative(base, case):
    value = apply_mutation(base, case.get("mutate", {}))
    if case.get("operation") == "oversize_target":
        value["target_outcome"] = "x" * 2001
    if case.get("operation") == "too_many_constraints":
        value["validated_constraints"] = [copy.deepcopy(base["validated_constraints"][0]) for _ in range(26)]
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
    for schema_id in (HANDOFF_ID, ENGAGEMENT_ID):
        for reference in all_refs(schemas[schema_id]):
            try:
                resolve(reference, schemas[schema_id], schemas)
            except (KeyError, TypeError):
                fail(f"unresolved reference: {reference}")

    handoff_schema = dereference(schemas[HANDOFF_ID], schemas[HANDOFF_ID], schemas)
    engagement_schema = dereference(schemas[ENGAGEMENT_ID], schemas[ENGAGEMENT_ID], schemas)
    if schemas[HANDOFF_ID]["properties"]["qualification_status"]["enum"] != ["QUALIFIED", "QUALIFIED_WITH_CONDITIONS"]:
        fail("handoff qualification vocabulary drifted")
    if schemas[ENGAGEMENT_ID]["properties"]["engagement_state"]["enum"] != ["OPEN", "ONBOARDING"]:
        fail("engagement state vocabulary drifted")
    if schemas[ENGAGEMENT_ID]["properties"]["engagement_type"].get("const") != "DIAGNOSTIC_OIA":
        fail("engagement type must remain DIAGNOSTIC_OIA")
    forbidden = {"metadata", "lead_history", "nurture_history", "campaign_history", "opener_verification", "communication_history", "transcript", "credentials", "payment", "agreement_authority", "access_authority", "implementation_authority", "deployment_authority"}
    if forbidden & set(schemas[HANDOFF_ID]["properties"]):
        fail("handoff exposes prohibited acquisition or authority fields")
    if "account" in schemas[ENGAGEMENT_ID]["properties"]:
        fail("engagement must keep account identity as a reference")

    checker = FormatChecker()
    checker.checks("date-time")(lambda value: isinstance(value, str) and value.endswith("Z"))
    handoff_validator = Draft202012Validator(handoff_schema, format_checker=checker)
    engagement_validator = Draft202012Validator(engagement_schema, format_checker=checker)
    fixtures = load(FIXTURE_PATH)
    for case in fixtures["acquisition_handoff"]["positive"]:
        if list(handoff_validator.iter_errors(case["value"])):
            fail(f"handoff positive failed: {case['name']}")
        utc_datetime(case["value"]["produced_at"])
    handoff_base = fixtures["acquisition_handoff"]["positive"][0]["value"]
    for case in fixtures["acquisition_handoff"]["negative"]:
        if not list(handoff_validator.iter_errors(make_negative(handoff_base, case))):
            fail(f"handoff negative passed: {case['name']}")
    for case in fixtures["engagement"]["positive"]:
        if list(engagement_validator.iter_errors(case["value"])):
            fail(f"engagement positive failed: {case['name']}")
        utc_datetime(case["value"]["opened_at"])
    engagement_base = fixtures["engagement"]["positive"][0]["value"]
    for case in fixtures["engagement"]["negative"]:
        if not list(engagement_validator.iter_errors(apply_mutation(engagement_base, case["mutate"]))):
            fail(f"engagement negative passed: {case['name']}")
    print(
        "handoff-engagement validation: PASS "
        f"({len(fixtures['acquisition_handoff']['positive']) + len(fixtures['engagement']['positive'])} positive, "
        f"{len(fixtures['acquisition_handoff']['negative']) + len(fixtures['engagement']['negative'])} negative, "
        f"{len(schemas)} unique schema IDs, all refs resolved)"
    )


if __name__ == "__main__":
    main()
