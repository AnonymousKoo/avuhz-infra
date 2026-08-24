#!/usr/bin/env python3
"""Validate the Phase 5 DiagnosticAgreementAuthority contract and its boundary."""
import copy, json, sys
from datetime import datetime
from pathlib import Path
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = ROOT / "contracts/schemas/v1"
SCHEMA_ID = "urn:avuhz:schema:contracts:domain:diagnostic-agreement-authority:v1"
FIXTURES = ROOT / "contracts/fixtures/v1/diagnostic-agreement-authority.cases.json"

def load(path):
    with path.open(encoding="utf-8") as handle: return json.load(handle)
def fail(message):
    print(f"diagnostic-agreement-authority validation: FAIL: {message}", file=sys.stderr); raise SystemExit(1)
def resolve(ref, document, schemas):
    target, fragment = (document, ref[1:]) if ref.startswith("#") else (schemas[ref.partition("#")[0]], ref.partition("#")[2])
    for part in ([] if not fragment else fragment[1:].split("/")): target = target[part]
    return target
def expand(value, document, schemas):
    if isinstance(value, dict):
        if "$ref" in value:
            expanded = expand(copy.deepcopy(resolve(value["$ref"], document, schemas)), document if value["$ref"].startswith("#") else schemas[value["$ref"].partition("#")[0]], schemas)
            return {**expanded, **{k: expand(v, document, schemas) for k, v in value.items() if k != "$ref"}}
        return {k: expand(v, document, schemas) for k, v in value.items()}
    if isinstance(value, list): return [expand(v, document, schemas) for v in value]
    return value
def mutate(value, changes):
    value = copy.deepcopy(value)
    for dotted, replacement in changes.items():
        target = value; parts = dotted.split(".")
        for part in parts[:-1]: target = target[part]
        target[parts[-1]] = replacement
    return value
def stamp(value): return datetime.fromisoformat(value[:-1] + "+00:00")
def semantic(value):
    if "ends_at" in value and stamp(value["ends_at"]) <= stamp(value["effective_at"]): return False
    if stamp(value["verified_at"]) < stamp(value["effective_at"]): return False
    if stamp(value["recorded_at"]) < stamp(value["verified_at"]): return False
    if "supersedes_reference" in value and value["supersedes_reference"]["reference_id"] == value["diagnostic_agreement_authority_id"]: return False
    return True
def main():
    paths = sorted(SCHEMAS.rglob("*.schema.json")); schemas = {load(p)["$id"]: load(p) for p in paths}
    for schema in schemas.values(): Draft202012Validator.check_schema(schema)
    schema = schemas[SCHEMA_ID]
    if schema["properties"]["agreement_type"].get("const") != "DIAGNOSTIC_OIA": fail("agreement type widened")
    if schema["properties"]["status"]["enum"] != ["VERIFIED_ACTIVE", "EXPIRED", "REVOKED", "SUPERSEDED"]: fail("status vocabulary drifted")
    prohibited = {"contract_document", "signature", "provider_payload", "payment", "credential", "access_grant", "production_change_authority", "metadata"}
    if prohibited & set(schema["properties"]): fail("authority boundary leaked")
    validator = Draft202012Validator(expand(schema, schema, schemas), format_checker=FormatChecker())
    fixtures = load(FIXTURES); base = fixtures["positive"][0]["value"]
    for case in fixtures["positive"]:
        if list(validator.iter_errors(case["value"])) or not semantic(case["value"]): fail(f"positive failed: {case['name']}")
    for case in fixtures["negative"]:
        value = mutate(base, case.get("mutate", {}))
        if "remove" in case: value.pop(case["remove"])
        if case.get("semantic_failure"):
            if semantic(value): fail(f"semantic negative passed: {case['name']}")
        elif not list(validator.iter_errors(value)): fail(f"negative passed: {case['name']}")
    print(f"diagnostic-agreement-authority validation: PASS ({len(fixtures['positive'])} positive, {len(fixtures['negative'])} negative, no authority leakage)")
if __name__ == "__main__": main()
