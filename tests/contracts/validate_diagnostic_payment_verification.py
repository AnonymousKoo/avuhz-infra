#!/usr/bin/env python3
"""Validate the Phase 5 DiagnosticPaymentVerification contract and its security boundary."""
import copy, json, sys
from datetime import datetime
from pathlib import Path
from jsonschema import Draft202012Validator, FormatChecker
ROOT = Path(__file__).resolve().parents[2]; SCHEMAS = ROOT / "contracts/schemas/v1"
SCHEMA_ID = "urn:avuhz:schema:contracts:domain:diagnostic-payment-verification:v1"
FIXTURES = ROOT / "contracts/fixtures/v1/diagnostic-payment-verification.cases.json"
def load(path):
    with path.open(encoding="utf-8") as handle: return json.load(handle)
def fail(message): print(f"diagnostic-payment-verification validation: FAIL: {message}", file=sys.stderr); raise SystemExit(1)
def resolve(ref, doc, schemas):
    target, fragment = (doc, ref[1:]) if ref.startswith("#") else (schemas[ref.partition("#")[0]], ref.partition("#")[2])
    for part in ([] if not fragment else fragment[1:].split("/")): target = target[part]
    return target
def expand(value, doc, schemas):
    if isinstance(value, dict):
        if "$ref" in value:
            target_doc = doc if value["$ref"].startswith("#") else schemas[value["$ref"].partition("#")[0]]
            return {**expand(copy.deepcopy(resolve(value["$ref"], doc, schemas)), target_doc, schemas), **{k: expand(v, doc, schemas) for k, v in value.items() if k != "$ref"}}
        return {k: expand(v, doc, schemas) for k, v in value.items()}
    if isinstance(value, list): return [expand(v, doc, schemas) for v in value]
    return value
def mutate(value, changes):
    value = copy.deepcopy(value)
    for dotted, replacement in changes.items():
        target = value; parts = dotted.split(".")
        for part in parts[:-1]: target = target[part]
        target[parts[-1]] = replacement
    return value
def stamp(value): return datetime.fromisoformat(value[:-1] + "+00:00")
def semantic(value): return "invalidated_at" not in value or stamp(value["invalidated_at"]) >= stamp(value["verified_at"])
def main():
    paths = sorted(SCHEMAS.rglob("*.schema.json")); schemas = {load(p)["$id"]: load(p) for p in paths}
    for schema in schemas.values(): Draft202012Validator.check_schema(schema)
    schema = schemas[SCHEMA_ID]; props = schema["properties"]
    if props["payment_purpose"].get("const") != "DIAGNOSTIC_OIA": fail("payment purpose widened")
    if props["verification_status"]["enum"] != ["VERIFIED", "INVALIDATED"]: fail("verification status drifted")
    if props["amount_minor"].get("type") != "integer" or props["amount_minor"].get("minimum") != 1: fail("money must be positive integer minor units")
    forbidden = {"invoice", "checkout_session", "card_number", "cvv", "expiration_date", "bank_account", "routing_number", "payment_token", "customer_secret", "webhook_secret", "provider_data", "raw", "metadata", "assessment_access_grant"}
    if forbidden & set(props): fail("payment boundary leaked")
    validator = Draft202012Validator(expand(schema, schema, schemas), format_checker=FormatChecker()); fixtures = load(FIXTURES); base = fixtures["positive"][0]["value"]
    for case in fixtures["positive"]:
        if list(validator.iter_errors(case["value"])) or not semantic(case["value"]): fail(f"positive failed: {case['name']}")
    for case in fixtures["negative"]:
        value = mutate(base, case.get("mutate", {}))
        if "remove" in case: value.pop(case["remove"])
        if case.get("semantic_failure"):
            if semantic(value): fail(f"semantic negative passed: {case['name']}")
        elif not list(validator.iter_errors(value)): fail(f"negative passed: {case['name']}")
    print(f"diagnostic-payment-verification validation: PASS ({len(fixtures['positive'])} positive, {len(fixtures['negative'])} negative, no payment or access leakage)")
if __name__ == "__main__": main()
