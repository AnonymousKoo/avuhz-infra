#!/usr/bin/env python3
"""Validate the provider-neutral plan model and exact blocked DEVELOPMENT draft."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.authorization_plan import validate_plan, validate_progress
from avuhz_runtime.schema_registry import SchemaRegistry


PLAN_PATH = ROOT / "contracts/plans/v1/development-auth-integration.plan.json"
PROGRESS_PATH = ROOT / "contracts/plans/v1/development-auth-integration.progress.json"
FIXTURE_PATH = ROOT / "contracts/fixtures/v1/authorization-plan.cases.json"
EXPECTED_STEPS = [
    "development.auth.step.01.local-hook-migration",
    "development.auth.step.02.apply-hook-migration",
    "development.auth.step.03.verify-disabled-hook",
    "development.auth.step.04.create-synthetic-identity",
    "development.auth.step.05.bind-synthetic-tenant",
    "development.auth.step.06.bind-server-capability",
    "development.auth.step.07.enable-hook",
    "development.auth.step.08.issue-ephemeral-token",
    "development.auth.step.09.fetch-jwks",
    "development.auth.step.10.validate-token-locally",
    "development.auth.step.11.record-evidence-and-terminate",
]


def main() -> int:
    schemas = ROOT / "contracts/schemas/v1"
    registry = SchemaRegistry(schemas)
    for schema_id in (
        "urn:avuhz:schema:contracts:orchestration:bounded-authorization-plan:v1",
        "urn:avuhz:schema:contracts:orchestration:bounded-authorization-plan-approval:v1",
        "urn:avuhz:schema:contracts:orchestration:bounded-authorization-plan-progress:v1",
    ):
        Draft202012Validator.check_schema(registry.resolve(schema_id))
        registry.expanded(schema_id)
    plan = json.loads(PLAN_PATH.read_text())
    progress = json.loads(PROGRESS_PATH.read_text())
    fixtures = json.loads(FIXTURE_PATH.read_text())
    validate_plan(plan, schemas)
    validate_progress(plan, progress, schemas)
    failures = []
    if plan["ordered_step_ids"] != EXPECTED_STEPS:
        failures.append("DEVELOPMENT step sequence differs from owner-approved intent")
    if (plan["environment"], plan["target"]["project_reference"], plan["target"]["responsibility"]) != (
        "DEVELOPMENT", "pwlhruwutoitnieactol", "AUTH",
    ):
        failures.append("DEVELOPMENT target binding mismatch")
    if plan["target"]["issuer_reference"] != "https://pwlhruwutoitnieactol.supabase.co/auth/v1":
        failures.append("DEVELOPMENT issuer mismatch")
    if plan["target"]["audience_reference"] != "audience.avuhz.command-service.development":
        failures.append("DEVELOPMENT audience mismatch")
    if plan["definition_status"] != "DRAFT_BLOCKED" or plan["authorization_window"]["binding_state"] != "UNRESOLVED_BLOCKER":
        failures.append("unapproved plan must remain blocked")
    if not any(step["unresolved_bindings"] for step in plan["steps"]):
        failures.append("unresolved provider-created bindings were invented")
    if any(state["authorization_state"] != "PENDING" or state["execution_state"] != "NOT_STARTED"
           or state["verification_state"] != "NOT_STARTED" or state["authorization_consumed"]
           for state in progress["step_states"]):
        failures.append("draft progress must remain entirely unexecuted")
    if list((ROOT / "contracts/plans/v1").glob("*approval*.json")):
        failures.append("owner approval record must not be fabricated")
    if not fixtures.get("fictional_only"):
        failures.append("contract fixtures must be fictional")
    if "public.avuhz_development_custom_access_token_hook_v1(jsonb)" not in PLAN_PATH.read_text():
        failures.append("exact hook target missing")
    if any(step["credential_policy"]["values_stored"] for step in plan["steps"]):
        failures.append("credential values may not be stored")
    if any(len(step["dependency_step_ids"]) > 1 for step in plan["steps"]):
        failures.append("draft must advance one immediately dependent resource boundary at a time")
    required_prohibitions = {
        "batch.mutation", "scope.expansion", "step.skip", "step.reorder",
        "failed-mutation.retry", "automatic.self-repair", "data.operation", "render.operation",
        "staging.target", "production.target",
        "jwt.authority", "secret.persist",
    }
    if not required_prohibitions <= set(plan["prohibited_actions"]):
        failures.append("global security prohibitions incomplete")
    if failures:
        for failure in failures:
            print(f"bounded authorization-plan validation: FAIL: {failure}", file=sys.stderr)
        return 1
    print(
        "bounded authorization-plan validation: PASS "
        "(3 schemas, 11 ordered DEVELOPMENT steps, blocked unresolved draft, "
        "separate approval, one-resource evidence gates)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
