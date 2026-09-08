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
from avuhz_runtime.implementation_handoff import canonical_digest
from avuhz_runtime.schema_registry import SchemaRegistry


PLAN_PATH = ROOT / "contracts/plans/v1/development-auth-integration.plan.json"
PROGRESS_PATH = ROOT / "contracts/plans/v1/development-auth-integration.progress.json"
STEP1_EVIDENCE_PATH = ROOT / "contracts/plans/v1/development-auth-step1-baseline.evidence.json"
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
    step1_evidence = json.loads(STEP1_EVIDENCE_PATH.read_text())
    fixtures = json.loads(FIXTURE_PATH.read_text())

    validate_plan(plan, schemas)
    validate_progress(plan, progress, schemas)

    failures = []

    step1 = plan["steps"][0]
    baseline_requirement = step1["required_evidence"][0]
    migration_evidence = step1_evidence.get("artifacts", {}).get("migration", {})
    source_evidence = step1_evidence.get("source", {})
    results_evidence = step1_evidence.get("results", {})

    if (
        baseline_requirement["binding_state"] != "BOUND"
        or baseline_requirement["exact_digest"] != canonical_digest(step1_evidence)
    ):
        failures.append("DEVELOPMENT Step 1 baseline evidence binding mismatch")

    if (
        step1_evidence.get("evidence_type") != "baseline.lineage.green"
        or step1_evidence.get("environment") != plan["environment"]
        or step1_evidence.get("responsibility") != plan["target"]["responsibility"]
        or step1_evidence.get("project_reference") != plan["target"]["project_reference"]
        or migration_evidence.get("path") != step1["resource"]["resource_reference"]
        or migration_evidence.get("content_digest") != step1["resource"]["exact_digest"]
        or f"git.commit.{source_evidence.get('merged_main_commit')}" != step1["resource"]["exact_version"]
        or results_evidence.get("postgres_validation_passed") is not True
        or results_evidence.get("baseline_gate_passed") is not True
        or results_evidence.get("provider_contact_attempted") is not False
        or results_evidence.get("remote_mutation_attempted") is not False
    ):
        failures.append("DEVELOPMENT Step 1 baseline evidence content mismatch")

    if plan["ordered_step_ids"] != EXPECTED_STEPS:
        failures.append("DEVELOPMENT step sequence differs from owner-approved intent")

    if plan["plan_version"] != 2:
        failures.append("DEVELOPMENT evidence-binding plan must be version 2")

    if (plan["environment"], plan["target"]["project_reference"], plan["target"]["responsibility"]) != (
        "DEVELOPMENT", "pwlhruwutoitnieactol", "AUTH",
    ):
        failures.append("DEVELOPMENT target binding mismatch")

    if plan["target"]["issuer_reference"] != "https://pwlhruwutoitnieactol.supabase.co/auth/v1":
        failures.append("DEVELOPMENT issuer mismatch")

    if plan["target"]["audience_reference"] != "audience.avuhz.command-service.development":
        failures.append("DEVELOPMENT audience mismatch")

    if (
        plan["definition_status"] != "DRAFT_BLOCKED"
        or plan["authorization_window"]["binding_state"] != "UNRESOLVED_BLOCKER"
    ):
        failures.append("unapproved plan must remain blocked")

    if step1["resource"]["binding_state"] != "BOUND" or step1["unresolved_bindings"]:
        failures.append("DEVELOPMENT Step 1 artifact binding is incomplete")

    if not any(step["unresolved_bindings"] for step in plan["steps"][1:]):
        failures.append("unresolved provider-created bindings were invented")

    if any(
        state["authorization_state"] != "PENDING"
        or state["execution_state"] != "NOT_STARTED"
        or state["verification_state"] != "NOT_STARTED"
        or state["authorization_consumed"]
        for state in progress["step_states"]
    ):
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
        "(3 schemas, 11 ordered DEVELOPMENT steps, Step 1 evidence bound, "
        "blocked unresolved draft, separate approval, one-resource evidence gates)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
