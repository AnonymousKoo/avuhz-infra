#!/usr/bin/env python3
"""Validate the provider-neutral plan model and exact blocked DEVELOPMENT v5 draft."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.authorization_plan import (
    plan_digest,
    progress_digest,
    validate_plan,
    validate_progress,
)
from avuhz_runtime.implementation_handoff import canonical_digest
from avuhz_runtime.schema_registry import SchemaRegistry


PLAN_PATH = ROOT / "contracts/plans/v1/development-auth-integration.plan.json"
PROGRESS_PATH = ROOT / "contracts/plans/v1/development-auth-integration.progress.json"
HISTORICAL_STEP1_EVIDENCE_PATH = (
    ROOT / "contracts/plans/v1/development-auth-step1-baseline.evidence.json"
)
REJECTED_V3_EVIDENCE_PATH = (
    ROOT / "contracts/plans/v1/development-auth-step1-v3-local.evidence.json"
)
STEP1_EVIDENCE_PATH = (
    ROOT / "contracts/plans/v1/development-auth-step1-v5-local.evidence.json"
)
PROVIDER_PREFLIGHT_PATH = ROOT / "contracts/plans/v1/development-auth-provider-preflight.evidence.json"
IDENTITY_MIGRATION_PATH = (
    ROOT
    / "supabase/migrations/20260908132000_development_auth_migration_identity_v1.sql"
)
HOOK_MIGRATION_PATH = (
    ROOT
    / "supabase/migrations/20260908133000_development_auth_custom_access_token_hook_v1.sql"
)
SEAL_MIGRATION_PATH = (
    ROOT
    / "supabase/migrations/20260908134000_development_auth_migration_identity_seal_v1.sql"
)
IDENTITY_TEST_PATH = (
    ROOT / "tests/migrations/test_development_auth_migration_identity_v1.py"
)
HOOK_TEST_PATH = (
    ROOT / "tests/migrations/test_development_auth_custom_access_token_hook_v1.py"
)
SEAL_TEST_PATH = (
    ROOT / "tests/migrations/test_development_auth_migration_identity_seal_v1.py"
)
FIXTURE_PATH = ROOT / "contracts/fixtures/v1/authorization-plan.cases.json"

HISTORICAL_EVIDENCE_DIGEST = (
    "sha256:8536127c85d6c7fa12241306fce4e539ae6ccf2f2b14c77388fa83fcec3da5e6"
)
REJECTED_V3_PLAN_DIGEST = (
    "sha256:b4f1f8a89010c7a4db52b3be3f2da0a5fcfab0583a9ccad70badbcb081c94dba"
)
SUPERSEDED_HOOK_DIGESTS = {
    "sha256:d436ad730291092b1d7688e7bbe87566a47a2d0be452e2ddb2e2cdcba6285b9c",
    "sha256:45304f737d90729e16190808f26bf38f4acc19a506f3ea1fa8558d92b598ca4c",
}
EXPECTED_STEPS = [
    "development.auth.step.01.local-hook-migration",
    "development.auth.step.02.bootstrap-migration-identity",
    "development.auth.step.03.apply-hook-migration",
    "development.auth.step.04.seal-migration-identity",
    "development.auth.step.05.verify-disabled-hook",
    "development.auth.step.06.create-synthetic-identity",
    "development.auth.step.07.bind-synthetic-tenant",
    "development.auth.step.08.bind-server-capability",
    "development.auth.step.09.enable-hook",
    "development.auth.step.10.issue-ephemeral-token",
    "development.auth.step.11.fetch-jwks",
    "development.auth.step.12.validate-token-locally",
    "development.auth.step.13.record-evidence-and-terminate",
]


def file_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


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
    historical_evidence = json.loads(HISTORICAL_STEP1_EVIDENCE_PATH.read_text())
    step1_evidence = json.loads(STEP1_EVIDENCE_PATH.read_text())
    provider_preflight = json.loads(PROVIDER_PREFLIGHT_PATH.read_text())
    fixtures = json.loads(FIXTURE_PATH.read_text())

    validate_plan(plan, schemas)
    validate_progress(plan, progress, schemas)

    failures: list[str] = []

    def require(condition: bool, message: str) -> None:
        if not condition:
            failures.append(message)

    require(PROVIDER_PREFLIGHT_PATH.exists(), "provider preflight evidence missing")
    require(provider_preflight.get("observation_only") is True and provider_preflight.get("project_reference") == "pwlhruwutoitnieactol", "provider preflight binding mismatch")
    step1, bootstrap, hook, seal, verify = plan["steps"][:5]
    baseline_requirement = step1["required_evidence"][0]
    provider_requirement = bootstrap["required_evidence"][1]
    require(provider_requirement.get("exact_digest") == canonical_digest(provider_preflight), "provider preflight digest mismatch")
    evidence_artifacts = step1_evidence.get("artifacts", {})
    evidence_source = step1_evidence.get("source", {})
    evidence_results = step1_evidence.get("results", {})

    require(
        canonical_digest(historical_evidence) == HISTORICAL_EVIDENCE_DIGEST,
        "historical v2 Step 1 evidence changed",
    )
    require(
        not REJECTED_V3_EVIDENCE_PATH.exists(),
        "rejected v3 local evidence remains present",
    )
    require(
        baseline_requirement["binding_state"] == "BOUND"
        and baseline_requirement["exact_digest"] == canonical_digest(step1_evidence),
        "DEVELOPMENT v5 Step 1 evidence binding mismatch",
    )

    expected_artifacts = {
        "migration_identity": (
            IDENTITY_MIGRATION_PATH,
            "supabase/migrations/20260908132000_development_auth_migration_identity_v1.sql",
        ),
        "hook_migration": (
            HOOK_MIGRATION_PATH,
            "supabase/migrations/20260908133000_development_auth_custom_access_token_hook_v1.sql",
        ),
        "migration_identity_seal": (
            SEAL_MIGRATION_PATH,
            "supabase/migrations/20260908134000_development_auth_migration_identity_seal_v1.sql",
        ),
        "migration_identity_validation": (
            IDENTITY_TEST_PATH,
            "tests/migrations/test_development_auth_migration_identity_v1.py",
        ),
        "hook_validation": (
            HOOK_TEST_PATH,
            "tests/migrations/test_development_auth_custom_access_token_hook_v1.py",
        ),
        "migration_identity_seal_validation": (
            SEAL_TEST_PATH,
            "tests/migrations/test_development_auth_migration_identity_seal_v1.py",
        ),
    }
    for key, (path, reference) in expected_artifacts.items():
        artifact = evidence_artifacts.get(key, {})
        require(
            artifact.get("path") == reference
            and artifact.get("content_digest") == file_digest(path),
            f"DEVELOPMENT v5 evidence artifact mismatch: {key}",
        )

    require(
        step1_evidence.get("evidence_type") == "migration.artifacts.local-validated-v5"
        and step1_evidence.get("environment") == "DEVELOPMENT"
        and step1_evidence.get("responsibility") == "AUTH"
        and step1_evidence.get("project_reference") == "pwlhruwutoitnieactol"
        and evidence_source.get("base_plan_version") == 2
        and evidence_source.get("base_plan_digest")
        == "sha256:d21ee19419521652dac328eb441f8200289e8880a2928fe8a299207d40249461"
        and evidence_source.get("historical_step1_evidence_digest")
        == HISTORICAL_EVIDENCE_DIGEST
        and evidence_source.get("rejected_draft_plan_version") == 4
        and evidence_source.get("rejected_draft_plan_digest")
        == "sha256:fd7b0760ff2939da616a2fdf8a476ac3772de39ccd5858e4d5b6e589a1384a3f"
        and evidence_source.get("lineage_classification")
        == "LOCAL_REJECTED_DRAFT_SUPERSEDED"
        and set(
            evidence_artifacts.get("hook_migration", {}).get(
                "superseded_content_digests", []
            )
        )
        == SUPERSEDED_HOOK_DIGESTS
        and evidence_results.get("ordered_lineage_verified") is True
        and evidence_results.get("v5_correction_security_findings_corrected") is True
        and evidence_source.get("provider_preflight_evidence_path") == "contracts/plans/v1/development-auth-provider-preflight.evidence.json"
        and evidence_source.get("v5_local_correction_provider_contact") is False
        and evidence_results.get("provider_contact_attempted") is False
        and evidence_results.get("remote_mutation_attempted") is False
        and evidence_results.get("role_created_remotely") is False
        and evidence_results.get("hook_created_remotely") is False
        and evidence_results.get("hook_enabled") is False,
        "DEVELOPMENT v5 local evidence content mismatch",
    )

    require(plan["ordered_step_ids"] == EXPECTED_STEPS, "v5 step sequence mismatch")
    require(plan["plan_version"] == 5, "plan version must be 5")
    require(plan["plan_digest"] == plan_digest(plan), "canonical plan digest mismatch")
    require(
        (
            plan["environment"],
            plan["target"]["provider_reference"],
            plan["target"]["project_reference"],
            plan["target"]["responsibility"],
        )
        == ("DEVELOPMENT", "supabase", "pwlhruwutoitnieactol", "AUTH"),
        "DEVELOPMENT namespace binding mismatch",
    )
    require(
        plan["target"]["issuer_reference"]
        == "https://pwlhruwutoitnieactol.supabase.co/auth/v1"
        and plan["target"]["audience_reference"]
        == "audience.avuhz.command-service.development",
        "DEVELOPMENT issuer or audience mismatch",
    )
    require(
        plan["definition_status"] == "DRAFT_BLOCKED"
        and plan["authorization_window"]
        == {"binding_state": "UNRESOLVED_BLOCKER", "starts_at": None, "expires_at": None},
        "unapproved v5 plan must remain blocked without a window",
    )

    require(
        step1["resource"]["resource_reference"]
        == "supabase/migrations/20260908133000_development_auth_custom_access_token_hook_v1.sql"
        and step1["resource"]["exact_digest"] == file_digest(HOOK_MIGRATION_PATH)
        and step1["unresolved_bindings"] == [],
        "v5 Step 1 artifact binding is incomplete",
    )

    require(
        bootstrap["resource"]["resource_reference"]
        == "postgres.role.avuhz_migration_service_dev"
        and bootstrap["resource"]["exact_digest"] == file_digest(IDENTITY_MIGRATION_PATH)
        and bootstrap["operation"] == "provider.migration.bootstrap-identity-exact"
        and bootstrap["execution_class"] == "PROVIDER_MUTATION"
        and bootstrap["credential_policy"]["allowed_classes"]
        == ["OWNER_INTERACTIVE_SESSION"]
        and bootstrap["dependency_step_ids"]
        == ["development.auth.step.01.local-hook-migration"]
        and "migration.identity.binding" in bootstrap["unresolved_bindings"]
        and "authorization.window" in bootstrap["unresolved_bindings"]
        and "no direct database ACL" in bootstrap["expected_postcondition"]
        and "ambient PUBLIC database privileges are unchanged"
        in bootstrap["expected_postcondition"],
        "migration identity bootstrap boundary mismatch",
    )

    identity_sql = IDENTITY_MIGRATION_PATH.read_text().lower()
    require(
        "session_user <> 'postgres' or current_user <> 'postgres'" in identity_sql
        and "create role avuhz_migration_service_dev" in identity_sql
        and "nologin" in identity_sql
        and "noinherit" in identity_sql
        and "nobypassrls" in identity_sql
        and "grant avuhz_migration_service_dev to postgres" in identity_sql
        and "with admin false, inherit false, set true" in identity_sql
        and "grant usage on schema public to avuhz_migration_service_dev" in identity_sql
        and "grant create on schema public to avuhz_migration_service_dev" in identity_sql
        and "with grant option" not in identity_sql
        and "grant usage on schema public to supabase_auth_admin" in identity_sql
        and "grant connect on database" not in identity_sql
        and "grant temporary on database" not in identity_sql,
        "bootstrap SQL does not enforce the corrected privilege envelope",
    )

    require(
        hook["operation"] == "provider.migration.apply-exact"
        and hook["execution_class"] == "PROVIDER_MUTATION"
        and hook["credential_policy"]["allowed_classes"] == ["MIGRATION_IDENTITY"]
        and hook["dependency_step_ids"]
        == ["development.auth.step.02.bootstrap-migration-identity"]
        and "migration.identity.binding" in hook["unresolved_bindings"]
        and "authorization.window" in hook["unresolved_bindings"]
        and "session_user=postgres" in hook["expected_postcondition"]
        and "current_user=avuhz_migration_service_dev"
        in hook["expected_postcondition"],
        "hook effective-role boundary mismatch",
    )
    hook_evidence_sources = {
        (item["evidence_type"], item["source_step_id"])
        for item in hook["required_evidence"]
    }
    require(
        hook_evidence_sources
        == {
            (
                "migration.identity.bootstrap.verified",
                "development.auth.step.02.bootstrap-migration-identity",
            ),
            (
                "hook.migration.artifact.validated",
                "development.auth.step.01.local-hook-migration",
            ),
        },
        "hook evidence dependencies mismatch",
    )

    hook_sql = HOOK_MIGRATION_PATH.read_text().lower()
    require(
        "session_user <> 'postgres' or current_user <> 'postgres'" in hook_sql
        and "set local role avuhz_migration_service_dev" in hook_sql
        and "current_user <> 'avuhz_migration_service_dev'" in hook_sql
        and hook_sql.index("current_user <> 'avuhz_migration_service_dev'")
        < hook_sql.index("create function")
        and "grant usage on schema public" not in hook_sql
        and "with grant option" not in hook_sql
        and "create temporary" not in hook_sql
        and "create temp " not in hook_sql,
        "hook SQL does not enforce the corrected effective-role boundary",
    )

    require(
        seal["operation"] == "provider.migration.seal-identity-exact"
        and seal["execution_class"] == "PROVIDER_MUTATION"
        and seal["credential_policy"]["allowed_classes"] == ["OWNER_INTERACTIVE_SESSION"]
        and seal["resource"]["exact_digest"] == file_digest(SEAL_MIGRATION_PATH)
        and seal["dependency_step_ids"]
        == ["development.auth.step.03.apply-hook-migration"]
        and seal["required_evidence"]
        == [
            {
                "evidence_type": "hook.migration.application.verified",
                "source_step_id": "development.auth.step.03.apply-hook-migration",
                "binding_state": "DERIVED_FROM_SOURCE_STEP",
                "exact_digest": None,
            }
        ],
        "migration identity seal boundary mismatch",
    )

    seal_sql = SEAL_MIGRATION_PATH.read_text().lower()
    require(
        "session_user <> 'postgres' or current_user <> 'postgres'" in seal_sql
        and "revoke create on schema public" in seal_sql
        and "revoke usage on schema public" in seal_sql
        and "revoke avuhz_migration_service_dev from postgres" in seal_sql
        and "alter role " not in seal_sql
        and "drop role " not in seal_sql
        and "grant " not in seal_sql
        and "create temporary" not in seal_sql
        and "create temp " not in seal_sql,
        "seal SQL mutation surface mismatch",
    )

    require(
        verify["operation"] == "provider.resource.verify-disabled-and-acl"
        and verify["execution_class"] == "PROVIDER_READ"
        and verify["credential_policy"]["allowed_classes"]
        == ["OWNER_INTERACTIVE_SESSION"]
        and verify["dependency_step_ids"]
        == ["development.auth.step.04.seal-migration-identity"]
        and verify["required_evidence"][0]["source_step_id"]
        == "development.auth.step.04.seal-migration-identity"
        and "provider.mutation" in verify["prohibited_actions"]
        and "resource.repair" in verify["prohibited_actions"],
        "post-seal verification boundary mismatch",
    )

    positions = {step_id: index for index, step_id in enumerate(EXPECTED_STEPS)}
    require(
        all(
            positions[dependency] < positions[step["step_id"]]
            for step in plan["steps"]
            for dependency in step["dependency_step_ids"]
        ),
        "plan dependency does not point backward",
    )
    plan_text = PLAN_PATH.read_text()
    require(
        not any(digest in plan_text for digest in SUPERSEDED_HOOK_DIGESTS),
        "superseded hook digest remains bound by plan v5",
    )

    require(
        progress["plan_version"] == 5
        and progress["plan_digest"] == plan["plan_digest"]
        and progress["progress_digest"] == progress_digest(progress)
        and [state["step_id"] for state in progress["step_states"]] == EXPECTED_STEPS,
        "v5 progress plan binding mismatch",
    )
    require(
        all(
            state["authorization_state"] == "PENDING"
            and state["execution_state"] == "NOT_STARTED"
            and state["verification_state"] == "NOT_STARTED"
            and state["authorization_consumed"] is False
            and state["evidence"] == []
            and state["observed_postcondition"] is None
            and state["safe_error_code"] is None
            for state in progress["step_states"]
        )
        and progress["overall_state"] == "NOT_STARTED",
        "draft v5 progress must remain entirely unexecuted",
    )
    require(
        not list((ROOT / "contracts/plans/v1").glob("*approval*.json")),
        "owner approval record must not be fabricated",
    )
    require(fixtures.get("fictional_only") is True, "contract fixtures must be fictional")
    require(
        all(not step["credential_policy"]["values_stored"] for step in plan["steps"]),
        "credential values may not be stored",
    )
    require(
        all(len(step["dependency_step_ids"]) <= 1 for step in plan["steps"]),
        "draft must advance one immediate resource boundary at a time",
    )

    required_prohibitions = {
        "batch.mutation",
        "scope.expansion",
        "step.skip",
        "step.reorder",
        "failed-mutation.retry",
        "automatic.self-repair",
        "data.operation",
        "render.operation",
        "staging.target",
        "production.target",
        "jwt.authority",
        "secret.persist",
    }
    require(
        required_prohibitions <= set(plan["prohibited_actions"]),
        "global security prohibitions incomplete",
    )

    if failures:
        for failure in failures:
            print(f"bounded authorization-plan validation: FAIL: {failure}", file=sys.stderr)
        return 1

    print(
        "bounded authorization-plan validation: PASS "
        "(3 schemas, 13 ordered DEVELOPMENT steps, fresh v5 local evidence bound, "
        "NOLOGIN migration identity bootstrap/effective-role/seal blocked, "
        "separate approval, zero authorization)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
