#!/usr/bin/env python3
"""Validate the provider-neutral plan model and exact blocked DEVELOPMENT v7 draft."""
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
V5_STEP1_EVIDENCE_PATH = (
    ROOT / "contracts/plans/v1/development-auth-step1-v5-local.evidence.json"
)
V6_STEP1_EVIDENCE_PATH = (
    ROOT / "contracts/plans/v1/development-auth-step1-v6-local.evidence.json"
)
V7_STEP1_EVIDENCE_PATH = (
    ROOT / "contracts/plans/v1/development-auth-step1-v7-local.evidence.json"
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
V5_STEP1_EVIDENCE_DIGEST = (
    "sha256:8d73fcd2b1ae9475a213716b8cd314803c5215b6b17eaa99dcb37d0e06d8a07e"
)
V6_STEP1_EVIDENCE_DIGEST = (
    "sha256:d39fa647a374e8e60c62227077683acd1b84a1aad7736cfc1ac98a589447102c"
)
V7_STEP1_EVIDENCE_DIGEST = (
    "sha256:75568298af56a7f02ab826118902d3e8b1f62e290e57bea93da770b7f82a6211"
)
PLAN_DIGEST = "sha256:c7dd1770ae91aa0aea570c739cfeb358890e69a3a3ff81260ab70e0c5ad94938"
PROGRESS_DIGEST = (
    "sha256:0dc83c7b72fccb4fde50baa3e37e30f4e8e14770406e0510ba67328fb2b36d52"
)
IDENTITY_DIGEST = (
    "sha256:b2af6edacb283afc5a5ad7d1c1ebdc5fdbd572bddd1cb115459caa6344acda45"
)
HOOK_DIGEST = "sha256:234a27973d4f9468dfb59ff5002f2ae1b7523dac9bd80b26fd01fbc64c8bc783"
SEAL_DIGEST = "sha256:aafec1973fa60e3a2b7076f36c989a373fb1115a1e9e3760781a0ef41ca9b1ad"
IDENTITY_TEST_DIGEST = (
    "sha256:f9225015305e064c4712faa9e6de89af690d45dfbc2f17187dd6d43b92545281"
)
HOOK_TEST_DIGEST = (
    "sha256:49b083a81dc53705aaf64e0f79ffb528ec25e1d96cea15d69c5ec098d29696a0"
)
SEAL_TEST_DIGEST = (
    "sha256:36c1a0fb8b3f6396cd7e027a0ff224b53c259943d0af7856bf2ca053d5fd236b"
)
PROVIDER_PREFLIGHT_DIGEST = (
    "sha256:f3d315085b9de80d856f8fa16b22646679e6be4367e3c2ddf48ee954d2580732"
)
SUPERSEDED_BOOTSTRAP_DIGEST = (
    "sha256:640fb4d2dbff9962f21b83b862cc455fe5e8be2ff5dd4b34bdf99cf3b0721356"
)
SUPERSEDED_SEAL_DIGEST = (
    "sha256:0b8450e0b5984988a191fc81cd992ba0ef20bb805dc7d71123019244af8830b5"
)
HISTORICAL_V5_SUPERSEDED_HOOK_DIGESTS = {
    "sha256:d436ad730291092b1d7688e7bbe87566a47a2d0be452e2ddb2e2cdcba6285b9c",
    "sha256:45304f737d90729e16190808f26bf38f4acc19a506f3ea1fa8558d92b598ca4c",
}
SUPERSEDED_HOOK_DIGESTS = {
    "sha256:66d487c0858e41358c0e169199ed448ddbf264be6f8c22481d183c9559ba9035",
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
    v5_step1_evidence = json.loads(V5_STEP1_EVIDENCE_PATH.read_text())
    step1_evidence = json.loads(V6_STEP1_EVIDENCE_PATH.read_text())
    v7_step1_evidence = json.loads(V7_STEP1_EVIDENCE_PATH.read_text())
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
    require(
        provider_requirement.get("exact_digest") == canonical_digest(provider_preflight)
        and canonical_digest(provider_preflight) == PROVIDER_PREFLIGHT_DIGEST,
        "provider preflight digest mismatch",
    )
    evidence_artifacts = step1_evidence.get("artifacts", {})
    evidence_lineage = step1_evidence.get("lineage", {})
    failed_ci = step1_evidence.get("failed_ci_certification", {})
    correction_state = step1_evidence.get("correction_state", {})
    v7_evidence_artifacts = v7_step1_evidence.get("artifacts", {})
    v7_evidence_lineage = v7_step1_evidence.get("lineage", {})
    rejected_v6_review = v7_step1_evidence.get("rejected_v6_local_review", {})
    corrections = v7_step1_evidence.get("corrections", {})
    certification_state = v7_step1_evidence.get("certification_state", {})
    provider_state = v7_step1_evidence.get("provider_and_authorization_state", {})
    v5_evidence_artifacts = v5_step1_evidence.get("artifacts", {})
    v5_evidence_source = v5_step1_evidence.get("source", {})
    v5_evidence_results = v5_step1_evidence.get("results", {})

    require(
        canonical_digest(historical_evidence) == HISTORICAL_EVIDENCE_DIGEST,
        "historical v2 Step 1 evidence changed",
    )
    require(
        not REJECTED_V3_EVIDENCE_PATH.exists(),
        "rejected v3 local evidence remains present",
    )
    require(
        canonical_digest(v5_step1_evidence) == V5_STEP1_EVIDENCE_DIGEST,
        "historical v5 Step 1 evidence changed",
    )
    require(
        len(step1["required_evidence"]) == 1
        and baseline_requirement["binding_state"] == "BOUND"
        and baseline_requirement["source_step_id"] is None
        and baseline_requirement["evidence_type"]
        == "migration.artifacts.local-forward-correction-v7"
        and baseline_requirement["exact_digest"] == canonical_digest(v7_step1_evidence)
        and canonical_digest(v7_step1_evidence) == V7_STEP1_EVIDENCE_DIGEST,
        "DEVELOPMENT v7 Step 1 evidence binding mismatch",
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
        artifact = v7_evidence_artifacts.get(key, {})
        require(
            artifact.get("path") == reference
            and artifact.get("content_digest") == file_digest(path),
            f"DEVELOPMENT v7 evidence artifact mismatch: {key}",
        )

    require(
        file_digest(IDENTITY_MIGRATION_PATH) == IDENTITY_DIGEST
        and file_digest(HOOK_MIGRATION_PATH) == HOOK_DIGEST
        and file_digest(SEAL_MIGRATION_PATH) == SEAL_DIGEST
        and file_digest(IDENTITY_TEST_PATH) == IDENTITY_TEST_DIGEST
        and file_digest(HOOK_TEST_PATH) == HOOK_TEST_DIGEST
        and file_digest(SEAL_TEST_PATH) == SEAL_TEST_DIGEST,
        "DEVELOPMENT v7 migration or test artifact digest mismatch",
    )

    require(
        v5_step1_evidence.get("evidence_type")
        == "migration.artifacts.local-validated-v5"
        and v5_step1_evidence.get("environment") == "DEVELOPMENT"
        and v5_step1_evidence.get("responsibility") == "AUTH"
        and v5_step1_evidence.get("project_reference") == "pwlhruwutoitnieactol"
        and v5_evidence_source.get("base_plan_version") == 2
        and v5_evidence_source.get("base_plan_digest")
        == "sha256:d21ee19419521652dac328eb441f8200289e8880a2928fe8a299207d40249461"
        and v5_evidence_source.get("historical_step1_evidence_digest")
        == HISTORICAL_EVIDENCE_DIGEST
        and v5_evidence_source.get("rejected_draft_plan_version") == 4
        and v5_evidence_source.get("rejected_draft_plan_digest")
        == "sha256:fd7b0760ff2939da616a2fdf8a476ac3772de39ccd5858e4d5b6e589a1384a3f"
        and v5_evidence_source.get("lineage_classification")
        == "LOCAL_REJECTED_DRAFT_SUPERSEDED"
        and set(
            v5_evidence_artifacts.get("hook_migration", {}).get(
                "superseded_content_digests", []
            )
        )
        == HISTORICAL_V5_SUPERSEDED_HOOK_DIGESTS
        and v5_evidence_results.get("ordered_lineage_verified") is True
        and v5_evidence_results.get("v5_correction_security_findings_corrected")
        is True
        and v5_evidence_source.get("provider_preflight_evidence_path")
        == "contracts/plans/v1/development-auth-provider-preflight.evidence.json"
        and v5_evidence_source.get("v5_local_correction_provider_contact") is False
        and v5_evidence_results.get("provider_contact_attempted") is False
        and v5_evidence_results.get("remote_mutation_attempted") is False
        and v5_evidence_results.get("role_created_remotely") is False
        and v5_evidence_results.get("hook_created_remotely") is False
        and v5_evidence_results.get("hook_enabled") is False,
        "historical DEVELOPMENT v5 local evidence content mismatch",
    )

    require(
        step1_evidence.get("evidence_type")
        == "migration.artifacts.local-forward-correction-v6"
        and step1_evidence.get("environment") == "DEVELOPMENT"
        and step1_evidence.get("responsibility") == "AUTH"
        and step1_evidence.get("project_reference") == "pwlhruwutoitnieactol"
        and step1_evidence.get("authority")
        == {
            "classification": "LOCAL_EVIDENCE_ONLY",
            "grants_provider_authority": False,
            "grants_mutation_authority": False,
            "grants_plan_approval": False,
        }
        and evidence_lineage.get("source_plan_version") == 5
        and evidence_lineage.get("source_plan_digest")
        == "sha256:e0f073c6e51923b97859aaf6072b6692e726c2f03adfcb4102d04b2fa4b6761f"
        and evidence_lineage.get("source_candidate_commit")
        == "bf4eae2b6157e43f8f79bfabde0de2776e79f804"
        and evidence_lineage.get("source_v5_local_evidence_path")
        == "contracts/plans/v1/development-auth-step1-v5-local.evidence.json"
        and evidence_lineage.get("source_v5_local_evidence_digest")
        == canonical_digest(v5_step1_evidence)
        and evidence_lineage.get("source_failed_ci_run_id") == 34377965523
        and evidence_lineage.get("source_ci_conclusion") == "FAILED"
        and evidence_lineage.get("target_plan_version") == 6
        and evidence_lineage.get("target_plan_binding_state")
        == "PENDING_LOCAL_PLAN_REVISION"
        and set(
            evidence_artifacts.get("hook_migration", {}).get(
                "superseded_content_digests", []
            )
        )
        == SUPERSEDED_HOOK_DIGESTS
        and failed_ci.get("postgresql_version") == "17.11"
        and failed_ci.get("postgresql_image_reference")
        == "postgres@sha256:67f41722b7a8cbdb868a44a4995c846eddfdc2973bccb291ce937dce88ad5675"
        and failed_ci.get("postgresql_started_successfully") is True
        and failed_ci.get("pinned_postgresql_registry_digest_resolved") is True
        and failed_ci.get("verified_gates")
        == [
            "bounded plan validation passed",
            "migration identity bootstrap PostgreSQL suite passed",
            "non-superuser SET ROLE regression passed",
        ]
        and failed_ci.get("failure_stage") == "hook effective-role certification"
        and failed_ci.get("failure_summary")
        == "Database ACL inspection passed a zero-dimensional ACL array to aclexplode when datacl was NULL."
        and failed_ci.get("not_reached")
        == [
            "seal suite after corrected hook",
            "baseline after complete corrected suites",
            "diff hygiene after complete corrected suites",
            "final checkout integrity",
        ]
        and failed_ci.get("raw_ci_log_payload_retained") is False
        and failed_ci.get("provider_contact_attempted") is False
        and failed_ci.get("supabase_mutation_attempted") is False
        and correction_state.get("corrected_hook_pg17_certification")
        == "NOT_YET_RUN"
        and correction_state.get("corrected_hook_effective_role_negative_result")
        == "NOT_YET_VERIFIED"
        and correction_state.get("seal_suite_after_corrected_hook")
        == "NOT_YET_RUN"
        and correction_state.get("complete_baseline_after_corrected_suites")
        == "NOT_YET_RUN"
        and correction_state.get("final_diff_and_integrity_gates")
        == "NOT_YET_RUN"
        and correction_state.get("provider_contact") is False
        and correction_state.get("supabase_mutation") is False
        and correction_state.get("hook_created_remotely") is False
        and correction_state.get("hook_enabled") is False,
        "DEVELOPMENT v6 forward-correction evidence content mismatch",
    )

    require(
        canonical_digest(step1_evidence) == V6_STEP1_EVIDENCE_DIGEST
        and evidence_artifacts.get("migration_identity", {}).get("content_digest")
        == SUPERSEDED_BOOTSTRAP_DIGEST
        and evidence_artifacts.get("hook_migration", {}).get("content_digest")
        == HOOK_DIGEST
        and evidence_artifacts.get("migration_identity_seal", {}).get("content_digest")
        == SUPERSEDED_SEAL_DIGEST
        and evidence_artifacts.get("migration_identity_validation", {}).get("content_digest")
        == file_digest(IDENTITY_TEST_PATH)
        and evidence_artifacts.get("hook_validation", {}).get("content_digest")
        == file_digest(HOOK_TEST_PATH)
        and evidence_artifacts.get("migration_identity_seal_validation", {}).get("content_digest")
        == file_digest(SEAL_TEST_PATH),
        "rejected DEVELOPMENT v6 evidence changed",
    )

    historical_v5 = v7_evidence_lineage.get("historical_v5", {})
    rejected_v6 = v7_evidence_lineage.get("rejected_v6", {})
    historical_v5_pg17 = v7_step1_evidence.get("historical_v5_pg17_observation", {})
    local_validation = v7_step1_evidence.get("local_validation", {})
    require(
        v7_step1_evidence.get("evidence_type")
        == "migration.artifacts.local-forward-correction-v7"
        and v7_step1_evidence.get("environment") == "DEVELOPMENT"
        and v7_step1_evidence.get("responsibility") == "AUTH"
        and v7_step1_evidence.get("project_reference") == "pwlhruwutoitnieactol"
        and v7_step1_evidence.get("authority")
        == {
            "classification": "LOCAL_EVIDENCE_ONLY",
            "grants_provider_authority": False,
            "grants_mutation_authority": False,
            "grants_plan_approval": False,
        },
        "DEVELOPMENT v7 evidence identity or authority mismatch",
    )
    require(
        historical_v5
        == {
            "plan_version": 5,
            "plan_digest": "sha256:e0f073c6e51923b97859aaf6072b6692e726c2f03adfcb4102d04b2fa4b6761f",
            "candidate_commit": "bf4eae2b6157e43f8f79bfabde0de2776e79f804",
            "failed_ci_run_id": 34377965523,
            "ci_conclusion": "FAILURE",
            "local_evidence_path": "contracts/plans/v1/development-auth-step1-v5-local.evidence.json",
            "local_evidence_digest": V5_STEP1_EVIDENCE_DIGEST,
            "certification_status": "FAILED",
        }
        and historical_v5.get("local_evidence_digest")
        == canonical_digest(v5_step1_evidence),
        "v7 historical failed-v5 lineage mismatch",
    )
    require(
        rejected_v6
        == {
            "plan_version": 6,
            "plan_digest": "sha256:38ff584ad6aee636cef2c1f75ce44f528900e159754f106f7378e3de7c9b7243",
            "local_evidence_path": "contracts/plans/v1/development-auth-step1-v6-local.evidence.json",
            "local_evidence_digest": V6_STEP1_EVIDENCE_DIGEST,
            "classification": "LOCAL_REJECTED_DRAFT_SUPERSEDED",
            "committed": False,
            "ci_executed": False,
            "provider_execution_occurred": False,
        }
        and rejected_v6.get("local_evidence_digest")
        == canonical_digest(step1_evidence)
        and v7_evidence_lineage.get("provider_preflight_evidence_path")
        == "contracts/plans/v1/development-auth-provider-preflight.evidence.json"
        and v7_evidence_lineage.get("provider_preflight_evidence_digest")
        == canonical_digest(provider_preflight)
        and v7_evidence_lineage.get("provider_preflight_classification")
        == "HISTORICAL_READ_ONLY_OBSERVATION_ONLY"
        and v7_evidence_lineage.get("target_plan_version") == 7
        and v7_evidence_lineage.get("target_plan_binding_state")
        == "PENDING_LOCAL_PLAN_REVISION",
        "v7 rejected-v6 or provider-preflight lineage mismatch",
    )
    require(
        rejected_v6_review.get("rejection_stage")
        == "FINAL_LOCAL_REVIEW_BEFORE_COMMIT"
        and "NULL database ACL inspection defect" in rejected_v6_review.get("rejection_reason", "")
        and rejected_v6_review.get("defect_expression").startswith(
            "coalesce(pg_database.datacl"
        )
        and set(rejected_v6_review.get("affected_checks", []))
        == {
            "bootstrap direct database ACL postcondition",
            "seal direct database ACL preflight",
            "seal direct database ACL postcondition",
        }
        and rejected_v6_review.get("ci_executed") is False
        and rejected_v6_review.get("committed") is False
        and rejected_v6_review.get("provider_execution_occurred") is False,
        "v7 rejected-v6 NULL database ACL defect lineage mismatch",
    )
    require(
        v7_evidence_artifacts.get("migration_identity", {}).get(
            "superseded_content_digests", []
        )
        == [SUPERSEDED_BOOTSTRAP_DIGEST]
        and set(
            v7_evidence_artifacts.get("hook_migration", {}).get(
                "superseded_content_digests", []
            )
        )
        == SUPERSEDED_HOOK_DIGESTS
        and v7_evidence_artifacts.get("migration_identity_seal", {}).get(
            "superseded_content_digests", []
        )
        == [SUPERSEDED_SEAL_DIGEST],
        "v7 superseded artifact lineage mismatch",
    )
    require(
        corrections.get("bootstrap")
        == {
            "database_acl_occurrences_corrected": 1,
            "null_datacl_passed_directly_to_aclexplode": True,
            "direct_database_acl_check_preserved": True,
        }
        and corrections.get("hook")
        == {
            "database_acl_occurrences_corrected": 1,
            "null_datacl_passed_directly_to_aclexplode": True,
            "direct_database_acl_check_preserved": True,
        }
        and corrections.get("seal")
        == {
            "database_acl_occurrences_corrected": 2,
            "null_datacl_passed_directly_to_aclexplode": True,
            "preflight_direct_database_acl_check_preserved": True,
            "postcondition_direct_database_acl_check_preserved": True,
        }
        and corrections.get("security_invariants")
        == {
            "security_check_removed": False,
            "privilege_widened": False,
            "migration_role_attributes_changed": False,
            "set_role_semantics_changed": False,
            "seal_mutation_surface_changed": False,
            "hook_claims_behavior_changed": False,
            "hook_acl_changed": False,
            "provider_target_changed": False,
            "auth_data_boundary_changed": False,
        },
        "v7 bounded NULL database ACL correction evidence mismatch",
    )
    require(
        certification_state.get("current_bootstrap_pg17_certified") is False
        and certification_state.get("current_hook_pg17_certified") is False
        and certification_state.get("current_seal_pg17_certified") is False
        and certification_state.get("full_current_artifact_set_pg17_certified") is False
        and certification_state.get("historical_v5_pg17_observation_is_digest_bound_only")
        is True
        and historical_v5_pg17.get("bootstrap_artifact_digest")
        == SUPERSEDED_BOOTSTRAP_DIGEST
        and historical_v5_pg17.get("bounded_plan_validation_passed") is True
        and historical_v5_pg17.get("bootstrap_postgresql_suite_passed") is True
        and historical_v5_pg17.get("non_superuser_set_role_regression_passed") is True
        and historical_v5_pg17.get("hook_certification_failed") is True
        and historical_v5_pg17.get("current_artifact_certification_claim") is False,
        "v7 current PG17 certification truth mismatch",
    )
    require(
        provider_state.get("provider_contact_attempted") is False
        and provider_state.get("remote_mutation_attempted") is False
        and provider_state.get("supabase_mutation_attempted") is False
        and provider_state.get("role_created_remotely") is False
        and provider_state.get("hook_created_remotely") is False
        and provider_state.get("hook_enabled") is False
        and provider_state.get("synthetic_identity_created") is False
        and provider_state.get("token_issued") is False
        and provider_state.get("authorization_consumed") is False
        and local_validation.get("postgresql_tests_executed") is False,
        "v7 provider, authorization, or local-certification truth mismatch",
    )

    require(plan["ordered_step_ids"] == EXPECTED_STEPS, "v7 step sequence mismatch")
    require(
        plan["plan_id"] == "a7100000-0000-4000-8000-000000000101"
        and plan["plan_version"] == 7,
        "plan identity or version must match v7",
    )
    require(
        plan["plan_digest"] == PLAN_DIGEST
        and plan["plan_digest"] == plan_digest(plan),
        "canonical v7 plan digest mismatch",
    )
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
        "unapproved v7 plan must remain blocked without a window",
    )

    require(
        step1["resource"]["resource_reference"]
        == "supabase/migrations/20260908133000_development_auth_custom_access_token_hook_v1.sql"
        and step1["resource"]["exact_version"] == "version.20260908133000"
        and step1["resource"]["exact_digest"] == HOOK_DIGEST
        and step1["resource"]["exact_digest"] == file_digest(HOOK_MIGRATION_PATH)
        and step1["unresolved_bindings"] == [],
        "v7 Step 1 artifact binding is incomplete",
    )

    require(
        bootstrap["resource"]["resource_reference"]
        == "postgres.role.avuhz_migration_service_dev"
        and bootstrap["resource"]["binding_state"] == "BOUND"
        and bootstrap["resource"]["exact_version"] == "version.20260908132000"
        and bootstrap["resource"]["exact_digest"] == IDENTITY_DIGEST
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
        and hook["resource"]["resource_reference"]
        == "public.avuhz_development_custom_access_token_hook_v1(jsonb)"
        and hook["resource"]["binding_state"] == "UNRESOLVED_BLOCKER"
        and hook["resource"]["exact_version"] == "version.20260908133000"
        and hook["resource"]["exact_digest"] == HOOK_DIGEST
        and hook["resource"]["exact_digest"] == file_digest(HOOK_MIGRATION_PATH)
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
        and seal["resource"]["resource_reference"]
        == "postgres.role.avuhz_migration_service_dev.sealed"
        and seal["resource"]["binding_state"] == "BOUND"
        and seal["resource"]["exact_version"] == "version.20260908134000"
        and seal["resource"]["exact_digest"] == SEAL_DIGEST
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
        "coalesce(database_record.datacl" not in identity_sql
        and identity_sql.count("aclexplode(database_record.datacl)") == 1
        and identity_sql.count("database_acl.grantee = migration_role_oid") == 1
        and "coalesce(database_record.datacl" not in hook_sql
        and hook_sql.count("aclexplode(database_record.datacl)") == 1
        and hook_sql.count("database_acl.grantee = migration_role_oid") == 1
        and "coalesce(database_record.datacl" not in seal_sql
        and seal_sql.count("aclexplode(database_record.datacl)") == 2
        and seal_sql.count("database_acl.grantee = migration_role_oid") == 2,
        "pg_database NULL ACL handling or direct-ACL checks regressed",
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
    active_binding_digests = {
        step["resource"].get("exact_digest") for step in plan["steps"]
    } | {
        evidence.get("exact_digest")
        for step in plan["steps"]
        for evidence in step["required_evidence"]
        if evidence.get("exact_digest") is not None
    }
    require(
        plan["plan_digest"] != REJECTED_V3_PLAN_DIGEST
        and V5_STEP1_EVIDENCE_DIGEST not in active_binding_digests
        and V6_STEP1_EVIDENCE_DIGEST not in active_binding_digests
        and SUPERSEDED_BOOTSTRAP_DIGEST not in active_binding_digests
        and SUPERSEDED_SEAL_DIGEST not in active_binding_digests
        and SUPERSEDED_HOOK_DIGESTS.isdisjoint(active_binding_digests),
        "historical or superseded digest remains actively bound by plan v7",
    )

    require(
        progress["progress_id"] == "a7100000-0000-4000-8000-000000000102"
        and progress["plan_id"] == plan["plan_id"]
        and progress["plan_version"] == 7
        and progress["record_version"] == 1
        and progress["plan_digest"] == PLAN_DIGEST
        and progress["plan_digest"] == plan["plan_digest"]
        and progress["progress_digest"] == PROGRESS_DIGEST
        and progress["progress_digest"] == progress_digest(progress)
        and [state["step_id"] for state in progress["step_states"]] == EXPECTED_STEPS,
        "v7 progress plan binding mismatch",
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
        "draft v7 progress must remain entirely unexecuted",
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
        "(3 schemas, 13 ordered DEVELOPMENT steps, v7 forward-correction evidence bound, "
        "NOLOGIN migration identity bootstrap/effective-role/seal blocked, "
        "separate approval, zero authorization)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
