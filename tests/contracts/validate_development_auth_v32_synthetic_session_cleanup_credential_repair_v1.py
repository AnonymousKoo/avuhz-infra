#!/usr/bin/env python3
"""Validate all four canonical DEVELOPMENT AUTH credential-repair outcomes."""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.authorization_plan import (  # noqa: E402
    approval_digest,
    authorize_step,
    initial_progress,
    plan_digest,
    progress_digest,
    record_step_outcome,
    validate_approval,
    validate_plan,
    validate_progress,
)
from avuhz_runtime.implementation_handoff import canonical_digest  # noqa: E402


SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
BASE = ROOT / "contracts/plans/v1"
BOUNDARY = "development-auth-v32-synthetic-session-cleanup-credential-repair-v1"
PLAN_PATH = BASE / f"{BOUNDARY}.plan.json"
PROGRESS_PATH = BASE / f"{BOUNDARY}.progress.json"
APPROVAL_PATH = BASE / f"{BOUNDARY}.approval.json"
PLAN_ID = "0224c4fb-845c-4627-b48f-252ec954283c"
PROGRESS_ID = "764ab6f1-e189-499a-9bb3-b1a7bcf6e52f"
PLAN_DIGEST = "sha256:57b26eefa9ca294a4dff95d617a50c3e46d0cdaab1cf1862c1d1239d042babcb"
PROGRESS_DIGEST = "sha256:027a7aaed6577ac0fccb97f225ebfdbecebb72224f3186ac82057459fd72e08e"
PLAN_RAW_DIGEST = "sha256:a9bfe2e9ba4969877b115ba30f69b43f9144541741da09f6e331a815d294f21a"
PROGRESS_RAW_DIGEST = "sha256:a2806d69ce3b598d45cf439931b94e58b8d6d1827f565bf7cc7964966ef78952"
APPROVAL_ID = "f0b629ae-22c4-4e6f-bcf9-ac563761cd65"
APPROVED_AT = "2026-09-23T19:48:02Z"
APPROVAL_DIGEST = "sha256:a15a0e53e35a8aea7a6cf7bb6fe766ecba67777c7b702148c3dbc92dba63eb33"
APPROVAL_RAW_DIGEST = "sha256:c904810ac2187895ff5f4d3464bc5e8b906a3cb031daa05cf97ade9dddd36a53"
STEP1_EVIDENCE_PATH = BASE / f"{BOUNDARY}-step1-success.evidence.json"
STEP2_EVIDENCE_PATH = BASE / f"{BOUNDARY}-step2-success.evidence.json"
STEP3_EVIDENCE_PATH = BASE / f"{BOUNDARY}-step3-success.evidence.json"
STEP4_EVIDENCE_PATH = BASE / f"{BOUNDARY}-step4-success.evidence.json"
EXECUTION_PROGRESS_PATH = BASE / f"{BOUNDARY}.execution-progress.json"
STEP1_ID = "development.auth.v32-synthetic-session-cleanup-credential-repair-v1.step.01.create-dedicated-cleanup-secret-key"
STEP1_EVIDENCE_DIGEST = "sha256:29fa0e715118b6cb70d6c08b28466b79407319bc5177947851b87b86c10dc47d"
STEP1_PROGRESS_DIGEST = "sha256:7588aa0e94eba118ab8fafcdf51472edc3cb0667a90c373ddb1f75bba1065ceb"
RECORDED_AT = "2026-09-24T16:35:39Z"
STEP2_RECORDED_AT = "2026-09-24T17:07:52Z"
STEP2_ID = "development.auth.v32-synthetic-session-cleanup-credential-repair-v1.step.02.bind-dedicated-key-to-github-development"
STEP2_EVIDENCE_DIGEST = "sha256:de7daf8b0c913f713225d292adae404bc877b298368c9fbedc5e451f6190e574"
STEP2_PROGRESS_DIGEST = "sha256:2efd6ac08c2a9a7ba1166bedff03c39375c87bd4408aceac082b753f016e9209"
STEP3_RECORDED_AT = "2026-09-24T17:50:55Z"
STEP3_ID = "development.auth.v32-synthetic-session-cleanup-credential-repair-v1.step.03.verify-github-binding-presence"
STEP3_EVIDENCE_DIGEST = "sha256:a431c44cac5069898b98784c82244f3b9335f124ee348666da0bb83894f3fce9"
STEP4_RECORDED_AT = "2026-09-24T18:52:56Z"
STEP4_ID = "development.auth.v32-synthetic-session-cleanup-credential-repair-v1.step.04.seal-retirement-obligation"
STEP4_EVIDENCE_DIGEST = "sha256:38ebcc897696f11284c540994c4a6144f08530ad8c4ec7e42c84a64f01559b8f"
STEP3_PROGRESS_DIGEST = "sha256:d8d34d20b29e101ddd015f71b1f449c9a4b878a9fccacc46324fa30766a1c1c1"
EXECUTION_PROGRESS_DIGEST = "sha256:6d4e4d5473a50790e1c6db4df50e4428fda37dc9988b4bf44ddb145955b6e2f9"
PRIOR_FAILURE_DIGEST = "sha256:3c41820fdcafa1adf2afe8653a1a3d1ba7561ab049cbc0ca84b370f78f9d4867"
PRIOR_STOPPED_PROGRESS_DIGEST = "sha256:a8344c793b45ea0d05024cd259ec11c58437f7db51c590d2cfccf5c8e8d11f2b"
PROJECT = "pwlhruwutoitnieactol"
DATA_PROJECT = "gnuqaefotwgkwurjpyik"
SECRET_REFERENCE = "AVUHZ_DEVELOPMENT_SUPABASE_AUTH_SESSION_CLEANUP_V2_EPHEMERAL"
OLD_SECRET_REFERENCE = "AVUHZ_DEVELOPMENT_SUPABASE_AUTH_SESSION_CLEANUP_V1_EPHEMERAL"
CREATED_AT = "2026-09-23T17:05:25Z"
WINDOW_START = "2026-09-24T15:00:00Z"
WINDOW_END = "2026-09-24T21:00:00Z"

# Public contract basis (documentation only; no project contact):
# https://supabase.com/docs/guides/api/api-keys
# Supabase secret API keys use the sb_secret_ prefix and are server-side
# credentials. This plan retains only the expected shape and a logical binding
# name; the value and any material-derived digest are prohibited everywhere.
CREATE_CONTRACT = {
    "project_reference": PROJECT,
    "responsibility": "AUTH",
    "resource": "dedicated-cleanup-v2-secret-api-key",
    "operation": "create-exactly-one",
    "creation_surface": "supabase.dashboard.project-api-keys",
    "credential_class": "SUPABASE_AUTH_ADMIN_EPHEMERAL",
    "execution_credential_class": "OWNER_INTERACTIVE_SESSION",
    "provider_key_kind": "secret",
    "provider_key_shape": "sb_secret_*",
    "dedicated_scope": "development-auth-synthetic-session-cleanup-v2-only",
    "maximum_keys_created": 1,
    "service_role_legacy_material_allowed": False,
    "retired_bootstrap_credential_reuse_allowed": False,
    "material_handling": {
        "agent_visible": False,
        "prompted": False,
        "logged": False,
        "persisted": False,
        "hashed": False,
        "provider_response_retained": False,
    },
    "success_classification": "DEDICATED_CLEANUP_CREDENTIAL_CREATED",
}
BIND_CONTRACT = {
    "repository": "AnonymousKoo/avuhz-infra",
    "environment": "development",
    "resource": "github-environment-secret-binding",
    "operation": "create-exactly-one-new-binding",
    "secret_reference": SECRET_REFERENCE,
    "source_credential_class": "SUPABASE_AUTH_ADMIN_EPHEMERAL",
    "transfer_surface": "OWNER_INTERACTIVE_DIRECT_TO_GITHUB_ENVIRONMENT_SECRET",
    "clipboard_allowed": False,
    "agent_visible": False,
    "prompts_allowed": False,
    "value_returned": False,
    "value_persisted_outside_secret_store": False,
    "other_secrets_changed": False,
    "success_classification": "CLEANUP_CREDENTIAL_BINDING_CREATED",
}
VERIFY_CONTRACT = {
    "repository": "AnonymousKoo/avuhz-infra",
    "environment": "development",
    "resource": "github-environment-secret-binding",
    "operation": "verify-presence-reference-only",
    "secret_reference": SECRET_REFERENCE,
    "value_read": False,
    "value_returned": False,
    "value_hashed": False,
    "other_secrets_changed": False,
    "success_classification": "CLEANUP_CREDENTIAL_BINDING_PRESENT",
}
RETIREMENT_CONTRACT = {
    "credential_reference": SECRET_REFERENCE,
    "dedicated_scope": "development-auth-synthetic-session-cleanup-v2-only",
    "operation": "seal-retirement-obligation-locally",
    "retirement_trigger": [
        "future-cleanup-continuation-completed",
        "future-cleanup-continuation-permanently-stopped",
    ],
    "retirement_requires_fresh_exact_authority": True,
    "ordered_retirement_resources": [
        "supabase-secret-api-key",
        "github-development-environment-secret-binding",
    ],
    "verification": ["provider-key-absent", "github-binding-absent"],
    "reuse_allowed": False,
    "success_classification": "CLEANUP_CREDENTIAL_RETIREMENT_REQUIRED",
}


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def raw_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def expected_step2_progress(
    plan: dict, approval: dict, step1_progress: dict, evidence: dict
) -> dict:
    step = plan["steps"][1]
    observation_digest = canonical_digest(evidence["authorization_observation"])
    preflight_declaration = next(
        declaration
        for declaration in step["binding_declarations"]
        if declaration["phase"] == "RESOLVED_BY_STEP_PREFLIGHT"
    )
    preflight_assertion = {
        "binding_id": preflight_declaration["binding_id"],
        "phase": preflight_declaration["phase"],
        "value_class": preflight_declaration["value_class"],
        "source_step_id": preflight_declaration["source_step_id"],
        "evidence_type": preflight_declaration["evidence_type"],
        "evidence_digest": observation_digest,
        "digest_policy": preflight_declaration["digest_policy"],
        "persistence_policy": preflight_declaration["persistence_policy"],
        "sanitized_value": None,
        "value_digest": observation_digest,
        "recorded_at": STEP2_RECORDED_AT,
    }
    request = {
        "plan_id": plan["plan_id"],
        "plan_version": plan["plan_version"],
        "plan_digest": plan["plan_digest"],
        "environment": plan["environment"],
        "provider_reference": plan["target"]["provider_reference"],
        "project_reference": plan["target"]["project_reference"],
        "responsibility": plan["target"]["responsibility"],
        "issuer_reference": plan["target"]["issuer_reference"],
        "audience_reference": plan["target"]["audience_reference"],
        "step_id": step["step_id"],
        "resource_reference": step["resource"]["resource_reference"],
        "resource_version": step["resource"]["exact_version"],
        "resource_digest": step["resource"]["exact_digest"],
        "operation": step["operation"],
        "execution_class": step["execution_class"],
        "credential_class": "OWNER_INTERACTIVE_SESSION",
        "required_evidence": [{
            "evidence_type": "auth.cleanup-admin-credential.created",
            "evidence_digest": STEP1_EVIDENCE_DIGEST,
        }],
        "prior_evidence_digests": [STEP1_EVIDENCE_DIGEST],
        "unexpected_remote_state": False,
        "extra_privileges": False,
        "unauthorized_migration_surface": False,
        "scope_expansion": False,
    }
    authorized = authorize_step(
        plan,
        approval,
        step1_progress,
        request,
        SCHEMA_ROOT,
        STEP2_RECORDED_AT,
        trusted_preflight_assertions=[preflight_assertion],
    )
    evidence_digest = raw_digest(STEP2_EVIDENCE_PATH)
    outcome_evidence = [{
        "evidence_type": evidence["evidence_type"],
        "evidence_reference": STEP2_EVIDENCE_PATH.name,
        "evidence_digest": evidence_digest,
        "recorded_at": STEP2_RECORDED_AT,
    }]
    produced_declaration = next(
        declaration
        for declaration in step["binding_declarations"]
        if declaration["phase"] == "PRODUCED_BY_CURRENT_STEP"
    )
    produced_assertion = {
        "binding_id": produced_declaration["binding_id"],
        "phase": produced_declaration["phase"],
        "value_class": produced_declaration["value_class"],
        "source_step_id": produced_declaration["source_step_id"],
        "evidence_type": produced_declaration["evidence_type"],
        "evidence_digest": evidence_digest,
        "digest_policy": produced_declaration["digest_policy"],
        "persistence_policy": produced_declaration["persistence_policy"],
        "sanitized_value": None,
        "value_digest": step["resource"]["exact_digest"],
        "recorded_at": STEP2_RECORDED_AT,
    }
    return record_step_outcome(
        plan,
        approval,
        authorized,
        STEP2_ID,
        "SUCCEEDED",
        "PASS",
        outcome_evidence,
        step["expected_postcondition"],
        None,
        SCHEMA_ROOT,
        STEP2_RECORDED_AT,
        binding_assertions=[produced_assertion],
    )


def expected_step3_progress(
    plan: dict, approval: dict, step2_progress: dict, evidence: dict
) -> dict:
    step = plan["steps"][2]
    observation_digest = canonical_digest(evidence["authorization_observation"])
    preflight_declaration = next(
        declaration
        for declaration in step["binding_declarations"]
        if declaration["phase"] == "RESOLVED_BY_STEP_PREFLIGHT"
    )


    preflight_assertion = {
        "binding_id": preflight_declaration["binding_id"],
        "phase": preflight_declaration["phase"],
        "value_class": preflight_declaration["value_class"],
        "source_step_id": preflight_declaration["source_step_id"],
        "evidence_type": preflight_declaration["evidence_type"],
        "evidence_digest": observation_digest,
        "digest_policy": preflight_declaration["digest_policy"],
        "persistence_policy": preflight_declaration["persistence_policy"],
        "sanitized_value": None,
        "value_digest": observation_digest,
        "recorded_at": STEP3_RECORDED_AT,
    }
    request = {
        "plan_id": plan["plan_id"],
        "plan_version": plan["plan_version"],
        "plan_digest": plan["plan_digest"],
        "environment": plan["environment"],
        "provider_reference": plan["target"]["provider_reference"],
        "project_reference": plan["target"]["project_reference"],
        "responsibility": plan["target"]["responsibility"],
        "issuer_reference": plan["target"]["issuer_reference"],
        "audience_reference": plan["target"]["audience_reference"],
        "step_id": step["step_id"],
        "resource_reference": step["resource"]["resource_reference"],
        "resource_version": step["resource"]["exact_version"],
        "resource_digest": step["resource"]["exact_digest"],
        "operation": step["operation"],
        "execution_class": step["execution_class"],
        "credential_class": "OWNER_INTERACTIVE_SESSION",
        "required_evidence": [{
            "evidence_type": "auth.cleanup-admin-github-binding.created",
            "evidence_digest": STEP2_EVIDENCE_DIGEST,
        }],
        "prior_evidence_digests": [STEP1_EVIDENCE_DIGEST, STEP2_EVIDENCE_DIGEST],
        "unexpected_remote_state": False,
        "extra_privileges": False,
        "unauthorized_migration_surface": False,
        "scope_expansion": False,
    }
    authorized = authorize_step(
        plan,
        approval,
        step2_progress,
        request,
        SCHEMA_ROOT,
        STEP3_RECORDED_AT,
        trusted_preflight_assertions=[preflight_assertion],
    )
    evidence_digest = raw_digest(STEP3_EVIDENCE_PATH)
    outcome_evidence = [{
        "evidence_type": evidence["evidence_type"],
        "evidence_reference": STEP3_EVIDENCE_PATH.name,
        "evidence_digest": evidence_digest,
        "recorded_at": STEP3_RECORDED_AT,
    }]
    produced_declaration = next(
        declaration
        for declaration in step["binding_declarations"]
        if declaration["phase"] == "PRODUCED_BY_CURRENT_STEP"
    )
    produced_assertion = {
        "binding_id": produced_declaration["binding_id"],
        "phase": produced_declaration["phase"],
        "value_class": produced_declaration["value_class"],
        "source_step_id": produced_declaration["source_step_id"],
        "evidence_type": produced_declaration["evidence_type"],
        "evidence_digest": evidence_digest,
        "digest_policy": produced_declaration["digest_policy"],
        "persistence_policy": produced_declaration["persistence_policy"],
        "sanitized_value": None,
        "value_digest": step["resource"]["exact_digest"],
        "recorded_at": STEP3_RECORDED_AT,
    }
    return record_step_outcome(
        plan,
        approval,
        authorized,
        STEP3_ID,
        "SUCCEEDED",
        "PASS",
        outcome_evidence,
        step["expected_postcondition"],
        None,
        SCHEMA_ROOT,
        STEP3_RECORDED_AT,
        binding_assertions=[produced_assertion],
    )


def expected_step4_progress(
    plan: dict, approval: dict, step3_progress: dict, evidence: dict
) -> dict:
    step = plan["steps"][3]
    request = {
        "plan_id": plan["plan_id"],
        "plan_version": plan["plan_version"],
        "plan_digest": plan["plan_digest"],
        "environment": plan["environment"],
        "provider_reference": plan["target"]["provider_reference"],
        "project_reference": plan["target"]["project_reference"],
        "responsibility": plan["target"]["responsibility"],
        "issuer_reference": plan["target"]["issuer_reference"],
        "audience_reference": plan["target"]["audience_reference"],
        "step_id": step["step_id"],
        "resource_reference": step["resource"]["resource_reference"],
        "resource_version": step["resource"]["exact_version"],
        "resource_digest": step["resource"]["exact_digest"],
        "operation": step["operation"],
        "execution_class": step["execution_class"],
        "credential_class": "NONE",
        "required_evidence": [
            {"evidence_type": "auth.cleanup-admin-credential.created",
             "evidence_digest": STEP1_EVIDENCE_DIGEST},
            {"evidence_type": "auth.cleanup-admin-github-binding.verified",
             "evidence_digest": STEP3_EVIDENCE_DIGEST},
        ],
        "prior_evidence_digests": [
            STEP1_EVIDENCE_DIGEST, STEP2_EVIDENCE_DIGEST, STEP3_EVIDENCE_DIGEST,
        ],
        "unexpected_remote_state": False,
        "extra_privileges": False,
        "unauthorized_migration_surface": False,
        "scope_expansion": False,
    }
    authorized = authorize_step(
        plan, approval, step3_progress, request, SCHEMA_ROOT, STEP4_RECORDED_AT
    )
    evidence_digest = raw_digest(STEP4_EVIDENCE_PATH)
    produced_declaration = next(
        declaration for declaration in step["binding_declarations"]
        if declaration["phase"] == "PRODUCED_BY_CURRENT_STEP"
    )
    produced_assertion = {
        "binding_id": produced_declaration["binding_id"],
        "phase": produced_declaration["phase"],
        "value_class": produced_declaration["value_class"],
        "source_step_id": produced_declaration["source_step_id"],
        "evidence_type": produced_declaration["evidence_type"],
        "evidence_digest": evidence_digest,
        "digest_policy": produced_declaration["digest_policy"],
        "persistence_policy": produced_declaration["persistence_policy"],
        "sanitized_value": None,
        "value_digest": step["resource"]["exact_digest"],
        "recorded_at": STEP4_RECORDED_AT,
    }
    return record_step_outcome(
        plan, approval, authorized, STEP4_ID, "SUCCEEDED", "PASS",
        [{
            "evidence_type": evidence["evidence_type"],
            "evidence_reference": STEP4_EVIDENCE_PATH.name,
            "evidence_digest": evidence_digest,
            "recorded_at": STEP4_RECORDED_AT,
        }],
        step["expected_postcondition"], None, SCHEMA_ROOT, STEP4_RECORDED_AT,
        binding_assertions=[produced_assertion],
    )


def expected_step1_progress(
    plan: dict, approval: dict, pristine_progress: dict, evidence: dict
) -> dict:
    step = plan["steps"][0]
    observation_digest = canonical_digest(evidence["authorization_observation"])
    preflight_declaration = next(
        declaration
        for declaration in step["binding_declarations"]
        if declaration["phase"] == "RESOLVED_BY_STEP_PREFLIGHT"
    )
    preflight_assertion = {
        "binding_id": preflight_declaration["binding_id"],
        "phase": preflight_declaration["phase"],
        "value_class": preflight_declaration["value_class"],
        "source_step_id": preflight_declaration["source_step_id"],
        "evidence_type": preflight_declaration["evidence_type"],
        "evidence_digest": observation_digest,
        "digest_policy": preflight_declaration["digest_policy"],
        "persistence_policy": preflight_declaration["persistence_policy"],
        "sanitized_value": None,
        "value_digest": observation_digest,
        "recorded_at": RECORDED_AT,
    }
    request = {
        "plan_id": plan["plan_id"],
        "plan_version": plan["plan_version"],
        "plan_digest": plan["plan_digest"],
        "environment": plan["environment"],
        "provider_reference": plan["target"]["provider_reference"],
        "project_reference": plan["target"]["project_reference"],
        "responsibility": plan["target"]["responsibility"],
        "issuer_reference": plan["target"]["issuer_reference"],
        "audience_reference": plan["target"]["audience_reference"],
        "step_id": step["step_id"],
        "resource_reference": step["resource"]["resource_reference"],
        "resource_version": step["resource"]["exact_version"],
        "resource_digest": step["resource"]["exact_digest"],
        "operation": step["operation"],
        "execution_class": step["execution_class"],
        "credential_class": "OWNER_INTERACTIVE_SESSION",
        "required_evidence": [
            {
                "evidence_type": item["evidence_type"],
                "evidence_digest": item["exact_digest"],
            }
            for item in step["required_evidence"]
        ],
        "prior_evidence_digests": [],
        "unexpected_remote_state": False,
        "extra_privileges": False,
        "unauthorized_migration_surface": False,
        "scope_expansion": False,
    }
    authorized = authorize_step(
        plan,
        approval,
        pristine_progress,
        request,
        SCHEMA_ROOT,
        RECORDED_AT,
        trusted_preflight_assertions=[preflight_assertion],
    )
    evidence_digest = raw_digest(STEP1_EVIDENCE_PATH)
    outcome_evidence = [{
        "evidence_type": evidence["evidence_type"],
        "evidence_reference": STEP1_EVIDENCE_PATH.name,
        "evidence_digest": evidence_digest,
        "recorded_at": RECORDED_AT,
    }]
    produced_declaration = next(
        declaration
        for declaration in step["binding_declarations"]
        if declaration["phase"] == "PRODUCED_BY_CURRENT_STEP"
    )
    produced_assertion = {
        "binding_id": produced_declaration["binding_id"],
        "phase": produced_declaration["phase"],
        "value_class": produced_declaration["value_class"],
        "source_step_id": produced_declaration["source_step_id"],
        "evidence_type": produced_declaration["evidence_type"],
        "evidence_digest": evidence_digest,
        "digest_policy": produced_declaration["digest_policy"],
        "persistence_policy": produced_declaration["persistence_policy"],
        "sanitized_value": None,
        "value_digest": step["resource"]["exact_digest"],
        "recorded_at": RECORDED_AT,
    }
    return record_step_outcome(
        plan,
        approval,
        authorized,
        STEP1_ID,
        "SUCCEEDED",
        "PASS",
        outcome_evidence,
        step["expected_postcondition"],
        None,
        SCHEMA_ROOT,
        RECORDED_AT,
        binding_assertions=[produced_assertion],
    )


def main() -> int:
    plan = load(PLAN_PATH)
    progress = load(PROGRESS_PATH)
    approval = load(APPROVAL_PATH)
    evidence = load(STEP1_EVIDENCE_PATH)
    step2_evidence = load(STEP2_EVIDENCE_PATH)
    step3_evidence = load(STEP3_EVIDENCE_PATH)
    step4_evidence = load(STEP4_EVIDENCE_PATH)
    execution_progress = load(EXECUTION_PROGRESS_PATH)
    validate_plan(plan, SCHEMA_ROOT)
    validate_progress(plan, progress, SCHEMA_ROOT)
    validate_approval(plan, approval, SCHEMA_ROOT, WINDOW_START)

    assert plan["plan_id"] == PLAN_ID
    assert plan["plan_digest"] == PLAN_DIGEST == plan_digest(plan)
    assert raw_digest(PLAN_PATH) == PLAN_RAW_DIGEST
    assert raw_digest(PROGRESS_PATH) == PROGRESS_RAW_DIGEST
    assert approval["approval_id"] == APPROVAL_ID
    assert approval["plan_id"] == PLAN_ID
    assert approval["plan_version"] == plan["plan_version"]
    assert approval["plan_digest"] == PLAN_DIGEST
    assert approval["owner_identity"] == "github:AnonymousKoo"
    assert approval["decision"] == "APPROVE"
    assert approval["environment"] == "DEVELOPMENT"
    assert approval["effective_at"] == WINDOW_START
    assert approval["expires_at"] == WINDOW_END
    assert approval["approved_at"] == APPROVED_AT < WINDOW_START
    assert approval["status"] == "ACTIVE"
    assert approval["authority_scope"] == "EXACT_PLAN_ONLY"
    assert approval["approval_digest"] == APPROVAL_DIGEST == approval_digest(approval)
    if APPROVAL_RAW_DIGEST:
        assert raw_digest(APPROVAL_PATH) == APPROVAL_RAW_DIGEST
    assert plan["definition_status"] == "READY_FOR_APPROVAL"
    assert plan["environment"] == "DEVELOPMENT"
    assert plan["target"]["provider_reference"] == "supabase"
    assert plan["target"]["project_reference"] == PROJECT
    assert plan["target"]["responsibility"] == "AUTH"
    assert plan["authorization_window"] == {
        "binding_state": "BOUND",
        "starts_at": WINDOW_START,
        "expires_at": WINDOW_END,
    }
    assert CREATED_AT < WINDOW_START < WINDOW_END
    assert plan["authority_effect"] == "NONE_UNTIL_SEPARATELY_APPROVED"

    assert progress == initial_progress(
        plan, SCHEMA_ROOT, PROGRESS_ID, CREATED_AT
    )
    assert progress["progress_digest"] == PROGRESS_DIGEST
    assert progress["overall_state"] == "NOT_STARTED"
    assert all(
        (
            state["authorization_state"], state["execution_state"],
            state["verification_state"], state["authorization_consumed"],
            state["evidence"], state["binding_assertions"],
        ) == ("PENDING", "NOT_STARTED", "NOT_STARTED", False, [], [])
        for state in progress["step_states"]
    )

    assert len(plan["steps"]) == 4
    create, bind, verify, retire = plan["steps"]
    assert plan["ordered_step_ids"] == [step["step_id"] for step in plan["steps"]]
    assert [step["ordinal"] for step in plan["steps"]] == [1, 2, 3, 4]
    assert [step["execution_class"] for step in plan["steps"]] == [
        "PROVIDER_MUTATION", "PROVIDER_MUTATION", "PROVIDER_READ", "LOCAL_ONLY"
    ]
    assert [step["credential_policy"] for step in plan["steps"]] == [
        {"permitted": True, "allowed_classes": ["OWNER_INTERACTIVE_SESSION"],
         "values_stored": False},
        {"permitted": True, "allowed_classes": ["OWNER_INTERACTIVE_SESSION"],
         "values_stored": False},
        {"permitted": True, "allowed_classes": ["OWNER_INTERACTIVE_SESSION"],
         "values_stored": False},
        {"permitted": False, "allowed_classes": ["NONE"], "values_stored": False},
    ]

    assert create["resource"]["exact_digest"] == canonical_digest(CREATE_CONTRACT)
    assert bind["resource"]["exact_digest"] == canonical_digest(BIND_CONTRACT)
    assert verify["resource"]["exact_digest"] == canonical_digest(VERIFY_CONTRACT)
    assert retire["resource"]["exact_digest"] == canonical_digest(RETIREMENT_CONTRACT)
    assert create["required_evidence"] == [{
        "evidence_type": "auth.synthetic-session.global-revocation.accepted",
        "source_step_id": None,
        "binding_state": "BOUND",
        "exact_digest": PRIOR_FAILURE_DIGEST,
    }]
    prior = load(
        BASE / "development-auth-v32-synthetic-session-cleanup-v1.execution-progress.json"
    )
    assert prior["overall_state"] == "STOPPED"
    assert prior["progress_digest"] == PRIOR_STOPPED_PROGRESS_DIGEST
    assert (
        prior["step_states"][1]["authorization_state"],
        prior["step_states"][1]["execution_state"],
        prior["step_states"][1]["verification_state"],
    ) == ("CONSUMED", "FAILED", "FAIL")
    assert prior["step_states"][2]["authorization_state"] == "BLOCKED"

    assert create["operation"] == (
        "provider.auth-admin-credential.create-dedicated-secret-key"
    )
    assert bind["operation"] == (
        "provider.auth-secret-binding.create-github-environment-reference"
    )
    assert verify["operation"] == (
        "provider.auth-secret-binding.verify-github-environment-reference"
    )
    assert retire["operation"] == (
        "local.auth-credential-retirement-requirement.seal"
    )
    assert bind["dependency_step_ids"] == [create["step_id"]]
    assert verify["dependency_step_ids"] == [bind["step_id"]]
    assert retire["dependency_step_ids"] == [verify["step_id"]]

    assert raw_digest(STEP1_EVIDENCE_PATH) == STEP1_EVIDENCE_DIGEST
    assert evidence["evidence_type"] == "auth.cleanup-admin-credential.created"
    assert evidence["environment"] == "DEVELOPMENT"
    assert evidence["responsibility"] == "AUTH"
    assert evidence["provider_reference"] == "supabase"
    assert evidence["project_reference"] == PROJECT
    assert evidence["plan_id"] == PLAN_ID and evidence["plan_digest"] == PLAN_DIGEST
    assert evidence["approval_id"] == APPROVAL_ID
    assert evidence["approval_digest"] == APPROVAL_DIGEST
    assert evidence["step_id"] == STEP1_ID
    assert evidence["attempt"] == 1
    assert evidence["outcome"] == "SUCCEEDED_VERIFIED"
    assert evidence["classification"] == "DEDICATED_CLEANUP_CREDENTIAL_CREATED"
    assert evidence["authorization_observation_digest"] == canonical_digest(
        evidence["authorization_observation"]
    )
    assert evidence["authorization_observation"] == {
        "interaction_surface": "supabase.dashboard.project-api-keys",
        "project_reference": PROJECT,
        "responsibility": "AUTH",
        "approval_exact": True,
        "authorization_window_execution_owner_confirmed": True,
        "credential_class": "OWNER_INTERACTIVE_SESSION",
        "credential_material_exposed_to_agent": False,
    }
    expected_result = {
        "classification": "DEDICATED_CLEANUP_CREDENTIAL_CREATED",
        "resource_reference": create["resource"]["resource_reference"],
        "provider_key_kind": "secret",
        "logical_key_name": "cleanup-v2-ephemeral",
        "dedicated_scope": "development-auth-synthetic-session-cleanup-v2-only",
    }
    assert evidence["sanitized_result"] == expected_result
    assert evidence["result_digest"] == canonical_digest(expected_result)
    assert evidence["configuration_reference_digest"] == create["resource"]["exact_digest"]
    assert evidence["execution_observation"] == {
        "execution_class": "PROVIDER_MUTATION",
        "execution_timestamp_retained": False,
        "recorded_at_is_execution_timestamp": False,
        "exact_provider_execution_timestamp_available": False,
        "provider_key_creation_attempts": 1,
        "provider_keys_created": 1,
        "github_environment_secret_binding_mutation_attempted": False,
        "cleanup_v2_prepared": False,
        "step2_executed": False,
        "step3_executed": False,
        "step4_executed": False,
        "sql_executed": False,
        "session_issued": False,
        "logout_attempted": False,
        "token_issued": False,
    }
    assert evidence["provider_mutation_attempted"] is True
    assert evidence["credential_material_retained"] is False
    assert evidence["credential_material_digest_recorded"] is False
    assert evidence["pii_retained"] is False
    assert evidence["record_basis"] == "OWNER_CONFIRMED_SANITIZED_EXECUTION_OUTCOME"
    assert evidence["recorded_at"] == RECORDED_AT
    step1_execution_progress = expected_step1_progress(
        plan, approval, progress, evidence
    )
    assert step1_execution_progress["progress_digest"] == STEP1_PROGRESS_DIGEST
    step2_execution_progress = expected_step2_progress(
        plan, approval, step1_execution_progress, step2_evidence
    )
    assert step2_execution_progress["progress_digest"] == STEP2_PROGRESS_DIGEST
    step3_execution_progress = expected_step3_progress(
        plan, approval, step2_execution_progress, step3_evidence
    )
    assert step3_execution_progress["progress_digest"] == STEP3_PROGRESS_DIGEST
    assert execution_progress == expected_step4_progress(
        plan, approval, step3_execution_progress, step4_evidence
    )
    validate_progress(plan, execution_progress, SCHEMA_ROOT)
    assert raw_digest(STEP3_EVIDENCE_PATH) == STEP3_EVIDENCE_DIGEST
    assert raw_digest(STEP2_EVIDENCE_PATH) == STEP2_EVIDENCE_DIGEST
    assert execution_progress["progress_digest"] == EXECUTION_PROGRESS_DIGEST == progress_digest(
        execution_progress
    )
    assert execution_progress["overall_state"] == "COMPLETED"
    first, second, third, fourth = execution_progress["step_states"]
    assert (
        first["authorization_state"], first["execution_state"],
        first["verification_state"], first["authorization_consumed"],
        first["safe_error_code"], len(first["evidence"]),
    ) == ("CONSUMED", "SUCCEEDED", "PASS", True, None, 1)
    assert [item["evidence_digest"] for item in first["evidence"]] == [STEP1_EVIDENCE_DIGEST]
    assert (
        second["authorization_state"], second["execution_state"],
        second["verification_state"], second["authorization_consumed"],
        second["safe_error_code"], len(second["evidence"]),
    ) == ("CONSUMED", "SUCCEEDED", "PASS", True, None, 1)
    assert [item["evidence_digest"] for item in second["evidence"]] == [STEP2_EVIDENCE_DIGEST]
    assert len(second["binding_assertions"]) == 3
    assert second["binding_assertions"][0]["evidence_digest"] == STEP1_EVIDENCE_DIGEST
    assert second["binding_assertions"][1]["evidence_type"] == "auth.cleanup-github-binding-owner-session.observed"
    assert second["binding_assertions"][2]["evidence_type"] == "auth.cleanup-admin-github-binding.created"
    assert (
        third["authorization_state"], third["execution_state"],
        third["verification_state"], third["authorization_consumed"],
        third["safe_error_code"], len(third["evidence"]),
    ) == ("CONSUMED", "SUCCEEDED", "PASS", True, None, 1)
    assert [item["evidence_digest"] for item in third["evidence"]] == [STEP3_EVIDENCE_DIGEST]
    assert len(third["binding_assertions"]) == 3
    assert third["binding_assertions"][0]["evidence_digest"] == STEP2_EVIDENCE_DIGEST
    assert third["binding_assertions"][1]["evidence_type"] == "auth.cleanup-github-binding-read-session.observed"
    assert third["binding_assertions"][2]["evidence_type"] == "auth.cleanup-admin-github-binding.verified"
    assert (
        fourth["authorization_state"], fourth["execution_state"],
        fourth["verification_state"], fourth["authorization_consumed"],
        fourth["safe_error_code"], len(fourth["evidence"]),
    ) == ("CONSUMED", "SUCCEEDED", "PASS", True, None, 1)
    assert [item["evidence_digest"] for item in fourth["evidence"]] == [STEP4_EVIDENCE_DIGEST]
    assert [item["binding_id"] for item in fourth["binding_assertions"]] == [
        "binding.development.auth.cleanup-credential-repair-v1.credential-reference",
        "binding.development.auth.cleanup-credential-repair-v1.github-binding-presence",
        "binding.development.auth.cleanup-credential-repair-v1.retirement-obligation",
    ]
    assert fourth["binding_assertions"][0]["evidence_digest"] == STEP1_EVIDENCE_DIGEST
    assert fourth["binding_assertions"][1]["evidence_digest"] == STEP3_EVIDENCE_DIGEST
    assert fourth["binding_assertions"][2]["evidence_digest"] == STEP4_EVIDENCE_DIGEST

    serialized = json.dumps({"plan": plan, "progress": progress}, sort_keys=True)
    assert SECRET_REFERENCE in serialized
    assert OLD_SECRET_REFERENCE not in serialized
    assert DATA_PROJECT not in serialized
    assert "cleanup-v2.prepare" in plan["prohibited_actions"]
    assert "cleanup-v1.retry" in plan["prohibited_actions"]
    assert "service-role.use" in plan["prohibited_actions"]
    for prohibited in (
        "identity.create", "identity.delete", "identity.modify", "hook.modify",
        "session.issue", "logout.execute", "sql.execute", "data.operation",
        "render.operation", "n8n.operation", "staging.target", "production.target",
    ):
        assert prohibited in plan["prohibited_actions"]
    assert RETIREMENT_CONTRACT["retirement_requires_fresh_exact_authority"] is True
    assert RETIREMENT_CONTRACT["reuse_allowed"] is False
    assert "provider.contact" in retire["prohibited_actions"]
    assert "provider.mutation" in retire["prohibited_actions"]

    expected_reference = (
        "github:AnonymousKoo/avuhz-infra:environment:development:secret:" + SECRET_REFERENCE
    )
    assert step2_evidence["evidence_type"] == "auth.cleanup-admin-github-binding.created"
    assert step2_evidence["environment"] == "DEVELOPMENT"
    assert step2_evidence["responsibility"] == "AUTH"
    assert step2_evidence["provider_reference"] == "github"
    assert step2_evidence["project_reference"] == PROJECT
    assert step2_evidence["repository"] == "AnonymousKoo/avuhz-infra"
    assert step2_evidence["environment_reference"] == "development"
    assert step2_evidence["plan_id"] == PLAN_ID and step2_evidence["plan_digest"] == PLAN_DIGEST
    assert step2_evidence["approval_id"] == APPROVAL_ID
    assert step2_evidence["approval_digest"] == APPROVAL_DIGEST
    assert step2_evidence["step_id"] == STEP2_ID
    assert step2_evidence["attempt"] == 1
    assert step2_evidence["outcome"] == "SUCCEEDED_VERIFIED"
    assert step2_evidence["classification"] == "CLEANUP_CREDENTIAL_BINDING_CREATED"
    assert step2_evidence["authorization_observation_digest"] == canonical_digest(
        step2_evidence["authorization_observation"]
    )
    assert step2_evidence["authorization_observation"] == {
        "interaction_surface": "github.environment.development.secrets",
        "repository": "AnonymousKoo/avuhz-infra",
        "environment": "development",
        "resource_reference": expected_reference,
        "approval_exact": True,
        "authorization_window_execution_owner_confirmed": True,
        "credential_class": "OWNER_INTERACTIVE_SESSION",
        "credential_material_exposed_to_agent": False,
    }
    expected_step2_result = {
        "classification": "CLEANUP_CREDENTIAL_BINDING_CREATED",
        "resource_reference": expected_reference,
        "repository": "AnonymousKoo/avuhz-infra",
        "environment": "development",
        "binding_created": True,
        "source_credential_reference": "supabase:" + PROJECT + ":secret-key:cleanup-v2-ephemeral",
    }
    assert step2_evidence["sanitized_result"] == expected_step2_result
    assert step2_evidence["result_digest"] == canonical_digest(expected_step2_result)
    assert step2_evidence["configuration_reference_digest"] == bind["resource"]["exact_digest"]
    assert step2_evidence["execution_observation"] == {
        "execution_class": "PROVIDER_MUTATION",
        "execution_timestamp_retained": False,
        "recorded_at_is_execution_timestamp": False,
        "exact_github_binding_execution_timestamp_available": False,
        "github_environment_secret_binding_mutation_attempts": 1,
        "exact_binding_created": True,
        "other_github_secret_mutations": False,
        "step3_executed": False,
        "step4_executed": False,
        "cleanup_v2_prepared": False,
        "supabase_contact_or_mutation": False,
        "sql_executed": False,
        "session_issued": False,
        "logout_attempted": False,
        "token_issued": False,
    }
    assert step2_evidence["provider_mutation_attempted"] is True
    assert step2_evidence["credential_material_retained"] is False
    assert step2_evidence["credential_material_digest_recorded"] is False
    assert step2_evidence["pii_retained"] is False
    assert step2_evidence["record_basis"] == "OWNER_CONFIRMED_SANITIZED_EXECUTION_OUTCOME"
    assert step2_evidence["recorded_at"] == STEP2_RECORDED_AT
    assert step2_evidence["security_state"]["github_secret_mutation_during_recording"] is False
    assert step2_evidence["security_state"]["only_exact_approved_binding_changed"] is True

    assert step3_evidence["evidence_type"] == "auth.cleanup-admin-github-binding.verified"
    assert step3_evidence["environment"] == "DEVELOPMENT"
    assert step3_evidence["responsibility"] == "AUTH"
    assert step3_evidence["provider_reference"] == "github"
    assert step3_evidence["project_reference"] == PROJECT
    assert step3_evidence["repository"] == "AnonymousKoo/avuhz-infra"
    assert step3_evidence["environment_reference"] == "development"
    assert step3_evidence["plan_id"] == PLAN_ID and step3_evidence["plan_digest"] == PLAN_DIGEST
    assert step3_evidence["approval_id"] == APPROVAL_ID
    assert step3_evidence["approval_digest"] == APPROVAL_DIGEST
    assert step3_evidence["step_id"] == STEP3_ID
    assert step3_evidence["attempt"] == 1
    assert step3_evidence["outcome"] == "SUCCEEDED_VERIFIED"
    assert step3_evidence["classification"] == "CLEANUP_CREDENTIAL_BINDING_PRESENT"
    assert step3_evidence["authorization_observation_digest"] == canonical_digest(
        step3_evidence["authorization_observation"]
    )
    assert step3_evidence["authorization_observation"] == {
        "interaction_surface": "github.environment.development.secret-reference-read",
        "repository": "AnonymousKoo/avuhz-infra",
        "environment": "development",
        "expected_reference": SECRET_REFERENCE,
        "exact_name_filter": True,
        "exact_reference_present": True,
        "value_requested": False,
        "value_returned": False,
        "credential_class": "OWNER_INTERACTIVE_SESSION",
    }
    expected_step3_result = {
        "classification": "CLEANUP_CREDENTIAL_BINDING_PRESENT",
        "repository": "AnonymousKoo/avuhz-infra",
        "environment": "development",
        "secret_reference": SECRET_REFERENCE,
        "exact_reference_present": True,
        "value_read": False,
        "value_returned": False,
        "other_secret_changes": False,
    }
    assert step3_evidence["sanitized_result"] == expected_step3_result
    assert step3_evidence["result_digest"] == canonical_digest(expected_step3_result)
    assert step3_evidence["configuration_reference_digest"] == verify["resource"]["exact_digest"]
    assert step3_evidence["configuration_reference_digest"] == canonical_digest(VERIFY_CONTRACT)
    assert step3_evidence["execution_observation"] == {
        "execution_class": "PROVIDER_READ",
        "execution_timestamp_retained": False,
        "recorded_at_is_execution_timestamp": False,
        "exact_read_execution_timestamp_available": False,
        "read_only_reference_check_attempts": 1,
        "exact_reference_presence_confirmed": True,
        "secret_value_requested": False,
        "secret_value_returned": False,
        "secret_value_read": False,
        "secret_value_hashed": False,
        "github_secret_mutation_attempted": False,
        "other_secret_change_observed": False,
        "step4_executed": False,
        "cleanup_v2_prepared": False,
        "supabase_contact": False,
        "sql_executed": False,
        "logout_attempted": False,
        "session_issued": False,
        "token_issued": False,
    }
    assert step3_evidence["provider_mutation_attempted"] is False
    assert step3_evidence["credential_material_retained"] is False
    assert step3_evidence["credential_material_digest_recorded"] is False
    assert step3_evidence["pii_retained"] is False
    assert step3_evidence["record_basis"] == "OWNER_CONFIRMED_SANITIZED_EXECUTION_OUTCOME"
    assert step3_evidence["recorded_at"] == STEP3_RECORDED_AT

    assert raw_digest(STEP4_EVIDENCE_PATH) == STEP4_EVIDENCE_DIGEST
    assert step4_evidence["evidence_type"] == "auth.cleanup-admin-retirement.required"
    assert step4_evidence["environment"] == "DEVELOPMENT"
    assert step4_evidence["responsibility"] == "AUTH"
    assert step4_evidence["provider_reference"] == "local"
    assert step4_evidence["project_reference"] == PROJECT
    assert step4_evidence["plan_id"] == PLAN_ID and step4_evidence["plan_digest"] == PLAN_DIGEST
    assert step4_evidence["approval_id"] == APPROVAL_ID
    assert step4_evidence["approval_digest"] == APPROVAL_DIGEST
    assert step4_evidence["step_id"] == STEP4_ID
    assert step4_evidence["attempt"] == 1
    assert step4_evidence["outcome"] == "SUCCEEDED_VERIFIED"
    assert step4_evidence["classification"] == "CLEANUP_CREDENTIAL_RETIREMENT_REQUIRED"
    assert step4_evidence["sanitized_result"]["fresh_exact_retirement_approval_required"] is True
    assert step4_evidence["sanitized_result"]["retirement_performed"] is False
    assert step4_evidence["sanitized_result"]["provider_contact_attempted"] is False
    assert step4_evidence["result_digest"] == canonical_digest(step4_evidence["sanitized_result"])
    assert step4_evidence["configuration_reference_digest"] == retire["resource"]["exact_digest"]
    assert step4_evidence["execution_observation"] == {
        "execution_class": "LOCAL_ONLY",
        "local_obligation_sealed": True,
        "execution_timestamp_retained": False,
        "recorded_at_is_execution_timestamp": False,
        "exact_local_execution_timestamp_available": False,
        "provider_contact_attempted": False,
        "provider_mutation_attempted": False,
        "credential_value_accessed": False,
        "credential_material_retained": False,
        "credential_material_digest_recorded": False,
        "supabase_key_deletion_attempted": False,
        "github_secret_mutation_attempted": False,
        "github_secret_deletion_attempted": False,
        "cleanup_v2_prepared": False,
        "fresh_retirement_authority_created": False,
    }
    assert step4_evidence["provider_mutation_attempted"] is False
    assert step4_evidence["credential_material_retained"] is False
    assert step4_evidence["credential_material_digest_recorded"] is False
    assert step4_evidence["pii_retained"] is False
    assert step4_evidence["recorded_at"] == STEP4_RECORDED_AT

    cleanup_v2 = BASE / "development-auth-v32-synthetic-session-cleanup-v2.plan.json"
    assert cleanup_v2.is_file()
    assert (BASE / "development-auth-v32-synthetic-session-cleanup-v2.progress.json").is_file()
    assert (BASE / "development-auth-v32-synthetic-session-cleanup-v2.approval.json").is_file()
    cleanup_v2_execution = load(BASE / "development-auth-v32-synthetic-session-cleanup-v2.execution-progress.json")
    assert cleanup_v2_execution["overall_state"] == "IN_PROGRESS"
    assert cleanup_v2_execution["step_states"][0]["execution_state"] == "SUCCEEDED"
    assert cleanup_v2_execution["step_states"][1]["authorization_state"] == "PENDING"
    assert cleanup_v2_execution["step_states"][2]["authorization_state"] == "PENDING"

    text = "".join(
        path.read_text(encoding="utf-8")
        for path in (
            PLAN_PATH, PROGRESS_PATH, APPROVAL_PATH,
            STEP1_EVIDENCE_PATH, STEP2_EVIDENCE_PATH, STEP3_EVIDENCE_PATH,
            STEP4_EVIDENCE_PATH,
            EXECUTION_PROGRESS_PATH,
        )
    )
    assert re.search(r"sb_secret_[A-Za-z0-9._-]{8,}", text) is None
    for sensitive_field in (
        '"credential_value"', '"secret_value"', '"service_role_key"',
        '"access_token"', '"refresh_token"', '"authorization"',
    ):
        assert sensitive_field not in text.lower()

    print(
        "DEVELOPMENT AUTH cleanup credential-repair v1: PASS "
        "(Steps 1-4 consumed/succeeded/pass; retirement obligation sealed locally; "
        "no credential material retained or provider retirement performed)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
