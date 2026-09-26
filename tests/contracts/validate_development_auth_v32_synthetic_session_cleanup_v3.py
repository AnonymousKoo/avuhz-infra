#!/usr/bin/env python3
"""Validate preparation-only DEVELOPMENT AUTH cleanup-v3 continuation."""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.authorization_plan import (  # noqa: E402
    initial_progress,
    plan_digest,
    validate_plan,
    validate_progress,
)
from avuhz_runtime.implementation_handoff import canonical_digest  # noqa: E402

BASE = ROOT / "contracts/plans/v1"
SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
BOUNDARY = "development-auth-v32-synthetic-session-cleanup-v3"
PLAN_PATH = BASE / f"{BOUNDARY}.plan.json"
PROGRESS_PATH = BASE / f"{BOUNDARY}.progress.json"
PROJECT = "pwlhruwutoitnieactol"
DATA_PROJECT = "gnuqaefotwgkwurjpyik"
PLAN_ID = "8e6fc27a-9b2d-4a38-b6a8-5104446fe694"
PLAN_DIGEST = "sha256:7621cb349e26c106fba7941f82088c669ddb0512bfd6a3c6a2bcb16c5fcc04b8"
PLAN_RAW_DIGEST = "sha256:d4ad359e27740b9f4224882c0607f9b98b1f693ac83916d71bf93b1d7a78d63f"
PROGRESS_ID = "082d092e-9750-4a7a-99ea-16efea0ce13b"
PROGRESS_DIGEST = "sha256:cf4b76e32638bb92ab188ef511ed48632720fd060073be735797b6852bbba40d"
PROGRESS_RAW_DIGEST = "sha256:a407e9d2f22cab8b90f9c7412a54fcad10e2451866122bfee6d22f06c5eaa19e"
CREATED_AT = "2026-09-26T15:24:31Z"
WINDOW_START = "2026-09-27T15:00:00Z"
WINDOW_END = "2026-09-27T21:00:00Z"
STEP1_ID = "development.auth.v32-synthetic-session-cleanup-v3.step.01.revoke-synthetic-sessions-global"
STEP2_ID = "development.auth.v32-synthetic-session-cleanup-v3.step.02.verify-zero-session-refresh-state"
ADMIN_REFERENCE = "AVUHZ_DEVELOPMENT_SUPABASE_AUTH_SESSION_CLEANUP_V2_EPHEMERAL"
PUBLISHABLE_REFERENCE = "AVUHZ_DEVELOPMENT_SUPABASE_PUBLISHABLE_KEY"
SYNTHETIC_EMAIL = "avuhz-development-synthetic@example.invalid"
REBASELINE_EVIDENCE = "sha256:e2955c02b79f245f75a0affefd289376f005cdd165f724c02be88699744a5b43"
REBASELINE_PROGRESS = "sha256:68178521cb34199e2ab27fe7c48948df78e3846f0dba918f17b59ed920a51104"
V2_FAILURE_EVIDENCE = "sha256:8344c3e26c26f464bcefa880251ac7619bfc6087a8a17e9c0987db4a843191eb"
V2_STOPPED_PROGRESS = "sha256:a942c1fa84f32e96619f916c1686ccb8d8ec1a6f3dd7393a0fa6cc992f167468"
REPAIR_PROGRESS = "sha256:6d4e4d5473a50790e1c6db4df50e4428fda37dc9988b4bf44ddb145955b6e2f9"
REPAIR_STEP1 = "sha256:29fa0e715118b6cb70d6c08b28466b79407319bc5177947851b87b86c10dc47d"
REPAIR_STEP2 = "sha256:de7daf8b0c913f713225d292adae404bc877b298368c9fbedc5e451f6190e574"
REPAIR_STEP3 = "sha256:a431c44cac5069898b98784c82244f3b9335f124ee348666da0bb83894f3fce9"
RETIREMENT = "sha256:38ebcc897696f11284c540994c4a6144f08530ad8c4ec7e42c84a64f01559b8f"
LIFECYCLE = "sha256:bc0d64001ee765c436d09a417668d8e7f2dc2cd405d7384df372b792487315b5"
VERIFY_SQL = """select
  (select count(*) from auth.sessions) as session_count,
  (select count(*) from auth.refresh_tokens) as refresh_token_count;"""


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def raw_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def cleanup_contract() -> dict:
    return {
        "project_reference": PROJECT,
        "responsibility": "AUTH",
        "execution_class": "PROVIDER_MUTATION",
        "credential_class": "SUPABASE_AUTH_ADMIN_EPHEMERAL",
        "admin_credential_reference": ADMIN_REFERENCE,
        "publishable_configuration_reference": PUBLISHABLE_REFERENCE,
        "rebaseline_evidence_digest": REBASELINE_EVIDENCE,
        "rebaseline_execution_progress_digest": REBASELINE_PROGRESS,
        "rebaseline_classification": "SESSION_CLEANUP_REQUIRED",
        "rebaseline_counts": {"session_count": 2, "refresh_token_count": 2},
        "prior_cleanup_v2_failure_evidence_digest": V2_FAILURE_EVIDENCE,
        "prior_cleanup_v2_stopped_progress_digest": V2_STOPPED_PROGRESS,
        "credential_repair_completed_progress_digest": REPAIR_PROGRESS,
        "credential_repair_evidence_digests": {
            "created": REPAIR_STEP1,
            "github_binding_created": REPAIR_STEP2,
            "github_binding_verified": REPAIR_STEP3,
            "retirement_obligation": RETIREMENT,
        },
        "lifecycle_module": "src/avuhz_engineering/development_auth_token_lifecycle.py",
        "lifecycle_module_sha256": LIFECYCLE,
        "lifecycle_functions": [
            "request_generate_recovery_credential",
            "request_direct_recovery_verification",
            "validate_development_synthetic_access_jwt",
            "request_global_session_logout",
        ],
        "run_recovery_session_lifecycle_used": False,
        "synthetic_identity": SYNTHETIC_EMAIL,
        "existing_user_only": True,
        "recovery_generation": {
            "method": "POST", "path": "/auth/v1/admin/generate_link", "type": "recovery",
            "email_sent": False, "memory_only": True, "maximum_attempts": 1,
        },
        "direct_verification": {
            "method": "POST", "path": "/auth/v1/verify", "type": "recovery",
            "token_hash_memory_only": True, "temporary_sessions_maximum": 1,
            "maximum_attempts": 1,
            "response_compatibility": (
                "expires_at optional-or-null; expires_in positive; identity nested "
                "user.id or top-level id; conflicts fail-closed"
            ),
        },
        "preexisting_total_count_assumption_after_verification": "NONE",
        "jwt_validation": {
            "algorithm": "ES256", "issuer": f"https://{PROJECT}.supabase.co/auth/v1",
            "audience": "audience.avuhz.command-service.development",
            "exact_tenant_and_subject_digest": True, "caller_kind": "HUMAN",
            "scopes": ["engagement:read"], "authority_roles": [], "aal": "aal1",
            "authenticated": True, "anonymous": False, "before_logout": True,
        },
        "global_logout": {
            "method": "POST", "path": "/auth/v1/logout?scope=global",
            "accepted_status": 204, "exactly_once": True,
            "immediately_after_jwt_validation": True,
        },
        "success_classification": "SESSION_REVOCATION_REQUEST_ACCEPTED",
        "cleanup_verified": False,
        "step2_readback_required": True,
        "retry_authorized": False,
        "retirement_obligation_evidence_digest": RETIREMENT,
        "retirement_required_after_completion_or_permanent_stop": True,
        "retirement_performed_by_cleanup_v3": False,
        "direct_auth_schema_delete": False,
        "credential_material_retained": False,
        "raw_provider_response_retained": False,
    }


def verify_contract() -> dict:
    return {
        "interaction_surface": "supabase.dashboard.sql-editor",
        "project_reference": PROJECT,
        "responsibility": "AUTH",
        "execution_class": "PROVIDER_READ",
        "credential_class": "OWNER_INTERACTIVE_SESSION",
        "query": VERIFY_SQL,
        "query_count": 1,
        "allowed_result_fields": ["session_count", "refresh_token_count"],
        "required_result": {"session_count": 0, "refresh_token_count": 0},
        "success_classification": "SESSION_CLEANUP_VERIFIED",
        "nonzero_classification": "SESSION_CLEANUP_NOT_VERIFIED",
        "unverified_classification": "SESSION_STATE_UNVERIFIED",
    }


def main() -> int:
    plan = load(PLAN_PATH)
    progress = load(PROGRESS_PATH)
    validate_plan(plan, SCHEMA_ROOT)
    validate_progress(plan, progress, SCHEMA_ROOT)

    assert plan["plan_id"] == PLAN_ID
    assert plan["plan_version"] == 3
    assert plan["plan_digest"] == PLAN_DIGEST == plan_digest(plan)
    assert raw_digest(PLAN_PATH) == PLAN_RAW_DIGEST
    assert raw_digest(PROGRESS_PATH) == PROGRESS_RAW_DIGEST
    assert progress["progress_id"] == PROGRESS_ID
    assert progress["progress_digest"] == PROGRESS_DIGEST
    assert plan["definition_status"] == "READY_FOR_APPROVAL"
    assert plan["environment"] == "DEVELOPMENT"
    assert plan["target"]["project_reference"] == PROJECT
    assert plan["target"]["responsibility"] == "AUTH"
    assert DATA_PROJECT not in json.dumps(plan)
    assert plan["created_at"] == CREATED_AT < WINDOW_START
    assert plan["authorization_window"] == {
        "binding_state": "BOUND", "starts_at": WINDOW_START, "expires_at": WINDOW_END,
    }
    assert plan["authority_effect"] == "NONE_UNTIL_SEPARATELY_APPROVED"
    assert plan["ordered_step_ids"] == [STEP1_ID, STEP2_ID]
    cleanup, verify = plan["steps"]
    assert [step["ordinal"] for step in plan["steps"]] == [1, 2]
    assert [step["execution_class"] for step in plan["steps"]] == ["PROVIDER_MUTATION", "PROVIDER_READ"]
    assert cleanup["dependency_step_ids"] == []
    assert verify["dependency_step_ids"] == [STEP1_ID]
    assert cleanup["resource"]["exact_digest"] == canonical_digest(cleanup_contract())
    assert verify["resource"]["exact_digest"] == canonical_digest(verify_contract())
    assert cleanup["resource"]["exact_version"] == "cleanup.v3"
    assert verify["resource"]["exact_version"] == "cleanup.v3"

    required = {(item["evidence_type"], item["exact_digest"]) for item in cleanup["required_evidence"]}
    assert ("auth.session-state.owner-interactive-rebaselined", REBASELINE_EVIDENCE) in required
    assert ("authorization-plan.execution-progress", REBASELINE_PROGRESS) in required
    assert ("auth.cleanup-admin-retirement.required", RETIREMENT) in required
    assert ("authorization-plan.execution-progress", REPAIR_PROGRESS) in required
    serialized = json.dumps(plan, sort_keys=True)
    assert LIFECYCLE in serialized
    assert V2_FAILURE_EVIDENCE in serialized
    assert V2_STOPPED_PROGRESS in serialized
    assert ADMIN_REFERENCE in serialized
    assert PUBLISHABLE_REFERENCE in serialized
    assert "run-recovery-session-lifecycle.use" in cleanup["prohibited_actions"]
    assert "cleanup-v2.retry" in cleanup["prohibited_actions"]
    assert "service-role.use" in plan["prohibited_actions"]
    assert "auth.sessions.delete-sql" in plan["prohibited_actions"]
    assert "auth.refresh-tokens.delete-sql" in plan["prohibited_actions"]
    assert "Do not require the project-wide count to equal one" not in cleanup["expected_postcondition"]
    assert "make no total-count-one assumption" in cleanup["expected_postcondition"]
    assert "SESSION_REVOCATION_REQUEST_ACCEPTED" in cleanup["expected_postcondition"]
    assert verify["expected_postcondition"].count(VERIFY_SQL) == 1
    assert "SESSION_CLEANUP_VERIFIED" in verify["expected_postcondition"]

    assert progress == initial_progress(plan, SCHEMA_ROOT, PROGRESS_ID, CREATED_AT)
    assert progress["overall_state"] == "NOT_STARTED"
    for state in progress["step_states"]:
        assert (state["authorization_state"], state["execution_state"], state["verification_state"]) == (
            "PENDING", "NOT_STARTED", "NOT_STARTED"
        )
        assert state["authorization_consumed"] is False
        assert state["evidence"] == []
        assert state["binding_assertions"] == []

    assert not (BASE / f"{BOUNDARY}.approval.json").exists()
    assert not (BASE / f"{BOUNDARY}.execution-progress.json").exists()
    assert not list(BASE.glob(f"{BOUNDARY}*.evidence.json"))
    assert not (ROOT / f"scripts/development_auth_v32_synthetic_session_cleanup_v3.py").exists()
    assert not (ROOT / f".github/workflows/development-auth-v32-synthetic-session-cleanup-v3.yml").exists()

    assert raw_digest(ROOT / "src/avuhz_engineering/development_auth_token_lifecycle.py") == LIFECYCLE
    rebaseline = load(BASE / "development-auth-v32-session-state-rebaseline-owner-interactive-v1-step1-success.evidence.json")
    assert rebaseline["classification"] == "SESSION_CLEANUP_REQUIRED"
    assert rebaseline["sanitized_result"]["session_count"] == 2
    assert rebaseline["sanitized_result"]["refresh_token_count"] == 2
    assert raw_digest(BASE / "development-auth-v32-session-state-rebaseline-owner-interactive-v1-step1-success.evidence.json") == REBASELINE_EVIDENCE
    rebaseline_progress = load(BASE / "development-auth-v32-session-state-rebaseline-owner-interactive-v1.execution-progress.json")
    assert rebaseline_progress["overall_state"] == "COMPLETED"
    assert rebaseline_progress["progress_digest"] == REBASELINE_PROGRESS
    cleanup_v2 = load(BASE / "development-auth-v32-synthetic-session-cleanup-v2.execution-progress.json")
    assert cleanup_v2["overall_state"] == "STOPPED"
    assert cleanup_v2["progress_digest"] == V2_STOPPED_PROGRESS
    assert raw_digest(BASE / "development-auth-v32-synthetic-session-cleanup-v2-step2-failure.evidence.json") == V2_FAILURE_EVIDENCE

    lowered = serialized.lower()
    assert re.search(r"sb_secret_[a-z0-9._-]{8,}", lowered) is None
    for forbidden in ('"secret_value"', '"credential_value"', '"access_token"', '"refresh_token"'):
        assert forbidden not in lowered

    print(
        "DEVELOPMENT AUTH v32 synthetic-session cleanup-v3 prep: PASS "
        "(2/2 rebaseline bound; corrected lifecycle pinned; no execution authority)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
