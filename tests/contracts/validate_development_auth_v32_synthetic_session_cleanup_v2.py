#!/usr/bin/env python3
"""Validate the pristine forward-only DEVELOPMENT AUTH cleanup-v2 boundary."""
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
BOUNDARY = "development-auth-v32-synthetic-session-cleanup-v2"
PLAN_PATH = BASE / f"{BOUNDARY}.plan.json"
PROGRESS_PATH = BASE / f"{BOUNDARY}.progress.json"
APPROVAL_PATH = BASE / f"{BOUNDARY}.approval.json"
EXECUTION_PROGRESS_PATH = BASE / f"{BOUNDARY}.execution-progress.json"
EVIDENCE_GLOB = f"{BOUNDARY}*.evidence.json"
EXECUTOR_PATH = ROOT / "scripts/development_auth_v32_synthetic_session_cleanup_v2.py"
WORKFLOW_PATH = ROOT / ".github/workflows/development-auth-v32-synthetic-session-cleanup-v2.yml"
LIFECYCLE_PATH = ROOT / "src/avuhz_engineering/development_auth_token_lifecycle.py"

PLAN_ID = "55b1ac96-b338-4821-bcb3-02f4ab1a0958"
PROGRESS_ID = "dd04fc49-cd7a-49f2-bc99-2df8b949e70b"
PLAN_DIGEST = "sha256:4afea8848bc07967d93be6905b142d6d6c995cd43f204a610c439c0efee50df3"
PROGRESS_DIGEST = "sha256:eba7fe63e59cda2b30d074eedbd2455c69a182d5ee7d1824aa212c9065d57caa"
PLAN_RAW_DIGEST = "sha256:9be863eb813210c2b534f3afc7e6e55c6e0f89fb599631447486fd755830306d"
PROGRESS_RAW_DIGEST = "sha256:042221ef8a99e4c654b6f41485b08d5f3ba9ed02a21dbef95b5af261c7310ea3"
CREATED_AT = "2026-09-24T20:17:04Z"
WINDOW_START = "2026-09-25T15:00:00Z"
WINDOW_END = "2026-09-25T21:00:00Z"
PROJECT = "pwlhruwutoitnieactol"
DATA_PROJECT = "gnuqaefotwgkwurjpyik"
SYNTHETIC_EMAIL = "avuhz-development-synthetic@example.invalid"
ADMIN_REFERENCE = "AVUHZ_DEVELOPMENT_SUPABASE_AUTH_SESSION_CLEANUP_V2_EPHEMERAL"
PUBLISHABLE_REFERENCE = "AVUHZ_DEVELOPMENT_SUPABASE_PUBLISHABLE_KEY"
REPAIR_PLAN_ID = "0224c4fb-845c-4627-b48f-252ec954283c"
REPAIR_PLAN_DIGEST = "sha256:57b26eefa9ca294a4dff95d617a50c3e46d0cdaab1cf1862c1d1239d042babcb"
REPAIR_PROGRESS_DIGEST = "sha256:6d4e4d5473a50790e1c6db4df50e4428fda37dc9988b4bf44ddb145955b6e2f9"
REPAIR_STEP1_EVIDENCE = "sha256:29fa0e715118b6cb70d6c08b28466b79407319bc5177947851b87b86c10dc47d"
REPAIR_STEP2_EVIDENCE = "sha256:de7daf8b0c913f713225d292adae404bc877b298368c9fbedc5e451f6190e574"
REPAIR_STEP3_EVIDENCE = "sha256:a431c44cac5069898b98784c82244f3b9335f124ee348666da0bb83894f3fce9"
RETIREMENT_EVIDENCE = "sha256:38ebcc897696f11284c540994c4a6144f08530ad8c4ec7e42c84a64f01559b8f"
PRIOR_CLEANUP_V1_PROGRESS = "sha256:a8344c793b45ea0d05024cd259ec11c58437f7db51c590d2cfccf5c8e8d11f2b"
LIFECYCLE_RAW_DIGEST = "sha256:55503f13489944b0b4b51e3dc24875d5c6e83c69e8fc6a8aed6a03fdb0736749"
ATTRIBUTION_EVIDENCE = "sha256:87448d893e3d6f013cd6a20bdf05eef25b5d1c3425513377469c62eab40dffcc"
STEP1_ID = "development.auth.v32-synthetic-session-cleanup-v2.step.01.verify-current-attributed-session-precondition"
STEP2_ID = "development.auth.v32-synthetic-session-cleanup-v2.step.02.revoke-synthetic-sessions-global"
STEP3_ID = "development.auth.v32-synthetic-session-cleanup-v2.step.03.verify-zero-session-refresh-state"

PRECHECK_SQL = """select
  count(*) as session_count,
  count(*) filter (
    where u.email = 'avuhz-development-synthetic@example.invalid'
  ) as synthetic_session_count
from auth.sessions as s
left join auth.users as u on u.id = s.user_id;"""

VERIFY_SQL = """select
  (select count(*) from auth.sessions) as session_count,
  (select count(*) from auth.refresh_tokens) as refresh_token_count;"""

PRECHECK_CONTRACT = {
    "interaction_surface": "supabase.dashboard.sql-editor",
    "project_reference": PROJECT,
    "responsibility": "AUTH",
    "execution_class": "PROVIDER_READ",
    "credential_class": "OWNER_INTERACTIVE_SESSION",
    "query": PRECHECK_SQL,
    "query_count": 1,
    "allowed_result_fields": ["session_count", "synthetic_session_count"],
    "required_result": {"session_count": 1, "synthetic_session_count": 1},
    "success_classification": "PRE_CLEANUP_SYNTHETIC_SESSION_CONFIRMED",
    "failure_behavior": "STOP_BEFORE_STEP_2",
    "refresh_token_query": False,
}

CLEANUP_CONTRACT = {
    "project_reference": PROJECT,
    "responsibility": "AUTH",
    "execution_class": "PROVIDER_MUTATION",
    "credential_class": "SUPABASE_AUTH_ADMIN_EPHEMERAL",
    "admin_credential_reference": ADMIN_REFERENCE,
    "publishable_configuration_reference": PUBLISHABLE_REFERENCE,
    "credential_repair_plan_id": REPAIR_PLAN_ID,
    "credential_repair_plan_digest": REPAIR_PLAN_DIGEST,
    "credential_repair_completed_progress_digest": REPAIR_PROGRESS_DIGEST,
    "credential_repair_evidence_digests": {
        "created": REPAIR_STEP1_EVIDENCE,
        "github_binding_created": REPAIR_STEP2_EVIDENCE,
        "github_binding_verified": REPAIR_STEP3_EVIDENCE,
        "retirement_obligation": RETIREMENT_EVIDENCE,
    },
    "lifecycle_module": "src/avuhz_engineering/development_auth_token_lifecycle.py",
    "lifecycle_module_sha256": LIFECYCLE_RAW_DIGEST,
    "synthetic_identity": SYNTHETIC_EMAIL,
    "existing_user_only": True,
    "recovery_generation": {
        "function": "request_generate_recovery_credential",
        "method": "POST",
        "path": "/auth/v1/admin/generate_link",
        "body": {"type": "recovery", "email": SYNTHETIC_EMAIL},
        "email_sent": False,
        "credential_extracted": "hashed_token",
        "memory_only": True,
        "maximum_attempts": 1,
    },
    "direct_verification": {
        "function": "request_direct_recovery_verification",
        "method": "POST",
        "path": "/auth/v1/verify",
        "body_fields": {"type": "recovery", "token_hash": "in-memory hashed_token"},
        "response": "direct top-level AccessTokenResponse with access_token, refresh_token, expires_in, expires_at, token_type, and user.id",
        "temporary_sessions_maximum": 1,
    },
    "jwt_validation": {
        "function": "validate_development_synthetic_access_jwt",
        "policy_reference": "DEVELOPMENT_SYNTHETIC_READ_ONLY_ALLOWLIST[0]",
        "algorithm": "ES256",
        "issuer": f"https://{PROJECT}.supabase.co/auth/v1",
        "audience": "audience.avuhz.command-service.development",
        "exact_tenant_and_subject_digest": True,
        "caller_kind": "HUMAN",
        "scopes": ["engagement:read"],
        "authority_roles": [],
        "aal": "aal1",
        "authenticated": True,
        "anonymous": False,
        "before_logout": True,
    },
    "global_logout": {
        "function": "request_global_session_logout",
        "method": "POST",
        "path": "/auth/v1/logout?scope=global",
        "bearer": "temporary access JWT",
        "accepted_status": 204,
        "exactly_once": True,
        "immediately_after_jwt_validation": True,
    },
    "success_classification": "SESSION_REVOCATION_REQUEST_ACCEPTED",
    "cleanup_verified": False,
    "step3_readback_required": True,
    "retry_authorized": False,
    "retirement_obligation_evidence_digest": RETIREMENT_EVIDENCE,
    "retirement_required_after_completion_or_permanent_stop": True,
    "retirement_performed_by_cleanup_v2": False,
    "direct_auth_schema_delete": False,
    "credential_material_retained": False,
    "raw_provider_response_retained": False,
}

VERIFY_CONTRACT = {
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


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def raw_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    plan = load(PLAN_PATH)
    progress = load(PROGRESS_PATH)
    validate_plan(plan, SCHEMA_ROOT)
    validate_progress(plan, progress, SCHEMA_ROOT)

    assert plan["plan_id"] == PLAN_ID
    assert plan["plan_version"] == 2
    assert plan["plan_digest"] == PLAN_DIGEST == plan_digest(plan)
    assert raw_digest(PLAN_PATH) == PLAN_RAW_DIGEST
    assert raw_digest(PROGRESS_PATH) == PROGRESS_RAW_DIGEST
    assert plan["definition_status"] == "READY_FOR_APPROVAL"
    assert plan["environment"] == "DEVELOPMENT"
    assert plan["target"]["provider_reference"] == "supabase"
    assert plan["target"]["project_reference"] == PROJECT
    assert plan["target"]["responsibility"] == "AUTH"
    assert plan["owner_identity"] == "github:AnonymousKoo"
    assert plan["created_at"] == CREATED_AT < WINDOW_START
    assert plan["authorization_window"] == {
        "binding_state": "BOUND", "starts_at": WINDOW_START, "expires_at": WINDOW_END,
    }
    assert plan["authority_effect"] == "NONE_UNTIL_SEPARATELY_APPROVED"
    assert plan["plan_digest"] == plan_digest(plan)
    assert plan["ordered_step_ids"] == [STEP1_ID, STEP2_ID, STEP3_ID]
    assert len(plan["steps"]) == 3
    precheck, cleanup, verify = plan["steps"]
    assert [s["ordinal"] for s in plan["steps"]] == [1, 2, 3]
    assert [s["execution_class"] for s in plan["steps"]] == [
        "PROVIDER_READ", "PROVIDER_MUTATION", "PROVIDER_READ",
    ]
    assert [s["credential_policy"]["allowed_classes"] for s in plan["steps"]] == [
        ["OWNER_INTERACTIVE_SESSION"],
        ["SUPABASE_AUTH_ADMIN_EPHEMERAL"],
        ["OWNER_INTERACTIVE_SESSION"],
    ]
    assert [s["dependency_step_ids"] for s in plan["steps"]] == [
        [], [STEP1_ID], [STEP2_ID],
    ]
    assert precheck["resource"]["exact_digest"] == canonical_digest(PRECHECK_CONTRACT)
    assert cleanup["resource"]["exact_digest"] == canonical_digest(CLEANUP_CONTRACT)
    assert verify["resource"]["exact_digest"] == canonical_digest(VERIFY_CONTRACT)
    assert precheck["expected_postcondition"].count(PRECHECK_SQL) == 1
    assert verify["expected_postcondition"].count(VERIFY_SQL) == 1
    assert "require 1/1 for PRE_CLEANUP_SYNTHETIC_SESSION_CONFIRMED" in precheck["expected_postcondition"]
    assert "SESSION_CLEANUP_VERIFIED" in verify["expected_postcondition"]
    assert "SESSION_CLEANUP_NOT_VERIFIED" in verify["expected_postcondition"]
    assert "SESSION_STATE_UNVERIFIED" in verify["expected_postcondition"]
    assert raw_digest(LIFECYCLE_PATH) == LIFECYCLE_RAW_DIGEST
    assert plan["steps"][0]["required_evidence"] == [{
        "evidence_type": "auth.session-attribution.owner-interactive-inspected",
        "source_step_id": None,
        "binding_state": "BOUND",
        "exact_digest": ATTRIBUTION_EVIDENCE,
    }]
    assert plan["steps"][1]["required_evidence"] == [
        {
            "evidence_type": "auth.synthetic-session.precleanup-attribution.verified",
            "source_step_id": STEP1_ID,
            "binding_state": "DERIVED_FROM_SOURCE_STEP",
            "exact_digest": None,
        },
        {"evidence_type": "auth.cleanup-admin-credential.created", "source_step_id": None,
         "binding_state": "BOUND", "exact_digest": REPAIR_STEP1_EVIDENCE},
        {"evidence_type": "auth.cleanup-admin-github-binding.created", "source_step_id": None,
         "binding_state": "BOUND", "exact_digest": REPAIR_STEP2_EVIDENCE},
        {"evidence_type": "auth.cleanup-admin-github-binding.verified", "source_step_id": None,
         "binding_state": "BOUND", "exact_digest": REPAIR_STEP3_EVIDENCE},
        {"evidence_type": "auth.cleanup-admin-retirement.required", "source_step_id": None,
         "binding_state": "BOUND", "exact_digest": RETIREMENT_EVIDENCE},
        {"evidence_type": "authorization-plan.execution-progress", "source_step_id": None,
         "binding_state": "BOUND", "exact_digest": REPAIR_PROGRESS_DIGEST},
    ]
    assert plan["steps"][2]["required_evidence"] == [{
        "evidence_type": "auth.synthetic-session.global-revocation.accepted",
        "source_step_id": STEP2_ID,
        "binding_state": "DERIVED_FROM_SOURCE_STEP",
        "exact_digest": None,
    }]
    cleanup_bindings = {b["binding_id"]: b for b in cleanup["binding_declarations"]}
    assert cleanup_bindings["binding.development.auth.cleanup-v2.admin-credential-reference"]["preapproval_value"] == {
        "value": ADMIN_REFERENCE, "exact_digest": canonical_digest(ADMIN_REFERENCE),
    }
    assert cleanup_bindings["binding.development.auth.cleanup-v2.publishable-configuration-reference"]["preapproval_value"] == {
        "value": PUBLISHABLE_REFERENCE, "exact_digest": canonical_digest(PUBLISHABLE_REFERENCE),
    }
    assert cleanup_bindings["binding.development.auth.cleanup-v2.credential-repair-completed-progress"]["preapproval_value"] == {
        "value": REPAIR_PROGRESS_DIGEST, "exact_digest": canonical_digest(REPAIR_PROGRESS_DIGEST),
    }
    assert cleanup_bindings["binding.development.auth.cleanup-v2.retirement-obligation"]["preapproval_value"] == {
        "value": RETIREMENT_EVIDENCE, "exact_digest": canonical_digest(RETIREMENT_EVIDENCE),
    }
    assert CLEANUP_CONTRACT["retirement_required_after_completion_or_permanent_stop"] is True
    assert CLEANUP_CONTRACT["retirement_performed_by_cleanup_v2"] is False
    assert "cleanup_verified=false" in cleanup["expected_postcondition"]
    assert "retry_authorized=false" in cleanup["expected_postcondition"]
    assert "future fresh approval" in cleanup["expected_postcondition"]
    assert precheck["resource"]["exact_version"] == "cleanup.v2"
    assert cleanup["resource"]["exact_version"] == "cleanup.v2"
    assert verify["resource"]["exact_version"] == "cleanup.v2"
    assert precheck["operation"] == "provider.auth-session-state.verify-current-attribution-owner-interactive-read-only"
    assert cleanup["operation"] == "provider.auth-session.recover-once-validate-and-logout-global"
    assert verify["operation"] == "provider.auth-session-state.verify-zero-owner-interactive-read-only"
    assert precheck["execution_class"] == verify["execution_class"] == "PROVIDER_READ"
    assert cleanup["execution_class"] == "PROVIDER_MUTATION"
    assert cleanup["credential_policy"]["ephemeral_handling"] == {
        "material_source": "APPROVED_ENVIRONMENT_SECRET_BOUNDARY",
        "material_residency": "SERVER_EXECUTOR_MEMORY_ONLY",
        "control_plane_visibility": "CLASS_LABEL_ONLY",
        "material_digest": "PROHIBITED",
        "persistence": "PROHIBITED",
        "logging": "PROHIBITED",
        "return_policy": "PROHIBITED",
        "proof_policy": "NON_SECRET_EXECUTOR_CAPABILITY_ATTESTATION",
    }
    assert precheck["resource"]["exact_digest"] == canonical_digest(PRECHECK_CONTRACT)
    assert verify["resource"]["exact_digest"] == canonical_digest(VERIFY_CONTRACT)
    assert "SESSION_REVOCATION_REQUEST_ACCEPTED" in cleanup["expected_postcondition"]
    assert "SESSION_CLEANUP_VERIFIED" in verify["expected_postcondition"]
    assert "SESSION_CLEANUP_NOT_VERIFIED" in verify["expected_postcondition"]
    assert "SESSION_STATE_UNVERIFIED" in verify["expected_postcondition"]
    assert RETIREMENT_EVIDENCE in [x["exact_digest"] for x in cleanup["required_evidence"]]
    assert cleanup["expected_postcondition"].count("future fresh approval") == 1
    assert set(plan["prohibited_actions"]) >= {
        "cleanup-v1.retry", "v31.retry", "v32.retry", "v33.prepare",
        "credential.create", "credential.rotate", "credential.copy",
        "credential.export", "credential.log", "credential.persist",
        "credential.digest", "service-role.use", "auth.sessions.delete-sql",
        "auth.refresh-tokens.delete-sql", "identity.create", "identity.delete",
        "identity.modify", "hook.modify", "tenant-metadata.modify", "password.set",
        "email.send", "additional.session.issue", "token.persist", "data.operation",
        "render.operation", "n8n.operation", "staging.target", "production.target",
        "phase6.begin",
    }
    assert all("cleanup-v1" not in s["step_id"] for s in plan["steps"])
    assert all("retry" not in s["operation"] for s in plan["steps"])
    assert plan["steps"][2]["execution_class"] == "PROVIDER_READ"
    assert "provider.mutation" in verify["prohibited_actions"]

    repair_progress_path = BASE / "development-auth-v32-synthetic-session-cleanup-credential-repair-v1.execution-progress.json"
    repair_progress = load(repair_progress_path)
    repair_plan = load(BASE / "development-auth-v32-synthetic-session-cleanup-credential-repair-v1.plan.json")
    repair_approval = load(BASE / "development-auth-v32-synthetic-session-cleanup-credential-repair-v1.approval.json")
    assert repair_plan["plan_id"] == REPAIR_PLAN_ID
    assert repair_plan["plan_digest"] == REPAIR_PLAN_DIGEST
    assert repair_progress["plan_digest"] == REPAIR_PLAN_DIGEST
    assert repair_progress["progress_digest"] == REPAIR_PROGRESS_DIGEST
    assert repair_progress["overall_state"] == "COMPLETED"
    assert all(
        (state["authorization_state"], state["execution_state"], state["verification_state"], state["authorization_consumed"])
        == ("CONSUMED", "SUCCEEDED", "PASS", True)
        for state in repair_progress["step_states"]
    )
    assert repair_approval["plan_id"] == REPAIR_PLAN_ID
    assert [raw_digest(BASE / f"development-auth-v32-synthetic-session-cleanup-credential-repair-v1-step{i}-success.evidence.json")
            for i in (1, 2, 3, 4)] == [
        REPAIR_STEP1_EVIDENCE, REPAIR_STEP2_EVIDENCE, REPAIR_STEP3_EVIDENCE, RETIREMENT_EVIDENCE,
    ]

    prior_cleanup = load(BASE / "development-auth-v32-synthetic-session-cleanup-v1.execution-progress.json")
    assert prior_cleanup["progress_digest"] == PRIOR_CLEANUP_V1_PROGRESS
    assert prior_cleanup["overall_state"] == "STOPPED"
    assert [
        (s["authorization_state"], s["execution_state"], s["verification_state"], s["authorization_consumed"])
        for s in prior_cleanup["step_states"]
    ] == [
        ("CONSUMED", "SUCCEEDED", "PASS", True),
        ("CONSUMED", "FAILED", "FAIL", True),
        ("BLOCKED", "NOT_STARTED", "NOT_STARTED", False),
    ]
    assert prior_cleanup["step_states"][1]["safe_error_code"] == "SESSION_CLEANUP_ADMIN_CREDENTIAL_UNAVAILABLE"

    assert progress == initial_progress(plan, SCHEMA_ROOT, PROGRESS_ID, CREATED_AT)
    assert progress["progress_digest"] == PROGRESS_DIGEST
    assert progress["overall_state"] == "NOT_STARTED"
    assert all(
        (s["authorization_state"], s["execution_state"], s["verification_state"],
         s["authorization_consumed"], s["evidence"], s["binding_assertions"])
        == ("PENDING", "NOT_STARTED", "NOT_STARTED", False, [], [])
        for s in progress["step_states"]
    )
    assert not APPROVAL_PATH.exists()
    assert not EXECUTION_PROGRESS_PATH.exists()
    assert not list(BASE.glob(EVIDENCE_GLOB))
    assert not EXECUTOR_PATH.exists()
    assert not WORKFLOW_PATH.exists()

    serialized = json.dumps({"plan": plan, "progress": progress}, sort_keys=True)
    assert DATA_PROJECT not in serialized
    assert ADMIN_REFERENCE in serialized
    assert PUBLISHABLE_REFERENCE in serialized
    assert SYNTHETIC_EMAIL in PRECHECK_SQL and SYNTHETIC_EMAIL in CLEANUP_CONTRACT["synthetic_identity"]
    assert "auth.refresh_tokens" not in PRECHECK_SQL
    assert "auth.users" in PRECHECK_SQL
    assert re.search(r"sb_secret_[A-Za-z0-9._-]{8,}", serialized) is None
    for field in ('"credential_value"', '"secret_value"', '"access_token"', '"refresh_token"', '"service_role_key"'):
        assert field not in serialized.lower()
    for prohibited in ("v31.retry", "v32.retry", "v33.prepare", "cleanup-v1.retry"):
        assert prohibited in plan["prohibited_actions"]
    print("DEVELOPMENT AUTH synthetic-session cleanup v2: PASS (three-step plan, exact external bindings, pristine/unapproved/unexecuted)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
