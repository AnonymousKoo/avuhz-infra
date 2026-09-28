#!/usr/bin/env python3
"""Exact repaired-recovery-lifecycle v2 Step 1 executor. One provider attempt; no retry or Step 2 readback."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from avuhz_engineering.authorization_plan import (
    AuthorizationPlanError,
    AuthorizationPlanStop,
    approval_digest,
    authorize_step,
    plan_digest,
    progress_digest,
    validate_approval,
    validate_plan,
    validate_progress,
)
from avuhz_engineering.development_auth_token_lifecycle import (
    IssuedSession,
    RecoveryVerificationCredential,
    SafeLifecycleStop,
    request_direct_recovery_verification,
    request_generate_recovery_credential,
    request_global_session_logout,
    validate_development_synthetic_access_jwt,
)
from avuhz_runtime.implementation_handoff import canonical_digest
from avuhz_service.development import DEVELOPMENT_AUTH_PROJECT_REF
from avuhz_service.development_supabase_identity import DEVELOPMENT_SYNTHETIC_READ_ONLY_ALLOWLIST

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
BASE = ROOT / "contracts/plans/v1"
BOUNDARY = "development-auth-repaired-recovery-lifecycle-v2"
PLAN_PATH = BASE / f"{BOUNDARY}.plan.json"
PRISTINE_PROGRESS_PATH = BASE / f"{BOUNDARY}.progress.json"
APPROVAL_PATH = BASE / f"{BOUNDARY}.approval.json"
EXECUTION_PROGRESS_PATH = BASE / f"{BOUNDARY}.execution-progress.json"
STEP1_EVIDENCE_PATTERN = f"{BOUNDARY}-step1-*.evidence.json"

PLAN_ID = "cdcda5de-5934-42f9-ba7c-e02eaa0d0fe6"
PLAN_VERSION = 2
PLAN_DIGEST = "sha256:7619a172fc3eca6a861567ebf9a0f6746d91c0ca6e69e348d5f4b07263cdeea3"
PRISTINE_PROGRESS_DIGEST = "sha256:9c98fe90a54233c42b88f4286789e26b24f945bd3d1770c125f594a71daaf3e6"
APPROVAL_ID = "8dd2aa60-91a4-4357-914e-638cf6320a59"
APPROVAL_DIGEST = "sha256:6154faa69e435d0ce9c03f6463a0709d014932e5794dbd5d0e988e0a94d7da62"
STEP1 = "development.auth.repaired-recovery-lifecycle-v2.step.01.recover-validate-and-logout-global"
STEP1_RESOURCE_DIGEST = "sha256:5fa2f2d6280c3daa858fe95c7d004397dc335f6da7a8782abe8d47f90d39c561"
STEP1_OPERATION = "provider.auth-session.recover-once-validate-and-logout-global"
CONFIRMATION = "RUN_REPAIRED_RECOVERY_LIFECYCLE_V2_STEP1"
PROJECT = "pwlhruwutoitnieactol"
WINDOW_START = "2026-09-28T16:30:00Z"
WINDOW_END = "2026-09-28T22:30:00Z"
TARGET_EMAIL = "avuhz-development-synthetic@example.invalid"
ADMIN_ENV = "AVUHZ_DEVELOPMENT_SUPABASE_AUTH_SESSION_CLEANUP_V2_EPHEMERAL"
PUBLISHABLE_ENV = "AVUHZ_DEVELOPMENT_SUPABASE_PUBLISHABLE_KEY"
CAPABILITY_BINDING_ID = "binding.development.auth.repaired-lifecycle-v2.admin-executor-capability"
CAPABILITY_EVIDENCE_TYPE = "auth.admin-executor-capability.observed"
LIFECYCLE_PATH = ROOT / "src/avuhz_engineering/development_auth_token_lifecycle.py"
LIFECYCLE_DIGEST = "sha256:5fa2f2d6280c3daa858fe95c7d004397dc335f6da7a8782abe8d47f90d39c561"
REBASELINE_EVIDENCE = "sha256:e2955c02b79f245f75a0affefd289376f005cdd165f724c02be88699744a5b43"
REBASELINE_PROGRESS = "sha256:68178521cb34199e2ab27fe7c48948df78e3846f0dba918f17b59ed920a51104"
V2_FAILURE_EVIDENCE = "sha256:8344c3e26c26f464bcefa880251ac7619bfc6087a8a17e9c0987db4a843191eb"
V2_STOPPED_PROGRESS = "sha256:a942c1fa84f32e96619f916c1686ccb8d8ec1a6f3dd7393a0fa6cc992f167468"
REPAIR_PROGRESS = "sha256:6d4e4d5473a50790e1c6db4df50e4428fda37dc9988b4bf44ddb145955b6e2f9"
REPAIR_EVIDENCE_DIGESTS = (
    "sha256:29fa0e715118b6cb70d6c08b28466b79407319bc5177947851b87b86c10dc47d",
    "sha256:de7daf8b0c913f713225d292adae404bc877b298368c9fbedc5e451f6190e574",
    "sha256:a431c44cac5069898b98784c82244f3b9335f124ee348666da0bb83894f3fce9",
    "sha256:38ebcc897696f11284c540994c4a6144f08530ad8c4ec7e42c84a64f01559b8f",
)
V3_PLAN_DIGEST = "sha256:7621cb349e26c106fba7941f82088c669ddb0512bfd6a3c6a2bcb16c5fcc04b8"
V3_PROGRESS_DIGEST = "sha256:cf4b76e32638bb92ab188ef511ed48632720fd060073be735797b6852bbba40d"

SAFE_ERROR_CODES = {
    "ACCESS_JWT_VALIDATION_FAILED", "APPROVAL_BINDING_MISMATCH", "APPROVAL_DIGEST_INVALID",
    "APPROVAL_NOT_ACTIVE", "AUTHORIZATION_WINDOW_INVALID", "BINDING_ASSERTION_MISMATCH",
    "CREDENTIAL_CLASS_NOT_ALLOWED", "EVIDENCE_MISSING", "GLOBAL_SESSION_LOGOUT_PROVIDER_REJECTED",
    "GLOBAL_SESSION_LOGOUT_REQUEST_FAILED", "GLOBAL_SESSION_LOGOUT_RESPONSE_INVALID",
    "PLAN_AUTHORIZATION_EXPIRED", "PLAN_DIGEST_INVALID", "PLAN_NOT_CONTINUABLE",
    "PREFLIGHT_BINDING_MISMATCH", "PREFLIGHT_DRIFT", "RECOVERY_CREDENTIAL_UNAVAILABLE",
    "RECOVERY_GENERATE_IDENTITY_MISMATCH", "RECOVERY_GENERATE_PROVIDER_REJECTED",
    "RECOVERY_GENERATE_REQUEST_FAILED", "RECOVERY_GENERATE_RESPONSE_INVALID",
    "RECOVERY_GENERATE_RESPONSE_SHAPE_INVALID", "RECOVERY_VERIFICATION_PROVIDER_REJECTED",
    "RECOVERY_VERIFICATION_REQUEST_FAILED", "RECOVERY_VERIFICATION_RESPONSE_INVALID",
    "RECOVERY_VERIFICATION_RESPONSE_SHAPE_INVALID", "REQUIRED_EVIDENCE_MISMATCH",
    "STEP_REPLAY_PROHIBITED", "REPAIRED_LIFECYCLE_V2_ADMIN_CREDENTIAL_UNAVAILABLE",
    "REPAIRED_LIFECYCLE_V2_AUTHORITY_INVALID", "REPAIRED_LIFECYCLE_V2_CONFIRMATION_MISMATCH",
    "REPAIRED_LIFECYCLE_V2_EVIDENCE_BINDING_MISMATCH", "REPAIRED_LIFECYCLE_V2_PROJECT_MISMATCH",
    "REPAIRED_LIFECYCLE_V2_PUBLISHABLE_CONFIG_UNAVAILABLE", "REPAIRED_LIFECYCLE_V2_STEP1_ALREADY_ATTEMPTED",
    "REPAIRED_LIFECYCLE_V2_UNEXPECTED_FAILURE", "REPAIRED_LIFECYCLE_V2_WORKFLOW_BINDING_MISMATCH",
}


def _load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        raise AuthorizationPlanStop("REPAIRED_LIFECYCLE_V2_AUTHORITY_INVALID") from None
    if not isinstance(value, dict):
        raise AuthorizationPlanStop("REPAIRED_LIFECYCLE_V2_AUTHORITY_INVALID")
    return value


def _raw_digest(path: Path) -> str:
    try:
        return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    except Exception:
        raise AuthorizationPlanStop("REPAIRED_LIFECYCLE_V2_AUTHORITY_INVALID") from None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _assert_evidence_bindings() -> None:
    predicate = _load(BASE / "development-auth-recovery-verification-predicate-diagnostic-v4.progress.json")
    cleanup_v4 = _load(BASE / "development-auth-v32-synthetic-session-cleanup-v4.execution-progress.json")
    failure = BASE / "development-auth-v32-synthetic-session-cleanup-v4-step1-failure.evidence.json"
    if (
        predicate.get("progress_digest") != "sha256:c05233df4d594db8110652de7e64ad8281daf76494758e64fec7f124e5fcce7f"
        or progress_digest(predicate) != predicate.get("progress_digest")
        or cleanup_v4.get("progress_digest") != "sha256:6a4a98913c7d7c0490fcc1c03f6b5a8b599ad29c1c2c7284ef58145128cbdb41"
        or progress_digest(cleanup_v4) != cleanup_v4.get("progress_digest")
        or _raw_digest(failure) != "sha256:60f2bc12d01f788a32dfef1ff274172ffe3148dfd23c0b903f9a1fb52a88d50d"
    ):
        raise AuthorizationPlanStop("REPAIRED_LIFECYCLE_V2_EVIDENCE_BINDING_MISMATCH")


def _capability_assertion(moment: str) -> dict[str, Any]:
    config = {
        "executor_reference": "github-actions.development-auth-repaired-recovery-lifecycle-v2-step1",
        "environment": "development",
        "project_reference": PROJECT,
        "step_id": STEP1,
        "operation": STEP1_OPERATION,
        "credential_class": "SUPABASE_AUTH_ADMIN_EPHEMERAL",
        "admin_binding_name": ADMIN_ENV,
        "publishable_binding_name": PUBLISHABLE_ENV,
        "executor_source_digest": _raw_digest(Path(__file__)),
    }
    config_digest = canonical_digest(config)
    evidence = {
        "evidence_type": CAPABILITY_EVIDENCE_TYPE,
        "environment": "DEVELOPMENT",
        "provider_reference": "supabase",
        "project_reference": PROJECT,
        "responsibility": "AUTH",
        "plan_id": PLAN_ID,
        "step_id": STEP1,
        "configuration_digest": config_digest,
        "credential_material_observed": False,
        "provider_contact_attempted": False,
    }
    return {
        "binding_id": CAPABILITY_BINDING_ID,
        "phase": "RESOLVED_BY_STEP_PREFLIGHT",
        "value_class": "CONFIGURATION_REFERENCE",
        "source_step_id": None,
        "evidence_type": CAPABILITY_EVIDENCE_TYPE,
        "evidence_digest": canonical_digest(evidence),
        "digest_policy": "REQUIRED",
        "persistence_policy": "DIGEST_ONLY",
        "sanitized_value": None,
        "value_digest": config_digest,
        "recorded_at": moment,
    }


def _request_for(plan: dict[str, Any]) -> dict[str, Any]:
    step = plan["steps"][0]
    return {
        "plan_id": plan["plan_id"],
        "plan_version": plan["plan_version"],
        "plan_digest": plan["plan_digest"],
        "environment": plan["environment"],
        "provider_reference": plan["target"]["provider_reference"],
        "project_reference": plan["target"]["project_reference"],
        "responsibility": plan["target"]["responsibility"],
        "issuer_reference": plan["target"]["issuer_reference"],
        "audience_reference": plan["target"]["audience_reference"],
        "step_id": STEP1,
        "resource_reference": step["resource"]["resource_reference"],
        "resource_version": step["resource"]["exact_version"],
        "resource_digest": step["resource"]["exact_digest"],
        "operation": step["operation"],
        "execution_class": "PROVIDER_MUTATION",
        "credential_class": "SUPABASE_AUTH_ADMIN_EPHEMERAL",
        "required_evidence": [
            {"evidence_type": item["evidence_type"], "evidence_digest": item["exact_digest"]}
            for item in step["required_evidence"]
        ],
        "prior_evidence_digests": [],
        "unexpected_remote_state": False,
        "extra_privileges": False,
        "unauthorized_migration_surface": False,
        "scope_expansion": False,
    }


def _validate_invocation(env: Mapping[str, str]) -> None:
    if env.get("GITHUB_REF") != "refs/heads/main" or env.get("GITHUB_RUN_NUMBER") != "1" or env.get("GITHUB_RUN_ATTEMPT") != "1":
        raise AuthorizationPlanStop("REPAIRED_LIFECYCLE_V2_WORKFLOW_BINDING_MISMATCH")
    if env.get("AVUHZ_CLEANUP_CONFIRMATION") != CONFIRMATION:
        raise AuthorizationPlanStop("REPAIRED_LIFECYCLE_V2_CONFIRMATION_MISMATCH")
    if env.get("AVUHZ_EXPECTED_PROJECT_REF") != PROJECT or DEVELOPMENT_AUTH_PROJECT_REF != PROJECT:
        raise AuthorizationPlanStop("REPAIRED_LIFECYCLE_V2_PROJECT_MISMATCH")
    if (
        env.get("AVUHZ_PLAN_ID") != PLAN_ID
        or env.get("AVUHZ_PLAN_DIGEST") != PLAN_DIGEST
        or env.get("AVUHZ_APPROVAL_ID") != APPROVAL_ID
        or env.get("AVUHZ_APPROVAL_DIGEST") != APPROVAL_DIGEST
        or env.get("AVUHZ_WINDOW_START") != WINDOW_START
        or env.get("AVUHZ_WINDOW_END") != WINDOW_END
    ):
        raise AuthorizationPlanStop("REPAIRED_LIFECYCLE_V2_WORKFLOW_BINDING_MISMATCH")


def _load_and_authorize(moment: str) -> dict[str, Any]:
    try:
        plan = _load(PLAN_PATH)
        pristine = _load(PRISTINE_PROGRESS_PATH)
        approval = _load(APPROVAL_PATH)
        validate_plan(plan, SCHEMA_ROOT)
        validate_progress(plan, pristine, SCHEMA_ROOT)
        validate_approval(plan, approval, SCHEMA_ROOT, moment)
    except (AuthorizationPlanError, AuthorizationPlanStop):
        raise AuthorizationPlanStop("REPAIRED_LIFECYCLE_V2_AUTHORITY_INVALID") from None

    if (
        plan.get("plan_id") != PLAN_ID
        or plan.get("plan_version") != PLAN_VERSION
        or plan.get("plan_digest") != PLAN_DIGEST
        or plan_digest(plan) != PLAN_DIGEST
        or plan.get("environment") != "DEVELOPMENT"
        or plan.get("target", {}).get("responsibility") != "AUTH"
        or plan.get("target", {}).get("project_reference") != PROJECT
        or plan.get("authorization_window") != {"binding_state": "BOUND", "starts_at": WINDOW_START, "expires_at": WINDOW_END}
        or pristine.get("progress_digest") != PRISTINE_PROGRESS_DIGEST
        or progress_digest(pristine) != PRISTINE_PROGRESS_DIGEST
        or pristine.get("overall_state") != "NOT_STARTED"
        or approval.get("approval_id") != APPROVAL_ID
        or approval.get("approval_digest") != APPROVAL_DIGEST
        or approval_digest(approval) != APPROVAL_DIGEST
        or approval.get("authority_scope") != "EXACT_PLAN_ONLY"
        or _raw_digest(LIFECYCLE_PATH) != LIFECYCLE_DIGEST
        or len(plan.get("steps", [])) != 2
        or plan.get("ordered_step_ids", [None])[0] != STEP1
    ):
        raise AuthorizationPlanStop("REPAIRED_LIFECYCLE_V2_AUTHORITY_INVALID")

    step = plan["steps"][0]
    resource = step["resource"]
    if (
        step.get("step_id") != STEP1
        or step.get("operation") != STEP1_OPERATION
        or step.get("execution_class") != "PROVIDER_MUTATION"
        or step.get("credential_policy", {}).get("allowed_classes") != ["SUPABASE_AUTH_ADMIN_EPHEMERAL"]
        or resource.get("resource_type") != "auth.synthetic-recovery-lifecycle-validation"
        or resource.get("resource_reference") != "supabase:pwlhruwutoitnieactol:repaired-recovery-lifecycle-validation"
        or resource.get("exact_version") != "repaired-lifecycle.v1"
        or resource.get("exact_digest") != STEP1_RESOURCE_DIGEST
        or "cleanup-v4.retry" not in step.get("prohibited_actions", [])
    ):
        raise AuthorizationPlanStop("REPAIRED_LIFECYCLE_V2_AUTHORITY_INVALID")

    first, second = pristine["step_states"]
    if (
        (first["authorization_state"], first["execution_state"], first["verification_state"], first["authorization_consumed"])
        != ("PENDING", "NOT_STARTED", "NOT_STARTED", False)
        or (second["authorization_state"], second["execution_state"], second["verification_state"], second["authorization_consumed"])
        != ("PENDING", "NOT_STARTED", "NOT_STARTED", False)
        or first["evidence"] or second["evidence"] or first["binding_assertions"] or second["binding_assertions"]
        or EXECUTION_PROGRESS_PATH.exists()
        or list(BASE.glob(STEP1_EVIDENCE_PATTERN))
    ):
        raise AuthorizationPlanStop("REPAIRED_LIFECYCLE_V2_STEP1_ALREADY_ATTEMPTED")

    _assert_evidence_bindings()
    authorized = authorize_step(
        plan,
        approval,
        pristine,
        _request_for(plan),
        SCHEMA_ROOT,
        moment,
        trusted_preflight_assertions=[_capability_assertion(moment)],
    )
    state = authorized["step_states"][0]
    if state["authorization_state"] != "AUTHORIZED" or state["execution_state"] != "NOT_STARTED" or state["authorization_consumed"] or state["evidence"]:
        raise AuthorizationPlanStop("REPAIRED_LIFECYCLE_V2_AUTHORITY_INVALID")
    return authorized


def execute_cleanup(
    *,
    admin_secret: str,
    publishable_key: str,
    generate: Callable[..., RecoveryVerificationCredential] = request_generate_recovery_credential,
    verify: Callable[..., IssuedSession] = request_direct_recovery_verification,
    validate_jwt: Callable[[str], Any] = validate_development_synthetic_access_jwt,
    logout_global: Callable[..., None] = request_global_session_logout,
) -> dict[str, Any]:
    credential: RecoveryVerificationCredential | None = None
    session: IssuedSession | None = None
    try:
        credential = generate(
            project_ref=PROJECT,
            admin_secret=admin_secret,
            existing_user_email=TARGET_EMAIL,
            expected_user_id=None,
            expected_subject_digest=DEVELOPMENT_SYNTHETIC_READ_ONLY_ALLOWLIST[0].subject_digest,
        )
        session = verify(
            project_ref=PROJECT,
            publishable_key=publishable_key,
            credential=credential,
            expected_user_id=None,
        )
        validate_jwt(session._access_text())
        logout_global(project_ref=PROJECT, publishable_key=publishable_key, bearer_token=session._access_text())
        return {
            "classification": "SESSION_REVOCATION_REQUEST_ACCEPTED",
            "temporary_session_issued": True,
            "temporary_session_count": 1,
            "jwt_validated_before_logout": True,
            "global_logout_attempted": True,
            "global_logout_accepted": True,
            "cleanup_verified": False,
            "step2_readback_required": True,
            "retry_authorized": False,
            "credential_material_retained": False,
            "pii_retained": False,
            "provider_mutation_attempted": True,
        }
    finally:
        if credential is not None:
            credential.clear()
        if session is not None:
            session.clear()
            session.user_id = ""


def _safe_failure(code: str, *, provider_mutation_attempted: bool) -> int:
    safe_code = code if code in SAFE_ERROR_CODES else "REPAIRED_LIFECYCLE_V2_UNEXPECTED_FAILURE"
    print(json.dumps({
        "classification": "SESSION_STATE_UNVERIFIED",
        "safe_error_code": safe_code,
        "cleanup_verified": False,
        "step2_readback_required": True,
        "retry_authorized": False,
        "credential_material_retained": False,
        "pii_retained": False,
        "provider_mutation_attempted": provider_mutation_attempted,
    }, sort_keys=True))
    return 1


def main(environment: Mapping[str, str] | None = None, *, preflight_only: bool = False) -> int:
    env = os.environ if environment is None else environment
    admin_secret: str | None = None
    publishable_key: str | None = None
    provider_mutation_attempted = False
    try:
        _validate_invocation(env)
        _load_and_authorize(_now())
        if preflight_only:
            print(json.dumps({"preflight": "PASS", "step_id": STEP1}, sort_keys=True))
            return 0

        admin_secret = env.get(ADMIN_ENV)
        publishable_key = env.get(PUBLISHABLE_ENV)
        if not isinstance(admin_secret, str) or not admin_secret.startswith("sb_secret_") or len(admin_secret) < len("sb_secret_") + 16:
            raise AuthorizationPlanStop("REPAIRED_LIFECYCLE_V2_ADMIN_CREDENTIAL_UNAVAILABLE")
        if not isinstance(publishable_key, str) or not publishable_key.startswith("sb_publishable_") or len(publishable_key) < len("sb_publishable_") + 16:
            raise AuthorizationPlanStop("REPAIRED_LIFECYCLE_V2_PUBLISHABLE_CONFIG_UNAVAILABLE")

        provider_mutation_attempted = True
        print(json.dumps(execute_cleanup(admin_secret=admin_secret, publishable_key=publishable_key), sort_keys=True))
        return 0
    except (AuthorizationPlanError, AuthorizationPlanStop) as exc:
        code = str(exc)
        if code not in SAFE_ERROR_CODES:
            code = "REPAIRED_LIFECYCLE_V2_AUTHORITY_INVALID"
        return _safe_failure(code, provider_mutation_attempted=provider_mutation_attempted)
    except SafeLifecycleStop as exc:
        return _safe_failure(exc.code, provider_mutation_attempted=provider_mutation_attempted)
    except Exception:
        return _safe_failure("REPAIRED_LIFECYCLE_V2_UNEXPECTED_FAILURE", provider_mutation_attempted=provider_mutation_attempted)
    finally:
        admin_secret = None
        publishable_key = None


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--preflight-only", action="store_true")
    args = parser.parse_args()
    raise SystemExit(main(preflight_only=args.preflight_only))
