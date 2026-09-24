#!/usr/bin/env python3
"""Dormant cleanup-v2 Step 2 executor; preparation does not invoke it."""
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
from avuhz_service.development_supabase_identity import (
    DEVELOPMENT_SYNTHETIC_READ_ONLY_ALLOWLIST,
)


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
BASE = ROOT / "contracts/plans/v1"
BOUNDARY = "development-auth-v32-synthetic-session-cleanup-v2"
PLAN_PATH = BASE / f"{BOUNDARY}.plan.json"
PRISTINE_PROGRESS_PATH = BASE / f"{BOUNDARY}.progress.json"
APPROVAL_PATH = BASE / f"{BOUNDARY}.approval.json"
EXECUTION_PROGRESS_PATH = BASE / f"{BOUNDARY}.execution-progress.json"
STEP1_EVIDENCE_PATH = BASE / f"{BOUNDARY}-step1-success.evidence.json"
STEP1_EVIDENCE_PATTERN = f"{BOUNDARY}-step1-*.evidence.json"
STEP2_EVIDENCE_PATTERN = f"{BOUNDARY}-step2-*.evidence.json"

PLAN_ID = "55b1ac96-b338-4821-bcb3-02f4ab1a0958"
PLAN_VERSION = 2
PLAN_DIGEST = "sha256:4afea8848bc07967d93be6905b142d6d6c995cd43f204a610c439c0efee50df3"
PRISTINE_PROGRESS_DIGEST = "sha256:eba7fe63e59cda2b30d074eedbd2455c69a182d5ee7d1824aa212c9065d57caa"
STEP1 = "development.auth.v32-synthetic-session-cleanup-v2.step.01.verify-current-attributed-session-precondition"
STEP2 = "development.auth.v32-synthetic-session-cleanup-v2.step.02.revoke-synthetic-sessions-global"
STEP3 = "development.auth.v32-synthetic-session-cleanup-v2.step.03.verify-zero-session-refresh-state"
STEP2_RESOURCE_DIGEST = "sha256:3e493f690ac86f2e2fdfcbdfba56761ab82acdda20459f17fcd9d0dd1fea3a18"
STEP2_OPERATION = "provider.auth-session.recover-once-validate-and-logout-global"
CONFIRMATION = "REVOKE_V32_SYNTHETIC_SESSIONS_GLOBAL_V2"
PROJECT = "pwlhruwutoitnieactol"
WINDOW_START = "2026-09-25T15:00:00Z"
WINDOW_END = "2026-09-25T21:00:00Z"
TARGET_EMAIL = "avuhz-development-synthetic@example.invalid"
ADMIN_ENV = "AVUHZ_DEVELOPMENT_SUPABASE_AUTH_SESSION_CLEANUP_V2_EPHEMERAL"
PUBLISHABLE_ENV = "AVUHZ_DEVELOPMENT_SUPABASE_PUBLISHABLE_KEY"
CAPABILITY_BINDING_ID = "binding.development.auth.cleanup-v2.admin-executor-capability"
CAPABILITY_EVIDENCE_TYPE = "auth.admin-executor-capability.observed"
STEP1_EVIDENCE_TYPE = "auth.synthetic-session.precleanup-attribution.verified"
LIFECYCLE_PATH = ROOT / "src/avuhz_engineering/development_auth_token_lifecycle.py"
LIFECYCLE_DIGEST = "sha256:55503f13489944b0b4b51e3dc24875d5c6e83c69e8fc6a8aed6a03fdb0736749"

REPAIR_BOUNDARY = "development-auth-v32-synthetic-session-cleanup-credential-repair-v1"
REPAIR_PLAN_ID = "0224c4fb-845c-4627-b48f-252ec954283c"
REPAIR_PLAN_DIGEST = "sha256:57b26eefa9ca294a4dff95d617a50c3e46d0cdaab1cf1862c1d1239d042babcb"
REPAIR_PROGRESS_DIGEST = "sha256:6d4e4d5473a50790e1c6db4df50e4428fda37dc9988b4bf44ddb145955b6e2f9"
REPAIR_EVIDENCE_DIGESTS = (
    "sha256:29fa0e715118b6cb70d6c08b28466b79407319bc5177947851b87b86c10dc47d",
    "sha256:de7daf8b0c913f713225d292adae404bc877b298368c9fbedc5e451f6190e574",
    "sha256:a431c44cac5069898b98784c82244f3b9335f124ee348666da0bb83894f3fce9",
    "sha256:38ebcc897696f11284c540994c4a6144f08530ad8c4ec7e42c84a64f01559b8f",
)
REPAIR_APPROVAL_ID = "f0b629ae-22c4-4e6f-bcf9-ac563761cd65"
REPAIR_APPROVAL_DIGEST = "sha256:a15a0e53e35a8aea7a6cf7bb6fe766ecba67777c7b702148c3dbc92dba63eb33"
RETIREMENT_EVIDENCE_TYPE = "auth.cleanup-admin-retirement.required"

SAFE_ERROR_CODES = {
    "APPROVAL_BINDING_MISMATCH", "APPROVAL_DIGEST_INVALID", "APPROVAL_NOT_ACTIVE",
    "AUTHORIZATION_WINDOW_INVALID", "BINDING_ASSERTION_MISMATCH",
    "CREDENTIAL_CLASS_NOT_ALLOWED", "EVIDENCE_MISSING", "PLAN_AUTHORIZATION_EXPIRED",
    "PLAN_DIGEST_INVALID", "PLAN_NOT_CONTINUABLE", "PREFLIGHT_BINDING_MISMATCH",
    "PREFLIGHT_DRIFT", "REQUIRED_EVIDENCE_MISMATCH", "STEP_REPLAY_PROHIBITED",
    "ACCESS_JWT_VALIDATION_FAILED", "GLOBAL_SESSION_LOGOUT_PROVIDER_REJECTED",
    "GLOBAL_SESSION_LOGOUT_REQUEST_FAILED", "GLOBAL_SESSION_LOGOUT_RESPONSE_INVALID",
    "RECOVERY_CREDENTIAL_UNAVAILABLE", "RECOVERY_GENERATE_IDENTITY_MISMATCH",
    "RECOVERY_GENERATE_PROVIDER_REJECTED", "RECOVERY_GENERATE_REQUEST_FAILED",
    "RECOVERY_GENERATE_RESPONSE_INVALID", "RECOVERY_GENERATE_RESPONSE_SHAPE_INVALID",
    "RECOVERY_VERIFICATION_PROVIDER_REJECTED", "RECOVERY_VERIFICATION_REQUEST_FAILED",
    "RECOVERY_VERIFICATION_RESPONSE_INVALID", "RECOVERY_VERIFICATION_RESPONSE_SHAPE_INVALID",
    "SESSION_CLEANUP_V2_ADMIN_CREDENTIAL_UNAVAILABLE",
    "SESSION_CLEANUP_V2_AUTHORITY_INVALID",
    "SESSION_CLEANUP_V2_CONFIRMATION_MISMATCH",
    "SESSION_CLEANUP_V2_CREDENTIAL_REPAIR_BINDING_MISMATCH",
    "SESSION_CLEANUP_V2_EXECUTION_PROGRESS_INVALID",
    "SESSION_CLEANUP_V2_PROJECT_MISMATCH",
    "SESSION_CLEANUP_V2_PUBLISHABLE_CONFIG_UNAVAILABLE",
    "SESSION_CLEANUP_V2_STEP1_EVIDENCE_INVALID",
    "SESSION_CLEANUP_V2_STEP2_ALREADY_ATTEMPTED",
    "SESSION_CLEANUP_V2_UNEXPECTED_FAILURE",
    "SESSION_CLEANUP_V2_WORKFLOW_BINDING_MISMATCH",
}


def _load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        raise AuthorizationPlanStop("SESSION_CLEANUP_V2_AUTHORITY_INVALID") from None
    if not isinstance(value, dict):
        raise AuthorizationPlanStop("SESSION_CLEANUP_V2_AUTHORITY_INVALID")
    return value


def _raw_digest(path: Path) -> str:
    try:
        return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    except Exception:
        raise AuthorizationPlanStop("SESSION_CLEANUP_V2_AUTHORITY_INVALID") from None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _assert_repair_bindings() -> None:
    repair_plan = _load(BASE / f"{REPAIR_BOUNDARY}.plan.json")
    repair_approval = _load(BASE / f"{REPAIR_BOUNDARY}.approval.json")
    repair_progress = _load(BASE / f"{REPAIR_BOUNDARY}.execution-progress.json")
    try:
        validate_plan(repair_plan, SCHEMA_ROOT)
        validate_progress(repair_plan, repair_progress, SCHEMA_ROOT)
    except (AuthorizationPlanError, AuthorizationPlanStop):
        raise AuthorizationPlanStop("SESSION_CLEANUP_V2_CREDENTIAL_REPAIR_BINDING_MISMATCH") from None
    if (
        repair_plan["plan_id"] != REPAIR_PLAN_ID
        or repair_plan["plan_digest"] != REPAIR_PLAN_DIGEST
        or repair_progress["plan_digest"] != REPAIR_PLAN_DIGEST
        or repair_progress["progress_digest"] != REPAIR_PROGRESS_DIGEST
        or progress_digest(repair_progress) != REPAIR_PROGRESS_DIGEST
        or repair_progress["overall_state"] != "COMPLETED"
        or repair_approval.get("approval_id") != REPAIR_APPROVAL_ID
        or repair_approval.get("approval_digest") != REPAIR_APPROVAL_DIGEST
        or approval_digest(repair_approval) != REPAIR_APPROVAL_DIGEST
        or repair_approval.get("plan_id") != REPAIR_PLAN_ID
        or repair_approval.get("plan_digest") != REPAIR_PLAN_DIGEST
    ):
        raise AuthorizationPlanStop("SESSION_CLEANUP_V2_CREDENTIAL_REPAIR_BINDING_MISMATCH")
    if any(
        (
            state["authorization_state"], state["execution_state"],
            state["verification_state"], state["authorization_consumed"],
        ) != ("CONSUMED", "SUCCEEDED", "PASS", True)
        for state in repair_progress["step_states"]
    ) or len(repair_progress["step_states"]) != 4:
        raise AuthorizationPlanStop("SESSION_CLEANUP_V2_CREDENTIAL_REPAIR_BINDING_MISMATCH")

    evidence_paths = [
        BASE / f"{REPAIR_BOUNDARY}-step{i}-success.evidence.json"
        for i in range(1, 5)
    ]
    expected_types = [
        "auth.cleanup-admin-credential.created",
        "auth.cleanup-admin-github-binding.created",
        "auth.cleanup-admin-github-binding.verified",
        RETIREMENT_EVIDENCE_TYPE,
    ]
    expected_classes = [
        "DEDICATED_CLEANUP_CREDENTIAL_CREATED",
        "CLEANUP_CREDENTIAL_BINDING_CREATED",
        "CLEANUP_CREDENTIAL_BINDING_PRESENT",
        "CLEANUP_CREDENTIAL_RETIREMENT_REQUIRED",
    ]
    for path, expected_digest, evidence_type, classification in zip(
        evidence_paths, REPAIR_EVIDENCE_DIGESTS, expected_types, expected_classes, strict=True
    ):
        evidence = _load(path)
        if (
            _raw_digest(path) != expected_digest
            or evidence.get("evidence_type") != evidence_type
            or evidence.get("classification") != classification
        ):
            raise AuthorizationPlanStop("SESSION_CLEANUP_V2_CREDENTIAL_REPAIR_BINDING_MISMATCH")
    retirement = _load(evidence_paths[3])
    retirement_result = retirement.get("sanitized_result")
    if (
        not isinstance(retirement_result, dict)
        or retirement_result.get("fresh_exact_retirement_approval_required") is not True
        or retirement_result.get("retirement_performed") is not False
        or retirement_result.get("provider_contact_attempted") is not False
        or retirement_result.get("credential_material_accessed") is not False
    ):
        raise AuthorizationPlanStop("SESSION_CLEANUP_V2_CREDENTIAL_REPAIR_BINDING_MISMATCH")


def _validate_step1_evidence(evidence: dict[str, Any], expected_digest: str) -> None:
    expected = {
        "evidence_type": STEP1_EVIDENCE_TYPE,
        "environment": "DEVELOPMENT",
        "responsibility": "AUTH",
        "project_reference": PROJECT,
        "plan_id": PLAN_ID,
        "plan_digest": PLAN_DIGEST,
        "step_id": STEP1,
        "outcome": "SUCCEEDED_VERIFIED",
        "classification": "PRE_CLEANUP_SYNTHETIC_SESSION_CONFIRMED",
        "sanitized_result": {"session_count": 1, "synthetic_session_count": 1},
        "provider_mutation_attempted": False,
        "credential_material_retained": False,
        "pii_retained": False,
    }
    if any(evidence.get(key) != value for key, value in expected.items()):
        raise AuthorizationPlanStop("SESSION_CLEANUP_V2_STEP1_EVIDENCE_INVALID")
    if _raw_digest(STEP1_EVIDENCE_PATH) != expected_digest:
        raise AuthorizationPlanStop("SESSION_CLEANUP_V2_STEP1_EVIDENCE_INVALID")


def _capability_assertion(moment: str) -> dict[str, Any]:
    config = {
        "executor_reference": "github-actions.development-auth-v32-synthetic-session-cleanup-v2",
        "environment": "development",
        "project_reference": PROJECT,
        "step_id": STEP2,
        "operation": STEP2_OPERATION,
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
        "step_id": STEP2,
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


def _request_for(plan: dict[str, Any], progress: dict[str, Any]) -> dict[str, Any]:
    step = plan["steps"][1]
    requirements = []
    for requirement in step["required_evidence"]:
        if requirement["source_step_id"] is None:
            digest = requirement["exact_digest"]
        else:
            source_index = plan["ordered_step_ids"].index(requirement["source_step_id"])
            matches = [
                item for item in progress["step_states"][source_index]["evidence"]
                if item["evidence_type"] == requirement["evidence_type"]
            ]
            if len(matches) != 1:
                raise AuthorizationPlanStop("REQUIRED_EVIDENCE_MISMATCH")
            digest = matches[0]["evidence_digest"]
        requirements.append({
            "evidence_type": requirement["evidence_type"],
            "evidence_digest": digest,
        })
    first_step_evidence = progress["step_states"][0]["evidence"]
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
        "step_id": STEP2,
        "resource_reference": step["resource"]["resource_reference"],
        "resource_version": step["resource"]["exact_version"],
        "resource_digest": step["resource"]["exact_digest"],
        "operation": step["operation"],
        "execution_class": "PROVIDER_MUTATION",
        "credential_class": "SUPABASE_AUTH_ADMIN_EPHEMERAL",
        "required_evidence": requirements,
        "prior_evidence_digests": [item["evidence_digest"] for item in first_step_evidence],
        "unexpected_remote_state": False,
        "extra_privileges": False,
        "unauthorized_migration_surface": False,
        "scope_expansion": False,
    }


def _validate_invocation(env: Mapping[str, str]) -> None:
    if (
        env.get("GITHUB_REF") != "refs/heads/main"
        or env.get("GITHUB_RUN_NUMBER") != "1"
        or env.get("GITHUB_RUN_ATTEMPT") != "1"
    ):
        raise AuthorizationPlanStop("SESSION_CLEANUP_V2_WORKFLOW_BINDING_MISMATCH")
    if env.get("AVUHZ_CLEANUP_CONFIRMATION") != CONFIRMATION:
        raise AuthorizationPlanStop("SESSION_CLEANUP_V2_CONFIRMATION_MISMATCH")
    if (
        env.get("AVUHZ_EXPECTED_PROJECT_REF") != PROJECT
        or DEVELOPMENT_AUTH_PROJECT_REF != PROJECT
    ):
        raise AuthorizationPlanStop("SESSION_CLEANUP_V2_PROJECT_MISMATCH")
    if (
        env.get("AVUHZ_PLAN_ID") != PLAN_ID
        or env.get("AVUHZ_PLAN_DIGEST") != PLAN_DIGEST
        or env.get("AVUHZ_WINDOW_START") != WINDOW_START
        or env.get("AVUHZ_WINDOW_END") != WINDOW_END
    ):
        raise AuthorizationPlanStop("SESSION_CLEANUP_V2_WORKFLOW_BINDING_MISMATCH")


def _load_and_authorize(moment: str) -> dict[str, Any]:
    try:
        plan = _load(PLAN_PATH)
        pristine = _load(PRISTINE_PROGRESS_PATH)
        approval = _load(APPROVAL_PATH)
        progress = _load(EXECUTION_PROGRESS_PATH)
        step1_evidence = _load(STEP1_EVIDENCE_PATH)
        validate_plan(plan, SCHEMA_ROOT)
        validate_progress(plan, pristine, SCHEMA_ROOT)
        validate_progress(plan, progress, SCHEMA_ROOT)
        validate_approval(plan, approval, SCHEMA_ROOT, moment)
    except (AuthorizationPlanError, AuthorizationPlanStop):
        raise AuthorizationPlanStop("SESSION_CLEANUP_V2_AUTHORITY_INVALID") from None

    if (
        plan["plan_id"] != PLAN_ID
        or plan["plan_version"] != PLAN_VERSION
        or plan["plan_digest"] != PLAN_DIGEST
        or plan_digest(plan) != PLAN_DIGEST
        or plan["environment"] != "DEVELOPMENT"
        or plan["target"]["responsibility"] != "AUTH"
        or plan["target"]["project_reference"] != PROJECT
        or plan["authorization_window"] != {
            "binding_state": "BOUND", "starts_at": WINDOW_START, "expires_at": WINDOW_END,
        }
        or pristine["progress_digest"] != PRISTINE_PROGRESS_DIGEST
        or pristine["overall_state"] != "NOT_STARTED"
        or pristine["plan_digest"] != PLAN_DIGEST
        or progress["plan_id"] != PLAN_ID
        or progress["plan_digest"] != PLAN_DIGEST
        or progress_digest(progress) != progress["progress_digest"]
        or _raw_digest(LIFECYCLE_PATH) != LIFECYCLE_DIGEST
        or plan["ordered_step_ids"] != [STEP1, STEP2, STEP3]
        or len(plan["steps"]) != 3
    ):
        raise AuthorizationPlanStop("SESSION_CLEANUP_V2_AUTHORITY_INVALID")

    cleanup_step = plan["steps"][1]
    cleanup_resource = cleanup_step["resource"]
    if (
        cleanup_step["step_id"] != STEP2
        or cleanup_step["operation"] != STEP2_OPERATION
        or cleanup_step["execution_class"] != "PROVIDER_MUTATION"
        or cleanup_step["credential_policy"]["allowed_classes"] != ["SUPABASE_AUTH_ADMIN_EPHEMERAL"]
        or cleanup_resource["resource_type"] != "auth.synthetic-session-provider-native-cleanup"
        or cleanup_resource["resource_reference"] != "supabase:pwlhruwutoitnieactol:synthetic-session-global-logout"
        or cleanup_resource["exact_version"] != "cleanup.v2"
        or cleanup_resource["exact_digest"] != STEP2_RESOURCE_DIGEST
    ):
        raise AuthorizationPlanStop("SESSION_CLEANUP_V2_AUTHORITY_INVALID")
    declarations = {item["binding_id"]: item for item in cleanup_step["binding_declarations"]}
    if (
        declarations["binding.development.auth.cleanup-v2.admin-credential-reference"]["preapproval_value"]["value"] != ADMIN_ENV
        or declarations["binding.development.auth.cleanup-v2.publishable-configuration-reference"]["preapproval_value"]["value"] != PUBLISHABLE_ENV
    ):
        raise AuthorizationPlanStop("SESSION_CLEANUP_V2_AUTHORITY_INVALID")

    if list(BASE.glob(f"{BOUNDARY}*.approval.json")) != [APPROVAL_PATH]:
        raise AuthorizationPlanStop("SESSION_CLEANUP_V2_AUTHORITY_INVALID")
    if list(BASE.glob(STEP1_EVIDENCE_PATTERN)) != [STEP1_EVIDENCE_PATH]:
        raise AuthorizationPlanStop("SESSION_CLEANUP_V2_STEP1_EVIDENCE_INVALID")

    first, second, third = progress["step_states"]
    if (
        (first["step_id"], first["authorization_state"], first["execution_state"],
         first["verification_state"], first["authorization_consumed"], first["safe_error_code"])
        != (STEP1, "CONSUMED", "SUCCEEDED", "PASS", True, None)
        or (second["step_id"], second["authorization_state"], second["execution_state"],
            second["verification_state"], second["authorization_consumed"], second["safe_error_code"])
        != (STEP2, "PENDING", "NOT_STARTED", "NOT_STARTED", False, None)
        or (third["step_id"], third["authorization_state"], third["execution_state"],
            third["verification_state"], third["authorization_consumed"], third["safe_error_code"])
        != (STEP3, "PENDING", "NOT_STARTED", "NOT_STARTED", False, None)
        or len(first["evidence"]) != 1
        or second["evidence"]
        or third["evidence"]
        or second["binding_assertions"]
        or third["binding_assertions"]
    ):
        raise AuthorizationPlanStop("SESSION_CLEANUP_V2_EXECUTION_PROGRESS_INVALID")
    first_evidence = first["evidence"][0]
    if first_evidence["evidence_type"] != STEP1_EVIDENCE_TYPE:
        raise AuthorizationPlanStop("SESSION_CLEANUP_V2_STEP1_EVIDENCE_INVALID")
    _validate_step1_evidence(step1_evidence, first_evidence["evidence_digest"])
    if list(BASE.glob(STEP2_EVIDENCE_PATTERN)):
        raise AuthorizationPlanStop("SESSION_CLEANUP_V2_STEP2_ALREADY_ATTEMPTED")

    _assert_repair_bindings()
    if _raw_digest(LIFECYCLE_PATH) != LIFECYCLE_DIGEST:
        raise AuthorizationPlanStop("SESSION_CLEANUP_V2_AUTHORITY_INVALID")
    authorized = authorize_step(
        plan,
        approval,
        progress,
        _request_for(plan, progress),
        SCHEMA_ROOT,
        moment,
        trusted_preflight_assertions=[_capability_assertion(moment)],
    )
    step2_state = authorized["step_states"][1]
    if (
        step2_state["authorization_state"] != "AUTHORIZED"
        or step2_state["execution_state"] != "NOT_STARTED"
        or step2_state["authorization_consumed"]
        or step2_state["evidence"]
    ):
        raise AuthorizationPlanStop("SESSION_CLEANUP_V2_EXECUTION_PROGRESS_INVALID")
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
    """Run the single recovery/validation/global-logout sequence; never retry."""
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
        logout_global(
            project_ref=PROJECT,
            publishable_key=publishable_key,
            bearer_token=session._access_text(),
        )
        return {
            "classification": "SESSION_REVOCATION_REQUEST_ACCEPTED",
            "temporary_session_issued": True,
            "temporary_session_count": 1,
            "jwt_validated_before_logout": True,
            "global_logout_attempted": True,
            "global_logout_accepted": True,
            "cleanup_verified": False,
            "step3_readback_required": True,
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
    safe_code = code if code in SAFE_ERROR_CODES else "SESSION_CLEANUP_V2_UNEXPECTED_FAILURE"
    print(json.dumps({
        "classification": "SESSION_STATE_UNVERIFIED",
        "safe_error_code": safe_code,
        "cleanup_verified": False,
        "step3_readback_required": True,
        "retry_authorized": False,
        "credential_material_retained": False,
        "pii_retained": False,
        "provider_mutation_attempted": provider_mutation_attempted,
    }, sort_keys=True))
    return 1


def main(
    environment: Mapping[str, str] | None = None,
    *,
    preflight_only: bool = False,
) -> int:
    env = os.environ if environment is None else environment
    admin_secret: str | None = None
    publishable_key: str | None = None
    provider_mutation_attempted = False
    try:
        _validate_invocation(env)
        _load_and_authorize(_now())
        if preflight_only:
            print(json.dumps({"preflight": "PASS", "step_id": STEP2}, sort_keys=True))
            return 0

        # Runtime credential values are read only after exact authority/preflight.
        admin_secret = env.get(ADMIN_ENV)
        publishable_key = env.get(PUBLISHABLE_ENV)
        if (
            not isinstance(admin_secret, str)
            or not admin_secret.startswith("sb_secret_")
            or len(admin_secret) < len("sb_secret_") + 16
            or not admin_secret[len("sb_secret_"):].replace("_", "").replace("-", "").isalnum()
        ):
            raise AuthorizationPlanStop("SESSION_CLEANUP_V2_ADMIN_CREDENTIAL_UNAVAILABLE")
        if (
            not isinstance(publishable_key, str)
            or not publishable_key.startswith("sb_publishable_")
            or len(publishable_key) < len("sb_publishable_") + 16
            or not publishable_key[len("sb_publishable_"):].replace("_", "").replace("-", "").isalnum()
        ):
            raise AuthorizationPlanStop("SESSION_CLEANUP_V2_PUBLISHABLE_CONFIG_UNAVAILABLE")

        provider_mutation_attempted = True
        print(json.dumps(execute_cleanup(
            admin_secret=admin_secret,
            publishable_key=publishable_key,
        ), sort_keys=True))
        return 0
    except (AuthorizationPlanError, AuthorizationPlanStop) as exc:
        code = str(exc)
        if code not in SAFE_ERROR_CODES:
            code = "SESSION_CLEANUP_V2_AUTHORITY_INVALID"
        return _safe_failure(code, provider_mutation_attempted=provider_mutation_attempted)
    except SafeLifecycleStop as exc:
        return _safe_failure(exc.code, provider_mutation_attempted=provider_mutation_attempted)
    except Exception:
        return _safe_failure(
            "SESSION_CLEANUP_V2_UNEXPECTED_FAILURE",
            provider_mutation_attempted=provider_mutation_attempted,
        )
    finally:
        admin_secret = None
        publishable_key = None


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--preflight-only", action="store_true")
    options = parser.parse_args()
    raise SystemExit(main(preflight_only=options.preflight_only))
