#!/usr/bin/env python3
"""Dormant executor for cleanup-v1 Step 2 only.

Repository preparation never invokes this file.  A future dispatch must supply
an exact owner approval and canonical Step 1 success progress/evidence before
the executor reads either runtime credential.  It performs no SQL/readback and
never claims cleanup verification; that remains owner-interactive Step 3.
"""
from __future__ import annotations

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
    authorize_step,
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
BOUNDARY = "development-auth-v32-synthetic-session-cleanup-v1"
PLAN_PATH = BASE / f"{BOUNDARY}.plan.json"
PRISTINE_PROGRESS_PATH = BASE / f"{BOUNDARY}.progress.json"
APPROVAL_PATH = BASE / f"{BOUNDARY}.approval.json"
EXECUTION_PROGRESS_PATH = BASE / f"{BOUNDARY}.execution-progress.json"
STEP1_EVIDENCE_PATH = BASE / f"{BOUNDARY}-step1-success.evidence.json"

PLAN_ID = "daa207fd-1426-455f-a921-1dc69d8f2d65"
PLAN_DIGEST = "sha256:19bc9c0182da26f3a4b56339f70211966aaa74957c910d5a5830f0f26d1a832e"
PLAN_RAW_DIGEST = "sha256:6880d642628eab13c18cfa3ab6f3bd5f1f09af282f538659fa70644c9d1a5f41"
PRISTINE_PROGRESS_DIGEST = "sha256:a3b0f0b477747af83a0cbe3b8aa660ff43d0258d763e0283c7877e129bf002c7"
STEP1 = "development.auth.v32-synthetic-session-cleanup-v1.step.01.verify-attributed-session-precondition"
STEP2 = "development.auth.v32-synthetic-session-cleanup-v1.step.02.revoke-synthetic-sessions-global"
STEP3 = "development.auth.v32-synthetic-session-cleanup-v1.step.03.verify-zero-session-refresh-state"
CONFIRMATION = "REVOKE_V32_SYNTHETIC_SESSIONS_GLOBAL"
PROJECT = "pwlhruwutoitnieactol"
TARGET_EMAIL = "avuhz-development-synthetic@example.invalid"
ADMIN_ENV = "AVUHZ_DEVELOPMENT_SUPABASE_AUTH_SESSION_CLEANUP_V1_EPHEMERAL"
PUBLISHABLE_ENV = "AVUHZ_DEVELOPMENT_SUPABASE_PUBLISHABLE_KEY"
CAPABILITY_BINDING_ID = (
    "binding.development.auth.v32-synthetic-session-cleanup-v1."
    "cleanup-executor-capability"
)
CAPABILITY_EVIDENCE_TYPE = "auth.admin-executor-capability.observed"
STEP1_EVIDENCE_TYPE = "auth.synthetic-session.precleanup-attribution.verified"


def _load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        raise AuthorizationPlanStop("SESSION_CLEANUP_AUTHORITY_INVALID") from None
    if not isinstance(value, dict):
        raise AuthorizationPlanStop("SESSION_CLEANUP_AUTHORITY_INVALID")
    return value


def _raw_digest(path: Path) -> str:
    try:
        return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    except Exception:
        raise AuthorizationPlanStop("SESSION_CLEANUP_AUTHORITY_INVALID") from None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _request_for(plan: dict[str, Any], progress: dict[str, Any]) -> dict[str, Any]:
    step = plan["steps"][1]
    source = progress["step_states"][0]
    matches = [
        item for item in source["evidence"]
        if item["evidence_type"] == STEP1_EVIDENCE_TYPE
    ]
    if len(matches) != 1:
        raise AuthorizationPlanStop("SESSION_CLEANUP_STEP1_EVIDENCE_INVALID")
    prior = [
        item["evidence_digest"]
        for state in progress["step_states"][:1]
        for item in state["evidence"]
    ]
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
        "required_evidence": [{
            "evidence_type": STEP1_EVIDENCE_TYPE,
            "evidence_digest": matches[0]["evidence_digest"],
        }],
        "prior_evidence_digests": prior,
        "unexpected_remote_state": False,
        "extra_privileges": False,
        "unauthorized_migration_surface": False,
        "scope_expansion": False,
    }


def _capability_assertion(moment: str) -> dict[str, Any]:
    config = {
        "executor_reference": "github-actions.development-auth-v32-synthetic-session-cleanup-v1",
        "environment": "development",
        "project_reference": PROJECT,
        "step_id": STEP2,
        "operation": "provider.auth-session.recover-once-validate-and-logout-global",
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


def _validate_step1_evidence(value: dict[str, Any], expected_digest: str) -> None:
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
        "sanitized_result": {
            "session_count": 1,
            "synthetic_session_count": 1,
        },
        "provider_mutation_attempted": False,
        "credential_material_retained": False,
        "pii_retained": False,
    }
    if any(value.get(key) != item for key, item in expected.items()):
        raise AuthorizationPlanStop("SESSION_CLEANUP_STEP1_EVIDENCE_INVALID")
    if _raw_digest(STEP1_EVIDENCE_PATH) != expected_digest:
        raise AuthorizationPlanStop("SESSION_CLEANUP_STEP1_EVIDENCE_INVALID")


def _load_and_authorize(moment: str) -> dict[str, Any]:
    plan = _load(PLAN_PATH)
    pristine = _load(PRISTINE_PROGRESS_PATH)
    approval = _load(APPROVAL_PATH)
    progress = _load(EXECUTION_PROGRESS_PATH)
    evidence = _load(STEP1_EVIDENCE_PATH)
    validate_plan(plan, SCHEMA_ROOT)
    validate_progress(plan, pristine, SCHEMA_ROOT)
    validate_progress(plan, progress, SCHEMA_ROOT)
    validate_approval(plan, approval, SCHEMA_ROOT, moment)
    if (
        plan["plan_id"] != PLAN_ID
        or plan["plan_digest"] != PLAN_DIGEST
        or _raw_digest(PLAN_PATH) != PLAN_RAW_DIGEST
        or pristine["progress_digest"] != PRISTINE_PROGRESS_DIGEST
        or pristine["overall_state"] != "NOT_STARTED"
    ):
        raise AuthorizationPlanStop("SESSION_CLEANUP_AUTHORITY_INVALID")
    first, second, third = progress["step_states"]
    if (
        first["step_id"] != STEP1
        or (
            first["authorization_state"], first["execution_state"],
            first["verification_state"], first["authorization_consumed"],
        ) != ("CONSUMED", "SUCCEEDED", "PASS", True)
        or second["step_id"] != STEP2
        or (
            second["authorization_state"], second["execution_state"],
            second["verification_state"], second["authorization_consumed"],
        ) != ("PENDING", "NOT_STARTED", "NOT_STARTED", False)
        or third["step_id"] != STEP3
        or (
            third["authorization_state"], third["execution_state"],
            third["verification_state"], third["authorization_consumed"],
        ) != ("PENDING", "NOT_STARTED", "NOT_STARTED", False)
    ):
        raise AuthorizationPlanStop("SESSION_CLEANUP_PROGRESS_INVALID")
    matches = [
        item for item in first["evidence"]
        if item["evidence_type"] == STEP1_EVIDENCE_TYPE
    ]
    if len(matches) != 1:
        raise AuthorizationPlanStop("SESSION_CLEANUP_STEP1_EVIDENCE_INVALID")
    _validate_step1_evidence(evidence, matches[0]["evidence_digest"])
    return authorize_step(
        plan,
        approval,
        progress,
        _request_for(plan, progress),
        SCHEMA_ROOT,
        moment,
        trusted_preflight_assertions=[_capability_assertion(moment)],
    )


def execute_cleanup(
    *,
    admin_secret: str,
    publishable_key: str,
    generate: Callable[..., RecoveryVerificationCredential] = request_generate_recovery_credential,
    verify: Callable[..., IssuedSession] = request_direct_recovery_verification,
    validate_jwt: Callable[[str], Any] = validate_development_synthetic_access_jwt,
    logout_global: Callable[..., None] = request_global_session_logout,
) -> dict[str, Any]:
    """Perform one generate/verify/validate/global-logout sequence, without retry."""

    credential: RecoveryVerificationCredential | None = None
    session: IssuedSession | None = None
    try:
        credential = generate(
            project_ref=PROJECT,
            admin_secret=admin_secret,
            existing_user_email=TARGET_EMAIL,
            expected_user_id=None,
            expected_subject_digest=(
                DEVELOPMENT_SYNTHETIC_READ_ONLY_ALLOWLIST[0].subject_digest
            ),
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


def _safe_failure(code: str) -> int:
    print(json.dumps({
        "classification": "SESSION_STATE_UNVERIFIED",
        "safe_error_code": code,
        "cleanup_verified": False,
        "step3_readback_required": True,
        "retry_authorized": False,
        "credential_material_retained": False,
        "pii_retained": False,
    }, sort_keys=True))
    return 1


def main(environment: Mapping[str, str] | None = None) -> int:
    env = os.environ if environment is None else environment
    admin_secret: str | None = None
    publishable_key: str | None = None
    try:
        if env.get("AVUHZ_CLEANUP_CONFIRMATION") != CONFIRMATION:
            raise AuthorizationPlanStop("SESSION_CLEANUP_CONFIRMATION_MISMATCH")
        if env.get("AVUHZ_EXPECTED_PROJECT_REF") != PROJECT:
            raise AuthorizationPlanStop("SESSION_CLEANUP_PROJECT_MISMATCH")
        if DEVELOPMENT_AUTH_PROJECT_REF != PROJECT:
            raise AuthorizationPlanStop("SESSION_CLEANUP_PROJECT_MISMATCH")

        # All repository authority is validated before either secret value is read.
        _load_and_authorize(_now())
        admin_secret = env.get(ADMIN_ENV)
        publishable_key = env.get(PUBLISHABLE_ENV)
        if not isinstance(admin_secret, str) or not admin_secret.startswith("sb_secret_"):
            raise AuthorizationPlanStop("SESSION_CLEANUP_ADMIN_CREDENTIAL_UNAVAILABLE")
        if (
            not isinstance(publishable_key, str)
            or not publishable_key.startswith("sb_publishable_")
        ):
            raise AuthorizationPlanStop("SESSION_CLEANUP_PUBLISHABLE_CONFIG_UNAVAILABLE")
        print(json.dumps(execute_cleanup(
            admin_secret=admin_secret,
            publishable_key=publishable_key,
        ), sort_keys=True))
        return 0
    except (AuthorizationPlanError, AuthorizationPlanStop) as exc:
        return _safe_failure(str(exc))
    except SafeLifecycleStop as exc:
        return _safe_failure(exc.code)
    except Exception:
        return _safe_failure("SESSION_CLEANUP_UNEXPECTED_FAILURE")
    finally:
        admin_secret = None
        publishable_key = None


if __name__ == "__main__":
    raise SystemExit(main())
