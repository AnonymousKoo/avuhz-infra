#!/usr/bin/env python3
"""One-shot DEVELOPMENT provider-adapter positive authentication v3 executor.

Issues one temporary recovery session for the existing passwordless
ImplementationHandoff provider-adapter identity, validates the JWT and server-owned
policy, proves the live Avuhz trusted-identity resolver accepts it using a
side-effect-free invalid-query probe, then requests global logout.

Raw credential, recovery, token, provider-subject, and PII material are never
printed, hashed, persisted, or returned. Cleanup is not claimed here; the ordered
plan requires an independent 0/0 session/refresh-token readback afterward.
"""
from __future__ import annotations

import hashlib
import json
import os
import urllib.error
import urllib.request
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
    validate_development_provider_adapter_access_jwt,
)
from avuhz_runtime.implementation_handoff import canonical_digest
from avuhz_service.development import DEVELOPMENT_AUTH_PROJECT_REF
from avuhz_service.development_supabase_identity import (
    DEVELOPMENT_PROVIDER_ADAPTER_IMPLEMENTATION_HANDOFF_ENTRY,
)

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
BASE = ROOT / "contracts/plans/v1"
BOUNDARY = "development-implementation-handoff-provider-adapter-positive-auth-v3"
PLAN_PATH = BASE / f"{BOUNDARY}.plan.json"
APPROVAL_PATH = BASE / f"{BOUNDARY}.approval.json"
EXECUTION_PROGRESS_PATH = BASE / f"{BOUNDARY}.execution-progress.json"
RESOURCE_PATH = BASE / f"{BOUNDARY}.resource.json"
STEP_ID = "development.implementation-handoff.provider-adapter-positive-auth-v3.step.05.authenticate-live-and-logout-global"
PROJECT = "pwlhruwutoitnieactol"
TARGET_EMAIL = "avuhz-implementation-handoff-provider-adapter-development@example.invalid"
ADMIN_ENV = "AVUHZ_DEVELOPMENT_SUPABASE_AUTH_PROVIDER_ADAPTER_POSITIVE_AUTH_V3_EPHEMERAL"
PUBLISHABLE_ENV = "AVUHZ_DEVELOPMENT_SUPABASE_PUBLISHABLE_KEY"
CONFIRMATION = "RUN_PROVIDER_ADAPTER_POSITIVE_AUTH_V3_STEP5"
LIVE_QUERY_URL = "https://avuhz-command-dev.onrender.com/v1/queries"

SAFE_ERROR_CODES = {
    "ACCESS_JWT_VALIDATION_FAILED",
    "APPROVAL_INVALID",
    "AUTHORITY_INVALID",
    "AUTHORIZATION_WINDOW_INACTIVE",
    "CREDENTIAL_UNAVAILABLE",
    "LIVE_AUTH_PROBE_FAILED",
    "PLAN_STATE_INVALID",
    "PROJECT_MISMATCH",
    "RECOVERY_CREDENTIAL_UNAVAILABLE",
    "RECOVERY_GENERATE_IDENTITY_MISMATCH",
    "RECOVERY_GENERATE_PROVIDER_REJECTED",
    "RECOVERY_GENERATE_REQUEST_FAILED",
    "RECOVERY_GENERATE_RESPONSE_INVALID",
    "RECOVERY_GENERATE_RESPONSE_SHAPE_INVALID",
    "RECOVERY_VERIFICATION_PROVIDER_REJECTED",
    "RECOVERY_VERIFICATION_REQUEST_FAILED",
    "RECOVERY_VERIFICATION_RESPONSE_INVALID",
    "RECOVERY_VERIFICATION_RESPONSE_SHAPE_INVALID",
    "GLOBAL_SESSION_LOGOUT_PROVIDER_REJECTED",
    "GLOBAL_SESSION_LOGOUT_REQUEST_FAILED",
    "GLOBAL_SESSION_LOGOUT_RESPONSE_INVALID",
    "POSITIVE_AUTH_FAILED_LOGOUT_UNVERIFIED",
    "WORKFLOW_BINDING_MISMATCH",
}


def _load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        raise AuthorizationPlanStop("AUTHORITY_INVALID") from None
    if not isinstance(value, dict):
        raise AuthorizationPlanStop("AUTHORITY_INVALID")
    return value


def _raw_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _request_for(plan: dict[str, Any], progress: dict[str, Any]) -> dict[str, Any]:
    step = next(item for item in plan["steps"] if item["step_id"] == STEP_ID)
    required = []
    prior = []
    for item in step["required_evidence"]:
        if item["binding_state"] == "BOUND":
            digest = item["exact_digest"]
        else:
            source = next(
                state for state in progress["step_states"]
                if state["step_id"] == item["source_step_id"]
            )
            matches = [
                evidence for evidence in source["evidence"]
                if evidence["evidence_type"] == item["evidence_type"]
            ]
            if len(matches) != 1:
                raise AuthorizationPlanStop("PLAN_STATE_INVALID")
            digest = matches[0]["evidence_digest"]
        required.append({"evidence_type": item["evidence_type"], "evidence_digest": digest})
        prior.append(digest)
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
        "step_id": STEP_ID,
        "resource_reference": step["resource"]["resource_reference"],
        "resource_version": step["resource"]["exact_version"],
        "resource_digest": step["resource"]["exact_digest"],
        "operation": step["operation"],
        "execution_class": step["execution_class"],
        "credential_class": "SUPABASE_AUTH_ADMIN_EPHEMERAL",
        "required_evidence": required,
        "prior_evidence_digests": prior,
        "unexpected_remote_state": False,
        "extra_privileges": False,
        "unauthorized_migration_surface": False,
        "scope_expansion": False,
    }


def _validate_invocation(env: Mapping[str, str]) -> None:
    if env.get("GITHUB_REF") != "refs/heads/main" or env.get("GITHUB_RUN_ATTEMPT") != "1":
        raise AuthorizationPlanStop("WORKFLOW_BINDING_MISMATCH")
    if env.get("AVUHZ_CONFIRMATION") != CONFIRMATION:
        raise AuthorizationPlanStop("WORKFLOW_BINDING_MISMATCH")
    if DEVELOPMENT_AUTH_PROJECT_REF != PROJECT:
        raise AuthorizationPlanStop("PROJECT_MISMATCH")


def _capability_assertion(moment: str, resource: dict[str, Any]) -> dict[str, Any]:
    config = {
        "executor_reference": "github-actions.development-provider-adapter-positive-auth-v3-step5",
        "environment": "development",
        "project_reference": PROJECT,
        "step_id": STEP_ID,
        "operation": "provider.auth-session.provider-adapter-recover-validate-live-probe-and-logout-global",
        "credential_class": "SUPABASE_AUTH_ADMIN_EPHEMERAL",
        "admin_binding_name": ADMIN_ENV,
        "publishable_binding_name": PUBLISHABLE_ENV,
        "executor_source_digest": _raw_digest(Path(__file__)),
        "workflow_source_digest": _raw_digest(ROOT / ".github/workflows/development-provider-adapter-positive-auth-v3-step5.yml"),
        "live_query_url": LIVE_QUERY_URL,
    }
    config_digest = canonical_digest(config)
    evidence = {
        "evidence_type": "auth.admin-executor-capability.observed",
        "environment": "DEVELOPMENT",
        "provider_reference": "supabase",
        "project_reference": PROJECT,
        "responsibility": "AUTH",
        "step_id": STEP_ID,
        "configuration_digest": config_digest,
        "credential_binding_name": resource["github_secret_binding_name"],
        "credential_material_observed": False,
        "provider_contact_attempted": False,
    }
    return {
        "binding_id": "binding.development.provider-adapter-positive-auth-v3.admin-executor-capability",
        "phase": "RESOLVED_BY_STEP_PREFLIGHT",
        "value_class": "CONFIGURATION_REFERENCE",
        "source_step_id": None,
        "evidence_type": "auth.admin-executor-capability.observed",
        "evidence_digest": canonical_digest(evidence),
        "digest_policy": "REQUIRED",
        "persistence_policy": "DIGEST_ONLY",
        "sanitized_value": None,
        "value_digest": config_digest,
        "recorded_at": moment,
    }


def _load_and_authorize(moment: str) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        plan = _load(PLAN_PATH)
        approval = _load(APPROVAL_PATH)
        progress = _load(EXECUTION_PROGRESS_PATH)
        resource = _load(RESOURCE_PATH)
        validate_plan(plan, SCHEMA_ROOT)
        validate_progress(plan, progress, SCHEMA_ROOT)
        validate_approval(plan, approval, SCHEMA_ROOT, moment)
    except (AuthorizationPlanError, AuthorizationPlanStop):
        raise AuthorizationPlanStop("AUTHORITY_INVALID") from None

    if (
        plan.get("environment") != "DEVELOPMENT"
        or plan.get("target", {}).get("project_reference") != PROJECT
        or plan.get("target", {}).get("responsibility") != "AUTH"
        or approval.get("decision") != "APPROVE"
        or approval.get("authority_scope") != "EXACT_PLAN_ONLY"
        or resource.get("project_reference") != PROJECT
        or resource.get("step5_executor_digest") != _raw_digest(Path(__file__))
        or resource.get("step5_workflow_digest")
        != _raw_digest(ROOT / ".github/workflows/development-provider-adapter-positive-auth-v3-step5.yml")
    ):
        raise AuthorizationPlanStop("AUTHORITY_INVALID")

    states = progress.get("step_states", [])
    if len(states) != 10:
        raise AuthorizationPlanStop("PLAN_STATE_INVALID")
    if any(
        (
            state.get("authorization_state"),
            state.get("execution_state"),
            state.get("verification_state"),
            state.get("authorization_consumed"),
        ) != ("CONSUMED", "SUCCEEDED", "PASS", True)
        for state in states[:4]
    ):
        raise AuthorizationPlanStop("PLAN_STATE_INVALID")
    fifth = states[4]
    if (
        fifth.get("step_id") != STEP_ID
        or (
            fifth.get("authorization_state"),
            fifth.get("execution_state"),
            fifth.get("verification_state"),
            fifth.get("authorization_consumed"),
        ) != ("PENDING", "NOT_STARTED", "NOT_STARTED", False)
        or any(
            state.get("authorization_state") != "PENDING"
            or state.get("execution_state") != "NOT_STARTED"
            for state in states[5:]
        )
    ):
        raise AuthorizationPlanStop("PLAN_STATE_INVALID")

    authorized = authorize_step(
        plan,
        approval,
        progress,
        _request_for(plan, progress),
        SCHEMA_ROOT,
        moment,
        trusted_preflight_assertions=[_capability_assertion(moment, resource)],
    )
    state = authorized["step_states"][4]
    if state["authorization_state"] != "AUTHORIZED" or state["authorization_consumed"] is not False:
        raise AuthorizationPlanStop("AUTHORITY_INVALID")
    return plan, authorized


def _live_identity_probe(
    access_token: str,
    *,
    urlopen: Callable[..., Any] = urllib.request.urlopen,
) -> None:
    request = urllib.request.Request(
        LIVE_QUERY_URL,
        data=b"{}",
        method="POST",
        headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    try:
        with urlopen(request, timeout=20) as response:
            _ = response.read(4097)
            raise SafeLifecycleStop("LIVE_AUTH_PROBE_FAILED")
    except urllib.error.HTTPError as exc:
        if exc.code != 400:
            raise SafeLifecycleStop("LIVE_AUTH_PROBE_FAILED") from None
        raw = exc.read(4097)
        if len(raw) > 4096:
            raise SafeLifecycleStop("LIVE_AUTH_PROBE_FAILED")
        try:
            payload = json.loads(raw.decode("utf-8"))
        except Exception:
            raise SafeLifecycleStop("LIVE_AUTH_PROBE_FAILED") from None
        if payload != {"error": "invalid_query"}:
            raise SafeLifecycleStop("LIVE_AUTH_PROBE_FAILED")
    except SafeLifecycleStop:
        raise
    except Exception:
        raise SafeLifecycleStop("LIVE_AUTH_PROBE_FAILED") from None


def execute_positive_auth(
    *,
    admin_secret: str,
    publishable_key: str,
    generate: Callable[..., RecoveryVerificationCredential] = request_generate_recovery_credential,
    verify: Callable[..., IssuedSession] = request_direct_recovery_verification,
    validate_jwt: Callable[[str], Any] = validate_development_provider_adapter_access_jwt,
    live_probe: Callable[[str], None] = _live_identity_probe,
    logout_global: Callable[..., None] = request_global_session_logout,
) -> dict[str, Any]:
    credential: RecoveryVerificationCredential | None = None
    session: IssuedSession | None = None
    logout_attempted = False
    entry = DEVELOPMENT_PROVIDER_ADAPTER_IMPLEMENTATION_HANDOFF_ENTRY
    try:
        credential = generate(
            project_ref=PROJECT,
            admin_secret=admin_secret,
            existing_user_email=TARGET_EMAIL,
            expected_user_id=None,
            expected_subject_digest=entry.subject_digest,
        )
        session = verify(
            project_ref=PROJECT,
            publishable_key=publishable_key,
            credential=credential,
            expected_user_id=None,
        )
        result = validate_jwt(session._access_text())
        if (
            result.subject_digest != entry.subject_digest
            or result.tenant_id != entry.tenant_id
            or result.caller_type != "PROVIDER_ADAPTER"
            or result.capabilities != ("implementation_handoff:accept",)
            or result.authority_roles != ()
        ):
            raise SafeLifecycleStop("ACCESS_JWT_VALIDATION_FAILED")

        live_probe(session._access_text())
        logout_attempted = True
        logout_global(
            project_ref=PROJECT,
            publishable_key=publishable_key,
            bearer_token=session._access_text(),
        )
        return {
            "classification": "PROVIDER_ADAPTER_POSITIVE_AUTH_LIVE_VERIFIED_PENDING_CLEANUP",
            "temporary_session_issued": True,
            "temporary_session_count": 1,
            "jwt_cryptographically_validated": True,
            "issuer_verified": True,
            "audience_verified": True,
            "subject_digest_verified": True,
            "tenant_verified": True,
            "caller_type": "PROVIDER_ADAPTER",
            "capabilities": ["implementation_handoff:accept"],
            "authority_roles": [],
            "live_runtime_probe_http": 400,
            "live_runtime_probe_error": "invalid_query",
            "implementation_handoff_attempted": False,
            "global_logout_attempted": True,
            "global_logout_accepted": True,
            "cleanup_verified": False,
            "step6_readback_required": True,
            "retry_authorized": False,
            "credential_material_retained": False,
            "token_material_retained": False,
            "pii_retained": False,
        }
    except Exception:
        logout_failed = False
        if session is not None and not logout_attempted:
            logout_attempted = True
            try:
                logout_global(
                    project_ref=PROJECT,
                    publishable_key=publishable_key,
                    bearer_token=session._access_text(),
                )
            except Exception:
                logout_failed = True
        if logout_failed:
            raise SafeLifecycleStop("POSITIVE_AUTH_FAILED_LOGOUT_UNVERIFIED") from None
        raise
    finally:
        if credential is not None:
            credential.clear()
        if session is not None:
            session.clear()
            session.user_id = ""


def _safe_failure(code: str, *, provider_mutation_attempted: bool) -> int:
    safe = code if code in SAFE_ERROR_CODES else "AUTHORITY_INVALID"
    print(json.dumps({
        "classification": "PROVIDER_ADAPTER_POSITIVE_AUTH_UNVERIFIED",
        "safe_error_code": safe,
        "cleanup_verified": False,
        "step6_readback_required": provider_mutation_attempted,
        "retry_authorized": False,
        "credential_material_retained": False,
        "token_material_retained": False,
        "pii_retained": False,
        "provider_mutation_attempted": provider_mutation_attempted,
    }, sort_keys=True))
    return 1


def main(environment: Mapping[str, str] | None = None, *, preflight_only: bool = False) -> int:
    env = os.environ if environment is None else environment
    admin_secret: str | None = None
    publishable_key: str | None = None
    attempted = False
    try:
        _validate_invocation(env)
        _load_and_authorize(_now())
        if preflight_only:
            print(json.dumps({"preflight": "PASS", "step_id": STEP_ID}, sort_keys=True))
            return 0

        admin_secret = env.get(ADMIN_ENV)
        publishable_key = env.get(PUBLISHABLE_ENV)
        if not isinstance(admin_secret, str) or not admin_secret.startswith("sb_secret_") or len(admin_secret) < 26:
            raise AuthorizationPlanStop("CREDENTIAL_UNAVAILABLE")
        if not isinstance(publishable_key, str) or not publishable_key.startswith("sb_publishable_") or len(publishable_key) < 31:
            raise AuthorizationPlanStop("CREDENTIAL_UNAVAILABLE")

        attempted = True
        print(json.dumps(
            execute_positive_auth(admin_secret=admin_secret, publishable_key=publishable_key),
            sort_keys=True,
        ))
        return 0
    except (AuthorizationPlanError, AuthorizationPlanStop) as exc:
        return _safe_failure(str(exc), provider_mutation_attempted=attempted)
    except SafeLifecycleStop as exc:
        return _safe_failure(exc.code, provider_mutation_attempted=attempted)
    except Exception:
        return _safe_failure("AUTHORITY_INVALID", provider_mutation_attempted=attempted)
    finally:
        admin_secret = None
        publishable_key = None


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--preflight-only", action="store_true")
    args = parser.parse_args()
    raise SystemExit(main(preflight_only=args.preflight_only))
