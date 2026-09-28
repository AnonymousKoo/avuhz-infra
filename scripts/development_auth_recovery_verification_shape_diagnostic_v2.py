#!/usr/bin/env python3
"""Bounded DEVELOPMENT AUTH recovery-verification shape diagnostic v2 executor.

One authorized provider attempt means exactly one recovery generation followed by
one direct recovery verification. Only fixed structural labels may be returned.
No parser, JWT validation, logout, cleanup, retry, or continuation is performed.
"""
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
    AuthorizationPlanError, AuthorizationPlanStop, approval_digest, authorize_step,
    plan_digest, progress_digest, validate_approval, validate_plan, validate_progress,
)
from avuhz_engineering.development_auth_token_lifecycle import (
    RecoveryVerificationCredential, SafeLifecycleStop, VERIFY_PATH, VERIFY_TYPE,
    _post_json, _provider_headers, classify_recovery_verification_response_shape,
    request_generate_recovery_credential,
)
from avuhz_runtime.implementation_handoff import canonical_digest
from avuhz_service.development import DEVELOPMENT_AUTH_PROJECT_REF
from avuhz_service.development_supabase_identity import DEVELOPMENT_SYNTHETIC_READ_ONLY_ALLOWLIST

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "contracts/plans/v1"
SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
BOUNDARY = "development-auth-recovery-verification-shape-diagnostic-v2"
PLAN_PATH = BASE / f"{BOUNDARY}.plan.json"
PROGRESS_PATH = BASE / f"{BOUNDARY}.progress.json"
APPROVAL_PATH = BASE / f"{BOUNDARY}.approval.json"
FAILURE_EVIDENCE_PATH = BASE / "development-auth-v32-synthetic-session-cleanup-v2-step2-failure.evidence.json"
LIFECYCLE_PATH = ROOT / "src/avuhz_engineering/development_auth_token_lifecycle.py"

PLAN_ID = "750bb51d-91c0-4d49-9584-d8d37081c46a"
PLAN_VERSION = 2
PLAN_DIGEST = "sha256:c66c6d7e805b50042c911f25829b523a47d149815fed5231d84ca0d817d03875"
PROGRESS_DIGEST = "sha256:206859bebc5d4feb8f14e76581c16ebb558ad06782b8d422b0da911b4814b5cb"
APPROVAL_ID = "ee05121f-ef52-4eea-bc6c-4e6487b50fc7"
APPROVAL_DIGEST = "sha256:a95fd89aa71d7e017ab153fac29be1b735c0e91e4c6c70cf6cbea85fb7bf34d3"
PROJECT = "pwlhruwutoitnieactol"
WINDOW_START = "2026-09-28T01:00:00Z"
WINDOW_END = "2026-09-28T07:00:00Z"
STEP = "development.auth.recovery-shape-diagnostic-v2.step.01.inspect-sanitized-shape-once"
OPERATION = "provider.auth-recovery-verification.inspect-sanitized-shape-once"
RESOURCE_DIGEST = "sha256:19c7c16c8cc495e0b4ab886ab897804251245c979b536498b14c7d94086809ce"
FAILURE_EVIDENCE_DIGEST = "sha256:8344c3e26c26f464bcefa880251ac7619bfc6087a8a17e9c0987db4a843191eb"
PREAPPROVAL_REFERENCE = "executor.development.auth.recovery-shape-diagnostic-v2.admin-capable"
PREAPPROVAL_REFERENCE_DIGEST = "sha256:c20b536febc80e21684d5e1e2fc1eb040e6eca48019ca8afda568c4f9fa0cbb3"
CAPABILITY_BINDING_ID = "binding.development.auth.recovery-shape-diagnostic-v2.admin-executor-capability"
CAPABILITY_EVIDENCE = "auth.admin-executor-capability.observed"
TARGET_EMAIL = "avuhz-development-synthetic@example.invalid"
ADMIN_ENV = "AVUHZ_DEVELOPMENT_AUTH_RECOVERY_SHAPE_DIAGNOSTIC_V2_ADMIN_EPHEMERAL"
PUBLISHABLE_ENV = "AVUHZ_DEVELOPMENT_SUPABASE_PUBLISHABLE_KEY"
CONFIRMATION = "INSPECT_DEVELOPMENT_AUTH_RECOVERY_SHAPE_V2_ONCE"


def _load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        raise AuthorizationPlanStop("RECOVERY_SHAPE_DIAGNOSTIC_V2_AUTHORITY_INVALID") from None
    if not isinstance(value, dict):
        raise AuthorizationPlanStop("RECOVERY_SHAPE_DIAGNOSTIC_V2_AUTHORITY_INVALID")
    return value


def _raw_digest(path: Path) -> str:
    try:
        return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    except Exception:
        raise AuthorizationPlanStop("RECOVERY_SHAPE_DIAGNOSTIC_V2_AUTHORITY_INVALID") from None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _capability_assertion(moment: str) -> dict[str, Any]:
    config = {
        "executor_reference": PREAPPROVAL_REFERENCE,
        "environment": "DEVELOPMENT",
        "project_reference": PROJECT,
        "step_id": STEP,
        "operation": OPERATION,
        "credential_class": "SUPABASE_AUTH_ADMIN_EPHEMERAL",
        "executor_source_digest": _raw_digest(Path(__file__)),
    }
    digest = canonical_digest(config)
    evidence = {
        "evidence_type": CAPABILITY_EVIDENCE,
        "environment": "DEVELOPMENT",
        "provider_reference": "supabase",
        "project_reference": PROJECT,
        "responsibility": "AUTH",
        "plan_id": PLAN_ID,
        "step_id": STEP,
        "configuration_digest": digest,
        "credential_material_observed": False,
        "provider_contact_attempted": False,
    }
    return {
        "binding_id": CAPABILITY_BINDING_ID,
        "phase": "RESOLVED_BY_STEP_PREFLIGHT",
        "value_class": "CONFIGURATION_REFERENCE",
        "source_step_id": None,
        "evidence_type": CAPABILITY_EVIDENCE,
        "evidence_digest": canonical_digest(evidence),
        "digest_policy": "REQUIRED",
        "persistence_policy": "DIGEST_ONLY",
        "sanitized_value": None,
        "value_digest": digest,
        "recorded_at": moment,
    }


def _request(plan: dict[str, Any]) -> dict[str, Any]:
    step = plan["steps"][0]
    return {
        "plan_id": PLAN_ID, "plan_version": PLAN_VERSION, "plan_digest": PLAN_DIGEST,
        "environment": "DEVELOPMENT", "provider_reference": "supabase",
        "project_reference": PROJECT, "responsibility": "AUTH",
        "issuer_reference": plan["target"]["issuer_reference"],
        "audience_reference": plan["target"]["audience_reference"],
        "step_id": STEP, "resource_reference": step["resource"]["resource_reference"],
        "resource_version": step["resource"]["exact_version"], "resource_digest": RESOURCE_DIGEST,
        "operation": OPERATION, "execution_class": "PROVIDER_MUTATION",
        "credential_class": "SUPABASE_AUTH_ADMIN_EPHEMERAL",
        "required_evidence": [{"evidence_type": "auth.cleanup-v4.failure.observed", "evidence_digest": FAILURE_EVIDENCE_DIGEST}],
        "prior_evidence_digests": [], "unexpected_remote_state": False,
        "extra_privileges": False, "unauthorized_migration_surface": False, "scope_expansion": False,
    }


def _load_and_authorize(moment: str) -> None:
    try:
        plan, progress, approval = _load(PLAN_PATH), _load(PROGRESS_PATH), _load(APPROVAL_PATH)
        validate_plan(plan, SCHEMA_ROOT)
        validate_progress(plan, progress, SCHEMA_ROOT)
        validate_approval(plan, approval, SCHEMA_ROOT, moment)
    except (AuthorizationPlanError, AuthorizationPlanStop):
        raise AuthorizationPlanStop("RECOVERY_SHAPE_DIAGNOSTIC_V2_AUTHORITY_INVALID") from None
    step = plan.get("steps", [{}])[0]
    declarations = {x["binding_id"]: x for x in step.get("binding_declarations", [])}
    admin_decl = declarations.get("binding.development.auth.recovery-shape-diagnostic-v2.admin-credential-reference", {})
    state = progress.get("step_states", [{}])[0]
    if (
        plan.get("plan_id") != PLAN_ID or plan.get("plan_version") != PLAN_VERSION
        or plan.get("plan_digest") != PLAN_DIGEST or plan_digest(plan) != PLAN_DIGEST
        or progress.get("progress_digest") != PROGRESS_DIGEST or progress_digest(progress) != PROGRESS_DIGEST
        or approval.get("approval_id") != APPROVAL_ID or approval.get("approval_digest") != APPROVAL_DIGEST
        or approval_digest(approval) != APPROVAL_DIGEST or approval.get("authority_scope") != "EXACT_PLAN_ONLY"
        or plan.get("authorization_window") != {"binding_state":"BOUND","starts_at":WINDOW_START,"expires_at":WINDOW_END}
        or DEVELOPMENT_AUTH_PROJECT_REF != PROJECT or plan.get("target", {}).get("project_reference") != PROJECT
        or plan.get("target", {}).get("responsibility") != "AUTH" or len(plan.get("steps", [])) != 1
        or step.get("step_id") != STEP or step.get("operation") != OPERATION
        or step.get("resource", {}).get("exact_digest") != RESOURCE_DIGEST or _raw_digest(LIFECYCLE_PATH) != RESOURCE_DIGEST
        or _raw_digest(FAILURE_EVIDENCE_PATH) != FAILURE_EVIDENCE_DIGEST
        or admin_decl.get("preapproval_value", {}).get("value") != PREAPPROVAL_REFERENCE
        or admin_decl.get("preapproval_value", {}).get("exact_digest") != PREAPPROVAL_REFERENCE_DIGEST
        or canonical_digest(PREAPPROVAL_REFERENCE) != PREAPPROVAL_REFERENCE_DIGEST
        or progress.get("overall_state") != "NOT_STARTED"
        or (state.get("authorization_state"),state.get("execution_state"),state.get("verification_state"),state.get("authorization_consumed")) != ("PENDING","NOT_STARTED","NOT_STARTED",False)
        or state.get("evidence") != [] or state.get("binding_assertions") != []
    ):
        raise AuthorizationPlanStop("RECOVERY_SHAPE_DIAGNOSTIC_V2_AUTHORITY_INVALID")
    authorized = authorize_step(plan, approval, progress, _request(plan), SCHEMA_ROOT, moment,
                                trusted_preflight_assertions=[_capability_assertion(moment)])
    s = authorized["step_states"][0]
    if s["authorization_state"] != "AUTHORIZED" or s["authorization_consumed"] or s["execution_state"] != "NOT_STARTED":
        raise AuthorizationPlanStop("RECOVERY_SHAPE_DIAGNOSTIC_V2_AUTHORITY_INVALID")


def execute_diagnostic(*, admin_secret: str, publishable_key: str,
                       generate: Callable[..., RecoveryVerificationCredential] = request_generate_recovery_credential,
                       post_json: Callable[..., dict[str, Any] | None] = _post_json) -> dict[str, str]:
    credential: RecoveryVerificationCredential | None = None
    payload: dict[str, Any] | None = None
    try:
        credential = generate(project_ref=PROJECT, admin_secret=admin_secret,
                              existing_user_email=TARGET_EMAIL, expected_user_id=None,
                              expected_subject_digest=DEVELOPMENT_SYNTHETIC_READ_ONLY_ALLOWLIST[0].subject_digest)
        payload = post_json(
            f"https://{PROJECT}.supabase.co{VERIFY_PATH}", headers=_provider_headers(publishable_key),
            body={"type": VERIFY_TYPE, "token_hash": credential._text()},
            provider_rejected_code="RECOVERY_VERIFICATION_PROVIDER_REJECTED",
            request_failed_code="RECOVERY_VERIFICATION_REQUEST_FAILED",
            response_invalid_code="RECOVERY_VERIFICATION_RESPONSE_INVALID",
        )
        if payload is None:
            raise SafeLifecycleStop("RECOVERY_VERIFICATION_RESPONSE_INVALID")
        return classify_recovery_verification_response_shape(payload)
    finally:
        if payload is not None:
            for field in ("access_token", "refresh_token", "id", "email"):
                if field in payload:
                    payload[field] = None
            user = payload.get("user") if isinstance(payload, dict) else None
            if isinstance(user, dict):
                for field in ("id", "email"):
                    if field in user:
                        user[field] = None
            payload.clear()
        if credential is not None:
            credential.clear()


def main(environment: Mapping[str, str] | None = None, *, preflight_only: bool = False) -> int:
    env = os.environ if environment is None else environment
    admin_secret: str | None = None
    publishable_key: str | None = None
    provider_attempted = False
    try:
        _load_and_authorize(_now())
        if preflight_only:
            print(json.dumps({"preflight":"PASS","step_id":STEP}, sort_keys=True))
            return 0
        if env.get("AVUHZ_RECOVERY_SHAPE_DIAGNOSTIC_CONFIRMATION") != CONFIRMATION:
            raise AuthorizationPlanStop("RECOVERY_SHAPE_DIAGNOSTIC_V2_CONFIRMATION_MISMATCH")
        admin_secret, publishable_key = env.get(ADMIN_ENV), env.get(PUBLISHABLE_ENV)
        if not isinstance(admin_secret, str) or not admin_secret.startswith("sb_secret_"):
            raise AuthorizationPlanStop("RECOVERY_SHAPE_DIAGNOSTIC_V2_ADMIN_CREDENTIAL_UNAVAILABLE")
        if not isinstance(publishable_key, str) or not publishable_key.startswith("sb_publishable_"):
            raise AuthorizationPlanStop("RECOVERY_SHAPE_DIAGNOSTIC_V2_PUBLISHABLE_CONFIG_UNAVAILABLE")
        provider_attempted = True
        shape = execute_diagnostic(admin_secret=admin_secret, publishable_key=publishable_key)
        print(json.dumps({"classification":"SANITIZED_SHAPE_OBSERVED","shape":shape,
                          "retry_authorized":False,"provider_mutation_attempted":True,
                          "credential_material_retained":False,"pii_retained":False}, sort_keys=True))
        return 0
    except (AuthorizationPlanError, AuthorizationPlanStop, SafeLifecycleStop) as exc:
        code = getattr(exc, "code", str(exc))
        print(json.dumps({"classification":"DIAGNOSTIC_STOPPED","safe_error_code":code,
                          "retry_authorized":False,"provider_mutation_attempted":provider_attempted,
                          "credential_material_retained":False,"pii_retained":False}, sort_keys=True))
        return 1
    except Exception:
        print(json.dumps({"classification":"DIAGNOSTIC_STOPPED","safe_error_code":"RECOVERY_SHAPE_DIAGNOSTIC_V2_UNEXPECTED_FAILURE",
                          "retry_authorized":False,"provider_mutation_attempted":provider_attempted,
                          "credential_material_retained":False,"pii_retained":False}, sort_keys=True))
        return 1
    finally:
        admin_secret = None
        publishable_key = None


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--preflight-only", action="store_true")
    args = parser.parse_args()
    raise SystemExit(main(preflight_only=args.preflight_only))
