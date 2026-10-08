#!/usr/bin/env python3
"""Fail-closed candidate executor for fresh DEVELOPMENT provider-adapter auth v15.

NO executable v15 approval, plan or credential is included in this change.
Until the new schema-valid main plan, independent cleanup fallback plan/approval,
exact hash-bound source resource and consumed prerequisite steps all exist,
preflight refuses execution *before* looking up an environment secret.

Reuses the shared recovery/JWT/global-logout lifecycle; the v14 executor and
its consumed authorization are not used. Nothing is logged except safe codes.
"""
from __future__ import annotations

import hashlib
import json
import os
import urllib.request
from collections.abc import Mapping
from functools import partial
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
from avuhz_engineering.development_auth_token_lifecycle import SafeLifecycleStop
from avuhz_runtime.implementation_handoff import canonical_digest
from avuhz_service.development import DEVELOPMENT_AUTH_PROJECT_REF
from scripts import development_provider_adapter_positive_auth_v4 as shared
from scripts import development_provider_adapter_positive_auth_v14 as historical
from scripts.development_provider_adapter_live_identity_probe_v15 import (
    DEVELOPMENT_QUERY_URL,
    authenticated_live_identity_probe,
)
from scripts.development_live_probe_classifier_v1 import PROBE_ACCEPTED

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
BASE = ROOT / "contracts/plans/v1"
BOUNDARY = "development-implementation-handoff-provider-adapter-positive-auth-v15"
FALLBACK_BOUNDARY = BOUNDARY + "-corrective-cleanup-v1"
PLAN_PATH = BASE / (BOUNDARY + ".plan.json")
APPROVAL_PATH = BASE / (BOUNDARY + ".approval.json")
PROGRESS_PATH = BASE / (BOUNDARY + ".progress.json")
RESOURCE_PATH = BASE / (BOUNDARY + ".resource.json")
WORKFLOW_PATH = ROOT / ".github/workflows/development-provider-adapter-positive-auth-v15-step4.yml"
STEP_ID = BOUNDARY + ".step.04.authenticate-live-and-logout-global"
PROJECT = "pwlhruwutoitnieactol"
ADMIN_ENV = "AVUHZ_DEVELOPMENT_SUPABASE_AUTH_PROVIDER_ADAPTER_POSITIVE_AUTH_V15_EPHEMERAL"
PUBLISHABLE_ENV = "AVUHZ_DEVELOPMENT_SUPABASE_PUBLISHABLE_KEY"
CONFIRMATION = "RUN_PROVIDER_ADAPTER_POSITIVE_AUTH_V15_STEP4"
OPERATION = "provider.auth-session.provider-adapter-recover-validate-live-probe-and-logout-global"

# All statuses are code-owned. Never display raw provider error text.
SAFE_FAILURE_CODES = frozenset({
    "AUTHORITY_INVALID",
    "PLAN_NOT_READY",
    "PROJECT_MISMATCH",
    "WORKFLOW_BINDING_MISMATCH",
    "PREDECESSOR_STATE_INVALID",
    "CLEANUP_FALLBACK_UNAVAILABLE",
    "CREDENTIAL_UNAVAILABLE",
    "ACCESS_JWT_VALIDATION_FAILED",
    "POSITIVE_AUTH_FAILED_LOGOUT_UNVERIFIED",
    "LIVE_PROBE_CREDENTIAL_UNAVAILABLE",
    "LIVE_PROBE_HTTP_STATUS_INVALID",
    "LIVE_PROBE_HTTP_TIMEOUT",
    "LIVE_PROBE_SERVICE_UNAVAILABLE",
    "LIVE_PROBE_RATE_LIMITED",
    "LIVE_PROBE_REDIRECT_REJECTED",
    "LIVE_PROBE_IDENTITY_REJECTED",
    "LIVE_PROBE_AUTHORIZATION_DENIED",
    "LIVE_PROBE_UNEXPECTED_HTTP_STATUS",
    "LIVE_PROBE_RESPONSE_SHAPE_INVALID",
    "LIVE_PROBE_RESPONSE_READ_FAILED",
    "LIVE_PROBE_NETWORK_TIMEOUT",
    "LIVE_PROBE_TLS_FAILURE",
    "LIVE_PROBE_DNS_FAILURE",
    "LIVE_PROBE_CONNECTION_FAILURE",
    "LIVE_PROBE_NETWORK_FAILURE",
    "GLOBAL_SESSION_LOGOUT_PROVIDER_REJECTED",
    "GLOBAL_SESSION_LOGOUT_REQUEST_FAILED",
    "GLOBAL_SESSION_LOGOUT_RESPONSE_INVALID",
})


def _load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        raise AuthorizationPlanStop("PLAN_NOT_READY") from None
    if type(value) is not dict:
        raise AuthorizationPlanStop("PLAN_NOT_READY")
    return value


def _sha(path: Path) -> str:
    try:
        return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    except Exception:
        raise AuthorizationPlanStop("PLAN_NOT_READY") from None


def _check_invocation(env: Mapping[str, str]) -> None:
    exact = {
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_RUN_NUMBER": "1",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_REPOSITORY": "AnonymousKoo/avuhz-infra",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "AVUHZ_ENVIRONMENT": "development",
        "AVUHZ_CONFIRMATION": CONFIRMATION,
    }
    if any(env.get(key) != value for key, value in exact.items()):
        raise AuthorizationPlanStop("WORKFLOW_BINDING_MISMATCH")
    if DEVELOPMENT_AUTH_PROJECT_REF != PROJECT:
        raise AuthorizationPlanStop("PROJECT_MISMATCH")


def _check_fallback(resource: dict[str, Any], moment: str) -> None:
    """Refuse token issuance unless a *separately* approved cleanup lane exists."""
    try:
        plan = _load(BASE / (FALLBACK_BOUNDARY + ".plan.json"))
        approval = _load(BASE / (FALLBACK_BOUNDARY + ".approval.json"))
        progress = _load(BASE / (FALLBACK_BOUNDARY + ".progress.json"))
        validate_plan(plan, SCHEMA_ROOT)
        validate_progress(plan, progress, SCHEMA_ROOT)
        validate_approval(plan, approval, SCHEMA_ROOT, moment)
        operations = [step["operation"] for step in plan["steps"]]
        required = {
            "provider.auth-session-state.inspect-read-only-via-supabase-mcp",
            "provider.auth-admin-credential.delete-dedicated-secret-key",
            "provider.auth-secret-binding.delete-github-environment-reference",
            "provider.auth-admin-credential.verify-dedicated-secret-key-absent",
            "provider.auth-secret-binding.verify-github-environment-reference-absent",
        }
        if (
            plan.get("plan_id") != resource.get("fallback_plan_id")
            or plan.get("plan_digest") != resource.get("fallback_plan_digest")
            or approval.get("approval_digest") != resource.get("fallback_approval_digest")
            or plan.get("environment") != "DEVELOPMENT"
            or plan.get("target", {}).get("project_reference") != PROJECT
            or plan.get("target", {}).get("responsibility") != "AUTH"
            or progress.get("overall_state") != "NOT_STARTED"
            or not required <= set(operations)
        ):
            raise AuthorizationPlanStop("CLEANUP_FALLBACK_UNAVAILABLE")
    except (AuthorizationPlanError, AuthorizationPlanStop):
        raise AuthorizationPlanStop("CLEANUP_FALLBACK_UNAVAILABLE") from None


def _request_for(plan: dict[str, Any], progress: dict[str, Any]) -> dict[str, Any]:
    index = 3
    step = plan["steps"][index]
    required = []
    for item in step["required_evidence"]:
        digest = item["exact_digest"]
        if item["source_step_id"] is not None:
            predecessor = next(
                state for state in progress["step_states"]
                if state["step_id"] == item["source_step_id"]
            )
            matches = [record for record in predecessor["evidence"]
                       if record["evidence_type"] == item["evidence_type"]]
            if len(matches) != 1:
                raise AuthorizationPlanStop("PREDECESSOR_STATE_INVALID")
            digest = matches[0]["evidence_digest"]
        required.append({"evidence_type": item["evidence_type"], "evidence_digest": digest})
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
        "prior_evidence_digests": [
            e["evidence_digest"]
            for state in progress["step_states"][:index] for e in state["evidence"]
        ],
        "unexpected_remote_state": False,
        "extra_privileges": False,
        "unauthorized_migration_surface": False,
        "scope_expansion": False,
    }


def _capability_assertion(moment: str, resource: dict[str, Any]) -> dict[str, Any]:
    config = {
        "executor_reference": "github-actions.development-provider-adapter-positive-auth-v15-step4",
        "environment": "development",
        "project_reference": PROJECT,
        "step_id": STEP_ID,
        "operation": OPERATION,
        "credential_class": "SUPABASE_AUTH_ADMIN_EPHEMERAL",
        "admin_binding_name": ADMIN_ENV,
        "publishable_binding_name": PUBLISHABLE_ENV,
        "executor_source_digest": resource["step4_executor_digest"],
        "workflow_source_digest": resource["step4_workflow_digest"],
        "live_query_url": DEVELOPMENT_QUERY_URL,
    }
    digest = canonical_digest(config)
    return {
        "binding_id": "binding.development.provider-adapter-positive-auth-v15.admin-executor-capability",
        "phase": "RESOLVED_BY_STEP_PREFLIGHT",
        "value_class": "CONFIGURATION_REFERENCE",
        "source_step_id": None,
        "evidence_type": "auth.admin-executor-capability.observed",
        "evidence_digest": digest,
        "digest_policy": "REQUIRED",
        "persistence_policy": "DIGEST_ONLY",
        "sanitized_value": None,
        "value_digest": digest,
        "recorded_at": moment,
    }


def _load_and_authorize(moment: str) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        plan, approval, progress, resource = (
            _load(PLAN_PATH), _load(APPROVAL_PATH), _load(PROGRESS_PATH), _load(RESOURCE_PATH)
        )
        validate_plan(plan, SCHEMA_ROOT)
        validate_progress(plan, progress, SCHEMA_ROOT)
        validate_approval(plan, approval, SCHEMA_ROOT, moment)
        if (
            plan.get("plan_version") != 15
            or plan.get("environment") != "DEVELOPMENT"
            or plan.get("target", {}).get("provider_reference") != "supabase"
            or plan.get("target", {}).get("project_reference") != PROJECT
            or plan.get("target", {}).get("responsibility") != "AUTH"
            or resource.get("project_reference") != PROJECT
            or resource.get("responsibility") != "AUTH"
            or resource.get("fresh_provider_key_reference")
            != "impl_handoff_provider_adapter_positive_auth_v15_ephemeral"
            or resource.get("github_secret_binding_name") != ADMIN_ENV
            or resource.get("live_query_url") != DEVELOPMENT_QUERY_URL
            or resource.get("step4_executor_digest") != _sha(Path(__file__))
            or resource.get("step4_workflow_digest") != _sha(WORKFLOW_PATH)
            or resource.get("step4_probe_digest") != _sha(
                ROOT / "scripts/development_provider_adapter_live_identity_probe_v15.py"
            )
            or resource.get("contract_digest") != canonical_digest({
                k: v for k, v in resource.items() if k != "contract_digest"
            })
            or resource.get("retry_authorized") is not False
            or resource.get("implementation_handoff_execution_authorized") is not False
            or resource.get("data_operation_authorized") is not False
            or resource.get("render_mutation_authorized") is not False
            or resource.get("production_authorized") is not False
        ):
            raise AuthorizationPlanStop("PLAN_NOT_READY")
        steps = plan.get("steps", [])
        states = progress.get("step_states", [])
        if (
            len(steps) != 9 or len(states) != 9
            or steps[3].get("step_id") != STEP_ID
            or steps[3].get("operation") != OPERATION
            or steps[3].get("execution_class") != "PROVIDER_MUTATION"
            or steps[3].get("credential_policy", {}).get("allowed_classes")
            != ["SUPABASE_AUTH_ADMIN_EPHEMERAL"]
            or steps[3].get("resource", {}).get("exact_digest") != resource["contract_digest"]
            or not any(
                decl.get("binding_id")
                == "binding.development.provider-adapter-positive-auth-v15.admin-executor-capability"
                and decl.get("phase") == "RESOLVED_BY_STEP_PREFLIGHT"
                for decl in steps[3].get("binding_declarations", [])
            )
        ):
            raise AuthorizationPlanStop("PLAN_NOT_READY")
        if any(
            (s["authorization_state"], s["execution_state"], s["verification_state"],
             s["authorization_consumed"]) != ("CONSUMED", "SUCCEEDED", "PASS", True)
            for s in states[:3]
        ) or any(
            s["authorization_state"] != "PENDING"
            or s["execution_state"] != "NOT_STARTED"
            or s["authorization_consumed"] is not False
            for s in states[3:]
        ):
            raise AuthorizationPlanStop("PREDECESSOR_STATE_INVALID")
        _check_fallback(resource, moment)
        authorized = authorize_step(
            plan, approval, progress, _request_for(plan, progress),
            SCHEMA_ROOT, moment,
            trusted_preflight_assertions=[_capability_assertion(moment, resource)],
        )
        if (
            authorized["step_states"][3]["authorization_state"] != "AUTHORIZED"
            or authorized["step_states"][3]["authorization_consumed"] is not False
        ):
            raise AuthorizationPlanStop("PLAN_NOT_READY")
        return plan, authorized
    except (AuthorizationPlanError, AuthorizationPlanStop) as exc:
        safe = str(exc)
        raise AuthorizationPlanStop(safe if safe in SAFE_FAILURE_CODES else "AUTHORITY_INVALID") from None
    except Exception:
        raise AuthorizationPlanStop("AUTHORITY_INVALID") from None


def execute_positive_auth(**overrides) -> dict[str, Any]:
    """One shared lifecycle; v15 replaces only the live response classifier."""
    opener = urllib.request.build_opener(
        historical._RejectRedirects(), urllib.request.ProxyHandler({})
    ).open
    defaults = {
        "generate": partial(shared.request_generate_recovery_credential, urlopen=opener),
        "verify": partial(shared.request_direct_recovery_verification, urlopen=opener),
        "validate_jwt": shared.validate_development_provider_adapter_access_jwt,
        "live_probe": authenticated_live_identity_probe,
        "logout_global": partial(shared.request_global_session_logout, urlopen=opener),
    }
    defaults.update(overrides)
    result = shared.execute_positive_auth(**defaults)
    result["credential_retirement_required"] = True
    result["github_binding_retirement_required"] = True
    result["session_state_readback_required"] = True
    return result


def _safe_failure(code: str, *, attempted: bool) -> int:
    safe = code if code in SAFE_FAILURE_CODES else "AUTHORITY_INVALID"
    print(json.dumps({
        "classification": "PROVIDER_ADAPTER_POSITIVE_AUTH_UNVERIFIED",
        "safe_error_code": safe,
        "failure_stage": "live_runtime_probe" if safe.startswith("LIVE_PROBE_") else "authorization_or_lifecycle",
        "provider_mutation_attempted": attempted,
        "session_state_readback_required": attempted,
        "credential_retirement_required": True,
        "github_binding_retirement_required": True,
        "cleanup_verified": False,
        "retry_authorized": False,
        "implementation_handoff_attempted": False,
        "credential_material_retained": False,
        "token_material_retained": False,
        "pii_retained": False,
    }, sort_keys=True))
    return 1


def main(environment: Mapping[str, str] | None = None, *, preflight_only: bool = False) -> int:
    env = os.environ if environment is None else environment
    admin_secret = publishable_key = None
    attempted = False
    try:
        _check_invocation(env)
        _load_and_authorize(shared._now())
        if preflight_only:
            print(json.dumps({"preflight": "PASS", "step_id": STEP_ID}, sort_keys=True))
            return 0
        admin_secret = env.get(ADMIN_ENV)
        publishable_key = env.get(PUBLISHABLE_ENV)
        if (
            type(admin_secret) is not str or not admin_secret.startswith("sb_secret_")
            or len(admin_secret) < 26 or type(publishable_key) is not str
            or not publishable_key.startswith("sb_publishable_")
            or len(publishable_key) < 31
        ):
            raise AuthorizationPlanStop("CREDENTIAL_UNAVAILABLE")
        attempted = True
        print(json.dumps(execute_positive_auth(
            admin_secret=admin_secret, publishable_key=publishable_key
        ), sort_keys=True))
        return 0
    except (AuthorizationPlanError, AuthorizationPlanStop) as exc:
        return _safe_failure(str(exc), attempted=attempted)
    except SafeLifecycleStop as exc:
        return _safe_failure(exc.code, attempted=attempted)
    except Exception:
        return _safe_failure("AUTHORITY_INVALID", attempted=attempted)
    finally:
        admin_secret = publishable_key = None


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--preflight-only", action="store_true")
    raise SystemExit(main(preflight_only=parser.parse_args().preflight_only))
