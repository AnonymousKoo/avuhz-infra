#!/usr/bin/env python3
"""Forward-only DEVELOPMENT AUTH corrective continuation for v14 Step 5.

The original v14 workflow failed closed before secret resolution because the
v14 plan exceeds the current schema's required_evidence maxItems on Steps 1
and 4. This continuation never retries that workflow. It reuses the already
created v14 ephemeral key and GitHub binding, binds immutable v14 Steps 1-4
evidence plus the preflight-failure record, and authorizes exactly one fresh
continuation lifecycle attempt before mandatory readback and retirement.
"""
from __future__ import annotations

import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from scripts import development_provider_adapter_positive_auth_v14 as original
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
from avuhz_engineering.development_auth_token_lifecycle import SafeLifecycleStop
from avuhz_engineering.evidence_digest import evidence_digest
from avuhz_runtime.implementation_handoff import canonical_digest
from avuhz_service.development import DEVELOPMENT_AUTH_PROJECT_REF

ROOT = original.ROOT
BASE = original.BASE
SCHEMA_ROOT = original.SCHEMA_ROOT
BOUNDARY = "development-implementation-handoff-provider-adapter-positive-auth-v14-continuation-v1"
PLAN_PATH = BASE / f"{BOUNDARY}.plan.json"
APPROVAL_PATH = BASE / f"{BOUNDARY}.approval.json"
PROGRESS_PATH = BASE / f"{BOUNDARY}.progress.json"
RESOURCE_PATH = BASE / f"{BOUNDARY}.resource.json"
WORKFLOW_PATH = ROOT / ".github/workflows/development-provider-adapter-positive-auth-v14-continuation-v1-step1.yml"
STEP_ID = BOUNDARY + ".step.01.authenticate-live-and-logout-global"
PROJECT = "pwlhruwutoitnieactol"
ADMIN_ENV = "AVUHZ_DEVELOPMENT_SUPABASE_AUTH_PROVIDER_ADAPTER_POSITIVE_AUTH_V14_EPHEMERAL"
PUBLISHABLE_ENV = "AVUHZ_DEVELOPMENT_SUPABASE_PUBLISHABLE_KEY"
CONFIRMATION = "RUN_PROVIDER_ADAPTER_POSITIVE_AUTH_V14_CONTINUATION_V1_STEP1"

ORIGINAL_BOUNDARY = "development-implementation-handoff-provider-adapter-positive-auth-v14"
ORIGINAL_PLAN_DIGEST = "sha256:8da4655cf8167a661935f88e340fe51d7da1821db807e9254ffca88b8b9ef47f"
ORIGINAL_APPROVAL_DIGEST = "sha256:9410d2e10b6fd7febe0d2c0d873608d54bdd1e9ca7c9da0e8aeec631847d36e0"
ORIGINAL_PROGRESS_DIGEST = "sha256:4d3e44ca05339f980bbf5cced174f67f70d992b70456e9a94a64668ec643a096"
ORIGINAL_STEP_EVIDENCE = (
    "sha256:d4aff55bac16e73efc867b327ef88eab79fd3f0db6dcac04fd82233e34cf1b18",
    "sha256:62ee203e20be12f515e698cd69a10ced3422f46eb4b7f21e67ba157fc53adab1",
    "sha256:3590b89ce68436bb0109025b08869d7a4184a7207f65b52b67dca38e9d9395e0",
    "sha256:a81f43f32718325822785e6c246f90f9f161e93a3b377301ba83a607c7e3b8b2",
)
ORIGINAL_FAILURE_EVIDENCE = "sha256:ddd3884f1edebc06d2c608a066146235c5864d10680e95a277140fb04261c1bc"


def _deny(code: str = "AUTHORITY_INVALID") -> None:
    raise AuthorizationPlanStop(code)


def _validate_invocation(env: Mapping[str, str]) -> None:
    expected = {
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_RUN_NUMBER": "1",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_REPOSITORY": "AnonymousKoo/avuhz-infra",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "AVUHZ_ENVIRONMENT": "development",
        "AVUHZ_CONFIRMATION": CONFIRMATION,
    }
    if any(env.get(key) != value for key, value in expected.items()):
        _deny("WORKFLOW_BINDING_MISMATCH")
    if DEVELOPMENT_AUTH_PROJECT_REF != PROJECT:
        _deny("PROJECT_MISMATCH")


def _validate_original_v14(resource: dict[str, Any]) -> None:
    plan = original.prior._load(BASE / f"{ORIGINAL_BOUNDARY}.plan.json")
    approval = original.prior._load(BASE / f"{ORIGINAL_BOUNDARY}.approval.json")
    progress = original.prior._load(BASE / f"{ORIGINAL_BOUNDARY}.execution-progress.json")
    failure = original.prior._load(
        BASE / f"{ORIGINAL_BOUNDARY}-step05-authorization-preflight-failure.evidence.json"
    )
    if (
        plan.get("plan_id") != "6ea08c43-5f97-4db2-b341-8f4e7c9a2d60"
        or plan.get("plan_version") != 14
        or plan.get("plan_digest") != ORIGINAL_PLAN_DIGEST
        or plan_digest(plan) != ORIGINAL_PLAN_DIGEST
        or approval.get("approval_id") != "8c5f3d72-7e46-4a9b-b231-0d6e4f8a5c73"
        or approval.get("approval_digest") != ORIGINAL_APPROVAL_DIGEST
        or approval_digest(approval) != ORIGINAL_APPROVAL_DIGEST
        or progress.get("progress_digest") != ORIGINAL_PROGRESS_DIGEST
        or progress_digest(progress) != ORIGINAL_PROGRESS_DIGEST
        or progress.get("overall_state") != "IN_PROGRESS"
        or evidence_digest(failure) != ORIGINAL_FAILURE_EVIDENCE
        or failure.get("outcome") != "FAILED_CLOSED_BEFORE_SECRET_RESOLUTION"
        or failure.get("root_cause_safe_code") != "SCHEMA_INVALID"
        or failure.get("execution_observation", {}).get("secret_resolution_attempted") is not False
        or failure.get("execution_observation", {}).get("provider_mutation_attempted") is not False
        or failure.get("execution_observation", {}).get("session_issued") is not False
        or failure.get("execution_observation", {}).get("token_issued") is not False
    ):
        _deny("PREDECESSOR_STATE_INVALID")
    states = progress.get("step_states", [])
    if len(states) != 10:
        _deny("PREDECESSOR_STATE_INVALID")
    for index, expected_digest in enumerate(ORIGINAL_STEP_EVIDENCE):
        state = states[index]
        if (
            (
                state.get("authorization_state"),
                state.get("execution_state"),
                state.get("verification_state"),
                state.get("authorization_consumed"),
            )
            != ("CONSUMED", "SUCCEEDED", "PASS", True)
            or len(state.get("evidence", [])) != 1
            or state["evidence"][0].get("evidence_digest") != expected_digest
        ):
            _deny("PREDECESSOR_STATE_INVALID")
    if any(
        (
            state.get("authorization_state"),
            state.get("execution_state"),
            state.get("verification_state"),
            state.get("authorization_consumed"),
        )
        != ("PENDING", "NOT_STARTED", "NOT_STARTED", False)
        for state in states[4:]
    ):
        _deny("PREDECESSOR_STATE_INVALID")
    if (
        resource.get("required_v14_plan_digest") != ORIGINAL_PLAN_DIGEST
        or resource.get("required_v14_approval_digest") != ORIGINAL_APPROVAL_DIGEST
        or resource.get("required_v14_steps1_4_progress_digest") != ORIGINAL_PROGRESS_DIGEST
        or resource.get("required_v14_step5_preflight_failure_evidence_digest")
        != ORIGINAL_FAILURE_EVIDENCE
    ):
        _deny("PREDECESSOR_BINDING_MISMATCH")


def _validate_boundary(plan: dict[str, Any], resource: dict[str, Any], progress: dict[str, Any]) -> None:
    if (
        resource.get("contract_digest")
        != canonical_digest({k: v for k, v in resource.items() if k != "contract_digest"})
        or resource.get("project_reference") != PROJECT
        or resource.get("responsibility") != "AUTH"
        or resource.get("fresh_provider_key_reference")
        != "impl_handoff_provider_adapter_positive_auth_v14_ephemeral"
        or resource.get("github_secret_binding_name") != ADMIN_ENV
        or resource.get("fresh_auth_admin_key_create_count_authorized") != 0
        or resource.get("github_secret_binding_create_count_authorized") != 0
        or resource.get("fresh_auth_admin_key_delete_count_authorized") != 1
        or resource.get("github_secret_binding_delete_count_authorized") != 1
        or resource.get("temporary_session_issue_count_authorized") != 1
        or resource.get("temporary_token_validation_count_authorized") != 1
        or resource.get("live_runtime_identity_probe_count_authorized") != 1
        or resource.get("global_logout_count_authorized") != 1
        or resource.get("retry_authorized") is not False
        or resource.get("implementation_handoff_execution_authorized") is not False
        or resource.get("data_operation_authorized") is not False
        or resource.get("render_mutation_authorized") is not False
        or resource.get("n8n_operation_authorized") is not False
        or resource.get("staging_authorized") is not False
        or resource.get("production_authorized") is not False
        or resource.get("step1_executor_digest") != original.prior._raw_digest(Path(__file__))
        or resource.get("step1_workflow_digest") != original.prior._raw_digest(WORKFLOW_PATH)
    ):
        _deny()
    _validate_original_v14(resource)
    window = plan.get("authorization_window", {})
    rules = resource.get("execution_rules", {})
    if (
        plan.get("environment") != "DEVELOPMENT"
        or plan.get("target", {}).get("project_reference") != PROJECT
        or plan.get("target", {}).get("responsibility") != "AUTH"
        or plan.get("target", {}).get("provider_reference") != "supabase"
        or window.get("starts_at") != rules.get("owner_approval_deadline")
        or window.get("expires_at") != rules.get("window_expiry")
    ):
        _deny()
    steps = plan.get("steps", [])
    if len(steps) != 6 or steps[0].get("step_id") != STEP_ID:
        _deny("PLAN_STATE_INVALID")
    if any(step.get("resource", {}).get("exact_digest") != resource["contract_digest"] for step in steps):
        _deny()
    if any(
        step.get("resource", {}).get("exact_version")
        != "provider-adapter-positive-auth-v14-continuation.v1"
        for step in steps
    ):
        _deny("PLAN_STATE_INVALID")
    if (
        steps[0].get("operation")
        != "provider.auth-session.provider-adapter-recover-validate-live-probe-and-logout-global"
        or steps[0].get("execution_class") != "PROVIDER_MUTATION"
        or steps[0].get("credential_policy", {}).get("allowed_classes")
        != ["SUPABASE_AUTH_ADMIN_EPHEMERAL"]
    ):
        _deny("PLAN_STATE_INVALID")
    states = progress.get("step_states", [])
    if len(states) != 6 or progress.get("overall_state") != "NOT_STARTED":
        _deny("PLAN_STATE_INVALID")
    if any(
        state.get("authorization_state") != "PENDING"
        or state.get("execution_state") != "NOT_STARTED"
        or state.get("verification_state") != "NOT_STARTED"
        or state.get("authorization_consumed") is not False
        for state in states
    ):
        _deny("PLAN_STATE_INVALID")


def _request_for(plan: dict[str, Any]) -> dict[str, Any]:
    step = plan["steps"][0]
    required = [
        {"evidence_type": item["evidence_type"], "evidence_digest": item["exact_digest"]}
        for item in step["required_evidence"]
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
        "step_id": STEP_ID,
        "resource_reference": step["resource"]["resource_reference"],
        "resource_version": step["resource"]["exact_version"],
        "resource_digest": step["resource"]["exact_digest"],
        "operation": step["operation"],
        "execution_class": step["execution_class"],
        "credential_class": "SUPABASE_AUTH_ADMIN_EPHEMERAL",
        "required_evidence": required,
        "prior_evidence_digests": [],
        "unexpected_remote_state": False,
        "extra_privileges": False,
        "unauthorized_migration_surface": False,
        "scope_expansion": False,
    }


def _capability_assertion(moment: str, resource: dict[str, Any]) -> dict[str, Any]:
    config = {
        "executor_reference": "github-actions.development-provider-adapter-positive-auth-v14-continuation-v1-step1",
        "environment": "development",
        "project_reference": PROJECT,
        "step_id": STEP_ID,
        "operation": "provider.auth-session.provider-adapter-recover-validate-live-probe-and-logout-global",
        "credential_class": "SUPABASE_AUTH_ADMIN_EPHEMERAL",
        "admin_binding_name": ADMIN_ENV,
        "publishable_binding_name": PUBLISHABLE_ENV,
        "executor_source_digest": resource["step1_executor_digest"],
        "workflow_source_digest": resource["step1_workflow_digest"],
        "live_query_url": original.LIVE_QUERY_URL,
    }
    digest = canonical_digest(config)
    return {
        "binding_id": "binding.development.provider-adapter-positive-auth-v14-continuation-v1.admin-executor-capability",
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
        plan = original.prior._load(PLAN_PATH)
        approval = original.prior._load(APPROVAL_PATH)
        progress = original.prior._load(PROGRESS_PATH)
        resource = original.prior._load(RESOURCE_PATH)
        validate_plan(plan, SCHEMA_ROOT)
        validate_progress(plan, progress, SCHEMA_ROOT)
        validate_approval(plan, approval, SCHEMA_ROOT, moment)
        _validate_boundary(plan, resource, progress)
        authorized = authorize_step(
            plan,
            approval,
            progress,
            _request_for(plan),
            SCHEMA_ROOT,
            moment,
            trusted_preflight_assertions=[_capability_assertion(moment, resource)],
        )
    except (AuthorizationPlanError, AuthorizationPlanStop):
        raise AuthorizationPlanStop("AUTHORITY_INVALID") from None
    state = authorized["step_states"][0]
    if state["authorization_state"] != "AUTHORIZED" or state["authorization_consumed"] is not False:
        _deny()
    return plan, authorized


def execute_positive_auth(**overrides) -> dict[str, Any]:
    return original.execute_positive_auth(**overrides)


def main(environment: Mapping[str, str] | None = None, *, preflight_only: bool = False) -> int:
    env = os.environ if environment is None else environment
    attempted = False
    admin_secret = publishable_key = None
    try:
        _validate_invocation(env)
        _load_and_authorize(original.prior._now())
        if preflight_only:
            print(json.dumps({"preflight": "PASS", "step_id": STEP_ID}, sort_keys=True))
            return 0
        admin_secret = env.get(ADMIN_ENV)
        publishable_key = env.get(PUBLISHABLE_ENV)
        if (
            not isinstance(admin_secret, str)
            or not admin_secret.startswith("sb_secret_")
            or len(admin_secret) < 26
            or not isinstance(publishable_key, str)
            or not publishable_key.startswith("sb_publishable_")
            or len(publishable_key) < 31
        ):
            raise AuthorizationPlanStop("CREDENTIAL_UNAVAILABLE")
        attempted = True
        result = execute_positive_auth(
            admin_secret=admin_secret,
            publishable_key=publishable_key,
        )
        print(json.dumps(result, sort_keys=True))
        return 0
    except (AuthorizationPlanError, AuthorizationPlanStop) as exc:
        return original._safe_failure(str(exc), provider_mutation_attempted=attempted)
    except SafeLifecycleStop as exc:
        return original._safe_failure(exc.code, provider_mutation_attempted=attempted)
    except Exception:
        return original._safe_failure("AUTHORITY_INVALID", provider_mutation_attempted=attempted)
    finally:
        admin_secret = publishable_key = None


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--preflight-only", action="store_true")
    raise SystemExit(main(preflight_only=parser.parse_args().preflight_only))
