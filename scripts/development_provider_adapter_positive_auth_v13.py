#!/usr/bin/env python3
"""Forward-only DEVELOPMENT provider-adapter positive authentication v13 executor.

Historical provider-adapter positive-auth plans and evidence remain immutable.
This executor may run only after v13 Steps 1-4 are independently completed
under exact authority. It binds the current clean predecessor state, rejects
redirects, emits only bounded sanitized failure telemetry, and never executes
ImplementationHandoff.
"""
from __future__ import annotations

import json
import os
import urllib.request
from collections.abc import Mapping
from functools import partial
from pathlib import Path
from typing import Any

from scripts import development_provider_adapter_positive_auth_v4 as prior
from avuhz_engineering.authorization_plan import (
    AuthorizationPlanError,
    AuthorizationPlanStop,
    authorize_step,
    validate_approval,
    validate_plan,
    validate_progress,
)
from avuhz_engineering.development_auth_token_lifecycle import SafeLifecycleStop
from avuhz_engineering.evidence_digest import evidence_digest
from avuhz_engineering.safe_auth_failure_diagnostics import sanitized_positive_auth_failure
from avuhz_runtime.implementation_handoff import canonical_digest
from avuhz_service.development import DEVELOPMENT_AUTH_PROJECT_REF

ROOT = prior.ROOT
BASE = prior.BASE
SCHEMA_ROOT = prior.SCHEMA_ROOT
BOUNDARY = "development-implementation-handoff-provider-adapter-positive-auth-v13"
PLAN_PATH = BASE / f"{BOUNDARY}.plan.json"
APPROVAL_PATH = BASE / f"{BOUNDARY}.approval.json"
EXECUTION_PROGRESS_PATH = BASE / f"{BOUNDARY}.execution-progress.json"
RESOURCE_PATH = BASE / f"{BOUNDARY}.resource.json"
STEP_ID = "development.implementation-handoff.provider-adapter-positive-auth-v13.step.05.authenticate-live-and-logout-global"
PROJECT = "pwlhruwutoitnieactol"
ADMIN_ENV = "AVUHZ_DEVELOPMENT_SUPABASE_AUTH_PROVIDER_ADAPTER_POSITIVE_AUTH_V13_EPHEMERAL"
PUBLISHABLE_ENV = "AVUHZ_DEVELOPMENT_SUPABASE_PUBLISHABLE_KEY"
CONFIRMATION = "RUN_PROVIDER_ADAPTER_POSITIVE_AUTH_V13_STEP5"
LIVE_QUERY_URL = "https://avuhz-command-dev.onrender.com/v1/queries"
WORKFLOW_PATH = ROOT / ".github/workflows/development-provider-adapter-positive-auth-v13-step5.yml"

PREDECESSOR_BOUNDARY = "development-implementation-handoff-provider-adapter-positive-auth-v6"
PREDECESSOR_RETIREMENT = "development-implementation-handoff-provider-adapter-positive-auth-v6-key-retirement-v4"
V4_BINDING_RECONCILIATION = (
    "development-implementation-handoff-provider-adapter-positive-auth-v4-github-binding-absence-reconciliation-v1"
)
V7_LATE_REJECTION = (
    "development-implementation-handoff-provider-adapter-positive-auth-v7-late-window-rejection"
)
V8_STOPPED_BOUNDARY = (
    "development-implementation-handoff-provider-adapter-positive-auth-v8"
)
V8_RETIREMENT = (
    "development-implementation-handoff-provider-adapter-positive-auth-v8-key-retirement-v2"
)
V9_STOPPED_BOUNDARY = (
    "development-implementation-handoff-provider-adapter-positive-auth-v9"
)
V9_RETIREMENT = (
    "development-implementation-handoff-provider-adapter-positive-auth-v9-key-retirement-v1"
)
V10_STOPPED_BOUNDARY = (
    "development-implementation-handoff-provider-adapter-positive-auth-v10"
)
V10_RETIREMENT_V1 = (
    "development-implementation-handoff-provider-adapter-positive-auth-v10-key-retirement-v1"
)
V10_RETIREMENT_V2 = (
    "development-implementation-handoff-provider-adapter-positive-auth-v10-key-retirement-v2"
)
V11_LATE_REJECTION = (
    "development-implementation-handoff-provider-adapter-positive-auth-v11-late-window-rejection"
)
V12_LATE_REJECTION = (
    "development-implementation-handoff-provider-adapter-positive-auth-v12-late-window-rejection"
)


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


def _validate_predecessor_state(resource: dict[str, Any]) -> None:
    stopped = prior._load(BASE / f"{PREDECESSOR_BOUNDARY}.execution-progress.json")
    stop_evidence = prior._load(
        BASE / f"{PREDECESSOR_BOUNDARY}-step02-plan-integrity-failure.evidence.json"
    )
    retired = prior._load(BASE / f"{PREDECESSOR_RETIREMENT}.execution-progress.json")
    key_absence = prior._load(BASE / f"{PREDECESSOR_RETIREMENT}-step2-success.evidence.json")
    github_absence = prior._load(BASE / f"{PREDECESSOR_RETIREMENT}-step3-success.evidence.json")
    reconciled = prior._load(BASE / f"{V4_BINDING_RECONCILIATION}.execution-progress.json")
    reconciliation_evidence = prior._load(
        BASE / f"{V4_BINDING_RECONCILIATION}-step1-success.evidence.json"
    )
    v7_late_rejection = prior._load(BASE / f"{V7_LATE_REJECTION}.evidence.json")
    v8_stopped = prior._load(BASE / f"{V8_STOPPED_BOUNDARY}.execution-progress.json")
    v8_retired = prior._load(BASE / f"{V8_RETIREMENT}.execution-progress.json")
    v8_key_absence = prior._load(BASE / f"{V8_RETIREMENT}-step1-success.evidence.json")
    v8_github_absence = prior._load(BASE / f"{V8_RETIREMENT}-step2-success.evidence.json")
    v9_stopped = prior._load(BASE / f"{V9_STOPPED_BOUNDARY}.execution-progress.json")
    v9_retired = prior._load(BASE / f"{V9_RETIREMENT}.execution-progress.json")
    v9_key_absence = prior._load(BASE / f"{V9_RETIREMENT}-step2-success.evidence.json")
    v9_github_absence = prior._load(BASE / f"{V9_RETIREMENT}-step4-success.evidence.json")
    v10_stopped = prior._load(BASE / f"{V10_STOPPED_BOUNDARY}.execution-progress.json")
    v10_failure = prior._load(
        BASE / f"{V10_STOPPED_BOUNDARY}-step05-plan-integrity-failure.evidence.json"
    )
    v10_retirement_v1 = prior._load(BASE / f"{V10_RETIREMENT_V1}.execution-progress.json")
    v10_key_retired = prior._load(BASE / f"{V10_RETIREMENT_V1}-step1-success.evidence.json")
    v10_key_absence = prior._load(BASE / f"{V10_RETIREMENT_V1}-step2-success.evidence.json")
    v10_post_window = prior._load(
        BASE / f"{V10_RETIREMENT_V1}-post-window-github-outcome.evidence.json"
    )
    v10_retirement_v2 = prior._load(BASE / f"{V10_RETIREMENT_V2}.execution-progress.json")
    v10_github_absence = prior._load(BASE / f"{V10_RETIREMENT_V2}-step1-success.evidence.json")
    v11_late_rejection = prior._load(BASE / f"{V11_LATE_REJECTION}.evidence.json")
    v12_late_rejection = prior._load(BASE / f"{V12_LATE_REJECTION}.evidence.json")

    if (
        stopped.get("overall_state") != "STOPPED"
        or stopped.get("progress_digest")
        != resource.get("required_v6_stopped_progress_digest")
        or evidence_digest(stop_evidence)
        != resource.get("required_v6_plan_integrity_failure_evidence_digest")
        or retired.get("overall_state") != "COMPLETED"
        or retired.get("progress_digest")
        != resource.get("required_v6_retirement_progress_digest")
        or evidence_digest(key_absence)
        != resource.get("required_v6_key_absence_evidence_digest")
        or evidence_digest(github_absence)
        != resource.get("required_v6_github_absence_evidence_digest")
        or reconciled.get("overall_state") != "COMPLETED"
        or reconciled.get("progress_digest")
        != resource.get("required_v4_binding_reconciliation_progress_digest")
        or evidence_digest(reconciliation_evidence)
        != resource.get("required_v4_binding_reconciliation_evidence_digest")
        or evidence_digest(v7_late_rejection)
        != resource.get("required_v7_late_rejection_evidence_digest")
        or v7_late_rejection.get("outcome")
        != "REJECTED_LATE_APPROVAL_NONCANONICALIZABLE"
        or v7_late_rejection.get("approval_artifact_created") is not False
        or v7_late_rejection.get("approval_canonicalized") is not False
        or v8_stopped.get("overall_state") != "STOPPED"
        or v8_stopped.get("progress_digest")
        != resource.get("required_v8_stopped_progress_digest")
        or v8_retired.get("overall_state") != "COMPLETED"
        or v8_retired.get("progress_digest")
        != resource.get("required_v8_retirement_progress_digest")
        or evidence_digest(v8_key_absence)
        != resource.get("required_v8_key_absence_evidence_digest")
        or evidence_digest(v8_github_absence)
        != resource.get("required_v8_github_absence_evidence_digest")
        or v9_stopped.get("overall_state") != "STOPPED"
        or v9_stopped.get("progress_digest")
        != resource.get("required_v9_stopped_progress_digest")
        or v9_retired.get("overall_state") != "COMPLETED"
        or v9_retired.get("progress_digest")
        != resource.get("required_v9_retirement_progress_digest")
        or evidence_digest(v9_key_absence)
        != resource.get("required_v9_key_absence_evidence_digest")
        or evidence_digest(v9_github_absence)
        != resource.get("required_v9_github_absence_evidence_digest")
        or v10_stopped.get("overall_state") != "STOPPED"
        or v10_stopped.get("progress_digest")
        != resource.get("required_v10_stopped_progress_digest")
        or evidence_digest(v10_failure)
        != resource.get("required_v10_plan_integrity_failure_evidence_digest")
        or v10_failure.get("safe_error_code") != "PLAN_STATE_INVALID"
        or v10_failure.get("sanitized_result", {}).get("provider_mutation_performed") is not False
        or v10_retirement_v1.get("overall_state") != "IN_PROGRESS"
        or v10_retirement_v1.get("progress_digest")
        != resource.get("required_v10_retirement_v1_progress_digest")
        or any(
            (
                state.get("authorization_state"),
                state.get("execution_state"),
                state.get("verification_state"),
                state.get("authorization_consumed"),
            )
            != ("CONSUMED", "SUCCEEDED", "PASS", True)
            for state in v10_retirement_v1.get("step_states", [])[:2]
        )
        or any(
            state.get("authorization_state") != "PENDING"
            or state.get("execution_state") != "NOT_STARTED"
            or state.get("verification_state") != "NOT_STARTED"
            or state.get("authorization_consumed") is not False
            for state in v10_retirement_v1.get("step_states", [])[2:]
        )
        or evidence_digest(v10_key_retired)
        != resource.get("required_v10_key_retirement_evidence_digest")
        or evidence_digest(v10_key_absence)
        != resource.get("required_v10_key_absence_evidence_digest")
        or evidence_digest(v10_post_window)
        != resource.get("required_v10_post_window_github_outcome_evidence_digest")
        or v10_post_window.get("authorization_assessment", {}).get(
            "retirement_v1_execution_progress_may_be_retroactively_advanced"
        ) is not False
        or v10_post_window.get("authorization_assessment", {}).get(
            "fresh_forward_only_v2_absence_reconciliation_required"
        ) is not True
        or v10_retirement_v2.get("overall_state") != "COMPLETED"
        or v10_retirement_v2.get("progress_digest")
        != resource.get("required_v10_retirement_v2_progress_digest")
        or evidence_digest(v10_github_absence)
        != resource.get("required_v10_github_absence_evidence_digest")
        or evidence_digest(v11_late_rejection)
        != resource.get("required_v11_late_rejection_evidence_digest")
        or v11_late_rejection.get("outcome")
        != "REJECTED_LATE_APPROVAL_NONCANONICALIZABLE"
        or v11_late_rejection.get("approval_artifact_created") is not False
        or v11_late_rejection.get("approval_canonicalized") is not False
        or evidence_digest(v12_late_rejection)
        != resource.get("required_v12_late_rejection_evidence_digest")
        or v12_late_rejection.get("outcome")
        != "REJECTED_LATE_APPROVAL_NONCANONICALIZABLE"
        or v12_late_rejection.get("approval_artifact_created") is not False
        or v12_late_rejection.get("approval_canonicalized") is not False
    ):
        _deny("PLAN_STATE_INVALID")


def _validate_boundary(plan: dict[str, Any], resource: dict[str, Any], progress: dict[str, Any]) -> None:
    if (
        resource.get("contract_digest")
        != canonical_digest({k: v for k, v in resource.items() if k != "contract_digest"})
        or resource.get("project_reference") != PROJECT
        or resource.get("responsibility") != "AUTH"
        or resource.get("fresh_provider_key_reference")
        != "impl_handoff_provider_adapter_positive_auth_v13_ephemeral"
        or resource.get("github_secret_binding_name") != ADMIN_ENV
        or resource.get("step5_executor_digest") != prior._raw_digest(Path(__file__))
        or resource.get("step5_workflow_digest") != prior._raw_digest(WORKFLOW_PATH)
        or resource.get("evidence_digest_source_digest")
        != prior._raw_digest(ROOT / "src/avuhz_engineering/evidence_digest.py")
        or resource.get("failure_diagnostics_source_digest")
        != prior._raw_digest(ROOT / "src/avuhz_engineering/safe_auth_failure_diagnostics.py")
        or resource.get("retry_authorized") is not False
        or resource.get("implementation_handoff_execution_authorized") is not False
        or resource.get("data_operation_authorized") is not False
        or resource.get("render_mutation_authorized") is not False
        or resource.get("n8n_operation_authorized") is not False
        or resource.get("staging_authorized") is not False
        or resource.get("production_authorized") is not False
    ):
        _deny()

    _validate_predecessor_state(resource)

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
    if len(steps) != 10 or steps[4].get("step_id") != STEP_ID:
        _deny("PLAN_STATE_INVALID")
    if any(
        step.get("resource", {}).get("exact_digest") != resource["contract_digest"]
        for step in steps
    ):
        _deny()
    if any(
        step.get("resource", {}).get("exact_version")
        != "provider-adapter-positive-auth.v13"
        for step in steps
    ):
        _deny("PLAN_STATE_INVALID")

    for index in (3, 5):
        step = steps[index]
        if (
            step.get("operation")
            not in {
                "provider.auth-state.inspect-aggregate-only-via-supabase-mcp",
                "provider.auth-session-state.inspect-read-only-via-supabase-mcp",
            }
            or step.get("execution_class") != "PROVIDER_READ"
            or step.get("credential_policy")
            != {"permitted": False, "allowed_classes": ["NONE"], "values_stored": False}
        ):
            _deny()

    fifth = steps[4]
    allowed = fifth.get("credential_policy", {}).get("allowed_classes")
    if (
        fifth.get("operation")
        != "provider.auth-session.provider-adapter-recover-validate-live-probe-and-logout-global"
        or fifth.get("execution_class") != "PROVIDER_MUTATION"
        or allowed != ["SUPABASE_AUTH_ADMIN_EPHEMERAL"]
    ):
        _deny()

    states = progress.get("step_states", [])
    if len(states) != 10 or progress.get("overall_state") != "IN_PROGRESS":
        _deny("PLAN_STATE_INVALID")
    for state in states[:4]:
        if (
            state.get("authorization_state"),
            state.get("execution_state"),
            state.get("verification_state"),
            state.get("authorization_consumed"),
        ) != ("CONSUMED", "SUCCEEDED", "PASS", True):
            _deny("PLAN_STATE_INVALID")
    fifth_state = states[4]
    if (
        fifth_state.get("step_id") != STEP_ID
        or (
            fifth_state.get("authorization_state"),
            fifth_state.get("execution_state"),
            fifth_state.get("verification_state"),
            fifth_state.get("authorization_consumed"),
        )
        != ("PENDING", "NOT_STARTED", "NOT_STARTED", False)
        or any(
            state.get("authorization_state") != "PENDING"
            or state.get("execution_state") != "NOT_STARTED"
            or state.get("verification_state") != "NOT_STARTED"
            or state.get("authorization_consumed") is not False
            for state in states[5:]
        )
    ):
        _deny("PLAN_STATE_INVALID")


def _request_for(plan: dict[str, Any], progress: dict[str, Any]) -> dict[str, Any]:
    step = plan["steps"][4]
    required: list[dict[str, str]] = []
    for item in step["required_evidence"]:
        if item["binding_state"] == "BOUND":
            digest = item["exact_digest"]
        else:
            source = next(
                state
                for state in progress["step_states"]
                if state["step_id"] == item["source_step_id"]
            )
            matches = [
                evidence
                for evidence in source["evidence"]
                if evidence["evidence_type"] == item["evidence_type"]
            ]
            if len(matches) != 1:
                _deny("PLAN_STATE_INVALID")
            digest = matches[0]["evidence_digest"]
        required.append(
            {"evidence_type": item["evidence_type"], "evidence_digest": digest}
        )

    prior_digests = [
        evidence["evidence_digest"]
        for state in progress["step_states"][:4]
        for evidence in state["evidence"]
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
        "prior_evidence_digests": prior_digests,
        "unexpected_remote_state": False,
        "extra_privileges": False,
        "unauthorized_migration_surface": False,
        "scope_expansion": False,
    }


def _capability_assertion(moment: str, resource: dict[str, Any]) -> dict[str, Any]:
    config = {
        "executor_reference": "github-actions.development-provider-adapter-positive-auth-v13-step5",
        "environment": "development",
        "project_reference": PROJECT,
        "step_id": STEP_ID,
        "operation": "provider.auth-session.provider-adapter-recover-validate-live-probe-and-logout-global",
        "credential_class": "SUPABASE_AUTH_ADMIN_EPHEMERAL",
        "admin_binding_name": ADMIN_ENV,
        "publishable_binding_name": PUBLISHABLE_ENV,
        "executor_source_digest": prior._raw_digest(Path(__file__)),
        "workflow_source_digest": prior._raw_digest(WORKFLOW_PATH),
        "evidence_digest_source_digest": prior._raw_digest(
            ROOT / "src/avuhz_engineering/evidence_digest.py"
        ),
        "failure_diagnostics_source_digest": prior._raw_digest(
            ROOT / "src/avuhz_engineering/safe_auth_failure_diagnostics.py"
        ),
        "live_query_url": LIVE_QUERY_URL,
    }
    digest = canonical_digest(config)
    return {
        "binding_id": "binding.development.provider-adapter-positive-auth-v13.admin-executor-capability",
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
        plan = prior._load(PLAN_PATH)
        approval = prior._load(APPROVAL_PATH)
        progress = prior._load(EXECUTION_PROGRESS_PATH)
        resource = prior._load(RESOURCE_PATH)
        validate_plan(plan, SCHEMA_ROOT)
        validate_progress(plan, progress, SCHEMA_ROOT)
        validate_approval(plan, approval, SCHEMA_ROOT, moment)
        _validate_boundary(plan, resource, progress)
    except (AuthorizationPlanError, AuthorizationPlanStop):
        raise AuthorizationPlanStop("AUTHORITY_INVALID") from None

    if (
        approval.get("decision") != "APPROVE"
        or approval.get("authority_scope") != "EXACT_PLAN_ONLY"
    ):
        _deny()

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
    if (
        state["authorization_state"] != "AUTHORIZED"
        or state["authorization_consumed"] is not False
    ):
        _deny()
    return plan, authorized


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def execute_positive_auth(**overrides) -> dict[str, Any]:
    """Run the existing tested lifecycle with redirects rejected for v13."""
    opener = urllib.request.build_opener(_RejectRedirects()).open
    defaults = {
        "generate": partial(prior.request_generate_recovery_credential, urlopen=opener),
        "verify": partial(prior.request_direct_recovery_verification, urlopen=opener),
        "live_probe": partial(prior._live_identity_probe, urlopen=opener),
        "logout_global": partial(prior.request_global_session_logout, urlopen=opener),
    }
    defaults.update(overrides)
    result = prior.execute_positive_auth(**defaults)
    result["credential_retirement_required"] = True
    result["github_binding_retirement_required"] = True
    return result


def _safe_failure(code: str | None, *, provider_mutation_attempted: bool) -> int:
    payload = sanitized_positive_auth_failure(
        code,
        provider_mutation_attempted=provider_mutation_attempted,
    )
    payload.update(
        {
            "session_state_readback_required": provider_mutation_attempted,
            "credential_retirement_required": True,
            "github_binding_retirement_required": True,
            "implementation_handoff_attempted": False,
        }
    )
    print(json.dumps(payload, sort_keys=True))
    return 1


def main(
    environment: Mapping[str, str] | None = None, *, preflight_only: bool = False
) -> int:
    env = os.environ if environment is None else environment
    attempted = False
    admin_secret = publishable_key = None
    try:
        _validate_invocation(env)
        _load_and_authorize(prior._now())
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
        return _safe_failure(str(exc), provider_mutation_attempted=attempted)
    except SafeLifecycleStop as exc:
        return _safe_failure(exc.code, provider_mutation_attempted=attempted)
    except Exception:
        return _safe_failure("AUTHORITY_INVALID", provider_mutation_attempted=attempted)
    finally:
        admin_secret = publishable_key = None


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--preflight-only", action="store_true")
    raise SystemExit(main(preflight_only=parser.parse_args().preflight_only))
