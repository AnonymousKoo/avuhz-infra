#!/usr/bin/env python3
"""Validate the forward-only provider-adapter positive-auth continuation v1 preparation."""
from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

import validate_development_provider_adapter_positive_auth_v2 as original_v2
import validate_development_provider_adapter_positive_auth_v2_step4_correction_v2 as correction_v2
from scripts import development_provider_adapter_positive_auth_continuation_v1 as executor
from avuhz_engineering.authorization_plan import (
    AuthorizationPlanError,
    AuthorizationPlanStop,
    approval_digest,
    authorize_step,
    initial_progress,
    plan_digest,
    validate_approval,
    validate_plan,
    validate_progress,
)
from avuhz_runtime.implementation_handoff import canonical_digest

B = ROOT / "contracts/plans/v1"
S = ROOT / "contracts/schemas/v1"
N = "development-implementation-handoff-provider-adapter-positive-auth-continuation-v1"
OLD = "development-implementation-handoff-provider-adapter-positive-auth-v2"
CORRECTION = OLD + "-step4-correction-v2"

PLAN_ID = "2ae4014b-99da-52c4-a5ce-2707245a8971"
PLAN_DIGEST = "sha256:256693b1f188441e288ec29b861b3b1b144acc57324eca922736a2f3ce584994"
PROGRESS_ID = "6afd9554-0e98-5450-b0a6-f17ebb377ea9"
PROGRESS_DIGEST = "sha256:89e45458443693ebd1a3b52ee68ab42487ef90a56f94326fc34ec6aba38cc4ec"
RESOURCE_ID = "671c545d-5424-5f69-881e-fe49f2f19706"
RESOURCE_DIGEST = "sha256:adc0c8b7f220135f858040c473a40ce52583f919e98ba250744b914b735aaa6e"
PREP_DIGEST = "sha256:490e82d0bd9aa847607b86e0f9b9097c486487265c3725af35fe5b977284f93b"
CREATED_AT = "2026-10-04T13:49:57Z"
APPROVAL_ID = "5a10b05e-db2d-5359-995d-8bcb168e5863"
APPROVAL_DIGEST = "sha256:ce6351e9e06f7bb875fa50fb04d3f56455c34296368598f1a1188cf6ed280f65"
APPROVED_AT = "2026-10-04T13:58:14Z"
WINDOW_START = "2026-10-04T16:00:00Z"
WINDOW_END = "2026-10-04T20:00:00Z"
PROJECT = "pwlhruwutoitnieactol"
KEY_NAME = "impl_handoff_provider_adapter_positive_auth_v1_ephemeral"
GITHUB_SECRET = "AVUHZ_DEVELOPMENT_SUPABASE_AUTH_PROVIDER_ADAPTER_POSITIVE_AUTH_V1_EPHEMERAL"
CORRECTION_SUCCESS = "sha256:29b5a66afbae1a36ef4893917d8c7ccbe43537c04523111380884e6c26892fa9"
CORRECTION_PROGRESS = "sha256:d12057f621c8ee3b7d0d998a0b8d1865467e84dd796511558ee510d4d09636e6"
ORIGINAL_PROGRESS = "sha256:656af77ba698ebaf159b0ce812f627e4a54e26472fd0ba69d0bdf97f52ed4060"
ORIGINAL_STEP_EVIDENCE = (
    "sha256:1afa5a5b2129364ca63f458e63211b1aa2201f004c1acc131f90aa1cd15c4a42",
    "sha256:9cf39e54d31c6c861607df0750df4f80ae920040ebc15ae664c94d67ebc7a7dd",
    "sha256:1949474314c7486e178e465e0e1436b6127c2da20260997daaf70bfb42a1d3d5",
)
QUERY = """select
  (select count(*) from auth.sessions) as session_count,
  (select count(*) from auth.refresh_tokens) as refresh_token_count;"""


def load(name: str) -> dict:
    value = json.loads((B / name).read_text())
    assert isinstance(value, dict)
    return value


def raw(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def denied(call, code: str) -> None:
    try:
        call()
    except (AuthorizationPlanError, AuthorizationPlanStop) as error:
        assert str(error) == code, (str(error), code)
        return
    raise AssertionError(f"unsafe operation accepted; expected {code}")


def synthetic_approval(plan: dict) -> dict:
    approval = {
        "approval_id": "c7203b60-b4ae-4d67-8517-d55e13c41b46",
        "plan_id": plan["plan_id"],
        "plan_version": plan["plan_version"],
        "plan_digest": plan["plan_digest"],
        "owner_identity": plan["owner_identity"],
        "decision": "APPROVE",
        "environment": plan["environment"],
        "effective_at": WINDOW_START,
        "expires_at": WINDOW_END,
        "approved_at": "2026-10-04T15:30:00Z",
        "status": "ACTIVE",
        "authority_scope": "EXACT_PLAN_ONLY",
    }
    approval["approval_digest"] = approval_digest(approval)
    return approval


def step1_request(plan: dict) -> dict:
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
        "step_id": step["step_id"],
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


def step1_assertion(resource: dict, moment: str) -> dict:
    config = {
        "step_id": executor.STEP_ID,
        "resource_digest": resource["contract_digest"],
        "executor_source_digest": resource["step1_executor_digest"],
        "workflow_source_digest": resource["step1_workflow_digest"],
        "admin_binding_name": executor.ADMIN_ENV,
        "publishable_binding_name": executor.PUBLISHABLE_ENV,
    }
    digest = canonical_digest(config)
    return {
        "binding_id": "binding.development.provider-adapter-positive-auth-continuation-v1.admin-executor-capability",
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


def main() -> int:
    # Historical truth must continue to validate first.
    original_v2.main()
    correction_v2.main()

    resource = load(N + ".resource.json")
    prep = load(N + "-preparation.evidence.json")
    plan = load(N + ".plan.json")
    progress = load(N + ".progress.json")
    approval = load(N + ".approval.json")
    old_plan = load(OLD + ".plan.json")
    old_exec = load(OLD + ".execution-progress.json")
    correction_exec = load(CORRECTION + ".execution-progress.json")

    validate_plan(plan, S)
    validate_progress(plan, progress, S)
    validate_approval(plan, approval, S, WINDOW_START)
    assert plan["plan_id"] == PLAN_ID
    assert plan["plan_version"] == 1
    assert plan["plan_digest"] == PLAN_DIGEST == plan_digest(plan)
    assert plan["definition_status"] == "READY_FOR_APPROVAL"
    assert plan["authority_effect"] == "NONE_UNTIL_SEPARATELY_APPROVED"
    assert plan["environment"] == "DEVELOPMENT"
    assert plan["target"]["project_reference"] == PROJECT
    assert plan["target"]["responsibility"] == "AUTH"
    assert plan["authorization_window"] == {
        "binding_state": "BOUND",
        "starts_at": WINDOW_START,
        "expires_at": WINDOW_END,
    }

    assert resource["resource_id"] == RESOURCE_ID
    assert resource["resource_version"] == "provider-adapter-positive-auth-continuation.v1"
    assert resource["contract_digest"] == RESOURCE_DIGEST == canonical_digest(
        {key: value for key, value in resource.items() if key != "contract_digest"}
    )
    assert resource["correction_v2_success_evidence_digest"] == CORRECTION_SUCCESS
    assert resource["correction_v2_execution_progress_digest"] == CORRECTION_PROGRESS
    assert resource["fresh_auth_admin_key_create_count_authorized"] == 0
    assert resource["github_secret_binding_create_count_authorized"] == 0
    assert resource["fresh_auth_admin_key_delete_count_authorized"] == 1
    assert resource["github_secret_binding_delete_count_authorized"] == 1
    assert resource["temporary_session_issue_count_authorized"] == 1
    assert resource["global_logout_count_authorized"] == 1
    assert resource["retry_authorized"] is False
    assert resource["implementation_handoff_execution_authorized"] is False
    assert resource["data_operation_authorized"] is False
    assert resource["render_mutation_authorized"] is False
    assert resource["n8n_operation_authorized"] is False
    assert resource["staging_authorized"] is False
    assert resource["production_authorized"] is False
    assert resource["credential_material_agent_visible"] is False
    assert resource["credential_material_persistence_authorized"] is False

    executor_path = ROOT / "scripts/development_provider_adapter_positive_auth_continuation_v1.py"
    workflow_path = ROOT / ".github/workflows/development-provider-adapter-positive-auth-continuation-v1-step1.yml"
    assert resource["step1_executor_digest"] == raw(executor_path)
    assert resource["step1_workflow_digest"] == raw(workflow_path)
    for path, digest in resource["source_artifact_sha256"].items():
        assert raw(ROOT / path) == digest, path

    session = resource["session_verification"]
    assert session == {
        "interaction_surface": "supabase.dashboard.sql-editor",
        "project_reference": PROJECT,
        "responsibility": "AUTH",
        "execution_class": "PROVIDER_READ",
        "credential_class": "OWNER_INTERACTIVE_SESSION",
        "query": QUERY,
        "query_sha256": "sha256:" + hashlib.sha256(QUERY.encode()).hexdigest(),
        "query_count": 1,
        "result_fields": ["session_count", "refresh_token_count"],
        "expected_result": {"session_count": 0, "refresh_token_count": 0},
        "aggregate_only": True,
        "raw_rows_authorized": False,
        "additional_sql_authorized": False,
        "retry_authorized": False,
        "on_nonzero_malformed_or_unavailable": "STOP_REQUIRES_FORWARD_ONLY_CORRECTIVE_CLEANUP_AND_RETIREMENT",
    }
    assert resource["retirement_interactions"]["step3"]["exact_name"] == KEY_NAME
    assert resource["retirement_interactions"]["step4"]["exact_name"] == GITHUB_SECRET
    assert resource["retirement_interactions"]["step5"]["exact_name"] == KEY_NAME
    assert resource["retirement_interactions"]["step6"]["exact_name"] == GITHUB_SECRET
    assert all(
        item["value_reads_authorized"] is False
        for item in resource["retirement_interactions"].values()
    )
    obligation = resource["failure_cleanup_obligation"]
    assert obligation["retry_authorized"] is False
    assert obligation["ordinary_successors_blocked"] is True
    assert obligation["cleanup_claim_without_zero_counts_prohibited"] is True
    assert obligation["logout_claim_without_accepted_response_prohibited"] is True
    assert resource["execution_rules"]["redirects_authorized"] is False
    assert resource["execution_rules"]["owner_approval_deadline"] == WINDOW_START
    assert resource["execution_rules"]["window_expiry"] == WINDOW_END

    assert prep["evidence_digest"] == PREP_DIGEST == canonical_digest(
        {key: value for key, value in prep.items() if key != "evidence_digest"}
    )
    assert prep["provider_authority"] == "NONE"
    assert prep["external_provider_contact"] == "PROHIBITED"
    assert prep["resource_contract_digest"] == RESOURCE_DIGEST
    assert prep["original_v2_step4_state"] == ["PENDING", "NOT_STARTED", "NOT_STARTED", False]
    assert prep["lineage"]["original_v2_execution_progress_digest"] == ORIGINAL_PROGRESS
    assert prep["lineage"]["correction_v2_success_evidence_digest"] == CORRECTION_SUCCESS
    assert prep["lineage"]["correction_v2_execution_progress_digest"] == CORRECTION_PROGRESS
    assert tuple(
        prep["lineage"][f"original_v2_step{i}_evidence_digest"] for i in range(1, 4)
    ) == ORIGINAL_STEP_EVIDENCE
    assert all(value is False for value in prep["security_state"].values())
    for name, digest in prep["preserved_artifact_sha256"].items():
        assert raw(ROOT / name) == digest, name

    assert progress == initial_progress(plan, S, PROGRESS_ID, CREATED_AT)
    assert progress["progress_digest"] == PROGRESS_DIGEST
    assert progress["overall_state"] == "NOT_STARTED"
    assert len(progress["step_states"]) == 6
    assert all(
        (
            state["authorization_state"],
            state["execution_state"],
            state["verification_state"],
            state["authorization_consumed"],
        ) == ("PENDING", "NOT_STARTED", "NOT_STARTED", False)
        for state in progress["step_states"]
    )
    assert approval == {
        "approval_id": APPROVAL_ID,
        "plan_id": PLAN_ID,
        "plan_version": 1,
        "plan_digest": PLAN_DIGEST,
        "owner_identity": "github:AnonymousKoo",
        "decision": "APPROVE",
        "environment": "DEVELOPMENT",
        "effective_at": WINDOW_START,
        "expires_at": WINDOW_END,
        "approved_at": APPROVED_AT,
        "status": "ACTIVE",
        "authority_scope": "EXACT_PLAN_ONLY",
        "approval_digest": APPROVAL_DIGEST,
    }
    assert approval_digest(approval) == APPROVAL_DIGEST
    assert APPROVED_AT < WINDOW_START
    assert not (B / (N + ".execution-progress.json")).exists()
    assert not list(B.glob(N + "-step*-*.evidence.json"))

    assert len(plan["steps"]) == 6
    assert [step["operation"] for step in plan["steps"]] == [
        step["operation"] for step in old_plan["steps"][4:]
    ]
    assert [step["execution_class"] for step in plan["steps"]] == [
        step["execution_class"] for step in old_plan["steps"][4:]
    ]
    assert [step["credential_policy"] for step in plan["steps"]] == [
        step["credential_policy"] for step in old_plan["steps"][4:]
    ]
    assert all(step["resource"]["exact_digest"] == RESOURCE_DIGEST for step in plan["steps"])
    assert all(
        step["resource"]["exact_version"] == "provider-adapter-positive-auth-continuation.v1"
        for step in plan["steps"]
    )
    assert KEY_NAME in plan["steps"][2]["resource"]["resource_reference"]
    assert GITHUB_SECRET in plan["steps"][3]["resource"]["resource_reference"]
    assert KEY_NAME in plan["steps"][4]["resource"]["resource_reference"]
    assert GITHUB_SECRET in plan["steps"][5]["resource"]["resource_reference"]
    assert "implementation-handoff.execute" in plan["prohibited_actions"]
    assert "provider.retry" in plan["prohibited_actions"]
    assert "positive-auth-v2.progress.advance" in plan["prohibited_actions"]
    assert "positive-auth-v2.step4.mark-success" in plan["prohibited_actions"]

    first_required = {
        (item["evidence_type"], item["exact_digest"]) for item in plan["steps"][0]["required_evidence"]
    }
    assert ("auth.provider-adapter-positive-auth-v2.step4-correction.counts-verified", CORRECTION_SUCCESS) in first_required
    assert ("authorization-plan.execution-progress", CORRECTION_PROGRESS) in first_required
    assert ("authorization-plan.execution-progress", ORIGINAL_PROGRESS) in first_required
    for digest in ORIGINAL_STEP_EVIDENCE:
        assert any(value == digest for _, value in first_required)
    assert old_exec["step_states"][3]["authorization_state"] == "PENDING"
    assert old_exec["step_states"][3]["execution_state"] == "NOT_STARTED"
    assert old_exec["step_states"][3]["verification_state"] == "NOT_STARTED"
    assert old_exec["step_states"][3]["authorization_consumed"] is False
    assert correction_exec["overall_state"] == "COMPLETED"
    assert correction_exec["progress_digest"] == CORRECTION_PROGRESS

    executor._validate_boundary(plan, resource, progress)
    request = step1_request(plan)
    assertion = step1_assertion(resource, WINDOW_START)
    authorized = authorize_step(
        plan, approval, progress, request, S, WINDOW_START,
        trusted_preflight_assertions=[assertion],
    )
    assert authorized["step_states"][0]["authorization_state"] == "AUTHORIZED"

    denied(
        lambda: authorize_step(plan, approval, progress, request, S, "2026-10-04T15:59:59Z",
                               trusted_preflight_assertions=[assertion]),
        "PLAN_AUTHORIZATION_EXPIRED",
    )
    denied(
        lambda: authorize_step(plan, approval, progress, request, S, WINDOW_END,
                               trusted_preflight_assertions=[assertion]),
        "PLAN_AUTHORIZATION_EXPIRED",
    )
    late = dict(approval, approved_at="2026-10-04T16:00:01Z")
    late["approval_digest"] = approval_digest(late)
    denied(
        lambda: validate_approval(plan, late, S, "2026-10-04T16:00:02Z"),
        "PLAN_AUTHORIZATION_EXPIRED",
    )
    wrong_project = copy.deepcopy(request)
    wrong_project["project_reference"] = "gnuqaefotwgkwurjpyik"
    denied(
        lambda: authorize_step(plan, approval, progress, wrong_project, S, WINDOW_START,
                               trusted_preflight_assertions=[assertion]),
        "PREFLIGHT_BINDING_MISMATCH",
    )
    wrong_evidence = copy.deepcopy(request)
    wrong_evidence["required_evidence"][0]["evidence_digest"] = "sha256:" + "0" * 64
    denied(
        lambda: authorize_step(plan, approval, progress, wrong_evidence, S, WINDOW_START,
                               trusted_preflight_assertions=[assertion]),
        "REQUIRED_EVIDENCE_MISMATCH",
    )
    scope_drift = copy.deepcopy(request)
    scope_drift["scope_expansion"] = True
    denied(
        lambda: authorize_step(plan, approval, progress, scope_drift, S, WINDOW_START,
                               trusted_preflight_assertions=[assertion]),
        "PREFLIGHT_DRIFT",
    )
    wrong_source = copy.deepcopy(resource)
    wrong_source["step1_executor_digest"] = "sha256:" + "0" * 64
    denied(lambda: executor._validate_boundary(plan, wrong_source, progress), "AUTHORITY_INVALID")
    missing_binding = copy.deepcopy(resource)
    missing_binding["github_secret_binding_name"] = "MISSING_REFERENCE"
    denied(lambda: executor._validate_boundary(plan, missing_binding, progress), "AUTHORITY_INVALID")

    workflow = workflow_path.read_text()
    assert "GITHUB_RUN_NUMBER" in workflow and "GITHUB_RUN_ATTEMPT" in workflow
    assert "refs/heads/main" in workflow
    assert "persist-credentials: false" in workflow
    assert "continue-on-error" not in workflow
    assert "RUN_PROVIDER_ADAPTER_POSITIVE_AUTH_CONTINUATION_V1_STEP1" in workflow
    assert "AVUHZ_DEVELOPMENT_SUPABASE_AUTH_PROVIDER_ADAPTER_POSITIVE_AUTH_V1_EPHEMERAL" in workflow

    rendered = "\n".join(
        (B / name).read_text()
        for name in (
            N + ".resource.json",
            N + "-preparation.evidence.json",
            N + ".plan.json",
            N + ".progress.json",
        )
    )
    for forbidden in ("sb_secret_", "Bearer eyJ", "service_role_key", "\"access_token\":", "\"refresh_token\":"):
        assert forbidden not in rendered

    print(
        "DEVELOPMENT provider-adapter positive-auth continuation v1: PASS "
        "(APPROVED; pristine six-step continuation; correction-v2 bound; "
        "original v2 Step 4 unchanged; exact Step 1 executor/workflow and Step 2 SQL bound; "
        "retirement mandatory; no provider authority)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
