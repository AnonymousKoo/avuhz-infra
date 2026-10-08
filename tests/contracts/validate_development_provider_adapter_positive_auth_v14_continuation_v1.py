from __future__ import annotations

import hashlib
import json
from pathlib import Path

from avuhz_engineering.authorization_plan import (
    approval_digest,
    plan_digest,
    progress_digest,
    validate_approval,
    validate_plan,
    validate_progress,
)
from avuhz_engineering.evidence_digest import evidence_digest
from avuhz_runtime.implementation_handoff import canonical_digest


ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "contracts/plans/v1"
SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
N = "development-implementation-handoff-provider-adapter-positive-auth-v14-continuation-v1"

RESOURCE = "sha256:19ac6ac911e168a1a8e5a750504188b5724c153b5dd99bfd338df7927c040ef3"
PREP = "sha256:c9c60020941d6fc8e3d9296880c45ee113a4153f90bfaee8cddbb1675c0ef2e8"
PLAN = "sha256:d98a32bc384782a0436976459092b7ee2f62c8155353856923d066bbd0324f8b"
PROGRESS = "sha256:89119cbc54fdd5273619c997aa6c84d2391e8289e6eb2e8ad3c2fb0b69a20825"
EXECUTOR = "sha256:91e7a63a3550bd366179a797070dcfca55d23d87f05c9bba13b74c9209a4998d"
WORKFLOW = "sha256:72f8de8a1979ec771fbe42ac4c8da173f79005b884e57ceabf68358bf6621e07"
V14_FAILURE = "sha256:ddd3884f1edebc06d2c608a066146235c5864d10680e95a277140fb04261c1bc"
APPROVED = "2026-10-08T10:07:10Z"
APPROVAL = "sha256:f09c9c6b2d7f332ed3468288dd488f84801d0a71c36db42d62ee06baa98ea2f2"
CURRENT_FAILURE = "sha256:63c1246fb571cc86cf01bbb994942c36d4438f9cd720028114abd53d3b5144aa"
EXECUTION_PROGRESS = "sha256:9bcf3c8a65985a96c3f4f1a8f9095f376a92be73639ea3ea414621551c2e100b"
CAPABILITY = "sha256:8a1695d0ff544091215771af39446a21c01c285e55354d4d8f88d04b10002afb"
WORKFLOW_RUN_ID = 37770555664


def load(suffix: str) -> dict:
    return json.loads((BASE / f"{N}{suffix}").read_text())


def raw_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    resource = load(".resource.json")
    prep = load("-preparation.evidence.json")
    plan = load(".plan.json")
    progress = load(".progress.json")
    approval = load(".approval.json")
    failure = json.loads(
        (BASE / "development-implementation-handoff-provider-adapter-positive-auth-v14-step05-authorization-preflight-failure.evidence.json").read_text()
    )
    current_failure = load("-step1-failure.evidence.json")
    execution = load(".execution-progress.json")

    validate_plan(plan, SCHEMA_ROOT)
    validate_progress(plan, progress, SCHEMA_ROOT)
    validate_progress(plan, execution, SCHEMA_ROOT)
    validate_approval(plan, approval, SCHEMA_ROOT, "2026-10-08T11:00:00Z")

    assert resource["contract_digest"] == RESOURCE == canonical_digest(
        {k: v for k, v in resource.items() if k != "contract_digest"}
    )
    assert prep["evidence_digest"] == PREP == evidence_digest(prep)
    assert plan["plan_digest"] == PLAN == plan_digest(plan)
    assert progress["progress_digest"] == PROGRESS == progress_digest(progress)
    assert evidence_digest(failure) == V14_FAILURE

    assert plan["plan_id"] == "7fb19d54-8a32-4c6e-b741-2d9f5a03c861"
    assert plan["plan_version"] == 1
    assert plan["definition_status"] == "READY_FOR_APPROVAL"
    assert plan["authority_effect"] == "NONE_UNTIL_SEPARATELY_APPROVED"
    assert plan["authorization_window"] == {
        "binding_state": "BOUND",
        "starts_at": "2026-10-08T11:00:00Z",
        "expires_at": "2026-10-08T15:00:00Z",
    }
    assert len(plan["steps"]) == 6
    assert [len(step["required_evidence"]) for step in plan["steps"]] == [9, 1, 1, 1, 2, 2]
    assert all(len(step["required_evidence"]) <= 16 for step in plan["steps"])
    assert plan["steps"][0]["operation"] == (
        "provider.auth-session.provider-adapter-recover-validate-live-probe-and-logout-global"
    )
    assert plan["steps"][0]["credential_policy"]["allowed_classes"] == [
        "SUPABASE_AUTH_ADMIN_EPHEMERAL"
    ]

    assert resource["fresh_auth_admin_key_create_count_authorized"] == 0
    assert resource["github_secret_binding_create_count_authorized"] == 0
    assert resource["fresh_auth_admin_key_delete_count_authorized"] == 1
    assert resource["github_secret_binding_delete_count_authorized"] == 1
    assert resource["temporary_session_issue_count_authorized"] == 1
    assert resource["retry_authorized"] is False
    assert resource["implementation_handoff_execution_authorized"] is False
    assert resource["data_operation_authorized"] is False
    assert resource["production_authorized"] is False
    assert resource["fresh_provider_key_reference"] == (
        "impl_handoff_provider_adapter_positive_auth_v14_ephemeral"
    )
    assert resource["github_secret_binding_name"] == (
        "AVUHZ_DEVELOPMENT_SUPABASE_AUTH_PROVIDER_ADAPTER_POSITIVE_AUTH_V14_EPHEMERAL"
    )
    assert resource["step1_executor_digest"] == EXECUTOR == raw_digest(
        ROOT / "scripts/development_provider_adapter_positive_auth_v14_continuation_v1.py"
    )
    assert resource["step1_workflow_digest"] == WORKFLOW == raw_digest(
        ROOT / ".github/workflows/development-provider-adapter-positive-auth-v14-continuation-v1-step1.yml"
    )
    assert resource["required_v14_step5_preflight_failure_evidence_digest"] == V14_FAILURE
    assert failure["outcome"] == "FAILED_CLOSED_BEFORE_SECRET_RESOLUTION"
    assert failure["execution_observation"]["secret_resolution_attempted"] is False
    assert failure["execution_observation"]["provider_mutation_attempted"] is False

    assert evidence_digest(current_failure) == CURRENT_FAILURE
    assert current_failure["plan_id"] == plan["plan_id"]
    assert current_failure["plan_digest"] == plan["plan_digest"]
    assert current_failure["approval_id"] == approval["approval_id"]
    assert current_failure["approval_digest"] == approval["approval_digest"]
    assert current_failure["step_id"] == plan["steps"][0]["step_id"]
    assert current_failure["attempt"] == 1
    assert current_failure["outcome"] == "FAILED_UNVERIFIED"
    assert current_failure["safe_error_code"] == "LIVE_AUTH_PROBE_FAILED"
    assert current_failure["classification"] == "PROVIDER_ADAPTER_POSITIVE_AUTH_UNVERIFIED"
    assert current_failure["failure_stage"] == "live_runtime_probe"
    assert current_failure["execution_observation"]["workflow_run_id"] == WORKFLOW_RUN_ID
    assert current_failure["execution_observation"]["execution_sha"] == "2c9c92e1f49f6e911600978d53f33e29b5550f7b"
    assert current_failure["execution_observation"]["run_number"] == 1
    assert current_failure["execution_observation"]["run_attempt"] == 1
    assert current_failure["execution_observation"]["authorization_preflight_passed_before_runtime_secret_resolution"] is True
    assert current_failure["execution_observation"]["secret_resolution_attempted"] is True
    assert current_failure["execution_observation"]["provider_mutation_attempted"] is True
    assert current_failure["execution_observation"]["retry_occurred"] is False
    assert current_failure["sanitized_runtime_outcome"]["cleanup_verified"] is False
    assert current_failure["sanitized_runtime_outcome"]["session_state_readback_required"] is True
    assert current_failure["sanitized_runtime_outcome"]["credential_retirement_obligation_remains"] is True
    assert current_failure["sanitized_runtime_outcome"]["github_binding_retirement_obligation_remains"] is True
    assert current_failure["sanitized_runtime_outcome"]["retry_authorized"] is False
    assert current_failure["sanitized_runtime_outcome"]["ordinary_later_steps_authorized"] is False
    assert current_failure["credential_material_retained"] is False
    assert current_failure["token_material_retained"] is False
    assert current_failure["provider_payload_retained"] is False
    assert current_failure["pii_retained"] is False
    assert not any(current_failure["security_state"].values())

    assert progress["overall_state"] == "NOT_STARTED"
    assert progress["record_version"] == 1
    assert all(
        (
            state["authorization_state"],
            state["execution_state"],
            state["verification_state"],
            state["authorization_consumed"],
        ) == ("PENDING", "NOT_STARTED", "NOT_STARTED", False)
        for state in progress["step_states"]
    )

    assert execution["progress_digest"] == EXECUTION_PROGRESS == progress_digest(execution)
    assert execution["record_version"] == 3
    assert execution["overall_state"] == "STOPPED"
    first = execution["step_states"][0]
    assert (
        first["authorization_state"],
        first["execution_state"],
        first["verification_state"],
        first["authorization_consumed"],
        first["safe_error_code"],
    ) == ("CONSUMED", "FAILED", "FAIL", True, "LIVE_AUTH_PROBE_FAILED")
    assert first["evidence"] == [{
        "evidence_type": current_failure["evidence_type"],
        "evidence_reference": "github.actions.run.37770555664.step1.attempt1.failed-unverified",
        "evidence_digest": CURRENT_FAILURE,
        "recorded_at": "2026-10-08T11:34:15Z",
    }]
    assert len(first["binding_assertions"]) == 1
    binding = first["binding_assertions"][0]
    assert binding["binding_id"] == "binding.development.provider-adapter-positive-auth-v14-continuation-v1.admin-executor-capability"
    assert binding["phase"] == "RESOLVED_BY_STEP_PREFLIGHT"
    assert binding["evidence_type"] == "auth.admin-executor-capability.observed"
    assert binding["evidence_digest"] == CAPABILITY
    assert binding["value_digest"] == CAPABILITY
    assert binding["sanitized_value"] is None
    assert binding["recorded_at"] == "2026-10-08T11:31:12Z"
    assert all(
        (
            state["authorization_state"],
            state["execution_state"],
            state["verification_state"],
            state["authorization_consumed"],
        ) == ("BLOCKED", "NOT_STARTED", "NOT_STARTED", False)
        for state in execution["step_states"][1:]
    )

    assert approval["approval_id"] == "9d6f4e83-2a57-4cb1-b942-6e0f3a8c5d74"
    assert approval["plan_id"] == plan["plan_id"]
    assert approval["plan_version"] == 1
    assert approval["plan_digest"] == plan["plan_digest"]
    assert approval["owner_identity"] == plan["owner_identity"]
    assert approval["decision"] == "APPROVE"
    assert approval["environment"] == "DEVELOPMENT"
    assert approval["approved_at"] == APPROVED
    assert APPROVED < plan["authorization_window"]["starts_at"]
    assert approval["effective_at"] == plan["authorization_window"]["starts_at"]
    assert approval["expires_at"] == plan["authorization_window"]["expires_at"]
    assert approval["status"] == "ACTIVE"
    assert approval["authority_scope"] == "EXACT_PLAN_ONLY"
    assert approval["approval_digest"] == APPROVAL == approval_digest(approval)
    assert (BASE / f"{N}.execution-progress.json").exists()

    rendered = "\n".join(
        (BASE / f"{N}{suffix}").read_text()
        for suffix in (
            ".resource.json",
            "-preparation.evidence.json",
            ".plan.json",
            ".progress.json",
            ".approval.json",
            "-step1-failure.evidence.json",
            ".execution-progress.json",
        )
    )
    assert "gnuqaefotwgkwurjpyik" not in rendered
    assert "sb_secret_" not in rendered
    assert "sb_publishable_" not in rendered
    assert "NONE_UNTIL_SEPARATELY_APPROVED" in rendered

    print(
        "DEVELOPMENT provider-adapter positive-auth v14 continuation v1: PASS "
        "(STOPPED; Step 1 CONSUMED/FAILED/FAIL at live runtime probe; "
        "provider mutation attempted; session state UNKNOWN; retry prohibited; "
        "Steps 2-6 BLOCKED; corrective cleanup/retirement required)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
