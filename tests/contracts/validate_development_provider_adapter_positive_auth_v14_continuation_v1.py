from __future__ import annotations

import hashlib
import json
from pathlib import Path

from avuhz_engineering.authorization_plan import (
    plan_digest,
    progress_digest,
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


def load(suffix: str) -> dict:
    return json.loads((BASE / f"{N}{suffix}").read_text())


def raw_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    resource = load(".resource.json")
    prep = load("-preparation.evidence.json")
    plan = load(".plan.json")
    progress = load(".progress.json")
    failure = json.loads(
        (BASE / "development-implementation-handoff-provider-adapter-positive-auth-v14-step05-authorization-preflight-failure.evidence.json").read_text()
    )

    validate_plan(plan, SCHEMA_ROOT)
    validate_progress(plan, progress, SCHEMA_ROOT)

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

    assert not (BASE / f"{N}.approval.json").exists()
    assert not (BASE / f"{N}.execution-progress.json").exists()

    rendered = "\n".join(
        (BASE / f"{N}{suffix}").read_text()
        for suffix in (
            ".resource.json",
            "-preparation.evidence.json",
            ".plan.json",
            ".progress.json",
        )
    )
    assert "gnuqaefotwgkwurjpyik" not in rendered
    assert "sb_secret_" not in rendered
    assert "sb_publishable_" not in rendered
    assert "NONE_UNTIL_SEPARATELY_APPROVED" in rendered

    print(
        "DEVELOPMENT provider-adapter positive-auth v14 continuation v1: PASS "
        "(schema-valid 6-step continuation; existing v14 key/binding reused; "
        "exact runtime preflight regression present; READY_FOR_APPROVAL / UNEXECUTED)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
