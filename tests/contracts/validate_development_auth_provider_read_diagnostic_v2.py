#!/usr/bin/env python3
"""Validate the forward-only DEVELOPMENT AUTH provider-read diagnostic v2."""
from __future__ import annotations

import ast
import hashlib
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.authorization_plan import (  # noqa: E402
    AuthorizationPlanStop,
    approval_digest,
    initial_progress,
    plan_digest,
    validate_approval,
    validate_plan,
    validate_progress,
)
from avuhz_engineering.development_auth_provider_read_diagnostic import (  # noqa: E402
    PROJECT_READ_CONTRACT,
    PROVIDER_READ_CREDENTIAL_CLASS,
    PROVIDER_READ_ENV_REFERENCE,
)
from avuhz_runtime.implementation_handoff import canonical_digest  # noqa: E402


SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
BASE = ROOT / "contracts/plans/v1"
V1_PLAN_PATH = BASE / "development-auth-provider-read-diagnostic-v1.plan.json"
V1_PROGRESS_PATH = (
    BASE / "development-auth-provider-read-diagnostic-v1.progress.json"
)
V1_APPROVAL_PATH = (
    BASE / "development-auth-provider-read-diagnostic-v1.approval.json"
)
V1_EXECUTION_PATH = (
    BASE / "development-auth-provider-read-diagnostic-v1.execution-progress.json"
)
PLAN_PATH = BASE / "development-auth-provider-read-diagnostic-v2.plan.json"
PROGRESS_PATH = BASE / "development-auth-provider-read-diagnostic-v2.progress.json"
APPROVAL_PATH = BASE / "development-auth-provider-read-diagnostic-v2.approval.json"
EXECUTION_PATH = (
    BASE / "development-auth-provider-read-diagnostic-v2.execution-progress.json"
)
WORKFLOW_PATH = (
    ROOT / ".github/workflows/development-auth-provider-read-diagnostic-v2.yml"
)
EXECUTOR_PATH = ROOT / "scripts/development_auth_provider_read_diagnostic_v2.py"
HELPER_PATH = (
    ROOT / "src/avuhz_engineering/development_auth_provider_read_diagnostic.py"
)
HTTP_HELPER_PATH = ROOT / "src/avuhz_engineering/provider_read_http.py"

PLAN_ID = "b6d86aea-a009-4080-a82c-8ace44b91f45"
PROGRESS_ID = "ec9ed53b-d3ac-40da-a19e-01571defb01e"
PLAN_DIGEST = "sha256:e461550ca90b8ffbb38c8f8be0b73e767c57ead19aec23e3a8b4eaeccc938bba"
PROGRESS_DIGEST = "sha256:7e2c5396e878deb90988d39f46596b886de98bd7b98bec6ea49961bcd0c71ab0"
V1_PLAN_RAW_DIGEST = (
    "sha256:06d73a1846bf1480b34fc42d1af0fd216edc83893015307471f3a18b9a6a2902"
)
V1_PROGRESS_RAW_DIGEST = (
    "sha256:caddfcb340e1434205a40af89f7f7c1bd9fde9c379eb9a4cbda9532d8f9eec43"
)
CREATED_AT = "2026-09-19T19:15:53Z"
WINDOW_START = "2026-09-20T15:00:00Z"
WINDOW_END = "2026-09-20T21:00:00Z"
V1_WINDOW_START = "2026-09-19T15:00:00Z"
V1_WINDOW_END = "2026-09-19T21:00:00Z"
POST_START_OBSERVATION = "2026-09-19T19:15:28Z"
STEP_ID = (
    "development.auth.provider-read-diagnostic-v2.step.01."
    "inspect-project-metadata-read-only"
)
CONFIRMATION = "DIAGNOSE_DEVELOPMENT_AUTH_PROVIDER_READ_V2"
PROJECT_READ_CONTRACT_DIGEST = (
    "sha256:6a41a1173c187f3f058578bff9717093164b4647de4b72b7fd2c9ed016fffe96"
)


def load(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict), path
    return value


def raw_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    v1_plan = load(V1_PLAN_PATH)
    v1_progress = load(V1_PROGRESS_PATH)
    plan = load(PLAN_PATH)
    progress = load(PROGRESS_PATH)

    validate_plan(v1_plan, SCHEMA_ROOT)
    validate_progress(v1_plan, v1_progress, SCHEMA_ROOT)
    validate_plan(plan, SCHEMA_ROOT)
    validate_progress(plan, progress, SCHEMA_ROOT)

    # v1 remains byte-exact, pristine, unapproved, unexecuted, and non-backdated.
    assert raw_digest(V1_PLAN_PATH) == V1_PLAN_RAW_DIGEST
    assert raw_digest(V1_PROGRESS_PATH) == V1_PROGRESS_RAW_DIGEST
    assert v1_plan["plan_digest"] == (
        "sha256:e38f0eac3128511f3e3c2d3bd45278276a69fe1ce86801e93c2417264e411f1d"
    )
    assert v1_progress["progress_digest"] == (
        "sha256:5f956df6a861088645ef7bb5831020683a03697ca87e93fbf631431951662e37"
    )
    assert v1_progress["overall_state"] == "NOT_STARTED"
    assert (
        v1_progress["step_states"][0]["authorization_state"],
        v1_progress["step_states"][0]["execution_state"],
        v1_progress["step_states"][0]["verification_state"],
        v1_progress["step_states"][0]["authorization_consumed"],
    ) == ("PENDING", "NOT_STARTED", "NOT_STARTED", False)
    assert not V1_APPROVAL_PATH.exists()
    assert not V1_EXECUTION_PATH.exists()
    assert not list(
        BASE.glob("development-auth-provider-read-diagnostic-v1*.evidence.json")
    )

    late_approval = {
        "approval_id": "54b8387e-c16b-45df-a492-a4546bd56424",
        "plan_id": v1_plan["plan_id"],
        "plan_version": v1_plan["plan_version"],
        "plan_digest": v1_plan["plan_digest"],
        "owner_identity": v1_plan["owner_identity"],
        "decision": "APPROVE",
        "environment": v1_plan["environment"],
        "effective_at": V1_WINDOW_START,
        "expires_at": V1_WINDOW_END,
        "approved_at": POST_START_OBSERVATION,
        "status": "ACTIVE",
        "authority_scope": "EXACT_PLAN_ONLY",
        "approval_digest": "",
    }
    late_approval["approval_digest"] = approval_digest(late_approval)
    try:
        validate_approval(
            v1_plan,
            late_approval,
            SCHEMA_ROOT,
            POST_START_OBSERVATION,
        )
    except AuthorizationPlanStop as exc:
        assert str(exc) == "PLAN_AUTHORIZATION_EXPIRED"
    else:
        raise AssertionError("post-start v1 approval must fail without backdating")

    assert plan_digest(plan) == PLAN_DIGEST
    assert plan["plan_id"] == PLAN_ID
    assert plan["plan_version"] == 2
    assert plan["definition_status"] == "READY_FOR_APPROVAL"
    assert plan["authority_effect"] == "NONE_UNTIL_SEPARATELY_APPROVED"
    assert plan["authorization_window"] == {
        "binding_state": "BOUND",
        "starts_at": WINDOW_START,
        "expires_at": WINDOW_END,
    }
    assert plan["target"] == v1_plan["target"]
    assert len(plan["steps"]) == 1
    step = plan["steps"][0]
    v1_step = v1_plan["steps"][0]
    assert plan["ordered_step_ids"] == [STEP_ID]
    assert step["step_id"] == STEP_ID
    assert step["operation"] == "provider.project-metadata.inspect-read-only"
    assert step["execution_class"] == "PROVIDER_READ"
    assert step["resource"] == v1_step["resource"]
    assert step["required_evidence"] == v1_step["required_evidence"]
    assert step["expected_postcondition"] == v1_step["expected_postcondition"]
    assert step["credential_policy"] == v1_step["credential_policy"] == {
        "permitted": True,
        "allowed_classes": [PROVIDER_READ_CREDENTIAL_CLASS],
        "values_stored": False,
    }
    assert canonical_digest(PROJECT_READ_CONTRACT) == PROJECT_READ_CONTRACT_DIGEST
    assert set(step["prohibited_actions"]) == set(
        v1_step["prohibited_actions"]
    ) | {
        "provider-read-diagnostic-v1.approval.backdate",
        "provider-read-diagnostic-v1.plan.execute",
    }
    assert set(plan["prohibited_actions"]) == set(
        v1_plan["prohibited_actions"]
    ) | {
        "provider-read-diagnostic-v1.approval.backdate",
        "provider-read-diagnostic-v1.plan.execute",
    }

    assert progress == initial_progress(
        plan,
        SCHEMA_ROOT,
        PROGRESS_ID,
        CREATED_AT,
    )
    assert progress["progress_digest"] == PROGRESS_DIGEST
    assert progress["overall_state"] == "NOT_STARTED"
    state = progress["step_states"][0]
    assert (
        state["authorization_state"],
        state["execution_state"],
        state["verification_state"],
        state["authorization_consumed"],
    ) == ("PENDING", "NOT_STARTED", "NOT_STARTED", False)
    assert state["evidence"] == []
    assert not APPROVAL_PATH.exists()
    assert not EXECUTION_PATH.exists()
    assert not list(
        BASE.glob("development-auth-provider-read-diagnostic-v2*.evidence.json")
    )

    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
    executor = EXECUTOR_PATH.read_text(encoding="utf-8")
    helper = HELPER_PATH.read_text(encoding="utf-8")
    http_helper = HTTP_HELPER_PATH.read_text(encoding="utf-8")
    assert CONFIRMATION in workflow
    assert workflow.count(f"secrets.{PROVIDER_READ_ENV_REFERENCE}") == 1
    assert PLAN_ID in workflow and PLAN_DIGEST in workflow
    assert WINDOW_START in workflow and WINDOW_END in workflow
    assert str(APPROVAL_PATH.relative_to(ROOT)) in workflow
    assert executor.count("inspect_development_auth_project_metadata(") == 1
    assert helper.count("request_json(") == 1

    http_tree = ast.parse(http_helper)
    urlopen_calls = [
        node
        for node in ast.walk(http_tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "urlopen"
    ]
    assert len(urlopen_calls) == 1

    surface = "\n".join((workflow, executor, helper, http_helper))
    for forbidden in (
        "/database/query/read-only",
        "auth.sessions",
        "auth.refresh_tokens",
        "/auth/v1/admin",
        "/auth/v1/logout",
        "SUPABASE_AUTH_ADMIN_EPHEMERAL",
        "service_role",
    ):
        assert forbidden not in surface

    print(
        "DEVELOPMENT AUTH provider-read diagnostic v2 validation: PASS "
        "(v1 pristine/post-start approval rejected; v2 pristine/unapproved)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
