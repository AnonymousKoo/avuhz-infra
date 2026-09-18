#!/usr/bin/env python3
"""Validate the pristine DEVELOPMENT AUTH provider-read diagnostic v1 boundary."""
from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.authorization_plan import (  # noqa: E402
    AuthorizationPlanError,
    initial_progress,
    plan_digest,
    validate_plan,
    validate_progress,
)
from avuhz_engineering.development_auth_provider_read_diagnostic import (  # noqa: E402
    DEVELOPMENT_AUTH_PROJECT_NAME,
    DEVELOPMENT_AUTH_PROJECT_REF,
    PROJECT_READ_CONTRACT,
    PROJECT_READ_URL,
    PROVIDER_READ_CREDENTIAL_CLASS,
    PROVIDER_READ_ENV_REFERENCE,
)
from avuhz_runtime.implementation_handoff import canonical_digest  # noqa: E402


SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
BASE = ROOT / "contracts/plans/v1"
PLAN_PATH = BASE / "development-auth-provider-read-diagnostic-v1.plan.json"
PROGRESS_PATH = BASE / "development-auth-provider-read-diagnostic-v1.progress.json"
APPROVAL_PATH = BASE / "development-auth-provider-read-diagnostic-v1.approval.json"
EXECUTION_PROGRESS_PATH = (
    BASE / "development-auth-provider-read-diagnostic-v1.execution-progress.json"
)
PRIOR_FAILURE_PATH = (
    BASE / "development-auth-v32-session-inspection-v1-failure.evidence.json"
)
PRIOR_EXECUTION_PROGRESS_PATH = (
    BASE / "development-auth-v32-session-inspection-v1.execution-progress.json"
)
WORKFLOW_PATH = (
    ROOT / ".github/workflows/development-auth-provider-read-diagnostic-v1.yml"
)
EXECUTOR_PATH = ROOT / "scripts/development_auth_provider_read_diagnostic_v1.py"
HELPER_PATH = (
    ROOT / "src/avuhz_engineering/development_auth_provider_read_diagnostic.py"
)
HTTP_HELPER_PATH = ROOT / "src/avuhz_engineering/provider_read_http.py"

PLAN_ID = "205c2cef-1b90-4346-b4eb-d19ded202d6a"
PROGRESS_ID = "8059e0cc-da3a-4c95-b4ad-00bc35512e54"
PLAN_DIGEST = "sha256:e38f0eac3128511f3e3c2d3bd45278276a69fe1ce86801e93c2417264e411f1d"
PROGRESS_DIGEST = "sha256:5f956df6a861088645ef7bb5831020683a03697ca87e93fbf631431951662e37"
PRIOR_FAILURE_RAW_DIGEST = (
    "sha256:ebf71894e7a6c774df7f4800bace81a23dfd898b27be96f505402ab326f272e5"
)
PROJECT_READ_CONTRACT_DIGEST = (
    "sha256:6a41a1173c187f3f058578bff9717093164b4647de4b72b7fd2c9ed016fffe96"
)
CREATED_AT = "2026-09-18T17:59:10Z"
WINDOW_START = "2026-09-19T15:00:00Z"
WINDOW_END = "2026-09-19T21:00:00Z"
STEP_ID = (
    "development.auth.provider-read-diagnostic-v1.step.01."
    "inspect-project-metadata-read-only"
)
OPERATION = "provider.project-metadata.inspect-read-only"
CONFIRMATION = "DIAGNOSE_DEVELOPMENT_AUTH_PROVIDER_READ_V1"


def load(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict), path
    return value


def raw_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def expect_schema_failure(candidate: dict) -> None:
    candidate["plan_digest"] = plan_digest(candidate)
    try:
        validate_plan(candidate, SCHEMA_ROOT)
    except AuthorizationPlanError as exc:
        assert str(exc) == "SCHEMA_INVALID", str(exc)
    else:
        raise AssertionError("invalid provider-read boundary must fail closed")


def main() -> int:
    plan = load(PLAN_PATH)
    progress = load(PROGRESS_PATH)
    prior_failure = load(PRIOR_FAILURE_PATH)
    prior_execution = load(PRIOR_EXECUTION_PROGRESS_PATH)

    validate_plan(plan, SCHEMA_ROOT)
    validate_progress(plan, progress, SCHEMA_ROOT)
    assert plan_digest(plan) == PLAN_DIGEST
    assert plan["plan_id"] == PLAN_ID
    assert plan["plan_version"] == 1
    assert plan["definition_status"] == "READY_FOR_APPROVAL"
    assert plan["authority_effect"] == "NONE_UNTIL_SEPARATELY_APPROVED"
    assert plan["environment"] == "DEVELOPMENT"
    assert plan["target"] == {
        "provider_class": "identity.provider",
        "provider_reference": "supabase",
        "project_reference": DEVELOPMENT_AUTH_PROJECT_REF,
        "responsibility": "AUTH",
        "issuer_reference": "https://pwlhruwutoitnieactol.supabase.co/auth/v1",
        "audience_reference": "audience.avuhz.command-service.development",
    }
    assert plan["authorization_window"] == {
        "binding_state": "BOUND",
        "starts_at": WINDOW_START,
        "expires_at": WINDOW_END,
    }
    assert plan["ordered_step_ids"] == [STEP_ID]
    assert len(plan["steps"]) == 1
    step = plan["steps"][0]
    assert step["step_id"] == STEP_ID
    assert step["operation"] == OPERATION
    assert step["execution_class"] == "PROVIDER_READ"
    assert step["dependency_step_ids"] == []
    assert step["credential_policy"] == {
        "permitted": True,
        "allowed_classes": [PROVIDER_READ_CREDENTIAL_CLASS],
        "values_stored": False,
    }
    assert step["resource"] == {
        "resource_type": "provider.project-metadata",
        "resource_reference": (
            f"supabase:{DEVELOPMENT_AUTH_PROJECT_REF}:project-metadata"
        ),
        "binding_state": "BOUND",
        "exact_version": "diagnostic.v1",
        "exact_digest": PROJECT_READ_CONTRACT_DIGEST,
    }
    assert canonical_digest(PROJECT_READ_CONTRACT) == PROJECT_READ_CONTRACT_DIGEST
    assert PROJECT_READ_CONTRACT == {
        "method": "GET",
        "url": PROJECT_READ_URL,
        "accepted_statuses": [200],
        "maximum_response_bytes": 256 * 1024,
        "expected_project": {
            "id": DEVELOPMENT_AUTH_PROJECT_REF,
            "ref": DEVELOPMENT_AUTH_PROJECT_REF,
            "name": DEVELOPMENT_AUTH_PROJECT_NAME,
        },
    }
    assert step["required_evidence"] == [
        {
            "evidence_type": "auth.session-state.inspected-read-only",
            "source_step_id": None,
            "binding_state": "BOUND",
            "exact_digest": PRIOR_FAILURE_RAW_DIGEST,
        }
    ]
    assert raw_digest(PRIOR_FAILURE_PATH) == PRIOR_FAILURE_RAW_DIGEST
    assert prior_failure["safe_error_code"] == "SESSION_INSPECTION_PROJECT_READ_FAILED"
    assert prior_failure["inspection_classification"] == "SESSION_STATE_UNVERIFIED"
    assert prior_execution["overall_state"] == "STOPPED"
    assert prior_execution["step_states"][0]["authorization_consumed"] is True
    assert prior_failure["authority_state"]["retry_authorized"] is False

    required_prohibitions = {
        "approval.create",
        "credential.create",
        "credential.rotate",
        "data.operation",
        "database.query",
        "identity.create",
        "identity.delete",
        "identity.modify",
        "n8n.operation",
        "production.target",
        "provider.mutation",
        "render.operation",
        "session.cleanup",
        "session.delete",
        "session.inspect",
        "session.issue",
        "sql.execute",
        "staging.target",
        "token.issue",
        "v32.retry",
        "v33.prepare",
    }
    assert required_prohibitions.issubset(plan["prohibited_actions"])
    assert required_prohibitions.issubset(step["prohibited_actions"])

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
    assert state["observed_postcondition"] is None
    assert state["safe_error_code"] is None

    assert not APPROVAL_PATH.exists()
    assert not EXECUTION_PROGRESS_PATH.exists()
    assert not list(
        BASE.glob("development-auth-provider-read-diagnostic-v1*.evidence.json")
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
    assert "workflow_dispatch" in workflow
    assert "PROVIDER_READ_ENV_REFERENCE" in executor
    assert "PROVIDER_READ_CREDENTIAL_CLASS" in executor
    assert PROVIDER_READ_ENV_REFERENCE in helper
    assert PROVIDER_READ_CREDENTIAL_CLASS in helper
    assert executor.count("inspect_development_auth_project_metadata(") == 1
    assert helper.count("request_json(") == 1
    assert http_helper.count("with urlopen(") == 1

    forbidden_surface = "\n".join((workflow, executor, helper, http_helper))
    for forbidden in (
        "/database/query/read-only",
        "auth.sessions",
        "auth.refresh_tokens",
        "/auth/v1/admin",
        "/auth/v1/logout",
        "SUPABASE_AUTH_ADMIN_EPHEMERAL",
        "service_role",
    ):
        assert forbidden not in forbidden_surface

    changed = copy.deepcopy(plan)
    changed["steps"][0]["operation"] = "provider.project-metadata.mutate"
    expect_schema_failure(changed)
    changed = copy.deepcopy(plan)
    changed["steps"][0]["execution_class"] = "PROVIDER_MUTATION"
    expect_schema_failure(changed)
    changed = copy.deepcopy(plan)
    changed["steps"][0]["credential_policy"]["allowed_classes"] = [
        PROVIDER_READ_CREDENTIAL_CLASS,
        "SUPABASE_AUTH_ADMIN_EPHEMERAL",
    ]
    expect_schema_failure(changed)

    schema = load(
        SCHEMA_ROOT / "orchestration/bounded-authorization-plan-v2.schema.json"
    )
    read_branch = next(
        branch
        for branch in schema["allOf"]
        if "SUPABASE_PROVIDER_READ" in json.dumps(branch, sort_keys=True)
    )
    assert set(
        read_branch["then"]["properties"]["steps"]["items"]["then"][
            "properties"
        ]["operation"]["enum"]
    ) == {
        "provider.auth-session-state.inspect-read-only",
        OPERATION,
    }

    print("DEVELOPMENT AUTH provider-read diagnostic v1 validation: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
