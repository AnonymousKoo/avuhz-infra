#!/usr/bin/env python3
"""Validate pristine DEVELOPMENT Render DATA secret-binding v1 package."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.authorization_plan import (  # noqa: E402
    approval_digest,
    initial_progress,
    plan_digest,
    validate_approval,
    validate_plan,
    validate_progress,
)
from avuhz_runtime.implementation_handoff import canonical_digest  # noqa: E402

SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
BASE = ROOT / "contracts/plans/v1"
PLAN_PATH = BASE / "development-render-data-secret-binding-v1.plan.json"
PROGRESS_PATH = BASE / "development-render-data-secret-binding-v1.progress.json"
RESOURCE_PATH = BASE / "development-render-data-secret-binding-v1.resource.json"
APPROVAL_PATH = BASE / "development-render-data-secret-binding-v1.approval.json"
CATALOG_EVIDENCE_PATH = BASE / "development-data-catalog-rls-validation-v1-step1-success.evidence.json"
CATALOG_PROGRESS_PATH = BASE / "development-data-catalog-rls-validation-v1.execution-progress.json"
BASELINE_PATH = ROOT / "scripts/check-baseline.sh"

PLAN_ID = "1ffefca9-e37d-4ead-9df1-1b33375f3d0d"
PLAN_DIGEST = "sha256:b1340b65458ef487d7fdc037ca6e255f38018b39207ff15718f7d1d6182fdcf8"
PROGRESS_ID = "a0a0b766-20a8-446f-bb16-ef85a038c09e"
PROGRESS_DIGEST = "sha256:8904127e314cdde0c2a7faf5ff754bdf20b48fad7a5ecca1393767f1dd0d4364"
RESOURCE_DIGEST = "sha256:6b5a9d6b18d2ad26df6eb650ca6838545676464c76475e8a053b7710f4fd74f9"
CATALOG_EVIDENCE_DIGEST = "sha256:b6db300972239326512e881d960659d29a8ad3d2ddb277029fb0b2edd46b7c76"
CATALOG_PROGRESS_DIGEST = "sha256:853f5cd3c6988c3e7dcccaf9b4272f7a60e7563cfb55e998ae2ab7ce01c56d45"
STEP_ID = "development.render.data-secret-binding-v1.step.01.bind-avuhz-postgres-dsn"
APPROVAL_ID = "6a7ddbe8-b969-49cf-ac79-788473c11d58"
APPROVAL_DIGEST = "sha256:d916a034dca70c662379f62041ff54f31888928f976382088e4ca52374634171"
APPROVED_AT = "2026-10-01T02:38:51Z"


def load(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict), path
    return value


def main() -> int:
    plan = load(PLAN_PATH)
    progress = load(PROGRESS_PATH)
    resource = load(RESOURCE_PATH)
    approval = load(APPROVAL_PATH)
    catalog_evidence = load(CATALOG_EVIDENCE_PATH)
    catalog_progress = load(CATALOG_PROGRESS_PATH)

    validate_plan(plan, SCHEMA_ROOT)
    validate_progress(plan, progress, SCHEMA_ROOT)
    validate_approval(plan, approval, SCHEMA_ROOT, plan["authorization_window"]["starts_at"])

    assert plan["plan_id"] == PLAN_ID
    assert plan["plan_version"] == 1
    assert plan["plan_digest"] == PLAN_DIGEST == plan_digest(plan)
    assert plan["definition_status"] == "READY_FOR_APPROVAL"
    assert plan["environment"] == "DEVELOPMENT"
    assert plan["target"] == {
        "provider_class": "runtime.provider",
        "provider_reference": "render",
        "project_reference": "srv-dab9n4qd0e5s73dq37mg",
        "responsibility": "RUNTIME",
        "issuer_reference": None,
        "audience_reference": None,
    }
    assert plan["authorization_window"] == {
        "binding_state": "BOUND",
        "starts_at": "2026-10-01T03:00:00Z",
        "expires_at": "2026-10-01T06:00:00Z",
    }
    assert plan["authority_effect"] == "NONE_UNTIL_SEPARATELY_APPROVED"
    assert plan["ordered_step_ids"] == [STEP_ID]

    step = plan["steps"][0]
    assert step["step_id"] == STEP_ID
    assert step["execution_class"] == "PROVIDER_MUTATION"
    assert step["operation"] == "provider.render.environment-variable.bind-owner-interactive"
    assert step["credential_policy"] == {
        "permitted": True,
        "allowed_classes": ["OWNER_INTERACTIVE_SESSION"],
        "values_stored": False,
    }
    assert step["resource"] == {
        "resource_type": "render.service.environment-variable",
        "resource_reference": "render:srv-dab9n4qd0e5s73dq37mg:AVUHZ_POSTGRES_DSN",
        "binding_state": "BOUND",
        "exact_version": "render.secret-binding.v1",
        "exact_digest": RESOURCE_DIGEST,
    }
    assert step["required_evidence"] == [
        {
            "evidence_type": "data.catalog-rls.validated",
            "source_step_id": None,
            "binding_state": "BOUND",
            "exact_digest": CATALOG_EVIDENCE_DIGEST,
        },
        {
            "evidence_type": "authorization-plan.execution-progress",
            "source_step_id": None,
            "binding_state": "BOUND",
            "exact_digest": CATALOG_PROGRESS_DIGEST,
        },
    ]

    assert canonical_digest(resource) == RESOURCE_DIGEST
    assert resource["environment"] == "DEVELOPMENT"
    assert resource["provider"] == "render"
    assert resource["workspace_id"] == "tea-dab95hv40ujc73a7ccag"
    assert resource["service_id"] == "srv-dab9n4qd0e5s73dq37mg"
    assert resource["service_name"] == "avuhz-command-dev"
    assert resource["environment_id"] == "evm-dab96l2jobas73bp95bg"
    assert resource["environment_variable"] == "AVUHZ_POSTGRES_DSN"
    assert resource["auto_deploy"] == "no"
    assert resource["current_live_deploy_id"] == "dep-dabab1942hec73acamdg"
    assert resource["current_live_commit"] == "6bff57065151462fc74861c68a232454b2ef9a20"
    assert resource["allowed_environment_variable_changes"] == 1
    assert resource["deploy_authorized"] is False
    assert resource["service_setting_changes_authorized"] is False
    assert resource["secret_material_agent_visible"] is False
    assert resource["secret_material_git_persisted"] is False
    assert resource["secret_material_local_persisted"] is False

    assert catalog_evidence["outcome"] == "SUCCEEDED_VERIFIED"
    assert catalog_evidence["evidence_type"] == "data.catalog-rls.validated"
    assert catalog_evidence["provider_observation"]["table_count"] == 16
    assert catalog_evidence["provider_observation"]["policy_count"] == 16
    assert catalog_evidence["provider_observation"]["transaction_read_only"] is True
    assert catalog_evidence["security_state"]["provider_mutation_attempted"] is False
    assert catalog_progress["overall_state"] == "COMPLETED"
    assert catalog_progress["progress_digest"] == CATALOG_PROGRESS_DIGEST

    assert progress == initial_progress(
        plan, SCHEMA_ROOT, PROGRESS_ID, plan["created_at"]
    )
    assert progress["progress_digest"] == PROGRESS_DIGEST
    assert progress["overall_state"] == "NOT_STARTED"
    state = progress["step_states"][0]
    assert state["authorization_state"] == "PENDING"
    assert state["execution_state"] == "NOT_STARTED"
    assert state["verification_state"] == "NOT_STARTED"
    assert state["authorization_consumed"] is False
    assert state["evidence"] == []
    assert state["binding_assertions"] == []
    assert approval == {
        "approval_id": APPROVAL_ID,
        "plan_id": PLAN_ID,
        "plan_version": 1,
        "plan_digest": PLAN_DIGEST,
        "owner_identity": "github:AnonymousKoo",
        "decision": "APPROVE",
        "environment": "DEVELOPMENT",
        "effective_at": "2026-10-01T03:00:00Z",
        "expires_at": "2026-10-01T06:00:00Z",
        "approved_at": APPROVED_AT,
        "status": "ACTIVE",
        "authority_scope": "EXACT_PLAN_ONLY",
        "approval_digest": APPROVAL_DIGEST,
    }
    assert approval["approval_digest"] == APPROVAL_DIGEST == approval_digest(approval)

    rendered = PLAN_PATH.read_text() + RESOURCE_PATH.read_text() + PROGRESS_PATH.read_text()
    for forbidden in (
        "postgresql://",
        "sslmode=require user=",
        "password=",
        "op://",
    ):
        assert forbidden not in rendered
    assert "render.deploy" in step["prohibited_actions"]
    assert "deployment.trigger" in step["prohibited_actions"]
    assert "environment-variable.other.modify" in step["prohibited_actions"]
    assert "secret.agent-visible" in step["prohibited_actions"]
    assert "secret.log" in step["prohibited_actions"]
    assert "secret.return" in step["prohibited_actions"]

    baseline = BASELINE_PATH.read_text(encoding="utf-8")
    assert "validate_development_render_data_secret_binding_v1.py" in baseline
    assert "forbidden credential-shaped content" in baseline
    assert "Semgrep local secret rules" in baseline

    print(
        "DEVELOPMENT Render DATA secret-binding v1: PASS "
        "(APPROVED; pristine progress; exact one-service/one-env-key scope; "
        "deploy prohibited; no secret material persisted or provider execution)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
