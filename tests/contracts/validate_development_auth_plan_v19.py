#!/usr/bin/env python3
"""Validate DEVELOPMENT AUTH v19 through exact owner-approval persistence."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.authorization_plan import (
    initial_progress,
    validate_approval,
    validate_plan,
    validate_progress,
)
from avuhz_runtime.implementation_handoff import canonical_digest

SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
PLAN_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v19.plan.json"
PROGRESS_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v19.progress.json"
APPROVAL_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v19.approval.json"
V18_PLAN_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v18.plan.json"
V18_PROGRESS_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v18.progress.json"
V16_EXECUTION_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v16.execution-progress.json"
V16_EVIDENCE_PATH = ROOT / "contracts/plans/v1/development-auth-step1-v16-success.evidence.json"

PLAN_ID = "d5b33ca7-9046-433b-b8fb-ea4ec02f337f"
PROGRESS_ID = "9ee565bb-40fa-460f-a72d-3762b97e402f"
PLAN_DIGEST = "sha256:4e6bb3a76b4d15b7993b2567c6743497b285bbecd03100f7ce73bbbc7a0cc72e"
PROGRESS_DIGEST = "sha256:ef3d232916d7be0d4a65e94d0bbfaa635258c937ae58bfa038fd43a4bf185fa8"
APPROVAL_ID = "3a1c0a4a-546f-49c3-b708-148d8af98e35"
APPROVAL_DIGEST = "sha256:3e31e523d03220c8301a76430dbd3d1c7a72538b711661b187ea063c3306e6d9"
V18_PLAN_DIGEST = "sha256:7da691db562c93e051a381411297116cc59de6d32eef215b65fc9ac7f10f8175"
V18_PROGRESS_DIGEST = "sha256:826919f64b1f72def239bac5d44ce247bf6ffabd4bbce686d0396c7a17f6c4b6"
V16_EVIDENCE_DIGEST = "sha256:0cfa1a3515e6496e9bc215de4579d5e4ff5b46f0299227b60708dc72ff2fb194"
V16_DEPLOYED_STATE_DIGEST = "sha256:97f18e0a729762f9e9c7d72507a489aa828bbe03a138b25acfadcd72dd43a735"
V16_DEPLOYED_STATE_VALUE_DIGEST = "sha256:2fc081713e1dd9288b6633eb484a80e157444241992588251f7f858fa06a0d9d"
STEP_ID = "development.auth.v19.step.01.create-synthetic-identity"
CREATED_AT = "2026-09-14T07:32:12Z"
APPROVED_AT = "2026-09-14T07:45:58Z"
WINDOW_START = "2026-09-14T09:00:00Z"
WINDOW_END = "2026-09-14T12:00:00Z"


def load(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    assert isinstance(value, dict), path
    return value


def raw_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    plan = load(PLAN_PATH)
    progress = load(PROGRESS_PATH)
    approval = load(APPROVAL_PATH)
    v18_plan = load(V18_PLAN_PATH)
    v18_progress = load(V18_PROGRESS_PATH)
    v16_execution = load(V16_EXECUTION_PATH)
    v16_evidence = load(V16_EVIDENCE_PATH)

    validate_plan(plan, SCHEMA_ROOT)
    validate_progress(plan, progress, SCHEMA_ROOT)
    validate_plan(v18_plan, SCHEMA_ROOT)
    validate_progress(v18_plan, v18_progress, SCHEMA_ROOT)
    validate_approval(plan, approval, SCHEMA_ROOT, WINDOW_START)
    validate_approval(plan, approval, SCHEMA_ROOT, "2026-09-14T11:59:59Z")

    assert plan["plan_id"] == PLAN_ID
    assert plan["plan_version"] == 19
    assert plan["plan_digest"] == PLAN_DIGEST
    assert plan["definition_status"] == "READY_FOR_APPROVAL"
    assert plan["environment"] == "DEVELOPMENT"
    assert plan["target"] == {
        "provider_class": "identity.provider",
        "provider_reference": "supabase",
        "project_reference": "pwlhruwutoitnieactol",
        "responsibility": "AUTH",
        "issuer_reference": "https://pwlhruwutoitnieactol.supabase.co/auth/v1",
        "audience_reference": "audience.avuhz.command-service.development",
    }
    assert plan["owner_identity"] == "github:AnonymousKoo"
    assert plan["created_at"] == CREATED_AT
    assert plan["authorization_window"] == {
        "binding_state": "BOUND",
        "starts_at": WINDOW_START,
        "expires_at": WINDOW_END,
    }
    assert plan["authority_effect"] == "NONE_UNTIL_SEPARATELY_APPROVED"
    assert plan["ordered_step_ids"] == [STEP_ID]

    assert approval == {
        "approval_id": APPROVAL_ID,
        "plan_id": PLAN_ID,
        "plan_version": 19,
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
    assert APPROVED_AT < WINDOW_START

    step = plan["steps"][0]
    assert step["step_id"] == STEP_ID
    assert step["resource"] == {
        "resource_type": "auth.synthetic-identity",
        "resource_reference": "identity.development.synthetic-avuhz",
        "binding_state": "BOUND",
        "exact_version": "version.1",
        "exact_digest": None,
    }
    assert step["operation"] == "provider.auth-identity.create-one"
    assert step["execution_class"] == "PROVIDER_MUTATION"
    assert step["dependency_step_ids"] == []
    assert step["credential_policy"] == {
        "permitted": True,
        "allowed_classes": ["OWNER_INTERACTIVE_SESSION"],
        "values_stored": False,
    }
    assert step["unresolved_bindings"] == []
    assert step["required_evidence"] == [{
        "evidence_type": "hook.v2.disabled-acl.verified",
        "source_step_id": None,
        "binding_state": "BOUND",
        "exact_digest": V16_EVIDENCE_DIGEST,
    }]

    for prohibited in (
        "customer.identity.create", "identity.bulk-create", "credential.persist",
        "tenant-metadata.bind", "server-allowlist.bind", "hook.enable", "token.issue",
        "data.operation", "render.operation", "staging.target", "production.target",
    ):
        assert prohibited in step["prohibited_actions"]
        assert prohibited in plan["prohibited_actions"]
    for prohibited in (
        "v17.approval.backdate", "v17.plan.execute",
        "v18.approval.backdate", "v18.plan.execute",
    ):
        assert prohibited in plan["prohibited_actions"]
    assert "provider.mutation" not in plan["prohibited_actions"]

    preapproval = next(
        item for item in step["binding_declarations"]
        if item["binding_id"] == "binding.development.auth.v19.v16-disabled-hook-state"
    )
    assert preapproval["phase"] == "PREAPPROVAL_BOUND"
    assert preapproval["value_class"] == "CONTENT_DIGEST"
    assert preapproval["persistence_policy"] == "DIGEST_ONLY"
    assert preapproval["preapproval_value"] == {
        "value": V16_DEPLOYED_STATE_DIGEST,
        "exact_digest": V16_DEPLOYED_STATE_VALUE_DIGEST,
    }
    assert canonical_digest(V16_DEPLOYED_STATE_DIGEST) == V16_DEPLOYED_STATE_VALUE_DIGEST

    preflight = next(
        item for item in step["binding_declarations"]
        if item["binding_id"] == "binding.development.auth.v19.identity-create-preflight"
    )
    assert preflight["phase"] == "RESOLVED_BY_STEP_PREFLIGHT"
    assert preflight["evidence_type"] == "auth.synthetic-identity.create-preflight.observed"
    assert preflight["persistence_policy"] == "DIGEST_ONLY"

    produced = next(
        item for item in step["binding_declarations"]
        if item["binding_id"] == "binding.development.auth.v19.synthetic-identity"
    )
    assert produced["phase"] == "PRODUCED_BY_CURRENT_STEP"
    assert produced["value_class"] == "STABLE_REFERENCE"
    assert produced["evidence_type"] == "auth.synthetic-identity.created"
    assert produced["persistence_policy"] == "DIGEST_ONLY"
    assert step["produced_evidence"] == [{
        "evidence_type": "auth.synthetic-identity.created",
        "established_binding_ids": ["binding.development.auth.v19.synthetic-identity"],
        "digest_policy": "REQUIRED",
    }]

    assert raw_digest(V16_EVIDENCE_PATH) == V16_EVIDENCE_DIGEST
    assert v16_evidence["evidence_type"] == "hook.v2.disabled-acl.verified"
    assert v16_evidence["outcome"] == "SUCCEEDED_VERIFIED"
    assert v16_evidence["project_reference"] == "pwlhruwutoitnieactol"
    assert v16_evidence["verification_observation"]["deployed_state_digest"] == V16_DEPLOYED_STATE_DIGEST
    assert v16_evidence["hosted_auth_observation"]["custom_access_token_hook_enabled"] is False
    assert v16_evidence["security_state"]["credential_retained"] is False
    assert v16_evidence["security_state"]["pii_retained"] is False
    assert v16_execution["overall_state"] == "COMPLETED"

    assert v18_plan["plan_version"] == 18
    assert v18_plan["plan_digest"] == V18_PLAN_DIGEST
    assert v18_progress["progress_digest"] == V18_PROGRESS_DIGEST
    assert v18_progress["overall_state"] == "NOT_STARTED"
    v18_state = v18_progress["step_states"][0]
    assert v18_state["authorization_state"] == "PENDING"
    assert v18_state["execution_state"] == "NOT_STARTED"
    assert v18_state["verification_state"] == "NOT_STARTED"
    assert v18_state["authorization_consumed"] is False
    assert v18_state["evidence"] == []
    assert not (ROOT / "contracts/plans/v1/development-auth-integration-v18.approval.json").exists()

    v18_step = v18_plan["steps"][0]
    for field in (
        "resource", "operation", "dependency_step_ids", "required_evidence",
        "expected_postcondition", "prohibited_actions", "stop_conditions",
        "correction_reference", "execution_class", "credential_policy", "unresolved_bindings",
    ):
        assert step[field] == v18_step[field], field

    expected_progress = initial_progress(plan, SCHEMA_ROOT, PROGRESS_ID, CREATED_AT)
    assert progress == expected_progress
    assert progress["progress_digest"] == PROGRESS_DIGEST
    state = progress["step_states"][0]
    assert state["authorization_state"] == "PENDING"
    assert state["execution_state"] == "NOT_STARTED"
    assert state["verification_state"] == "NOT_STARTED"
    assert state["authorization_consumed"] is False
    assert state["evidence"] == []
    assert state["binding_assertions"] == []

    for path in (
        ROOT / "contracts/plans/v1/development-auth-integration-v19.execution-progress.json",
        ROOT / "contracts/plans/v1/development-auth-step1-v19-preflight.evidence.json",
        ROOT / "contracts/plans/v1/development-auth-step1-v19-success.evidence.json",
    ):
        assert not path.exists(), path

    print(
        "DEVELOPMENT_AUTH_V19_APPROVAL=PASS "
        "(exact owner approval persisted before effective time; full synthetic-identity scope "
        "certification preserved; Step 1 pending/unexecuted/unconsumed; no provider mutation attempted)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
