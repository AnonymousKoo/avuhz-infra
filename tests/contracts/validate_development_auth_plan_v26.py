#!/usr/bin/env python3
"""Validate DEVELOPMENT AUTH v26 through exact owner-approval persistence."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.authorization_plan import (
    AuthorizationPlanStop,
    approval_digest,
    initial_progress,
    plan_digest,
    validate_approval,
    validate_plan,
    validate_progress,
)
from avuhz_runtime.implementation_handoff import canonical_digest
from avuhz_service.development import (
    DEVELOPMENT_AUTH_ISSUER,
    DEVELOPMENT_AUTH_PROJECT_REF,
    DEVELOPMENT_SERVICE_AUDIENCE,
)
from avuhz_service.development_supabase_identity import DevelopmentIdentityAllowlistEntry

SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
BASE = ROOT / "contracts/plans/v1"
PLAN_PATH = BASE / "development-auth-integration-v26.plan.json"
PROGRESS_PATH = BASE / "development-auth-integration-v26.progress.json"
APPROVAL_PATH = BASE / "development-auth-integration-v26.approval.json"
V25_PLAN_PATH = BASE / "development-auth-integration-v25.plan.json"
V25_PROGRESS_PATH = BASE / "development-auth-integration-v25.progress.json"
V25_APPROVAL_PATH = BASE / "development-auth-integration-v25.approval.json"
V25_EXPIRY_PATH = BASE / "development-auth-v25-expiry.evidence.json"
V21_SUCCESS_PATH = BASE / "development-auth-step1-v21-success.evidence.json"
V24_SUCCESS_PATH = BASE / "development-auth-step1-v24-success.evidence.json"
IDENTITY_POLICY_PATH = ROOT / "src/avuhz_service/development_supabase_identity.py"
DEVELOPMENT_COMPOSITION_PATH = ROOT / "src/avuhz_service/development.py"

PLAN_ID = "f6c223d0-5e3e-43e1-b90c-190367840bec"
PLAN_DIGEST = "sha256:e43e7a01dd79686bbb5efa744444126800e0d5b488461253fa7281fdd227a2c4"
PROGRESS_ID = "87328d7e-4da7-4ecb-967b-5c06b4dc0e32"
PROGRESS_DIGEST = "sha256:204fdf51178987ecd23b8843030e03e2199ca1137b7e6e2e26afbcaac34000cc"
APPROVAL_ID = "81b253a2-c63e-4749-b918-20665c0a335c"
APPROVAL_DIGEST = "sha256:9c0c24b34d9bdedebd4506b20062cb0ead936b176e4ecde8583bf2312895f226"
APPROVAL_FILE_DIGEST = "sha256:4d7b8b08c7e934754b5988578575e313bc2ae15f3ca1f648732e7bb2d9d3c911"
APPROVED_AT = "2026-09-15T13:01:38Z"
STEP_ID = "development.auth.v26.step.01.bind-server-read-only-allowlist"
PROJECT = "pwlhruwutoitnieactol"
SUBJECT_DIGEST = "sha256:96ed2639ff64f1c0712d9548f8d524c4cd7f3025d30013c8857aace8661a84a5"
TENANT_ID = "1ad3998c-92ab-4a36-9d1c-ed97f2fa98f0"
PRINCIPAL_REFERENCE = "subject.development-synthetic-user"
POLICY_DIGEST = "sha256:864019b6d904f790fab298f0142989e067af65fa735094edc28ffa756de406f6"
V21_SUCCESS_DIGEST = "sha256:16fbd6f2b1b779a4879f9eca7b5469267822884740dab7a02d3a0f8c7211fffa"
V24_SUCCESS_DIGEST = "sha256:41614e42a7a65b6686affef494ad5ea00894c4fee2507331430ec35c0f80488e"
WINDOW_START = "2026-09-15T15:00:00Z"
WINDOW_END = "2026-09-15T21:00:00Z"


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def raw_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def declaration(step: dict, binding_id: str) -> dict:
    matches = [item for item in step["binding_declarations"] if item["binding_id"] == binding_id]
    assert len(matches) == 1, binding_id
    return matches[0]


def main() -> int:
    plan = load(PLAN_PATH)
    progress = load(PROGRESS_PATH)
    approval = load(APPROVAL_PATH)
    validate_plan(plan, SCHEMA_ROOT)
    validate_progress(plan, progress, SCHEMA_ROOT)
    validate_approval(plan, approval, SCHEMA_ROOT, WINDOW_START)
    validate_approval(plan, approval, SCHEMA_ROOT, "2026-09-15T20:59:59Z")

    assert plan["plan_id"] == PLAN_ID and plan["plan_version"] == 26
    assert plan["plan_digest"] == PLAN_DIGEST and plan_digest(plan) == PLAN_DIGEST
    assert plan["definition_status"] == "READY_FOR_APPROVAL"
    assert plan["authority_effect"] == "NONE_UNTIL_SEPARATELY_APPROVED"
    assert plan["environment"] == "DEVELOPMENT"
    assert plan["owner_identity"] == "github:AnonymousKoo"
    assert plan["target"] == {
        "provider_class": "identity.provider",
        "provider_reference": "supabase",
        "project_reference": PROJECT,
        "responsibility": "AUTH",
        "issuer_reference": DEVELOPMENT_AUTH_ISSUER,
        "audience_reference": DEVELOPMENT_SERVICE_AUDIENCE,
    }
    assert DEVELOPMENT_AUTH_PROJECT_REF == PROJECT
    assert plan["authorization_window"] == {
        "binding_state": "BOUND",
        "starts_at": WINDOW_START,
        "expires_at": WINDOW_END,
    }
    assert plan["ordered_step_ids"] == [STEP_ID]

    assert raw_digest(APPROVAL_PATH) == APPROVAL_FILE_DIGEST
    assert approval == {
        "approval_id": APPROVAL_ID,
        "plan_id": PLAN_ID,
        "plan_version": 26,
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

    step = plan["steps"][0]
    assert step["step_id"] == STEP_ID and step["ordinal"] == 1
    assert step["operation"] == "local.capability-policy.bind-exact-tuple"
    assert step["execution_class"] == "LOCAL_ONLY"
    assert step["credential_policy"] == {
        "permitted": False,
        "allowed_classes": ["NONE"],
        "values_stored": False,
    }
    assert step["resource"] == {
        "resource_type": "server.capability-policy-entry",
        "resource_reference": "policy.development.synthetic-engagement-read",
        "binding_state": "BOUND",
        "exact_version": "version.1",
        "exact_digest": POLICY_DIGEST,
    }
    assert step["dependency_step_ids"] == [] and step["unresolved_bindings"] == []
    assert step["required_evidence"] == [
        {"evidence_type": "auth.synthetic-identity.created", "source_step_id": None, "binding_state": "BOUND", "exact_digest": V21_SUCCESS_DIGEST},
        {"evidence_type": "auth.synthetic-identity.tenant-metadata.bound", "source_step_id": None, "binding_state": "BOUND", "exact_digest": V24_SUCCESS_DIGEST},
    ]
    for prohibited in (
        "provider.read", "provider.mutation", "credential.use", "hook.enable",
        "token.issue", "session.issue", "capability.wildcard", "authority-role.add",
        "raw-provider-subject.persist", "data.operation", "render.operation",
        "staging.target", "production.target",
    ):
        assert prohibited in step["prohibited_actions"]
        assert prohibited in plan["prohibited_actions"]

    target_policy = {
        "issuer": DEVELOPMENT_AUTH_ISSUER,
        "audience": DEVELOPMENT_SERVICE_AUDIENCE,
        "subject_digest": SUBJECT_DIGEST,
        "principal_reference": PRINCIPAL_REFERENCE,
        "tenant_id": TENANT_ID,
        "caller_type": "HUMAN",
        "capabilities": ["engagement:read"],
        "authority_roles": [],
    }
    assert canonical_digest(target_policy) == POLICY_DIGEST
    exact_values = {
        "binding.development.auth.v26.synthetic-subject-digest": SUBJECT_DIGEST,
        "binding.development.auth.v26.canonical-tenant": TENANT_ID,
        "binding.development.auth.v26.principal-reference": PRINCIPAL_REFERENCE,
        "binding.development.auth.v26.target-server-capability-policy": POLICY_DIGEST,
    }
    for binding_id, value in exact_values.items():
        item = declaration(step, binding_id)
        assert item["phase"] == "PREAPPROVAL_BOUND"
        assert item["preapproval_value"]["value"] == value
        assert item["preapproval_value"]["exact_digest"] == canonical_digest(value)
    produced = declaration(step, "binding.development.auth.v26.server-capability-policy")
    assert produced["phase"] == "PRODUCED_BY_CURRENT_STEP"
    assert produced["evidence_type"] == "server.capability-policy.verified"
    assert step["produced_evidence"] == [{
        "evidence_type": "server.capability-policy.verified",
        "established_binding_ids": ["binding.development.auth.v26.server-capability-policy"],
        "digest_policy": "REQUIRED",
    }]

    assert raw_digest(V21_SUCCESS_PATH) == V21_SUCCESS_DIGEST
    assert raw_digest(V24_SUCCESS_PATH) == V24_SUCCESS_DIGEST
    expected_progress = initial_progress(plan, SCHEMA_ROOT, PROGRESS_ID, plan["created_at"])
    assert progress == expected_progress
    assert progress["progress_digest"] == PROGRESS_DIGEST
    state = progress["step_states"][0]
    assert progress["overall_state"] == "NOT_STARTED"
    assert state["authorization_state"] == "PENDING"
    assert state["execution_state"] == "NOT_STARTED"
    assert state["verification_state"] == "NOT_STARTED"
    assert state["authorization_consumed"] is False
    assert state["evidence"] == [] and state["binding_assertions"] == []

    v25_plan = load(V25_PLAN_PATH)
    v25_progress = load(V25_PROGRESS_PATH)
    v25_approval = load(V25_APPROVAL_PATH)
    v25_expiry = load(V25_EXPIRY_PATH)
    validate_plan(v25_plan, SCHEMA_ROOT)
    validate_progress(v25_plan, v25_progress, SCHEMA_ROOT)
    assert v25_expiry["outcome"] == "EXPIRED_UNEXECUTED"
    assert v25_expiry["progress_state"]["authorization_consumed"] is False
    assert v25_expiry["effects"] == {
        "allowlist_bound": False,
        "provider_contact_attempted": False,
        "provider_mutation_attempted": False,
        "credential_used": False,
    }
    assert v25_expiry["approval_file_digest"] == raw_digest(V25_APPROVAL_PATH)
    try:
        validate_approval(v25_plan, v25_approval, SCHEMA_ROOT, v25_expiry["observed_at"])
    except AuthorizationPlanStop as exc:
        assert str(exc) == "PLAN_AUTHORIZATION_EXPIRED"
    else:
        raise AssertionError("v25 approval must be expired at audit observation time")

    entry = DevelopmentIdentityAllowlistEntry(
        subject_digest=SUBJECT_DIGEST,
        principal_reference=PRINCIPAL_REFERENCE,
        tenant_id=TENANT_ID,
    )
    assert entry.subject_digest == SUBJECT_DIGEST
    assert entry.principal_reference == PRINCIPAL_REFERENCE
    assert entry.tenant_id == TENANT_ID
    identity_policy = IDENTITY_POLICY_PATH.read_text(encoding="utf-8")
    for fragment in (
        '_READ_ONLY_CAPABILITIES = frozenset({"engagement:read"})',
        '_SYNTHETIC_CALLER_TYPE = "HUMAN"',
        'len(allowlist) != 1',
        'authority_roles=frozenset()',
    ):
        assert fragment in identity_policy, fragment
    assert "identity_resolver=_UnavailableIdentityResolver()" in DEVELOPMENT_COMPOSITION_PATH.read_text(encoding="utf-8")

    assert not (BASE / "development-auth-integration-v26.execution-progress.json").exists()
    assert not (BASE / "development-auth-step1-v26-preflight.evidence.json").exists()
    assert not (BASE / "development-auth-step1-v26-success.evidence.json").exists()
    assert not list((ROOT / ".github/workflows").glob("*v26*"))

    print(
        "DEVELOPMENT_AUTH_V26_APPROVAL=PASS "
        "(exact owner approval persisted before effective time; LOCAL_ONLY; credential NONE; pristine/unexecuted; no provider contact)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
