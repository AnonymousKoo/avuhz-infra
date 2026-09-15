#!/usr/bin/env python3
"""Validate the repository-only DEVELOPMENT AUTH v25 read-only allowlist plan preparation."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.authorization_plan import initial_progress, plan_digest, validate_plan, validate_progress
from avuhz_runtime.implementation_handoff import canonical_digest
from avuhz_service.development import (
    DEVELOPMENT_AUTH_ISSUER,
    DEVELOPMENT_AUTH_PROJECT_REF,
    DEVELOPMENT_SERVICE_AUDIENCE,
)
from avuhz_service.development_supabase_identity import DevelopmentIdentityAllowlistEntry

SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
BASE = ROOT / "contracts/plans/v1"
PLAN_PATH = BASE / "development-auth-integration-v25.plan.json"
PROGRESS_PATH = BASE / "development-auth-integration-v25.progress.json"
V21_SUCCESS_PATH = BASE / "development-auth-step1-v21-success.evidence.json"
V24_SUCCESS_PATH = BASE / "development-auth-step1-v24-success.evidence.json"
IDENTITY_POLICY_PATH = ROOT / "src/avuhz_service/development_supabase_identity.py"
DEVELOPMENT_COMPOSITION_PATH = ROOT / "src/avuhz_service/development.py"
CURRENT_STATE_PATH = ROOT / "docs/current-build-state.md"
ROADMAP_PATH = ROOT / "docs/roadmap.md"

PLAN_ID = "b9532651-b0a2-420f-a3fb-bde9c5c3d396"
PLAN_VERSION = 25
PLAN_DIGEST = "sha256:70f57ac94af8906388dc07fe21284d46182c3efb9c8c5eb2cc3d303e723aa5b8"
PROGRESS_ID = "a95f013c-839e-40e8-bd52-e04494034617"
PROGRESS_DIGEST = "sha256:8a9a5a36174bfadd5b67e182ce9c6891904b6a4e4c27850144f9c97eed4ef8d9"
STEP_ID = "development.auth.v25.step.01.bind-server-read-only-allowlist"
PROJECT = "pwlhruwutoitnieactol"
SUBJECT_DIGEST = "sha256:96ed2639ff64f1c0712d9548f8d524c4cd7f3025d30013c8857aace8661a84a5"
TENANT_ID = "1ad3998c-92ab-4a36-9d1c-ed97f2fa98f0"
PRINCIPAL_REFERENCE = "subject.development-synthetic-user"
POLICY_DIGEST = "sha256:864019b6d904f790fab298f0142989e067af65fa735094edc28ffa756de406f6"
V21_SUCCESS_DIGEST = "sha256:16fbd6f2b1b779a4879f9eca7b5469267822884740dab7a02d3a0f8c7211fffa"
V24_SUCCESS_DIGEST = "sha256:41614e42a7a65b6686affef494ad5ea00894c4fee2507331430ec35c0f80488e"
WINDOW_START = "2026-09-15T04:00:00Z"
WINDOW_END = "2026-09-15T10:00:00Z"

TARGET_POLICY = {
    "issuer": DEVELOPMENT_AUTH_ISSUER,
    "audience": DEVELOPMENT_SERVICE_AUDIENCE,
    "subject_digest": SUBJECT_DIGEST,
    "principal_reference": PRINCIPAL_REFERENCE,
    "tenant_id": TENANT_ID,
    "caller_type": "HUMAN",
    "capabilities": ["engagement:read"],
    "authority_roles": [],
}


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
    validate_plan(plan, SCHEMA_ROOT)
    validate_progress(plan, progress, SCHEMA_ROOT)

    assert plan["plan_id"] == PLAN_ID and plan["plan_version"] == PLAN_VERSION
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
        "binding_state": "BOUND", "starts_at": WINDOW_START, "expires_at": WINDOW_END,
    }
    assert plan["ordered_step_ids"] == [STEP_ID]

    step = plan["steps"][0]
    assert step["step_id"] == STEP_ID and step["ordinal"] == 1
    assert step["execution_class"] == "LOCAL_ONLY"
    assert step["operation"] == "local.capability-policy.bind-exact-tuple"
    assert step["credential_policy"] == {"permitted": False, "allowed_classes": ["NONE"], "values_stored": False}
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
        "provider.read", "provider.mutation", "credential.use", "tenant-metadata.bind",
        "hook.enable", "token.issue", "session.issue", "capability.wildcard",
        "authority-role.add", "raw-provider-subject.persist", "data.operation",
        "render.operation", "staging.target", "production.target",
    ):
        assert prohibited in step["prohibited_actions"] and prohibited in plan["prohibited_actions"]

    assert canonical_digest(TARGET_POLICY) == POLICY_DIGEST
    exact_values = {
        "binding.development.auth.v25.synthetic-subject-digest": SUBJECT_DIGEST,
        "binding.development.auth.v25.canonical-tenant": TENANT_ID,
        "binding.development.auth.v25.principal-reference": PRINCIPAL_REFERENCE,
        "binding.development.auth.v25.target-server-capability-policy": POLICY_DIGEST,
    }
    for binding_id, value in exact_values.items():
        item = declaration(step, binding_id)
        assert item["phase"] == "PREAPPROVAL_BOUND"
        assert item["preapproval_value"]["value"] == value
        assert item["preapproval_value"]["exact_digest"] == canonical_digest(value)
    produced = declaration(step, "binding.development.auth.v25.server-capability-policy")
    assert produced["phase"] == "PRODUCED_BY_CURRENT_STEP"
    assert produced["evidence_type"] == "server.capability-policy.verified"
    assert step["produced_evidence"] == [{
        "evidence_type": "server.capability-policy.verified",
        "established_binding_ids": ["binding.development.auth.v25.server-capability-policy"],
        "digest_policy": "REQUIRED",
    }]

    v21 = load(V21_SUCCESS_PATH)
    assert raw_digest(V21_SUCCESS_PATH) == V21_SUCCESS_DIGEST
    assert v21["outcome"] == "SUCCEEDED_VERIFIED"
    assert v21["project_reference"] == PROJECT
    assert v21["provider_observation"]["synthetic_subject_digest"] == SUBJECT_DIGEST
    assert v21["provider_observation"]["auth_user_count"] == 1
    assert v21["provider_observation"]["session_count"] == 0
    assert v21["provider_observation"]["refresh_token_count"] == 0

    v24 = load(V24_SUCCESS_PATH)
    assert raw_digest(V24_SUCCESS_PATH) == V24_SUCCESS_DIGEST
    assert v24["outcome"] == "SUCCEEDED_VERIFIED"
    assert v24["project_reference"] == PROJECT
    assert v24["provider_observation"]["synthetic_subject_digest"] == SUBJECT_DIGEST
    assert v24["provider_observation"]["canonical_tenant_id"] == TENANT_ID
    assert v24["provider_observation"]["app_metadata_exact_target_shape"] is True
    assert v24["provider_observation"]["session_count"] == 0
    assert v24["provider_observation"]["refresh_token_count"] == 0

    expected_progress = initial_progress(plan, SCHEMA_ROOT, PROGRESS_ID, plan["created_at"])
    assert progress == expected_progress
    assert progress["progress_digest"] == PROGRESS_DIGEST
    assert progress["overall_state"] == "NOT_STARTED"
    state = progress["step_states"][0]
    assert state["authorization_state"] == "PENDING"
    assert state["execution_state"] == "NOT_STARTED"
    assert state["verification_state"] == "NOT_STARTED"
    assert state["authorization_consumed"] is False
    assert state["evidence"] == [] and state["binding_assertions"] == []

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
        'hmac.compare_digest(entry.subject_digest, digest)',
        'and entry.tenant_id == tenant_id',
        'authority_roles=frozenset()',
    ):
        assert fragment in identity_policy, fragment
    composition = DEVELOPMENT_COMPOSITION_PATH.read_text(encoding="utf-8")
    assert "identity_resolver=_UnavailableIdentityResolver()" in composition

    assert not (BASE / "development-auth-integration-v25.approval.json").exists()
    assert not (BASE / "development-auth-integration-v25.execution-progress.json").exists()
    assert not (BASE / "development-auth-step1-v25-success.evidence.json").exists()
    assert not (BASE / "development-auth-step1-v25-preflight.evidence.json").exists()
    assert not list((ROOT / ".github/workflows").glob("*v25*"))

    current_state = CURRENT_STATE_PATH.read_text(encoding="utf-8")
    roadmap = ROADMAP_PATH.read_text(encoding="utf-8")
    assert "AUTH v24 tenant metadata binding is complete and verified" in current_state
    assert "AUTH v25" in current_state and "server-owned read-only allowlist" in current_state
    assert "Bind provider-controlled tenant metadata — COMPLETE through AUTH v24" in roadmap
    assert "Prepare forward-only AUTH v25" in roadmap

    print(
        "DEVELOPMENT_AUTH_V25_PREPARED=PASS "
        "(exact local-only server allowlist plan; credential class NONE; no provider contact or mutation; no v25 approval/execution artifacts)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
