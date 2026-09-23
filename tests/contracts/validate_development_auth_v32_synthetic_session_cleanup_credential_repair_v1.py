#!/usr/bin/env python3
"""Validate the pristine DEVELOPMENT AUTH cleanup credential-repair boundary."""
from __future__ import annotations

import hashlib
import json
import re
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
BOUNDARY = "development-auth-v32-synthetic-session-cleanup-credential-repair-v1"
PLAN_PATH = BASE / f"{BOUNDARY}.plan.json"
PROGRESS_PATH = BASE / f"{BOUNDARY}.progress.json"
APPROVAL_PATH = BASE / f"{BOUNDARY}.approval.json"
PLAN_ID = "0224c4fb-845c-4627-b48f-252ec954283c"
PROGRESS_ID = "764ab6f1-e189-499a-9bb3-b1a7bcf6e52f"
PLAN_DIGEST = "sha256:57b26eefa9ca294a4dff95d617a50c3e46d0cdaab1cf1862c1d1239d042babcb"
PROGRESS_DIGEST = "sha256:027a7aaed6577ac0fccb97f225ebfdbecebb72224f3186ac82057459fd72e08e"
PLAN_RAW_DIGEST = "sha256:a9bfe2e9ba4969877b115ba30f69b43f9144541741da09f6e331a815d294f21a"
PROGRESS_RAW_DIGEST = "sha256:a2806d69ce3b598d45cf439931b94e58b8d6d1827f565bf7cc7964966ef78952"
APPROVAL_ID = "f0b629ae-22c4-4e6f-bcf9-ac563761cd65"
APPROVED_AT = "2026-09-23T19:48:02Z"
APPROVAL_DIGEST = "sha256:a15a0e53e35a8aea7a6cf7bb6fe766ecba67777c7b702148c3dbc92dba63eb33"
APPROVAL_RAW_DIGEST = "sha256:c904810ac2187895ff5f4d3464bc5e8b906a3cb031daa05cf97ade9dddd36a53"
PRIOR_FAILURE_DIGEST = "sha256:3c41820fdcafa1adf2afe8653a1a3d1ba7561ab049cbc0ca84b370f78f9d4867"
PRIOR_STOPPED_PROGRESS_DIGEST = "sha256:a8344c793b45ea0d05024cd259ec11c58437f7db51c590d2cfccf5c8e8d11f2b"
PROJECT = "pwlhruwutoitnieactol"
DATA_PROJECT = "gnuqaefotwgkwurjpyik"
SECRET_REFERENCE = "AVUHZ_DEVELOPMENT_SUPABASE_AUTH_SESSION_CLEANUP_V2_EPHEMERAL"
OLD_SECRET_REFERENCE = "AVUHZ_DEVELOPMENT_SUPABASE_AUTH_SESSION_CLEANUP_V1_EPHEMERAL"
CREATED_AT = "2026-09-23T17:05:25Z"
WINDOW_START = "2026-09-24T15:00:00Z"
WINDOW_END = "2026-09-24T21:00:00Z"

# Public contract basis (documentation only; no project contact):
# https://supabase.com/docs/guides/api/api-keys
# Supabase secret API keys use the sb_secret_ prefix and are server-side
# credentials. This plan retains only the expected shape and a logical binding
# name; the value and any material-derived digest are prohibited everywhere.
CREATE_CONTRACT = {
    "project_reference": PROJECT,
    "responsibility": "AUTH",
    "resource": "dedicated-cleanup-v2-secret-api-key",
    "operation": "create-exactly-one",
    "creation_surface": "supabase.dashboard.project-api-keys",
    "credential_class": "SUPABASE_AUTH_ADMIN_EPHEMERAL",
    "execution_credential_class": "OWNER_INTERACTIVE_SESSION",
    "provider_key_kind": "secret",
    "provider_key_shape": "sb_secret_*",
    "dedicated_scope": "development-auth-synthetic-session-cleanup-v2-only",
    "maximum_keys_created": 1,
    "service_role_legacy_material_allowed": False,
    "retired_bootstrap_credential_reuse_allowed": False,
    "material_handling": {
        "agent_visible": False,
        "prompted": False,
        "logged": False,
        "persisted": False,
        "hashed": False,
        "provider_response_retained": False,
    },
    "success_classification": "DEDICATED_CLEANUP_CREDENTIAL_CREATED",
}
BIND_CONTRACT = {
    "repository": "AnonymousKoo/avuhz-infra",
    "environment": "development",
    "resource": "github-environment-secret-binding",
    "operation": "create-exactly-one-new-binding",
    "secret_reference": SECRET_REFERENCE,
    "source_credential_class": "SUPABASE_AUTH_ADMIN_EPHEMERAL",
    "transfer_surface": "OWNER_INTERACTIVE_DIRECT_TO_GITHUB_ENVIRONMENT_SECRET",
    "clipboard_allowed": False,
    "agent_visible": False,
    "prompts_allowed": False,
    "value_returned": False,
    "value_persisted_outside_secret_store": False,
    "other_secrets_changed": False,
    "success_classification": "CLEANUP_CREDENTIAL_BINDING_CREATED",
}
VERIFY_CONTRACT = {
    "repository": "AnonymousKoo/avuhz-infra",
    "environment": "development",
    "resource": "github-environment-secret-binding",
    "operation": "verify-presence-reference-only",
    "secret_reference": SECRET_REFERENCE,
    "value_read": False,
    "value_returned": False,
    "value_hashed": False,
    "other_secrets_changed": False,
    "success_classification": "CLEANUP_CREDENTIAL_BINDING_PRESENT",
}
RETIREMENT_CONTRACT = {
    "credential_reference": SECRET_REFERENCE,
    "dedicated_scope": "development-auth-synthetic-session-cleanup-v2-only",
    "operation": "seal-retirement-obligation-locally",
    "retirement_trigger": [
        "future-cleanup-continuation-completed",
        "future-cleanup-continuation-permanently-stopped",
    ],
    "retirement_requires_fresh_exact_authority": True,
    "ordered_retirement_resources": [
        "supabase-secret-api-key",
        "github-development-environment-secret-binding",
    ],
    "verification": ["provider-key-absent", "github-binding-absent"],
    "reuse_allowed": False,
    "success_classification": "CLEANUP_CREDENTIAL_RETIREMENT_REQUIRED",
}


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def raw_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    plan = load(PLAN_PATH)
    progress = load(PROGRESS_PATH)
    approval = load(APPROVAL_PATH)
    validate_plan(plan, SCHEMA_ROOT)
    validate_progress(plan, progress, SCHEMA_ROOT)
    validate_approval(plan, approval, SCHEMA_ROOT, WINDOW_START)

    assert plan["plan_id"] == PLAN_ID
    assert plan["plan_digest"] == PLAN_DIGEST == plan_digest(plan)
    assert raw_digest(PLAN_PATH) == PLAN_RAW_DIGEST
    assert raw_digest(PROGRESS_PATH) == PROGRESS_RAW_DIGEST
    assert approval["approval_id"] == APPROVAL_ID
    assert approval["plan_id"] == PLAN_ID
    assert approval["plan_version"] == plan["plan_version"]
    assert approval["plan_digest"] == PLAN_DIGEST
    assert approval["owner_identity"] == "github:AnonymousKoo"
    assert approval["decision"] == "APPROVE"
    assert approval["environment"] == "DEVELOPMENT"
    assert approval["effective_at"] == WINDOW_START
    assert approval["expires_at"] == WINDOW_END
    assert approval["approved_at"] == APPROVED_AT < WINDOW_START
    assert approval["status"] == "ACTIVE"
    assert approval["authority_scope"] == "EXACT_PLAN_ONLY"
    assert approval["approval_digest"] == APPROVAL_DIGEST == approval_digest(approval)
    if APPROVAL_RAW_DIGEST:
        assert raw_digest(APPROVAL_PATH) == APPROVAL_RAW_DIGEST
    assert plan["definition_status"] == "READY_FOR_APPROVAL"
    assert plan["environment"] == "DEVELOPMENT"
    assert plan["target"]["provider_reference"] == "supabase"
    assert plan["target"]["project_reference"] == PROJECT
    assert plan["target"]["responsibility"] == "AUTH"
    assert plan["authorization_window"] == {
        "binding_state": "BOUND",
        "starts_at": WINDOW_START,
        "expires_at": WINDOW_END,
    }
    assert CREATED_AT < WINDOW_START < WINDOW_END
    assert plan["authority_effect"] == "NONE_UNTIL_SEPARATELY_APPROVED"

    assert progress == initial_progress(
        plan, SCHEMA_ROOT, PROGRESS_ID, CREATED_AT
    )
    assert progress["progress_digest"] == PROGRESS_DIGEST
    assert progress["overall_state"] == "NOT_STARTED"
    assert all(
        (
            state["authorization_state"], state["execution_state"],
            state["verification_state"], state["authorization_consumed"],
            state["evidence"], state["binding_assertions"],
        ) == ("PENDING", "NOT_STARTED", "NOT_STARTED", False, [], [])
        for state in progress["step_states"]
    )

    assert len(plan["steps"]) == 4
    create, bind, verify, retire = plan["steps"]
    assert plan["ordered_step_ids"] == [step["step_id"] for step in plan["steps"]]
    assert [step["ordinal"] for step in plan["steps"]] == [1, 2, 3, 4]
    assert [step["execution_class"] for step in plan["steps"]] == [
        "PROVIDER_MUTATION", "PROVIDER_MUTATION", "PROVIDER_READ", "LOCAL_ONLY"
    ]
    assert [step["credential_policy"] for step in plan["steps"]] == [
        {"permitted": True, "allowed_classes": ["OWNER_INTERACTIVE_SESSION"],
         "values_stored": False},
        {"permitted": True, "allowed_classes": ["OWNER_INTERACTIVE_SESSION"],
         "values_stored": False},
        {"permitted": True, "allowed_classes": ["OWNER_INTERACTIVE_SESSION"],
         "values_stored": False},
        {"permitted": False, "allowed_classes": ["NONE"], "values_stored": False},
    ]

    assert create["resource"]["exact_digest"] == canonical_digest(CREATE_CONTRACT)
    assert bind["resource"]["exact_digest"] == canonical_digest(BIND_CONTRACT)
    assert verify["resource"]["exact_digest"] == canonical_digest(VERIFY_CONTRACT)
    assert retire["resource"]["exact_digest"] == canonical_digest(RETIREMENT_CONTRACT)
    assert create["required_evidence"] == [{
        "evidence_type": "auth.synthetic-session.global-revocation.accepted",
        "source_step_id": None,
        "binding_state": "BOUND",
        "exact_digest": PRIOR_FAILURE_DIGEST,
    }]
    prior = load(
        BASE / "development-auth-v32-synthetic-session-cleanup-v1.execution-progress.json"
    )
    assert prior["overall_state"] == "STOPPED"
    assert prior["progress_digest"] == PRIOR_STOPPED_PROGRESS_DIGEST
    assert (
        prior["step_states"][1]["authorization_state"],
        prior["step_states"][1]["execution_state"],
        prior["step_states"][1]["verification_state"],
    ) == ("CONSUMED", "FAILED", "FAIL")
    assert prior["step_states"][2]["authorization_state"] == "BLOCKED"

    assert create["operation"] == (
        "provider.auth-admin-credential.create-dedicated-secret-key"
    )
    assert bind["operation"] == (
        "provider.auth-secret-binding.create-github-environment-reference"
    )
    assert verify["operation"] == (
        "provider.auth-secret-binding.verify-github-environment-reference"
    )
    assert retire["operation"] == (
        "local.auth-credential-retirement-requirement.seal"
    )
    assert bind["dependency_step_ids"] == [create["step_id"]]
    assert verify["dependency_step_ids"] == [bind["step_id"]]
    assert retire["dependency_step_ids"] == [verify["step_id"]]

    serialized = json.dumps({"plan": plan, "progress": progress}, sort_keys=True)
    assert SECRET_REFERENCE in serialized
    assert OLD_SECRET_REFERENCE not in serialized
    assert DATA_PROJECT not in serialized
    assert "cleanup-v2.prepare" in plan["prohibited_actions"]
    assert "cleanup-v1.retry" in plan["prohibited_actions"]
    assert "service-role.use" in plan["prohibited_actions"]
    for prohibited in (
        "identity.create", "identity.delete", "identity.modify", "hook.modify",
        "session.issue", "logout.execute", "sql.execute", "data.operation",
        "render.operation", "n8n.operation", "staging.target", "production.target",
    ):
        assert prohibited in plan["prohibited_actions"]
    assert RETIREMENT_CONTRACT["retirement_requires_fresh_exact_authority"] is True
    assert RETIREMENT_CONTRACT["reuse_allowed"] is False
    assert "provider.contact" in retire["prohibited_actions"]
    assert "provider.mutation" in retire["prohibited_actions"]

    assert not (BASE / f"{BOUNDARY}.execution-progress.json").exists()
    assert not list(BASE.glob(f"{BOUNDARY}*.evidence.json"))
    assert not list(BASE.glob("*synthetic-session-cleanup-v2*.plan.json"))

    text = PLAN_PATH.read_text(encoding="utf-8") + PROGRESS_PATH.read_text(encoding="utf-8")
    assert re.search(r"sb_secret_[A-Za-z0-9._-]{8,}", text) is None
    for sensitive_field in (
        '"credential_value"', '"secret_value"', '"service_role_key"',
        '"access_token"', '"refresh_token"', '"authorization"',
    ):
        assert sensitive_field not in text.lower()

    print(
        "DEVELOPMENT AUTH cleanup credential-repair v1: PASS "
        "(exact approval; pristine/unexecuted; four separately authorized ordered steps; "
        "new v2 binding reference only; retirement obligation sealed last)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
