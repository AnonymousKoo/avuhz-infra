#!/usr/bin/env python3
"""Validate forward-only DEVELOPMENT AUTH v20 blocked admin-create plan."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.authorization_plan import (
    initial_progress,
    validate_plan,
    validate_progress,
)

SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
PLAN_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v20.plan.json"
PROGRESS_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v20.progress.json"
V19_PLAN_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v19.plan.json"
V19_PROGRESS_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v19.progress.json"
V19_APPROVAL_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v19.approval.json"
V16_EVIDENCE_PATH = ROOT / "contracts/plans/v1/development-auth-step1-v16-success.evidence.json"
AUTH_PLAN_SCHEMA_V1_PATH = ROOT / "contracts/schemas/v1/orchestration/bounded-authorization-plan.schema.json"
AUTH_PLAN_SCHEMA_V2_PATH = ROOT / "contracts/schemas/v1/orchestration/bounded-authorization-plan-v2.schema.json"

PLAN_ID = "f616853e-5395-4210-8f94-c9b56a4235a5"
PROGRESS_ID = "2de97dca-8e7c-424b-8272-990e3f81ebac"
PLAN_DIGEST = "sha256:3870b6e83f4a7983e2a1fa668066790f4fd5ef77a70e4e801c081ae2459f509b"
PROGRESS_DIGEST = "sha256:60c1818e6951a6493c08111a485ffdf3820b3ec9cc7c923b95a4ea5d3d79ec97"
V19_PLAN_DIGEST = "sha256:4e6bb3a76b4d15b7993b2567c6743497b285bbecd03100f7ce73bbbc7a0cc72e"
V19_PROGRESS_DIGEST = "sha256:ef3d232916d7be0d4a65e94d0bbfaa635258c937ae58bfa038fd43a4bf185fa8"
V19_APPROVAL_DIGEST = "sha256:3e31e523d03220c8301a76430dbd3d1c7a72538b711661b187ea063c3306e6d9"
V16_EVIDENCE_DIGEST = "sha256:0cfa1a3515e6496e9bc215de4579d5e4ff5b46f0299227b60708dc72ff2fb194"
STEP_ID = "development.auth.v20.step.01.create-synthetic-identity-admin"
CREATED_AT = "2026-09-14T10:49:44Z"
SYNTHETIC_EMAIL = "avuhz-development-synthetic@example.invalid"
ADMIN_PROCEDURE_TEXT = "Supabase Admin createUser email-only confirmed path"
CREDENTIAL_BINDING = "binding.development.auth.v20.server-admin-credential-class"
NEW_CREDENTIAL_CLASS = "SUPABASE_AUTH_ADMIN_EPHEMERAL"


def load(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    assert isinstance(value, dict), path
    return value


def raw_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def credential_classes(schema: dict) -> list[str]:
    return (
        schema["$defs"]["credentialPolicy"]["properties"]
        ["allowed_classes"]["items"]["enum"]
    )


def main() -> int:
    plan = load(PLAN_PATH)
    progress = load(PROGRESS_PATH)
    v19_plan = load(V19_PLAN_PATH)
    v19_progress = load(V19_PROGRESS_PATH)
    v19_approval = load(V19_APPROVAL_PATH)
    v16_evidence = load(V16_EVIDENCE_PATH)
    auth_plan_schema_v1 = load(AUTH_PLAN_SCHEMA_V1_PATH)
    auth_plan_schema_v2 = load(AUTH_PLAN_SCHEMA_V2_PATH)

    validate_plan(plan, SCHEMA_ROOT)
    validate_progress(plan, progress, SCHEMA_ROOT)
    validate_plan(v19_plan, SCHEMA_ROOT)
    validate_progress(v19_plan, v19_progress, SCHEMA_ROOT)

    assert plan["plan_id"] == PLAN_ID
    assert plan["plan_version"] == 20
    assert plan["plan_digest"] == PLAN_DIGEST
    assert plan["definition_status"] == "DRAFT_BLOCKED"
    assert plan["environment"] == "DEVELOPMENT"
    assert plan["target"] == {
        "provider_class": "identity.provider",
        "provider_reference": "supabase",
        "project_reference": "pwlhruwutoitnieactol",
        "responsibility": "AUTH",
        "issuer_reference": "https://pwlhruwutoitnieactol.supabase.co/auth/v1",
        "audience_reference": "audience.avuhz.command-service.development",
    }
    assert plan["authorization_window"] == {
        "binding_state": "UNRESOLVED_BLOCKER",
        "starts_at": None,
        "expires_at": None,
    }
    assert plan["authority_effect"] == "NONE_UNTIL_SEPARATELY_APPROVED"
    assert plan["ordered_step_ids"] == [STEP_ID]

    legacy_classes = credential_classes(auth_plan_schema_v1)
    assert legacy_classes == [
        "NONE",
        "OWNER_INTERACTIVE_SESSION",
        "MIGRATION_IDENTITY",
        "SYNTHETIC_IDENTITY",
        "EPHEMERAL_SYNTHETIC_ACCESS_TOKEN",
    ]
    current_classes = credential_classes(auth_plan_schema_v2)
    assert current_classes == legacy_classes + [
        NEW_CREDENTIAL_CLASS,
        "SUPABASE_PROVIDER_READ",
    ]
    for classes in (legacy_classes, current_classes):
        assert "SERVER_ADMIN_CREDENTIAL" not in classes
        assert "SERVICE_ROLE" not in classes

    step = plan["steps"][0]
    assert step["resource"] == v19_plan["steps"][0]["resource"]
    assert step["operation"] == v19_plan["steps"][0]["operation"] == "provider.auth-identity.create-one"
    assert step["execution_class"] == "PROVIDER_MUTATION"
    assert step["required_evidence"] == v19_plan["steps"][0]["required_evidence"] == [{
        "evidence_type": "hook.v2.disabled-acl.verified",
        "source_step_id": None,
        "binding_state": "BOUND",
        "exact_digest": V16_EVIDENCE_DIGEST,
    }]
    assert step["credential_policy"] == {
        "permitted": False,
        "allowed_classes": ["NONE"],
        "values_stored": False,
    }
    assert "ephemeral_handling" not in step["credential_policy"]
    assert step["unresolved_bindings"] == [CREDENTIAL_BINDING]
    assert SYNTHETIC_EMAIL in step["expected_postcondition"]
    assert ADMIN_PROCEDURE_TEXT in step["expected_postcondition"]

    for prohibited in (
        "credential.persist", "credential.expose", "credential.log",
        "password.set", "password-hash.set", "invitation.send",
        "user-metadata.bind", "tenant-metadata.bind", "app-metadata.bind",
        "server-allowlist.bind", "hook.enable", "token.issue", "session.issue",
        "data.operation", "render.operation", "staging.target", "production.target",
    ):
        assert prohibited in step["prohibited_actions"]
        assert prohibited in plan["prohibited_actions"]
    assert "v19.plan.execute" in plan["prohibited_actions"]
    assert "v19.approval.reuse" in plan["prohibited_actions"]
    assert "provider.mutation" not in plan["prohibited_actions"]

    declarations = step["binding_declarations"]
    assert all(item["phase"] != "PREAPPROVAL_BOUND" for item in declarations)
    by_id = {item["binding_id"]: item for item in declarations}
    assert set(by_id) == {
        CREDENTIAL_BINDING,
        "binding.development.auth.v20.identity-create-preflight",
        "binding.development.auth.v20.synthetic-identity",
    }
    credential = by_id[CREDENTIAL_BINDING]
    assert credential == {
        "binding_id": CREDENTIAL_BINDING,
        "phase": "UNRESOLVED_BLOCKER",
        "value_class": "EPHEMERAL_SENSITIVE",
        "source_step_id": None,
        "evidence_type": None,
        "digest_policy": "PROHIBITED",
        "persistence_policy": "PROHIBITED",
    }
    preflight = by_id["binding.development.auth.v20.identity-create-preflight"]
    assert preflight["phase"] == "RESOLVED_BY_STEP_PREFLIGHT"
    assert preflight["persistence_policy"] == "DIGEST_ONLY"
    produced = by_id["binding.development.auth.v20.synthetic-identity"]
    assert produced["phase"] == "PRODUCED_BY_CURRENT_STEP"
    assert produced["persistence_policy"] == "DIGEST_ONLY"

    assert raw_digest(V16_EVIDENCE_PATH) == V16_EVIDENCE_DIGEST
    assert v16_evidence["outcome"] == "SUCCEEDED_VERIFIED"
    assert v16_evidence["project_reference"] == "pwlhruwutoitnieactol"
    assert v16_evidence["hosted_auth_observation"]["custom_access_token_hook_enabled"] is False
    assert v16_evidence["security_state"]["credential_retained"] is False
    assert v16_evidence["security_state"]["pii_retained"] is False

    assert v19_plan["plan_digest"] == V19_PLAN_DIGEST
    assert v19_progress["progress_digest"] == V19_PROGRESS_DIGEST
    assert v19_approval["approval_digest"] == V19_APPROVAL_DIGEST
    assert v19_progress["overall_state"] == "NOT_STARTED"
    v19_state = v19_progress["step_states"][0]
    assert v19_state["authorization_state"] == "PENDING"
    assert v19_state["execution_state"] == "NOT_STARTED"
    assert v19_state["verification_state"] == "NOT_STARTED"
    assert v19_state["authorization_consumed"] is False
    assert v19_state["evidence"] == []

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
        ROOT / "contracts/plans/v1/development-auth-integration-v20.approval.json",
        ROOT / "contracts/plans/v1/development-auth-integration-v20.execution-progress.json",
        ROOT / "contracts/plans/v1/development-auth-step1-v20-preflight.evidence.json",
        ROOT / "contracts/plans/v1/development-auth-step1-v20-success.evidence.json",
        ROOT / "contracts/plans/v1/development-auth-integration-v19.execution-progress.json",
        ROOT / "contracts/plans/v1/development-auth-step1-v19-success.evidence.json",
    ):
        assert not path.exists(), path

    print(
        "DEVELOPMENT_AUTH_V20_BLOCKED=PASS "
        "(historical v20 blocker remains immutable under authorization-plan v2; "
        "new Auth-admin class is available only to a fresh forward-only plan; "
        "v20 has no approval/provider authority)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
