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
from avuhz_runtime.implementation_handoff import canonical_digest

SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
PLAN_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v20.plan.json"
PROGRESS_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v20.progress.json"
V19_PLAN_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v19.plan.json"
V19_PROGRESS_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v19.progress.json"
V19_APPROVAL_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v19.approval.json"
V16_EVIDENCE_PATH = ROOT / "contracts/plans/v1/development-auth-step1-v16-success.evidence.json"
AUTH_PLAN_SCHEMA_PATH = ROOT / "contracts/schemas/v1/orchestration/bounded-authorization-plan.schema.json"

PLAN_ID = "f616853e-5395-4210-8f94-c9b56a4235a5"
PROGRESS_ID = "2de97dca-8e7c-424b-8272-990e3f81ebac"
PLAN_DIGEST = "sha256:30953b8fdb7b47369441787e254869c62b66eeee9621029a2f855525e64a1581"
PROGRESS_DIGEST = "sha256:d29b22a6c0f2a14f5aaaf838bdb146671ac4b04c5bb3f16c83ee91c66cae2edb"
V19_PLAN_DIGEST = "sha256:4e6bb3a76b4d15b7993b2567c6743497b285bbecd03100f7ce73bbbc7a0cc72e"
V19_PROGRESS_DIGEST = "sha256:ef3d232916d7be0d4a65e94d0bbfaa635258c937ae58bfa038fd43a4bf185fa8"
V19_APPROVAL_DIGEST = "sha256:3e31e523d03220c8301a76430dbd3d1c7a72538b711661b187ea063c3306e6d9"
V16_EVIDENCE_DIGEST = "sha256:0cfa1a3515e6496e9bc215de4579d5e4ff5b46f0299227b60708dc72ff2fb194"
V16_DEPLOYED_STATE_DIGEST = "sha256:97f18e0a729762f9e9c7d72507a489aa828bbe03a138b25acfadcd72dd43a735"
V16_DEPLOYED_STATE_VALUE_DIGEST = "sha256:2fc081713e1dd9288b6633eb484a80e157444241992588251f7f858fa06a0d9d"
STEP_ID = "development.auth.v20.step.01.create-synthetic-identity-admin"
CREATED_AT = "2026-09-14T10:49:44Z"
SYNTHETIC_EMAIL = "avuhz-development-synthetic@example.invalid"
SYNTHETIC_EMAIL_DIGEST = "sha256:deaa8eccae27d7cd9c51cebd4ba3bfc3a8d2de415a10c64af4f7c35097cd75ea"
SYNTHETIC_EMAIL_VALUE_DIGEST = "sha256:64d37516d6c00b2d292707f6dac3feb06df3bd23679237628e741bc860ed872d"
ADMIN_PROCEDURE = "procedure.supabase.auth.admin.create-user.email-only-confirmed"
ADMIN_PROCEDURE_DIGEST = "sha256:a031db2804de8d98ff27261eb2bd4f730aa4f2b2587d90dd843f3c709a6e7219"
CREDENTIAL_BINDING = "binding.development.auth.v20.server-admin-credential-class"


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
    v19_plan = load(V19_PLAN_PATH)
    v19_progress = load(V19_PROGRESS_PATH)
    v19_approval = load(V19_APPROVAL_PATH)
    v16_evidence = load(V16_EVIDENCE_PATH)
    auth_plan_schema = load(AUTH_PLAN_SCHEMA_PATH)

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

    recognized_credentials = (
        auth_plan_schema["$defs"]["credentialPolicy"]["properties"]
        ["allowed_classes"]["items"]["enum"]
    )
    assert recognized_credentials == [
        "NONE",
        "OWNER_INTERACTIVE_SESSION",
        "MIGRATION_IDENTITY",
        "SYNTHETIC_IDENTITY",
        "EPHEMERAL_SYNTHETIC_ACCESS_TOKEN",
    ]
    assert "SERVER_ADMIN_CREDENTIAL" not in recognized_credentials
    assert "SERVICE_ROLE" not in recognized_credentials

    step = plan["steps"][0]
    assert step["resource"] == v19_plan["steps"][0]["resource"]
    assert step["operation"] == v19_plan["steps"][0]["operation"] == "provider.auth-identity.create-one"
    assert step["execution_class"] == "PROVIDER_MUTATION"
    assert step["required_evidence"] == v19_plan["steps"][0]["required_evidence"]
    assert step["credential_policy"] == {
        "permitted": False,
        "allowed_classes": ["NONE"],
        "values_stored": False,
    }
    assert step["unresolved_bindings"] == [CREDENTIAL_BINDING]
    assert SYNTHETIC_EMAIL in step["expected_postcondition"]
    assert "Supabase Admin createUser email-only confirmed path" in step["expected_postcondition"]

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

    by_id = {item["binding_id"]: item for item in step["binding_declarations"]}
    assert by_id["binding.development.auth.v20.v16-disabled-hook-state"]["preapproval_value"] == {
        "value": V16_DEPLOYED_STATE_DIGEST,
        "exact_digest": V16_DEPLOYED_STATE_VALUE_DIGEST,
    }
    procedure = by_id["binding.development.auth.v20.admin-create-procedure"]
    assert procedure["phase"] == "PREAPPROVAL_BOUND"
    assert procedure["value_class"] == "PROCEDURE_REFERENCE"
    assert procedure["preapproval_value"] == {
        "value": ADMIN_PROCEDURE,
        "exact_digest": ADMIN_PROCEDURE_DIGEST,
    }
    assert canonical_digest(ADMIN_PROCEDURE) == ADMIN_PROCEDURE_DIGEST

    email_binding = by_id["binding.development.auth.v20.synthetic-email"]
    assert email_binding["preapproval_value"] == {
        "value": SYNTHETIC_EMAIL_DIGEST,
        "exact_digest": SYNTHETIC_EMAIL_VALUE_DIGEST,
    }
    assert "sha256:" + hashlib.sha256(SYNTHETIC_EMAIL.encode()).hexdigest() == SYNTHETIC_EMAIL_DIGEST
    assert canonical_digest(SYNTHETIC_EMAIL_DIGEST) == SYNTHETIC_EMAIL_VALUE_DIGEST

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
        "(forward-only Admin createUser route is exact; no password/metadata/token path; "
        "server-admin credential class is intentionally unresolved; no approval or provider authority)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
