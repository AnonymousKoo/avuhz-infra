#!/usr/bin/env python3
"""Validate forward-only DEVELOPMENT AUTH v21 passwordless synthetic identity plan."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.authorization_plan import initial_progress, plan_digest, validate_plan, validate_progress

SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
PLAN_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v21.plan.json"
PROGRESS_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v21.progress.json"
V20_PLAN_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v20.plan.json"
V20_PROGRESS_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v20.progress.json"
V19_PLAN_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v19.plan.json"
V19_PROGRESS_PATH = ROOT / "contracts/plans/v1/development-auth-integration-v19.progress.json"
V16_EVIDENCE_PATH = ROOT / "contracts/plans/v1/development-auth-step1-v16-success.evidence.json"

PLAN_ID = "e818f636-5470-4f39-a040-12f7e723b6c3"
PROGRESS_ID = "01813bf8-cf24-48c2-aad2-af87c8aab6e6"
PLAN_DIGEST = "sha256:e7410c35e9de2e8c4e60d538e9f1e7fd79bc49e58f51788b2a1e5d931467ab0c"
PROGRESS_DIGEST = "sha256:4fe494c84a052e5c5d6e6e6cb54eb4a5ffb7c6b24d71fb03ba1472e3518e5982"
V20_PLAN_DIGEST = "sha256:3870b6e83f4a7983e2a1fa668066790f4fd5ef77a70e4e801c081ae2459f509b"
V20_PROGRESS_DIGEST = "sha256:60c1818e6951a6493c08111a485ffdf3820b3ec9cc7c923b95a4ea5d3d79ec97"
V19_PLAN_DIGEST = "sha256:4e6bb3a76b4d15b7993b2567c6743497b285bbecd03100f7ce73bbbc7a0cc72e"
V19_PROGRESS_DIGEST = "sha256:ef3d232916d7be0d4a65e94d0bbfaa635258c937ae58bfa038fd43a4bf185fa8"
V16_EVIDENCE_DIGEST = "sha256:0cfa1a3515e6496e9bc215de4579d5e4ff5b46f0299227b60708dc72ff2fb194"
STEP_ID = "development.auth.v21.step.01.create-synthetic-identity-admin"
CREATED_AT = "2026-09-14T12:44:21Z"
STARTS_AT = "2026-09-14T14:00:00Z"
EXPIRES_AT = "2026-09-14T17:00:00Z"
CREDENTIAL_CLASS = "SUPABASE_AUTH_ADMIN_EPHEMERAL"
CAPABILITY_EVIDENCE = "auth.admin-executor-capability.observed"
SYNTHETIC_EMAIL = "avuhz-development-synthetic@example.invalid"
HANDLING = {
    "material_source": "APPROVED_ENVIRONMENT_SECRET_BOUNDARY",
    "material_residency": "SERVER_EXECUTOR_MEMORY_ONLY",
    "control_plane_visibility": "CLASS_LABEL_ONLY",
    "material_digest": "PROHIBITED",
    "persistence": "PROHIBITED",
    "logging": "PROHIBITED",
    "return_policy": "PROHIBITED",
    "proof_policy": "NON_SECRET_EXECUTOR_CAPABILITY_ATTESTATION",
}
REQUIRED_CREDENTIAL_PROHIBITIONS = {
    "credential.persist", "credential.expose", "credential.log", "credential.return",
    "credential.digest", "credential.copy", "credential.create", "credential.rotate",
    "credential.export",
}


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
    v20_plan = load(V20_PLAN_PATH)
    v20_progress = load(V20_PROGRESS_PATH)
    v19_plan = load(V19_PLAN_PATH)
    v19_progress = load(V19_PROGRESS_PATH)
    v16_evidence = load(V16_EVIDENCE_PATH)

    validate_plan(plan, SCHEMA_ROOT)
    validate_progress(plan, progress, SCHEMA_ROOT)
    validate_plan(v20_plan, SCHEMA_ROOT)
    validate_progress(v20_plan, v20_progress, SCHEMA_ROOT)

    assert plan["plan_id"] == PLAN_ID
    assert plan["plan_version"] == 21
    assert plan["plan_digest"] == PLAN_DIGEST == plan_digest(plan)
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
    assert plan["authorization_window"] == {
        "binding_state": "BOUND",
        "starts_at": STARTS_AT,
        "expires_at": EXPIRES_AT,
    }
    assert plan["authority_effect"] == "NONE_UNTIL_SEPARATELY_APPROVED"
    assert plan["ordered_step_ids"] == [STEP_ID]

    step = plan["steps"][0]
    assert step["step_id"] == STEP_ID
    assert step["operation"] == "provider.auth-identity.create-one"
    assert step["execution_class"] == "PROVIDER_MUTATION"
    assert step["resource"] == v20_plan["steps"][0]["resource"]
    assert step["required_evidence"] == [{
        "evidence_type": "hook.v2.disabled-acl.verified",
        "source_step_id": None,
        "binding_state": "BOUND",
        "exact_digest": V16_EVIDENCE_DIGEST,
    }]
    assert SYNTHETIC_EMAIL in step["expected_postcondition"]
    assert "Supabase Admin createUser email-only confirmed path" in step["expected_postcondition"]
    assert "no password" in step["expected_postcondition"]
    assert "no password" not in step["prohibited_actions"]

    assert step["credential_policy"] == {
        "permitted": True,
        "allowed_classes": [CREDENTIAL_CLASS],
        "values_stored": False,
        "ephemeral_handling": HANDLING,
    }
    assert step["unresolved_bindings"] == []
    assert REQUIRED_CREDENTIAL_PROHIBITIONS <= set(step["prohibited_actions"])
    assert REQUIRED_CREDENTIAL_PROHIBITIONS <= set(plan["prohibited_actions"])
    for prohibited in (
        "password.set", "password-hash.set", "invitation.send", "user-metadata.bind",
        "tenant-metadata.bind", "app-metadata.bind", "server-allowlist.bind", "hook.enable",
        "token.issue", "session.issue", "data.operation", "render.operation",
        "staging.target", "production.target",
    ):
        assert prohibited in step["prohibited_actions"]
        assert prohibited in plan["prohibited_actions"]
    for prohibited in ("v19.plan.execute", "v19.approval.reuse", "v20.approval.create", "v20.plan.execute", "v20.plan.rewrite"):
        assert prohibited in plan["prohibited_actions"]

    declarations = step["binding_declarations"]
    assert all(item["value_class"] != "EPHEMERAL_SENSITIVE" for item in declarations)
    by_id = {item["binding_id"]: item for item in declarations}
    assert set(by_id) == {
        "binding.development.auth.v21.v16-disabled-hook-state",
        "binding.development.auth.v21.admin-executor-capability",
        "binding.development.auth.v21.identity-create-preflight",
        "binding.development.auth.v21.synthetic-identity",
    }
    disabled = by_id["binding.development.auth.v21.v16-disabled-hook-state"]
    assert disabled["phase"] == "PREAPPROVAL_BOUND"
    assert disabled["preapproval_value"] == {
        "value": "sha256:97f18e0a729762f9e9c7d72507a489aa828bbe03a138b25acfadcd72dd43a735",
        "exact_digest": "sha256:2fc081713e1dd9288b6633eb484a80e157444241992588251f7f858fa06a0d9d",
    }
    capability = by_id["binding.development.auth.v21.admin-executor-capability"]
    assert capability == {
        "binding_id": "binding.development.auth.v21.admin-executor-capability",
        "phase": "RESOLVED_BY_STEP_PREFLIGHT",
        "value_class": "CONFIGURATION_REFERENCE",
        "source_step_id": None,
        "evidence_type": CAPABILITY_EVIDENCE,
        "digest_policy": "REQUIRED",
        "persistence_policy": "DIGEST_ONLY",
    }
    identity_preflight = by_id["binding.development.auth.v21.identity-create-preflight"]
    assert identity_preflight["phase"] == "RESOLVED_BY_STEP_PREFLIGHT"
    assert identity_preflight["evidence_type"] == "auth.synthetic-identity.create-preflight.observed"
    produced = by_id["binding.development.auth.v21.synthetic-identity"]
    assert produced["phase"] == "PRODUCED_BY_CURRENT_STEP"
    assert produced["persistence_policy"] == "DIGEST_ONLY"
    assert step["produced_evidence"] == [{
        "evidence_type": "auth.synthetic-identity.created",
        "established_binding_ids": ["binding.development.auth.v21.synthetic-identity"],
        "digest_policy": "REQUIRED",
    }]

    assert raw_digest(V16_EVIDENCE_PATH) == V16_EVIDENCE_DIGEST
    assert v16_evidence["outcome"] == "SUCCEEDED_VERIFIED"
    assert v16_evidence["project_reference"] == "pwlhruwutoitnieactol"
    assert v16_evidence["hosted_auth_observation"]["custom_access_token_hook_enabled"] is False
    assert v16_evidence["security_state"]["credential_retained"] is False
    assert v16_evidence["security_state"]["pii_retained"] is False

    assert v19_plan["plan_digest"] == V19_PLAN_DIGEST
    assert v19_progress["progress_digest"] == V19_PROGRESS_DIGEST
    assert v19_progress["overall_state"] == "NOT_STARTED"
    assert v19_progress["step_states"][0]["authorization_consumed"] is False

    assert v20_plan["plan_digest"] == V20_PLAN_DIGEST
    assert v20_progress["progress_digest"] == V20_PROGRESS_DIGEST
    assert v20_plan["definition_status"] == "DRAFT_BLOCKED"
    assert v20_plan["steps"][0]["credential_policy"] == {
        "permitted": False,
        "allowed_classes": ["NONE"],
        "values_stored": False,
    }
    assert v20_progress["overall_state"] == "NOT_STARTED"

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
        ROOT / "contracts/plans/v1/development-auth-integration-v21.approval.json",
        ROOT / "contracts/plans/v1/development-auth-integration-v21.execution-progress.json",
        ROOT / "contracts/plans/v1/development-auth-step1-v21-preflight.evidence.json",
        ROOT / "contracts/plans/v1/development-auth-step1-v21-success.evidence.json",
        ROOT / "contracts/plans/v1/development-auth-integration-v20.approval.json",
        ROOT / "contracts/plans/v1/development-auth-integration-v20.execution-progress.json",
        ROOT / "contracts/plans/v1/development-auth-step1-v20-success.evidence.json",
    ):
        assert not path.exists(), path

    print(
        "DEVELOPMENT_AUTH_V21_PLAN=PASS "
        "(READY_FOR_APPROVAL only; DEVELOPMENT AUTH exact target; passwordless Admin createUser; "
        "Supabase Auth-admin ephemeral class only; non-secret executor capability preflight required; "
        "v20 immutable; no approval/provider authority)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
