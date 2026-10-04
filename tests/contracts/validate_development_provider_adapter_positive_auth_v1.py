#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.authorization_plan import (
    initial_progress,
    plan_digest,
    validate_plan,
    validate_progress,
)
from avuhz_runtime.implementation_handoff import canonical_digest

B = ROOT / "contracts/plans/v1"
S = ROOT / "contracts/schemas/v1"
N = "development-implementation-handoff-provider-adapter-positive-auth-v1"

PLAN_ID = "d83a0d62-93c5-4a85-b8c3-220fca4c87e7"
PLAN_DIGEST = "sha256:8f5f28b6b811fb8296c1a980157aa300b2c869394fcee4f424bf4e6785620148"
PROGRESS_ID = "00f84934-8040-4d63-a95d-0bd218e6e8c1"
PROGRESS_DIGEST = "sha256:49959ccc2d45d605de770c5c211785a65cfb191506b920c6ff97e1e5d390ee3d"
RESOURCE_DIGEST = "sha256:5848060a86586ee8bc71caa55413307b5976b1ed35eba4501e717c8151f0da5a"
PREP_DIGEST = "sha256:796b8d6c73c37c4b9d66c659e6233a6ffd900631a6151a2e7bca4d59478920d0"

EXECUTOR = "sha256:7a4623bfd42a7cbbae24f307c6d888e3aed9fa35bc486fb9f69d29c221efbf48"
WORKFLOW = "sha256:48cdd1e138a43f1663c38acdbfa07aeea7af39251d2b1259caa7dbd517ad9029"
LIFECYCLE = "sha256:d8b68df0ed06fec06cbf538e9511b432678d3baa73ee656c3495eb724bde0797"
IDENTITY = "sha256:bbdf9c44c683118adedd42645bfb6b3c40617bbe8e402ce4bb65b20a7b1f6189"
JWT = "sha256:52de43a29eddd4d17e428fa3989ac7bb20397b3c131b0eaa6eef5b37de37713c"

PASSWORDLESS = "sha256:26a90c35357ac14b23d1b7f17e18762e958248462d53aed168985dba249cbb10"
TENANT = "sha256:42a33b97e8ab5c8fd9c7972d5d4a9cad57d06135ea9a05952ed6f669026c3936"
ALLOWLIST = "sha256:07b1103c5a90a04849e4cc6c4d9c303adcf09b7a639086ae88a90979ad301325"
V11_RUNTIME = "sha256:f49f6882f2e6ec0274935137a52c7b7c942bfbe0bc72baebca143a90aedc5345"
V11_PROGRESS = "sha256:762fc38748aeb4483a5b26179a703e687bab13e7f5c73160b29a3a77d4480e5c"
OLD_KEY_ABSENCE = "sha256:3857f828649e58538e99088ad486f4b4f64d3909759553428d72d79b6543ca80"
OLD_GH_ABSENCE = "sha256:7e6ab69ae4f2cb65e1c1031c1c6f1cb792cf934c02583d59c6dc31ee86ca1c65"
OLD_RETIRE_PROGRESS = "sha256:bd660fa458b2b83918c8f90a68bbb8a79c5be83768be819c2b4c7e1f7aa4007a"


def load(name: str):
    return json.loads((B / name).read_text())


def raw(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    r = load(N + ".resource.json")
    prep = load(N + "-preparation.evidence.json")
    p = load(N + ".plan.json")
    g = load(N + ".progress.json")

    validate_plan(p, S)
    validate_progress(p, g, S)
    assert not (B / (N + ".approval.json")).exists()
    assert not (B / (N + ".execution-progress.json")).exists()

    assert p["plan_id"] == PLAN_ID
    assert p["plan_version"] == 1
    assert p["plan_digest"] == PLAN_DIGEST == plan_digest(p)
    assert p["definition_status"] == "READY_FOR_APPROVAL"
    assert p["authority_effect"] == "NONE_UNTIL_SEPARATELY_APPROVED"
    assert p["environment"] == "DEVELOPMENT"
    assert p["target"] == {
        "provider_class": "identity.provider",
        "provider_reference": "supabase",
        "project_reference": "pwlhruwutoitnieactol",
        "responsibility": "AUTH",
        "issuer_reference": "https://pwlhruwutoitnieactol.supabase.co/auth/v1",
        "audience_reference": "audience.avuhz.command-service.development",
    }
    assert p["authorization_window"] == {
        "binding_state": "BOUND",
        "starts_at": "2026-10-04T04:30:00Z",
        "expires_at": "2026-10-04T07:30:00Z",
    }

    assert r["contract_digest"] == RESOURCE_DIGEST == canonical_digest(
        {k: v for k, v in r.items() if k != "contract_digest"}
    )
    assert prep["evidence_digest"] == PREP_DIGEST == canonical_digest(
        {k: v for k, v in prep.items() if k != "evidence_digest"}
    )
    assert prep["observation_only"] is True
    assert all(value is False for value in prep["security_state"].values())

    assert raw(ROOT / "scripts/development_provider_adapter_positive_auth_v1.py") == EXECUTOR
    assert raw(ROOT / ".github/workflows/development-provider-adapter-positive-auth-v1-step5.yml") == WORKFLOW
    assert raw(ROOT / "src/avuhz_engineering/development_auth_token_lifecycle.py") == LIFECYCLE
    assert raw(ROOT / "src/avuhz_service/development_supabase_identity.py") == IDENTITY
    assert raw(ROOT / "src/avuhz_service/development_supabase_jwt.py") == JWT
    assert r["step5_executor_digest"] == EXECUTOR
    assert r["step5_workflow_digest"] == WORKFLOW
    assert r["token_lifecycle_source_digest"] == LIFECYCLE
    assert r["identity_policy_source_digest"] == IDENTITY
    assert r["jwt_verifier_source_digest"] == JWT

    assert load("development-implementation-handoff-provider-adapter-auth-v2-password-hash-correction-v2-step02-success.evidence.json")["evidence_digest"] == PASSWORDLESS
    assert load("development-implementation-handoff-provider-adapter-tenant-binding-v1-step02-success.evidence.json")["evidence_digest"] == TENANT
    assert load("development-implementation-handoff-provider-adapter-allowlist-binding-v1-step01-success.evidence.json")["evidence_digest"] == ALLOWLIST
    assert raw(B / "development-render-deployment-v11-step02-success.evidence.json") == V11_RUNTIME
    assert load("development-render-deployment-v11.execution-progress.json")["progress_digest"] == V11_PROGRESS
    assert load("development-implementation-handoff-provider-adapter-auth-v2-credential-retirement-v1-step03-success.evidence.json")["evidence_digest"] == OLD_KEY_ABSENCE
    assert load("development-implementation-handoff-provider-adapter-auth-v2-credential-retirement-v1-step04-success.evidence.json")["evidence_digest"] == OLD_GH_ABSENCE
    retired = load("development-implementation-handoff-provider-adapter-auth-v2-credential-retirement-v1.progress.json")
    assert retired["progress_digest"] == OLD_RETIRE_PROGRESS and retired["overall_state"] == "COMPLETED"

    assert r["target_subject_digest"] == "sha256:21ae3658908a20bb95e6440850180d699bba96da97ee1556e0574d1b12293e7a"
    assert r["tenant_id"] == "1ad3998c-92ab-4a36-9d1c-ed97f2fa98f0"
    assert r["caller_type"] == "PROVIDER_ADAPTER"
    assert r["capabilities"] == ["implementation_handoff:accept"]
    assert r["authority_roles"] == []
    assert r["live_runtime_expected_http"] == 400
    assert r["live_runtime_expected_error"] == "invalid_query"
    assert r["temporary_session_issue_count_authorized"] == 1
    assert r["temporary_token_validation_count_authorized"] == 1
    assert r["live_runtime_identity_probe_count_authorized"] == 1
    assert r["global_logout_count_authorized"] == 1
    assert r["provider_adapter_positive_auth_test_authorized"] is True
    for key in (
        "implementation_handoff_execution_authorized",
        "token_refresh_authorized",
        "retry_authorized",
        "password_change_authorized",
        "identity_change_authorized",
        "tenant_change_authorized",
        "allowlist_change_authorized",
        "hook_change_authorized",
        "data_operation_authorized",
        "render_mutation_authorized",
        "n8n_operation_authorized",
        "staging_authorized",
        "production_authorized",
        "credential_material_agent_visible",
        "credential_material_persistence_authorized",
        "raw_provider_subject_persistence_authorized",
        "pii_persistence_authorized",
    ):
        assert r[key] is False

    assert len(p["steps"]) == 10
    assert p["ordered_step_ids"] == [step["step_id"] for step in p["steps"]]
    operations = [step["operation"] for step in p["steps"]]
    assert operations == [
        "provider.auth-admin-credential.create-dedicated-secret-key",
        "provider.auth-secret-binding.create-github-environment-reference",
        "provider.auth-secret-binding.verify-github-environment-reference",
        "provider.auth-state.inspect-aggregate-only",
        "provider.auth-session.provider-adapter-recover-validate-live-probe-and-logout-global",
        "provider.auth-session-state.inspect-read-only",
        "provider.auth-admin-credential.delete-dedicated-secret-key",
        "provider.auth-secret-binding.delete-github-environment-reference",
        "provider.auth-admin-credential.verify-dedicated-secret-key-absent",
        "provider.auth-secret-binding.verify-github-environment-reference-absent",
    ]
    for index, step in enumerate(p["steps"]):
        assert step["ordinal"] == index + 1
        assert step["resource"]["exact_digest"] == RESOURCE_DIGEST
        if index:
            assert step["dependency_step_ids"] == [p["steps"][index - 1]["step_id"]]
        else:
            assert step["dependency_step_ids"] == []

    step5 = p["steps"][4]
    assert step5["credential_policy"]["allowed_classes"] == ["SUPABASE_AUTH_ADMIN_EPHEMERAL"]
    assert step5["credential_policy"]["values_stored"] is False
    assert step5["credential_policy"]["ephemeral_handling"] == {
        "material_source": "APPROVED_ENVIRONMENT_SECRET_BOUNDARY",
        "material_residency": "SERVER_EXECUTOR_MEMORY_ONLY",
        "control_plane_visibility": "CLASS_LABEL_ONLY",
        "material_digest": "PROHIBITED",
        "persistence": "PROHIBITED",
        "logging": "PROHIBITED",
        "return_policy": "PROHIBITED",
        "proof_policy": "NON_SECRET_EXECUTOR_CAPABILITY_ATTESTATION",
    }
    capability = [
        binding for binding in step5["binding_declarations"]
        if binding["evidence_type"] == "auth.admin-executor-capability.observed"
    ]
    assert len(capability) == 1
    assert capability[0]["phase"] == "RESOLVED_BY_STEP_PREFLIGHT"
    assert capability[0]["value_class"] == "CONFIGURATION_REFERENCE"
    assert capability[0]["persistence_policy"] == "DIGEST_ONLY"
    for action in (
        "credential.persist",
        "credential.expose",
        "credential.log",
        "credential.return",
        "credential.digest",
        "credential.copy",
        "credential.create",
        "credential.rotate",
        "credential.export",
        "implementation-handoff.execute",
        "token.refresh",
        "provider.retry",
    ):
        assert action in step5["prohibited_actions"]

    assert g == initial_progress(p, S, PROGRESS_ID, p["created_at"])
    assert g["progress_digest"] == PROGRESS_DIGEST
    assert g["overall_state"] == "NOT_STARTED"
    assert all(
        state["authorization_state"] == "PENDING"
        and state["execution_state"] == "NOT_STARTED"
        and state["verification_state"] == "NOT_STARTED"
        and state["authorization_consumed"] is False
        and not state["evidence"]
        for state in g["step_states"]
    )

    rendered = "".join(
        (B / (N + suffix)).read_text()
        for suffix in (
            ".resource.json",
            "-preparation.evidence.json",
            ".plan.json",
            ".progress.json",
        )
    )
    for forbidden in (
        "postgresql://",
        "postgres://",
        "Bearer eyJ",
        '"secret_value"',
        '"service_role_key"',
        '"access_token"',
        '"refresh_token"',
    ):
        assert forbidden not in rendered

    print(
        "DEVELOPMENT provider-adapter positive-auth v1: PASS "
        "(READY_FOR_APPROVAL; 10 ordered resource steps; one temporary session; "
        "live 400 identity proof; mandatory cleanup and credential retirement; "
        "no ImplementationHandoff execution)"
    )


if __name__ == "__main__":
    main()
