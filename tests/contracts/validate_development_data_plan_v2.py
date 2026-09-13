#!/usr/bin/env python3
"""Validate the bounded DEVELOPMENT DATA v2 migration-identity package."""
from __future__ import annotations

import hashlib
import json
import subprocess
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
PLAN_PATH = ROOT / "contracts/plans/v1/development-data-integration-v2.plan.json"
APPROVAL_PATH = ROOT / "contracts/plans/v1/development-data-integration-v2.approval.json"
PROGRESS_PATH = ROOT / "contracts/plans/v1/development-data-integration-v2.progress.json"
V1_APPROVAL_PATH = ROOT / "contracts/plans/v1/development-data-integration-v1.approval.json"
MIGRATION_PATH = ROOT / "supabase/migrations/20260831120000_rebaseline_provider_neutral_avuhz.sql"
BOOTSTRAP_PATH = ROOT / "supabase/provider-artifacts/development-data/current/development_data_migration_identity_v1.sql"
ROLE_BINDING_PATH = ROOT / "supabase/provider-artifacts/development-data/current/development_data_migration_role_binding_v1.sql"
SEAL_PATH = ROOT / "supabase/provider-artifacts/development-data/current/development_data_migration_identity_seal_v1.sql"

PLAN_ID = "a7034439-f9e7-4358-90ef-cf221dfd1d1b"
APPROVAL_ID = "d77cc375-f92b-4168-9404-07fe79399ba7"
PROGRESS_ID = "c81b4126-1e73-4b0f-98b8-afee13d262b7"
PLAN_DIGEST = "sha256:066f6cc97adbe4cdc0be03dd880726f506a454064c6b249605455c7a5eac0d36"
APPROVAL_DIGEST = "sha256:d0378f644153d69d25df5de22843f4719a6689c6ac8fb19272bb1b798d761c90"
PROGRESS_DIGEST = "sha256:f878207a4812e0ce53c0e7eda417b2d6fa55453c1809f1fb846cacc1966736d8"
APPROVAL_FILE_DIGEST = "sha256:625036601df6b25aa95c61d4a43b2c38d5b47f73e274698220d763676a64755c"
PACKAGE_IDENTITY_DIGEST = "sha256:7ee54f4e817cefe62f40bf31d8b8321591db901b08991ddae5a64881bdfa75ee"
PROJECT_REFERENCE = "gnuqaefotwgkwurjpyik"
WINDOW_START = "2026-09-13T21:00:00Z"
WINDOW_END = "2026-09-14T01:00:00Z"
MIGRATION_GIT_BLOB = "ff2fa6ce4e2b788a9eada5379f85593e96d82424"
MIGRATION_GIT_COMMIT = "14d60d809d856fed1ea1ec917d91f50270bae793"
BOOTSTRAP_GIT_BLOB = "68a830b37d6389333506bdfeccf97f57c0d31219"
ROLE_BINDING_GIT_BLOB = "978fafb64a21b8acb3572c237e08d739afd473f0"
SEAL_GIT_BLOB = "65952c5900a6b73f8f413fe21f3c124c2f3e182e"
V1_PLAN_DIGEST = "sha256:f4a0dfdba82a1f23430f0b299d738a19f89caeaec9401adcef90c9ee92bd8563"
V1_APPROVAL_DIGEST = "sha256:8d8dd92ce4b380af65cc8f2e2cf26ebc9fbaece537dd6a6e55f85840e964cf84"
STEP_IDS = [
    "development.data.v2.step.01.verify-empty-bootstrap-boundary",
    "development.data.v2.step.02.bootstrap-migration-identity",
    "development.data.v2.step.03.verify-migration-identity",
    "development.data.v2.step.04.apply-initial-migration",
    "development.data.v2.step.05.seal-migration-identity",
    "development.data.v2.step.06.verify-tenant-isolation",
]


def load(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    assert isinstance(value, dict), path
    return value


def raw_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def git_blob(path: Path) -> str:
    relative = path.relative_to(ROOT).as_posix()
    return subprocess.check_output(
        ["git", "rev-parse", f"HEAD:{relative}"], cwd=ROOT, text=True
    ).strip()


def main() -> int:
    plan = load(PLAN_PATH)
    approval = load(APPROVAL_PATH)
    progress = load(PROGRESS_PATH)
    v1_approval = load(V1_APPROVAL_PATH)

    validate_plan(plan, SCHEMA_ROOT)
    validate_progress(plan, progress, SCHEMA_ROOT)
    validate_approval(plan, approval, SCHEMA_ROOT, WINDOW_START)

    assert plan["plan_id"] == PLAN_ID
    assert plan["plan_version"] == 2
    assert plan["plan_digest"] == PLAN_DIGEST
    assert plan["environment"] == "DEVELOPMENT"
    assert plan["target"] == {
        "provider_class": "data.provider",
        "provider_reference": "supabase",
        "project_reference": PROJECT_REFERENCE,
        "responsibility": "DATA",
        "issuer_reference": None,
        "audience_reference": None,
    }
    assert plan["authorization_window"] == {
        "binding_state": "BOUND",
        "starts_at": WINDOW_START,
        "expires_at": WINDOW_END,
    }
    assert plan["ordered_step_ids"] == STEP_IDS
    assert plan["authority_effect"] == "NONE_UNTIL_SEPARATELY_APPROVED"
    assert "development.data.v1.execute" in plan["prohibited_actions"]
    assert "v1.execution.attempted" in plan["stop_conditions"]
    assert "pwlhruwutoitnieactol" not in json.dumps(plan, sort_keys=True)

    package_identity = {
        "repository": "AnonymousKoo/avuhz-infra",
        "project_reference": PROJECT_REFERENCE,
        "migration": {
            "path": "supabase/migrations/20260831120000_rebaseline_provider_neutral_avuhz.sql",
            "canonical_commit": MIGRATION_GIT_COMMIT,
            "git_blob": MIGRATION_GIT_BLOB,
        },
        "bootstrap": {
            "path": "supabase/provider-artifacts/development-data/current/development_data_migration_identity_v1.sql",
            "git_blob": BOOTSTRAP_GIT_BLOB,
        },
        "role_binding": {
            "path": "supabase/provider-artifacts/development-data/current/development_data_migration_role_binding_v1.sql",
            "git_blob": ROLE_BINDING_GIT_BLOB,
        },
        "seal": {
            "path": "supabase/provider-artifacts/development-data/current/development_data_migration_identity_seal_v1.sql",
            "git_blob": SEAL_GIT_BLOB,
        },
        "historical_v1": {
            "plan_digest": V1_PLAN_DIGEST,
            "approval_digest": V1_APPROVAL_DIGEST,
            "status": "ACTIVE",
            "execution_under_v2": "PROHIBITED",
        },
    }
    assert canonical_digest(package_identity) == PACKAGE_IDENTITY_DIGEST
    assert git_blob(MIGRATION_PATH) == MIGRATION_GIT_BLOB
    assert git_blob(BOOTSTRAP_PATH) == BOOTSTRAP_GIT_BLOB
    assert git_blob(ROLE_BINDING_PATH) == ROLE_BINDING_GIT_BLOB
    assert git_blob(SEAL_PATH) == SEAL_GIT_BLOB

    assert v1_approval["plan_digest"] == V1_PLAN_DIGEST
    assert v1_approval["approval_digest"] == V1_APPROVAL_DIGEST
    assert v1_approval["status"] == "ACTIVE"

    initial, bootstrap, verify_role, migration, seal, verification = plan["steps"]
    assert initial["required_evidence"] == [{
        "evidence_type": "repository.data-v2.artifact-package.verified",
        "source_step_id": None,
        "binding_state": "BOUND",
        "exact_digest": PACKAGE_IDENTITY_DIGEST,
    }]
    assert "unchanged historical evidence" in initial["expected_postcondition"]
    assert [step["execution_class"] for step in plan["steps"]] == [
        "PROVIDER_READ", "PROVIDER_MUTATION", "PROVIDER_READ",
        "PROVIDER_MUTATION", "PROVIDER_MUTATION", "PROVIDER_READ",
    ]
    for index, step in enumerate(plan["steps"]):
        assert step["dependency_step_ids"] == ([] if index == 0 else [STEP_IDS[index - 1]])
        assert step["credential_policy"] == {
            "permitted": True,
            "allowed_classes": ["OWNER_INTERACTIVE_SESSION"],
            "values_stored": False,
        }

    assert bootstrap["resource"]["exact_version"] == "gitblob." + BOOTSTRAP_GIT_BLOB
    assert "USAGE WITH GRANT OPTION" in bootstrap["expected_postcondition"]
    assert verify_role["operation"] == "provider.resource.verify-data-migration-identity"
    assert "USAGE WITH GRANT OPTION" in verify_role["expected_postcondition"]
    assert migration["resource"]["exact_version"] == "gitblob." + MIGRATION_GIT_BLOB
    assert migration["operation"] == "provider.resource.apply-bound-role-scoped-initial-migration"
    assert "owner-direct-schema-migration" in migration["prohibited_actions"]
    assert seal["resource"]["exact_version"] == "gitblob." + SEAL_GIT_BLOB
    assert "PostgreSQL-17 ADMIN/NOSET/NOINHERIT creator edges" in seal["expected_postcondition"]
    assert verification["operation"] == "provider.resource.verify-tenant-isolation-and-sealed-identity"
    assert "exactly 16 Avuhz tables" in verification["expected_postcondition"]

    bootstrap_sql = BOOTSTRAP_PATH.read_text(encoding="utf-8").lower()
    assert "create role avuhz_data_migration_service_dev" in bootstrap_sql
    for marker in ("nologin", "nosuperuser", "noinherit", "nocreatedb", "createrole", "noreplication", "nobypassrls"):
        assert marker in bootstrap_sql
    assert "grant usage on schema public to avuhz_data_migration_service_dev with grant option" in bootstrap_sql
    assert "grant create on schema public to avuhz_data_migration_service_dev" in bootstrap_sql
    assert "set local role avuhz_data_migration_service_dev" in bootstrap_sql

    role_binding_sql = ROLE_BINDING_PATH.read_text(encoding="utf-8")
    executable_lines = [
        line.strip().lower() for line in role_binding_sql.splitlines()
        if line.strip() and not line.lstrip().startswith("--")
    ]
    assert executable_lines == ["set local role avuhz_data_migration_service_dev;"]

    seal_sql = SEAL_PATH.read_text(encoding="utf-8").lower()
    assert "grant usage on schema public to avuhz_command_service" in seal_sql
    assert "alter role avuhz_data_migration_service_dev nocreaterole" in seal_sql
    assert "revoke usage on schema public from avuhz_data_migration_service_dev cascade" in seal_sql
    assert "revoke avuhz_data_migration_service_dev from postgres granted by postgres" in seal_sql
    assert "command_admin_edge_count <> 1" in seal_sql
    assert "pg_has_role('postgres', 'avuhz_data_migration_service_dev', 'set')" in seal_sql

    migration_sql = MIGRATION_PATH.read_text(encoding="utf-8")
    lower = migration_sql.lower()
    begin_marker = "\nbegin;\n"
    assert begin_marker in lower
    begin_index = lower.index(begin_marker) + len(begin_marker)
    composed = migration_sql[:begin_index] + "\nset local role avuhz_data_migration_service_dev;\n" + migration_sql[begin_index:]
    composed_lower = composed.lower()
    assert composed_lower.count("set local role avuhz_data_migration_service_dev;") == 1
    assert composed_lower.index("set local role avuhz_data_migration_service_dev;") < composed_lower.index("do $avuhz_initial_preflight$")
    assert lower.count("create table public.avuhz_") == 16
    assert lower.count(" enable row level security;") == 16
    assert "create policy avuhz_command_service_tenant_isolation" in lower
    assert "current_setting('avuhz.tenant_id',true)" in lower
    assert "create role avuhz_command_service nologin nosuperuser nobypassrls" in lower

    assert approval["approval_id"] == APPROVAL_ID
    assert approval["plan_digest"] == PLAN_DIGEST
    assert approval["approval_digest"] == APPROVAL_DIGEST
    assert approval["status"] == "ACTIVE"
    assert approval["authority_scope"] == "EXACT_PLAN_ONLY"
    assert raw_digest(APPROVAL_PATH) == APPROVAL_FILE_DIGEST

    expected_progress = initial_progress(plan, SCHEMA_ROOT, PROGRESS_ID, plan["created_at"])
    assert progress == expected_progress
    assert progress["progress_digest"] == PROGRESS_DIGEST
    assert all(
        state["authorization_state"] == "PENDING"
        and state["execution_state"] == "NOT_STARTED"
        and state["verification_state"] == "NOT_STARTED"
        and not state["authorization_consumed"]
        for state in progress["step_states"]
    )

    print("DEVELOPMENT DATA v2 migration-identity package: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
