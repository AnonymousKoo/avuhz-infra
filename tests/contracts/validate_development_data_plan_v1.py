#!/usr/bin/env python3
"""Validate the bounded DEVELOPMENT DATA v1 bootstrap plan package."""
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
PLAN_PATH = ROOT / "contracts/plans/v1/development-data-integration-v1.plan.json"
APPROVAL_PATH = ROOT / "contracts/plans/v1/development-data-integration-v1.approval.json"
PROGRESS_PATH = ROOT / "contracts/plans/v1/development-data-integration-v1.progress.json"
MIGRATION_PATH = ROOT / "supabase/migrations/20260831120000_rebaseline_provider_neutral_avuhz.sql"

PLAN_ID = "e8378a7e-9840-426c-9575-9427b437c619"
APPROVAL_ID = "64480469-11a5-4397-a111-9f91c8411b7a"
PROGRESS_ID = "4406cb84-dccd-44ba-bf79-38f1c28c4bf0"
PLAN_DIGEST = "sha256:f4a0dfdba82a1f23430f0b299d738a19f89caeaec9401adcef90c9ee92bd8563"
APPROVAL_DIGEST = "sha256:8d8dd92ce4b380af65cc8f2e2cf26ebc9fbaece537dd6a6e55f85840e964cf84"
PROGRESS_DIGEST = "sha256:e8305b2edb1493f19ea62d99fe8a73de91dc4b1505c46cc623557ae0ea30b589"
APPROVAL_FILE_DIGEST = "sha256:da44f85800453644c1cc4008c6209fa212633444cdade417d2b945b2f8c8d359"
PROJECT_REFERENCE = "gnuqaefotwgkwurjpyik"
MIGRATION_GIT_BLOB = "ff2fa6ce4e2b788a9eada5379f85593e96d82424"
MIGRATION_GIT_COMMIT = "14d60d809d856fed1ea1ec917d91f50270bae793"
MIGRATION_IDENTITY_DIGEST = "sha256:3894ddd17b431afb7cf32d1f1d4d8b6f47f87e990e8a297c3b3b386e72e6cf75"
WINDOW_START = "2026-09-13T20:35:00Z"
WINDOW_END = "2026-09-13T23:35:00Z"
STEP_IDS = [
    "development.data.v1.step.01.verify-empty-baseline",
    "development.data.v1.step.02.apply-initial-migration",
    "development.data.v1.step.03.verify-tenant-isolation",
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
        ["git", "rev-parse", f"HEAD:{relative}"],
        cwd=ROOT,
        text=True,
    ).strip()


def main() -> int:
    plan = load(PLAN_PATH)
    approval = load(APPROVAL_PATH)
    progress = load(PROGRESS_PATH)

    validate_plan(plan, SCHEMA_ROOT)
    validate_progress(plan, progress, SCHEMA_ROOT)
    validate_approval(plan, approval, SCHEMA_ROOT, WINDOW_START)

    assert plan["plan_id"] == PLAN_ID
    assert plan["plan_version"] == 1
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

    serialized = json.dumps(plan, sort_keys=True)
    assert "pwlhruwutoitnieactol" not in serialized
    for prohibited in (
        "production.target",
        "staging.target",
        "vertical.infrastructure",
        "credential.persistence",
        "migration.history.repair",
        "unbound-migration.execute",
    ):
        assert prohibited in plan["prohibited_actions"]

    migration_identity = {
        "repository": "AnonymousKoo/avuhz-infra",
        "canonical_commit": MIGRATION_GIT_COMMIT,
        "migration_path": "supabase/migrations/20260831120000_rebaseline_provider_neutral_avuhz.sql",
        "git_blob": MIGRATION_GIT_BLOB,
    }
    assert canonical_digest(migration_identity) == MIGRATION_IDENTITY_DIGEST
    assert git_blob(MIGRATION_PATH) == MIGRATION_GIT_BLOB

    initial = plan["steps"][0]
    mutation = plan["steps"][1]
    verification = plan["steps"][2]
    assert initial["execution_class"] == "PROVIDER_READ"
    assert initial["operation"] == "provider.resource.verify-empty-avuhz-baseline"
    assert initial["required_evidence"] == [{
        "evidence_type": "repository.migration.identity.verified",
        "source_step_id": None,
        "binding_state": "BOUND",
        "exact_digest": MIGRATION_IDENTITY_DIGEST,
    }]
    assert "provider.mutation" in initial["prohibited_actions"]

    assert mutation["execution_class"] == "PROVIDER_MUTATION"
    assert mutation["operation"] == "provider.resource.apply-initial-migration"
    assert mutation["resource"]["resource_reference"] == "supabase/migrations/20260831120000_rebaseline_provider_neutral_avuhz.sql"
    assert mutation["resource"]["exact_version"] == "gitblob." + MIGRATION_GIT_BLOB
    assert mutation["dependency_step_ids"] == [STEP_IDS[0]]
    assert mutation["credential_policy"] == {
        "permitted": True,
        "allowed_classes": ["OWNER_INTERACTIVE_SESSION"],
        "values_stored": False,
    }
    for prohibited in (
        "batch.mutation",
        "auth.operation",
        "row-data.mutation",
        "migration.history.repair",
        "unbound-migration.execute",
        "vertical.infrastructure",
    ):
        assert prohibited in mutation["prohibited_actions"]

    preapprovals = {
        item["binding_id"]: item["preapproval_value"]
        for item in mutation["binding_declarations"]
        if item["phase"] == "PREAPPROVAL_BOUND"
    }
    assert preapprovals["binding.development.data.v1.migration-git-blob"] == {
        "value": "gitblob." + MIGRATION_GIT_BLOB,
        "exact_digest": canonical_digest("gitblob." + MIGRATION_GIT_BLOB),
    }
    assert preapprovals["binding.development.data.v1.migration-git-commit"] == {
        "value": "gitcommit." + MIGRATION_GIT_COMMIT,
        "exact_digest": canonical_digest("gitcommit." + MIGRATION_GIT_COMMIT),
    }

    assert verification["execution_class"] == "PROVIDER_READ"
    assert verification["operation"] == "provider.resource.verify-tenant-isolation"
    assert verification["dependency_step_ids"] == [STEP_IDS[1]]
    assert "provider.mutation" in verification["prohibited_actions"]
    assert "exactly 16 Avuhz tables" in verification["expected_postcondition"]

    sql = MIGRATION_PATH.read_text(encoding="utf-8")
    lower = sql.lower()
    assert lower.count(" enable row level security;") == 16
    assert lower.count("create table public.avuhz_") == 16
    assert "create policy avuhz_command_service_tenant_isolation" in lower
    assert "current_setting('avuhz.tenant_id',true)" in lower
    assert "create role avuhz_command_service nologin nosuperuser nobypassrls" in lower
    assert "revoke all on table" in lower
    assert "'anon','authenticated','service_role'" in lower
    assert "remote application is unauthorized by default" in lower

    assert approval["approval_id"] == APPROVAL_ID
    assert approval["approval_digest"] == APPROVAL_DIGEST
    assert approval["plan_id"] == PLAN_ID
    assert approval["plan_digest"] == PLAN_DIGEST
    assert approval["owner_identity"] == "github:AnonymousKoo"
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

    print("DEVELOPMENT DATA v1 bounded plan package: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
