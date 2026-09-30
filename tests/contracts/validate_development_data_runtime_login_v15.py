#!/usr/bin/env python3
"""Validate verified DEVELOPMENT DATA runtime-login v15 outcome evidence."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "contracts/plans/v1"
PLAN_PATH = BASE / "development-data-runtime-login-v15.plan.json"
APPROVAL_PATH = BASE / "development-data-runtime-login-v15.approval.json"
EVIDENCE_PATH = BASE / "development-data-runtime-login-v15-step1-success.evidence.json"
EXECUTION_PROGRESS_PATH = BASE / "development-data-runtime-login-v15.execution-progress.json"
PROGRESS_SCHEMA_PATH = (
    ROOT / "contracts/schemas/v1/orchestration/bounded-authorization-plan-progress.schema.json"
)

PLAN_ID = "7c4d9204-4d9a-43df-9ef7-4b8c2f5a7a01"
PLAN_DIGEST = "sha256:c9fbd3dfbb8096cb501a85a61e52c2cdf184c76fb3c5b7f019bea0d1c3da2caa"
APPROVAL_ID = "43222b5d-716a-4f40-a2a3-2a1fd5389a3b"
APPROVAL_DIGEST = "sha256:c0d063dd9df8f36fbfb68211b8b98d582981a3d3f44b54d3a55f13131264222a"
EVIDENCE_DIGEST = "sha256:817df8e5a593314325827b89e8b8d38d60c13157ea571ba22575ffab5f02de8a"


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def raw_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    plan = load(PLAN_PATH)
    approval = load(APPROVAL_PATH)
    evidence = load(EVIDENCE_PATH)
    progress_schema = load(PROGRESS_SCHEMA_PATH)

    assert plan["plan_id"] == PLAN_ID
    assert plan["plan_digest"] == PLAN_DIGEST
    assert approval["approval_id"] == APPROVAL_ID
    assert approval["plan_id"] == PLAN_ID
    assert approval["plan_digest"] == PLAN_DIGEST
    assert approval["approval_digest"] == APPROVAL_DIGEST
    assert raw_digest(EVIDENCE_PATH) == EVIDENCE_DIGEST

    assert evidence["evidence_type"] == "data.runtime-login.created-and-verified"
    assert evidence["environment"] == "DEVELOPMENT"
    assert evidence["responsibility"] == "DATA"
    assert evidence["project_reference"] == "gnuqaefotwgkwurjpyik"
    assert evidence["plan_id"] == PLAN_ID
    assert evidence["plan_digest"] == PLAN_DIGEST
    assert evidence["approval_id"] == APPROVAL_ID
    assert evidence["approval_digest"] == APPROVAL_DIGEST
    assert evidence["outcome"] == "SUCCEEDED_VERIFIED"
    assert evidence["authorization_state"] == "CONSUMED"
    assert evidence["authorization_consumed"] is True
    assert evidence["execution_state"] == "SUCCEEDED"
    assert evidence["verification_state"] == "PASS"

    provider = evidence["provider_observation"]
    assert provider["runtime_role_exists"] is True
    assert provider["runtime_role_can_login"] is True
    for key in (
        "runtime_role_superuser",
        "runtime_role_createdb",
        "runtime_role_createrole",
        "runtime_role_inherit",
        "runtime_role_replication",
        "runtime_role_bypassrls",
        "temporary_postgres_migration_edge_survived",
        "postgres_can_set_migration_after",
        "migration_can_set_command_after",
    ):
        assert provider[key] is False, key
    assert provider["runtime_command_membership_exact"] is True
    assert provider["sealed_postgres_migration_edge_preserved"] is True
    assert provider["sealed_migration_command_edge_preserved"] is True
    assert provider["runtime_can_set_command_after"] is True
    assert provider["runtime_direct_table_grants"] == 0

    security = evidence["security_state"]
    for key in (
        "credential_value_returned",
        "credential_value_retained",
        "credential_exposed_by_execution_output",
        "temporary_env_file_retained",
        "temporary_runner_file_retained",
        "rls_changed",
        "auth_touched",
        "render_touched",
        "staging_touched",
        "production_touched",
    ):
        assert security[key] is False, key

    postcondition = plan["steps"][0]["expected_postcondition"]
    max_length = (
        progress_schema["$defs"]["stepState"]["properties"]["observed_postcondition"]
        ["oneOf"][0]["maxLength"]
    )
    compatibility = evidence["progress_recording"]
    assert len(postcondition) == 732
    assert max_length == 500
    assert len(postcondition) > max_length
    assert compatibility["status"] == "NOT_WRITTEN_SCHEMA_INCOMPATIBLE"
    assert compatibility["approved_postcondition_length"] == len(postcondition)
    assert compatibility["progress_schema_observed_postcondition_max_length"] == max_length
    assert compatibility["plan_mutated_after_execution"] is False
    assert compatibility["schema_mutated_after_execution"] is False
    assert not EXECUTION_PROGRESS_PATH.exists()

    print("DEVELOPMENT DATA runtime-login v15 verified outcome evidence: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
