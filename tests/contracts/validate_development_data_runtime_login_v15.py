#!/usr/bin/env python3
"""Validate verified DEVELOPMENT DATA runtime-login v15 completion."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.authorization_plan import (
    plan_digest,
    validate_plan,
    validate_progress,
)

BASE = ROOT / "contracts/plans/v1"
SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
PLAN_PATH = BASE / "development-data-runtime-login-v15.plan.json"
APPROVAL_PATH = BASE / "development-data-runtime-login-v15.approval.json"
EVIDENCE_PATH = BASE / "development-data-runtime-login-v15-step1-success.evidence.json"
EXECUTION_PROGRESS_PATH = BASE / "development-data-runtime-login-v15.execution-progress.json"
PLAN_SCHEMA_PATH = (
    ROOT / "contracts/schemas/v1/orchestration/bounded-authorization-plan-v2.schema.json"
)
PROGRESS_SCHEMA_PATH = (
    ROOT / "contracts/schemas/v1/orchestration/bounded-authorization-plan-progress.schema.json"
)

PLAN_ID = "7c4d9204-4d9a-43df-9ef7-4b8c2f5a7a01"
PLAN_DIGEST = "sha256:c9fbd3dfbb8096cb501a85a61e52c2cdf184c76fb3c5b7f019bea0d1c3da2caa"
APPROVAL_ID = "43222b5d-716a-4f40-a2a3-2a1fd5389a3b"
APPROVAL_DIGEST = "sha256:c0d063dd9df8f36fbfb68211b8b98d582981a3d3f44b54d3a55f13131264222a"
EVIDENCE_DIGEST = "sha256:817df8e5a593314325827b89e8b8d38d60c13157ea571ba22575ffab5f02de8a"
PROGRESS_DIGEST = "sha256:cedb1f757b8182af0596eec2dc7c5803dcf0be3c8100e3bc4a0967cb3fcd2c84"
ROLE_STATE_DIGEST = "sha256:bdc78286bcb2f25a9f122dc8563b7e6a33314d4603c92f212bd80f942ad492a8"
POSTCONDITION_MAX_LENGTH = 1000


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def raw_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    plan = load(PLAN_PATH)
    approval = load(APPROVAL_PATH)
    evidence = load(EVIDENCE_PATH)
    execution = load(EXECUTION_PROGRESS_PATH)
    plan_schema = load(PLAN_SCHEMA_PATH)
    progress_schema = load(PROGRESS_SCHEMA_PATH)

    validate_plan(plan, SCHEMA_ROOT)
    validate_progress(plan, execution, SCHEMA_ROOT)

    assert plan["plan_id"] == PLAN_ID
    assert plan["plan_digest"] == PLAN_DIGEST == plan_digest(plan)
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
    plan_limit = plan_schema["$defs"]["postconditionText"]["maxLength"]
    progress_limit = (
        progress_schema["$defs"]["stepState"]["properties"]["observed_postcondition"]
        ["oneOf"][0]["maxLength"]
    )
    assert len(postcondition) == 732
    assert plan_limit == POSTCONDITION_MAX_LENGTH
    assert progress_limit == POSTCONDITION_MAX_LENGTH
    assert len(postcondition) <= plan_limit

    # The success evidence is immutable historical truth: at recording time the
    # progress schema was too small. The forward correction must not rewrite it.
    compatibility = evidence["progress_recording"]
    assert compatibility["status"] == "NOT_WRITTEN_SCHEMA_INCOMPATIBLE"
    assert compatibility["approved_postcondition_length"] == 732
    assert compatibility["progress_schema_observed_postcondition_max_length"] == 500
    assert compatibility["plan_mutated_after_execution"] is False
    assert compatibility["schema_mutated_after_execution"] is False

    assert execution["progress_id"] == "b6d39e14-f4b7-4aca-9f5f-3d5b7f842c1e"
    assert execution["plan_id"] == PLAN_ID
    assert execution["plan_digest"] == PLAN_DIGEST
    assert execution["record_version"] == 3
    assert execution["overall_state"] == "COMPLETED"
    assert execution["progress_digest"] == PROGRESS_DIGEST
    assert execution["updated_at"] == evidence["recorded_at"]

    state = execution["step_states"][0]
    assert state["step_id"] == plan["ordered_step_ids"][0]
    assert state["authorization_state"] == "CONSUMED"
    assert state["authorization_consumed"] is True
    assert state["execution_state"] == "SUCCEEDED"
    assert state["verification_state"] == "PASS"
    assert state["safe_error_code"] is None
    assert state["observed_postcondition"] == postcondition
    assert len(state["evidence"]) == 1
    assert state["evidence"][0]["evidence_digest"] == EVIDENCE_DIGEST
    assert state["evidence"][0]["recorded_at"] == evidence["recorded_at"]

    assertions = state["binding_assertions"]
    assert len(assertions) == 1
    assertion = assertions[0]
    assert assertion["binding_id"] == "binding.development.data.runtime-login.v15.role-state"
    assert assertion["evidence_digest"] == EVIDENCE_DIGEST
    assert assertion["value_digest"] == ROLE_STATE_DIGEST
    assert assertion["sanitized_value"] is None
    assert assertion["recorded_at"] == evidence["recorded_at"]

    print("DEVELOPMENT DATA runtime-login v15 completion: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
