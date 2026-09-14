#!/usr/bin/env python3
"""Validate the fresh DEVELOPMENT DATA v3 continuation after v2 expiry."""
from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime
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
PLAN_PATH = ROOT / "contracts/plans/v1/development-data-integration-v3.plan.json"
APPROVAL_PATH = ROOT / "contracts/plans/v1/development-data-integration-v3.approval.json"
PROGRESS_PATH = ROOT / "contracts/plans/v1/development-data-integration-v3.progress.json"
V2_PLAN_PATH = ROOT / "contracts/plans/v1/development-data-integration-v2.plan.json"
V2_APPROVAL_PATH = ROOT / "contracts/plans/v1/development-data-integration-v2.approval.json"
V2_EXECUTION_PATH = ROOT / "contracts/plans/v1/development-data-integration-v2.execution-progress.json"
STEP4_EVIDENCE_PATH = ROOT / "contracts/plans/v1/development-data-step4-v2-success.evidence.json"
SEAL_PATH = ROOT / "supabase/provider-artifacts/development-data/current/development_data_migration_identity_seal_v1.sql"

PLAN_ID = "f6ae6374-878e-4a84-9b33-3f5718ed01b9"
PROGRESS_ID = "02ce9f9e-7ec4-424a-b1f0-8b36ecf98a80"
PLAN_DIGEST = "sha256:d958bb5cb4d12524ebfb3d748e025af64b8c32da6e77e17ca8559239f18e0eb8"
APPROVAL_DIGEST = "sha256:be256ec837284cac990158e64d7560355e134fc0dd34c6494c9cd39985669c1d"
INITIAL_PROGRESS_DIGEST = "sha256:74987ec0ec0017e33b11020dde570846879ccd00f465cb24c000d7a35252741e"
STEP4_EVIDENCE_DIGEST = "sha256:23f5efaad368cde39ce6d8d4c58e1d3c9912d508ae4c83c994ff12c37463c0a8"
INITIAL_MIGRATION_STATE_DIGEST = "sha256:727e3ac7dc0f74c323d119b400166a32c187036e9fd521a8092e3afa4bbc5ba3"
INITIAL_MIGRATION_PREAPPROVAL_DIGEST = "sha256:515f13a3431aac7ccdb0f6ce5f2c7f8b06801991cf8c29a876add467ae4f4a3f"
SEAL_BLOB = "65952c5900a6b73f8f413fe21f3c124c2f3e182e"
SEAL_REFERENCE = "gitblob.65952c5900a6b73f8f413fe21f3c124c2f3e182e"
SEAL_REFERENCE_DIGEST = "sha256:0b1bcfc2c5fee3d88f5c203267c2f55aada1a0bfcb37743cf1ad9aaf4fcb0e2b"
WINDOW_START = "2026-09-14T01:40:00Z"
WINDOW_END = "2026-09-14T05:40:00Z"
CREATED_AT = "2026-09-14T01:28:04Z"
V2_EXPIRES_AT = "2026-09-14T01:00:00Z"
STEP1 = "development.data.v3.step.01.seal-migration-identity"
STEP2 = "development.data.v3.step.02.verify-tenant-isolation"


def load(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    assert isinstance(value, dict), path
    return value


def raw_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def git_blob_sha(path: Path) -> str:
    body = path.read_bytes()
    return hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest()


def utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def main() -> int:
    plan = load(PLAN_PATH)
    approval = load(APPROVAL_PATH)
    progress = load(PROGRESS_PATH)
    v2_plan = load(V2_PLAN_PATH)
    v2_approval = load(V2_APPROVAL_PATH)
    v2_execution = load(V2_EXECUTION_PATH)
    step4_evidence = load(STEP4_EVIDENCE_PATH)

    validate_plan(plan, SCHEMA_ROOT)
    validate_progress(plan, progress, SCHEMA_ROOT)
    validate_approval(plan, approval, SCHEMA_ROOT, WINDOW_START)

    assert plan["plan_id"] == PLAN_ID
    assert plan["plan_version"] == 3
    assert plan["plan_digest"] == PLAN_DIGEST
    assert plan["environment"] == "DEVELOPMENT"
    assert plan["target"] == {
        "provider_class": "data.provider",
        "provider_reference": "supabase",
        "project_reference": "gnuqaefotwgkwurjpyik",
        "responsibility": "DATA",
        "issuer_reference": None,
        "audience_reference": None,
    }
    assert plan["authorization_window"] == {
        "binding_state": "BOUND",
        "starts_at": WINDOW_START,
        "expires_at": WINDOW_END,
    }
    assert plan["ordered_step_ids"] == [STEP1, STEP2]
    assert plan["authority_effect"] == "NONE_UNTIL_SEPARATELY_APPROVED"
    assert "v2.expired-authorization.execute" in plan["prohibited_actions"]
    assert "search-path.repair" in plan["prohibited_actions"]
    assert "security-advisor.finding.ignore" in plan["prohibited_actions"]

    step1, step2 = plan["steps"]
    assert step1["step_id"] == STEP1
    assert step1["operation"] == "provider.resource.seal-data-migration-identity"
    assert step1["execution_class"] == "PROVIDER_MUTATION"
    assert step1["dependency_step_ids"] == []
    assert step1["resource"]["resource_reference"] == str(SEAL_PATH.relative_to(ROOT))
    assert step1["resource"]["exact_version"] == SEAL_REFERENCE
    assert git_blob_sha(SEAL_PATH) == SEAL_BLOB
    assert step1["required_evidence"] == [
        {
            "evidence_type": "data.initial-migration.applied",
            "source_step_id": None,
            "binding_state": "BOUND",
            "exact_digest": STEP4_EVIDENCE_DIGEST,
        }
    ]
    assert "search-path.repair" in step1["prohibited_actions"]

    seal_binding = next(
        item
        for item in step1["binding_declarations"]
        if item["binding_id"] == "binding.development.data.v3.seal-git-blob"
    )
    assert seal_binding["preapproval_value"] == {
        "value": SEAL_REFERENCE,
        "exact_digest": SEAL_REFERENCE_DIGEST,
    }
    assert canonical_digest(SEAL_REFERENCE) == SEAL_REFERENCE_DIGEST

    migration_state = next(
        item
        for item in step1["binding_declarations"]
        if item["binding_id"] == "binding.development.data.v3.v2-initial-migration-state"
    )
    assert migration_state["preapproval_value"] == {
        "value": INITIAL_MIGRATION_STATE_DIGEST,
        "exact_digest": INITIAL_MIGRATION_PREAPPROVAL_DIGEST,
    }
    assert canonical_digest(INITIAL_MIGRATION_STATE_DIGEST) == INITIAL_MIGRATION_PREAPPROVAL_DIGEST

    assert step2["step_id"] == STEP2
    assert step2["execution_class"] == "PROVIDER_READ"
    assert step2["dependency_step_ids"] == [STEP1]
    assert "provider.mutation" in step2["prohibited_actions"]
    assert "search-path.repair" in step2["prohibited_actions"]
    assert "security-advisor.finding" in step2["stop_conditions"]

    assert raw_digest(STEP4_EVIDENCE_PATH) == STEP4_EVIDENCE_DIGEST
    assert step4_evidence["outcome"] == "SUCCEEDED_VERIFIED"
    assert step4_evidence["project_reference"] == "gnuqaefotwgkwurjpyik"
    assert step4_evidence["verification_observation"]["security_advisor_finding_codes"] == [
        "function_search_path_mutable"
    ]
    assert step4_evidence["verification_observation"]["security_advisor_deferred_to_step6"] is True

    assert v2_plan["plan_version"] == 2
    assert v2_approval["expires_at"] == V2_EXPIRES_AT
    assert utc(V2_EXPIRES_AT) < utc(CREATED_AT)
    assert v2_execution["progress_digest"] == "sha256:68896643359b0ff274b9203651fff1f950f0b096ddb03b16e5737c6cf1f7013d"
    assert v2_execution["step_states"][3]["authorization_state"] == "CONSUMED"
    assert v2_execution["step_states"][3]["execution_state"] == "SUCCEEDED"
    assert v2_execution["step_states"][3]["verification_state"] == "PASS"
    for state in v2_execution["step_states"][4:]:
        assert state["authorization_state"] == "PENDING"
        assert state["execution_state"] == "NOT_STARTED"
        assert state["verification_state"] == "NOT_STARTED"
        assert state["authorization_consumed"] is False

    assert approval["approval_digest"] == APPROVAL_DIGEST
    assert approval["authority_scope"] == "EXACT_PLAN_ONLY"
    assert approval["effective_at"] == WINDOW_START
    assert approval["expires_at"] == WINDOW_END

    expected_progress = initial_progress(plan, SCHEMA_ROOT, PROGRESS_ID, CREATED_AT)
    assert progress == expected_progress
    assert progress["progress_digest"] == INITIAL_PROGRESS_DIGEST
    assert progress["overall_state"] == "NOT_STARTED"
    assert all(
        state["authorization_state"] == "PENDING"
        and state["execution_state"] == "NOT_STARTED"
        and state["verification_state"] == "NOT_STARTED"
        and state["authorization_consumed"] is False
        for state in progress["step_states"]
    )

    print("DEVELOPMENT DATA v3 continuation validation: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
