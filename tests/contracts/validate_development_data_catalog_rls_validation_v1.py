#!/usr/bin/env python3
"""Validate the pristine DEVELOPMENT DATA catalog/RLS validation v1 package."""
from __future__ import annotations

import hashlib
import json
import subprocess
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
from avuhz_engineering.development_data_catalog_rls_validation import (  # noqa: E402
    DATA_CATALOG_VALIDATION_CONTRACT,
    DATA_CATALOG_VALIDATION_OPERATION,
    DATA_RUNTIME_READ_CREDENTIAL_CLASS,
    EXPECTED_CATALOG_DIGEST,
)
from avuhz_runtime.implementation_handoff import canonical_digest  # noqa: E402


SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
BASE = ROOT / "contracts/plans/v1"
PLAN_PATH = BASE / "development-data-catalog-rls-validation-v1.plan.json"
PROGRESS_PATH = BASE / "development-data-catalog-rls-validation-v1.progress.json"
APPROVAL_PATH = BASE / "development-data-catalog-rls-validation-v1.approval.json"
EVIDENCE_PATH = BASE / "development-data-catalog-rls-validation-v1-step1-success.evidence.json"
EXECUTION_PROGRESS_PATH = BASE / "development-data-catalog-rls-validation-v1.execution-progress.json"
EXECUTOR_PATH = ROOT / "scripts/development_data_catalog_rls_validation_v1.py"
HELPER_PATH = (
    ROOT / "src/avuhz_engineering/development_data_catalog_rls_validation.py"
)
BASELINE_PATH = ROOT / "scripts/check-baseline.sh"

PLAN_ID = "a4e15530-b16a-4d45-9bc1-00c4d54a7271"
PROGRESS_ID = "d35c52af-28c7-4f2a-9687-4ed7a173e1d4"
STEP_ID = "development.data.catalog-rls-validation-v1.step.01.inspect-read-only"
PLAN_DIGEST = "sha256:0713d866acdfb2ef3fe15e2eca46aeb4a4c8ef18eca528f1eb83f6cd868dca29"
PROGRESS_DIGEST = "sha256:90ebe6e250ebf7452078733d0fd0f4ae5e07d17702608eea4e3b4b417024962d"
APPROVAL_ID = "8220ef0c-0eef-4849-a413-4ed8bd5d1ae6"
APPROVAL_DIGEST = "sha256:6aaab135e7ddf18d2f28a2c9d8fa3ba752aa5232956b807f41dd4e9c278f123a"
APPROVED_AT = "2026-10-01T01:43:29Z"
EXECUTED_AT = "2026-10-01T02:14:48Z"
EVIDENCE_DIGEST = "sha256:b6db300972239326512e881d960659d29a8ad3d2ddb277029fb0b2edd46b7c76"
EXECUTION_PROGRESS_ID = "65f5d97a-951f-42b6-8617-f399137ccbc4"
EXECUTION_PROGRESS_DIGEST = "sha256:853f5cd3c6988c3e7dcccaf9b4272f7a60e7563cfb55e998ae2ab7ce01c56d45"
PROVIDER_OBSERVATION_DIGEST = "sha256:cab743a119b54eecba50632606a62de195c1748782c90a3459648e7368b787a4"
CAPABILITY_EVIDENCE_DIGEST = "sha256:3337fa57a3f499f727da3f369cc01a2c983a051ba2979d5ddb808fb6decdc186"
CAPABILITY_VALUE_DIGEST = "sha256:5b48c3148fb1c2b7063f338a4290981eff9debbf35fc95c6d9acae9d35402094"
EXECUTOR_BLOB = "5e1a29c95b9cab4695f52f752ca10e7a03070973"
HELPER_BLOB = "c47b36d3406e26a9d9ac66c8b943afa6a3c9ca81"
CONTRACT_DIGEST = "sha256:ac7555458c5d0f6c40f535b1c81166aaa03295801035a83443ea537a7ccc74cc"
V15_SUCCESS_EVIDENCE_DIGEST = (
    "sha256:817df8e5a593314325827b89e8b8d38d60c13157ea571ba22575ffab5f02de8a"
)

REQUIRED_PROHIBITIONS = {
    "provider.mutation",
    "business-row.read",
    "auth-data.read",
    "credential.persist",
    "credential.expose",
    "credential.log",
    "credential.return",
    "credential.digest",
    "credential.copy",
    "credential.create",
    "credential.rotate",
    "credential.export",
    "service-role.use",
    "migration-identity.use",
    "ddl.execute",
}


def load(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict), path
    return value


def raw_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def git_blob(path: Path) -> str:
    return subprocess.check_output(
        ["git", "rev-parse", f"HEAD:{path.relative_to(ROOT).as_posix()}"],
        cwd=ROOT,
        text=True,
    ).strip()


def binding(step: dict, binding_id: str) -> dict:
    values = [
        item
        for item in step["binding_declarations"]
        if item["binding_id"] == binding_id
    ]
    assert len(values) == 1, binding_id
    return values[0]


def main() -> int:
    plan = load(PLAN_PATH)
    progress = load(PROGRESS_PATH)
    approval = load(APPROVAL_PATH)
    evidence = load(EVIDENCE_PATH)
    execution = load(EXECUTION_PROGRESS_PATH)

    validate_plan(plan, SCHEMA_ROOT)
    validate_progress(plan, progress, SCHEMA_ROOT)
    validate_progress(plan, execution, SCHEMA_ROOT)
    validate_approval(
        plan,
        approval,
        SCHEMA_ROOT,
        plan["authorization_window"]["starts_at"],
    )

    assert plan["plan_id"] == PLAN_ID
    assert plan["plan_version"] == 1
    assert plan["plan_digest"] == PLAN_DIGEST == plan_digest(plan)
    assert plan["definition_status"] == "READY_FOR_APPROVAL"
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
        "starts_at": "2026-10-01T02:00:00Z",
        "expires_at": "2026-10-01T05:00:00Z",
    }
    assert plan["authority_effect"] == "NONE_UNTIL_SEPARATELY_APPROVED"
    assert plan["ordered_step_ids"] == [STEP_ID]
    assert REQUIRED_PROHIBITIONS <= set(plan["prohibited_actions"])

    assert len(plan["steps"]) == 1
    step = plan["steps"][0]
    assert step["step_id"] == STEP_ID
    assert step["operation"] == DATA_CATALOG_VALIDATION_OPERATION
    assert step["execution_class"] == "PROVIDER_READ"
    assert step["credential_policy"] == {
        "permitted": True,
        "allowed_classes": [DATA_RUNTIME_READ_CREDENTIAL_CLASS],
        "values_stored": False,
    }
    assert REQUIRED_PROHIBITIONS <= set(step["prohibited_actions"])
    assert step["resource"] == {
        "resource_type": "database.catalog-rls-validation-executor",
        "resource_reference": "scripts/development_data_catalog_rls_validation_v1.py",
        "binding_state": "BOUND",
        "exact_version": "gitblob." + EXECUTOR_BLOB,
        "exact_digest": CONTRACT_DIGEST,
    }
    assert step["required_evidence"] == [{
        "evidence_type": "data.runtime-login.created-and-verified",
        "source_step_id": None,
        "binding_state": "BOUND",
        "exact_digest": V15_SUCCESS_EVIDENCE_DIGEST,
    }]

    assert git_blob(EXECUTOR_PATH) == EXECUTOR_BLOB
    assert git_blob(HELPER_PATH) == HELPER_BLOB
    assert canonical_digest(DATA_CATALOG_VALIDATION_CONTRACT) == CONTRACT_DIGEST
    assert (
        DATA_CATALOG_VALIDATION_CONTRACT["expected_catalog_digest"]
        == EXPECTED_CATALOG_DIGEST
    )

    executor_binding = binding(
        step,
        "binding.development.data.catalog-rls-validation-v1.executor-git-blob",
    )
    helper_binding = binding(
        step,
        "binding.development.data.catalog-rls-validation-v1.helper-git-blob",
    )
    contract_binding = binding(
        step,
        "binding.development.data.catalog-rls-validation-v1.validation-contract",
    )
    prior_binding = binding(
        step,
        "binding.development.data.catalog-rls-validation-v1.v15-runtime-login-success",
    )
    capability_binding = binding(
        step,
        "binding.development.data.catalog-rls-validation-v1.runtime-read-capability",
    )
    result_binding = binding(
        step,
        "binding.development.data.catalog-rls-validation-v1.result",
    )
    assert executor_binding["preapproval_value"]["value"] == "gitblob." + EXECUTOR_BLOB
    assert helper_binding["preapproval_value"]["value"] == "gitblob." + HELPER_BLOB
    assert contract_binding["preapproval_value"]["value"] == CONTRACT_DIGEST
    assert prior_binding["preapproval_value"]["value"] == V15_SUCCESS_EVIDENCE_DIGEST
    assert capability_binding["phase"] == "RESOLVED_BY_STEP_PREFLIGHT"
    assert capability_binding["value_class"] == "CONFIGURATION_REFERENCE"
    assert capability_binding["evidence_type"] == (
        "data.runtime-read-executor-capability.observed"
    )
    assert capability_binding["persistence_policy"] == "DIGEST_ONLY"
    assert result_binding["phase"] == "PRODUCED_BY_CURRENT_STEP"
    assert result_binding["evidence_type"] == "data.catalog-rls.validated"
    assert step["produced_evidence"] == [{
        "evidence_type": "data.catalog-rls.validated",
        "established_binding_ids": [
            "binding.development.data.catalog-rls-validation-v1.result"
        ],
        "digest_policy": "REQUIRED",
    }]

    assert progress == initial_progress(
        plan,
        SCHEMA_ROOT,
        PROGRESS_ID,
        plan["created_at"],
    )
    assert progress["progress_digest"] == PROGRESS_DIGEST
    assert progress["overall_state"] == "NOT_STARTED"
    state = progress["step_states"][0]
    assert (
        state["authorization_state"],
        state["execution_state"],
        state["verification_state"],
        state["authorization_consumed"],
    ) == ("PENDING", "NOT_STARTED", "NOT_STARTED", False)
    assert state["evidence"] == []
    assert state["binding_assertions"] == []
    assert approval == {
        "approval_id": APPROVAL_ID,
        "plan_id": PLAN_ID,
        "plan_version": 1,
        "plan_digest": PLAN_DIGEST,
        "owner_identity": "github:AnonymousKoo",
        "decision": "APPROVE",
        "environment": "DEVELOPMENT",
        "effective_at": "2026-10-01T02:00:00Z",
        "expires_at": "2026-10-01T05:00:00Z",
        "approved_at": APPROVED_AT,
        "status": "ACTIVE",
        "authority_scope": "EXACT_PLAN_ONLY",
        "approval_digest": APPROVAL_DIGEST,
    }
    assert approval["approval_digest"] == APPROVAL_DIGEST == approval_digest(approval)
    assert raw_digest(EVIDENCE_PATH) == EVIDENCE_DIGEST
    assert evidence["evidence_type"] == "data.catalog-rls.validated"
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
    assert evidence["recorded_at"] == EXECUTED_AT

    observed = evidence["provider_observation"]
    assert observed["validation_classification"] == "DATA_CATALOG_RLS_VALIDATED"
    assert observed["catalog_digest"] == EXPECTED_CATALOG_DIGEST
    assert observed["expected_catalog_digest"] == EXPECTED_CATALOG_DIGEST
    assert observed["validation_contract_digest"] == CONTRACT_DIGEST
    assert canonical_digest(observed) == PROVIDER_OBSERVATION_DIGEST
    assert observed["table_count"] == 16
    assert observed["column_count"] == 306
    assert observed["constraint_count"] == 266
    assert observed["policy_count"] == 16
    assert observed["table_grant_count"] == 31
    assert observed["column_grant_count"] == 638
    assert observed["schema_usage"] is True
    assert observed["schema_create"] is False
    assert observed["transaction_read_only"] is True
    assert observed["connection_count"] == 1
    assert observed["connection_attempted"] is True
    assert observed["rollback_attempted"] is True

    security = evidence["security_state"]
    for key in (
        "business_rows_read",
        "auth_data_read",
        "credential_material_retained",
        "raw_catalog_metadata_retained",
        "provider_mutation_attempted",
        "ddl_attempted",
        "render_touched",
        "n8n_touched",
        "staging_touched",
        "production_touched",
    ):
        assert security[key] is False, key

    assert execution["progress_id"] == EXECUTION_PROGRESS_ID
    assert execution["plan_id"] == PLAN_ID
    assert execution["plan_digest"] == PLAN_DIGEST
    assert execution["record_version"] == 3
    assert execution["overall_state"] == "COMPLETED"
    assert execution["updated_at"] == EXECUTED_AT
    assert execution["progress_digest"] == EXECUTION_PROGRESS_DIGEST
    completed = execution["step_states"][0]
    assert completed["step_id"] == STEP_ID
    assert completed["authorization_state"] == "CONSUMED"
    assert completed["authorization_consumed"] is True
    assert completed["execution_state"] == "SUCCEEDED"
    assert completed["verification_state"] == "PASS"
    assert completed["safe_error_code"] is None
    assert completed["observed_postcondition"] == step["expected_postcondition"]
    assert completed["evidence"] == [{
        "evidence_type": "data.catalog-rls.validated",
        "evidence_reference": "provider.execution.data-catalog-rls-v1.step1.attempt1.verified",
        "evidence_digest": EVIDENCE_DIGEST,
        "recorded_at": EXECUTED_AT,
    }]
    assert len(completed["binding_assertions"]) == 2
    capability, result = completed["binding_assertions"]
    assert capability["binding_id"] == capability_binding["binding_id"]
    assert capability["evidence_digest"] == CAPABILITY_EVIDENCE_DIGEST
    assert capability["value_digest"] == CAPABILITY_VALUE_DIGEST
    assert capability["sanitized_value"] is None
    assert capability["recorded_at"] == EXECUTED_AT
    assert result["binding_id"] == result_binding["binding_id"]
    assert result["evidence_digest"] == EVIDENCE_DIGEST
    assert result["value_digest"] == PROVIDER_OBSERVATION_DIGEST
    assert result["sanitized_value"] is None
    assert result["recorded_at"] == EXECUTED_AT

    executor = EXECUTOR_PATH.read_text(encoding="utf-8")
    main_source = executor[executor.index("def main() -> int:") :]
    approval_index = main_source.index("validate_approval(")
    credential_index = main_source.index(
        "os.environ.get(DATA_RUNTIME_DSN_ENV_REFERENCE)"
    )
    authorize_index = main_source.index("authorize_step(")
    connection_index = main_source.index("inspect_development_data_catalog(")
    assert approval_index < credential_index < authorize_index < connection_index
    assert main_source.count("inspect_development_data_catalog(") == 1
    assert main_source.count("connection_factory_from_environment(") == 1
    assert "service_role" not in executor
    assert "migration-identity.use" not in executor

    baseline = BASELINE_PATH.read_text(encoding="utf-8")
    assert "validate_development_data_catalog_rls_validation_v1.py" in baseline
    assert "forbidden credential-shaped content" in baseline
    assert "Semgrep local secret rules" in baseline

    print(
        "DEVELOPMENT DATA catalog/RLS validation v1 completion: PASS "
        "(read-only provider validation verified; 16-table/RLS fingerprint matched; "
        "authority consumed; no business-row/AUTH read or mutation)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
