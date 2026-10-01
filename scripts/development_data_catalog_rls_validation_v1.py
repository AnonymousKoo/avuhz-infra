#!/usr/bin/env python3
"""Execute one separately approved DEVELOPMENT DATA catalog/RLS validation.

This file is dormant without an exact plan, pristine progress, active owner
approval, exact code bindings, and the runtime-only DEVELOPMENT DATA credential.
It performs no repair, DDL, business-row read, AUTH-data read, Render change, or
provider mutation and emits only bounded secret-free output.
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from avuhz_engineering.authorization_plan import (
    AuthorizationPlanError,
    AuthorizationPlanStop,
    authorize_step,
    validate_approval,
    validate_plan,
    validate_progress,
)
from avuhz_engineering.development_data_catalog_rls_validation import (
    DATA_CATALOG_VALIDATION_CONTRACT,
    DATA_CATALOG_VALIDATION_OPERATION,
    DATA_RUNTIME_DSN_ENV_REFERENCE,
    DATA_RUNTIME_READ_CREDENTIAL_CLASS,
    DEVELOPMENT_DATA_PROJECT_REF,
    EXPECTED_CATALOG_DIGEST,
    SafeDevelopmentDataValidationStop,
    inspect_development_data_catalog,
    sanitized_data_catalog_evidence,
)
from avuhz_runtime.implementation_handoff import canonical_digest
from avuhz_runtime.postgres import connection_factory_from_environment


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
PLAN_PATH = (
    ROOT
    / "contracts/plans/v1/development-data-catalog-rls-validation-v1.plan.json"
)
PROGRESS_PATH = (
    ROOT
    / "contracts/plans/v1/development-data-catalog-rls-validation-v1.progress.json"
)
APPROVAL_PATH = (
    ROOT
    / "contracts/plans/v1/development-data-catalog-rls-validation-v1.approval.json"
)
HELPER_PATH = (
    ROOT
    / "src/avuhz_engineering/development_data_catalog_rls_validation.py"
)

PLAN_ID = "a4e15530-b16a-4d45-9bc1-00c4d54a7271"
STEP_ID = "development.data.catalog-rls-validation-v1.step.01.inspect-read-only"
V15_SUCCESS_EVIDENCE_DIGEST = (
    "sha256:817df8e5a593314325827b89e8b8d38d60c13157ea571ba22575ffab5f02de8a"
)
EXECUTOR_BINDING_ID = (
    "binding.development.data.catalog-rls-validation-v1.executor-git-blob"
)
HELPER_BINDING_ID = (
    "binding.development.data.catalog-rls-validation-v1.helper-git-blob"
)
CAPABILITY_BINDING_ID = (
    "binding.development.data.catalog-rls-validation-v1.runtime-read-capability"
)
CAPABILITY_EVIDENCE_TYPE = "data.runtime-read-executor-capability.observed"


def _load(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        raise AuthorizationPlanStop("DATA_CATALOG_AUTHORITY_INVALID") from None
    if not isinstance(value, dict):
        raise AuthorizationPlanStop("DATA_CATALOG_AUTHORITY_INVALID")
    return value


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00",
        "Z",
    )


def _git_blob(path: Path) -> str:
    data = path.read_bytes()
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()


def _preapproval_binding(plan: dict, binding_id: str) -> str:
    try:
        binding = next(
            item
            for item in plan["steps"][0]["binding_declarations"]
            if item["binding_id"] == binding_id
        )
        if (
            binding["phase"] != "PREAPPROVAL_BOUND"
            or binding["value_class"] != "STABLE_REFERENCE"
            or binding["persistence_policy"] != "SANITIZED_VALUE_ALLOWED"
        ):
            raise KeyError
        value = binding["preapproval_value"]["value"]
    except Exception:
        raise AuthorizationPlanStop("DATA_CATALOG_CODE_BINDING_INVALID") from None
    if not isinstance(value, str):
        raise AuthorizationPlanStop("DATA_CATALOG_CODE_BINDING_INVALID")
    return value


def _verify_exact_authority_shape(plan: dict) -> None:
    if (
        plan.get("plan_id") != PLAN_ID
        or plan.get("environment") != "DEVELOPMENT"
        or plan.get("authority_effect") != "NONE_UNTIL_SEPARATELY_APPROVED"
        or plan.get("ordered_step_ids") != [STEP_ID]
    ):
        raise AuthorizationPlanStop("DATA_CATALOG_AUTHORITY_INVALID")
    target = plan.get("target", {})
    if target != {
        "provider_class": "data.provider",
        "provider_reference": "supabase",
        "project_reference": DEVELOPMENT_DATA_PROJECT_REF,
        "responsibility": "DATA",
        "issuer_reference": None,
        "audience_reference": None,
    }:
        raise AuthorizationPlanStop("DATA_CATALOG_TARGET_MISMATCH")
    step = plan["steps"][0]
    if (
        step.get("step_id") != STEP_ID
        or step.get("operation") != DATA_CATALOG_VALIDATION_OPERATION
        or step.get("execution_class") != "PROVIDER_READ"
        or step.get("credential_policy")
        != {
            "permitted": True,
            "allowed_classes": [DATA_RUNTIME_READ_CREDENTIAL_CLASS],
            "values_stored": False,
        }
        or step.get("resource", {}).get("resource_reference")
        != "scripts/development_data_catalog_rls_validation_v1.py"
        or step.get("resource", {}).get("exact_digest")
        != canonical_digest(DATA_CATALOG_VALIDATION_CONTRACT)
    ):
        raise AuthorizationPlanStop("DATA_CATALOG_AUTHORITY_INVALID")

    expected_executor = "gitblob." + _git_blob(Path(__file__).resolve())
    expected_helper = "gitblob." + _git_blob(HELPER_PATH)
    if (
        step["resource"].get("exact_version") != expected_executor
        or _preapproval_binding(plan, EXECUTOR_BINDING_ID) != expected_executor
        or _preapproval_binding(plan, HELPER_BINDING_ID) != expected_helper
    ):
        raise AuthorizationPlanStop("DATA_CATALOG_CODE_BINDING_MISMATCH")


def _safe_failure(
    code: str,
    *,
    connection_attempted: bool,
) -> int:
    print(
        json.dumps(
            {
                "validation_classification": "DATA_CATALOG_RLS_UNVERIFIED",
                "safe_error_code": code,
                "connection_limit": 1,
                "connection_attempted": connection_attempted,
                "business_rows_read": False,
                "auth_data_read": False,
                "provider_mutation_attempted": False,
                "ddl_attempted": False,
                "credential_material_retained": False,
                "raw_catalog_metadata_retained": False,
                "render_touched": False,
                "staging_touched": False,
                "production_touched": False,
            },
            sort_keys=True,
        )
    )
    return 1


def main() -> int:
    connection_attempts = 0
    try:
        plan = _load(PLAN_PATH)
        progress = _load(PROGRESS_PATH)
        approval = _load(APPROVAL_PATH)
        moment = _now()

        validate_plan(plan, SCHEMA_ROOT)
        validate_progress(plan, progress, SCHEMA_ROOT)
        validate_approval(plan, approval, SCHEMA_ROOT, moment)
        _verify_exact_authority_shape(plan)

        if (
            progress.get("overall_state") != "NOT_STARTED"
            or len(progress.get("step_states", [])) != 1
            or progress["step_states"][0].get("authorization_state") != "PENDING"
            or progress["step_states"][0].get("execution_state") != "NOT_STARTED"
            or progress["step_states"][0].get("verification_state") != "NOT_STARTED"
            or progress["step_states"][0].get("authorization_consumed") is not False
        ):
            raise AuthorizationPlanStop("DATA_CATALOG_PROGRESS_NOT_PRISTINE")

        # Check only the existence of the approved runtime secret reference after
        # exact owner approval validation. The value is never copied or rendered.
        if not os.environ.get(DATA_RUNTIME_DSN_ENV_REFERENCE):
            raise AuthorizationPlanStop("DATA_CATALOG_CREDENTIAL_UNAVAILABLE")

        capability = {
            **DATA_CATALOG_VALIDATION_CONTRACT,
            "executor_git_blob": "gitblob." + _git_blob(Path(__file__).resolve()),
            "helper_git_blob": "gitblob." + _git_blob(HELPER_PATH),
            "connection_limit": 1,
        }
        capability_assertion = {
            "binding_id": CAPABILITY_BINDING_ID,
            "phase": "RESOLVED_BY_STEP_PREFLIGHT",
            "value_class": "CONFIGURATION_REFERENCE",
            "source_step_id": None,
            "evidence_type": CAPABILITY_EVIDENCE_TYPE,
            "evidence_digest": canonical_digest(capability),
            "digest_policy": "REQUIRED",
            "persistence_policy": "DIGEST_ONLY",
            "sanitized_value": None,
            "value_digest": canonical_digest(
                "environment.development.AVUHZ_POSTGRES_DSN"
            ),
            "recorded_at": moment,
        }
        step = plan["steps"][0]
        request = {
            "plan_id": plan["plan_id"],
            "plan_version": plan["plan_version"],
            "plan_digest": plan["plan_digest"],
            "environment": "DEVELOPMENT",
            "provider_reference": "supabase",
            "project_reference": DEVELOPMENT_DATA_PROJECT_REF,
            "responsibility": "DATA",
            "issuer_reference": None,
            "audience_reference": None,
            "step_id": STEP_ID,
            "resource_reference": step["resource"]["resource_reference"],
            "resource_version": step["resource"]["exact_version"],
            "resource_digest": step["resource"]["exact_digest"],
            "operation": DATA_CATALOG_VALIDATION_OPERATION,
            "execution_class": "PROVIDER_READ",
            "credential_class": DATA_RUNTIME_READ_CREDENTIAL_CLASS,
            "required_evidence": [
                {
                    "evidence_type": "data.runtime-login.created-and-verified",
                    "evidence_digest": V15_SUCCESS_EVIDENCE_DIGEST,
                }
            ],
            "prior_evidence_digests": [],
            "unexpected_remote_state": False,
            "extra_privileges": False,
            "unauthorized_migration_surface": False,
            "scope_expansion": False,
        }
        authorize_step(
            plan,
            approval,
            progress,
            request,
            SCHEMA_ROOT,
            moment,
            trusted_preflight_assertions=[capability_assertion],
        )

        base_factory = connection_factory_from_environment(
            DATA_RUNTIME_DSN_ENV_REFERENCE
        )

        def one_connection():
            nonlocal connection_attempts
            connection_attempts += 1
            if connection_attempts != 1:
                raise RuntimeError("connection limit exceeded")
            return base_factory()

        result = inspect_development_data_catalog(
            connection_factory=one_connection,
        )
        evidence = sanitized_data_catalog_evidence(
            result,
            plan_id=plan["plan_id"],
            plan_digest=plan["plan_digest"],
            attempted_at=moment,
        )
        evidence["validation_contract_digest"] = canonical_digest(
            DATA_CATALOG_VALIDATION_CONTRACT
        )
        evidence["connection_attempted"] = connection_attempts == 1
        print(json.dumps(evidence, sort_keys=True))
        return 0
    except (AuthorizationPlanError, AuthorizationPlanStop) as exc:
        return _safe_failure(
            str(exc),
            connection_attempted=connection_attempts > 0,
        )
    except SafeDevelopmentDataValidationStop as exc:
        return _safe_failure(
            exc.code,
            connection_attempted=connection_attempts > 0,
        )
    except Exception:
        return _safe_failure(
            "DATA_CATALOG_UNEXPECTED_FAILURE",
            connection_attempted=connection_attempts > 0,
        )


if __name__ == "__main__":
    raise SystemExit(main())
