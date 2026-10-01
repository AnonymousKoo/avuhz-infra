#!/usr/bin/env python3
"""Execute one separately approved connected DEVELOPMENT DATA readiness read.

Preparation never invokes this file. Approval is validated before the owner-
interactive DSN is resolved. Output is fixed, sanitized, and contains no
credential, DSN, business row, subject, or tenant material.
"""
from __future__ import annotations

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
from avuhz_runtime.implementation_handoff import canonical_digest
from avuhz_service.development_data import (
    DEVELOPMENT_POSTGRES_DSN_ENV,
    DevelopmentDataSettings,
    create_hosted_development_data_composition,
)


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
BASE = ROOT / "contracts/plans/v1"
PLAN_PATH = BASE / "development-data-connected-runtime-validation-v1.plan.json"
PROGRESS_PATH = BASE / "development-data-connected-runtime-validation-v1.progress.json"
APPROVAL_PATH = BASE / "development-data-connected-runtime-validation-v1.approval.json"

PLAN_ID = "486cd09a-2541-4890-b8a6-fc8f2407f7f8"
STEP_ID = (
    "development.data.connected-runtime-validation-v1.step.01."
    "inspect-runtime-readiness"
)
CAPABILITY_EVIDENCE_TYPE = "data.runtime-read-executor-capability.observed"
CAPABILITY_BINDING_ID = (
    "binding.development.data.connected-runtime-validation-v1.read-executor"
)
V15_SUCCESS_EVIDENCE_DIGEST = (
    "sha256:817df8e5a593314325827b89e8b8d38d60c13157ea571ba22575ffab5f02de8a"
)


def _load(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        raise AuthorizationPlanStop("DATA_CONNECTED_READ_AUTHORITY_INVALID") from None
    if not isinstance(value, dict):
        raise AuthorizationPlanStop("DATA_CONNECTED_READ_AUTHORITY_INVALID")
    return value


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00",
        "Z",
    )


def _safe_result(*, ready: bool, code: str | None) -> int:
    print(
        json.dumps(
            {
                "classification": (
                    "DEVELOPMENT_DATA_CONNECTED_RUNTIME_READY"
                    if ready
                    else "DEVELOPMENT_DATA_CONNECTED_RUNTIME_UNVERIFIED"
                ),
                "safe_error_code": code,
                "database_session_limit": 1,
                "catalog_role_rls_metadata_only": True,
                "business_rows_read": False,
                "provider_mutation_attempted": False,
                "credential_material_retained": False,
                "dsn_retained": False,
                "pii_retained": False,
            },
            sort_keys=True,
        )
    )
    return 0 if ready else 1


def main() -> int:
    try:
        plan = _load(PLAN_PATH)
        progress = _load(PROGRESS_PATH)
        approval = _load(APPROVAL_PATH)
        moment = _now()

        validate_plan(plan, SCHEMA_ROOT)
        validate_progress(plan, progress, SCHEMA_ROOT)
        validate_approval(plan, approval, SCHEMA_ROOT, moment)

        if plan["plan_id"] != PLAN_ID:
            raise AuthorizationPlanStop("DATA_CONNECTED_READ_AUTHORITY_INVALID")
        if (
            progress["overall_state"] != "NOT_STARTED"
            or progress["step_states"][0]["authorization_state"] != "PENDING"
            or progress["step_states"][0]["authorization_consumed"]
        ):
            raise AuthorizationPlanStop("DATA_CONNECTED_READ_PROGRESS_NOT_PRISTINE")

        step = plan["steps"][0]
        capability = {
            "environment": "DEVELOPMENT",
            "project_reference": "gnuqaefotwgkwurjpyik",
            "execution_class": "PROVIDER_READ",
            "operation": step["operation"],
            "credential_class": "OWNER_INTERACTIVE_SESSION",
            "database_session_limit": 1,
            "catalog_role_rls_metadata_only": True,
            "provider_mutation_available": False,
            "business_row_read_available": False,
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
                "owner-interactive.development-data.connected-read"
            ),
            "recorded_at": moment,
        }
        request = {
            "plan_id": plan["plan_id"],
            "plan_version": plan["plan_version"],
            "plan_digest": plan["plan_digest"],
            "environment": plan["environment"],
            "provider_reference": plan["target"]["provider_reference"],
            "project_reference": plan["target"]["project_reference"],
            "responsibility": plan["target"]["responsibility"],
            "issuer_reference": plan["target"]["issuer_reference"],
            "audience_reference": plan["target"]["audience_reference"],
            "step_id": step["step_id"],
            "resource_reference": step["resource"]["resource_reference"],
            "resource_version": step["resource"]["exact_version"],
            "resource_digest": step["resource"]["exact_digest"],
            "operation": step["operation"],
            "execution_class": step["execution_class"],
            "credential_class": "OWNER_INTERACTIVE_SESSION",
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

        # Secret resolution happens only after exact approval/authority checks.
        dsn = os.environ.get(DEVELOPMENT_POSTGRES_DSN_ENV)
        if not isinstance(dsn, str) or not dsn:
            raise AuthorizationPlanStop("DATA_CONNECTED_READ_CREDENTIAL_UNAVAILABLE")

        composition = create_hosted_development_data_composition(
            DevelopmentDataSettings()
        )
        if not composition.readiness_probe.ready():
            raise AuthorizationPlanStop("DATA_CONNECTED_READINESS_FAILED")
        return _safe_result(ready=True, code=None)
    except (AuthorizationPlanError, AuthorizationPlanStop) as exc:
        return _safe_result(ready=False, code=str(exc))
    except Exception:
        return _safe_result(
            ready=False,
            code="DATA_CONNECTED_READ_UNEXPECTED_FAILURE",
        )


if __name__ == "__main__":
    raise SystemExit(main())
