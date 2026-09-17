#!/usr/bin/env python3
"""Execute the separately approved v32 read-only session inspection.

Preparation does not invoke this file. It contains no cleanup or provider
mutation path and never renders provider rows, subject identifiers, or the
provider-read credential.
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
from avuhz_engineering.development_auth_session_inspection import (
    PROVIDER_READ_CREDENTIAL_CLASS,
    PROVIDER_READ_ENV_REFERENCE,
    InspectionClassification,
    SafeInspectionStop,
    inspect_development_auth_session_state,
    sanitized_inspection_evidence,
)
from avuhz_runtime.implementation_handoff import canonical_digest
from avuhz_service.development_supabase_identity import (
    DEVELOPMENT_SYNTHETIC_READ_ONLY_ALLOWLIST,
)


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
PLAN_PATH = ROOT / "contracts/plans/v1/development-auth-v32-session-inspection-v1.plan.json"
PROGRESS_PATH = ROOT / "contracts/plans/v1/development-auth-v32-session-inspection-v1.progress.json"
APPROVAL_PATH = ROOT / "contracts/plans/v1/development-auth-v32-session-inspection-v1.approval.json"

PLAN_ID = "8a1300d3-4bfb-461c-90c4-a22a53a11647"
PLAN_DIGEST = "sha256:c397fc40fe5622047ab38d435ebad57f119a2b7882103ef0d175e39ee0d5bdf1"
STEP_ID = "development.auth.v32-session-inspection-v1.step.01.inspect-session-state-read-only"
V32_FAILURE_EVIDENCE_DIGEST = (
    "sha256:45cddb8d3c0753f4b48e323e7983843f918b194f811b511848bd26f7908c6dc5"
)
CAPABILITY_EVIDENCE_TYPE = "provider.read-executor-capability.observed"
CAPABILITY_BINDING_ID = (
    "binding.development.auth.v32-session-inspection-v1.provider-read-executor"
)


def _load(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        raise AuthorizationPlanStop("SESSION_INSPECTION_AUTHORITY_INVALID") from None
    if not isinstance(value, dict):
        raise AuthorizationPlanStop("SESSION_INSPECTION_AUTHORITY_INVALID")
    return value


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _safe_failure(code: str) -> int:
    print(
        json.dumps(
            {
                "inspection_classification": "SESSION_STATE_UNVERIFIED",
                "safe_error_code": code,
                "provider_mutation_attempted": False,
                "credential_material_retained": False,
                "pii_retained": False,
            },
            sort_keys=True,
        )
    )
    return 1


def main() -> int:
    try:
        plan = _load(PLAN_PATH)
        progress = _load(PROGRESS_PATH)
        approval = _load(APPROVAL_PATH)
        moment = _now()
        validate_plan(plan, SCHEMA_ROOT)
        validate_progress(plan, progress, SCHEMA_ROOT)
        validate_approval(plan, approval, SCHEMA_ROOT, moment)
        if plan["plan_id"] != PLAN_ID or plan["plan_digest"] != PLAN_DIGEST:
            raise AuthorizationPlanStop("SESSION_INSPECTION_AUTHORITY_INVALID")
        if (
            progress["overall_state"] != "NOT_STARTED"
            or progress["step_states"][0]["authorization_state"] != "PENDING"
        ):
            raise AuthorizationPlanStop("SESSION_INSPECTION_PROGRESS_NOT_PRISTINE")

        # Resolve the existing secret only after exact approval validation. Its
        # value is never copied into authority, evidence, error, or output data.
        read_token = os.environ.get(PROVIDER_READ_ENV_REFERENCE)
        if not isinstance(read_token, str) or not read_token:
            raise AuthorizationPlanStop("SESSION_INSPECTION_CREDENTIAL_UNAVAILABLE")

        capability = {
            "environment": "DEVELOPMENT",
            "project_reference": "pwlhruwutoitnieactol",
            "execution_class": "PROVIDER_READ",
            "operation": "provider.auth-session-state.inspect-read-only",
            "credential_class": PROVIDER_READ_CREDENTIAL_CLASS,
            "credential_reference": PROVIDER_READ_ENV_REFERENCE,
            "provider_mutation_available": False,
        }
        capability_digest = canonical_digest(capability)
        capability_assertion = {
            "binding_id": CAPABILITY_BINDING_ID,
            "phase": "RESOLVED_BY_STEP_PREFLIGHT",
            "value_class": "CONFIGURATION_REFERENCE",
            "source_step_id": None,
            "evidence_type": CAPABILITY_EVIDENCE_TYPE,
            "evidence_digest": capability_digest,
            "digest_policy": "REQUIRED",
            "persistence_policy": "DIGEST_ONLY",
            "sanitized_value": None,
            "value_digest": canonical_digest("github.environment.development.provider-read"),
            "recorded_at": moment,
        }
        step = plan["steps"][0]
        request = {
            "plan_id": PLAN_ID,
            "plan_version": 1,
            "plan_digest": PLAN_DIGEST,
            "environment": "DEVELOPMENT",
            "provider_reference": "supabase",
            "project_reference": "pwlhruwutoitnieactol",
            "responsibility": "AUTH",
            "issuer_reference": "https://pwlhruwutoitnieactol.supabase.co/auth/v1",
            "audience_reference": "audience.avuhz.command-service.development",
            "step_id": STEP_ID,
            "resource_reference": step["resource"]["resource_reference"],
            "resource_version": step["resource"]["exact_version"],
            "resource_digest": step["resource"]["exact_digest"],
            "operation": "provider.auth-session-state.inspect-read-only",
            "execution_class": "PROVIDER_READ",
            "credential_class": PROVIDER_READ_CREDENTIAL_CLASS,
            "required_evidence": [
                {
                    "evidence_type": "auth.synthetic-session.lifecycle-completed",
                    "evidence_digest": V32_FAILURE_EVIDENCE_DIGEST,
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

        expected_digest = DEVELOPMENT_SYNTHETIC_READ_ONLY_ALLOWLIST[0].subject_digest
        result = inspect_development_auth_session_state(
            read_token=read_token,
            expected_subject_digest=expected_digest,
        )
        evidence = sanitized_inspection_evidence(
            result,
            plan_id=PLAN_ID,
            plan_digest=PLAN_DIGEST,
        )
        print(json.dumps(evidence, sort_keys=True))
        if result.classification is InspectionClassification.IDENTITY_BINDING_MISMATCH:
            return 1
        return 0
    except (AuthorizationPlanError, AuthorizationPlanStop) as exc:
        return _safe_failure(str(exc))
    except SafeInspectionStop as exc:
        return _safe_failure(exc.code)
    except Exception:
        return _safe_failure("SESSION_INSPECTION_UNEXPECTED_FAILURE")


if __name__ == "__main__":
    raise SystemExit(main())
