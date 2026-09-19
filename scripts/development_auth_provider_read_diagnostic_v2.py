#!/usr/bin/env python3
"""Execute the separately approved v2 one-GET provider-read diagnostic.

Preparation does not invoke this file. It contains no SQL, cleanup, token,
identity, or provider-mutation operation and renders only fixed classifications.
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
from avuhz_engineering.development_auth_provider_read_diagnostic import (
    PROVIDER_READ_CREDENTIAL_CLASS,
    PROVIDER_READ_ENV_REFERENCE,
    SafeProviderReadDiagnosticStop,
    inspect_development_auth_project_metadata,
    sanitized_project_read_evidence,
)
from avuhz_runtime.implementation_handoff import canonical_digest


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
PLAN_PATH = (
    ROOT
    / "contracts/plans/v1/development-auth-provider-read-diagnostic-v2.plan.json"
)
PROGRESS_PATH = (
    ROOT
    / "contracts/plans/v1/development-auth-provider-read-diagnostic-v2.progress.json"
)
APPROVAL_PATH = (
    ROOT
    / "contracts/plans/v1/development-auth-provider-read-diagnostic-v2.approval.json"
)

PLAN_ID = "b6d86aea-a009-4080-a82c-8ace44b91f45"
PLAN_DIGEST = "sha256:e461550ca90b8ffbb38c8f8be0b73e767c57ead19aec23e3a8b4eaeccc938bba"
STEP_ID = (
    "development.auth.provider-read-diagnostic-v2.step.01."
    "inspect-project-metadata-read-only"
)
PRIOR_FAILURE_EVIDENCE_DIGEST = (
    "sha256:ebf71894e7a6c774df7f4800bace81a23dfd898b27be96f505402ab326f272e5"
)
CAPABILITY_EVIDENCE_TYPE = "provider.read-executor-capability.observed"
CAPABILITY_BINDING_ID = (
    "binding.development.auth.provider-read-diagnostic-v2.provider-read-executor"
)


def _load(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        raise AuthorizationPlanStop("PROJECT_READ_AUTHORITY_INVALID") from None
    if not isinstance(value, dict):
        raise AuthorizationPlanStop("PROJECT_READ_AUTHORITY_INVALID")
    return value


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00",
        "Z",
    )


def _safe_failure(code: str) -> int:
    print(
        json.dumps(
            {
                "diagnostic_classification": "PROJECT_READ_UNVERIFIED",
                "safe_error_code": code,
                "provider_request_limit": 1,
                "sql_session_inspection_attempted": False,
                "provider_mutation_attempted": False,
                "credential_material_retained": False,
                "raw_provider_response_retained": False,
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
            raise AuthorizationPlanStop("PROJECT_READ_AUTHORITY_INVALID")
        if (
            progress["overall_state"] != "NOT_STARTED"
            or progress["step_states"][0]["authorization_state"] != "PENDING"
        ):
            raise AuthorizationPlanStop("PROJECT_READ_PROGRESS_NOT_PRISTINE")

        # The existing secret is resolved only after exact approval validation.
        # Its value never enters output, authority, evidence, or exception text.
        read_token = os.environ.get(PROVIDER_READ_ENV_REFERENCE)
        if not isinstance(read_token, str) or not read_token:
            raise AuthorizationPlanStop("PROJECT_READ_CREDENTIAL_UNAVAILABLE")

        capability = {
            "environment": "DEVELOPMENT",
            "project_reference": "pwlhruwutoitnieactol",
            "execution_class": "PROVIDER_READ",
            "operation": "provider.project-metadata.inspect-read-only",
            "credential_class": PROVIDER_READ_CREDENTIAL_CLASS,
            "credential_reference": PROVIDER_READ_ENV_REFERENCE,
            "provider_request_limit": 1,
            "provider_mutation_available": False,
            "sql_available": False,
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
                "github.environment.development.provider-read"
            ),
            "recorded_at": moment,
        }
        step = plan["steps"][0]
        request = {
            "plan_id": PLAN_ID,
            "plan_version": 2,
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
            "operation": "provider.project-metadata.inspect-read-only",
            "execution_class": "PROVIDER_READ",
            "credential_class": PROVIDER_READ_CREDENTIAL_CLASS,
            "required_evidence": [
                {
                    "evidence_type": "auth.session-state.inspected-read-only",
                    "evidence_digest": PRIOR_FAILURE_EVIDENCE_DIGEST,
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

        result = inspect_development_auth_project_metadata(
            read_token=read_token,
        )
        print(
            json.dumps(
                sanitized_project_read_evidence(
                    result,
                    plan_id=PLAN_ID,
                    plan_digest=PLAN_DIGEST,
                ),
                sort_keys=True,
            )
        )
        return 0
    except (AuthorizationPlanError, AuthorizationPlanStop) as exc:
        return _safe_failure(str(exc))
    except SafeProviderReadDiagnosticStop as exc:
        return _safe_failure(exc.code)
    except Exception:
        return _safe_failure("PROJECT_READ_UNEXPECTED_FAILURE")


if __name__ == "__main__":
    raise SystemExit(main())
