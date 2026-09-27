#!/usr/bin/env python3
"""Validate the bounded recovery-verification sanitized-shape authorization rule."""
from __future__ import annotations

import copy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.authorization_plan import AuthorizationPlanError, plan_digest, validate_plan

SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
OPERATION = "provider.auth-recovery-verification.inspect-sanitized-shape-once"
EVIDENCE = "auth.recovery-verification.sanitized-shape.observed"
DIGEST_A = "sha256:" + "a" * 64
HANDLING = {
    "material_source": "APPROVED_ENVIRONMENT_SECRET_BOUNDARY",
    "material_residency": "SERVER_EXECUTOR_MEMORY_ONLY",
    "control_plane_visibility": "CLASS_LABEL_ONLY",
    "material_digest": "PROHIBITED",
    "persistence": "PROHIBITED",
    "logging": "PROHIBITED",
    "return_policy": "PROHIBITED",
    "proof_policy": "NON_SECRET_EXECUTOR_CAPABILITY_ATTESTATION",
}
ADMIN_PROHIBITIONS = {
    "credential.persist", "credential.expose", "credential.log", "credential.return",
    "credential.digest", "credential.copy", "credential.create", "credential.rotate",
    "credential.export",
}
DIAGNOSTIC_PROHIBITIONS = {
    "session.cleanup", "global-logout.execute", "provider.retry",
    "raw-provider-payload.persist", "token.persist", "pii.return",
}


def diagnostic_plan() -> dict:
    prohibited = sorted(ADMIN_PROHIBITIONS | DIAGNOSTIC_PROHIBITIONS | {"scope.widen"})
    step = {
        "step_id": "diagnostic.step.01",
        "ordinal": 1,
        "resource": {
            "resource_type": "auth.recovery-verification-shape",
            "resource_reference": "supabase:project.fictional.auth-development:recovery-verification-shape",
            "binding_state": "BOUND",
            "exact_version": "diagnostic.v1",
            "exact_digest": DIGEST_A,
        },
        "operation": OPERATION,
        "dependency_step_ids": [],
        "required_evidence": [{
            "evidence_type": "auth.prerequisite.verified",
            "source_step_id": None,
            "binding_state": "BOUND",
            "exact_digest": DIGEST_A,
        }],
        "expected_postcondition": "sanitized recovery verification response shape observed once",
        "prohibited_actions": prohibited,
        "stop_conditions": ["target.mismatch", "outcome.ambiguous"],
        "correction_reference": "correction.stop-for-owner-review-no-retry",
        "execution_class": "PROVIDER_MUTATION",
        "credential_policy": {
            "permitted": True,
            "allowed_classes": ["SUPABASE_AUTH_ADMIN_EPHEMERAL"],
            "values_stored": False,
            "ephemeral_handling": copy.deepcopy(HANDLING),
        },
        "binding_declarations": [{
            "binding_id": "binding.diagnostic.admin-executor-capability",
            "phase": "RESOLVED_BY_STEP_PREFLIGHT",
            "value_class": "CONFIGURATION_REFERENCE",
            "source_step_id": None,
            "evidence_type": "auth.admin-executor-capability.observed",
            "digest_policy": "REQUIRED",
            "persistence_policy": "DIGEST_ONLY",
        }],
        "produced_evidence": [{
            "evidence_type": EVIDENCE,
            "digest_policy": "REQUIRED",
            "established_binding_ids": [],
        }],
        "unresolved_bindings": [],
    }
    value = {
        "plan_id": "a7210000-0000-4000-8000-000000000101",
        "plan_version": 1,
        "plan_digest": DIGEST_A,
        "definition_status": "READY_FOR_APPROVAL",
        "environment": "DEVELOPMENT",
        "target": {
            "provider_class": "identity.provider",
            "provider_reference": "supabase",
            "project_reference": "project.fictional.auth-development",
            "responsibility": "AUTH",
            "issuer_reference": "https://auth.example.invalid/issuer",
            "audience_reference": "audience.fictional.command-service",
        },
        "owner_identity": "owner.fictional",
        "created_at": "2030-01-15T14:00:00Z",
        "authorization_window": {
            "binding_state": "BOUND",
            "starts_at": "2030-01-15T15:00:00Z",
            "expires_at": "2030-01-15T16:00:00Z",
        },
        "ordered_step_ids": [step["step_id"]],
        "steps": [step],
        "prohibited_actions": prohibited,
        "stop_conditions": ["scope.drift", "target.drift", "outcome.ambiguous"],
        "authority_effect": "NONE_UNTIL_SEPARATELY_APPROVED",
    }
    value["plan_digest"] = plan_digest(value)
    return value


def must_fail(value: dict) -> None:
    value["plan_digest"] = plan_digest(value)
    try:
        validate_plan(value, SCHEMA_ROOT)
    except AuthorizationPlanError as exc:
        assert str(exc) == "SCHEMA_INVALID", str(exc)
    else:
        raise AssertionError("diagnostic authorization drift must fail closed")


def main() -> int:
    validate_plan(diagnostic_plan(), SCHEMA_ROOT)

    for action in DIAGNOSTIC_PROHIBITIONS:
        bad = diagnostic_plan()
        bad["steps"][0]["prohibited_actions"].remove(action)
        must_fail(bad)

    bad = diagnostic_plan()
    bad["environment"] = "STAGING"
    must_fail(bad)

    bad = diagnostic_plan()
    bad["target"]["responsibility"] = "DATA"
    must_fail(bad)

    bad = diagnostic_plan()
    bad["steps"][0]["credential_policy"]["allowed_classes"] = ["OWNER_INTERACTIVE_SESSION"]
    del bad["steps"][0]["credential_policy"]["ephemeral_handling"]
    must_fail(bad)

    bad = diagnostic_plan()
    bad["steps"][0]["produced_evidence"][0]["evidence_type"] = "auth.raw-provider-payload.observed"
    must_fail(bad)

    bad = diagnostic_plan()
    bad["steps"][0]["produced_evidence"].append(
        copy.deepcopy(bad["steps"][0]["produced_evidence"][0])
    )
    must_fail(bad)

    print("RECOVERY_VERIFICATION_SHAPE_AUTHORIZATION_RULE=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
