#!/usr/bin/env python3
"""Validate the bounded recovery-verification sanitized-shape authorization rule."""
from __future__ import annotations

import copy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.authorization_plan import AuthorizationPlanError, plan_digest, validate_plan
from tests.contracts.validate_supabase_auth_admin_credential_model import plan as admin_plan

SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
OPERATION = "provider.auth-recovery-verification.inspect-sanitized-shape-once"
EVIDENCE = "auth.recovery-verification.sanitized-shape.observed"
DIGEST_A = "sha256:" + "a" * 64\nHANDLING = {\n    "material_source": "APPROVED_ENVIRONMENT_SECRET_BOUNDARY",\n    "material_residency": "SERVER_EXECUTOR_MEMORY_ONLY",\n    "control_plane_visibility": "CLASS_LABEL_ONLY",\n    "material_digest": "PROHIBITED",\n    "persistence": "PROHIBITED",\n    "logging": "PROHIBITED",\n    "return_policy": "PROHIBITED",\n    "proof_policy": "NON_SECRET_EXECUTOR_CAPABILITY_ATTESTATION",\n}\nADMIN_PROHIBITIONS = {\n    "credential.persist", "credential.expose", "credential.log", "credential.return",\n    "credential.digest", "credential.copy", "credential.create", "credential.rotate",\n    "credential.export",\n}\nREQUIRED = {
    "session.cleanup",
    "global-logout.execute",
    "provider.retry",
    "raw-provider-payload.persist",
    "token.persist",
    "pii.return",
}


def diagnostic_plan() -> dict:
    value = admin_plan()
    step = value["steps"][0]
    step["operation"] = OPERATION
    step["expected_postcondition"] = "sanitized recovery verification response shape observed once"
    step["prohibited_actions"] = sorted(set(step["prohibited_actions"]) | REQUIRED)
    step["produced_evidence"] = [{
        "evidence_type": EVIDENCE,
        "digest_policy": "REQUIRED",
        "persistence_policy": "DIGEST_ONLY",
    }]
    value["prohibited_actions"] = sorted(set(value["prohibited_actions"]) | REQUIRED)
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
    value = diagnostic_plan()
    validate_plan(value, SCHEMA_ROOT)

    for action in REQUIRED:
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
    bad["steps"][0]["produced_evidence"].append(copy.deepcopy(bad["steps"][0]["produced_evidence"][0]))
    must_fail(bad)

    print("RECOVERY_VERIFICATION_SHAPE_AUTHORIZATION_RULE=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
