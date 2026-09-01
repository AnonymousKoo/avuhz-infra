"""Deterministic fictional tests for bounded provider-neutral authorization plans."""
from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.authorization_plan import (
    AuthorizationPlanError,
    AuthorizationPlanStop,
    approval_digest,
    authorize_step,
    initial_progress,
    plan_digest,
    record_step_outcome,
    validate_approval,
    validate_plan,
    validate_progress,
)


SCHEMAS = ROOT / "contracts/schemas/v1"
PLAN_ID = "a7100000-0000-4000-8000-000000000001"
APPROVAL_ID = "a7100000-0000-4000-8000-000000000002"
PROGRESS_ID = "a7100000-0000-4000-8000-000000000003"
DIGESTS = ["sha256:" + value * 64 for value in ("a", "b", "c", "d", "e", "f")]
T0 = "2030-01-15T15:01:00Z"


def step(step_id, ordinal, operation, execution_class, dependencies, evidence, resource_digest, credential):
    return {
        "step_id": step_id,
        "ordinal": ordinal,
        "resource": {
            "resource_type": "provider.resource",
            "resource_reference": f"resource.fictional.{ordinal}",
            "binding_state": "BOUND",
            "exact_version": f"version.{ordinal}",
            "exact_digest": resource_digest,
        },
        "operation": operation,
        "dependency_step_ids": dependencies,
        "required_evidence": evidence,
        "expected_postcondition": f"fictional postcondition {ordinal} verified",
        "prohibited_actions": ["scope.widen", "environment.change"],
        "stop_conditions": ["target.mismatch", "evidence.mismatch", "outcome.ambiguous"],
        "correction_reference": "correction.forward-only",
        "execution_class": execution_class,
        "credential_policy": {
            "permitted": credential != "NONE",
            "allowed_classes": [credential],
            "values_stored": False,
        },
        "unresolved_bindings": [],
    }


def bound_evidence(evidence_type, digest):
    return {
        "evidence_type": evidence_type,
        "source_step_id": None,
        "binding_state": "BOUND",
        "exact_digest": digest,
    }


def derived_evidence(evidence_type, source):
    return {
        "evidence_type": evidence_type,
        "source_step_id": source,
        "binding_state": "DERIVED_FROM_SOURCE_STEP",
        "exact_digest": None,
    }


def plan():
    steps = [
        step("plan.step.01", 1, "local.artifact.create", "LOCAL_ONLY", [],
             [bound_evidence("baseline.green", DIGESTS[0])], DIGESTS[1], "NONE"),
        step("plan.step.02", 2, "provider.resource.create", "PROVIDER_MUTATION", ["plan.step.01"],
             [derived_evidence("local.artifact", "plan.step.01")], DIGESTS[2], "MIGRATION_IDENTITY"),
        step("plan.step.03", 3, "provider.resource.verify", "PROVIDER_READ", ["plan.step.02"],
             [derived_evidence("resource.verification", "plan.step.02")], DIGESTS[2], "OWNER_INTERACTIVE_SESSION"),
    ]
    value = {
        "plan_id": PLAN_ID,
        "plan_version": 1,
        "plan_digest": DIGESTS[5],
        "definition_status": "READY_FOR_APPROVAL",
        "environment": "DEVELOPMENT",
        "target": {
            "provider_class": "provider.fictional",
            "provider_reference": "provider.fictional",
            "project_reference": "project.fictional.development",
            "responsibility": "AUTH",
            "issuer_reference": "https://auth.example.invalid/issuer",
            "audience_reference": "audience.fictional.service",
        },
        "owner_identity": "owner.fictional",
        "created_at": "2030-01-15T14:00:00Z",
        "authorization_window": {
            "binding_state": "BOUND",
            "starts_at": "2030-01-15T15:00:00Z",
            "expires_at": "2030-01-15T16:00:00Z",
        },
        "ordered_step_ids": [item["step_id"] for item in steps],
        "steps": steps,
        "prohibited_actions": [
            "batch.mutation", "data.operation", "production.target", "staging.target",
            "jwt.authority", "self.repair",
        ],
        "stop_conditions": [
            "scope.drift", "target.drift", "evidence.missing", "outcome.ambiguous",
            "authorization.expired",
        ],
        "authority_effect": "NONE_UNTIL_SEPARATELY_APPROVED",
    }
    value["plan_digest"] = plan_digest(value)
    return value


def approval(value):
    result = {
        "approval_id": APPROVAL_ID,
        "plan_id": value["plan_id"],
        "plan_version": value["plan_version"],
        "plan_digest": value["plan_digest"],
        "approval_digest": DIGESTS[5],
        "owner_identity": value["owner_identity"],
        "decision": "APPROVE",
        "environment": value["environment"],
        "effective_at": value["authorization_window"]["starts_at"],
        "expires_at": value["authorization_window"]["expires_at"],
        "approved_at": "2030-01-15T14:59:00Z",
        "status": "ACTIVE",
        "authority_scope": "EXACT_PLAN_ONLY",
    }
    result["approval_digest"] = approval_digest(result)
    return result


def request(value, step_index, progress, **changes):
    item = value["steps"][step_index]
    expected_evidence = []
    for requirement in item["required_evidence"]:
        if requirement["source_step_id"] is None:
            digest = requirement["exact_digest"]
        else:
            source = value["ordered_step_ids"].index(requirement["source_step_id"])
            match = [
                evidence for evidence in progress["step_states"][source]["evidence"]
                if evidence["evidence_type"] == requirement["evidence_type"]
            ]
            digest = match[0]["evidence_digest"] if match else "sha256:" + "0" * 64
        expected_evidence.append({"evidence_type": requirement["evidence_type"], "evidence_digest": digest})
    result = {
        "plan_id": value["plan_id"],
        "plan_version": value["plan_version"],
        "plan_digest": value["plan_digest"],
        "environment": value["environment"],
        "provider_reference": value["target"]["provider_reference"],
        "project_reference": value["target"]["project_reference"],
        "responsibility": value["target"]["responsibility"],
        "issuer_reference": value["target"]["issuer_reference"],
        "audience_reference": value["target"]["audience_reference"],
        "step_id": item["step_id"],
        "resource_reference": item["resource"]["resource_reference"],
        "resource_version": item["resource"]["exact_version"],
        "resource_digest": item["resource"]["exact_digest"],
        "operation": item["operation"],
        "execution_class": item["execution_class"],
        "credential_class": item["credential_policy"]["allowed_classes"][0],
        "required_evidence": expected_evidence,
        "prior_evidence_digests": [
            evidence["evidence_digest"]
            for state in progress["step_states"][:step_index]
            for evidence in state["evidence"]
        ],
        "unexpected_remote_state": False,
        "extra_privileges": False,
        "unauthorized_migration_surface": False,
        "scope_expansion": False,
    }
    result.update(changes)
    return result


def evidence(evidence_type, digest, ordinal):
    return [{
        "evidence_type": evidence_type,
        "evidence_reference": f"evidence.fictional.{ordinal}",
        "evidence_digest": digest,
        "recorded_at": f"2030-01-15T15:0{ordinal}:30Z",
    }]


class BoundedAuthorizationPlanTests(unittest.TestCase):
    def test_exact_plan_approval_and_schema_bindings(self):
        value = plan()
        validate_plan(value, SCHEMAS)
        validate_approval(value, approval(value), SCHEMAS, T0)
        progress = initial_progress(value, SCHEMAS, PROGRESS_ID, T0)
        validate_progress(value, progress, SCHEMAS)
        self.assertEqual(progress["overall_state"], "NOT_STARTED")
        self.assertTrue(all(not item["authorization_consumed"] for item in progress["step_states"]))

    def test_one_resource_evidence_gates_and_resume_without_replay(self):
        value = plan(); owner = approval(value)
        progress = initial_progress(value, SCHEMAS, PROGRESS_ID, T0)
        with self.assertRaisesRegex(AuthorizationPlanStop, "PREFLIGHT_BINDING_MISMATCH"):
            authorize_step(value, owner, progress, request(value, 1, progress), SCHEMAS, T0)
        progress = authorize_step(value, owner, progress, request(value, 0, progress), SCHEMAS, T0)
        progress = record_step_outcome(
            value, owner, progress, "plan.step.01", "SUCCEEDED", "PASS",
            evidence("local.artifact", DIGESTS[3], 1),
            value["steps"][0]["expected_postcondition"], None, SCHEMAS, "2030-01-15T15:02:00Z",
        )
        with self.assertRaisesRegex(AuthorizationPlanStop, "PREFLIGHT_BINDING_MISMATCH"):
            authorize_step(value, owner, progress, request(value, 0, progress), SCHEMAS, "2030-01-15T15:03:00Z")
        progress = authorize_step(
            value, owner, progress, request(value, 1, progress), SCHEMAS, "2030-01-15T15:03:00Z"
        )
        self.assertEqual(progress["step_states"][0]["authorization_state"], "CONSUMED")
        self.assertEqual(progress["step_states"][1]["authorization_state"], "AUTHORIZED")

    def test_scope_environment_credential_and_evidence_drift_stop(self):
        value = plan(); owner = approval(value)
        progress = initial_progress(value, SCHEMAS, PROGRESS_ID, T0)
        cases = (
            {"project_reference": "project.fictional.staging"},
            {"environment": "STAGING"},
            {"issuer_reference": "https://auth.other.invalid/issuer"},
            {"audience_reference": "audience.fictional.other"},
            {"resource_digest": DIGESTS[4]},
            {"operation": "provider.resource.delete"},
            {"credential_class": "OWNER_INTERACTIVE_SESSION"},
            {"scope_expansion": True},
            {"unexpected_remote_state": True},
            {"extra_privileges": True},
            {"unauthorized_migration_surface": True},
            {"required_evidence": []},
        )
        for changes in cases:
            with self.subTest(changes=changes):
                with self.assertRaises(AuthorizationPlanStop):
                    authorize_step(value, owner, progress, request(value, 0, progress, **changes), SCHEMAS, T0)

    def test_failed_or_ambiguous_step_stops_and_cannot_retry(self):
        value = plan(); owner = approval(value)
        for execution_state, verification_state, error_code in (
            ("FAILED", "FAIL", "EXECUTION_FAILED"),
            ("AMBIGUOUS", "AMBIGUOUS", "OUTCOME_AMBIGUOUS"),
        ):
            with self.subTest(execution_state=execution_state):
                progress = initial_progress(value, SCHEMAS, PROGRESS_ID, T0)
                progress = authorize_step(value, owner, progress, request(value, 0, progress), SCHEMAS, T0)
                progress = record_step_outcome(
                    value, owner, progress, "plan.step.01", execution_state, verification_state,
                    evidence("local.artifact", DIGESTS[3], 1), "unverified outcome",
                    error_code, SCHEMAS, "2030-01-15T15:02:00Z",
                )
                self.assertEqual(progress["overall_state"], "STOPPED")
                self.assertTrue(progress["step_states"][0]["authorization_consumed"])
                with self.assertRaisesRegex(AuthorizationPlanStop, "PLAN_NOT_CONTINUABLE"):
                    authorize_step(
                        value, owner, progress, request(value, 0, progress),
                        SCHEMAS, "2030-01-15T15:03:00Z",
                    )

    def test_digest_version_owner_and_expiration_mismatch_stop(self):
        value = plan()
        cases = []
        for key, replacement in (
            ("plan_digest", DIGESTS[0]),
            ("plan_version", 2),
            ("owner_identity", "owner.other"),
            ("environment", "STAGING"),
        ):
            changed = approval(value); changed[key] = replacement; changed["approval_digest"] = approval_digest(changed)
            cases.append(changed)
        for changed in cases:
            with self.assertRaises(AuthorizationPlanStop):
                validate_approval(value, changed, SCHEMAS, T0)
        with self.assertRaisesRegex(AuthorizationPlanStop, "PLAN_AUTHORIZATION_EXPIRED"):
            validate_approval(value, approval(value), SCHEMAS, "2030-01-15T16:00:00Z")
        owner = approval(value)
        progress = initial_progress(value, SCHEMAS, PROGRESS_ID, T0)
        progress = authorize_step(value, owner, progress, request(value, 0, progress), SCHEMAS, T0)
        with self.assertRaisesRegex(AuthorizationPlanStop, "PLAN_AUTHORIZATION_EXPIRED"):
            record_step_outcome(
                value, owner, progress, "plan.step.01", "SUCCEEDED", "PASS",
                evidence("local.artifact", DIGESTS[3], 1),
                value["steps"][0]["expected_postcondition"], None,
                SCHEMAS, "2030-01-15T16:00:00Z",
            )

    def test_unresolved_plan_and_sensitive_or_jwt_authority_input_fail_closed(self):
        value = plan()
        value["steps"][0]["unresolved_bindings"] = ["migration.digest"]
        value["definition_status"] = "DRAFT_BLOCKED"
        value["plan_digest"] = plan_digest(value)
        validate_plan(value, SCHEMAS)
        with self.assertRaisesRegex(AuthorizationPlanStop, "PLAN_UNRESOLVED"):
            validate_approval(value, approval(value), SCHEMAS, T0)
        ready = plan(); owner = approval(ready)
        progress = initial_progress(ready, SCHEMAS, PROGRESS_ID, T0)
        injected = request(ready, 0, progress)
        injected["jwt_roles"] = ["ADMIN"]
        with self.assertRaisesRegex(AuthorizationPlanStop, "PREFLIGHT_SURFACE_INVALID"):
            authorize_step(ready, owner, progress, injected, SCHEMAS, T0)
        sensitive = copy.deepcopy(ready); sensitive["access_token"] = "prohibited"
        with self.assertRaisesRegex(AuthorizationPlanError, "SENSITIVE_FIELD_PROHIBITED"):
            validate_plan(sensitive, SCHEMAS)

    def test_provider_neutral_target_is_not_supabase_specific(self):
        value = plan()
        value["target"] = {
            "provider_class": "runtime.provider",
            "provider_reference": "provider.runtime.fictional",
            "project_reference": "project.runtime.fictional",
            "responsibility": "RUNTIME",
            "issuer_reference": None,
            "audience_reference": None,
        }
        value["plan_digest"] = plan_digest(value)
        validate_plan(value, SCHEMAS)
        self.assertNotIn("supabase", str(value).lower())


if __name__ == "__main__":
    unittest.main()
