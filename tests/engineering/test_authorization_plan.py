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
    progress_digest,
    record_step_outcome,
    validate_approval,
    validate_plan,
    validate_progress,
)
from avuhz_runtime.implementation_handoff import canonical_digest


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


V8_STEP0_OUTCOME_AT = "2030-01-15T15:02:00Z"
V8_STEP1_AUTHORIZE_AT = "2030-01-15T15:03:00Z"
V8_STEP1_OUTCOME_AT = "2030-01-15T15:04:00Z"
V8_STEP2_AUTHORIZE_AT = "2030-01-15T15:05:00Z"


def typed_binding(
    binding_id,
    phase,
    value_class,
    source_step_id,
    evidence_type,
    digest_policy="REQUIRED",
    persistence_policy="SANITIZED_VALUE_ALLOWED",
):
    return {
        "binding_id": binding_id,
        "phase": phase,
        "value_class": value_class,
        "source_step_id": source_step_id,
        "evidence_type": evidence_type,
        "digest_policy": digest_policy,
        "persistence_policy": persistence_policy,
    }


def typed_assertion(
    declaration,
    evidence_digest,
    sanitized_value,
    value_digest,
    recorded_at,
):
    return {
        **copy.deepcopy(declaration),
        "evidence_digest": evidence_digest,
        "sanitized_value": sanitized_value,
        "value_digest": value_digest,
        "recorded_at": recorded_at,
    }


def typed_declaration(value, step_index, binding_id):
    return next(
        declaration
        for declaration in value["steps"][step_index]["binding_declarations"]
        if declaration["binding_id"] == binding_id
    )


def typed_plan():
    value = plan()
    value["plan_version"] = 8
    for item in value["steps"]:
        item["binding_declarations"] = []
        item["produced_evidence"] = []

    preapproval = typed_binding(
        "binding.preapproval.resource",
        "PREAPPROVAL_BOUND",
        "STABLE_REFERENCE",
        None,
        None,
        "REQUIRED",
        "DIGEST_ONLY",
    )
    produced_runtime = typed_binding(
        "binding.runtime.reference",
        "PRODUCED_BY_CURRENT_STEP",
        "STABLE_REFERENCE",
        None,
        "local.artifact",
    )
    derived_runtime = typed_binding(
        "binding.runtime.reference",
        "DERIVED_FROM_SOURCE_STEP",
        "STABLE_REFERENCE",
        "plan.step.01",
        "local.artifact",
    )
    preflight = typed_binding(
        "binding.preflight.reference",
        "RESOLVED_BY_STEP_PREFLIGHT",
        "STABLE_REFERENCE",
        None,
        "preflight.result",
    )
    produced_created = typed_binding(
        "binding.created.reference",
        "PRODUCED_BY_CURRENT_STEP",
        "STABLE_REFERENCE",
        None,
        "resource.verification",
    )
    derived_created = typed_binding(
        "binding.created.reference",
        "DERIVED_FROM_SOURCE_STEP",
        "STABLE_REFERENCE",
        "plan.step.02",
        "resource.verification",
    )
    ephemeral = typed_binding(
        "binding.ephemeral.handoff",
        "EPHEMERAL_HANDOFF",
        "EPHEMERAL_SENSITIVE",
        "plan.step.02",
        "resource.verification",
        "PROHIBITED",
        "PROHIBITED",
    )

    value["steps"][0]["binding_declarations"] = [
        preapproval,
        produced_runtime,
    ]
    value["steps"][0]["produced_evidence"] = [{
        "evidence_type": "local.artifact",
        "established_binding_ids": ["binding.runtime.reference"],
        "digest_policy": "REQUIRED",
    }]
    value["steps"][1]["binding_declarations"] = [
        derived_runtime,
        preflight,
        produced_created,
    ]
    value["steps"][1]["produced_evidence"] = [{
        "evidence_type": "resource.verification",
        "established_binding_ids": [
            "binding.created.reference",
            "binding.ephemeral.handoff",
        ],
        "digest_policy": "REQUIRED",
    }]
    value["steps"][2]["binding_declarations"] = [
        derived_created,
        ephemeral,
    ]
    value["steps"][2]["produced_evidence"] = [{
        "evidence_type": "final.verification",
        "established_binding_ids": [],
        "digest_policy": "REQUIRED",
    }]
    value["plan_digest"] = plan_digest(value)
    return value


def typed_plan_with_exact_preapproval(
    exact_value="reference.fictional.owner-bound",
    value_class="STABLE_REFERENCE",
):
    value = typed_plan()
    declaration = typed_declaration(
        value, 0, "binding.preapproval.resource"
    )
    declaration["value_class"] = value_class
    declaration["preapproval_value"] = {
        "value": exact_value,
        "exact_digest": canonical_digest(exact_value),
    }
    value["plan_digest"] = plan_digest(value)
    return value


def typed_preflight_assertion(value, recorded_at=V8_STEP1_AUTHORIZE_AT):
    declaration = typed_declaration(
        value, 1, "binding.preflight.reference"
    )
    return typed_assertion(
        declaration,
        DIGESTS[4],
        "resource.fictional.preflight",
        DIGESTS[5],
        recorded_at,
    )


def typed_authorized_step0(value=None):
    value = typed_plan() if value is None else value
    owner = approval(value)
    progress = initial_progress(value, SCHEMAS, PROGRESS_ID, T0)
    progress = authorize_step(
        value, owner, progress, request(value, 0, progress), SCHEMAS, T0
    )
    return value, owner, progress


def typed_completed_step0(value=None):
    value, owner, progress = typed_authorized_step0(value)
    declaration = typed_declaration(
        value, 0, "binding.runtime.reference"
    )
    assertion = typed_assertion(
        declaration,
        DIGESTS[3],
        "resource.fictional.created",
        DIGESTS[4],
        V8_STEP0_OUTCOME_AT,
    )
    progress = record_step_outcome(
        value,
        owner,
        progress,
        "plan.step.01",
        "SUCCEEDED",
        "PASS",
        evidence("local.artifact", DIGESTS[3], 1),
        value["steps"][0]["expected_postcondition"],
        None,
        SCHEMAS,
        V8_STEP0_OUTCOME_AT,
        [assertion],
    )
    return value, owner, progress


def typed_authorized_step1():
    value, owner, progress = typed_completed_step0()
    progress = authorize_step(
        value,
        owner,
        progress,
        request(value, 1, progress),
        SCHEMAS,
        V8_STEP1_AUTHORIZE_AT,
        [typed_preflight_assertion(value)],
    )
    return value, owner, progress


def typed_authorized_step2():
    value, owner, progress = typed_authorized_step1()
    declaration = typed_declaration(
        value, 1, "binding.created.reference"
    )
    assertion = typed_assertion(
        declaration,
        DIGESTS[4],
        "resource.fictional.verified",
        DIGESTS[5],
        V8_STEP1_OUTCOME_AT,
    )
    progress = record_step_outcome(
        value,
        owner,
        progress,
        "plan.step.02",
        "SUCCEEDED",
        "PASS",
        evidence("resource.verification", DIGESTS[4], 2),
        value["steps"][1]["expected_postcondition"],
        None,
        SCHEMAS,
        V8_STEP1_OUTCOME_AT,
        [assertion],
    )
    progress = authorize_step(
        value,
        owner,
        progress,
        request(value, 2, progress),
        SCHEMAS,
        V8_STEP2_AUTHORIZE_AT,
    )
    return value, owner, progress


def refresh_progress_digest(progress):
    progress["progress_digest"] = progress_digest(progress)
    return progress


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


class TypedV8AuthorizationPlanTests(unittest.TestCase):
    def assert_progress_rejected(self, value, progress):
        refresh_progress_digest(progress)
        with self.assertRaises(AuthorizationPlanError):
            validate_progress(value, progress, SCHEMAS)

    def test_v8_readiness_phase_matrix(self):
        value = typed_plan()
        validate_plan(value, SCHEMAS)
        validate_approval(value, approval(value), SCHEMAS, T0)
        phases = {
            declaration["phase"]
            for item in value["steps"]
            for declaration in item["binding_declarations"]
        }
        self.assertTrue({
            "PREAPPROVAL_BOUND",
            "DERIVED_FROM_SOURCE_STEP",
            "PRODUCED_BY_CURRENT_STEP",
            "RESOLVED_BY_STEP_PREFLIGHT",
            "EPHEMERAL_HANDOFF",
        } <= phases)

        invalid_preapproval = copy.deepcopy(value)
        invalid_preapproval["steps"][0]["resource"]["binding_state"] = (
            "UNRESOLVED_BLOCKER"
        )
        invalid_preapproval["definition_status"] = "DRAFT_BLOCKED"
        invalid_preapproval["plan_digest"] = plan_digest(invalid_preapproval)
        with self.assertRaisesRegex(
            AuthorizationPlanError, "BINDING_DECLARATION_INVALID"
        ):
            validate_plan(invalid_preapproval, SCHEMAS)

        blocked = copy.deepcopy(value)
        blocked["steps"][2]["binding_declarations"].append(typed_binding(
            "binding.unresolved.blocker",
            "UNRESOLVED_BLOCKER",
            "STABLE_REFERENCE",
            None,
            None,
            "PROHIBITED",
            "PROHIBITED",
        ))
        blocked["definition_status"] = "DRAFT_BLOCKED"
        blocked["plan_digest"] = plan_digest(blocked)
        validate_plan(blocked, SCHEMAS)
        with self.assertRaisesRegex(AuthorizationPlanStop, "PLAN_UNRESOLVED"):
            validate_approval(blocked, approval(blocked), SCHEMAS, T0)

        for source_step in ("plan.step.unknown", "plan.step.03"):
            malformed = copy.deepcopy(value)
            typed_declaration(
                malformed, 1, "binding.runtime.reference"
            )["source_step_id"] = source_step
            malformed["plan_digest"] = plan_digest(malformed)
            with self.subTest(source_step=source_step):
                with self.assertRaisesRegex(
                    AuthorizationPlanError, "BINDING_SOURCE_INVALID"
                ):
                    validate_plan(malformed, SCHEMAS)

        legacy = plan()
        legacy["steps"][0]["unresolved_bindings"] = ["resource.future"]
        legacy["definition_status"] = "DRAFT_BLOCKED"
        legacy["plan_digest"] = plan_digest(legacy)
        validate_plan(legacy, SCHEMAS)
        with self.assertRaisesRegex(AuthorizationPlanStop, "PLAN_UNRESOLVED"):
            validate_approval(legacy, approval(legacy), SCHEMAS, T0)

    def test_v8_exact_preapproval_value_enforcement_matrix(self):
        valid = typed_plan_with_exact_preapproval()
        validate_plan(valid, SCHEMAS)
        validate_approval(valid, approval(valid), SCHEMAS, T0)
        progress = initial_progress(valid, SCHEMAS, PROGRESS_ID, T0)
        authorized = authorize_step(
            valid,
            approval(valid),
            progress,
            request(valid, 0, progress),
            SCHEMAS,
            T0,
        )
        self.assertEqual(
            authorized["step_states"][0]["authorization_state"],
            "AUTHORIZED",
        )
        self.assertEqual(valid["definition_status"], "READY_FOR_APPROVAL")

        uuid_value = "00000000-0000-4000-8000-000000000001"
        uuid_plan = typed_plan_with_exact_preapproval(
            uuid_value,
            "UUID_IDENTIFIER",
        )
        validate_plan(uuid_plan, SCHEMAS)

        mismatch = typed_plan_with_exact_preapproval()
        typed_declaration(
            mismatch, 0, "binding.preapproval.resource"
        )["preapproval_value"]["exact_digest"] = DIGESTS[0]
        mismatch["plan_digest"] = plan_digest(mismatch)
        with self.assertRaisesRegex(
            AuthorizationPlanError, "BINDING_DECLARATION_INVALID"
        ):
            validate_plan(mismatch, SCHEMAS)

        malformed = typed_plan_with_exact_preapproval(
            "not-a-canonical-uuid",
            "UUID_IDENTIFIER",
        )
        with self.assertRaisesRegex(AuthorizationPlanError, "SCHEMA_INVALID"):
            validate_plan(malformed, SCHEMAS)

        runtime_declarations = (
            (0, "binding.runtime.reference"),
            (1, "binding.runtime.reference"),
            (1, "binding.preflight.reference"),
            (2, "binding.ephemeral.handoff"),
        )
        for step_index, binding_id in runtime_declarations:
            runtime = typed_plan()
            declaration = typed_declaration(runtime, step_index, binding_id)
            declaration["preapproval_value"] = {
                "value": "reference.fictional.runtime",
                "exact_digest": canonical_digest("reference.fictional.runtime"),
            }
            runtime["plan_digest"] = plan_digest(runtime)
            with self.subTest(phase=declaration["phase"]):
                with self.assertRaisesRegex(
                    AuthorizationPlanError, "SCHEMA_INVALID"
                ):
                    validate_plan(runtime, SCHEMAS)

        unresolved = typed_plan()
        declaration = typed_binding(
            "binding.fictional.unresolved",
            "UNRESOLVED_BLOCKER",
            "STABLE_REFERENCE",
            None,
            None,
            "PROHIBITED",
            "PROHIBITED",
        )
        declaration["preapproval_value"] = {
            "value": "reference.fictional.unresolved",
            "exact_digest": canonical_digest("reference.fictional.unresolved"),
        }
        unresolved["steps"][2]["binding_declarations"].append(declaration)
        unresolved["definition_status"] = "DRAFT_BLOCKED"
        unresolved["plan_digest"] = plan_digest(unresolved)
        with self.subTest(phase="UNRESOLVED_BLOCKER"):
            with self.assertRaisesRegex(AuthorizationPlanError, "SCHEMA_INVALID"):
                validate_plan(unresolved, SCHEMAS)

        unbound = typed_plan_with_exact_preapproval()
        typed_declaration(
            unbound, 0, "binding.preapproval.resource"
        )["preapproval_value"].pop("exact_digest")
        unbound["plan_digest"] = plan_digest(unbound)
        with self.assertRaisesRegex(AuthorizationPlanError, "SCHEMA_INVALID"):
            validate_plan(unbound, SCHEMAS)

        injected_request = request(valid, 0, progress)
        injected_request["preapproval_value"] = "reference.fictional.override"
        with self.assertRaisesRegex(
            AuthorizationPlanStop, "PREFLIGHT_SURFACE_INVALID"
        ):
            authorize_step(
                valid,
                approval(valid),
                progress,
                injected_request,
                SCHEMAS,
                T0,
            )

        injected_preflight = [{
            "binding_id": "binding.preapproval.resource",
            "preapproval_value": {
                "value": "reference.fictional.override",
                "exact_digest": canonical_digest("reference.fictional.override"),
            },
        }]
        with self.assertRaisesRegex(
            AuthorizationPlanStop, "PREFLIGHT_BINDING_MISMATCH"
        ):
            authorize_step(
                valid,
                approval(valid),
                progress,
                request(valid, 0, progress),
                SCHEMAS,
                T0,
                injected_preflight,
            )

        ephemeral = typed_declaration(
            valid, 2, "binding.ephemeral.handoff"
        )
        self.assertNotIn("preapproval_value", ephemeral)
        self.assertEqual(ephemeral["digest_policy"], "PROHIBITED")
        self.assertEqual(ephemeral["persistence_policy"], "PROHIBITED")

    def test_v8_derived_source_provenance_matrix(self):
        value, owner, source_progress = typed_completed_step0()
        progress = authorize_step(
            value,
            owner,
            source_progress,
            request(value, 1, source_progress),
            SCHEMAS,
            V8_STEP1_AUTHORIZE_AT,
            [typed_preflight_assertion(value)],
        )
        source_state = progress["step_states"][0]
        self.assertEqual(source_state["execution_state"], "SUCCEEDED")
        self.assertEqual(source_state["verification_state"], "PASS")
        derived = next(
            item
            for item in progress["step_states"][1]["binding_assertions"]
            if item["phase"] == "DERIVED_FROM_SOURCE_STEP"
        )
        self.assertEqual(derived["source_step_id"], "plan.step.01")
        self.assertEqual(derived["evidence_type"], "local.artifact")
        self.assertEqual(
            derived["evidence_digest"],
            source_state["evidence"][0]["evidence_digest"],
        )

        mutations = []

        missing_assertion = copy.deepcopy(source_progress)
        missing_assertion["step_states"][0]["binding_assertions"] = []
        mutations.append(("missing assertion", missing_assertion))

        source_failed = copy.deepcopy(source_progress)
        source_failed["step_states"][0]["execution_state"] = "FAILED"
        source_failed["step_states"][0]["verification_state"] = "FAIL"
        source_failed["step_states"][0]["safe_error_code"] = "SAFE_FAILURE"
        mutations.append(("source failed", source_failed))

        source_unverified = copy.deepcopy(source_progress)
        source_unverified["step_states"][0]["verification_state"] = "FAIL"
        source_unverified["step_states"][0]["safe_error_code"] = "SAFE_FAILURE"
        mutations.append(("source verification failed", source_unverified))

        missing_evidence = copy.deepcopy(source_progress)
        missing_evidence["step_states"][0]["evidence"] = []
        mutations.append(("missing evidence", missing_evidence))

        duplicate_evidence = copy.deepcopy(source_progress)
        duplicate = copy.deepcopy(
            duplicate_evidence["step_states"][0]["evidence"][0]
        )
        duplicate["evidence_reference"] = "evidence.fictional.duplicate"
        duplicate["evidence_digest"] = DIGESTS[5]
        duplicate_evidence["step_states"][0]["evidence"].append(duplicate)
        mutations.append(("duplicate evidence", duplicate_evidence))

        wrong_type = copy.deepcopy(source_progress)
        wrong_type["step_states"][0]["evidence"][0]["evidence_type"] = (
            "unrelated.evidence"
        )
        mutations.append(("wrong evidence type", wrong_type))

        wrong_digest = copy.deepcopy(source_progress)
        wrong_digest["step_states"][0]["binding_assertions"][0][
            "evidence_digest"
        ] = DIGESTS[5]
        mutations.append(("wrong evidence digest", wrong_digest))

        undeclared = copy.deepcopy(source_progress)
        extra = copy.deepcopy(
            undeclared["step_states"][0]["binding_assertions"][0]
        )
        extra["binding_id"] = "binding.undeclared.reference"
        undeclared["step_states"][0]["binding_assertions"].append(extra)
        mutations.append(("undeclared assertion", undeclared))

        for label, changed in mutations:
            with self.subTest(label=label):
                self.assert_progress_rejected(value, changed)

        injected = request(value, 1, source_progress)
        injected["binding_assertions"] = [{
            "binding_id": "binding.runtime.reference",
            "sanitized_value": "resource.fictional.substitute",
        }]
        with self.assertRaisesRegex(
            AuthorizationPlanStop, "PREFLIGHT_SURFACE_INVALID"
        ):
            authorize_step(
                value,
                owner,
                source_progress,
                injected,
                SCHEMAS,
                V8_STEP1_AUTHORIZE_AT,
                [typed_preflight_assertion(value)],
            )

    def test_v8_produced_current_step_outcome_matrix(self):
        value, owner, authorized = typed_authorized_step0()
        declaration = typed_declaration(
            value, 0, "binding.runtime.reference"
        )
        valid_assertion = typed_assertion(
            declaration,
            DIGESTS[3],
            "resource.fictional.created",
            DIGESTS[4],
            V8_STEP0_OUTCOME_AT,
        )
        valid_evidence = evidence("local.artifact", DIGESTS[3], 1)
        completed = record_step_outcome(
            value,
            owner,
            authorized,
            "plan.step.01",
            "SUCCEEDED",
            "PASS",
            valid_evidence,
            value["steps"][0]["expected_postcondition"],
            None,
            SCHEMAS,
            V8_STEP0_OUTCOME_AT,
            [valid_assertion],
        )
        state = completed["step_states"][0]
        self.assertTrue(state["authorization_consumed"])
        self.assertEqual(state["execution_state"], "SUCCEEDED")
        self.assertEqual(state["verification_state"], "PASS")

        cases = [
            ("missing evidence", [], [valid_assertion]),
            (
                "undeclared evidence",
                evidence("undeclared.evidence", DIGESTS[3], 1),
                [valid_assertion],
            ),
            ("missing assertion", valid_evidence, []),
        ]
        undeclared_assertion = copy.deepcopy(valid_assertion)
        undeclared_assertion["binding_id"] = "binding.undeclared.reference"
        cases.append(
            ("undeclared assertion", valid_evidence, [undeclared_assertion])
        )
        cases.append(
            (
                "duplicate assertion",
                valid_evidence,
                [valid_assertion, copy.deepcopy(valid_assertion)],
            )
        )
        wrong_digest = copy.deepcopy(valid_assertion)
        wrong_digest["evidence_digest"] = DIGESTS[5]
        cases.append(("wrong digest", valid_evidence, [wrong_digest]))
        wrong_persistence = copy.deepcopy(valid_assertion)
        wrong_persistence["sanitized_value"] = None
        cases.append(
            ("wrong persistence", valid_evidence, [wrong_persistence])
        )

        for label, supplied_evidence, assertions in cases:
            with self.subTest(label=label):
                with self.assertRaises(AuthorizationPlanError):
                    record_step_outcome(
                        value,
                        owner,
                        authorized,
                        "plan.step.01",
                        "SUCCEEDED",
                        "PASS",
                        supplied_evidence,
                        value["steps"][0]["expected_postcondition"],
                        None,
                        SCHEMAS,
                        V8_STEP0_OUTCOME_AT,
                        assertions,
                    )

        stopped = record_step_outcome(
            value,
            owner,
            authorized,
            "plan.step.01",
            "SUCCEEDED",
            "PASS",
            valid_evidence,
            "fictional postcondition mismatch",
            "POSTCONDITION_MISMATCH",
            SCHEMAS,
            V8_STEP0_OUTCOME_AT,
            [],
        )
        self.assertEqual(stopped["overall_state"], "STOPPED")
        self.assertTrue(stopped["step_states"][0]["authorization_consumed"])
        with self.assertRaises(AuthorizationPlanError):
            record_step_outcome(
                value,
                owner,
                authorized,
                "plan.step.01",
                "SUCCEEDED",
                "PASS",
                valid_evidence,
                "fictional postcondition mismatch",
                None,
                SCHEMAS,
                V8_STEP0_OUTCOME_AT,
                [valid_assertion],
            )

    def test_v8_trusted_preflight_and_caller_injection_matrix(self):
        value, owner, progress = typed_completed_step0()
        preflight = typed_preflight_assertion(value)
        authorized = authorize_step(
            value,
            owner,
            progress,
            request(value, 1, progress),
            SCHEMAS,
            V8_STEP1_AUTHORIZE_AT,
            [preflight],
        )
        assertions = authorized["step_states"][1]["binding_assertions"]
        self.assertTrue(any(
            item["phase"] == "RESOLVED_BY_STEP_PREFLIGHT"
            for item in assertions
        ))

        for field, injected_value in (
            ("binding_assertions", [preflight]),
            ("command_payload_values", {"binding": "fictional.value"}),
            ("jwt_claims", {"role": "fictional"}),
            ("untrusted_provider_output", {"state": "fictional"}),
        ):
            injected = request(value, 1, progress)
            injected[field] = injected_value
            with self.subTest(field=field):
                with self.assertRaisesRegex(
                    AuthorizationPlanStop, "PREFLIGHT_SURFACE_INVALID"
                ):
                    authorize_step(
                        value,
                        owner,
                        progress,
                        injected,
                        SCHEMAS,
                        V8_STEP1_AUTHORIZE_AT,
                        [preflight],
                    )

        malformed_cases = []
        unrelated = copy.deepcopy(preflight)
        unrelated["evidence_type"] = "unrelated.evidence"
        malformed_cases.append([unrelated])
        wrong_phase = copy.deepcopy(preflight)
        wrong_phase["phase"] = "DERIVED_FROM_SOURCE_STEP"
        malformed_cases.append([wrong_phase])
        stale = copy.deepcopy(preflight)
        stale["recorded_at"] = V8_STEP0_OUTCOME_AT
        malformed_cases.append([stale])
        malformed_cases.append([preflight, copy.deepcopy(preflight)])

        with self.assertRaisesRegex(
            AuthorizationPlanStop, "PREFLIGHT_BINDING_MISMATCH"
        ):
            authorize_step(
                value,
                owner,
                progress,
                request(value, 1, progress),
                SCHEMAS,
                V8_STEP1_AUTHORIZE_AT,
            )
        for supplied in malformed_cases:
            with self.subTest(supplied=supplied):
                with self.assertRaises(AuthorizationPlanError):
                    authorize_step(
                        value,
                        owner,
                        progress,
                        request(value, 1, progress),
                        SCHEMAS,
                        V8_STEP1_AUTHORIZE_AT,
                        supplied,
                    )

    def test_v8_ephemeral_handoff_nonpersistence_matrix(self):
        value, _, progress = typed_authorized_step2()
        ephemeral = next(
            item
            for item in progress["step_states"][2]["binding_assertions"]
            if item["phase"] == "EPHEMERAL_HANDOFF"
        )
        self.assertEqual(ephemeral["source_step_id"], "plan.step.02")
        self.assertIsNone(ephemeral["sanitized_value"])
        self.assertIsNone(ephemeral["value_digest"])
        self.assertEqual(ephemeral["persistence_policy"], "PROHIBITED")
        self.assertEqual(ephemeral["digest_policy"], "PROHIBITED")

        cases = []
        raw_value = copy.deepcopy(progress)
        raw_value["step_states"][2]["binding_assertions"][1][
            "sanitized_value"
        ] = "fictional.ephemeral.material"
        cases.append(("raw ephemeral value", raw_value))

        credential_label = copy.deepcopy(progress)
        credential_label["step_states"][2]["binding_assertions"][1][
            "sanitized_value"
        ] = "fictional.credential.material"
        cases.append(("credential-shaped value", credential_label))

        value_digest = copy.deepcopy(progress)
        value_digest["step_states"][2]["binding_assertions"][1][
            "value_digest"
        ] = DIGESTS[0]
        cases.append(("prohibited value digest", value_digest))

        for label, changed in cases:
            with self.subTest(label=label):
                self.assert_progress_rejected(value, changed)

    def test_v8_typed_progress_validation_matrix(self):
        value, _, progress = typed_authorized_step2()
        cases = []

        unknown = copy.deepcopy(progress)
        unknown["step_states"][0]["binding_assertions"][0][
            "binding_id"
        ] = "binding.unknown.reference"
        cases.append(("unknown binding", unknown))

        wrong_phase = copy.deepcopy(progress)
        wrong_phase["step_states"][0]["binding_assertions"][0][
            "phase"
        ] = "RESOLVED_BY_STEP_PREFLIGHT"
        cases.append(("wrong phase", wrong_phase))

        wrong_source = copy.deepcopy(progress)
        wrong_source["step_states"][2]["binding_assertions"][0][
            "source_step_id"
        ] = "plan.step.03"
        cases.append(("wrong source", wrong_source))

        wrong_evidence_type = copy.deepcopy(progress)
        wrong_evidence_type["step_states"][2]["binding_assertions"][0][
            "evidence_type"
        ] = "unrelated.evidence"
        cases.append(("wrong evidence type", wrong_evidence_type))

        wrong_evidence_digest = copy.deepcopy(progress)
        wrong_evidence_digest["step_states"][2]["binding_assertions"][0][
            "evidence_digest"
        ] = DIGESTS[0]
        cases.append(("wrong evidence digest", wrong_evidence_digest))

        wrong_persistence = copy.deepcopy(progress)
        wrong_persistence["step_states"][0]["binding_assertions"][0][
            "persistence_policy"
        ] = "DIGEST_ONLY"
        cases.append(("persistence mismatch", wrong_persistence))

        wrong_value_class = copy.deepcopy(progress)
        wrong_value_class["step_states"][0]["binding_assertions"][0][
            "sanitized_value"
        ] = "not a bounded reference"
        cases.append(("wrong value class", wrong_value_class))

        duplicate = copy.deepcopy(progress)
        duplicate["step_states"][0]["binding_assertions"].append(
            copy.deepcopy(duplicate["step_states"][0]["binding_assertions"][0])
        )
        cases.append(("duplicate assertion", duplicate))

        future = copy.deepcopy(progress)
        future["step_states"][2]["binding_assertions"][0][
            "source_step_id"
        ] = "plan.step.03"
        cases.append(("future provenance", future))

        for label, changed in cases:
            with self.subTest(label=label):
                self.assert_progress_rejected(value, changed)

        digest_only_plan = typed_plan()
        for step_index in (0, 1):
            declaration = typed_declaration(
                digest_only_plan, step_index, "binding.runtime.reference"
            )
            declaration["persistence_policy"] = "DIGEST_ONLY"
        digest_only_plan["plan_digest"] = plan_digest(digest_only_plan)
        value2, owner2, authorized2 = typed_authorized_step0(digest_only_plan)
        declaration2 = typed_declaration(
            value2, 0, "binding.runtime.reference"
        )
        valid_digest_only = typed_assertion(
            declaration2,
            DIGESTS[3],
            None,
            DIGESTS[4],
            V8_STEP0_OUTCOME_AT,
        )
        completed2 = record_step_outcome(
            value2,
            owner2,
            authorized2,
            "plan.step.01",
            "SUCCEEDED",
            "PASS",
            evidence("local.artifact", DIGESTS[3], 1),
            value2["steps"][0]["expected_postcondition"],
            None,
            SCHEMAS,
            V8_STEP0_OUTCOME_AT,
            [valid_digest_only],
        )
        digest_only_violation = copy.deepcopy(completed2)
        digest_only_violation["step_states"][0]["binding_assertions"][0][
            "sanitized_value"
        ] = "resource.fictional.prohibited"
        self.assert_progress_rejected(value2, digest_only_violation)


if __name__ == "__main__":
    unittest.main()
