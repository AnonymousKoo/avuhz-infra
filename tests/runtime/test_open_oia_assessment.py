import copy
import sys
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_runtime.guards import GuardPipeline, TrustedExecutionContext
from avuhz_runtime.in_memory import Executor, MemoryStore
from avuhz_runtime.schema_registry import SchemaRegistry
from avuhz_runtime.validation import CommandValidator


class OpenOIAAssessmentTests(unittest.TestCase):
    tenant = "a3000000-0000-4000-8000-000000000002"
    other_tenant = "a3000000-0000-4000-8000-000000000099"
    engagement_id = "a3000000-0000-4000-8000-000000000004"
    scope_id = "a3000000-0000-4000-8000-000000000005"
    agreement_id = "a3000000-0000-4000-8000-000000000013"
    payment_id = "a3000000-0000-4000-8000-000000000014"
    grant_id = "a3000000-0000-4000-8000-000000000015"
    assessment_id = "a3000000-0000-4000-8000-000000000020"
    now = "2030-01-15T15:00:00Z"
    digest = "sha256:" + "a" * 64

    def setUp(self):
        self.store = self.authority_store()
        self.executor = Executor(
            CommandValidator(ROOT / "contracts/schemas/v1"),
            GuardPipeline(),
            self.store,
            clock=lambda: self.now,
            ids=lambda: "a3000000-0000-4000-8000-000000000030",
        )

    def authority_store(self):
        store = MemoryStore()
        store.engagements[self.engagement_id] = {
            "tenant_id": self.tenant, "engagement_id": self.engagement_id,
            "engagement_state": "OPEN", "record_version": 1,
        }
        store.scopes[self.scope_id] = {
            "tenant_id": self.tenant, "engagement_id": self.engagement_id,
            "diagnostic_scope_id": self.scope_id, "scope_version": 1,
            "record_version": 2, "status": "APPROVED",
            "canonical_scope_digest": self.digest, "action_set_version": 1,
            "in_scope_systems": [{"system_reference_id": "system-001"}],
            "permitted_diagnostic_actions": ["VIEW_CONFIGURATION"],
        }
        store.agreements[self.agreement_id] = {
            "tenant_id": self.tenant, "engagement_id": self.engagement_id,
            "diagnostic_agreement_authority_id": self.agreement_id,
            "record_version": 1, "status": "VERIFIED_ACTIVE",
            "scope_reference": {"reference_id": self.scope_id, "reference_version": 1},
            "canonical_scope_digest": self.digest,
            "effective_at": "2030-01-01T00:00:00Z", "ends_at": "2030-03-01T00:00:00Z",
        }
        store.payments[self.payment_id] = {
            "tenant_id": self.tenant, "engagement_id": self.engagement_id,
            "diagnostic_payment_verification_id": self.payment_id,
            "record_version": 1, "payment_purpose": "DIAGNOSTIC_OIA",
            "verification_status": "VERIFIED",
            "diagnostic_agreement_authority_reference": {"reference_id": self.agreement_id},
        }
        store.grants[(self.tenant, self.grant_id)] = {
            "tenant_id": self.tenant, "engagement_id": self.engagement_id,
            "assessment_access_grant_id": self.grant_id, "record_version": 2,
            "status": "ACTIVE", "active_from": "2030-01-15T14:00:00Z",
            "expires_at": "2030-02-15T15:00:00Z",
            "diagnostic_scope_reference": {"reference_type": "DIAGNOSTIC_SCOPE", "reference_id": self.scope_id, "reference_version": 1},
            "canonical_scope_digest": self.digest, "action_set_version": 1,
            "diagnostic_agreement_authority_reference": {"reference_type": "DIAGNOSTIC_AGREEMENT_AUTHORITY", "reference_id": self.agreement_id, "reference_version": 1},
            "diagnostic_payment_verification_reference": {"reference_type": "DIAGNOSTIC_PAYMENT_VERIFICATION", "reference_id": self.payment_id, "reference_version": 1},
            "target_system_references": [{"system_reference_id": "system-001"}],
            "permitted_actions": ["VIEW_CONFIGURATION"],
        }
        return store

    def context(self, tenant=None):
        return TrustedExecutionContext(
            True, "oia.service-01", "INTERNAL_SERVICE", tenant or self.tenant, None,
            frozenset({"oia:open"}), frozenset(), "TEST", "avuhz-command-api",
            "STRONG", False, "2030-01-15T14:00:00Z", "2030-01-15T16:00:00Z",
        )

    def raw(self, assessment_id=None, idempotency_key="phase5b-open-oia-0001", command_id=None):
        assessment_id = assessment_id or self.assessment_id
        payload = {
            "oia_assessment_id": assessment_id,
            "engagement_id": self.engagement_id,
            "diagnostic_scope_id": self.scope_id,
            "diagnostic_scope_version": 1,
            "canonical_scope_digest": self.digest,
            "assessment_access_grant_id": self.grant_id,
        }
        return {
            "command_id": command_id or "a3000000-0000-4000-8000-000000000021",
            "command_type": "OpenOIAAssessment", "command_schema_version": 1,
            "tenant_id": self.tenant, "engagement_id": self.engagement_id,
            "subject_type": "OIA_ASSESSMENT", "subject_id": assessment_id,
            "requested_by": "oia.service-01", "caller_type": "INTERNAL_SERVICE",
            "caller_identity": {
                "subject": "oia.service-01", "audience": "avuhz-command-api",
                "caller_type": "INTERNAL_SERVICE", "tenant_ids": [self.tenant],
                "capabilities": ["oia:open"], "environment": "TEST",
                "authentication_strength": "STRONG", "step_up_performed": False,
                "authenticated_at": "2030-01-15T14:00:00Z", "expires_at": "2030-01-15T16:00:00Z",
            },
            "correlation_id": "a3000000-0000-4000-8000-000000000022",
            "idempotency_key": idempotency_key, "requested_at": self.now,
            "environment": "TEST",
            "payload_schema": "urn:avuhz:schema:contracts:commands:open-oia-assessment-payload:v1",
            "payload_version": 1, "payload": payload,
        }

    def assert_no_oia_side_effects(self):
        self.assertEqual(self.store.oia_assessments, {})
        self.assertFalse(any(event.get("event_type") == "oia.assessment_opened" for event in self.store.events))
        self.assertEqual(self.store.outbox, [])

    def test_happy_path_preserves_exact_authority_and_is_contract_representable(self):
        raw = self.raw()
        self.assertEqual(self.executor.execute(raw, self.context())["result"], "ACCEPTED")
        assessment = self.store.oia_assessments[(self.tenant, self.assessment_id)]
        self.assertEqual(assessment, {
            "tenant_id": self.tenant, "oia_assessment_id": self.assessment_id,
            "engagement_id": self.engagement_id, "diagnostic_scope_id": self.scope_id,
            "diagnostic_scope_version": 1, "canonical_scope_digest": self.digest,
            "assessment_access_grant_id": self.grant_id, "state": "IN_PROGRESS",
            "record_version": 1, "opened_at": self.now, "created_at": self.now, "updated_at": self.now,
        })
        registry = SchemaRegistry(ROOT / "contracts/schemas/v1")
        snapshot = self.store.snapshot(CommandValidator(ROOT / "contracts/schemas/v1").prepare(raw).prepared)
        self.assertEqual((snapshot.subject_type, snapshot.state, snapshot.record_version), ("OIA_ASSESSMENT", "IN_PROGRESS", 1))
        validator = Draft202012Validator(registry.expanded("urn:avuhz:schema:contracts:domain:oia-assessment:v1"), format_checker=FormatChecker())
        self.assertEqual(list(validator.iter_errors(assessment)), [])
        event = self.store.events[-1]
        self.assertEqual(event["event_type"], "oia.assessment_opened")
        self.assertEqual(event["authoritative_subject_reference"], {"reference_type": "OIA_ASSESSMENT", "reference_id": self.assessment_id})
        self.assertEqual(event["sanitized_metadata"], {"oia_assessment_id": self.assessment_id, "record_version": 1})
        event_validator = Draft202012Validator(registry.expanded("urn:avuhz:schema:contracts:orchestration:lifecycle-event:v1"), format_checker=FormatChecker())
        self.assertEqual(list(event_validator.iter_errors(event)), [])
        self.assertEqual(self.store.outbox, [{"event_id": event["event_id"], "status": "PENDING"}])
        for forbidden in ("password", "api_key", "oauth", "authorization", "provider_payload", "connection_string"):
            self.assertNotIn(forbidden, repr((assessment, event, self.store.outbox)).lower())

    def test_exact_replay_is_duplicate_and_changed_meaning_conflicts(self):
        raw = self.raw()
        self.assertEqual(self.executor.execute(raw, self.context())["result"], "ACCEPTED")
        self.assertEqual(self.executor.execute(copy.deepcopy(raw), self.context())["result"], "DUPLICATE")
        changed = self.raw("a3000000-0000-4000-8000-000000000023")
        self.assertEqual(self.executor.execute(changed, self.context())["result"], "CONFLICT")
        self.assertEqual((len(self.store.oia_assessments), len(self.store.events), len(self.store.outbox)), (1, 1, 1))

    def test_one_assessment_per_exact_grant(self):
        self.assertEqual(self.executor.execute(self.raw(), self.context())["result"], "ACCEPTED")
        second = self.raw("a3000000-0000-4000-8000-000000000024", "phase5b-open-oia-0002", "a3000000-0000-4000-8000-000000000025")
        self.assertEqual(self.executor.execute(second, self.context())["result"], "REJECTED")
        self.assertEqual((len(self.store.oia_assessments), len(self.store.events), len(self.store.outbox)), (1, 1, 1))

    def move_grant_to_other_tenant(self):
        grant = self.store.grants.pop((self.tenant, self.grant_id))
        grant["tenant_id"] = self.other_tenant
        self.store.grants[(self.other_tenant, self.grant_id)] = grant

    def test_current_authority_failures_are_fail_closed(self):
        cases = (
            ("missing-engagement", lambda: self.store.engagements.pop(self.engagement_id)),
            ("scope-not-approved", lambda: self.store.scopes[self.scope_id].update(status="REVIEW_PENDING")),
            ("scope-version-mismatch", lambda: self.store.scopes[self.scope_id].update(scope_version=2)),
            ("missing-agreement", lambda: self.store.agreements.pop(self.agreement_id)),
            ("missing-payment", lambda: self.store.payments.pop(self.payment_id)),
            ("invalid-payment", lambda: self.store.payments[self.payment_id].update(verification_status="INVALIDATED")),
            ("exact-expiry", lambda: self.store.grants[(self.tenant, self.grant_id)].update(expires_at=self.now)),
            ("non-active-grant", lambda: self.store.grants[(self.tenant, self.grant_id)].update(status="APPROVED")),
            ("grant-other-tenant", self.move_grant_to_other_tenant),
            ("scope-digest", lambda: self.store.scopes[self.scope_id].update(canonical_scope_digest="sha256:" + "b" * 64)),
            ("agreement-ended", lambda: self.store.agreements[self.agreement_id].update(ends_at=self.now)),
        )
        for name, mutate in cases:
            with self.subTest(name=name):
                self.setUp(); mutate()
                self.assertEqual(self.executor.execute(self.raw(), self.context())["result"], "REJECTED")
                self.assert_no_oia_side_effects()

    def test_wrong_tenant_and_wrong_grant_scope_binding_reject(self):
        self.assertEqual(self.executor.execute(self.raw(), self.context(self.other_tenant))["result"], "REJECTED")
        self.assert_no_oia_side_effects()
        self.setUp()
        self.store.grants[(self.tenant, self.grant_id)]["diagnostic_scope_reference"]["reference_id"] = "a3000000-0000-4000-8000-000000000026"
        self.assertEqual(self.executor.execute(self.raw(), self.context())["result"], "REJECTED")
        self.assert_no_oia_side_effects()

    def test_contract_rejects_caller_claimed_lifecycle_truth(self):
        validator = CommandValidator(ROOT / "contracts/schemas/v1")
        for field, value in (("state", "IN_PROGRESS"), ("opened_at", self.now), ("record_version", 1), ("credentials", {})):
            raw = self.raw(); raw["payload"][field] = value
            self.assertEqual(validator.prepare(raw).reason.value, "FIELD_FORBIDDEN")


if __name__ == "__main__":
    unittest.main()
