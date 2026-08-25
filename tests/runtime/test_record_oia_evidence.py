import copy
import sys
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_runtime.guards import GuardPipeline, TrustedExecutionContext
from avuhz_runtime.in_memory import Executor, MemoryStore, UnitOfWork
from avuhz_runtime.schema_registry import SchemaRegistry
from avuhz_runtime.validation import CommandValidator


class RecordOIAEvidenceTests(unittest.TestCase):
    tenant = "a3000000-0000-4000-8000-000000000002"
    other_tenant = "a3000000-0000-4000-8000-000000000099"
    engagement_id = "a3000000-0000-4000-8000-000000000004"
    scope_id = "a3000000-0000-4000-8000-000000000005"
    agreement_id = "a3000000-0000-4000-8000-000000000013"
    payment_id = "a3000000-0000-4000-8000-000000000014"
    grant_id = "a3000000-0000-4000-8000-000000000015"
    assessment_id = "a3000000-0000-4000-8000-000000000020"
    evidence_id = "a3000000-0000-4000-8000-000000000031"
    now = "2030-01-15T15:00:00Z"
    captured_at = "2030-01-15T14:59:00Z"
    digest = "sha256:" + "a" * 64

    def setUp(self):
        self.store = self.authority_store()
        self.executor = Executor(
            CommandValidator(ROOT / "contracts/schemas/v1"), GuardPipeline(), self.store,
            clock=lambda: self.now, ids=lambda: "a3000000-0000-4000-8000-000000000040",
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
            "permitted_diagnostic_actions": ["VIEW_CONFIGURATION", "VIEW_METRICS"],
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
        store.oia_assessments[(self.tenant, self.assessment_id)] = {
            "tenant_id": self.tenant, "oia_assessment_id": self.assessment_id,
            "engagement_id": self.engagement_id, "diagnostic_scope_id": self.scope_id,
            "diagnostic_scope_version": 1, "canonical_scope_digest": self.digest,
            "assessment_access_grant_id": self.grant_id, "state": "IN_PROGRESS",
            "record_version": 1, "opened_at": self.now, "created_at": self.now, "updated_at": self.now,
        }
        return store

    def context(self, tenant=None, principal="workload.oia-collector", caller_type="INTERNAL_SERVICE", capability="oia:evidence:record"):
        return TrustedExecutionContext(
            True, principal, caller_type, tenant or self.tenant, None,
            frozenset({capability}), frozenset(), "TEST", "avuhz-command-api",
            "STRONG", False, "2030-01-15T14:00:00Z", "2030-01-15T16:00:00Z",
        )

    def raw(self, evidence_id=None, idempotency_key="phase5b-record-evidence-0001", command_id=None, tenant=None, assessment_id=None, **payload_updates):
        evidence_id = evidence_id or self.evidence_id
        tenant = tenant or self.tenant
        payload = {
            "oia_evidence_id": evidence_id,
            "oia_assessment_id": assessment_id or self.assessment_id,
            "source_system_reference": "system-001",
            "evidence_type": "CONFIGURATION_SNAPSHOT",
            "captured_at": self.captured_at,
            "scope_action": "VIEW_CONFIGURATION",
            "secure_object_reference": "secure-object-001",
            "content_digest": self.digest,
            "sensitivity": "RESTRICTED",
        }
        payload.update(payload_updates)
        return {
            "command_id": command_id or "a3000000-0000-4000-8000-000000000032",
            "command_type": "RecordOIAEvidence", "command_schema_version": 1,
            "tenant_id": tenant, "engagement_id": self.engagement_id,
            "subject_type": "OIA_EVIDENCE_ITEM", "subject_id": evidence_id,
            "requested_by": "workload.oia-collector", "caller_type": "INTERNAL_SERVICE",
            "caller_identity": {
                "subject": "workload.oia-collector", "audience": "avuhz-command-api",
                "caller_type": "INTERNAL_SERVICE", "tenant_ids": [tenant],
                "capabilities": ["oia:evidence:record"], "environment": "TEST",
                "authentication_strength": "STRONG", "step_up_performed": False,
                "authenticated_at": "2030-01-15T14:00:00Z", "expires_at": "2030-01-15T16:00:00Z",
            },
            "correlation_id": "a3000000-0000-4000-8000-000000000033",
            "idempotency_key": idempotency_key, "requested_at": self.now,
            "environment": "TEST",
            "payload_schema": "urn:avuhz:schema:contracts:commands:record-oia-evidence-payload:v1",
            "payload_version": 1, "payload": payload,
        }

    def invalidation_raw(self):
        return {
            "command_id": "a3000000-0000-4000-8000-000000000034",
            "command_type": "InvalidateDiagnosticPaymentVerification", "command_schema_version": 1,
            "tenant_id": self.tenant, "engagement_id": self.engagement_id,
            "subject_type": "DIAGNOSTIC_PAYMENT_VERIFICATION", "subject_id": self.payment_id,
            "requested_by": "commercial.service", "caller_type": "INTERNAL_SERVICE",
            "caller_identity": {
                "subject": "commercial.service", "audience": "avuhz-command-api",
                "caller_type": "INTERNAL_SERVICE", "tenant_ids": [self.tenant],
                "capabilities": ["diagnostic_payment:invalidate"], "environment": "TEST",
                "authentication_strength": "STRONG", "step_up_performed": False,
                "authenticated_at": "2030-01-15T14:00:00Z", "expires_at": "2030-01-15T16:00:00Z",
            },
            "correlation_id": "a3000000-0000-4000-8000-000000000035",
            "idempotency_key": "phase5b-evidence-payment-invalidate-0001", "requested_at": self.now,
            "environment": "TEST", "expected_record_version": 1,
            "payload_schema": "urn:avuhz:schema:contracts:commands:invalidate-diagnostic-payment-verification-payload:v1",
            "payload_version": 1, "payload": {"diagnostic_payment_verification_id": self.payment_id},
        }

    def assert_no_evidence_side_effects(self, existing_events=0, existing_outbox=0):
        self.assertEqual(self.store.oia_evidence_items, {})
        self.assertEqual(sum(event.get("event_type") == "oia.evidence_recorded" for event in self.store.events), 0)
        self.assertEqual((len(self.store.events), len(self.store.outbox)), (existing_events, existing_outbox))

    def test_happy_path_is_immutable_contract_representable_provenance(self):
        raw = self.raw(excerpt_character_count=512)
        self.assertEqual(self.executor.execute(raw, self.context())["result"], "ACCEPTED")
        expected = {
            "tenant_id": self.tenant, "oia_evidence_id": self.evidence_id,
            "oia_assessment_id": self.assessment_id, "source_system_reference": "system-001",
            "evidence_type": "CONFIGURATION_SNAPSHOT", "captured_at": self.captured_at,
            "captured_by": "workload.oia-collector", "scope_action": "VIEW_CONFIGURATION",
            "secure_object_reference": "secure-object-001", "content_digest": self.digest,
            "sensitivity": "RESTRICTED", "retention_status": "AVAILABLE",
            "created_at": self.now, "excerpt_character_count": 512,
        }
        self.assertEqual(self.store.oia_evidence_items[(self.tenant, self.evidence_id)], expected)
        registry = SchemaRegistry(ROOT / "contracts/schemas/v1")
        domain_validator = Draft202012Validator(registry.expanded("urn:avuhz:schema:contracts:domain:oia-evidence-item:v1"), format_checker=FormatChecker())
        self.assertEqual(list(domain_validator.iter_errors(expected)), [])
        prepared = CommandValidator(ROOT / "contracts/schemas/v1").prepare(raw).prepared
        snapshot = self.store.snapshot(prepared)
        self.assertEqual((snapshot.subject_type, snapshot.record_version, snapshot.engagement_id), ("OIA_EVIDENCE_ITEM", 1, self.engagement_id))
        event = self.store.events[-1]
        self.assertEqual(event["event_type"], "oia.evidence_recorded")
        self.assertEqual(event["authoritative_subject_reference"], {"reference_type": "OIA_EVIDENCE_ITEM", "reference_id": self.evidence_id})
        self.assertEqual(event["sanitized_metadata"], {"oia_assessment_id": self.assessment_id, "oia_evidence_id": self.evidence_id})
        event_validator = Draft202012Validator(registry.expanded("urn:avuhz:schema:contracts:orchestration:lifecycle-event:v1"), format_checker=FormatChecker())
        self.assertEqual(list(event_validator.iter_errors(event)), [])
        self.assertEqual(self.store.outbox, [{"event_id": event["event_id"], "status": "PENDING"}])
        uow = UnitOfWork(self.store)
        returned = uow.oia_evidence_items.get(self.tenant, self.evidence_id)
        returned["secure_object_reference"] = "changed"
        self.assertEqual(uow.oia_evidence_items.get(self.tenant, self.evidence_id), expected)
        self.assertFalse(hasattr(uow.oia_evidence_items, "update"))

    def test_current_access_expiry_agreement_and_terminal_states_fail_closed(self):
        cases = (
            ("exact-expiry", lambda: self.store.grants[(self.tenant, self.grant_id)].update(expires_at=self.now)),
            ("agreement-ended", lambda: self.store.agreements[self.agreement_id].update(ends_at=self.now)),
            ("terminal-grant", lambda: self.store.grants[(self.tenant, self.grant_id)].update(status="REVOKED", revoked_at=self.now)),
            ("missing-assessment", lambda: self.store.oia_assessments.pop((self.tenant, self.assessment_id))),
            ("closed-assessment", lambda: self.store.oia_assessments[(self.tenant, self.assessment_id)].update(state="CLOSED", ready_for_delivery_at=self.now, findings_delivered_at=self.now, findings_delivery_id="a3000000-0000-4000-8000-000000000036", closed_at=self.now)),
        )
        for name, mutate in cases:
            with self.subTest(name=name):
                self.setUp(); mutate()
                self.assertEqual(self.executor.execute(self.raw(), self.context())["result"], "REJECTED")
                self.assert_no_evidence_side_effects()

    def test_payment_invalidation_through_phase5a_executor_fails_closed_without_closing_assessment(self):
        invalidation_context = self.context(principal="commercial.service", capability="diagnostic_payment:invalidate")
        self.assertEqual(self.executor.execute(self.invalidation_raw(), invalidation_context)["result"], "ACCEPTED")
        self.assertEqual(self.store.payments[self.payment_id]["verification_status"], "INVALIDATED")
        self.assertEqual(self.executor.execute(self.raw(), self.context())["result"], "REJECTED")
        self.assertEqual(self.store.oia_assessments[(self.tenant, self.assessment_id)]["state"], "IN_PROGRESS")
        self.assert_no_evidence_side_effects(1, 1)

    def test_target_action_and_prohibited_action_fail_closed(self):
        wrong_target = self.raw(source_system_reference="system-999")
        self.assertEqual(self.executor.execute(wrong_target, self.context())["result"], "REJECTED")
        self.assert_no_evidence_side_effects()
        self.setUp()
        wrong_action = self.raw(scope_action="VIEW_METRICS")
        self.assertEqual(self.executor.execute(wrong_action, self.context())["result"], "REJECTED")
        self.assert_no_evidence_side_effects()
        self.setUp()
        prohibited = self.raw(scope_action="CHANGE_CONFIGURATION")
        self.assertEqual(self.executor.execute(prohibited, self.context())["result"], "VALIDATION_FAILED")
        self.assert_no_evidence_side_effects()

    def test_cross_assessment_grant_authority_cannot_be_borrowed(self):
        grant_b = "a3000000-0000-4000-8000-000000000037"
        assessment_b = "a3000000-0000-4000-8000-000000000038"
        self.store.scopes[self.scope_id]["in_scope_systems"].append({"system_reference_id": "system-002"})
        other_grant = copy.deepcopy(self.store.grants[(self.tenant, self.grant_id)])
        other_grant.update(assessment_access_grant_id=grant_b, target_system_references=[{"system_reference_id": "system-002"}])
        self.store.grants[(self.tenant, grant_b)] = other_grant
        other_assessment = copy.deepcopy(self.store.oia_assessments[(self.tenant, self.assessment_id)])
        other_assessment.update(oia_assessment_id=assessment_b, assessment_access_grant_id=grant_b)
        self.store.oia_assessments[(self.tenant, assessment_b)] = other_assessment
        attack = self.raw(source_system_reference="system-002")
        self.assertEqual(self.executor.execute(attack, self.context())["result"], "REJECTED")
        self.assert_no_evidence_side_effects()

    def test_wrong_tenant_and_untrusted_caller_fail_closed(self):
        cross_tenant = self.raw(tenant=self.other_tenant)
        self.assertEqual(self.executor.execute(cross_tenant, self.context())["result"], "REJECTED")
        self.assert_no_evidence_side_effects()
        self.setUp()
        browser = self.raw()
        browser["caller_type"] = "CLIENT_USER"
        browser["caller_identity"]["caller_type"] = "CLIENT_USER"
        browser_context = self.context(caller_type="CLIENT_USER")
        self.assertEqual(self.executor.execute(browser, browser_context)["result"], "VALIDATION_FAILED")
        self.assert_no_evidence_side_effects()

    def test_duplicate_conflict_and_resource_identity_uniqueness(self):
        raw = self.raw()
        self.assertEqual(self.executor.execute(raw, self.context())["result"], "ACCEPTED")
        self.assertEqual(self.executor.execute(copy.deepcopy(raw), self.context())["result"], "DUPLICATE")
        changed = self.raw("a3000000-0000-4000-8000-000000000039")
        self.assertEqual(self.executor.execute(changed, self.context())["result"], "CONFLICT")
        changed_engagement = copy.deepcopy(raw)
        changed_engagement["engagement_id"] = "a3000000-0000-4000-8000-000000000042"
        self.assertEqual(self.executor.execute(changed_engagement, self.context())["result"], "CONFLICT")
        same_identity_new_key = self.raw(idempotency_key="phase5b-record-evidence-0002", command_id="a3000000-0000-4000-8000-000000000041")
        self.assertEqual(self.executor.execute(same_identity_new_key, self.context())["result"], "REJECTED")
        self.assertEqual((len(self.store.oia_evidence_items), len(self.store.events), len(self.store.outbox)), (1, 1, 1))

    def test_human_interview_requires_human_and_attributes_trusted_principal(self):
        raw = self.raw(evidence_type="HUMAN_INTERVIEW_CORROBORATION")
        self.assertEqual(self.executor.execute(raw, self.context())["result"], "REJECTED")
        self.assert_no_evidence_side_effects()
        raw["caller_type"] = "HUMAN"
        raw["caller_identity"].update(subject="human.assessor-001", caller_type="HUMAN")
        human = self.context(principal="human.assessor-001", caller_type="HUMAN")
        self.assertEqual(self.executor.execute(raw, human)["result"], "ACCEPTED")
        self.assertEqual(self.store.oia_evidence_items[(self.tenant, self.evidence_id)]["captured_by"], "human.assessor-001")

    def test_schema_rejects_secrets_access_claims_and_caller_lifecycle_fields(self):
        forbidden = (
            "password", "api_key", "access_token", "authorization_header", "connection_string", "private_key",
            "assessment_access_grant_id", "grant_is_active", "payment_verified", "agreement_valid", "access_usable", "target_authorized", "action_authorized",
            "captured_by", "retention_status", "created_at", "record_version", "provider_response", "raw", "content",
        )
        for field in forbidden:
            with self.subTest(field=field):
                raw = self.raw(); raw["payload"][field] = "forbidden"
                result = self.executor.execute(raw, self.context())
                self.assertEqual((result["result"], result["reason_code"]), ("VALIDATION_FAILED", "FIELD_FORBIDDEN"))
        self.assert_no_evidence_side_effects()


if __name__ == "__main__":
    unittest.main()
