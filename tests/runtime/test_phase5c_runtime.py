"""Complete in-memory Phase 5C authority-chain and security-negative coverage."""
from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_runtime.guards import GuardPipeline, TrustedExecutionContext
from avuhz_runtime.in_memory import Executor, UnitOfWork
from avuhz_runtime.phase5c import (
    PHASE5C_CAPABILITIES,
    PROHIBITED_CHANGE_ACTIONS,
    Phase5CReadService,
    ongoing_access_authorizes_action,
    ongoing_access_usability,
)
from avuhz_runtime.schema_registry import SchemaRegistry
from avuhz_runtime.validation import CommandValidator
from tests.runtime import test_oia_findings_delivery as delivery_module


class Phase5CRuntimeTests(unittest.TestCase):
    conversion_id = "c5100000-0000-4000-8000-000000000001"
    agreement_id = "c5100000-0000-4000-8000-000000000002"
    payment_id = "c5100000-0000-4000-8000-000000000003"
    ongoing_grant_id = "c5100000-0000-4000-8000-000000000004"
    offboarding_id = "c5100000-0000-4000-8000-000000000005"
    revocation_id = "c5100000-0000-4000-8000-000000000006"
    later = "2030-02-15T15:00:00Z"

    def setUp(self):
        base = delivery_module.OIAFindingsDeliveryRuntimeTests()
        base.setUp(); base.ready(); base.deliver()
        self.base = base
        self.store = base.store
        self.store.events.clear(); self.store.outbox.clear(); self.store.idempotency.clear()
        self._number = 100
        self.executor = Executor(
            CommandValidator(ROOT / "contracts/schemas/v1"), GuardPipeline(), self.store,
            clock=lambda: self.now, ids=self.next_id,
        )

    def next_id(self):
        self._number += 1
        return f"c5190000-0000-4000-8000-{self._number:012d}"

    @property
    def tenant(self): return self.base.tenant
    @property
    def engagement_id(self): return self.base.engagement_id
    @property
    def assessment_id(self): return self.base.assessment_id
    @property
    def delivery_id(self): return self.base.delivery_id
    @property
    def finding_id(self): return self.base.finding_id
    @property
    def diagnostic_grant_id(self): return self.base.grant_id
    @property
    def now(self): return self.base.now

    def context(self, command, caller_type=None, role=None, tenant=None, principal=None):
        human_commands = {
            "RecordOIAConversionDecision", "AcceptOIAConversion",
            "RecordOngoingAgreementApproval", "TerminateOngoingAgreement",
            "RecordOngoingAccessApproval", "InitiateOngoingOffboarding",
        }
        caller_type = caller_type or ("HUMAN" if command in human_commands else "INTERNAL_SERVICE")
        principal = principal or (
            "human.client-authority" if role == "CLIENT_DECISION_AUTHORITY"
            else "human.sekinfra-authority" if caller_type == "HUMAN"
            else "service.phase5c-command"
        )
        human = caller_type == "HUMAN"
        return TrustedExecutionContext(
            True, principal, caller_type, tenant or self.tenant, None,
            frozenset({PHASE5C_CAPABILITIES[command]}), frozenset({role} if role else ()),
            "TEST", "avuhz-command-api", "STRONG", False,
            "2030-01-15T14:00:00Z", "2030-03-15T16:00:00Z",
            principal if human else None, "organization.client" if role == "CLIENT_DECISION_AUTHORITY" else "organization.sekinfra" if human else None,
            role,
        )

    def raw(self, command, payload, *, expected=None, key=None, command_id=None,
            caller_type=None, tenant=None, engagement=None):
        subject_type = {
            "RecordOIAConversionDecision": "OIA_CONVERSION_DECISION", "AcceptOIAConversion": "OIA_CONVERSION_DECISION",
            "ProposeOngoingAgreement": "ONGOING_AGREEMENT_AUTHORITY", "RecordOngoingAgreementApproval": "ONGOING_AGREEMENT_AUTHORITY",
            "ActivateOngoingAgreement": "ONGOING_AGREEMENT_AUTHORITY", "TerminateOngoingAgreement": "ONGOING_AGREEMENT_AUTHORITY",
            "RecordOngoingPaymentVerification": "ONGOING_PAYMENT_VERIFICATION", "InvalidateOngoingPaymentVerification": "ONGOING_PAYMENT_VERIFICATION",
            "ProposeOngoingAccessGrant": "ONGOING_ACCESS_GRANT", "RecordOngoingAccessApproval": "ONGOING_ACCESS_GRANT",
            "ApproveOngoingAccessGrant": "ONGOING_ACCESS_GRANT", "VerifyOngoingAccess": "ONGOING_ACCESS_GRANT",
            "RevokeOngoingAccess": "ONGOING_ACCESS_GRANT", "CloseOngoingAccess": "ONGOING_ACCESS_GRANT",
            "InitiateOngoingOffboarding": "ONGOING_OFFBOARDING", "CompleteOngoingOffboarding": "ONGOING_OFFBOARDING",
            "VerifyOngoingAccessRevocation": "ONGOING_ACCESS_REVOCATION_VERIFICATION",
        }[command]
        identity_field = {
            "OIA_CONVERSION_DECISION": "oia_conversion_decision_id",
            "ONGOING_AGREEMENT_AUTHORITY": "ongoing_agreement_authority_id",
            "ONGOING_PAYMENT_VERIFICATION": "ongoing_payment_verification_id",
            "ONGOING_ACCESS_GRANT": "ongoing_access_grant_id",
            "ONGOING_OFFBOARDING": "ongoing_offboarding_id",
            "ONGOING_ACCESS_REVOCATION_VERIFICATION": "ongoing_access_revocation_verification_id",
        }[subject_type]
        schema = {
            "RecordOIAConversionDecision": "record-oia-conversion-decision", "AcceptOIAConversion": "accept-oia-conversion",
            "ProposeOngoingAgreement": "propose-ongoing-agreement", "RecordOngoingAgreementApproval": "record-ongoing-agreement-approval",
            "ActivateOngoingAgreement": "activate-ongoing-agreement", "TerminateOngoingAgreement": "terminate-ongoing-agreement",
            "RecordOngoingPaymentVerification": "record-ongoing-payment-verification", "InvalidateOngoingPaymentVerification": "invalidate-ongoing-payment-verification",
            "ProposeOngoingAccessGrant": "propose-ongoing-access-grant", "RecordOngoingAccessApproval": "record-ongoing-access-approval",
            "ApproveOngoingAccessGrant": "approve-ongoing-access-grant", "VerifyOngoingAccess": "verify-ongoing-access",
            "RevokeOngoingAccess": "revoke-ongoing-access", "CloseOngoingAccess": "close-ongoing-access",
            "InitiateOngoingOffboarding": "initiate-ongoing-offboarding", "VerifyOngoingAccessRevocation": "verify-ongoing-access-revocation",
            "CompleteOngoingOffboarding": "complete-ongoing-offboarding",
        }[command]
        caller_type = caller_type or ("HUMAN" if command in {
            "RecordOIAConversionDecision", "AcceptOIAConversion", "RecordOngoingAgreementApproval",
            "TerminateOngoingAgreement", "RecordOngoingAccessApproval", "InitiateOngoingOffboarding"
        } else "INTERNAL_SERVICE")
        tenant = tenant or self.tenant
        value = {
            "command_id": command_id or self.next_id(), "command_type": command,
            "command_schema_version": 1, "tenant_id": tenant,
            "engagement_id": engagement or self.engagement_id, "subject_type": subject_type,
            "subject_id": payload[identity_field], "requested_by": "trusted.phase5c",
            "caller_type": caller_type,
            "caller_identity": {
                "subject": "trusted.phase5c", "audience": "avuhz-command-api", "caller_type": caller_type,
                "tenant_ids": [tenant], "capabilities": [PHASE5C_CAPABILITIES[command]],
                "environment": "TEST", "authentication_strength": "STRONG",
                "step_up_performed": False, "authenticated_at": "2030-01-15T14:00:00Z",
                "expires_at": "2030-03-15T16:00:00Z",
            },
            "correlation_id": "c5100000-0000-4000-8000-000000000090",
            "idempotency_key": key or f"phase5c-{command.lower()}-0001",
            "requested_at": self.now, "environment": "TEST",
            "payload_schema": f"urn:avuhz:schema:contracts:commands:{schema}-payload:v1",
            "payload_version": 1, "payload": copy.deepcopy(payload),
        }
        if expected is not None: value["expected_record_version"] = expected
        return value

    def execute(self, command, payload, *, expected=None, role=None, caller_type=None, key=None, command_id=None):
        raw = self.raw(command, payload, expected=expected, caller_type=caller_type, key=key, command_id=command_id)
        result = self.executor.execute(raw, self.context(command, caller_type, role))
        self.assertEqual(result["result"], "ACCEPTED", (command, result))
        return raw

    def delivery_finding(self):
        return copy.deepcopy(UnitOfWork(self.store).oia_findings_deliveries.get(self.tenant, self.delivery_id)["finding_revisions"][0])

    def convert(self, decision="PROCEED"):
        selected = [self.delivery_finding()] if decision == "PROCEED" else []
        self.execute("RecordOIAConversionDecision", {
            "oia_conversion_decision_id": self.conversion_id, "decision_version": 1,
            "oia_assessment_id": self.assessment_id, "oia_findings_delivery_id": self.delivery_id,
            "decision": decision, "selected_finding_revisions": selected,
        }, role="CLIENT_DECISION_AUTHORITY")
        if decision == "PROCEED":
            self.execute("AcceptOIAConversion", {"oia_conversion_decision_id": self.conversion_id, "decision_version": 1}, expected=1, role="SEKINFRA_ENGAGEMENT_AUTHORITY")

    def activate_agreement(self):
        scope = {
            "selected_finding_revisions": [self.delivery_finding()],
            "intervention_categories": ["PROCESS_CHANGE"], "service_areas": ["fictional.operations"],
            "target_system_references": [{"resource_reference_id": "fictional.target"}],
            "commercial_boundaries": ["Bounded fictional ongoing services."],
            "explicit_exclusions": ["Implementation and deployment are excluded."],
        }
        self.execute("ProposeOngoingAgreement", {
            "ongoing_agreement_authority_id": self.agreement_id, "agreement_version": 1,
            "oia_conversion_decision_id": self.conversion_id, "decision_version": 1,
            "agreement_reference": "agreement.fictional.v1", "service_scope": scope,
            "effective_at": self.now, "ends_at": self.later,
        })
        for role, suffix in (("CLIENT_DECISION_AUTHORITY", "client"), ("SEKINFRA_ENGAGEMENT_AUTHORITY", "sekinfra")):
            self.execute("RecordOngoingAgreementApproval", {
                "ongoing_agreement_authority_id": self.agreement_id, "agreement_version": 1,
                "authority_role": role,
            }, expected=1, role=role, key=f"phase5c-agreement-approval-{suffix}-0001")
        self.execute("ActivateOngoingAgreement", {
            "ongoing_agreement_authority_id": self.agreement_id, "agreement_version": 1,
        }, expected=1)

    def verify_payment(self):
        self.execute("RecordOngoingPaymentVerification", {
            "ongoing_payment_verification_id": self.payment_id,
            "ongoing_agreement_authority_id": self.agreement_id, "agreement_version": 1,
            "verification_basis": "APPROVED_COMMERCIAL_COVERAGE", "coverage_from": self.now,
            "coverage_until": self.later, "verification_reference": "commercial.fictional.coverage",
        })

    def activate_access(self):
        self.execute("ProposeOngoingAccessGrant", {
            "ongoing_access_grant_id": self.ongoing_grant_id,
            "ongoing_agreement_authority_id": self.agreement_id, "agreement_version": 1,
            "ongoing_payment_verification_id": self.payment_id,
            "target_resource_references": [{"resource_reference_id": "fictional.target"}],
            "access_channel_reference": "channel.fictional", "effective_at": self.now,
            "review_at": "2030-02-01T15:00:00Z", "expires_at": self.later,
        })
        for role, suffix in (("CLIENT_DECISION_AUTHORITY", "client"), ("SEKINFRA_ENGAGEMENT_AUTHORITY", "sekinfra")):
            self.execute("RecordOngoingAccessApproval", {
                "ongoing_access_grant_id": self.ongoing_grant_id, "authority_role": role,
            }, expected=1, role=role, key=f"phase5c-access-approval-{suffix}-0001")
        self.execute("ApproveOngoingAccessGrant", {"ongoing_access_grant_id": self.ongoing_grant_id}, expected=1)
        self.execute("VerifyOngoingAccess", {"ongoing_access_grant_id": self.ongoing_grant_id}, expected=2)

    def build_active(self):
        self.convert(); self.activate_agreement(); self.verify_payment(); self.activate_access()

    def test_complete_governed_progression_and_all_reads(self):
        self.build_active()
        uow = UnitOfWork(self.store)
        conversion = uow.oia_conversion_decisions.get_version(self.tenant, self.conversion_id, 1)
        agreement = uow.ongoing_agreement_authorities.get_version(self.tenant, self.agreement_id, 1)
        payment = uow.ongoing_payment_verifications.get(self.tenant, self.payment_id)
        grant = uow.ongoing_access_grants.get(self.tenant, self.ongoing_grant_id)
        self.assertEqual((conversion["state"], agreement["state"], payment["status"], grant["state"]), ("ACCEPTED", "ACTIVE", "VERIFIED", "ACTIVE"))
        self.assertNotEqual(self.ongoing_grant_id, self.diagnostic_grant_id)
        self.assertTrue(ongoing_access_usability(uow, self.tenant, self.ongoing_grant_id, self.now, "fictional.target")["usable"])
        self.assertTrue(all(not ongoing_access_authorizes_action(grant, action) for action in PROHIBITED_CHANGE_ACTIONS))
        reads = Phase5CReadService(uow)
        values = (
            ("oia-conversion-status-view", reads.conversion_status(self.tenant, self.conversion_id, 1, self.now)),
            ("ongoing-agreement-authority-view", reads.agreement_authority(self.tenant, self.agreement_id, 1, self.now)),
            ("ongoing-commercial-authority-view", reads.commercial_authority(self.tenant, self.payment_id, self.now)),
            ("ongoing-access-status-view", reads.access_status(self.tenant, self.ongoing_grant_id, self.now)),
            ("ongoing-engagement-eligibility-view", reads.eligibility(self.tenant, self.engagement_id, self.now)),
            ("phase5c-authority-progression-view", reads.progression(self.tenant, self.engagement_id, self.now)),
        )
        registry = SchemaRegistry(ROOT / "contracts/schemas/v1")
        formatter = FormatChecker(); formatter.checks("date-time")(lambda value: isinstance(value, str) and value.endswith("Z"))
        for name, value in values:
            schema = registry.expanded(f"urn:avuhz:schema:contracts:read-models:{name}:v1")
            self.assertFalse(list(Draft202012Validator(schema, format_checker=formatter).iter_errors(value)), name)
        self.assertEqual(len(self.store.events), 12)
        self.assertEqual(len(self.store.events), len(self.store.outbox))
        event_schema = registry.expanded("urn:avuhz:schema:contracts:orchestration:lifecycle-event:v1")
        for event in self.store.events:
            self.assertFalse(list(Draft202012Validator(event_schema, format_checker=formatter).iter_errors(event)), event["event_type"])

    def test_decline_is_terminal_and_creates_no_ongoing_authority(self):
        self.convert("DECLINE")
        uow = UnitOfWork(self.store)
        conversion = uow.oia_conversion_decisions.get_version(self.tenant, self.conversion_id, 1)
        self.assertEqual(conversion["state"], "DECLINED")
        self.assertFalse(self.store.ongoing_agreement_authorities)
        self.assertFalse(self.store.ongoing_payment_verifications)
        self.assertFalse(self.store.ongoing_access_grants)
        raw = self.raw("AcceptOIAConversion", {"oia_conversion_decision_id": self.conversion_id, "decision_version": 1}, expected=1)
        result = self.executor.execute(raw, self.context("AcceptOIAConversion", role="SEKINFRA_ENGAGEMENT_AUTHORITY"))
        self.assertEqual(result["result"], "REJECTED")

        self.execute("InitiateOngoingOffboarding", {
            "ongoing_offboarding_id": self.offboarding_id,
            "oia_conversion_decision_id": self.conversion_id,
            "decision_version": 1,
            "reason": "CONVERSION_DECLINED",
            "ongoing_access_grant_ids": [],
        }, role="CLIENT_DECISION_AUTHORITY")
        initiated = UnitOfWork(self.store).ongoing_offboardings.get(self.tenant, self.offboarding_id)
        self.assertEqual((initiated["state"], initiated["access_revocation_required"]),
                         ("INITIATED", False))
        self.execute("CompleteOngoingOffboarding", {
            "ongoing_offboarding_id": self.offboarding_id,
        }, expected=1)
        completed = UnitOfWork(self.store).ongoing_offboardings.get(self.tenant, self.offboarding_id)
        self.assertEqual(completed["state"], "COMPLETED")
    def test_commercial_invalidation_is_immediate_and_close_is_reconciliatory(self):
        self.build_active()
        self.execute("InvalidateOngoingPaymentVerification", {
            "ongoing_payment_verification_id": self.payment_id, "invalidation_reason": "VERIFICATION_REVOKED",
        }, expected=1)
        uow = UnitOfWork(self.store)
        self.assertFalse(ongoing_access_usability(uow, self.tenant, self.ongoing_grant_id, self.now)["usable"])
        grant_before = copy.deepcopy(uow.ongoing_access_grants.get(self.tenant, self.ongoing_grant_id))
        self.assertEqual(grant_before["state"], "ACTIVE")
        self.execute("CloseOngoingAccess", {
            "ongoing_access_grant_id": self.ongoing_grant_id,
            "closure_reason": "COMMERCIAL_AUTHORITY_INVALID",
            "closure_source_reference": {"reference_type": "ONGOING_PAYMENT_VERIFICATION", "reference_id": self.payment_id, "reference_version": 2},
        }, expected=3)
        closed = UnitOfWork(self.store).ongoing_access_grants.get(self.tenant, self.ongoing_grant_id)
        self.assertEqual((closed["state"], closed["record_version"]), ("CLOSED", 4))
        for key in ("conversion_decision_reference", "ongoing_agreement_reference", "ongoing_payment_verification_reference", "active_from"):
            self.assertEqual(closed[key], grant_before[key])

    def test_manual_revocation_offboarding_and_external_verification_are_distinct_and_durable(self):
        self.build_active()
        self.execute("RevokeOngoingAccess", {
            "ongoing_access_grant_id": self.ongoing_grant_id,
            "revocation_reason": "EMERGENCY_SECURITY_REVOCATION",
        }, expected=3, role="SEKINFRA_ENGAGEMENT_AUTHORITY", caller_type="HUMAN")
        self.assertFalse(ongoing_access_usability(UnitOfWork(self.store), self.tenant, self.ongoing_grant_id, self.now)["usable"])
        self.execute("InitiateOngoingOffboarding", {
            "ongoing_offboarding_id": self.offboarding_id,
            "oia_conversion_decision_id": self.conversion_id, "decision_version": 1,
            "ongoing_agreement_authority_id": self.agreement_id, "agreement_version": 1,
            "reason": "ENGAGEMENT_COMPLETED", "ongoing_access_grant_ids": [self.ongoing_grant_id],
        }, role="SEKINFRA_ENGAGEMENT_AUTHORITY")
        self.assertEqual(UnitOfWork(self.store).ongoing_offboardings.get(self.tenant, self.offboarding_id)["revocation_verification_references"], [])
        self.execute("VerifyOngoingAccessRevocation", {
            "ongoing_access_revocation_verification_id": self.revocation_id,
            "ongoing_access_grant_id": self.ongoing_grant_id, "ongoing_offboarding_id": self.offboarding_id,
        }, expected=4)
        self.execute("CompleteOngoingOffboarding", {"ongoing_offboarding_id": self.offboarding_id}, expected=1)
        uow = UnitOfWork(self.store)
        offboarding = uow.ongoing_offboardings.get(self.tenant, self.offboarding_id)
        verification = uow.ongoing_access_revocation_verifications.get(self.tenant, self.revocation_id)
        self.assertEqual((offboarding["state"], verification["record_version"]), ("COMPLETED", 1))
        status = Phase5CReadService(uow).offboarding_status(self.tenant, self.offboarding_id, self.now)
        self.assertTrue(status["access_revocation_verified"])
        self.assertFalse(Phase5CReadService(uow).eligibility(self.tenant, self.engagement_id, self.now)["eligible_for_ongoing_work"])
        self.assertTrue(self.store.oia_findings_deliveries)
        self.assertTrue(self.store.oia_findings)
        self.assertTrue(self.store.ongoing_agreement_authorities)
        self.assertTrue(self.store.ongoing_payment_verifications)
        self.assertTrue(self.store.ongoing_access_grants)
        self.assertTrue(self.store.events)

    def test_agreement_termination_immediately_invalidates_active_access(self):
        self.build_active()
        self.execute("TerminateOngoingAgreement", {
            "ongoing_agreement_authority_id": self.agreement_id,
            "agreement_version": 1,
            "termination_reason": "CLIENT_TERMINATION",
        }, expected=2, role="CLIENT_DECISION_AUTHORITY")
        uow = UnitOfWork(self.store)
        agreement = uow.ongoing_agreement_authorities.get_version(self.tenant, self.agreement_id, 1)
        grant = uow.ongoing_access_grants.get(self.tenant, self.ongoing_grant_id)
        self.assertEqual((agreement["state"], grant["state"]), ("TERMINATED", "ACTIVE"))
        self.assertFalse(ongoing_access_usability(uow, self.tenant, self.ongoing_grant_id, self.now)["usable"])

    def test_idempotency_stale_version_atomicity_and_security_negatives(self):
        payload = {
            "oia_conversion_decision_id": self.conversion_id, "decision_version": 1,
            "oia_assessment_id": self.assessment_id, "oia_findings_delivery_id": self.delivery_id,
            "decision": "PROCEED", "selected_finding_revisions": [self.delivery_finding()],
        }
        raw = self.raw("RecordOIAConversionDecision", payload, key="phase5c-conversion-replay-0001")
        context = self.context("RecordOIAConversionDecision", role="CLIENT_DECISION_AUTHORITY")
        self.assertEqual(self.executor.execute(raw, context)["result"], "ACCEPTED")
        before = copy.deepcopy((self.store.oia_conversion_decisions, self.store.approvals, self.store.events, self.store.outbox, self.store.idempotency))
        self.assertEqual(self.executor.execute(copy.deepcopy(raw), context)["result"], "DUPLICATE")
        changed = copy.deepcopy(raw); changed["payload"]["decision"] = "DECLINE"; changed["payload"]["selected_finding_revisions"] = []
        self.assertEqual(self.executor.execute(changed, context)["result"], "CONFLICT")
        self.assertEqual((self.store.oia_conversion_decisions, self.store.approvals, self.store.events, self.store.outbox, self.store.idempotency), before)
        stale = self.raw("AcceptOIAConversion", {"oia_conversion_decision_id": self.conversion_id, "decision_version": 1}, expected=99)
        self.assertEqual(self.executor.execute(stale, self.context("AcceptOIAConversion", role="SEKINFRA_ENGAGEMENT_AUTHORITY"))["reason_code"], "VERSION_STALE")
        for field, value in (("client_approved", True), ("implementation_design", {"steps": ["deploy"]}), ("password", "forbidden")):
            injected = copy.deepcopy(raw); injected["command_id"] = self.next_id(); injected["idempotency_key"] = f"phase5c-injection-{field}-0001"; injected["payload"][field] = value
            self.assertEqual(self.executor.execute(injected, context)["result"], "VALIDATION_FAILED")
        workload = copy.deepcopy(raw); workload["command_id"] = self.next_id(); workload["idempotency_key"] = "phase5c-workload-spoof-0001"; workload["caller_type"] = "INTERNAL_SERVICE"; workload["caller_identity"]["caller_type"] = "INTERNAL_SERVICE"
        self.assertEqual(self.executor.execute(workload, self.context("RecordOIAConversionDecision", "INTERNAL_SERVICE"))["result"], "VALIDATION_FAILED")

    def test_assessment_grant_identity_reuse_and_cross_tenant_delivery_are_denied(self):
        self.convert(); self.activate_agreement(); self.verify_payment()
        payload = {
            "ongoing_access_grant_id": self.diagnostic_grant_id,
            "ongoing_agreement_authority_id": self.agreement_id, "agreement_version": 1,
            "ongoing_payment_verification_id": self.payment_id,
            "target_resource_references": [{"resource_reference_id": "fictional.target"}],
            "access_channel_reference": "channel.fictional", "effective_at": self.now,
            "review_at": "2030-02-01T15:00:00Z", "expires_at": self.later,
        }
        raw = self.raw("ProposeOngoingAccessGrant", payload)
        self.assertEqual(self.executor.execute(raw, self.context("ProposeOngoingAccessGrant"))["result"], "REJECTED")
        self.setUp()
        other = self.base.base.base.base.base.other_tenant
        raw = self.raw("RecordOIAConversionDecision", {
            "oia_conversion_decision_id": self.conversion_id, "decision_version": 1,
            "oia_assessment_id": self.assessment_id, "oia_findings_delivery_id": self.delivery_id,
            "decision": "PROCEED", "selected_finding_revisions": [self.delivery_finding()],
        }, tenant=other)
        result = self.executor.execute(raw, self.context("RecordOIAConversionDecision", role="CLIENT_DECISION_AUTHORITY", tenant=other))
        self.assertEqual(result["result"], "REJECTED")


if __name__ == "__main__":
    unittest.main()
