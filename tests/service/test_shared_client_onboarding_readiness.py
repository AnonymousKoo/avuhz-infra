"""Shared-client onboarding plan is actionable without granting any authority."""
from __future__ import annotations

from dataclasses import fields, replace
import unittest

from avuhz_service.shared_client_onboarding_readiness import (
    ClientOnboardingObservation,
    SharedClientOnboardingReadinessUnavailable,
    review_shared_client_onboarding, source_only_platform_observation,
)

HOSTED = "DEVELOPMENT_VERIFIED"
LOCAL = "LOCAL_TESTED"
ABSENT = "NOT_READY"
UNKNOWN = "UNKNOWN"


class SharedClientOnboardingReadinessTests(unittest.TestCase):
    def setUp(self):
        self.platform = source_only_platform_observation()
        self.empty = ClientOnboardingObservation()

    _NOT_PASSED = object()

    def review(self, client=None, paid=False, status=_NOT_PASSED):
        return review_shared_client_onboarding(
            self.empty if client is None else client,
            platform_status=self.platform if status is self._NOT_PASSED else status,
            paid_pilot=paid,
        )

    def test_no_client_selected_still_yields_platform_next_move(self):
        result = self.review()
        self.assertEqual(result.business_stage, "NO_CLIENT_SELECTED")
        self.assertEqual(result.next_business_action, "CONTINUE_PROSPECT_DISCOVERY")
        self.assertEqual(result.next_platform_action, "CERTIFY_SHARED_ACQUISITION_RUNTIME")
        self.assertEqual(len(result.platform_gates), 7)
        self.assertEqual(sum(g.sufficient_hosted_evidence_reported for g in result.platform_gates), 0)
        self.assertTrue(all(g.observed_status in (LOCAL, ABSENT) for g in result.platform_gates))
        self.assertFalse(result.authorized_to_open_hosted_intake)
        self.assertFalse(result.authorized_to_send)

    def test_shared_services_can_progress_without_selecting_customer(self):
        status = {key: HOSTED for key in self.platform}
        result = self.review(status=status)
        self.assertEqual(result.business_stage, "NO_CLIENT_SELECTED")
        self.assertEqual(result.next_platform_action, "REVIEW_SEPARATE_HOSTED_PILOT_AUTHORIZATION")
        self.assertTrue(all(g.sufficient_hosted_evidence_reported for g in result.platform_gates))
        self.assertTrue(all(not getattr(result, f.name) for f in fields(result) if f.name.startswith("authorized_to_")))

    def test_two_different_clients_same_backbone_no_vertical_names(self):
        clients = (
            ClientOnboardingObservation(business_reference="business.fictional-alpha"),
            ClientOnboardingObservation(business_reference="business.fictional-beta"),
        )
        result = [self.review(c) for c in clients]
        self.assertEqual(result[0], result[1])
        self.assertEqual(result[0].business_stage, "OWNER_VERIFICATION_PENDING")
        self.assertEqual(result[0].next_business_action, "VERIFY_INDEPENDENT_BUSINESS_AUTHORITY")
        self.assertNotIn("fictional-alpha", repr(result))
        self.assertNotIn("fictional-beta", repr(result))

    def test_local_mfa_and_independent_owner_proof_not_hosted(self):
        for property_name in ("independent_business_authority", "owner_auth_mfa"):
            with self.subTest(property_name=property_name):
                c = ClientOnboardingObservation(
                    business_reference="business.test", independent_business_authority=HOSTED,
                    owner_auth_mfa=HOSTED,
                )
                c = replace(c, **{property_name: LOCAL})
                actual = self.review(c)
                self.assertEqual(actual.business_stage, "OWNER_VERIFICATION_PENDING")
                self.assertTrue(actual.next_business_action.startswith("VERIFY_"))

    def test_pending_registration_never_infers_active(self):
        c = ClientOnboardingObservation(
            business_reference="business.test",
            independent_business_authority=HOSTED,
            owner_auth_mfa=HOSTED,
            organization_state="PENDING_VERIFICATION",
            owner_membership_state="PENDING_VERIFICATION",
        )
        result = self.review(c)
        self.assertEqual(result.business_stage, "ACTIVATION_PENDING")
        self.assertEqual(result.next_business_action, "REVIEW_SEPARATE_ACTIVE_TRANSITION")
        self.assertFalse(result.authorized_to_activate)

    def test_no_tenant_then_active_requires_separate_steps(self):
        c = ClientOnboardingObservation(
            business_reference="business.test",
            independent_business_authority=HOSTED, owner_auth_mfa=HOSTED,
        )
        self.assertEqual(self.review(c).business_stage, "ENROLLMENT_PENDING")
        self.assertEqual(
            self.review(c).next_business_action,
            "REVIEW_PENDING_TENANT_REGISTRATION",
        )
        active = replace(c, organization_state="ACTIVE", owner_membership_state="ACTIVE")
        result = self.review(active)
        self.assertEqual(result.business_stage, "PRINCIPAL_BINDING_PENDING")
        self.assertFalse(result.authorized_to_register)

    def test_inconsistent_tenant_owner_state_fails_closed(self):
        c = ClientOnboardingObservation(
            business_reference="business.test",
            independent_business_authority=HOSTED, owner_auth_mfa=HOSTED,
        )
        for org, owner in (
            ("ACTIVE", "PENDING_VERIFICATION"),
            ("PENDING_VERIFICATION", "ACTIVE"),
            ("ACTIVE", "NONE"),
            ("UNKNOWN", "UNKNOWN"),
            ("NONE", "ACTIVE"),
        ):
            with self.subTest(org=org, owner=owner):
                result = self.review(replace(c,
                    organization_state=org, owner_membership_state=owner))
                self.assertEqual(result.business_stage, "RECONCILIATION_REQUIRED")
                self.assertEqual(
                    result.next_business_action,
                    "RECONCILE_TENANT_AND_OWNER_STATES",
                )

    def test_principal_binding_and_pilot_are_distinct(self):
        c = ClientOnboardingObservation(
            business_reference="business.test", independent_business_authority=HOSTED,
            owner_auth_mfa=HOSTED, organization_state="ACTIVE", owner_membership_state="ACTIVE",
        )
        self.assertEqual(self.review(c).next_business_action,
                         "VERIFY_INDEPENDENT_SIGNED_PRINCIPAL_BINDING")
        c=replace(c,signed_principal_binding=HOSTED)
        self.assertEqual(self.review(c).next_business_action,
                         "REVIEW_CONTROLLED_PILOT_CUTOVER")
        c=replace(c,pilot_approval=HOSTED)
        result=self.review(c)
        self.assertEqual(result.next_business_action,"REVERIFY_OWNER_AND_PILOT_SCOPE")
        for f in fields(result):
            if f.name.startswith("authorized_to_"):
                self.assertFalse(getattr(result,f.name))

    def test_stages_fail_closed_in_canonical_order(self):
        expected = (
            ("ACQUISITION_RUNTIME", "CERTIFY_SHARED_ACQUISITION_RUNTIME"),
            ("TRUSTED_INGRESS", "CERTIFY_SHARED_HTTPS_INGRESS"),
            ("N8N_RECEIPT", "CERTIFY_SHARED_N8N_RECEIPT"),
            ("WORK_ITEM_WRITER", "CERTIFY_SHARED_WORK_ITEM_WRITER"),
            ("DUE_REVIEW", "CERTIFY_SHARED_DUE_REVIEW"),
            ("BOOKING_CONFIRMATION", "CERTIFY_BOOKING_CONFIRMATIONS"),
            ("CUSTOMER_COMMUNICATION", "CERTIFY_SHARED_CUSTOMER_COMMUNICATION"),
        )
        status={key:ABSENT for key in self.platform}
        for name, next_step in expected:
            with self.subTest(name=name):
                report=self.review(status=status)
                self.assertEqual(report.next_platform_action,next_step)
                status[name]=HOSTED
        self.assertEqual(
            self.review(status=status).next_platform_action,
            "REVIEW_SEPARATE_HOSTED_PILOT_AUTHORIZATION",
        )

    def test_paid_pilot_requires_shared_billing_but_unpaid_does_not(self):
        status={key:HOSTED for key in self.platform}
        status["SHARED_BILLING"]=ABSENT
        unpaid=self.review(status=status)
        self.assertEqual(len(unpaid.platform_gates),7)
        self.assertEqual(unpaid.next_platform_action,"REVIEW_SEPARATE_HOSTED_PILOT_AUTHORIZATION")
        paid=self.review(status=status,paid=True)
        self.assertEqual(len(paid.platform_gates),8)
        self.assertEqual(paid.next_platform_action,"CERTIFY_SHARED_BILLING")
        self.assertFalse(paid.authorized_to_bill)

    def test_invalid_business_reference_and_secret_shaped_strings_rejected(self):
        for ref in (
            "", "SEKINFRA", "a", "full@email.example", "Business With Spaces",
            "a"*129, True, [], {"tenant_id":"user-supplied"},
        ):
            with self.subTest(ref=repr(ref)):
                with self.assertRaises(SharedClientOnboardingReadinessUnavailable):
                    ClientOnboardingObservation(business_reference=ref)

    def test_clientless_progress_claim_rejected(self):
        for value in (
            {"owner_auth_mfa": HOSTED},
            {"pilot_approval": LOCAL},
            {"organization_state": "ACTIVE"},
            {"owner_membership_state": "ACTIVE"},
            {"independent_business_authority": ABSENT},
        ):
            with self.subTest(value=value):
                with self.assertRaises(SharedClientOnboardingReadinessUnavailable):
                    ClientOnboardingObservation(**value)

    def test_invalid_gate_observations_deny_without_reporting_completion(self):
        tests=(
            ([],False),(None,False),({},False),
            ({"TRUSTED_INGRESS":HOSTED},False),
            ({**self.platform, "NEW_VERTICAL_BILLING": HOSTED},False),
            ({**self.platform,"SHARED_BILLING":True},False),
            ({**self.platform,"SHARED_BILLING":"COMPLETE"},False),
            (self.platform, "yes"),
        )
        for status, paid in tests:
            with self.subTest(status=type(status).__name__,paid=paid):
                with self.assertRaises(SharedClientOnboardingReadinessUnavailable):
                    self.review(status=status,paid=paid)

    def test_source_demo_is_conservative(self):
        current=source_only_platform_observation()
        self.assertTrue(current)
        self.assertNotIn(HOSTED, current.values())
        self.assertEqual(current["BOOKING_CONFIRMATION"],ABSENT)
        self.assertEqual(current["CUSTOMER_COMMUNICATION"],ABSENT)
        self.assertEqual(current["SHARED_BILLING"],ABSENT)


if __name__ == "__main__":
    unittest.main()
