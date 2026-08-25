import copy
import sys
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests" / "runtime")]
from avuhz_runtime.assessment_access_verification import InMemoryAssessmentAccessVerifier, VerificationFailureReason
from avuhz_runtime.guards import TrustedExecutionContext
from avuhz_runtime.in_memory import UnitOfWork
from avuhz_runtime.issue_assessment_access_grant import IssueAssessmentAccessGrantHandler
from avuhz_runtime.verify_assessment_access import AssessmentAccessVerificationRejected, VerifyAssessmentAccessHandler
from test_execute_assessment_access_approval import AssessmentApprovalExecutorTests

class CountingVerifier(InMemoryAssessmentAccessVerifier):
    def __init__(self, outcomes=None): super().__init__(outcomes); self.calls = 0
    def verify(self, request): self.calls += 1; return super().verify(request)

class VerifyAssessmentAccessTests(unittest.TestCase):
    tenant = "a3000000-0000-4000-8000-000000000002"
    proposal_id = "a3000000-0000-4000-8000-000000000012"
    grant_id = "a3000000-0000-4000-8000-000000000015"
    now = "2030-01-15T15:00:00Z"
    def context(self, tenant=None): return TrustedExecutionContext(True, "verifier", "INTERNAL_SERVICE", tenant or self.tenant, None, frozenset({"assessment_access:verify"}), frozenset(), "TEST", "avuhz-command-api", "STRONG", False, self.now)
    def setup(self):
        approval = AssessmentApprovalExecutorTests(); flow = approval.established()
        self.assertEqual(flow.x.execute(approval.raw(flow), approval.human())["result"], "ACCEPTED")
        self.assertEqual(flow.x.execute(approval.raw(flow, "assessment-approval-key-0002", "SEKINFRA_ENGAGEMENT_AUTHORITY", "b9000000-0000-4000-8000-000000000101"), approval.human("SEKINFRA_ENGAGEMENT_AUTHORITY", principal="human:sekinfra", organization="org:sekinfra"))["result"], "ACCEPTED")
        uow = UnitOfWork(flow.s); IssueAssessmentAccessGrantHandler(uow).issue(TrustedExecutionContext(True, "issuer", "INTERNAL_SERVICE", self.tenant, None, frozenset({"assessment_access:issue"}), frozenset(), "TEST", "avuhz-command-api", "STRONG", False, self.now), {"assessment_access_grant_id": self.grant_id, "assessment_access_proposal_id": self.proposal_id}, self.now)
        return uow
    def verify(self, uow, verifier=None, tenant=None): return VerifyAssessmentAccessHandler(uow, verifier or CountingVerifier()).verify(self.context(tenant), {"assessment_access_grant_id": self.grant_id}, self.now)
    def test_success_activates_with_ttl_and_immutable_authority(self):
        uow = self.setup(); before = uow.assessment_access_grants.get(self.tenant, self.grant_id); active = self.verify(uow)
        self.assertEqual((active["status"], active["verified_at"], active["active_from"], active["expires_at"]), ("ACTIVE", self.now, self.now, "2030-02-14T15:00:00Z"))
        for key in ("tenant_id", "engagement_id", "diagnostic_scope_reference", "canonical_scope_digest", "action_set_version", "diagnostic_agreement_authority_reference", "diagnostic_payment_verification_reference", "target_system_references", "permitted_actions", "assessment_access_authority_digest", "source_assessment_access_proposal_reference"): self.assertEqual(active[key], before[key])
        self.assertEqual(uow.assessment_access_proposals.get(self.tenant, self.proposal_id)["status"], "CONSUMED")
    def test_failure_partial_and_retry_leave_approved_until_success(self):
        uow = self.setup(); target = uow.assessment_access_grants.get(self.tenant, self.grant_id)["target_system_references"][-1]["system_reference_id"]
        failure = CountingVerifier({target: VerificationFailureReason.TARGET_UNAVAILABLE})
        with self.assertRaises(AssessmentAccessVerificationRejected): self.verify(uow, failure)
        self.assertEqual(failure.calls, 1); self.assertEqual(uow.assessment_access_grants.get(self.tenant, self.grant_id)["status"], "APPROVED")
        active = self.verify(uow); self.assertEqual(active["status"], "ACTIVE")
    def test_commercial_and_authority_failures_do_not_call_verifier(self):
        for failure in ("payment", "agreement", "scope"):
            uow = self.setup(); verifier = CountingVerifier()
            if failure == "payment": uow.working.payments["a3000000-0000-4000-8000-000000000014"]["verification_status"] = "INVALIDATED"
            if failure == "agreement": uow.working.agreements["a3000000-0000-4000-8000-000000000013"]["ends_at"] = "2030-01-15T14:00:00Z"
            if failure == "scope": uow.working.scopes["a3000000-0000-4000-8000-000000000005"]["canonical_scope_digest"] = "sha256:" + "b" * 64
            with self.assertRaises(AssessmentAccessVerificationRejected): self.verify(uow, verifier)
            self.assertEqual(verifier.calls, 0); self.assertEqual(uow.assessment_access_grants.get(self.tenant, self.grant_id)["status"], "APPROVED")
    def test_earlier_end_nonapproved_and_wrong_tenant_reject(self):
        uow = self.setup(); uow.working.agreements["a3000000-0000-4000-8000-000000000013"]["ends_at"] = "2030-01-20T00:00:00Z"
        self.assertEqual(self.verify(uow)["expires_at"], "2030-01-20T00:00:00Z")
        with self.assertRaises(AssessmentAccessVerificationRejected): self.verify(uow)
        other = self.setup()
