import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_runtime.assessment_access_verification import AssessmentAccessVerificationRequest, InMemoryAssessmentAccessVerifier, VerificationFailureReason

class AssessmentAccessVerifierTests(unittest.TestCase):
    def grant(self):
        return {"assessment_access_grant_id": "a3000000-0000-4000-8000-000000000015", "tenant_id": "a3000000-0000-4000-8000-000000000002", "engagement_id": "a3000000-0000-4000-8000-000000000005", "target_system_references": [{"system_reference_id": "sys:target-a"}, {"system_reference_id": "sys:target-b"}], "permitted_actions": ["VIEW_CONFIGURATION", "VIEW_LOGS"], "status": "APPROVED"}

    def test_all_targets_success_without_grant_mutation(self):
        grant = self.grant(); before = copy.deepcopy(grant)
        request = AssessmentAccessVerificationRequest.from_grant(grant)
        result = InMemoryAssessmentAccessVerifier().verify(request)
        self.assertTrue(result.success); self.assertTrue(all(target.success for target in result.target_results))
        self.assertEqual(request.permitted_actions, ("VIEW_CONFIGURATION", "VIEW_LOGS")); self.assertEqual(grant, before)
        self.assertEqual(set(request.__dict__), {"assessment_access_grant_id", "tenant_id", "engagement_id", "target_system_references", "permitted_actions"})
        self.assertNotIn("verified_at", grant); self.assertNotIn("active_from", grant); self.assertNotIn("expires_at", grant)

    def test_technical_failure_is_sanitized_and_does_not_mutate_grant(self):
        grant = self.grant(); before = copy.deepcopy(grant)
        result = InMemoryAssessmentAccessVerifier({"sys:target-a": VerificationFailureReason.AUTHENTICATION_FAILED}).verify(AssessmentAccessVerificationRequest.from_grant(grant))
        self.assertFalse(result.success)
        failure = next(target for target in result.target_results if not target.success)
        self.assertEqual(failure.failure_reason, VerificationFailureReason.AUTHENTICATION_FAILED); self.assertEqual(grant, before)
        self.assertNotIn("credentials", repr(result).lower())

    def test_partial_target_failure_is_not_overall_success(self):
        request = AssessmentAccessVerificationRequest.from_grant(self.grant())
        result = InMemoryAssessmentAccessVerifier({"sys:target-b": VerificationFailureReason.TARGET_UNAVAILABLE}).verify(request)
        self.assertFalse(result.success); self.assertEqual([target.success for target in result.target_results], [True, False])

if __name__ == "__main__":
    unittest.main()
