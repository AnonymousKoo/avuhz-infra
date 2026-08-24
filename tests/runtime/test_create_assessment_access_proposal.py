import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from avuhz_runtime.assessment_access_authority import compute_assessment_access_authority_digest
from avuhz_runtime.assessment_access_proposal import AssessmentAccessProposalRejected, CreateAssessmentAccessProposalHandler
from avuhz_runtime.guards import TrustedExecutionContext
from avuhz_runtime.in_memory import MemoryStore, UnitOfWork


class CreateAssessmentAccessProposalTests(unittest.TestCase):
    def setUp(self):
        self.store = MemoryStore(); self.uow = UnitOfWork(self.store); self.tenant = "tenant"; self.now = "2030-01-15T00:00:00Z"
        self.context = TrustedExecutionContext(True, "service", "INTERNAL_SERVICE", self.tenant, None, frozenset({"assessment_access:propose"}), frozenset(), "TEST", "avuhz-command-api", "STRONG", False, self.now)
        self.uow.engagements.save({"tenant_id": self.tenant, "engagement_id": "engagement", "engagement_state": "OPEN", "record_version": 1})
        self.uow.diagnostic_scopes.save({"tenant_id": self.tenant, "engagement_id": "engagement", "diagnostic_scope_id": "scope", "scope_version": 2, "record_version": 3, "status": "APPROVED", "canonical_scope_digest": "sha256:" + "a" * 64, "action_set_version": 4, "in_scope_systems": [{"system_reference_id": "system-a"}, {"system_reference_id": "system-b"}], "permitted_diagnostic_actions": ["VIEW_CONFIGURATION", "VIEW_LOGS"]})
        self.uow.diagnostic_agreement_authorities.save({"tenant_id": self.tenant, "engagement_id": "engagement", "diagnostic_agreement_authority_id": "agreement", "record_version": 5, "status": "VERIFIED_ACTIVE", "scope_reference": {"reference_id": "scope", "reference_version": 2}, "canonical_scope_digest": "sha256:" + "a" * 64, "effective_at": "2030-01-01T00:00:00Z", "ends_at": "2030-02-01T00:00:00Z"})
        self.uow.diagnostic_payment_verifications.save({"tenant_id": self.tenant, "engagement_id": "engagement", "diagnostic_payment_verification_id": "payment", "record_version": 6, "payment_purpose": "DIAGNOSTIC_OIA", "verification_status": "VERIFIED", "diagnostic_agreement_authority_reference": {"reference_id": "agreement"}})
        self.handler = CreateAssessmentAccessProposalHandler(self.uow)
    def payload(self):
        return {"assessment_access_proposal_id": "proposal", "engagement_id": "engagement", "diagnostic_scope_id": "scope", "scope_version": 2, "diagnostic_agreement_authority_reference": {"reference_type": "DIAGNOSTIC_AGREEMENT_AUTHORITY", "reference_id": "agreement", "reference_version": 5}, "diagnostic_payment_verification_reference": {"reference_type": "DIAGNOSTIC_PAYMENT_VERIFICATION", "reference_id": "payment", "reference_version": 6}, "target_system_references": [{"system_reference_id": "system-a"}], "permitted_actions": ["VIEW_CONFIGURATION"]}
    def create(self, payload=None):
        return self.handler.create(self.context, payload or self.payload(), self.now)
    def test_creates_narrow_open_proposal_and_reads_it_back(self):
        proposal = self.create()
        self.assertEqual(proposal["status"], "OPEN"); self.assertEqual(proposal["tenant_id"], self.tenant); self.assertEqual(proposal["engagement_id"], "engagement")
        self.assertEqual(proposal["diagnostic_scope_reference"], {"reference_type": "DIAGNOSTIC_SCOPE", "reference_id": "scope", "reference_version": 2}); self.assertEqual(proposal["canonical_scope_digest"], "sha256:" + "a" * 64); self.assertEqual(proposal["action_set_version"], 4)
        self.assertEqual(proposal["target_system_references"], [{"system_reference_id": "system-a"}]); self.assertEqual(proposal["permitted_actions"], ["VIEW_CONFIGURATION"]); self.assertEqual(proposal["assessment_access_authority_digest"], compute_assessment_access_authority_digest(proposal)); self.assertEqual(self.uow.assessment_access_proposals.get(self.tenant, "proposal"), proposal)
    def test_invalidated_payment_rejects_without_proposal(self):
        self.uow.working.payments["payment"]["verification_status"] = "INVALIDATED"
        with self.assertRaises(AssessmentAccessProposalRejected): self.create()
        self.assertIsNone(self.uow.assessment_access_proposals.get(self.tenant, "proposal"))
    def test_target_or_action_widening_rejects_without_proposal(self):
        for field, value in (("target_system_references", [{"system_reference_id": "outside"}]), ("permitted_actions", ["VIEW_METRICS"])):
            with self.subTest(field=field):
                payload = self.payload(); payload[field] = value
                with self.assertRaises(AssessmentAccessProposalRejected): self.create(payload)
                self.assertIsNone(self.uow.assessment_access_proposals.get(self.tenant, "proposal"))
    def test_conflicting_identity_does_not_overwrite_original(self):
        original = self.create(); conflicting = copy.deepcopy(self.payload()); conflicting["permitted_actions"] = ["VIEW_LOGS"]
        with self.assertRaises(ValueError): self.create(conflicting)
        self.assertEqual(self.uow.assessment_access_proposals.get(self.tenant, "proposal"), original)


if __name__ == "__main__":
    unittest.main()
