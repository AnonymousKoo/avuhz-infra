import copy
import sys
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from avuhz_runtime.assessment_access_approval import AssessmentAccessApprovalRejected, RecordAssessmentAccessApprovalHandler
from avuhz_runtime.guards import TrustedExecutionContext
from avuhz_runtime.in_memory import MemoryStore, UnitOfWork

class AssessmentApprovalCoreTests(unittest.TestCase):
    def setUp(self):
        self.tenant = "a3000000-0000-4000-8000-000000000002"; self.now = "2030-01-15T15:00:00Z"; self.uow = UnitOfWork(MemoryStore())
        self.proposal = {"assessment_access_proposal_id": "a3000000-0000-4000-8000-000000000012", "tenant_id": self.tenant, "engagement_id": "a3000000-0000-4000-8000-000000000004", "assessment_access_authority_digest": "sha256:" + "a" * 64, "status": "OPEN", "record_version": 1}
        self.uow.assessment_access_proposals.create(self.proposal); self.handler = RecordAssessmentAccessApprovalHandler(self.uow)
    def context(self, role="CLIENT_DECISION_AUTHORITY", caller="HUMAN", tenant=None, principal=None, organization=None):
        return TrustedExecutionContext(True, "session", caller, tenant or self.tenant, None, frozenset({"assessment_access:approve"}), frozenset(), "TEST", "avuhz-command-api", "STRONG", False, self.now, "2030-01-15T16:00:00Z", principal or "human:client", organization or "org:client", role)
    def record(self, role="CLIENT_DECISION_AUTHORITY", context=None, approval_id="a3000000-0000-4000-8000-000000000020"):
        return self.handler.record(context or self.context(role), {"assessment_access_proposal_id": self.proposal["assessment_access_proposal_id"], "authority_role": role}, self.now, approval_id, "a3000000-0000-4000-8000-000000000021", "assessment-approval-command-0001")
    def test_client_and_sekinfra_record_distinct_attributed_active_approvals(self):
        client = self.record(); sek = self.record("SEKINFRA_ENGAGEMENT_AUTHORITY", self.context("SEKINFRA_ENGAGEMENT_AUTHORITY", principal="human:sekinfra", organization="org:sekinfra"), "a3000000-0000-4000-8000-000000000022")
        self.assertEqual((client["status"], client["subject_type"], client["actor_identity"], client["actor_organization"]), ("ACTIVE", "ASSESSMENT_ACCESS_PROPOSAL", "human:client", "org:client"))
        self.assertEqual((sek["actor_role"], sek["actor_identity"], sek["actor_organization"]), ("SEKINFRA_ENGAGEMENT_AUTHORITY", "human:sekinfra", "org:sekinfra"))
        self.assertEqual(client["assessment_access"]["assessment_access_authority_digest"], self.proposal["assessment_access_authority_digest"]); self.assertEqual(sek["assessment_access"]["assessment_access_proposal_id"], self.proposal["assessment_access_proposal_id"])
        self.assertEqual(len(self.uow.working.approvals), 2); self.assertEqual(self.uow.assessment_access_proposals.get(self.tenant, self.proposal["assessment_access_proposal_id"])["status"], "OPEN")
        self.assertIsNotNone(self.uow.human_approvals.find_active_assessment_access_binding(self.tenant, self.proposal["assessment_access_proposal_id"], self.proposal["assessment_access_authority_digest"], "CLIENT_DECISION_AUTHORITY"))
    def test_rejections_leave_repositories_unchanged(self):
        cases = [("SEKINFRA_ENGAGEMENT_AUTHORITY", self.context()), ("CLIENT_DECISION_AUTHORITY", self.context(caller="INTERNAL_SERVICE")), ("CLIENT_DECISION_AUTHORITY", self.context(tenant="a3000000-0000-4000-8000-000000000099"))]
        for role, context in cases:
            with self.subTest(role=role, caller=context.caller_type):
                with self.assertRaises(AssessmentAccessApprovalRejected): self.record(role, context)
                self.assertEqual(self.uow.working.approvals, {}); self.assertEqual(self.uow.assessment_access_proposals.get(self.tenant, self.proposal["assessment_access_proposal_id"]), self.proposal)
    def test_non_open_and_duplicate_same_role_are_rejected(self):
        for status in ("SUPERSEDED", "WITHDRAWN", "CONSUMED"):
            with self.subTest(status=status):
                self.uow.working.proposals[(self.tenant, self.proposal["assessment_access_proposal_id"])]["status"] = status
                with self.assertRaises(AssessmentAccessApprovalRejected): self.record()
                self.assertEqual(self.uow.working.approvals, {})
                self.uow.working.proposals[(self.tenant, self.proposal["assessment_access_proposal_id"])]["status"] = "OPEN"
        original = self.record()
        with self.assertRaises(AssessmentAccessApprovalRejected): self.record(approval_id="a3000000-0000-4000-8000-000000000023")
        self.assertEqual(len(self.uow.working.approvals), 1); self.assertEqual(self.uow.human_approvals.get(self.tenant, original["approval_id"]), original)
    def test_identical_digest_does_not_transfer_between_proposals(self):
        other = copy.deepcopy(self.proposal); other["assessment_access_proposal_id"] = "a3000000-0000-4000-8000-000000000013"; self.uow.assessment_access_proposals.create(other)
        self.record(); payload = {"assessment_access_proposal_id": other["assessment_access_proposal_id"], "authority_role": "CLIENT_DECISION_AUTHORITY"}
        approval = self.handler.record(self.context(), payload, self.now, "a3000000-0000-4000-8000-000000000024", "a3000000-0000-4000-8000-000000000021", "assessment-approval-command-0002")
