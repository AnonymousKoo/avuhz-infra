import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests" / "runtime")]

from avuhz_runtime.assessment_access_dual_approval import evaluate_assessment_access_dual_approval
from avuhz_runtime.in_memory import MemoryStore, UnitOfWork
from test_execute_assessment_access_approval import AssessmentApprovalExecutorTests


class AssessmentAccessDualApprovalTests(unittest.TestCase):
    tenant = "a3000000-0000-4000-8000-000000000002"
    proposal_id = "a3000000-0000-4000-8000-000000000012"
    digest = "sha256:" + "a" * 64

    def setUp(self):
        self.uow = UnitOfWork(MemoryStore())
        self.uow.assessment_access_proposals.create({"assessment_access_proposal_id": self.proposal_id, "tenant_id": self.tenant, "engagement_id": "a3000000-0000-4000-8000-000000000004", "assessment_access_authority_digest": self.digest, "status": "OPEN", "record_version": 1})

    def record(self, role, proposal_id=None, digest=None, actor=True):
        approval_id = "approval-" + role.lower()
        proposal_id = proposal_id or self.proposal_id
        self.uow.human_approvals.record_assessment_access({"approval_id": approval_id + proposal_id[-1:], "tenant_id": self.tenant, "engagement_id": "a3000000-0000-4000-8000-000000000004", "subject_type": "ASSESSMENT_ACCESS_PROPOSAL", "subject_id": proposal_id, "actor_role": role, "actor_identity": "human:" + role if actor else None, "actor_organization": "org:" + role if actor else None, "assessment_access": {"assessment_access_proposal_id": proposal_id, "assessment_access_authority_digest": digest or self.digest}, "status": "ACTIVE"})

    def evaluate(self, tenant=None, proposal_id=None):
        return evaluate_assessment_access_dual_approval(self.uow, tenant or self.tenant, proposal_id or self.proposal_id)

    def test_both_executor_recorded_approvals_satisfy_without_mutation(self):
        helper = AssessmentApprovalExecutorTests()
        flow = helper.established()
        client = helper.raw(flow)
        sekinfra = helper.raw(flow, "assessment-approval-key-0002", "SEKINFRA_ENGAGEMENT_AUTHORITY", "b9000000-0000-4000-8000-000000000101")
        self.assertEqual(flow.x.execute(client, helper.human())["result"], "ACCEPTED")
        self.assertEqual(flow.x.execute(sekinfra, helper.human("SEKINFRA_ENGAGEMENT_AUTHORITY", principal="human:sekinfra", organization="org:sekinfra"))["result"], "ACCEPTED")
        read = UnitOfWork(flow.s)
        before = copy.deepcopy(read.working)
        result = evaluate_assessment_access_dual_approval(read, self.tenant, self.proposal_id)
        self.assertEqual((result.satisfied, result.reason), (True, None))
        self.assertEqual(read.working, before)
        self.assertEqual(flow.s.proposals[(self.tenant, self.proposal_id)]["status"], "OPEN")

    def test_missing_roles_have_deterministic_reasons(self):
        self.assertEqual(self.evaluate().reason, "CLIENT_APPROVAL_MISSING")
        self.record("CLIENT_DECISION_AUTHORITY")
        self.assertEqual(self.evaluate().reason, "SEKINFRA_APPROVAL_MISSING")
        self.uow.working.approvals.clear()
        self.record("SEKINFRA_ENGAGEMENT_AUTHORITY")
        self.assertEqual(self.evaluate().reason, "CLIENT_APPROVAL_MISSING")

    def test_proposal_and_digest_bindings_do_not_transfer(self):
        other_id = "a3000000-0000-4000-8000-000000000013"
        self.uow.assessment_access_proposals.create({"assessment_access_proposal_id": other_id, "tenant_id": self.tenant, "engagement_id": "a3000000-0000-4000-8000-000000000004", "assessment_access_authority_digest": self.digest, "status": "OPEN", "record_version": 1})
        self.record("CLIENT_DECISION_AUTHORITY")
        self.record("SEKINFRA_ENGAGEMENT_AUTHORITY", other_id)
        self.assertFalse(self.evaluate().satisfied)
        self.assertFalse(self.evaluate(proposal_id=other_id).satisfied)
        self.uow.working.approvals.clear()
        self.record("CLIENT_DECISION_AUTHORITY")
        self.record("SEKINFRA_ENGAGEMENT_AUTHORITY", digest="sha256:" + "b" * 64)
        self.assertEqual(self.evaluate().reason, "SEKINFRA_APPROVAL_MISSING")

    def test_non_open_tenant_and_attribution_do_not_satisfy(self):
        self.record("CLIENT_DECISION_AUTHORITY")
        self.record("SEKINFRA_ENGAGEMENT_AUTHORITY")
        for status in ("SUPERSEDED", "WITHDRAWN", "CONSUMED"):
            self.uow.working.proposals[(self.tenant, self.proposal_id)]["status"] = status
            self.assertEqual(self.evaluate().reason, "PROPOSAL_NOT_OPEN")
        self.uow.working.proposals[(self.tenant, self.proposal_id)]["status"] = "OPEN"
        self.assertEqual(self.evaluate(tenant="a3000000-0000-4000-8000-000000000099").reason, "PROPOSAL_NOT_FOUND")
        self.uow.working.approvals.clear()
        self.record("CLIENT_DECISION_AUTHORITY")
        self.record("SEKINFRA_ENGAGEMENT_AUTHORITY")
        duplicate = copy.deepcopy(next(a for a in self.uow.working.approvals.values() if a["actor_role"] == "CLIENT_DECISION_AUTHORITY"))
        duplicate["approval_id"] = "duplicate-client-approval"
        self.uow.working.approvals[duplicate["approval_id"]] = duplicate
        self.assertEqual(self.evaluate().reason, "APPROVAL_BINDING_MISMATCH")
        self.uow.working.approvals.clear()
        self.record("CLIENT_DECISION_AUTHORITY", actor=False)
        self.record("SEKINFRA_ENGAGEMENT_AUTHORITY")
        self.assertEqual(self.evaluate().reason, "APPROVAL_BINDING_MISMATCH")


if __name__ == "__main__":
    unittest.main()
