import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests" / "runtime")]

from avuhz_runtime.guards import TrustedExecutionContext
from avuhz_runtime.in_memory import UnitOfWork
from avuhz_runtime.issue_assessment_access_grant import AssessmentAccessGrantRejected, IssueAssessmentAccessGrantHandler
from test_execute_assessment_access_approval import AssessmentApprovalExecutorTests


class IssueAssessmentAccessGrantTests(unittest.TestCase):
    tenant = "a3000000-0000-4000-8000-000000000002"
    proposal_id = "a3000000-0000-4000-8000-000000000012"
    grant_id = "a3000000-0000-4000-8000-000000000015"

    def setup_flow(self, roles=("CLIENT_DECISION_AUTHORITY", "SEKINFRA_ENGAGEMENT_AUTHORITY")):
        helper = AssessmentApprovalExecutorTests(); flow = helper.established()
        if "CLIENT_DECISION_AUTHORITY" in roles:
            self.assertEqual(flow.x.execute(helper.raw(flow), helper.human())["result"], "ACCEPTED")
        if "SEKINFRA_ENGAGEMENT_AUTHORITY" in roles:
            self.assertEqual(flow.x.execute(helper.raw(flow, "assessment-approval-key-0002", "SEKINFRA_ENGAGEMENT_AUTHORITY", "b9000000-0000-4000-8000-000000000101"), helper.human("SEKINFRA_ENGAGEMENT_AUTHORITY", principal="human:sekinfra", organization="org:sekinfra"))["result"], "ACCEPTED")
        uow = UnitOfWork(flow.s)
        return flow, uow, IssueAssessmentAccessGrantHandler(uow)

    def context(self, tenant=None):
        return TrustedExecutionContext(True, "issuer", "INTERNAL_SERVICE", tenant or self.tenant, None, frozenset({"assessment_access:issue"}), frozenset(), "TEST", "avuhz-command-api", "STRONG", False, "2030-01-15T15:00:00Z")

    def payload(self, grant_id=None):
        return {"assessment_access_grant_id": grant_id or self.grant_id, "assessment_access_proposal_id": self.proposal_id}

    def test_issue_approved_grant_and_consume_exact_proposal(self):
        _, uow, handler = self.setup_flow()
        proposal = uow.assessment_access_proposals.get(self.tenant, self.proposal_id)
        grant = handler.issue(self.context(), self.payload(), "2030-01-15T15:00:00Z")
        self.assertEqual((grant["status"], grant["assessment_access_authority_digest"], grant["target_system_references"], grant["permitted_actions"]), ("APPROVED", proposal["assessment_access_authority_digest"], proposal["target_system_references"], proposal["permitted_actions"]))
        self.assertEqual(grant["source_assessment_access_proposal_reference"]["reference_id"], self.proposal_id)
        self.assertEqual(uow.assessment_access_proposals.get(self.tenant, self.proposal_id)["status"], "CONSUMED")
        self.assertIn("consumed_at", uow.assessment_access_proposals.get(self.tenant, self.proposal_id)); self.assertNotIn("verified_at", grant); self.assertNotIn("active_from", grant); self.assertNotIn("expires_at", grant)

    def test_missing_approval_and_commercial_or_scope_failures_do_not_write(self):
        cases = [((), None), (("CLIENT_DECISION_AUTHORITY",), None), (("CLIENT_DECISION_AUTHORITY", "SEKINFRA_ENGAGEMENT_AUTHORITY"), "payment"), (("CLIENT_DECISION_AUTHORITY", "SEKINFRA_ENGAGEMENT_AUTHORITY"), "agreement"), (("CLIENT_DECISION_AUTHORITY", "SEKINFRA_ENGAGEMENT_AUTHORITY"), "scope")]
        for roles, failure in cases:
            with self.subTest(roles=roles, failure=failure):
                flow, uow, handler = self.setup_flow(roles)
                if failure == "payment": uow.working.payments["a3000000-0000-4000-8000-000000000014"]["verification_status"] = "INVALIDATED"
                if failure == "agreement": uow.working.agreements["a3000000-0000-4000-8000-000000000013"]["ends_at"] = "2030-01-15T14:00:00Z"
                if failure == "scope": uow.working.scopes["a3000000-0000-4000-000000000005" if False else "a3000000-0000-4000-8000-000000000005"]["canonical_scope_digest"] = "sha256:" + "b" * 64
                with self.assertRaises(AssessmentAccessGrantRejected): handler.issue(self.context(), self.payload(), "2030-01-15T15:00:00Z")
                self.assertFalse(uow.working.grants); self.assertEqual(uow.assessment_access_proposals.get(self.tenant, self.proposal_id)["status"], "OPEN")

    def test_non_open_second_issue_and_wrong_tenant_reject(self):
        _, uow, handler = self.setup_flow(); handler.issue(self.context(), self.payload(), "2030-01-15T15:00:00Z")
        with self.assertRaises(AssessmentAccessGrantRejected): handler.issue(self.context(), self.payload("a3000000-0000-4000-8000-000000000016"), "2030-01-15T15:00:00Z")
        self.assertEqual(len(uow.working.grants), 1)
        _, other_uow, other_handler = self.setup_flow()
        with self.assertRaises(AssessmentAccessGrantRejected): other_handler.issue(self.context("a3000000-0000-4000-8000-000000000099"), self.payload(), "2030-01-15T15:00:00Z")

    def test_executor_issues_once_and_replays_without_duplicates(self):
        helper = AssessmentApprovalExecutorTests(); flow = helper.established()
        self.assertEqual(flow.x.execute(helper.raw(flow), helper.human())["result"], "ACCEPTED")
        self.assertEqual(flow.x.execute(helper.raw(flow, "assessment-approval-key-0002", "SEKINFRA_ENGAGEMENT_AUTHORITY", "b9000000-0000-4000-8000-000000000101"), helper.human("SEKINFRA_ENGAGEMENT_AUTHORITY", principal="human:sekinfra", organization="org:sekinfra"))["result"], "ACCEPTED")
        raw = flow.raw("RecordHumanApproval", "grant-executor-key-0001", "b9000000-0000-4000-8000-000000000120")
        raw.update(command_type="IssueAssessmentAccessGrant", subject_type="ASSESSMENT_ACCESS_GRANT", subject_id=self.grant_id, payload_schema="urn:avuhz:schema:contracts:commands:issue-assessment-access-grant-payload:v1", payload=self.payload())
        raw["caller_type"] = "INTERNAL_SERVICE"; raw["caller_identity"].update(caller_type="INTERNAL_SERVICE", capabilities=["assessment_access:issue"])
        self.assertEqual(flow.x.execute(raw, self.context())["result"], "ACCEPTED")
        self.assertEqual(flow.x.execute(raw, self.context())["result"], "DUPLICATE")
        self.assertEqual(flow.s.grants[(self.tenant, self.grant_id)]["status"], "APPROVED")
        self.assertEqual(flow.s.proposals[(self.tenant, self.proposal_id)]["status"], "CONSUMED")
        self.assertEqual(flow.s.events[-1]["event_type"], "assessment_access.grant_issued")
        self.assertEqual(flow.s.outbox[-1]["status"], "PENDING")
