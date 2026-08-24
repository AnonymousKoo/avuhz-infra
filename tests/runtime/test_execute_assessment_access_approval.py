import copy
import sys
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests" / "contracts"), str(ROOT / "tests" / "runtime")]
from avuhz_runtime.guards import TrustedExecutionContext, COMMAND_CAPABILITIES
from avuhz_runtime.in_memory import UnitOfWork
from test_execute_assessment_access_proposal import ProposalExecutorTests
from test_record_human_approval import context as service_context


class AssessmentApprovalExecutorTests(unittest.TestCase):
    def established(self):
        helper = ProposalExecutorTests(); helper.setUp()
        flow = helper.build()
        self.assertEqual(flow.x.execute(helper.raw(), service_context("CreateAssessmentAccessProposal"))["result"], "ACCEPTED")
        return flow
    def raw(self, flow, key="assessment-approval-key-0001", role="CLIENT_DECISION_AUTHORITY", command_id="b9000000-0000-4000-8000-000000000100"):
        value = flow.raw("RecordHumanApproval", key, command_id); value.update(command_type="RecordAssessmentAccessApproval", subject_type="ASSESSMENT_ACCESS_PROPOSAL", subject_id="a3000000-0000-4000-8000-000000000012", payload_schema="urn:avuhz:schema:contracts:commands:record-assessment-access-approval-payload:v1", payload={"assessment_access_proposal_id": "a3000000-0000-4000-8000-000000000012", "authority_role": role})
        value["caller_type"] = "HUMAN"; value["caller_identity"].update(caller_type="HUMAN", capabilities=["assessment_access:approve"])
        return value
    def human(self, role="CLIENT_DECISION_AUTHORITY", caller="HUMAN", tenant="a3000000-0000-4000-8000-000000000002", principal="human:client", organization="org:client"):
        return TrustedExecutionContext(True, principal, caller, tenant, None, frozenset({"assessment_access:approve"}), frozenset(), "TEST", "avuhz-command-api", "STRONG", False, "2030-01-15T15:00:00Z", "2030-01-15T16:00:00Z", principal if caller == "HUMAN" else None, organization if caller == "HUMAN" else None, role)
    def test_client_and_sekinfra_execute_independently(self):
        flow = self.established(); client = self.raw(flow); sek = self.raw(flow, "assessment-approval-key-0002", "SEKINFRA_ENGAGEMENT_AUTHORITY", "b9000000-0000-4000-8000-000000000101")
        self.assertEqual(flow.x.execute(client, self.human())["result"], "ACCEPTED")
        self.assertEqual(flow.x.execute(sek, self.human("SEKINFRA_ENGAGEMENT_AUTHORITY", principal="human:sekinfra", organization="org:sekinfra"))["result"], "ACCEPTED")
        approvals = list(flow.s.approvals.values()); self.assertEqual(len(approvals), 4); assessment = [a for a in approvals if a.get("subject_type") == "ASSESSMENT_ACCESS_PROPOSAL"]
        self.assertEqual({a["actor_role"] for a in assessment}, {"CLIENT_DECISION_AUTHORITY", "SEKINFRA_ENGAGEMENT_AUTHORITY"}); self.assertEqual({a["assessment_access"]["assessment_access_authority_digest"] for a in assessment}, {flow.s.proposals[("a3000000-0000-4000-8000-000000000002", "a3000000-0000-4000-8000-000000000012")]["assessment_access_authority_digest"]})
        self.assertEqual([event["event_type"] for event in flow.s.events][-2:], ["assessment_access.approval_recorded", "assessment_access.approval_recorded"]); self.assertEqual([item["status"] for item in flow.s.outbox][-2:], ["PENDING", "PENDING"])
        self.assertEqual(flow.s.proposals[("a3000000-0000-4000-8000-000000000002", "a3000000-0000-4000-8000-000000000012")]["status"], "OPEN")
        digest = flow.s.proposals[("a3000000-0000-4000-8000-000000000002", client["subject_id"])]["assessment_access_authority_digest"]
        approvals = UnitOfWork(flow.s).human_approvals
        self.assertIsNotNone(approvals.find_active_assessment_access_binding("a3000000-0000-4000-8000-000000000002", client["subject_id"], digest, "CLIENT_DECISION_AUTHORITY"))
        self.assertIsNotNone(approvals.find_active_assessment_access_binding("a3000000-0000-4000-8000-000000000002", client["subject_id"], digest, "SEKINFRA_ENGAGEMENT_AUTHORITY"))
        self.assertIsNotNone(flow.x.store.approvals[client["command_id"]]); self.assertIsNotNone(flow.x.store.approvals[sek["command_id"]]); self.assertIsNotNone(flow.x.store.proposals[("a3000000-0000-4000-8000-000000000002", client["subject_id"])])

    def test_replay_conflict_and_new_key_duplicate_authority(self):
        flow = self.established(); raw = self.raw(flow); self.assertEqual(flow.x.execute(raw, self.human())["result"], "ACCEPTED")
        self.assertEqual(flow.x.execute(raw, self.human())["result"], "DUPLICATE")
        conflict = self.raw(flow, role="SEKINFRA_ENGAGEMENT_AUTHORITY", command_id="b9000000-0000-4000-8000-000000000102")
        self.assertEqual(flow.x.execute(conflict, self.human())["result"], "CONFLICT")
        duplicate_authority = self.raw(flow, "assessment-approval-key-0002", command_id="b9000000-0000-4000-8000-000000000103")
        self.assertEqual(flow.x.execute(duplicate_authority, self.human())["result"], "REJECTED")
        assessment = [a for a in flow.s.approvals.values() if a.get("subject_type") == "ASSESSMENT_ACCESS_PROPOSAL"]
        self.assertEqual(len(assessment), 1); self.assertEqual(len(flow.s.events), 9); self.assertEqual(len(flow.s.outbox), 9)
    def test_workload_role_mismatch_and_non_open_reject_without_artifacts(self):
        for role, trusted, status in (("CLIENT_DECISION_AUTHORITY", self.human(caller="WORKLOAD"), None), ("SEKINFRA_ENGAGEMENT_AUTHORITY", self.human(), None), ("CLIENT_DECISION_AUTHORITY", self.human(), "SUPERSEDED")):
            flow = self.established()
            if status:
                flow.s.proposals[("a3000000-0000-4000-8000-000000000002", "a3000000-0000-4000-8000-000000000012")]["status"] = status
            result = flow.x.execute(self.raw(flow, role=role), trusted)
            self.assertEqual(result["result"], "REJECTED")
            self.assertFalse(any(a.get("subject_type") == "ASSESSMENT_ACCESS_PROPOSAL" for a in flow.s.approvals.values()))
            self.assertEqual(len(flow.s.events), 8)
            self.assertEqual(len(flow.s.outbox), 8)

    def test_failpoints_roll_back_approval_transaction(self):
        for stage in ("AUTHORITATIVE_WRITE", "IDEMPOTENCY_RESERVE", "IDEMPOTENCY_COMPLETE", "LIFECYCLE_EVENT_APPEND", "OUTBOX_APPEND", "COMMIT"):
            flow = self.established()
            before = (len(flow.s.approvals), len(flow.s.events), len(flow.s.outbox), len(flow.s.idempotency))
            flow.s.fail_stage = stage
            result = flow.x.execute(self.raw(flow, "assessment-approval-failpoint-" + stage.lower()), self.human())
            self.assertEqual(result["result"], "REJECTED")
            self.assertEqual((len(flow.s.approvals), len(flow.s.events), len(flow.s.outbox), len(flow.s.idempotency)), before)
            self.assertEqual(flow.s.proposals[("a3000000-0000-4000-8000-000000000002", "a3000000-0000-4000-8000-000000000012")]["status"], "OPEN")


