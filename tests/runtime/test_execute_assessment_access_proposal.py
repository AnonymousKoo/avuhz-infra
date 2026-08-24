import copy
import sys
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests" / "contracts"), str(ROOT / "tests" / "runtime")]
from validate_command_payloads import envelope, payloads
from test_record_human_approval import Tests as ScopeFlow, context

class ProposalExecutorTests(unittest.TestCase):
    def build(self):
        flow = ScopeFlow(); flow.setUp(); flow.establish()
        self.assertEqual(flow.approval("CLIENT_DECISION_AUTHORITY", "proposal-scope-client-0001", "b9000000-0000-4000-8000-000000000010")["result"], "ACCEPTED")
        self.assertEqual(flow.approval("SEKINFRA_ENGAGEMENT_AUTHORITY", "proposal-scope-sekinfra-0001", "b9000000-0000-4000-8000-000000000011")["result"], "ACCEPTED")
        self.assertEqual(flow.final("proposal-scope-final-0001", 2)["result"], "ACCEPTED")
        scope = flow.s.scopes["a3000000-0000-4000-8000-000000000005"]
        scope["in_scope_systems"].append({"system_reference_id": "system-002"}); scope["permitted_diagnostic_actions"].append("VIEW_LOGS")
        flow.s.agreements["a3000000-0000-4000-8000-000000000013"] = {"tenant_id": "a3000000-0000-4000-8000-000000000002", "engagement_id": "a3000000-0000-4000-8000-000000000004", "diagnostic_agreement_authority_id": "a3000000-0000-4000-8000-000000000013", "record_version": 1, "status": "VERIFIED_ACTIVE", "scope_reference": {"reference_id": scope["diagnostic_scope_id"], "reference_version": scope["scope_version"]}, "canonical_scope_digest": scope["canonical_scope_digest"], "effective_at": "2030-01-01T00:00:00Z"}
        flow.s.payments["a3000000-0000-4000-8000-000000000014"] = {"tenant_id": "a3000000-0000-4000-8000-000000000002", "engagement_id": "a3000000-0000-4000-8000-000000000004", "diagnostic_payment_verification_id": "a3000000-0000-4000-8000-000000000014", "record_version": 1, "payment_purpose": "DIAGNOSTIC_OIA", "verification_status": "VERIFIED", "diagnostic_agreement_authority_reference": {"reference_id": "a3000000-0000-4000-8000-000000000013"}}
        return flow
    def raw(self, key="proposal-command-key-0001", command_id="b9000000-0000-4000-8000-000000000090", payload=None):
        value = envelope("CreateAssessmentAccessProposal", copy.deepcopy(payload or payloads()["CreateAssessmentAccessProposal"])); value.update(idempotency_key=key, command_id=command_id)
        return value
    def test_positive_duplicate_and_authoritative_readback(self):
        flow = self.build(); raw = self.raw(); result = flow.x.execute(raw, context("CreateAssessmentAccessProposal"))
        self.assertEqual(result["result"], "ACCEPTED"); self.assertEqual(len(flow.s.proposals), 1); self.assertEqual(len(flow.s.events), 8); self.assertEqual(len(flow.s.outbox), 8); self.assertEqual(len(flow.s.idempotency), 8)
        proposal = flow.s.proposals[("a3000000-0000-4000-8000-000000000002", "a3000000-0000-4000-8000-000000000012")]
        self.assertEqual(proposal["status"], "OPEN"); self.assertEqual(flow.s.events[-1]["event_type"], "assessment_access.proposal_created"); self.assertEqual(flow.s.events[-1]["engagement_id"], proposal["engagement_id"]); self.assertEqual(flow.s.outbox[-1]["status"], "PENDING")
        self.assertEqual(flow.x.execute(raw, context("CreateAssessmentAccessProposal"))["result"], "DUPLICATE"); self.assertEqual((len(flow.s.proposals), len(flow.s.events), len(flow.s.outbox)), (1, 8, 8))
    def test_conflict_and_semantic_set_ordering(self):
        flow = self.build(); payload = payloads()["CreateAssessmentAccessProposal"]; payload["target_system_references"] = [{"system_reference_id": "system-001"}, {"system_reference_id": "system-002"}]; payload["permitted_actions"] = ["VIEW_CONFIGURATION", "VIEW_LOGS"]
        self.assertEqual(flow.x.execute(self.raw("proposal-order-key-0001", payload=payload), context("CreateAssessmentAccessProposal"))["result"], "ACCEPTED")
        reordered = copy.deepcopy(payload); reordered["target_system_references"].reverse(); reordered["permitted_actions"].reverse()
        self.assertEqual(flow.x.execute(self.raw("proposal-order-key-0001", "b9000000-0000-4000-8000-000000000091", reordered), context("CreateAssessmentAccessProposal"))["result"], "DUPLICATE")
        conflict = copy.deepcopy(payload); conflict["permitted_actions"] = ["VIEW_LOGS"]
        self.assertEqual(flow.x.execute(self.raw("proposal-order-key-0001", "b9000000-0000-4000-8000-000000000092", conflict), context("CreateAssessmentAccessProposal"))["result"], "CONFLICT"); self.assertEqual(len(flow.s.proposals), 1); self.assertEqual(len(flow.s.events), 8)
    def test_business_failure_and_failpoints_are_atomic(self):
        flow = self.build(); flow.s.payments["a3000000-0000-4000-8000-000000000014"]["verification_status"] = "INVALIDATED"
        self.assertEqual(flow.x.execute(self.raw(), context("CreateAssessmentAccessProposal"))["result"], "REJECTED"); self.assertEqual(len(flow.s.proposals), 0); self.assertEqual(len(flow.s.events), 7); self.assertEqual(len(flow.s.outbox), 7)
    def test_named_failpoints_are_atomic(self):
        for point in ("AUTHORITATIVE_WRITE", "IDEMPOTENCY_RESERVE", "IDEMPOTENCY_COMPLETE", "LIFECYCLE_EVENT_APPEND", "OUTBOX_APPEND", "COMMIT"):
            with self.subTest(point=point):
                flow = self.build(); before = (len(flow.s.events), len(flow.s.outbox), len(flow.s.idempotency)); flow.s.fail_stage = point
                self.assertEqual(flow.x.execute(self.raw("proposal-failpoint-key-" + point.lower()), context("CreateAssessmentAccessProposal"))["result"], "REJECTED")
                self.assertEqual(len(flow.s.proposals), 0); self.assertEqual((len(flow.s.events), len(flow.s.outbox), len(flow.s.idempotency)), before)


if __name__ == "__main__":
    unittest.main()
