import copy
import sys
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests" / "runtime")]
from avuhz_runtime.assessment_access_verification import InMemoryAssessmentAccessVerifier, VerificationFailureReason
from avuhz_runtime.guards import TrustedExecutionContext
from test_execute_assessment_access_approval import AssessmentApprovalExecutorTests

class CountingVerifier(InMemoryAssessmentAccessVerifier):
    def __init__(self, outcomes=None): super().__init__(outcomes); self.calls = 0
    def verify(self, request): self.calls += 1; return super().verify(request)

class VerifyAssessmentAccessExecutorTests(unittest.TestCase):
    tenant="a3000000-0000-4000-8000-000000000002"; proposal_id="a3000000-0000-4000-8000-000000000012"; grant_id="a3000000-0000-4000-8000-000000000015"
    def context(self,tenant=None): return TrustedExecutionContext(True,"verifier","INTERNAL_SERVICE",tenant or self.tenant,None,frozenset({"assessment_access:verify"}),frozenset(),"TEST","avuhz-command-api","STRONG",False,"2030-01-15T15:00:00Z")
    def established(self):
        helper=AssessmentApprovalExecutorTests();flow=helper.established();self.assertEqual(flow.x.execute(helper.raw(flow),helper.human())["result"],"ACCEPTED")
        self.assertEqual(flow.x.execute(helper.raw(flow,"assessment-approval-key-0002","SEKINFRA_ENGAGEMENT_AUTHORITY","b9000000-0000-4000-8000-000000000101"),helper.human("SEKINFRA_ENGAGEMENT_AUTHORITY",principal="human:sekinfra",organization="org:sekinfra"))["result"],"ACCEPTED")
        raw=flow.raw("RecordHumanApproval","verify-grant-issue-key","b9000000-0000-4000-8000-000000000120");raw.update(command_type="IssueAssessmentAccessGrant",subject_type="ASSESSMENT_ACCESS_GRANT",subject_id=self.grant_id,payload_schema="urn:avuhz:schema:contracts:commands:issue-assessment-access-grant-payload:v1",payload={"assessment_access_grant_id":self.grant_id,"assessment_access_proposal_id":self.proposal_id});raw["caller_type"]="INTERNAL_SERVICE";raw["caller_identity"].update(caller_type="INTERNAL_SERVICE",capabilities=["assessment_access:issue"])
        issuer=TrustedExecutionContext(True,"issuer","INTERNAL_SERVICE",self.tenant,None,frozenset({"assessment_access:issue"}),frozenset(),"TEST","avuhz-command-api","STRONG",False,"2030-01-15T15:00:00Z");self.assertEqual(flow.x.execute(raw,issuer)["result"],"ACCEPTED");return flow
    def raw(self,flow,key="verify-key-00001",command_id="b9000000-0000-4000-8000-000000000130",grant_id=None):
        value=flow.raw("RecordHumanApproval",key,command_id);value.update(command_type="VerifyAssessmentAccess",subject_type="ASSESSMENT_ACCESS_GRANT",subject_id=self.grant_id,payload_schema="urn:avuhz:schema:contracts:commands:verify-assessment-access-payload:v1",payload={"assessment_access_grant_id":grant_id or self.grant_id},expected_record_version=1);value["caller_type"]="INTERNAL_SERVICE";value["caller_identity"].update(caller_type="INTERNAL_SERVICE",capabilities=["assessment_access:verify"]);return value
    def test_success_duplicate_conflict_and_no_refresh(self):
        flow=self.established();verifier=CountingVerifier();flow.x.assessment_access_verifier=verifier;raw=self.raw(flow);self.assertEqual(flow.x.execute(raw,self.context())["result"],"ACCEPTED");grant=copy.deepcopy(flow.s.grants[(self.tenant,self.grant_id)])
        self.assertEqual((grant["status"],grant["verified_at"],grant["active_from"],grant["expires_at"]),("ACTIVE","2030-01-15T15:00:00Z","2030-01-15T15:00:00Z","2030-02-14T15:00:00Z"));self.assertEqual(flow.x.execute(raw,self.context())["result"],"DUPLICATE");self.assertEqual(verifier.calls,1)
        self.assertEqual(flow.x.execute(self.raw(flow,grant_id="a3000000-0000-4000-8000-000000000016"),self.context())["result"],"CONFLICT");self.assertEqual(flow.x.execute(self.raw(flow,"verify-key-00002","b9000000-0000-4000-8000-000000000131"),self.context())["result"],"REJECTED");self.assertEqual(flow.s.grants[(self.tenant,self.grant_id)],grant)
        event=flow.s.events[-1];self.assertEqual((event["event_type"],event["engagement_id"],event["sanitized_metadata"]["assessment_access_grant_id"]),("assessment_access.verified_and_activated",grant["engagement_id"],self.grant_id));self.assertEqual(flow.s.outbox[-1]["status"],"PENDING")
        self.assertEqual(event["sanitized_metadata"]["verified_at"],grant["verified_at"])
    def test_failure_retry_authority_and_failpoints(self):
        flow=self.established();target=flow.s.grants[(self.tenant,self.grant_id)]["target_system_references"][-1]["system_reference_id"];verifier=CountingVerifier({target:VerificationFailureReason.TARGET_UNAVAILABLE});flow.x.assessment_access_verifier=verifier;before=(len(flow.s.events),len(flow.s.outbox),len(flow.s.idempotency));self.assertEqual(flow.x.execute(self.raw(flow),self.context())["result"],"REJECTED");self.assertEqual((len(flow.s.events),len(flow.s.outbox),len(flow.s.idempotency)),before)
        flow.x.assessment_access_verifier=CountingVerifier();self.assertEqual(flow.x.execute(self.raw(flow,"verify-key-00002","b9000000-0000-4000-8000-000000000131"),self.context())["result"],"ACCEPTED")
        for point in ("AUTHORITATIVE_WRITE","IDEMPOTENCY_RESERVE","IDEMPOTENCY_COMPLETE","LIFECYCLE_EVENT_APPEND","OUTBOX_APPEND","COMMIT"):
            flow=self.established();flow.x.assessment_access_verifier=CountingVerifier();before=(len(flow.s.events),len(flow.s.outbox),len(flow.s.idempotency));flow.s.fail_stage=point;self.assertEqual(flow.x.execute(self.raw(flow,"verify-"+point.lower()+"-attempt"),self.context())["result"],"REJECTED");grant=flow.s.grants[(self.tenant,self.grant_id)];self.assertEqual((grant["status"],set(grant)&{"verified_at","active_from","expires_at"}),("APPROVED",set()));self.assertEqual((len(flow.s.events),len(flow.s.outbox),len(flow.s.idempotency)),before)

    def test_commercial_and_scope_rejections_do_not_invoke_verifier(self):
        for failure in ("payment","agreement","scope"):
            flow=self.established();verifier=CountingVerifier();flow.x.assessment_access_verifier=verifier
            if failure=="payment":flow.s.payments["a3000000-0000-4000-8000-000000000014"]["verification_status"]="INVALIDATED"
            if failure=="agreement":flow.s.agreements["a3000000-0000-4000-8000-000000000013"]["ends_at"]="2030-01-15T14:00:00Z"
            if failure=="scope":flow.s.scopes["a3000000-0000-4000-8000-000000000005"]["canonical_scope_digest"]="sha256:"+"b"*64
            self.assertEqual(flow.x.execute(self.raw(flow),self.context())["result"],"REJECTED");self.assertEqual(verifier.calls,0);self.assertEqual(flow.s.grants[(self.tenant,self.grant_id)]["status"],"APPROVED")

if __name__ == "__main__": unittest.main()
