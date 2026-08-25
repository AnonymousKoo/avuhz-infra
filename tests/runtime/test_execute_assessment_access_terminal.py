import sys, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path[:0]=[str(ROOT/"src"),str(ROOT/"tests"/"runtime")]
from avuhz_runtime.guards import TrustedExecutionContext
from avuhz_runtime.assessment_access_usability import evaluate_assessment_access_usability
from test_execute_verify_assessment_access import VerifyAssessmentAccessExecutorTests

class TerminalExecutorTests(unittest.TestCase):
    tenant="a3000000-0000-4000-8000-000000000002"; grant="a3000000-0000-4000-8000-000000000015"; agreement="a3000000-0000-4000-8000-000000000013"
    schemas={"ExpireAssessmentAccess":"expire-assessment-access","RevokeAssessmentAccess":"revoke-assessment-access","CloseAssessmentAccessForAgreementEnd":"close-assessment-access-for-agreement-end"}
    capabilities={"ExpireAssessmentAccess":"assessment_access:expire","RevokeAssessmentAccess":"assessment_access:revoke","CloseAssessmentAccessForAgreementEnd":"assessment_access:close"}
    def context(self,command): return TrustedExecutionContext(True,"terminal","INTERNAL_SERVICE",self.tenant,None,frozenset({self.capabilities[command]}),frozenset(),"TEST","avuhz-command-api","STRONG",False,"2030-01-15T15:00:00Z")
    def flow(self,active=False):
        helper=VerifyAssessmentAccessExecutorTests(); flow=helper.established()
        if active: self.assertEqual(flow.x.execute(helper.raw(flow),helper.context())["result"],"ACCEPTED")
        return helper,flow
    def raw(self,helper,flow,command,key="terminal-command-key-001",grant=None):
        value=helper.raw(flow,key,"b9000000-0000-4000-8000-000000000180",grant or self.grant);value.update(command_type=command,payload_schema=f"urn:avuhz:schema:contracts:commands:{self.schemas[command]}-payload:v1",payload={"assessment_access_grant_id":grant or self.grant},expected_record_version=2)
        value["caller_identity"].update(capabilities=[self.capabilities[command]]);return value
    def execute(self,helper,flow,command,key="terminal-command-key-001"): return flow.x.execute(self.raw(helper,flow,command,key),self.context(command))
    def test_expire_replay_conflict_and_too_early(self):
        helper,flow=self.flow(True);flow.x.clock=lambda:"2030-02-14T15:00:00Z";raw=self.raw(helper,flow,"ExpireAssessmentAccess")
        self.assertEqual(flow.x.execute(raw,self.context("ExpireAssessmentAccess"))["result"],"ACCEPTED");self.assertEqual(flow.s.grants[(self.tenant,self.grant)]["status"],"EXPIRED")
        self.assertEqual((flow.s.events[-1]["event_type"],flow.s.outbox[-1]["status"]),("assessment_access.expired","PENDING"));self.assertEqual(flow.x.execute(raw,self.context("ExpireAssessmentAccess"))["result"],"DUPLICATE")
        changed=self.raw(helper,flow,"ExpireAssessmentAccess",grant="a3000000-0000-4000-8000-000000000016");self.assertEqual(flow.x.execute(changed,self.context("ExpireAssessmentAccess"))["result"],"CONFLICT")
        helper,flow=self.flow(True);self.assertEqual(self.execute(helper,flow,"ExpireAssessmentAccess")["result"],"REJECTED");self.assertEqual(flow.s.grants[(self.tenant,self.grant)]["status"],"ACTIVE")
    def test_revoke_approved_active_and_authority_failure(self):
        for active in (False,True):
            helper,flow=self.flow(active);self.assertEqual(self.execute(helper,flow,"RevokeAssessmentAccess")["result"],"ACCEPTED");grant=flow.s.grants[(self.tenant,self.grant)]
            self.assertEqual((grant["status"],flow.s.events[-1]["event_type"],flow.s.outbox[-1]["status"]),("REVOKED","assessment_access.revoked","PENDING"))
        helper,flow=self.flow();raw=self.raw(helper,flow,"RevokeAssessmentAccess");raw["caller_identity"].update(capabilities=[]);context=TrustedExecutionContext(True,"terminal","INTERNAL_SERVICE",self.tenant,None,frozenset(),frozenset(),"TEST","avuhz-command-api","STRONG",False,"2030-01-15T15:00:00Z");self.assertEqual(flow.x.execute(raw,context)["result"],"REJECTED")
    def test_agreement_close_and_terminal_rejection(self):
        for active in (False,True):
            helper,flow=self.flow(active);flow.s.agreements[self.agreement]["ends_at"]="2030-01-15T15:00:00Z";self.assertEqual(self.execute(helper,flow,"CloseAssessmentAccessForAgreementEnd")["result"],"ACCEPTED")
            grant=flow.s.grants[(self.tenant,self.grant)];self.assertEqual((grant["status"],flow.s.events[-1]["event_type"],flow.s.events[-1]["sanitized_metadata"]["closure_cause"]),("CLOSED","assessment_access.closed","AGREEMENT_ENDED"))
        helper,flow=self.flow();self.assertEqual(self.execute(helper,flow,"CloseAssessmentAccessForAgreementEnd")["result"],"REJECTED")
        helper,flow=self.flow(True);flow.x.clock=lambda:"2030-02-14T15:00:00Z";self.assertEqual(self.execute(helper,flow,"ExpireAssessmentAccess")["result"],"ACCEPTED");self.assertEqual(self.execute(helper,flow,"RevokeAssessmentAccess","terminal-command-key-002")["result"],"REJECTED")
    def test_failpoints_and_usability(self):
        for point in ("AUTHORITATIVE_WRITE","IDEMPOTENCY_RESERVE","IDEMPOTENCY_COMPLETE","LIFECYCLE_EVENT_APPEND","OUTBOX_APPEND","COMMIT"):
            helper,flow=self.flow(True);flow.x.clock=lambda:"2030-02-14T15:00:00Z";before=(len(flow.s.events),len(flow.s.outbox),len(flow.s.idempotency));flow.s.fail_stage=point
            self.assertEqual(self.execute(helper,flow,"ExpireAssessmentAccess",f"terminal-{point.lower()}-001")["result"],"REJECTED");grant=flow.s.grants[(self.tenant,self.grant)]
            self.assertEqual((grant["status"],len(flow.s.events),len(flow.s.outbox),len(flow.s.idempotency)),("ACTIVE",*before))
        helper,flow=self.flow(True);flow.x.clock=lambda:"2030-02-14T15:00:00Z";self.assertFalse(evaluate_assessment_access_usability(flow.x.uow_factory(flow.s),self.tenant,self.grant,"2030-02-14T15:00:00Z").usable)

if __name__=="__main__":unittest.main()
