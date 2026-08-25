import sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path[:0]=[str(ROOT/"src"),str(ROOT/"tests"/"runtime")]
from avuhz_runtime.assessment_access_terminal import AssessmentAccessTerminalHandler,AssessmentAccessTerminalRejected
from avuhz_runtime.guards import TrustedExecutionContext
from test_verify_assessment_access import VerifyAssessmentAccessTests
class Tests(unittest.TestCase):
 tenant="a3000000-0000-4000-8000-000000000002";grant="a3000000-0000-4000-8000-000000000015"
 def ctx(self,cap):return TrustedExecutionContext(True,"internal","INTERNAL_SERVICE",self.tenant,None,frozenset({cap}),frozenset(),"TEST","avuhz-command-api","STRONG",False,"2030-01-15T15:00:00Z")
 def uow(self,active=True):
  h=VerifyAssessmentAccessTests();u=h.setup();h.verify(u) if active else None;return u
 def test_transitions(self):
  u=self.uow();h=AssessmentAccessTerminalHandler(u);self.assertEqual(h.expire(self.ctx("assessment_access:expire"),{"assessment_access_grant_id":self.grant},"2030-02-14T15:00:00Z")["status"],"EXPIRED")
  u=self.uow();h=AssessmentAccessTerminalHandler(u);self.assertEqual(h.revoke(self.ctx("assessment_access:revoke"),{"assessment_access_grant_id":self.grant},"2030-01-16T00:00:00Z")["status"],"REVOKED")
  u=self.uow(False);u.working.agreements["a3000000-0000-4000-8000-000000000013"]["ends_at"]="2030-01-15T15:00:00Z";h=AssessmentAccessTerminalHandler(u);self.assertEqual(h.close_for_agreement_end(self.ctx("assessment_access:close"),{"assessment_access_grant_id":self.grant},"2030-01-15T15:00:00Z")["status"],"CLOSED")
 def test_rejections(self):
  u=self.uow();h=AssessmentAccessTerminalHandler(u)
  with self.assertRaises(AssessmentAccessTerminalRejected):h.expire(self.ctx("assessment_access:expire"),{"assessment_access_grant_id":self.grant},"2030-01-15T15:00:00Z")
