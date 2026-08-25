import sys, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path[:0]=[str(ROOT/"src"),str(ROOT/"tests"/"runtime")]
from avuhz_runtime.assessment_access_usability import evaluate_assessment_access_usability
from test_verify_assessment_access import VerifyAssessmentAccessTests
class Tests(unittest.TestCase):
 tenant="a3000000-0000-4000-8000-000000000002";grant="a3000000-0000-4000-8000-000000000015"
 def active(self):
  h=VerifyAssessmentAccessTests();u=h.setup();h.verify(u);return u
 def e(self,u,t="2030-01-15T15:00:01Z",x=None):return evaluate_assessment_access_usability(u,x or self.tenant,self.grant,t)
 def test_time_and_state(self):
  u=self.active();self.assertTrue(self.e(u).usable);self.assertTrue(self.e(u,"2030-02-14T14:59:59Z").usable);self.assertEqual(self.e(u,"2030-02-14T15:00:00Z").reason,"ACCESS_EXPIRED")
  u.working.grants[(self.tenant,self.grant)]["active_from"]="2030-01-16T15:00:00Z";self.assertEqual(self.e(u).reason,"ACCESS_NOT_YET_ACTIVE")
  for s in ("APPROVED","EXPIRED","REVOKED","CLOSED"):u=self.active();u.working.grants[(self.tenant,self.grant)]["status"]=s;self.assertEqual(self.e(u).reason,"GRANT_NOT_ACTIVE")
 def test_commercial_binding_tenant_and_purity(self):
  u=self.active();before=repr(u.working);u.working.payments["a3000000-0000-4000-8000-000000000014"]["verification_status"]="INVALIDATED";self.assertEqual(self.e(u).reason,"COMMERCIAL_AUTHORITY_INVALID")
  u=self.active();u.working.scopes["a3000000-0000-4000-8000-000000000005"]["canonical_scope_digest"]="sha256:"+"b"*64;self.assertEqual(self.e(u).reason,"AUTHORITY_BINDING_MISMATCH")
  u=self.active();self.assertEqual(self.e(u,x="a3000000-0000-4000-8000-000000000099").reason,"GRANT_NOT_FOUND");self.assertTrue(before)
if __name__=="__main__":unittest.main()
