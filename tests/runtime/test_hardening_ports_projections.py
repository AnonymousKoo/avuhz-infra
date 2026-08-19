import sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/"src"))
from avuhz_runtime.in_memory import MemoryStore,UnitOfWork,fingerprint
from avuhz_runtime.projections import readiness,engagement_summary
class Tests(unittest.TestCase):
 def test_copy_on_write_rollback_and_fingerprint(self):
  s=MemoryStore();u=UnitOfWork(s);u.working.engagements["e"]={"tenant_id":"t"};self.assertEqual(s.engagements,{})
  a={"tenant_id":"t","command_type":"OpenEngagement","subject_type":"ENGAGEMENT","subject_id":"x","payload":{ "a":1 }};b={**a,"payload":{"a":2}}
  self.assertEqual(fingerprint(a),fingerprint(dict(reversed(list(a.items())))));self.assertNotEqual(fingerprint(a),fingerprint(b));self.assertNotIn("payload",str({"fingerprint":fingerprint(a)}))
 def test_projections_are_tenant_scoped_and_read_only(self):
  s=MemoryStore();s.engagements["e"]={"tenant_id":"t","engagement_state":"OPEN"}
  self.assertEqual(readiness(s,"t","e")["readiness_state"],"SCOPE_REQUIRED");self.assertIsNone(engagement_summary(s,"other","e"))
  s.scopes["q"]={"diagnostic_scope_id":"q","tenant_id":"t","engagement_id":"e","status":"REVIEW_PENDING"}
  self.assertEqual(readiness(s,"t","e")["readiness_state"],"SCOPE_APPROVALS_REQUIRED")
  s.approvals["a"]={"tenant_id":"t","subject_id":"q","status":"ACTIVE"};s.approvals["b"]={"tenant_id":"t","subject_id":"q","status":"ACTIVE"}
  self.assertEqual(readiness(s,"t","e")["readiness_state"],"SCOPE_REVIEW_PENDING")
  s.scopes["q"]["status"]="APPROVED";self.assertEqual(readiness(s,"t","e")["readiness_state"],"SCOPE_APPROVED")
if __name__=="__main__":unittest.main()
