import sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/"src"))
from avuhz_runtime.in_memory import MemoryStore,UnitOfWork,fingerprint
from avuhz_runtime.projections import readiness,engagement_summary
class Tests(unittest.TestCase):
 def test_copy_on_write_rollback_and_fingerprint(self):
  s=MemoryStore();u=UnitOfWork(s);u.working.engagements["e"]={"tenant_id":"t"};self.assertEqual(s.engagements,{})
  a={"tenant_id":"t","command_type":"OpenEngagement","subject_type":"ENGAGEMENT","subject_id":"x","payload":{"a":1}};b={**a,"payload":{"a":2}};self.assertNotEqual(fingerprint(a),fingerprint(b))
 def test_generic_engagement_projection_is_tenant_scoped(self):
  s=MemoryStore();self.assertEqual(readiness(s,"t")["readiness_state"],"READY_TO_OPEN_ENGAGEMENT");self.assertEqual(readiness(s,"t","e")["readiness_state"],"HANDOFF_PENDING")
  s.engagements["e"]={"tenant_id":"t","engagement_state":"OPEN"};self.assertEqual(readiness(s,"t","e")["readiness_state"],"ENGAGEMENT_OPEN");self.assertIsNone(engagement_summary(s,"other","e"))
if __name__=="__main__":unittest.main()
