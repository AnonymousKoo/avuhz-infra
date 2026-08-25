import sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/"src"))
from avuhz_runtime.in_memory import *
class Tests(unittest.TestCase):
 def test_surfaces_share_working_transaction_and_are_tenant_aware(self):
  s=MemoryStore();u=UnitOfWork(s)
  self.assertTrue(all(hasattr(u,n) for n in ("handoffs","engagements","diagnostic_scopes","oia_assessments","oia_evidence_items","human_approvals","idempotency","lifecycle_events","outbox")))
  r={"handoff_id":"h","tenant_id":"t"};u.handoffs.save(r);self.assertEqual(u.handoffs.get("t","h"),r);self.assertIsNone(u.handoffs.get("other","h"));self.assertEqual(s.handoffs,{})
  u.lifecycle_events.append({"event_id":"e"});u.outbox.append({"event_id":"e","status":"PENDING"});u.idempotency.save_result(("k",),{"fingerprint":"fp"});u.commit()
  self.assertEqual(len(s.events),1);self.assertEqual(len(s.outbox),1);self.assertIn(("k",),s.idempotency)
if __name__=="__main__":unittest.main()
