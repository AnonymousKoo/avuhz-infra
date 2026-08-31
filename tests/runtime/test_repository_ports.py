import sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/"src"))
from avuhz_runtime.in_memory import MemoryStore,UnitOfWork
class Tests(unittest.TestCase):
 def test_active_uow_surfaces_are_generic_and_transactional(self):
  store=MemoryStore();uow=UnitOfWork(store)
  expected=("handoffs","engagements","implementation_handoffs","implementation_briefs","implementation_authorizations","codex_build_packages","build_execution_results","qa_results","client_acceptances","deployment_authorizations","human_approvals","idempotency","lifecycle_events","outbox")
  self.assertTrue(all(hasattr(uow,name) for name in expected));uow.lifecycle_events.append({"event_id":"e"});uow.outbox.append({"event_id":"e","status":"PENDING"});uow.commit();self.assertEqual(len(store.events),1)
if __name__=="__main__":unittest.main()
