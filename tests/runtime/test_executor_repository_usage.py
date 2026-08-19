import inspect,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/"src"))
from avuhz_runtime.in_memory import Executor
class Tests(unittest.TestCase):
 def test_executor_uses_repository_surfaces(self):
  source=inspect.getsource(Executor.execute)
  for forbidden in ("self.store.idempotency","working.events","working.outbox","working.idempotency"):
   self.assertNotIn(forbidden,source)
  for required in ("u.idempotency.get","u.idempotency.reserve","u.idempotency.save_result","u.lifecycle_events.append","u.outbox.append"):
   self.assertIn(required,source)
if __name__=="__main__":unittest.main()
