import inspect,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/"src"))
from avuhz_runtime.in_memory import Executor
class Tests(unittest.TestCase):
 def test_handlers_use_uow_repositories_not_working_state(self):
  source=inspect.getsource(Executor._handle)
  self.assertNotIn(".working",source)
  for surface in ("u.handoffs","u.engagements","u.diagnostic_scopes","u.human_approvals"):
   self.assertIn(surface,source)
if __name__=="__main__":unittest.main()
