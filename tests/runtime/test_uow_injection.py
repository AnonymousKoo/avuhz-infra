import copy,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path[:0]=[str(ROOT/"src"),str(ROOT/"tests/contracts")]
from avuhz_runtime.in_memory import MemoryStore,UnitOfWork,Executor
from avuhz_runtime.validation import CommandValidator
from avuhz_runtime.guards import GuardPipeline,TrustedExecutionContext,COMMAND_CAPABILITIES
from validate_command_payloads import envelope,payloads,handoff
class Factory:
 def __init__(self):self.calls=0
 def __call__(self,store):self.calls+=1;return UnitOfWork(store)
class Tests(unittest.TestCase):
 def test_executor_acquires_injected_unit_of_work(self):
  s=MemoryStore();h=handoff();s.handoffs[h["handoff_id"]]=h;f=Factory();x=Executor(CommandValidator(ROOT/"contracts/schemas/v1"),GuardPipeline(),s,uow_factory=f)
  c=TrustedExecutionContext(True,"p","INTERNAL_SERVICE","a3000000-0000-4000-8000-000000000002",None,frozenset({COMMAND_CAPABILITIES["AcceptAcquisitionHandoff"]}),frozenset(),"TEST","avuhz-command-api","STRONG",False,"2030-01-15T15:00:00Z","2030-01-15T16:00:00Z")
  self.assertEqual(x.execute(envelope("AcceptAcquisitionHandoff",copy.deepcopy(payloads()["AcceptAcquisitionHandoff"])),c)["result"],"ACCEPTED");self.assertEqual(f.calls,1)
if __name__=="__main__":unittest.main()
