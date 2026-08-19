import copy,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path[:0]=[str(ROOT/"src"),str(ROOT/"tests/contracts")]
from avuhz_runtime.in_memory import MemoryStore,Executor
from avuhz_runtime.validation import CommandValidator
from avuhz_runtime.guards import GuardPipeline,TrustedExecutionContext,COMMAND_CAPABILITIES
from validate_command_payloads import envelope,payloads,handoff
T="a3000000-0000-4000-8000-000000000002"
class Tests(unittest.TestCase):
 def test_all_named_failpoints_rollback_handoff(self):
  for point in ("AUTHORITATIVE_WRITE","IDEMPOTENCY_RESERVE","IDEMPOTENCY_COMPLETE","LIFECYCLE_EVENT_APPEND","OUTBOX_APPEND","COMMIT"):
   s=MemoryStore(fail_stage=point);h=handoff();s.handoffs[h["handoff_id"]]=h;x=Executor(CommandValidator(ROOT/"contracts/schemas/v1"),GuardPipeline(),s)
   c=TrustedExecutionContext(True,"p","INTERNAL_SERVICE",T,None,frozenset({COMMAND_CAPABILITIES["AcceptAcquisitionHandoff"]}),frozenset(),"TEST","avuhz-command-api","STRONG",False,"2030-01-15T15:00:00Z","2030-01-15T16:00:00Z")
   r=x.execute(envelope("AcceptAcquisitionHandoff",copy.deepcopy(payloads()["AcceptAcquisitionHandoff"])),c)
   self.assertEqual(r["result"],"REJECTED",point);self.assertNotIn("accepted",s.handoffs[h["handoff_id"]],point);self.assertEqual(s.events,[],point);self.assertEqual(s.outbox,[],point);self.assertEqual(s.idempotency,{},point)
if __name__=="__main__":unittest.main()
