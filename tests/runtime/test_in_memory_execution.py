import copy,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path[:0]=[str(ROOT/"src"),str(ROOT/"tests/contracts")]
from avuhz_runtime.in_memory import *
from avuhz_runtime.validation import CommandValidator
from avuhz_runtime.guards import GuardPipeline,TrustedExecutionContext,COMMAND_CAPABILITIES
from validate_command_payloads import envelope,payloads,handoff
T="a3000000-0000-4000-8000-000000000002"
def ctx(c):return TrustedExecutionContext(True,"fictional-principal","INTERNAL_SERVICE",T,None,frozenset({COMMAND_CAPABILITIES[c]}),frozenset(),"TEST","avuhz-command-api","STRONG",False,"2030-01-15T15:00:00Z","2030-01-15T16:00:00Z")
class Tests(unittest.TestCase):
 def setUp(self):
  self.s=MemoryStore();h=handoff();self.s.handoffs[h["handoff_id"]]=h;self.x=Executor(CommandValidator(ROOT/"contracts/schemas/v1"),GuardPipeline(),self.s,ids=lambda:"b6000000-0000-4000-8000-000000000001")
 def execute_command(self,c):return self.x.execute(envelope(c,copy.deepcopy(payloads()[c])),ctx(c))
 def test_happy_duplicate_conflict_and_rollback(self):
  self.assertEqual(self.execute_command("AcceptAcquisitionHandoff")["result"],"ACCEPTED");self.assertEqual(self.execute_command("AcceptAcquisitionHandoff")["result"],"DUPLICATE")
  self.assertEqual(self.execute_command("OpenEngagement")["result"],"ACCEPTED");self.assertEqual(self.execute_command("SubmitDiagnosticScope")["result"],"ACCEPTED");self.assertEqual(self.execute_command("CanonicalizeDiagnosticScope")["result"],"ACCEPTED")
  p=payloads()["ApproveDiagnosticScope"];scope="a3000000-0000-4000-8000-000000000005";digest=self.s.scopes[scope]["canonical_scope_digest"]
  for ref,role,auth in ((p["client_approval_reference"],"CLIENT_DECISION_AUTHORITY","CLIENT_AUTHORITY"),(p["sekinfra_approval_reference"],"SEKINFRA_ENGAGEMENT_AUTHORITY","SEKINFRA_AUTHORITY")):
   self.s.approvals[ref["reference_id"]]={"tenant_id":T,"authority_role":role,"authority_category":auth,"status":"ACTIVE","subject_id":scope,"subject_version":1,"canonical_scope_digest":digest,"action_set_version":1}
  p["scope_content_digest"]=digest;raw=envelope("ApproveDiagnosticScope",copy.deepcopy(p));raw["expected_record_version"]=2
  self.assertEqual(self.x.execute(raw,ctx("ApproveDiagnosticScope"))["result"],"ACCEPTED");self.assertEqual(len(self.s.events),5);self.assertEqual(len(self.s.outbox),5);self.assertEqual(self.s.scopes[scope]["status"],"APPROVED")
  raw["payload"]["scope_content_digest"]="sha256:"+"b"*64;self.assertEqual(self.x.execute(raw,ctx("ApproveDiagnosticScope"))["result"],"CONFLICT")
 def test_failures_do_not_commit(self):
  before=(len(self.s.events),len(self.s.outbox));self.assertEqual(self.execute_command("OpenEngagement")["result"],"REJECTED");self.assertEqual((len(self.s.events),len(self.s.outbox)),before)
if __name__=="__main__":unittest.main()
