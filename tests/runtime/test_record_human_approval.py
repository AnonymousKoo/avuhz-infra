import copy,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path[:0]=[str(ROOT/"src"),str(ROOT/"tests"/"contracts")]
from avuhz_runtime.in_memory import Executor,MemoryStore
from avuhz_runtime.guards import GuardPipeline,TrustedExecutionContext,COMMAND_CAPABILITIES
from avuhz_runtime.projections import readiness
from avuhz_runtime.validation import CommandValidator
from validate_command_payloads import envelope,payloads,handoff
T="a3000000-0000-4000-8000-000000000002";E="a3000000-0000-4000-8000-000000000004";S="a3000000-0000-4000-8000-000000000005"
def context(command,role=None,caller="INTERNAL_SERVICE",principal="service",organization=None,tenant=T):
 return TrustedExecutionContext(True,principal,caller,tenant,None,frozenset({COMMAND_CAPABILITIES[command]}),frozenset(),"TEST","avuhz-command-api","STRONG",False,"2030-01-15T15:00:00Z","2030-01-15T16:00:00Z",principal if caller=="HUMAN" else None,organization,role)
class Tests(unittest.TestCase):
 def setUp(self):
  self.s=MemoryStore();h=handoff();self.s.handoffs[h["handoff_id"]]=h;ids=iter(f"b9000000-0000-4000-8000-{n:012d}" for n in range(1,100));self.x=Executor(CommandValidator(ROOT/"contracts/schemas/v1"),GuardPipeline(),self.s,ids=lambda:next(ids))
 def raw(self,command,key,command_id,version=1):
  x=envelope(command,copy.deepcopy(payloads()[command]));x["idempotency_key"]=key;x["command_id"]=command_id
  if command not in ("AcceptAcquisitionHandoff","OpenEngagement"):x["expected_record_version"]=version
  return x
 def execute_command(self,command,key,command_id,ctx=None,version=1):return self.x.execute(self.raw(command,key,command_id,version),ctx or context(command))
 def establish(self):
  for n,c in enumerate(("AcceptAcquisitionHandoff","OpenEngagement","SubmitDiagnosticScope","CanonicalizeDiagnosticScope"),1):self.assertEqual(self.execute_command(c,f"approval-base-{n:04d}",f"b9000000-0000-4000-8000-{n:012d}",version=1)["result"],"ACCEPTED")
  self.assertIsNotNone(self.s.scopes[S]["canonical_scope_digest"])
 def approval(self,role,key,ident,ctx=None):
  x=self.raw("RecordHumanApproval",key,ident,2);x["caller_type"]="HUMAN";x["caller_identity"]["caller_type"]="HUMAN";x["caller_identity"]["capabilities"]=["scope:approve"];x["payload"]["authority_role"]=role;return self.x.execute(x,ctx or context("RecordHumanApproval",role,"HUMAN",f"human:{role.lower()}",f"org:{role.lower()}"))
 def final(self,key="approval-final-0001",version=2):
  x=self.raw("ApproveDiagnosticScope",key,"b9000000-0000-4000-8000-000000000030",version);x["payload"].update(scope_content_digest=self.s.scopes[S]["canonical_scope_digest"],client_approval_reference={"reference_type":"HUMAN_APPROVAL","reference_id":"b9000000-0000-4000-8000-000000000010","reference_version":1},sekinfra_approval_reference={"reference_type":"HUMAN_APPROVAL","reference_id":"b9000000-0000-4000-8000-000000000011","reference_version":1});return self.x.execute(x,context("ApproveDiagnosticScope"))
 def test_full_flow_separate_attributed_approvals_and_finalizer(self):
  self.establish();self.assertEqual(self.approval("CLIENT_DECISION_AUTHORITY","approval-client-0001","b9000000-0000-4000-8000-000000000010")["result"],"ACCEPTED");self.assertEqual(self.s.scopes[S]["status"],"REVIEW_PENDING")
  self.assertEqual(self.approval("SEKINFRA_ENGAGEMENT_AUTHORITY","approval-sekinfra-0001","b9000000-0000-4000-8000-000000000011")["result"],"ACCEPTED");self.assertEqual(self.s.scopes[S]["status"],"REVIEW_PENDING")
  a=list(self.s.approvals.values());self.assertEqual(len(a),2);self.assertEqual({x["authority_role"] for x in a},{"CLIENT_DECISION_AUTHORITY","SEKINFRA_ENGAGEMENT_AUTHORITY"});self.assertEqual({x["canonical_scope_digest"] for x in a},{self.s.scopes[S]["canonical_scope_digest"]});self.assertEqual({x["action_set_version"] for x in a},{1});self.assertEqual({x["approving_organization_reference"] for x in a},{"org:client_decision_authority","org:sekinfra_engagement_authority"})
  self.assertEqual(self.final()["result"],"ACCEPTED");self.assertEqual(self.s.scopes[S]["status"],"APPROVED");self.assertEqual(readiness(self.s,T,E)["readiness_state"],"SCOPE_APPROVED");self.assertEqual([e["event_type"] for e in self.s.events][-3:],["human_approval.recorded","human_approval.recorded","diagnostic_scope.approved"])
 def test_finalizer_requires_exact_dual_authority_binding(self):
  self.establish();digest=self.s.scopes[S]["canonical_scope_digest"]
  def record(role,tenant=T,scope=S,version=1,bound=digest,action=1,status="ACTIVE"):return {"tenant_id":tenant,"authority_role":role,"status":status,"subject_id":scope,"subject_version":version,"canonical_scope_digest":bound,"action_set_version":action}
  self.assertEqual(self.final("final-no-approvals-0001")["result"],"REJECTED")
  cases=[(record("CLIENT_DECISION_AUTHORITY"),None),(None,record("SEKINFRA_ENGAGEMENT_AUTHORITY")),(record("CLIENT_DECISION_AUTHORITY",tenant="a3000000-0000-4000-8000-000000000099"),record("SEKINFRA_ENGAGEMENT_AUTHORITY")),(record("CLIENT_DECISION_AUTHORITY",scope="a3000000-0000-4000-8000-000000000099"),record("SEKINFRA_ENGAGEMENT_AUTHORITY")),(record("CLIENT_DECISION_AUTHORITY",version=2),record("SEKINFRA_ENGAGEMENT_AUTHORITY")),(record("CLIENT_DECISION_AUTHORITY",bound="sha256:"+"b"*64),record("SEKINFRA_ENGAGEMENT_AUTHORITY")),(record("CLIENT_DECISION_AUTHORITY",action=2),record("SEKINFRA_ENGAGEMENT_AUTHORITY")),(record("CLIENT_DECISION_AUTHORITY",status="REVOKED"),record("SEKINFRA_ENGAGEMENT_AUTHORITY")),(record("CLIENT_DECISION_AUTHORITY"),record("CLIENT_DECISION_AUTHORITY"))]
  for n,(client,sek) in enumerate(cases):
   self.s.approvals={};
   if client:self.s.approvals["b9000000-0000-4000-8000-000000000010"]=client
   if sek:self.s.approvals["b9000000-0000-4000-8000-000000000011"]=sek
   self.assertEqual(self.final(f"final-binding-negative-{n:04d}")["result"],"REJECTED")
 def test_approval_and_finalizer_rejections(self):
  # pre-canonicalization, workload forgery, role mismatch, missing attribution, versions, unknown/duplicate authority.
  for n,c in enumerate(("AcceptAcquisitionHandoff","OpenEngagement","SubmitDiagnosticScope"),1):self.assertEqual(self.execute_command(c,f"approval-pre-{n:04d}",f"b9000000-0000-4000-8000-{40+n:012d}")["result"],"ACCEPTED")
  self.assertEqual(self.approval("CLIENT_DECISION_AUTHORITY","approval-pre-canonical-0001","b9000000-0000-4000-8000-000000000050")["result"],"REJECTED");self.assertEqual(self.execute_command("CanonicalizeDiagnosticScope","approval-canon-neg-0001","b9000000-0000-4000-8000-000000000051")["result"],"ACCEPTED")
  cases=[context("RecordHumanApproval","CLIENT_DECISION_AUTHORITY","INTERNAL_SERVICE"),context("RecordHumanApproval","SEKINFRA_ENGAGEMENT_AUTHORITY","HUMAN","human:client","org:client"),context("RecordHumanApproval","CLIENT_DECISION_AUTHORITY","HUMAN","human:client",None),context("RecordHumanApproval","CLIENT_DECISION_AUTHORITY","HUMAN","human:client","org:client", "a3000000-0000-4000-8000-000000000099")]
  for i,c in enumerate(cases):self.assertEqual(self.approval("CLIENT_DECISION_AUTHORITY",f"approval-denied-{i:04d}",f"b9000000-0000-4000-8000-{60+i:012d}",c)["result"],"REJECTED")
  self.assertEqual(self.approval("CLIENT_DECISION_AUTHORITY","client-only-0001","b9000000-0000-4000-8000-000000000010")["result"],"ACCEPTED");self.assertEqual(self.approval("CLIENT_DECISION_AUTHORITY","duplicate-role-0001","b9000000-0000-4000-8000-000000000070")["result"],"REJECTED");self.assertEqual(self.final("final-client-only-0001")["result"],"REJECTED")
  bad=self.raw("RecordHumanApproval","wrong-action-0001","b9000000-0000-4000-8000-000000000071",2);bad["payload"].update(authority_role="SEKINFRA_ENGAGEMENT_AUTHORITY",action_set_version=2);self.assertEqual(self.x.execute(bad,context("RecordHumanApproval","SEKINFRA_ENGAGEMENT_AUTHORITY","HUMAN","human:sek","org:sek"))["result"],"REJECTED")
if __name__=="__main__":unittest.main()
