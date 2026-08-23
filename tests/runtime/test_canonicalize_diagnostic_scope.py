import copy, sys, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path[:0]=[str(ROOT/"src"),str(ROOT/"tests"/"contracts")]
from avuhz_runtime.canonical_scope import compute_canonical_scope_digest
from avuhz_runtime.guards import COMMAND_CAPABILITIES, GuardPipeline, TrustedExecutionContext
from avuhz_runtime.in_memory import Executor, MemoryStore
from avuhz_runtime.projections import readiness
from avuhz_runtime.validation import CommandValidator
from validate_command_payloads import envelope, handoff, payloads
T="a3000000-0000-4000-8000-000000000002"; E="a3000000-0000-4000-8000-000000000004"; S="a3000000-0000-4000-8000-000000000005"
def ctx(capabilities=None, tenant=T):
 return TrustedExecutionContext(True,"canonicalization-service","INTERNAL_SERVICE",tenant,None,frozenset({COMMAND_CAPABILITIES["CanonicalizeDiagnosticScope"]} if capabilities is None else capabilities),frozenset(),"TEST","avuhz-command-api","STRONG",False,"2030-01-15T15:00:00Z","2030-01-15T16:00:00Z")
class Tests(unittest.TestCase):
 def setUp(self):
  self.s=MemoryStore(); h=handoff(); self.s.handoffs[h["handoff_id"]]=h
  self.x=Executor(CommandValidator(ROOT/"contracts/schemas/v1"),GuardPipeline(),self.s,ids=lambda:"b7000000-0000-4000-8000-000000000001")
 def raw(self, key="slice1-canonicalize-0001", version=1):
  value=envelope("CanonicalizeDiagnosticScope",copy.deepcopy(payloads()["CanonicalizeDiagnosticScope"])); value["idempotency_key"]=key; value["expected_record_version"]=version; return value
 def establish_submitted_scope(self):
  def run(command):
   value=envelope(command,copy.deepcopy(payloads()[command])); return self.x.execute(value,TrustedExecutionContext(True,"canonicalization-service","INTERNAL_SERVICE",T,None,frozenset({COMMAND_CAPABILITIES[command]}),frozenset(),"TEST","avuhz-command-api","STRONG",False,"2030-01-15T15:00:00Z","2030-01-15T16:00:00Z"))
  self.assertEqual(run("AcceptAcquisitionHandoff")["result"],"ACCEPTED"); self.assertEqual(run("OpenEngagement")["result"],"ACCEPTED"); self.assertEqual(run("SubmitDiagnosticScope")["result"],"ACCEPTED")
  return self.s.scopes[S]
 def test_positive_executor_flow_digest_event_outbox_and_no_approvals(self):
  scope=self.establish_submitted_scope(); before=copy.deepcopy(scope)
  self.assertIsNone(scope.get("canonical_scope_digest")); self.assertEqual(self.x.execute(self.raw(),ctx())["result"],"ACCEPTED")
  stored=self.s.scopes[S]; self.assertEqual(stored["canonical_scope_digest"],compute_canonical_scope_digest(stored)); self.assertEqual(stored["record_version"],before["record_version"]+1)
  for key in ("diagnostic_scope_id","engagement_id","tenant_id","scope_version","status","target_outcome","in_scope_systems","excluded_systems","permitted_diagnostic_actions","prohibited_actions","assumptions","constraints"): self.assertEqual(stored[key],before[key])
  self.assertEqual(self.s.approvals,{}); self.assertNotEqual(readiness(self.s,T,E)["readiness_state"],"SCOPE_APPROVED"); self.assertEqual(stored["status"],"REVIEW_PENDING")
  self.assertEqual(len(self.s.events),4); self.assertEqual(len(self.s.outbox),4); self.assertEqual(self.s.events[-1]["event_type"],"diagnostic_scope.canonicalized"); self.assertEqual(self.s.events[-1]["subject_id"],S); self.assertEqual(self.s.outbox[-1],{"event_id":self.s.events[-1]["event_id"],"status":"PENDING"})
 def test_idempotency_and_identical_recanonicalization_are_bounded(self):
  self.establish_submitted_scope(); raw=self.raw(); self.assertEqual(self.x.execute(raw,ctx())["result"],"ACCEPTED"); frozen=copy.deepcopy(self.s.scopes[S])
  self.assertEqual(self.x.execute(raw,ctx())["result"],"DUPLICATE"); changed=copy.deepcopy(raw); changed["payload"]["scope_version"]=2; self.assertEqual(self.x.execute(changed,ctx())["result"],"CONFLICT")
  self.assertEqual(self.x.execute(self.raw("slice1-canonicalize-0002",2),ctx())["result"],"ACCEPTED"); self.assertEqual(self.s.scopes[S],frozen)
 def test_rejects_tenant_subject_version_and_capability_failures(self):
  self.establish_submitted_scope(); wrong_tenant=self.raw("slice1-canonicalize-tenant"); wrong_tenant["tenant_id"]="a3000000-0000-4000-8000-000000000099"; self.assertEqual(self.x.execute(wrong_tenant,ctx())["result"],"REJECTED")
  unknown=self.raw("slice1-canonicalize-unknown"); unknown["subject_id"]="a3000000-0000-4000-8000-000000000099"; unknown["payload"]["diagnostic_scope_id"]=unknown["subject_id"]; self.assertEqual(self.x.execute(unknown,ctx())["result"],"REJECTED")
  wrong_version=self.raw("slice1-canonicalize-version"); wrong_version["payload"]["scope_version"]=2; self.assertEqual(self.x.execute(wrong_version,ctx())["result"],"REJECTED")
  self.assertEqual(self.x.execute(self.raw("slice1-canonicalize-no-submit"),ctx(frozenset()))["result"],"REJECTED"); self.assertEqual(self.x.execute(self.raw("slice1-canonicalize-approve-only"),ctx(frozenset({"scope:approve"})))["result"],"REJECTED")
 def test_rejects_payload_digest_and_conflicting_existing_digest_without_human_authority(self):
  self.establish_submitted_scope(); invalid=self.raw("slice1-canonicalize-payload"); invalid["payload"]["canonical_scope_digest"]="sha256:"+"a"*64; self.assertEqual(self.x.execute(invalid,ctx())["result"],"VALIDATION_FAILED")
  self.assertEqual(self.x.execute(self.raw(),ctx())["result"],"ACCEPTED"); self.s.scopes[S]["target_outcome"]="Changed authoritative content"; result=self.x.execute(self.raw("slice1-canonicalize-conflict",2),ctx()); self.assertEqual(result["result"],"CONFLICT"); self.assertEqual(self.s.approvals,{})
if __name__=="__main__":unittest.main()
