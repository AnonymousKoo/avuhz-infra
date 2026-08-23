"""Local-only durable trusted HumanApproval and finalization coverage."""
from __future__ import annotations
import copy,os,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path[:0]=[str(ROOT/"src"),str(ROOT/"tests"/"contracts")]
import psycopg
from avuhz_runtime.guards import COMMAND_CAPABILITIES,GuardPipeline,TrustedExecutionContext
from avuhz_runtime.in_memory import Executor,MemoryStore
from avuhz_runtime.postgres import PostgresStore,PostgresUnitOfWork,connection_factory_from_environment
from avuhz_runtime.projections import readiness
from avuhz_runtime.validation import CommandValidator
from validate_command_payloads import envelope,handoff,payloads
DSN=os.environ.get("AVUHZ_POSTGRES_DSN");T="a3000000-0000-4000-8000-000000000002";OTHER="a3000000-0000-4000-8000-000000000099";E="a3000000-0000-4000-8000-000000000004";S="a3000000-0000-4000-8000-000000000005"
def context(command,role=None,caller="INTERNAL_SERVICE",principal="durable-service",organization=None,tenant=T):
 return TrustedExecutionContext(True,principal,caller,tenant,None,frozenset({COMMAND_CAPABILITIES[command]}),frozenset(),"TEST","avuhz-command-api","STRONG",False,"2030-01-15T15:00:00Z","2030-01-15T16:00:00Z",principal if caller=="HUMAN" else None,organization,role)
@unittest.skipUnless(DSN,"AVUHZ_POSTGRES_DSN is required")
class Tests(unittest.TestCase):
 def setUp(self):
  with psycopg.connect(DSN) as c:
   for table in ("avuhz_outbox_deliveries","avuhz_lifecycle_events","avuhz_idempotency_records","avuhz_human_approvals","avuhz_diagnostic_scopes","avuhz_engagements","avuhz_acquisition_handoffs"):c.execute(f"delete from public.{table}")
   h=handoff();c.execute("insert into public.avuhz_acquisition_handoffs (tenant_id,handoff_id,handoff_version,canonical_account_reference,acquisition_opportunity_reference,qualification_status,target_outcome,validated_constraints,stakeholder_context,assumptions,exclusions,requested_engagement_type,source_system,source_record_version,producer_identity,produced_at,correlation_id,idempotency_key,accepted_at) values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,null)",(h["tenant_id"],h["handoff_id"],h["handoff_version"],__import__("json").dumps(h["canonical_account_reference"]),__import__("json").dumps(h["acquisition_opportunity_reference"]),h["qualification_status"],h["target_outcome"],"[]","[]","[]","[]",h["requested_engagement_type"],h["source_system"],h["source_record_version"],h["producer_identity"],h["produced_at"],h["correlation_id"],h["idempotency_key"]))
  self.store=PostgresStore(connection_factory_from_environment());ids=iter(f"ba000000-0000-4000-8000-{n:012d}" for n in range(1,100));self.x=Executor(CommandValidator(ROOT/"contracts/schemas/v1"),GuardPipeline(),self.store,ids=lambda:next(ids),uow_factory=PostgresUnitOfWork)
 def raw(self,command,key,ident,version=1):
  x=envelope(command,copy.deepcopy(payloads()[command]));x["idempotency_key"]=key;x["command_id"]=ident
  if command not in ("AcceptAcquisitionHandoff","OpenEngagement"):x["expected_record_version"]=version
  if command=="RecordHumanApproval":x["caller_type"]="HUMAN";x["caller_identity"]["caller_type"]="HUMAN";x["caller_identity"]["capabilities"]=["scope:approve"]
  return x
 def execute_command(self,command,key,ident,ctx=None,version=1):return self.x.execute(self.raw(command,key,ident,version),ctx or context(command))
 def approval(self,role,key,ident,ctx=None):
  x=self.raw("RecordHumanApproval",key,ident,2);x["payload"]["authority_role"]=role;return self.x.execute(x,ctx or context("RecordHumanApproval",role,"HUMAN",f"human:{role.lower()}",f"org:{role.lower()}"))
 def scope(self,tenant=T):
  u=PostgresUnitOfWork(self.store)
  try:return u.diagnostic_scopes.get(tenant,S)
  finally:u.close()
 def establish(self):
  for n,c in enumerate(("AcceptAcquisitionHandoff","OpenEngagement","SubmitDiagnosticScope","CanonicalizeDiagnosticScope"),1):self.assertEqual(self.execute_command(c,f"durable-approval-base-{n:04d}",f"ba000000-0000-4000-8000-{n:012d}")["result"],"ACCEPTED")
 def final(self,key="durable-approval-final-0001"):
  x=self.raw("ApproveDiagnosticScope",key,"ba000000-0000-4000-8000-000000000030",2);x["payload"].update(scope_content_digest=self.scope()["canonical_scope_digest"],client_approval_reference={"reference_type":"HUMAN_APPROVAL","reference_id":"ba000000-0000-4000-8000-000000000010","reference_version":1},sekinfra_approval_reference={"reference_type":"HUMAN_APPROVAL","reference_id":"ba000000-0000-4000-8000-000000000011","reference_version":1});return self.x.execute(x,context("ApproveDiagnosticScope"))
 def counts(self):
  with psycopg.connect(DSN) as c:return tuple(c.execute(f"select count(*) from public.{t}").fetchone()[0] for t in ("avuhz_human_approvals","avuhz_idempotency_records","avuhz_lifecycle_events","avuhz_outbox_deliveries"))
 def test_durable_full_flow_attribution_restart_duplicate_and_tenant_isolation(self):
  self.establish();self.assertEqual(self.approval("CLIENT_DECISION_AUTHORITY","durable-client-approval-0001","ba000000-0000-4000-8000-000000000010")["result"],"ACCEPTED");self.assertEqual(self.scope()["status"],"REVIEW_PENDING");self.assertEqual(self.approval("SEKINFRA_ENGAGEMENT_AUTHORITY","durable-sekinfra-approval-0001","ba000000-0000-4000-8000-000000000011")["result"],"ACCEPTED");self.assertEqual(self.final()["result"],"ACCEPTED")
  with psycopg.connect(DSN) as c: rows=c.execute("select approval_role,approving_principal_reference,approving_organization_reference,diagnostic_scope_id,approved_scope_version,canonical_scope_digest,action_set_version,status from public.avuhz_human_approvals where tenant_id=%s order by approval_role",(T,)).fetchall()
  self.assertEqual([(x[0],x[1],x[2],str(x[3]),x[4],x[6],x[7]) for x in rows],[("CLIENT_DECISION_AUTHORITY","human:client_decision_authority","org:client_decision_authority",S,1,1,"ACTIVE"),("SEKINFRA_ENGAGEMENT_AUTHORITY","human:sekinfra_engagement_authority","org:sekinfra_engagement_authority",S,1,1,"ACTIVE")]);self.assertEqual({x[5] for x in rows},{self.scope()["canonical_scope_digest"]});self.assertEqual(self.scope()["status"],"APPROVED");self.assertEqual(self.counts(),(2,7,7,7))
  fresh=Executor(CommandValidator(ROOT/"contracts/schemas/v1"),GuardPipeline(),PostgresStore(connection_factory_from_environment()),ids=lambda:"ba000000-0000-4000-8000-000000000099",uow_factory=PostgresUnitOfWork);raw=self.raw("RecordHumanApproval","durable-client-approval-0001","ba000000-0000-4000-8000-000000000010",2);raw["payload"]["authority_role"]="CLIENT_DECISION_AUTHORITY";self.assertEqual(fresh.execute(raw,context("RecordHumanApproval","CLIENT_DECISION_AUTHORITY","HUMAN","human:client_decision_authority","org:client_decision_authority"))["result"],"DUPLICATE");self.assertEqual(self.counts(),(2,7,7,7));self.assertIsNone(self.scope(OTHER));other=copy.deepcopy(raw);other["tenant_id"]=OTHER;self.assertEqual(fresh.execute(other,context("RecordHumanApproval","CLIENT_DECISION_AUTHORITY","HUMAN","human:other","org:other",OTHER))["result"],"REJECTED")
  state=MemoryStore();state.engagements[E]={"tenant_id":T,"engagement_state":"OPEN"};state.scopes[S]=self.scope();state.approvals={str(i):{"tenant_id":T,"subject_id":S,"status":"ACTIVE"} for i in (1,2)};self.assertEqual(readiness(state,T,E)["readiness_state"],"SCOPE_APPROVED")
 def test_approval_failpoints_leave_no_partial_artifacts(self):
  for point in ("AUTHORITATIVE_WRITE","IDEMPOTENCY_RESERVE","IDEMPOTENCY_COMPLETE","LIFECYCLE_EVENT_APPEND","OUTBOX_APPEND","COMMIT"):
   self.setUp();self.establish();self.store.fail_stage=point;self.assertEqual(self.approval("CLIENT_DECISION_AUTHORITY",f"durable-fail-{point.lower()}","ba000000-0000-4000-8000-000000000010")["result"],"REJECTED");self.assertEqual(self.counts(),(0,4,4,4),point)
 def test_duplicate_active_authority_and_finalizer_negative(self):
  self.establish();self.assertEqual(self.approval("CLIENT_DECISION_AUTHORITY","durable-client-one-0001","ba000000-0000-4000-8000-000000000010")["result"],"ACCEPTED");self.assertEqual(self.approval("CLIENT_DECISION_AUTHORITY","durable-client-two-0001","ba000000-0000-4000-8000-000000000012")["result"],"REJECTED");self.assertEqual(self.final("durable-final-client-only-0001")["result"],"REJECTED")
if __name__=="__main__":unittest.main()
