"""Local-only durable coverage for CanonicalizeDiagnosticScope."""
from __future__ import annotations
import copy, os, sys, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path[:0]=[str(ROOT/"src"),str(ROOT/"tests"/"contracts")]
import psycopg
from avuhz_runtime.canonical_scope import compute_canonical_scope_digest
from avuhz_runtime.guards import COMMAND_CAPABILITIES, GuardPipeline, TrustedExecutionContext
from avuhz_runtime.in_memory import Executor, MemoryStore
from avuhz_runtime.postgres import PostgresStore, PostgresUnitOfWork, connection_factory_from_environment
from avuhz_runtime.projections import readiness
from avuhz_runtime.validation import CommandValidator
from validate_command_payloads import envelope, handoff, payloads
DSN=os.environ.get("AVUHZ_POSTGRES_DSN")
T="a3000000-0000-4000-8000-000000000002"; OTHER="a3000000-0000-4000-8000-000000000099"; E="a3000000-0000-4000-8000-000000000004"; S="a3000000-0000-4000-8000-000000000005"
def context(command, tenant=T):
 return TrustedExecutionContext(True,"durable-canonicalization-service","INTERNAL_SERVICE",tenant,None,frozenset({COMMAND_CAPABILITIES[command]}),frozenset(),"TEST","avuhz-command-api","STRONG",False,"2030-01-15T15:00:00Z","2030-01-15T16:00:00Z")
@unittest.skipUnless(DSN,"AVUHZ_POSTGRES_DSN is required for local integration tests")
class DurableCanonicalizationTests(unittest.TestCase):
 def setUp(self):
  with psycopg.connect(DSN) as c:
   for table in ("avuhz_outbox_deliveries","avuhz_lifecycle_events","avuhz_idempotency_records","avuhz_human_approvals","avuhz_diagnostic_scopes","avuhz_engagements","avuhz_acquisition_handoffs"): c.execute(f"delete from public.{table}")
   h=handoff(); c.execute("insert into public.avuhz_acquisition_handoffs (tenant_id,handoff_id,handoff_version,canonical_account_reference,acquisition_opportunity_reference,qualification_status,target_outcome,validated_constraints,stakeholder_context,assumptions,exclusions,requested_engagement_type,source_system,source_record_version,producer_identity,produced_at,correlation_id,idempotency_key,accepted_at) values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,null)",(h["tenant_id"],h["handoff_id"],h["handoff_version"],__import__("json").dumps(h["canonical_account_reference"]),__import__("json").dumps(h["acquisition_opportunity_reference"]),h["qualification_status"],h["target_outcome"],"[]","[]","[]","[]",h["requested_engagement_type"],h["source_system"],h["source_record_version"],h["producer_identity"],h["produced_at"],h["correlation_id"],h["idempotency_key"]))
  self.store=PostgresStore(connection_factory_from_environment()); ids=iter([f"b8000000-0000-4000-8000-{n:012d}" for n in range(1,100)])
  self.x=Executor(CommandValidator(ROOT/"contracts/schemas/v1"),GuardPipeline(),self.store,ids=lambda:next(ids),uow_factory=PostgresUnitOfWork)
 def raw(self, command, key=None, version=1):
  value=envelope(command,copy.deepcopy(payloads()[command])); value["idempotency_key"]=key or f"durable-{command.lower()}-0001"
  if command=="CanonicalizeDiagnosticScope": value["expected_record_version"]=version
  return value
 def execute(self, command, key=None, version=1, tenant=T): return self.x.execute(self.raw(command,key,version),context(command,tenant))
 def scope(self, tenant=T):
  u=PostgresUnitOfWork(self.store)
  try:return u.diagnostic_scopes.get(tenant,S)
  finally:u.close()
 def counts(self):
  with psycopg.connect(DSN) as c:
   return tuple(c.execute(f"select count(*) from public.{table} where " + ("tenant_id=%s and event_type='diagnostic_scope.canonicalized'" if table=="avuhz_lifecycle_events" else "tenant_id=%s and lifecycle_event_id in (select lifecycle_event_id from public.avuhz_lifecycle_events where tenant_id=%s and event_type='diagnostic_scope.canonicalized')" if table=="avuhz_outbox_deliveries" else "tenant_id=%s and command_type='CanonicalizeDiagnosticScope'" if table=="avuhz_idempotency_records" else "tenant_id=%s and diagnostic_scope_id=%s") , (T,T) if table=="avuhz_outbox_deliveries" else (T,S) if table=="avuhz_diagnostic_scopes" else (T,)).fetchone()[0] for table in ("avuhz_diagnostic_scopes","avuhz_idempotency_records","avuhz_lifecycle_events","avuhz_outbox_deliveries"))
 def establish(self):
  for command in ("AcceptAcquisitionHandoff","OpenEngagement","SubmitDiagnosticScope"): self.assertEqual(self.execute(command)["result"],"ACCEPTED")
  scope=self.scope(); self.assertIsNone(scope["canonical_scope_digest"]); return scope
 def test_durable_command_flow_atomicity_restart_duplicate_conflict_and_tenant_isolation(self):
  submitted=self.establish(); expected=compute_canonical_scope_digest(submitted); raw=self.raw("CanonicalizeDiagnosticScope","durable-canonicalize-0001")
  self.assertEqual(self.x.execute(raw,context("CanonicalizeDiagnosticScope"))["result"],"ACCEPTED"); stored=self.scope(); self.assertEqual(stored["canonical_scope_digest"],expected); self.assertEqual(stored["record_version"],2); self.assertEqual(stored["status"],"REVIEW_PENDING"); self.assertEqual(self.counts(),(1,1,1,1))
  with psycopg.connect(DSN) as c:
   event=c.execute("select event_type,authoritative_subject_id from public.avuhz_lifecycle_events where tenant_id=%s and event_type='diagnostic_scope.canonicalized'",(T,)).fetchall(); idem=c.execute("select processing_status from public.avuhz_idempotency_records where tenant_id=%s and command_type='CanonicalizeDiagnosticScope'",(T,)).fetchall(); approvals=c.execute("select count(*) from public.avuhz_human_approvals where tenant_id=%s",(T,)).fetchone()[0]
  self.assertEqual([(kind,str(subject)) for kind,subject in event],[("diagnostic_scope.canonicalized",S)]); self.assertEqual(idem,[("COMPLETED",)]); self.assertEqual(approvals,0)
  restarted=Executor(CommandValidator(ROOT/"contracts/schemas/v1"),GuardPipeline(),PostgresStore(connection_factory_from_environment()),ids=lambda:"b8000000-0000-4000-8000-000000000099",uow_factory=PostgresUnitOfWork)
  self.assertEqual(restarted.execute(raw,context("CanonicalizeDiagnosticScope"))["result"],"DUPLICATE"); changed=copy.deepcopy(raw); changed["payload"]["scope_version"]=2; self.assertEqual(restarted.execute(changed,context("CanonicalizeDiagnosticScope"))["result"],"CONFLICT"); self.assertEqual(self.counts(),(1,1,1,1))
  self.assertIsNone(self.scope(OTHER)); other=copy.deepcopy(raw); other["tenant_id"]=OTHER; self.assertEqual(restarted.execute(other,context("CanonicalizeDiagnosticScope",OTHER))["result"],"REJECTED"); self.assertEqual(self.scope()["canonical_scope_digest"],expected)
  replay_scope=self.scope(); state=MemoryStore(); state.engagements[E]={"tenant_id":T,"engagement_state":"OPEN"}; state.scopes[S]=replay_scope; self.assertNotEqual(readiness(state,T,E)["readiness_state"],"SCOPE_APPROVED")
 def test_failpoints_leave_no_partial_canonicalization_transaction(self):
  for point in ("AUTHORITATIVE_WRITE","IDEMPOTENCY_RESERVE","IDEMPOTENCY_COMPLETE","LIFECYCLE_EVENT_APPEND","OUTBOX_APPEND","COMMIT"):
   self.setUp(); self.establish(); self.store.fail_stage=point; result=self.execute("CanonicalizeDiagnosticScope",f"durable-failpoint-{point.lower()}")
   self.assertEqual(result["result"],"REJECTED",point); scope=self.scope(); self.assertIsNone(scope["canonical_scope_digest"],point); self.assertEqual(self.counts(),(1,0,0,0),point)
 def test_repository_exact_update_and_concurrency_predicates(self):
  submitted=self.establish(); digest=compute_canonical_scope_digest(submitted); u=PostgresUnitOfWork(self.store)
  try:u.diagnostic_scopes.set_canonical_scope_digest(T,S,1,1,digest);u.commit()
  finally:u.close()
  stored=self.scope(); self.assertEqual((stored["canonical_scope_digest"],stored["record_version"]),(digest,2))
  for tenant,version,record_version in ((OTHER,1,2),(T,2,2),(T,1,1)):
   u=PostgresUnitOfWork(self.store)
   try:
    with self.assertRaises(ValueError):u.diagnostic_scopes.set_canonical_scope_digest(tenant,S,version,record_version,digest)
    u.rollback()
   finally:u.close()
  stored=self.scope(); self.assertEqual((stored["canonical_scope_digest"],stored["record_version"]),(digest,2))
if __name__=="__main__":unittest.main()
