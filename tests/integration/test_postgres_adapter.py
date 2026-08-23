"""Local-only integration coverage for the PostgreSQL Slice 1 adapter."""
from __future__ import annotations
import copy, os, sys, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; sys.path[:0]=[str(ROOT/'src'),str(ROOT/'tests/contracts')]
import psycopg
from avuhz_runtime.in_memory import Executor
from avuhz_runtime.postgres import PostgresStore, PostgresUnitOfWork, connection_factory_from_environment
from avuhz_runtime.validation import CommandValidator
from avuhz_runtime.guards import GuardPipeline, TrustedExecutionContext, COMMAND_CAPABILITIES
from validate_command_payloads import envelope, payloads, handoff

DSN=os.environ.get('AVUHZ_POSTGRES_DSN')
T='a3000000-0000-4000-8000-000000000002'
def ctx(): return TrustedExecutionContext(True,'durable-test-principal','INTERNAL_SERVICE',T,None,frozenset({COMMAND_CAPABILITIES['AcceptAcquisitionHandoff']}),frozenset(),'TEST','avuhz-command-api','STRONG',False,'2030-01-15T15:00:00Z','2030-01-15T16:00:00Z')

@unittest.skipUnless(DSN, 'AVUHZ_POSTGRES_DSN is required for local integration tests')
class PostgresAdapterTests(unittest.TestCase):
 def setUp(self):
  with psycopg.connect(DSN) as c:
   c.execute('delete from public.avuhz_outbox_deliveries'); c.execute('delete from public.avuhz_lifecycle_events'); c.execute('delete from public.avuhz_idempotency_records'); c.execute('delete from public.avuhz_human_approvals'); c.execute('delete from public.avuhz_diagnostic_scopes'); c.execute('delete from public.avuhz_engagements'); c.execute('delete from public.avuhz_acquisition_handoffs')
   h=handoff(); c.execute('insert into public.avuhz_acquisition_handoffs (tenant_id,handoff_id,handoff_version,canonical_account_reference,acquisition_opportunity_reference,qualification_status,target_outcome,validated_constraints,stakeholder_context,assumptions,exclusions,requested_engagement_type,source_system,source_record_version,producer_identity,produced_at,correlation_id,idempotency_key,accepted_at) values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,null)',(h['tenant_id'],h['handoff_id'],h['handoff_version'],__import__('json').dumps(h['canonical_account_reference']),__import__('json').dumps(h['acquisition_opportunity_reference']),h['qualification_status'],h['target_outcome'],'[]','[]','[]','[]',h['requested_engagement_type'],h['source_system'],h['source_record_version'],h['producer_identity'],h['produced_at'],h['correlation_id'],h['idempotency_key']))
  self.store=PostgresStore(connection_factory_from_environment()); self.x=Executor(CommandValidator(ROOT/'contracts/schemas/v1'),GuardPipeline(),self.store,ids=lambda:'b6000000-0000-4000-8000-000000000001',uow_factory=PostgresUnitOfWork)
 def raw(self): return envelope('AcceptAcquisitionHandoff',copy.deepcopy(payloads()['AcceptAcquisitionHandoff']))
 def count(self,table):
  with psycopg.connect(DSN) as c:return c.execute(f'select count(*) from public.{table}').fetchone()[0]
 def test_durable_accept_duplicate_conflict_restart_and_tenant_isolation(self):
  self.assertEqual(self.x.execute(self.raw(),ctx())['result'],'ACCEPTED')
  self.x=Executor(CommandValidator(ROOT/'contracts/schemas/v1'),GuardPipeline(),self.store,ids=lambda:'b6000000-0000-4000-8000-000000000001',uow_factory=PostgresUnitOfWork)
  self.assertEqual(self.x.execute(self.raw(),ctx())['result'],'DUPLICATE')
  changed=self.raw(); changed['payload']['acquisition_handoff']['target_outcome']='Different'; self.assertEqual(self.x.execute(changed,ctx())['result'],'CONFLICT')
  self.assertEqual((self.count('avuhz_acquisition_handoffs'),self.count('avuhz_idempotency_records'),self.count('avuhz_lifecycle_events'),self.count('avuhz_outbox_deliveries')),(1,1,1,1))
  u=PostgresUnitOfWork(self.store); self.assertIsNone(u.handoffs.get('b3000000-0000-4000-8000-000000000002',handoff()['handoff_id'])); u.rollback(); u.close()
 def test_failpoints_rollback(self):
  for point in ('AUTHORITATIVE_WRITE','IDEMPOTENCY_RESERVE','IDEMPOTENCY_COMPLETE','LIFECYCLE_EVENT_APPEND','OUTBOX_APPEND','COMMIT'):
   self.setUp(); self.store.fail_stage=point; self.assertEqual(self.x.execute(self.raw(),ctx())['result'],'REJECTED'); self.assertEqual((self.count('avuhz_idempotency_records'),self.count('avuhz_lifecycle_events'),self.count('avuhz_outbox_deliveries')),(0,0,0),point)

if __name__=='__main__': unittest.main()
