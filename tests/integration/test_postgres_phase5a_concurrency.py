"""Real-connection Phase 5A contention and rollback certification."""
from __future__ import annotations
import copy
import os
import sys
import threading
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'tests'/'contracts'),str(ROOT/'tests'/'integration')]
import psycopg
from avuhz_runtime.assessment_access_usability import evaluate_assessment_access_usability
from avuhz_runtime.in_memory import Executor
from avuhz_runtime.postgres import PostgresStore,PostgresUnitOfWork,connection_factory_from_environment
from avuhz_runtime.validation import CommandValidator
from validate_command_payloads import payloads
from test_postgres_phase5a_executor_chain import DurablePhase5AExecutorChain,T,E,S,A,P,service,human

DSN=os.environ.get('AVUHZ_POSTGRES_DSN')
POINTS=('AUTHORITATIVE_WRITE','IDEMPOTENCY_RESERVE','IDEMPOTENCY_COMPLETE','LIFECYCLE_EVENT_APPEND','OUTBOX_APPEND','COMMIT')
def ident(n): return f'ca000000-0000-4000-8000-{n:012d}'

@unittest.skipUnless(DSN,'AVUHZ_POSTGRES_DSN is required')
class Phase5AConcurrency(DurablePhase5AExecutorChain):
 def approved_scope(self,tag):
  self.establish()
  self.assertEqual(self.approval('CLIENT_DECISION_AUTHORITY','durable-client-approval-0001','ba000000-0000-4000-8000-000000000010')['result'],'ACCEPTED')
  self.assertEqual(self.approval('SEKINFRA_ENGAGEMENT_AUTHORITY','durable-sekinfra-approval-0001','ba000000-0000-4000-8000-000000000011')['result'],'ACCEPTED')
  self.assertEqual(self.final('durable-approval-final-0001')['result'],'ACCEPTED')
 def race(self,entries):
  barrier=threading.Barrier(len(entries),timeout=15);results=[];errors=[];lock=threading.Lock()
  def run(raw,ctx,now='2030-01-15T15:00:00Z'):
   try:
    barrier.wait(); result=self.fresh_executor(now).execute(raw,ctx)
    with lock:results.append(result)
   except BaseException as error:
    with lock:errors.append(error)
  workers=[threading.Thread(target=run,args=entry,daemon=True) for entry in entries]
  for worker in workers:worker.start()
  for worker in workers:worker.join(20)
  self.assertFalse(any(worker.is_alive() for worker in workers),'concurrent worker timed out')
  self.assertEqual(errors,[],f'raw worker failure: {errors!r}')
  return results
 def open_approved_proposal(self,tag,base):
  self.approved_scope(tag)
  a=f'a3000000-0000-4000-8000-{base:012d}';p=f'a3000000-0000-4000-8000-{base+1:012d}';q=f'a3000000-0000-4000-8000-{base+2:012d}';seed=f'a3000000-0000-4000-8000-{base+3:012d}'
  self.active_grant(a,p,q,seed,tag+'-seed',base+100)
  q2=f'a3000000-0000-4000-8000-{base+4:012d}';proposal=copy.deepcopy(payloads()['CreateAssessmentAccessProposal'])
  proposal.update(assessment_access_proposal_id=q2,diagnostic_agreement_authority_reference={'reference_type':'DIAGNOSTIC_AGREEMENT_AUTHORITY','reference_id':a,'reference_version':1},diagnostic_payment_verification_reference={'reference_type':'DIAGNOSTIC_PAYMENT_VERIFICATION','reference_id':p,'reference_version':1})
  raw=self.phase5raw('CreateAssessmentAccessProposal',proposal,tag+'-proposal',ident(base+10),'ASSESSMENT_ACCESS_PROPOSAL',q2,'create-assessment-access-proposal')
  self.assertEqual(self.fresh_executor().execute(raw,service('CreateAssessmentAccessProposal'))['result'],'ACCEPTED')
  for offset,role in ((11,'CLIENT_DECISION_AUTHORITY'),(12,'SEKINFRA_ENGAGEMENT_AUTHORITY')):
   approval=self.phase5raw('RecordAssessmentAccessApproval',{'assessment_access_proposal_id':q2,'authority_role':role},tag+'-'+role,ident(base+offset),'ASSESSMENT_ACCESS_PROPOSAL',q2,'record-assessment-access-approval');approval['caller_type']='HUMAN';approval['caller_identity'].update(caller_type='HUMAN',capabilities=['assessment_access:approve'])
   self.assertEqual(self.fresh_executor().execute(approval,human(role,role+'-'+tag))['result'],'ACCEPTED')
  return a,p,q2
 def grant(self,q,g,key,n):return self.phase5raw('IssueAssessmentAccessGrant',{'assessment_access_grant_id':g,'assessment_access_proposal_id':q},'phase5a-'+key+'-0001',ident(n),'ASSESSMENT_ACCESS_GRANT',g,'issue-assessment-access-grant')
 def test_real_postgres_concurrent_grant_and_idempotency(self):
  a,p,q=self.open_approved_proposal('race-grant',510);g1='a3000000-0000-4000-8000-000000000515';g2='a3000000-0000-4000-8000-000000000516'
  results=self.race(((self.grant(q,g1,'race-grant-a',520),service('IssueAssessmentAccessGrant')),(self.grant(q,g2,'race-grant-b',521),service('IssueAssessmentAccessGrant'))))
  self.assertEqual(sorted(item['result'] for item in results),['ACCEPTED','REJECTED'])
  with psycopg.connect(DSN) as c:self.assertEqual(c.execute('select count(*) from public.avuhz_assessment_access_grants where tenant_id=%s and source_assessment_access_proposal_id=%s',(T,q)).fetchone()[0],1)
  winner=g1 if self.event_count('assessment_access.grant_issued',g1) else g2;self.assertEqual(self.event_count('assessment_access.grant_issued',winner),1);self.assertEqual(self.pending_outbox('assessment_access.grant_issued',winner),1)
  self.setUp();self.approved_scope('race-idempotency');agreement={'diagnostic_agreement_authority_id':A,'engagement_id':E,'diagnostic_scope_id':S,'scope_version':1,'agreement_reference':'agreement.race','effective_at':'2030-01-01T00:00:00Z'}
  raw=self.phase5raw('RecordDiagnosticAgreementAuthority',agreement,'phase5a-race-same-0001',ident(530),'DIAGNOSTIC_AGREEMENT_AUTHORITY',A,'record-diagnostic-agreement-authority')
  results=self.race(((copy.deepcopy(raw),service('RecordDiagnosticAgreementAuthority')),(copy.deepcopy(raw),service('RecordDiagnosticAgreementAuthority'))));self.assertEqual(sorted(item['result'] for item in results),['ACCEPTED','DUPLICATE']);self.assertEqual(self.event_count('diagnostic_agreement.authority_recorded',A),1);self.assertEqual(self.pending_outbox('diagnostic_agreement.authority_recorded',A),1)
  payment={'diagnostic_payment_verification_id':P,'engagement_id':E,'diagnostic_agreement_authority_reference':{'reference_type':'DIAGNOSTIC_AGREEMENT_AUTHORITY','reference_id':A,'reference_version':1},'amount_minor':10000,'currency':'USD','provider_reference':'payment.race'}
  first=self.phase5raw('RecordDiagnosticPaymentVerification',payment,'phase5a-race-conflict-0001',ident(531),'DIAGNOSTIC_PAYMENT_VERIFICATION',P,'record-diagnostic-payment-verification');changed=copy.deepcopy(first);changed['command_id']=ident(532);changed['subject_id']='a3000000-0000-4000-8000-000000000533';changed['payload']['diagnostic_payment_verification_id']=changed['subject_id'];changed['payload']['provider_reference']='payment.race-other'
  results=self.race(((first,service('RecordDiagnosticPaymentVerification')),(changed,service('RecordDiagnosticPaymentVerification'))));self.assertEqual(sorted(item['result'] for item in results),['ACCEPTED','CONFLICT']);self.assertEqual(self.count('diagnostic_payment.verified'),1);
  with psycopg.connect(DSN) as c:self.assertEqual(c.execute("select count(*) from public.avuhz_outbox_deliveries o join public.avuhz_lifecycle_events e on e.lifecycle_event_id=o.lifecycle_event_id where e.event_type='diagnostic_payment.verified' and o.status='PENDING'").fetchone()[0],1)
 def test_real_postgres_concurrent_approval_activation_terminal_invalidation(self):
  a,p,q=self.open_approved_proposal('race-all',540);g='a3000000-0000-4000-8000-000000000545';self.assertEqual(self.fresh_executor().execute(self.grant(q,g,'race-approve-grant',546),service('IssueAssessmentAccessGrant'))['result'],'ACCEPTED')
  verify=self.phase5raw('VerifyAssessmentAccess',{'assessment_access_grant_id':g},'phase5a-race-verify-a-0001',ident(547),'ASSESSMENT_ACCESS_GRANT',g,'verify-assessment-access');verify2=copy.deepcopy(verify);verify2['idempotency_key']='phase5a-race-verify-b-0001';verify2['command_id']=ident(548)
  results=self.race(((verify,service('VerifyAssessmentAccess')),(verify2,service('VerifyAssessmentAccess'))));self.assertEqual(sorted(item['result'] for item in results),['ACCEPTED','REJECTED']);self.assertEqual(self.event_count('assessment_access.verified_and_activated',g),1);self.assertEqual(self.pending_outbox('assessment_access.verified_and_activated',g),1)
  inv=self.phase5raw('InvalidateDiagnosticPaymentVerification',{'diagnostic_payment_verification_id':p},'phase5a-race-invalidate-a-0001',ident(549),'DIAGNOSTIC_PAYMENT_VERIFICATION',p,'invalidate-diagnostic-payment-verification',2);inv2=copy.deepcopy(inv);inv2['idempotency_key']='phase5a-race-invalidate-b-0001';inv2['command_id']=ident(550)
  results=self.race(((inv,service('InvalidateDiagnosticPaymentVerification')),(inv2,service('InvalidateDiagnosticPaymentVerification'))));self.assertEqual(sorted(item['result'] for item in results),['ACCEPTED','REJECTED']);self.assertEqual(self.event_count('diagnostic_payment.invalidated',p),1);self.assertEqual(self.pending_outbox('diagnostic_payment.invalidated',p),1)
  uow=PostgresUnitOfWork(self.store,service('VerifyAssessmentAccess'))
  try:self.assertFalse(evaluate_assessment_access_usability(uow,T,g,'2030-01-16T00:00:00Z').usable)
  finally:uow.rollback();uow.close()
  self.setUp();self.approved_scope('race-terminal');a='a3000000-0000-4000-8000-000000000560';p='a3000000-0000-4000-8000-000000000561';q='a3000000-0000-4000-8000-000000000562';g='a3000000-0000-4000-8000-000000000563';self.active_grant(a,p,q,g,'race-terminal',570)
  expire=self.phase5raw('ExpireAssessmentAccess',{'assessment_access_grant_id':g},'phase5a-race-expire-0001',ident(571),'ASSESSMENT_ACCESS_GRANT',g,'expire-assessment-access',2);revoke=self.phase5raw('RevokeAssessmentAccess',{'assessment_access_grant_id':g},'phase5a-race-revoke-0001',ident(572),'ASSESSMENT_ACCESS_GRANT',g,'revoke-assessment-access',2)
  results=self.race(((expire,service('ExpireAssessmentAccess',expires_at='2030-03-15T16:00:00Z'),'2030-02-15T16:00:00Z'),(revoke,service('RevokeAssessmentAccess',expires_at='2030-03-15T16:00:00Z'),'2030-02-15T16:00:00Z')));self.assertEqual(sorted(item['result'] for item in results),['ACCEPTED','REJECTED']);self.assertEqual(self.event_count('assessment_access.expired',g)+self.event_count('assessment_access.revoked',g),1)
 def test_failpoints_are_durable_atomic_and_retryable(self):
  for point in POINTS:
   self.setUp();self.approved_scope('phase5a-fp-a-'+point.lower()+'-0001');agreement={'diagnostic_agreement_authority_id':A,'engagement_id':E,'diagnostic_scope_id':S,'scope_version':1,'agreement_reference':'agreement.fp-'+point.lower(),'effective_at':'2030-01-01T00:00:00Z'};raw=self.phase5raw('RecordDiagnosticAgreementAuthority',agreement,'phase5a-fp-a-'+point.lower()+'-0001',ident(600),'DIAGNOSTIC_AGREEMENT_AUTHORITY',A,'record-diagnostic-agreement-authority');self.store.fail_stage=point
   self.assertEqual(self.x.execute(raw,service('RecordDiagnosticAgreementAuthority'))['result'],'REJECTED');self.assertEqual(self.event_count('diagnostic_agreement.authority_recorded',A),0);self.assertEqual(self.pending_outbox('diagnostic_agreement.authority_recorded',A),0);self.store.fail_stage=None;self.assertEqual(self.x.execute(raw,service('RecordDiagnosticAgreementAuthority'))['result'],'ACCEPTED')
  for point in POINTS:
   self.setUp();a,p,q=self.open_approved_proposal('phase5a-fp-g-'+point.lower()+'-0001',620);g='a3000000-0000-4000-8000-000000000629';raw=self.grant(q,g,'phase5a-fp-g-'+point.lower()+'-0001',630);self.store.fail_stage=point
   self.assertEqual(self.x.execute(raw,service('IssueAssessmentAccessGrant'))['result'],'REJECTED');uow=PostgresUnitOfWork(self.store,service('IssueAssessmentAccessGrant'))
   try:self.assertIsNone(uow.assessment_access_grants.get(T,g));self.assertEqual(uow.assessment_access_proposals.get(T,q)['status'],'OPEN')
   finally:uow.rollback();uow.close()
   self.assertEqual(self.event_count('assessment_access.grant_issued',g),0);self.assertEqual(self.pending_outbox('assessment_access.grant_issued',g),0);self.store.fail_stage=None;self.assertEqual(self.x.execute(raw,service('IssueAssessmentAccessGrant'))['result'],'ACCEPTED')
 @unittest.skipUnless(os.environ.get('AVUHZ_PHASE5A_RLS_TEST_PASSWORD'),'local disposable RLS password is required')
 def test_non_owner_command_service_rls_isolation_and_cleanup(self):
  from psycopg.conninfo import make_conninfo
  from psycopg import sql
  password=os.environ['AVUHZ_PHASE5A_RLS_TEST_PASSWORD'];login='avuhz_phase5a_rls_test'
  with psycopg.connect(DSN,autocommit=True) as owner:
   owner.execute('drop role if exists '+login)
   owner.execute(sql.SQL('create role {} login noinherit nosuperuser nocreatedb nocreaterole noreplication nobypassrls password {}').format(sql.Identifier(login),sql.Literal(password)))
   owner.execute('grant avuhz_command_service to '+login)
  def factory():
   connection=psycopg.connect(make_conninfo(DSN,user=login,password=password),autocommit=False,row_factory=psycopg.rows.dict_row)
   connection.execute('set role avuhz_command_service')
   connection.commit()
   return connection
  try:
   self.approved_scope('rls')
   store=PostgresStore(factory); executor=Executor(CommandValidator(ROOT/'contracts/schemas/v1'),__import__('avuhz_runtime.guards',fromlist=['GuardPipeline']).GuardPipeline(),store,clock=lambda:'2030-01-15T15:00:00Z',uow_factory=PostgresUnitOfWork)
   agreement={'diagnostic_agreement_authority_id':A,'engagement_id':E,'diagnostic_scope_id':S,'scope_version':1,'agreement_reference':'agreement.rls-local','effective_at':'2030-01-01T00:00:00Z'}
   raw=self.phase5raw('RecordDiagnosticAgreementAuthority',agreement,'phase5a-rls-agreement-0001',ident(760),'DIAGNOSTIC_AGREEMENT_AUTHORITY',A,'record-diagnostic-agreement-authority')
   self.assertEqual(executor.execute(raw,service('RecordDiagnosticAgreementAuthority'))['result'],'ACCEPTED')
   unbound=PostgresUnitOfWork(store)
   try:self.assertIsNone(unbound.engagements.get(T,E))
   finally:unbound.rollback();unbound.close()
   bound=PostgresUnitOfWork(store,service('RecordDiagnosticAgreementAuthority'))
   try:self.assertIsNotNone(bound.engagements.get(T,E));self.assertIsNone(bound.engagements.get('b3000000-0000-4000-8000-000000000002',E))
   finally:bound.rollback();bound.close()
   fresh=PostgresUnitOfWork(store)
   try:self.assertIsNone(fresh.engagements.get(T,E))
   finally:fresh.rollback();fresh.close()
  finally:
   with psycopg.connect(DSN,autocommit=True) as owner:
    owner.execute('revoke avuhz_command_service from '+login)
    owner.execute('drop role if exists '+login)
 def open_proposal(self,tag,base):
  self.approved_scope(tag)
  a=f'a3000000-0000-4000-8000-{base:012d}';p=f'a3000000-0000-4000-8000-{base+1:012d}';q=f'a3000000-0000-4000-8000-{base+2:012d}';seed=f'a3000000-0000-4000-8000-{base+3:012d}'
  self.active_grant(a,p,q,seed,tag+'-seed',base+100)
  proposal_id=f'a3000000-0000-4000-8000-{base+4:012d}';proposal=copy.deepcopy(payloads()['CreateAssessmentAccessProposal'])
  proposal.update(assessment_access_proposal_id=proposal_id,diagnostic_agreement_authority_reference={'reference_type':'DIAGNOSTIC_AGREEMENT_AUTHORITY','reference_id':a,'reference_version':1},diagnostic_payment_verification_reference={'reference_type':'DIAGNOSTIC_PAYMENT_VERIFICATION','reference_id':p,'reference_version':1})
  raw=self.phase5raw('CreateAssessmentAccessProposal',proposal,'phase5a-'+tag+'-open-proposal-0001',ident(base+10),'ASSESSMENT_ACCESS_PROPOSAL',proposal_id,'create-assessment-access-proposal')
  self.assertEqual(self.fresh_executor().execute(raw,service('CreateAssessmentAccessProposal'))['result'],'ACCEPTED')
  return a,p,proposal_id
 def same_store_executor(self,trusted_now='2030-01-15T15:00:00Z'):
  return Executor(self.x.validator,self.x.pipeline,self.store,clock=lambda:trusted_now,ids=lambda:next(self._ids),uow_factory=PostgresUnitOfWork)
 def completed_idempotency(self,command,key):
  with psycopg.connect(DSN) as c:return c.execute("select count(*) from public.avuhz_idempotency_records where tenant_id=%s and command_type=%s and idempotency_key=%s and processing_status='COMPLETED'",(T,command,key)).fetchone()[0]
 def test_real_postgres_concurrent_approval_uniqueness(self):
  a,p,q=self.open_proposal('approval-race',800);entries=[]
  for n in (811,812):
   raw=self.phase5raw('RecordAssessmentAccessApproval',{'assessment_access_proposal_id':q,'authority_role':'CLIENT_DECISION_AUTHORITY'},'phase5a-approval-race-'+str(n)+'-0001',ident(n),'ASSESSMENT_ACCESS_PROPOSAL',q,'record-assessment-access-approval');raw['caller_type']='HUMAN';raw['caller_identity'].update(caller_type='HUMAN',capabilities=['assessment_access:approve']);entries.append((raw,human('CLIENT_DECISION_AUTHORITY','approval-race-client-'+str(n))))
  results=self.race(tuple(entries));self.assertEqual(sorted(item['result'] for item in results),['ACCEPTED','REJECTED'])
  with psycopg.connect(DSN) as c:self.assertEqual(c.execute("select count(*) from public.avuhz_human_approvals where tenant_id=%s and assessment_access_proposal_id=%s and actor_role='CLIENT_DECISION_AUTHORITY' and status='ACTIVE'",(T,q)).fetchone()[0],1)
  self.assertEqual(self.event_count('assessment_access.approval_recorded',q),1);self.assertEqual(self.pending_outbox('assessment_access.approval_recorded',q),1)
  sek=self.phase5raw('RecordAssessmentAccessApproval',{'assessment_access_proposal_id':q,'authority_role':'SEKINFRA_ENGAGEMENT_AUTHORITY'},'phase5a-approval-race-sekinfra-0001',ident(813),'ASSESSMENT_ACCESS_PROPOSAL',q,'record-assessment-access-approval');sek['caller_type']='HUMAN';sek['caller_identity'].update(caller_type='HUMAN',capabilities=['assessment_access:approve'])
  self.assertEqual(self.fresh_executor().execute(sek,human('SEKINFRA_ENGAGEMENT_AUTHORITY','approval-race-sekinfra'))['result'],'ACCEPTED')
  with psycopg.connect(DSN) as c:self.assertEqual(c.execute("select count(*) from public.avuhz_human_approvals where tenant_id=%s and assessment_access_proposal_id=%s and actor_role in ('CLIENT_DECISION_AUTHORITY','SEKINFRA_ENGAGEMENT_AUTHORITY') and status='ACTIVE'",(T,q)).fetchone()[0],2)
 def test_verify_invalidate_and_terminal_failpoints_are_atomic(self):
  for point in POINTS:
   self.setUp();a,p,q=self.open_approved_proposal('verify-fp-'+point.lower(),830);g='a3000000-0000-4000-8000-000000000837';self.assertEqual(self.fresh_executor().execute(self.grant(q,g,'verify-fp-grant-'+point.lower(),838),service('IssueAssessmentAccessGrant'))['result'],'ACCEPTED')
   key='phase5a-verify-fp-'+point.lower()+'-0001';raw=self.phase5raw('VerifyAssessmentAccess',{'assessment_access_grant_id':g},key,ident(839),'ASSESSMENT_ACCESS_GRANT',g,'verify-assessment-access',2);self.store.fail_stage=point
   self.assertEqual(self.same_store_executor().execute(raw,service('VerifyAssessmentAccess'))['result'],'REJECTED');self.store.fail_stage=None
   uow=PostgresUnitOfWork(self.store,service('VerifyAssessmentAccess'))
   try:
    grant=uow.assessment_access_grants.get(T,g);self.assertEqual(grant['status'],'APPROVED');self.assertNotIn('verified_at',grant);self.assertNotIn('active_from',grant);self.assertNotIn('expires_at',grant)
   finally:uow.rollback();uow.close()
   self.assertEqual(self.event_count('assessment_access.verified_and_activated',g),0);self.assertEqual(self.pending_outbox('assessment_access.verified_and_activated',g),0);self.assertEqual(self.completed_idempotency('VerifyAssessmentAccess',key),0);self.assertEqual(self.same_store_executor().execute(raw,service('VerifyAssessmentAccess'))['result'],'ACCEPTED')
  for point in POINTS:
   self.setUp();self.approved_scope('invalidation-fp-'+point.lower());a='a3000000-0000-4000-8000-000000000850';p='a3000000-0000-4000-8000-000000000851';q='a3000000-0000-4000-8000-000000000852';g='a3000000-0000-4000-8000-000000000853';self.active_grant(a,p,q,g,'invalidation-fp-'+point.lower(),860)
   key='phase5a-invalidation-fp-'+point.lower()+'-0001';raw=self.phase5raw('InvalidateDiagnosticPaymentVerification',{'diagnostic_payment_verification_id':p},key,ident(861),'DIAGNOSTIC_PAYMENT_VERIFICATION',p,'invalidate-diagnostic-payment-verification',2);self.store.fail_stage=point
   self.assertEqual(self.same_store_executor().execute(raw,service('InvalidateDiagnosticPaymentVerification'))['result'],'REJECTED');self.store.fail_stage=None
   uow=PostgresUnitOfWork(self.store,service('InvalidateDiagnosticPaymentVerification'))
   try:
    payment=uow.diagnostic_payment_verifications.get(T,p);self.assertEqual(payment['verification_status'],'VERIFIED');self.assertNotIn('invalidated_at',payment);self.assertTrue(evaluate_assessment_access_usability(uow,T,g,'2030-01-16T00:00:00Z').usable)
   finally:uow.rollback();uow.close()
   self.assertEqual(self.event_count('diagnostic_payment.invalidated',p),0);self.assertEqual(self.pending_outbox('diagnostic_payment.invalidated',p),0);self.assertEqual(self.completed_idempotency('InvalidateDiagnosticPaymentVerification',key),0);self.assertEqual(self.same_store_executor().execute(raw,service('InvalidateDiagnosticPaymentVerification'))['result'],'ACCEPTED')
   uow=PostgresUnitOfWork(self.store,service('InvalidateDiagnosticPaymentVerification'))
   try:self.assertFalse(evaluate_assessment_access_usability(uow,T,g,'2030-01-16T00:00:00Z').usable)
   finally:uow.rollback();uow.close()
  for point in POINTS:
   self.setUp();self.approved_scope('terminal-fp-'+point.lower());a='a3000000-0000-4000-8000-000000000870';p='a3000000-0000-4000-8000-000000000871';q='a3000000-0000-4000-8000-000000000872';g='a3000000-0000-4000-8000-000000000873';self.active_grant(a,p,q,g,'terminal-fp-'+point.lower(),880)
   key='phase5a-terminal-fp-'+point.lower()+'-0001';raw=self.phase5raw('RevokeAssessmentAccess',{'assessment_access_grant_id':g},key,ident(881),'ASSESSMENT_ACCESS_GRANT',g,'revoke-assessment-access',2);self.store.fail_stage=point
   self.assertEqual(self.same_store_executor().execute(raw,service('RevokeAssessmentAccess'))['result'],'REJECTED');self.store.fail_stage=None
   uow=PostgresUnitOfWork(self.store,service('RevokeAssessmentAccess'))
   try:
    grant=uow.assessment_access_grants.get(T,g);self.assertEqual(grant['status'],'ACTIVE');self.assertNotIn('revoked_at',grant)
   finally:uow.rollback();uow.close()
   self.assertEqual(self.event_count('assessment_access.revoked',g),0);self.assertEqual(self.pending_outbox('assessment_access.revoked',g),0);self.assertEqual(self.completed_idempotency('RevokeAssessmentAccess',key),0);self.assertEqual(self.same_store_executor().execute(raw,service('RevokeAssessmentAccess'))['result'],'ACCEPTED')
 def tenant_raw(self,raw,tenant):
  value=copy.deepcopy(raw);value['tenant_id']=tenant;value['caller_identity']['tenant_ids']=[tenant];return value
 def tenant_service(self,command,tenant):
  from dataclasses import replace
  return replace(service(command),tenant_id=tenant)
 def seed_tenant_b_authority(self):
  tenant_b='b3000000-0000-4000-8000-000000000002';handoff_b='b3000000-0000-4000-8000-000000000001';engagement_b='b3000000-0000-4000-8000-000000000004';scope_b='b3000000-0000-4000-8000-000000000005';agreement_b='b3000000-0000-4000-8000-000000000013';payment_b='b3000000-0000-4000-8000-000000000014';proposal_b='b3000000-0000-4000-8000-000000000012'
  with psycopg.connect(DSN) as c:
   c.execute("insert into public.avuhz_acquisition_handoffs (tenant_id,handoff_id,handoff_version,canonical_account_reference,acquisition_opportunity_reference,qualification_status,target_outcome,validated_constraints,stakeholder_context,assumptions,exclusions,requested_engagement_type,source_system,source_record_version,producer_identity,produced_at,correlation_id,idempotency_key,received_at,accepted_at,created_at) select %s,%s,handoff_version,canonical_account_reference,acquisition_opportunity_reference,qualification_status,target_outcome,validated_constraints,stakeholder_context,assumptions,exclusions,requested_engagement_type,source_system,source_record_version,producer_identity,produced_at,correlation_id,idempotency_key,received_at,accepted_at,created_at from public.avuhz_acquisition_handoffs where tenant_id=%s",(tenant_b,handoff_b,T))
   c.execute("insert into public.avuhz_engagements (engagement_id,tenant_id,acquisition_handoff_id,acquisition_handoff_version,account_reference,acquisition_opportunity_reference,engagement_type,engagement_state,engagement_version,record_version,opened_at,created_at,updated_at) select %s,%s,%s,acquisition_handoff_version,account_reference,acquisition_opportunity_reference,engagement_type,engagement_state,engagement_version,record_version,opened_at,created_at,updated_at from public.avuhz_engagements where tenant_id=%s",(engagement_b,tenant_b,handoff_b,T))
   c.execute("insert into public.avuhz_diagnostic_scopes (diagnostic_scope_id,tenant_id,engagement_id,scope_version,record_version,status,canonical_scope_digest,action_set_version,target_outcome,in_scope_systems,excluded_systems,permitted_actions,prohibited_actions,assumptions,constraint_references,effective_at,created_at,updated_at) select %s,%s,%s,scope_version,record_version,status,canonical_scope_digest,action_set_version,target_outcome,in_scope_systems,excluded_systems,permitted_actions,prohibited_actions,assumptions,constraint_references,effective_at,created_at,updated_at from public.avuhz_diagnostic_scopes where tenant_id=%s",(scope_b,tenant_b,engagement_b,T))
  agreement={'diagnostic_agreement_authority_id':agreement_b,'engagement_id':engagement_b,'diagnostic_scope_id':scope_b,'scope_version':1,'agreement_reference':'agreement.tenant-b','effective_at':'2030-01-01T00:00:00Z'}
  agreement_raw=self.tenant_raw(self.phase5raw('RecordDiagnosticAgreementAuthority',agreement,'phase5a-b-agreement-0001',ident(900),'DIAGNOSTIC_AGREEMENT_AUTHORITY',agreement_b,'record-diagnostic-agreement-authority'),tenant_b);self.assertEqual(self.fresh_executor().execute(agreement_raw,self.tenant_service('RecordDiagnosticAgreementAuthority',tenant_b))['result'],'ACCEPTED')
  payment={'diagnostic_payment_verification_id':payment_b,'engagement_id':engagement_b,'diagnostic_agreement_authority_reference':{'reference_type':'DIAGNOSTIC_AGREEMENT_AUTHORITY','reference_id':agreement_b,'reference_version':1},'amount_minor':10000,'currency':'USD','provider_reference':'payment.tenant-b'}
  payment_raw=self.tenant_raw(self.phase5raw('RecordDiagnosticPaymentVerification',payment,'phase5a-b-payment-0001',ident(901),'DIAGNOSTIC_PAYMENT_VERIFICATION',payment_b,'record-diagnostic-payment-verification'),tenant_b);self.assertEqual(self.fresh_executor().execute(payment_raw,self.tenant_service('RecordDiagnosticPaymentVerification',tenant_b))['result'],'ACCEPTED')
  proposal=copy.deepcopy(payloads()['CreateAssessmentAccessProposal']);proposal.update(assessment_access_proposal_id=proposal_b,engagement_id=engagement_b,diagnostic_scope_id=scope_b,diagnostic_agreement_authority_reference={'reference_type':'DIAGNOSTIC_AGREEMENT_AUTHORITY','reference_id':agreement_b,'reference_version':1},diagnostic_payment_verification_reference={'reference_type':'DIAGNOSTIC_PAYMENT_VERIFICATION','reference_id':payment_b,'reference_version':1})
  proposal_raw=self.tenant_raw(self.phase5raw('CreateAssessmentAccessProposal',proposal,'phase5a-b-proposal-0001',ident(902),'ASSESSMENT_ACCESS_PROPOSAL',proposal_b,'create-assessment-access-proposal'),tenant_b);self.assertEqual(self.fresh_executor().execute(proposal_raw,self.tenant_service('CreateAssessmentAccessProposal',tenant_b))['result'],'ACCEPTED')
  return tenant_b,engagement_b,scope_b,agreement_b,payment_b,proposal_b
 def test_cross_tenant_authority_chains_fail_closed(self):
  self.approved_scope('cross-tenant');tenant_b,engagement_b,scope_b,agreement_b,payment_b,proposal_b=self.seed_tenant_b_authority();attack_keys=[]
  payment={'diagnostic_payment_verification_id':'a3000000-0000-4000-8000-000000000910','engagement_id':E,'diagnostic_agreement_authority_reference':{'reference_type':'DIAGNOSTIC_AGREEMENT_AUTHORITY','reference_id':agreement_b,'reference_version':1},'amount_minor':10000,'currency':'USD','provider_reference':'payment.cross-tenant'}
  key='phase5a-cross-payment-0001';attack_keys.append(key);raw=self.phase5raw('RecordDiagnosticPaymentVerification',payment,key,ident(910),'DIAGNOSTIC_PAYMENT_VERIFICATION',payment['diagnostic_payment_verification_id'],'record-diagnostic-payment-verification');self.assertEqual(self.fresh_executor().execute(raw,service('RecordDiagnosticPaymentVerification'))['result'],'REJECTED')
  proposal=copy.deepcopy(payloads()['CreateAssessmentAccessProposal']);proposal.update(assessment_access_proposal_id='a3000000-0000-4000-8000-000000000911',diagnostic_scope_id=scope_b,diagnostic_agreement_authority_reference={'reference_type':'DIAGNOSTIC_AGREEMENT_AUTHORITY','reference_id':agreement_b,'reference_version':1},diagnostic_payment_verification_reference={'reference_type':'DIAGNOSTIC_PAYMENT_VERIFICATION','reference_id':payment_b,'reference_version':1})
  key='phase5a-cross-proposal-0001';attack_keys.append(key);raw=self.phase5raw('CreateAssessmentAccessProposal',proposal,key,ident(911),'ASSESSMENT_ACCESS_PROPOSAL',proposal['assessment_access_proposal_id'],'create-assessment-access-proposal');self.assertEqual(self.fresh_executor().execute(raw,service('CreateAssessmentAccessProposal'))['result'],'REJECTED')
  key='phase5a-cross-approval-0001';attack_keys.append(key);raw=self.phase5raw('RecordAssessmentAccessApproval',{'assessment_access_proposal_id':proposal_b,'authority_role':'CLIENT_DECISION_AUTHORITY'},key,ident(912),'ASSESSMENT_ACCESS_PROPOSAL',proposal_b,'record-assessment-access-approval');raw['caller_type']='HUMAN';raw['caller_identity'].update(caller_type='HUMAN',capabilities=['assessment_access:approve']);self.assertEqual(self.fresh_executor().execute(raw,human('CLIENT_DECISION_AUTHORITY','cross-tenant-client'))['result'],'REJECTED')
  grant='a3000000-0000-4000-8000-000000000913';key='phase5a-cross-grant-0001';attack_keys.append(key);raw=self.grant(proposal_b,grant,'cross-grant',913);raw['idempotency_key']=key;self.assertEqual(self.fresh_executor().execute(raw,service('IssueAssessmentAccessGrant'))['result'],'REJECTED')
  with psycopg.connect(DSN) as c:
   self.assertEqual(c.execute('select count(*) from public.avuhz_diagnostic_payment_verifications where tenant_id=%s and diagnostic_payment_verification_id=%s',(T,payment['diagnostic_payment_verification_id'])).fetchone()[0],0);self.assertEqual(c.execute('select count(*) from public.avuhz_assessment_access_proposals where tenant_id=%s and assessment_access_proposal_id=%s',(T,proposal['assessment_access_proposal_id'])).fetchone()[0],0);self.assertEqual(c.execute('select count(*) from public.avuhz_assessment_access_grants where tenant_id=%s and assessment_access_grant_id=%s',(T,grant)).fetchone()[0],0);self.assertEqual(c.execute('select status from public.avuhz_assessment_access_proposals where tenant_id=%s and assessment_access_proposal_id=%s',(tenant_b,proposal_b)).fetchone()[0],'OPEN');self.assertEqual(c.execute('select count(*) from public.avuhz_lifecycle_events where idempotency_key = any(%s)',(attack_keys,)).fetchone()[0],0);self.assertEqual(c.execute("select count(*) from public.avuhz_outbox_deliveries o join public.avuhz_lifecycle_events e on e.lifecycle_event_id=o.lifecycle_event_id where e.idempotency_key = any(%s)",(attack_keys,)).fetchone()[0],0)
 def test_phase5a_certification_rows_exclude_credentials_and_provider_payloads(self):
  self.approved_scope('credential-scan');self.active_grant('a3000000-0000-4000-8000-000000000930','a3000000-0000-4000-8000-000000000931','a3000000-0000-4000-8000-000000000932','a3000000-0000-4000-8000-000000000933','credential-scan',940)
  tables=('avuhz_diagnostic_agreement_authorities','avuhz_diagnostic_payment_verifications','avuhz_assessment_access_proposals','avuhz_human_approvals','avuhz_assessment_access_grants','avuhz_idempotency_records','avuhz_lifecycle_events','avuhz_outbox_deliveries')
  with psycopg.connect(DSN) as c:
   durable=''.join(str(c.execute(f'select coalesce(json_agg(row_to_json(x)),\'[]\'::json) from (select * from public.{table}) x').fetchone()[0]) for table in tables).lower()
  for forbidden in ('password','api_key','oauth','ssh_key','postgresql://','authorization','provider_response','raw_payment','raw_agreement','verifier_response'):
   self.assertNotIn(forbidden,durable)
