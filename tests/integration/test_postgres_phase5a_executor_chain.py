"""Local PostgreSQL happy-path certification for the normal Phase 5A executor."""
from __future__ import annotations
import copy, os, sys, unittest
from datetime import datetime, timedelta
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path[:0]=[str(ROOT/'src'),str(ROOT/'tests'/'contracts'),str(ROOT/'tests'/'integration')]
import psycopg
from avuhz_runtime.assessment_access_dual_approval import evaluate_assessment_access_dual_approval
from avuhz_runtime.assessment_access_usability import evaluate_assessment_access_usability
from avuhz_runtime.assessment_access_verification import InMemoryAssessmentAccessVerifier
from avuhz_runtime.guards import COMMAND_CAPABILITIES, GuardPipeline, TrustedExecutionContext
from avuhz_runtime.in_memory import Executor
from avuhz_runtime.postgres import PostgresStore,PostgresUnitOfWork,connection_factory_from_environment
from avuhz_runtime.validation import CommandValidator
from validate_command_payloads import envelope,payloads
from test_postgres_human_approval import Tests as Phase4, context, T,E,S
DSN=os.environ.get('AVUHZ_POSTGRES_DSN'); A='a3000000-0000-4000-8000-000000000013';P='a3000000-0000-4000-8000-000000000014';Q='a3000000-0000-4000-8000-000000000012';G='a3000000-0000-4000-8000-000000000015'
def service(command, principal='phase5a-service', expires_at='2030-01-15T16:00:00Z'):
 return TrustedExecutionContext(True,principal,'INTERNAL_SERVICE',T,None,frozenset({COMMAND_CAPABILITIES[command]}),frozenset(),'TEST','avuhz-command-api','STRONG',False,'2030-01-15T15:00:00Z',expires_at)
def human(role,principal):
 return TrustedExecutionContext(True,principal,'HUMAN',T,None,frozenset({'assessment_access:approve'}),frozenset(),'TEST','avuhz-command-api','STRONG',False,'2030-01-15T15:00:00Z','2030-01-15T16:00:00Z',principal,'org:'+principal,role)
@unittest.skipUnless(DSN,'AVUHZ_POSTGRES_DSN is required')
class DurablePhase5AExecutorChain(Phase4):
 def setUp(self):
  with psycopg.connect(DSN) as c:
   for t in ('avuhz_outbox_deliveries','avuhz_lifecycle_events','avuhz_idempotency_records','avuhz_human_approvals','avuhz_assessment_access_grants','avuhz_assessment_access_proposals','avuhz_diagnostic_payment_verifications','avuhz_diagnostic_agreement_authorities'):c.execute(f'delete from public.{t}')
  super().setUp(); self._ids=iter(f"c9000000-0000-4000-8000-{n:012d}" for n in range(100,300)); self.x=Executor(CommandValidator(ROOT/'contracts/schemas/v1'),GuardPipeline(),self.store,clock=lambda:'2030-01-15T15:00:00Z',ids=lambda:next(self._ids),uow_factory=PostgresUnitOfWork,assessment_access_verifier=InMemoryAssessmentAccessVerifier())
 def tearDown(self):
  with psycopg.connect(DSN) as c:
   for t in ('avuhz_outbox_deliveries','avuhz_lifecycle_events','avuhz_idempotency_records','avuhz_human_approvals','avuhz_assessment_access_grants','avuhz_assessment_access_proposals','avuhz_diagnostic_payment_verifications','avuhz_diagnostic_agreement_authorities'):c.execute(f'delete from public.{t}')
  super().tearDown()
 def phase5raw(self, command, payload, key, ident, subject_type, subject_id, schema, version=1):
  x=envelope('CreateAssessmentAccessProposal',copy.deepcopy(payloads()['CreateAssessmentAccessProposal']));x.update(command_id=ident,command_type=command,tenant_id=T,subject_type=subject_type,subject_id=subject_id,idempotency_key=key,engagement_id=E,expected_record_version=version,payload_schema='urn:avuhz:schema:contracts:commands:'+schema+'-payload:v1',payload=payload);x['caller_type']='INTERNAL_SERVICE';x['caller_identity'].update(caller_type='INTERNAL_SERVICE',capabilities=[COMMAND_CAPABILITIES[command]]);return x
 def count(self, typ):
  with psycopg.connect(DSN) as c:return c.execute('select count(*) from public.avuhz_lifecycle_events where event_type=%s',(typ,)).fetchone()[0]
 def fresh_executor(self, trusted_now='2030-01-15T15:00:00Z'):
  return Executor(CommandValidator(ROOT/'contracts/schemas/v1'),GuardPipeline(),PostgresStore(connection_factory_from_environment()),clock=lambda:trusted_now,ids=lambda:next(self._ids),uow_factory=PostgresUnitOfWork,assessment_access_verifier=InMemoryAssessmentAccessVerifier())
 def pending_outbox(self, typ, subject_id):
  with psycopg.connect(DSN) as c:return c.execute("select count(*) from public.avuhz_outbox_deliveries o join public.avuhz_lifecycle_events e on e.lifecycle_event_id=o.lifecycle_event_id where e.event_type=%s and e.authoritative_subject_id=%s and o.status='PENDING'",(typ,subject_id)).fetchone()[0]
 def event_count(self, typ, subject_id):
  with psycopg.connect(DSN) as c:return c.execute('select count(*) from public.avuhz_lifecycle_events where event_type=%s and authoritative_subject_id=%s',(typ,subject_id)).fetchone()[0]
 def active_grant(self, agreement_id, payment_id, proposal_id, grant_id, tag, sequence, ends_at=None):
  executor=self.fresh_executor();agreement={'diagnostic_agreement_authority_id':agreement_id,'engagement_id':E,'diagnostic_scope_id':S,'scope_version':1,'agreement_reference':'agreement.external-'+tag,'effective_at':'2030-01-01T00:00:00Z'}
  if ends_at:agreement['ends_at']=ends_at
  agreement_raw=self.phase5raw('RecordDiagnosticAgreementAuthority',agreement,'phase5a-'+tag+'-agreement-0001',f'c9000000-0000-4000-8000-{sequence:012d}','DIAGNOSTIC_AGREEMENT_AUTHORITY',agreement_id,'record-diagnostic-agreement-authority');self.assertEqual(executor.execute(agreement_raw,service('RecordDiagnosticAgreementAuthority'))['result'],'ACCEPTED')
  payment={'diagnostic_payment_verification_id':payment_id,'engagement_id':E,'diagnostic_agreement_authority_reference':{'reference_type':'DIAGNOSTIC_AGREEMENT_AUTHORITY','reference_id':agreement_id,'reference_version':1},'amount_minor':10000,'currency':'USD','provider_reference':'payment.external-'+tag};payment_raw=self.phase5raw('RecordDiagnosticPaymentVerification',payment,'phase5a-'+tag+'-payment-0001',f'c9000000-0000-4000-8000-{sequence+1:012d}','DIAGNOSTIC_PAYMENT_VERIFICATION',payment_id,'record-diagnostic-payment-verification');self.assertEqual(executor.execute(payment_raw,service('RecordDiagnosticPaymentVerification'))['result'],'ACCEPTED')
  proposal=copy.deepcopy(payloads()['CreateAssessmentAccessProposal']);proposal.update(assessment_access_proposal_id=proposal_id,diagnostic_agreement_authority_reference={'reference_type':'DIAGNOSTIC_AGREEMENT_AUTHORITY','reference_id':agreement_id,'reference_version':1},diagnostic_payment_verification_reference={'reference_type':'DIAGNOSTIC_PAYMENT_VERIFICATION','reference_id':payment_id,'reference_version':1});proposal_raw=self.phase5raw('CreateAssessmentAccessProposal',proposal,'phase5a-'+tag+'-proposal-0001',f'c9000000-0000-4000-8000-{sequence+2:012d}','ASSESSMENT_ACCESS_PROPOSAL',proposal_id,'create-assessment-access-proposal');self.assertEqual(executor.execute(proposal_raw,service('CreateAssessmentAccessProposal'))['result'],'ACCEPTED')
  for offset,role,principal in ((3,'CLIENT_DECISION_AUTHORITY','client-'+tag),(4,'SEKINFRA_ENGAGEMENT_AUTHORITY','sekinfra-'+tag)):
   approval=self.phase5raw('RecordAssessmentAccessApproval',{'assessment_access_proposal_id':proposal_id,'authority_role':role},'phase5a-'+tag+'-'+role,f'c9000000-0000-4000-8000-{sequence+offset:012d}','ASSESSMENT_ACCESS_PROPOSAL',proposal_id,'record-assessment-access-approval');approval['caller_type']='HUMAN';approval['caller_identity'].update(caller_type='HUMAN',capabilities=['assessment_access:approve']);self.assertEqual(executor.execute(approval,human(role,principal))['result'],'ACCEPTED')
  approval_uow=PostgresUnitOfWork(PostgresStore(connection_factory_from_environment()),service('IssueAssessmentAccessGrant'))
  try:self.assertTrue(evaluate_assessment_access_dual_approval(approval_uow,T,proposal_id).satisfied)
  finally:approval_uow.rollback();approval_uow.close()
  grant_raw=self.phase5raw('IssueAssessmentAccessGrant',{'assessment_access_grant_id':grant_id,'assessment_access_proposal_id':proposal_id},'phase5a-'+tag+'-grant-0001',f'c9000000-0000-4000-8000-{sequence+5:012d}','ASSESSMENT_ACCESS_GRANT',grant_id,'issue-assessment-access-grant');self.assertEqual(executor.execute(grant_raw,service('IssueAssessmentAccessGrant'))['result'],'ACCEPTED')
  verify_raw=self.phase5raw('VerifyAssessmentAccess',{'assessment_access_grant_id':grant_id},'phase5a-'+tag+'-verify-0001',f'c9000000-0000-4000-8000-{sequence+6:012d}','ASSESSMENT_ACCESS_GRANT',grant_id,'verify-assessment-access');self.assertEqual(executor.execute(verify_raw,service('VerifyAssessmentAccess'))['result'],'ACCEPTED');del executor
  return agreement_raw,payment_raw,proposal_raw,grant_raw,verify_raw
 def test_durable_phase5a_replay_and_command_scoped_conflict_after_fresh_runtime(self):
  self.establish();self.assertEqual(self.approval('CLIENT_DECISION_AUTHORITY','phase5a-replay-client-0001','ba000000-0000-4000-8000-000000000010')['result'],'ACCEPTED');self.assertEqual(self.approval('SEKINFRA_ENGAGEMENT_AUTHORITY','phase5a-replay-sek-0001','ba000000-0000-4000-8000-000000000011')['result'],'ACCEPTED');self.assertEqual(self.final('phase5a-replay-final-0001')['result'],'ACCEPTED')
  agreement={'diagnostic_agreement_authority_id':A,'engagement_id':E,'diagnostic_scope_id':S,'scope_version':1,'agreement_reference':'agreement.external-replay-001','effective_at':'2030-01-01T00:00:00Z'};ar=self.phase5raw('RecordDiagnosticAgreementAuthority',agreement,'phase5a-replay-agreement-0001','c9000000-0000-4000-8000-000000000010','DIAGNOSTIC_AGREEMENT_AUTHORITY',A,'record-diagnostic-agreement-authority');original=self.fresh_executor();self.assertEqual(original.execute(ar,service('RecordDiagnosticAgreementAuthority'))['result'],'ACCEPTED')
  payment={'diagnostic_payment_verification_id':P,'engagement_id':E,'diagnostic_agreement_authority_reference':{'reference_type':'DIAGNOSTIC_AGREEMENT_AUTHORITY','reference_id':A,'reference_version':1},'amount_minor':10000,'currency':'USD','provider_reference':'payment.external-replay-001'};pr=self.phase5raw('RecordDiagnosticPaymentVerification',payment,'phase5a-replay-payment-0001','c9000000-0000-4000-8000-000000000011','DIAGNOSTIC_PAYMENT_VERIFICATION',P,'record-diagnostic-payment-verification');self.assertEqual(original.execute(pr,service('RecordDiagnosticPaymentVerification'))['result'],'ACCEPTED');del original
  payment_replay=self.fresh_executor();self.assertEqual(payment_replay.execute(copy.deepcopy(pr),service('RecordDiagnosticPaymentVerification'))['result'],'DUPLICATE');changed_payment=copy.deepcopy(pr);changed_payment.update(command_id='c9000000-0000-4000-8000-000000000201',subject_id='c9000000-0000-4000-8000-000000000021');changed_payment['payload']['diagnostic_payment_verification_id']=changed_payment['subject_id'];self.assertEqual(payment_replay.execute(changed_payment,service('RecordDiagnosticPaymentVerification'))['result'],'CONFLICT');del payment_replay
  with psycopg.connect(DSN) as c:self.assertEqual(c.execute('select count(*) from public.avuhz_diagnostic_payment_verifications where tenant_id=%s',(T,)).fetchone()[0],1)
  self.assertEqual(self.count('diagnostic_payment.verified'),1);self.assertEqual(self.pending_outbox('diagnostic_payment.verified',P),1)
  proposal=copy.deepcopy(payloads()['CreateAssessmentAccessProposal']);qr=envelope('CreateAssessmentAccessProposal',proposal);qr.update(command_id='c9000000-0000-4000-8000-000000000012',idempotency_key='phase5a-replay-proposal-0001');original=self.fresh_executor();self.assertEqual(original.execute(qr,service('CreateAssessmentAccessProposal'))['result'],'ACCEPTED');del original
  proposal_replay=self.fresh_executor();self.assertEqual(proposal_replay.execute(copy.deepcopy(qr),service('CreateAssessmentAccessProposal'))['result'],'DUPLICATE');del proposal_replay
  with psycopg.connect(DSN) as c:self.assertEqual(c.execute('select count(*) from public.avuhz_assessment_access_proposals where tenant_id=%s',(T,)).fetchone()[0],1)
  self.assertEqual(self.count('assessment_access.proposal_created'),1);self.assertEqual(self.pending_outbox('assessment_access.proposal_created',Q),1)
  approvals=self.fresh_executor()
  for role,ident,principal in (('CLIENT_DECISION_AUTHORITY','c9000000-0000-4000-8000-000000000013','client'),('SEKINFRA_ENGAGEMENT_AUTHORITY','c9000000-0000-4000-8000-000000000014','sekinfra')):
   rr=self.phase5raw('RecordAssessmentAccessApproval',{'assessment_access_proposal_id':Q,'authority_role':role},'phase5a-replay-'+role,ident,'ASSESSMENT_ACCESS_PROPOSAL',Q,'record-assessment-access-approval');rr['caller_type']='HUMAN';rr['caller_identity'].update(caller_type='HUMAN',capabilities=['assessment_access:approve']);self.assertEqual(approvals.execute(rr,human(role,principal))['result'],'ACCEPTED')
  del approvals;approval_uow=PostgresUnitOfWork(PostgresStore(connection_factory_from_environment()),service('IssueAssessmentAccessGrant'));self.assertTrue(evaluate_assessment_access_dual_approval(approval_uow,T,Q).satisfied);approval_uow.rollback();approval_uow.close()
  gr=self.phase5raw('IssueAssessmentAccessGrant',{'assessment_access_grant_id':G,'assessment_access_proposal_id':Q},'phase5a-replay-grant-0001','c9000000-0000-4000-8000-000000000015','ASSESSMENT_ACCESS_GRANT',G,'issue-assessment-access-grant');original=self.fresh_executor();self.assertEqual(original.execute(gr,service('IssueAssessmentAccessGrant'))['result'],'ACCEPTED');del original
  grant_replay=self.fresh_executor();self.assertEqual(grant_replay.execute(copy.deepcopy(gr),service('IssueAssessmentAccessGrant'))['result'],'DUPLICATE');changed_grant=copy.deepcopy(gr);changed_grant.update(command_id='c9000000-0000-4000-8000-000000000202',subject_id='c9000000-0000-4000-8000-000000000022');changed_grant['payload']['assessment_access_grant_id']=changed_grant['subject_id'];self.assertEqual(grant_replay.execute(changed_grant,service('IssueAssessmentAccessGrant'))['result'],'CONFLICT');del grant_replay
  issued_uow=PostgresUnitOfWork(PostgresStore(connection_factory_from_environment()),service('IssueAssessmentAccessGrant'))
  try:self.assertEqual(issued_uow.assessment_access_grants.get(T,G)['status'],'APPROVED');self.assertEqual(issued_uow.assessment_access_proposals.get(T,Q)['status'],'CONSUMED')
  finally:issued_uow.rollback();issued_uow.close()
  with psycopg.connect(DSN) as c:
   self.assertEqual(c.execute('select count(*) from public.avuhz_assessment_access_grants where tenant_id=%s',(T,)).fetchone()[0],1);self.assertEqual(str(c.execute("select subject_id from public.avuhz_idempotency_records where tenant_id=%s and trusted_principal_id=%s and command_type='IssueAssessmentAccessGrant' and idempotency_key=%s",(T,'phase5a-service','phase5a-replay-grant-0001')).fetchone()[0]),G)
  self.assertEqual(self.count('assessment_access.grant_issued'),1);self.assertEqual(self.pending_outbox('assessment_access.grant_issued',G),1)
  vr=self.phase5raw('VerifyAssessmentAccess',{'assessment_access_grant_id':G},'phase5a-replay-verify-0001','c9000000-0000-4000-8000-000000000016','ASSESSMENT_ACCESS_GRANT',G,'verify-assessment-access');original=self.fresh_executor();self.assertEqual(original.execute(vr,service('VerifyAssessmentAccess'))['result'],'ACCEPTED');del original
  before_uow=PostgresUnitOfWork(PostgresStore(connection_factory_from_environment()),service('VerifyAssessmentAccess'))
  try:before=tuple(before_uow.assessment_access_grants.get(T,G)[field] for field in ('verified_at','active_from','expires_at'))
  finally:before_uow.rollback();before_uow.close()
  verify_replay=self.fresh_executor();self.assertEqual(verify_replay.execute(copy.deepcopy(vr),service('VerifyAssessmentAccess'))['result'],'DUPLICATE');del verify_replay
  after_uow=PostgresUnitOfWork(PostgresStore(connection_factory_from_environment()),service('VerifyAssessmentAccess'))
  try:after=tuple(after_uow.assessment_access_grants.get(T,G)[field] for field in ('verified_at','active_from','expires_at'))
  finally:after_uow.rollback();after_uow.close()
  self.assertEqual(after,before);self.assertEqual(self.count('assessment_access.verified_and_activated'),1);self.assertEqual(self.pending_outbox('assessment_access.verified_and_activated',G),1)
 def test_durable_payment_invalidation_and_terminal_closure(self):
  self.establish();self.assertEqual(self.approval('CLIENT_DECISION_AUTHORITY','phase5a-terminal-client-0001','ba000000-0000-4000-8000-000000000010')['result'],'ACCEPTED');self.assertEqual(self.approval('SEKINFRA_ENGAGEMENT_AUTHORITY','phase5a-terminal-sek-0001','ba000000-0000-4000-8000-000000000011')['result'],'ACCEPTED');self.assertEqual(self.final('phase5a-terminal-final-0001')['result'],'ACCEPTED')
  self.active_grant(A,P,Q,G,'payment-invalidation',400)
  usable_uow=PostgresUnitOfWork(PostgresStore(connection_factory_from_environment()),service('VerifyAssessmentAccess'))
  try:self.assertTrue(evaluate_assessment_access_usability(usable_uow,T,G,'2030-01-16T00:00:00Z').usable)
  finally:usable_uow.rollback();usable_uow.close()
  invalidation=self.phase5raw('InvalidateDiagnosticPaymentVerification',{'diagnostic_payment_verification_id':P},'phase5a-payment-invalidation-0001','c9000000-0000-4000-8000-000000000407','DIAGNOSTIC_PAYMENT_VERIFICATION',P,'invalidate-diagnostic-payment-verification',2);original=self.fresh_executor();self.assertEqual(original.execute(invalidation,service('InvalidateDiagnosticPaymentVerification'))['result'],'ACCEPTED');del original
  invalidated_uow=PostgresUnitOfWork(PostgresStore(connection_factory_from_environment()),service('InvalidateDiagnosticPaymentVerification'))
  try:
   payment=invalidated_uow.diagnostic_payment_verifications.get(T,P);grant=invalidated_uow.assessment_access_grants.get(T,G);self.assertEqual(payment['verification_status'],'INVALIDATED');self.assertIn('invalidated_at',payment);invalidated_at=payment['invalidated_at'];self.assertEqual(grant['status'],'ACTIVE');self.assertEqual(evaluate_assessment_access_usability(invalidated_uow,T,G,'2030-01-16T00:00:00Z').reason,'COMMERCIAL_AUTHORITY_INVALID')
  finally:invalidated_uow.rollback();invalidated_uow.close()
  self.assertEqual(self.event_count('diagnostic_payment.invalidated',P),1);self.assertEqual(self.pending_outbox('diagnostic_payment.invalidated',P),1)
  for typ in ('assessment_access.expired','assessment_access.revoked','assessment_access.closed'):self.assertEqual(self.event_count(typ,G),0)
  invalidation_replay=self.fresh_executor();self.assertEqual(invalidation_replay.execute(copy.deepcopy(invalidation),service('InvalidateDiagnosticPaymentVerification'))['result'],'DUPLICATE');del invalidation_replay
  replay_uow=PostgresUnitOfWork(PostgresStore(connection_factory_from_environment()),service('InvalidateDiagnosticPaymentVerification'))
  try:self.assertEqual(replay_uow.diagnostic_payment_verifications.get(T,P)['invalidated_at'],invalidated_at);self.assertEqual(replay_uow.assessment_access_grants.get(T,G)['status'],'ACTIVE');self.assertEqual(evaluate_assessment_access_usability(replay_uow,T,G,'2030-01-16T00:00:00Z').reason,'COMMERCIAL_AUTHORITY_INVALID')
  finally:replay_uow.rollback();replay_uow.close()
  self.assertEqual(self.event_count('diagnostic_payment.invalidated',P),1);self.assertEqual(self.pending_outbox('diagnostic_payment.invalidated',P),1)
  A2='a3000000-0000-4000-8000-000000000016';P2='a3000000-0000-4000-8000-000000000017';Q2='a3000000-0000-4000-8000-000000000018';G2='a3000000-0000-4000-8000-000000000019';self.active_grant(A2,P2,Q2,G2,'natural-expiration',420,'2030-01-16T00:00:00Z')
  expiry_uow=PostgresUnitOfWork(PostgresStore(connection_factory_from_environment()),service('ExpireAssessmentAccess'))
  try:
   expiring=expiry_uow.assessment_access_grants.get(T,G2);expires_at=expiring['expires_at'];self.assertEqual(expires_at,'2030-01-16T00:00:00Z');self.assertTrue(evaluate_assessment_access_usability(expiry_uow,T,G2,'2030-01-15T15:00:00Z').usable);boundary=evaluate_assessment_access_usability(expiry_uow,T,G2,expires_at);self.assertFalse(boundary.usable);self.assertEqual(boundary.reason,'ACCESS_EXPIRED')
  finally:expiry_uow.rollback();expiry_uow.close()
  expiration=self.phase5raw('ExpireAssessmentAccess',{'assessment_access_grant_id':G2},'phase5a-natural-expiration-0001','c9000000-0000-4000-8000-000000000427','ASSESSMENT_ACCESS_GRANT',G2,'expire-assessment-access',2);terminal_context=service('ExpireAssessmentAccess',expires_at='2030-02-15T16:00:00Z');original=self.fresh_executor(expires_at);self.assertEqual(original.execute(expiration,terminal_context)['result'],'ACCEPTED');del original
  terminal_uow=PostgresUnitOfWork(PostgresStore(connection_factory_from_environment()),service('ExpireAssessmentAccess'))
  try:self.assertEqual(terminal_uow.assessment_access_grants.get(T,G2)['status'],'EXPIRED')
  finally:terminal_uow.rollback();terminal_uow.close()
  self.assertEqual(self.event_count('assessment_access.expired',G2),1);self.assertEqual(self.pending_outbox('assessment_access.expired',G2),1)
  expiration_replay=self.fresh_executor(expires_at);self.assertEqual(expiration_replay.execute(copy.deepcopy(expiration),terminal_context)['result'],'DUPLICATE');del expiration_replay
  before_terminal_uow=PostgresUnitOfWork(PostgresStore(connection_factory_from_environment()),service('ExpireAssessmentAccess'))
  try:before_terminal=tuple(before_terminal_uow.assessment_access_grants.get(T,G2)[field] for field in ('verified_at','active_from','expires_at'))
  finally:before_terminal_uow.rollback();before_terminal_uow.close()
  revoke=self.phase5raw('RevokeAssessmentAccess',{'assessment_access_grant_id':G2},'phase5a-expired-revoke-0001','c9000000-0000-4000-8000-000000000428','ASSESSMENT_ACCESS_GRANT',G2,'revoke-assessment-access',3)
  close=self.phase5raw('CloseAssessmentAccessForAgreementEnd',{'assessment_access_grant_id':G2},'phase5a-expired-close-0001','c9000000-0000-4000-8000-000000000429','ASSESSMENT_ACCESS_GRANT',G2,'close-assessment-access-for-agreement-end',3)
  verify=self.phase5raw('VerifyAssessmentAccess',{'assessment_access_grant_id':G2},'phase5a-expired-verify-0001','c9000000-0000-4000-8000-000000000430','ASSESSMENT_ACCESS_GRANT',G2,'verify-assessment-access',3)
  terminal_executor=self.fresh_executor(expires_at)
  for raw,command in ((revoke,'RevokeAssessmentAccess'),(close,'CloseAssessmentAccessForAgreementEnd'),(verify,'VerifyAssessmentAccess')):self.assertEqual(terminal_executor.execute(raw,service(command,expires_at='2030-02-15T16:00:00Z'))['result'],'REJECTED')
  del terminal_executor
  fresh_terminal_uow=PostgresUnitOfWork(PostgresStore(connection_factory_from_environment()),service('ExpireAssessmentAccess'))
  try:
   terminal=fresh_terminal_uow.assessment_access_grants.get(T,G2);self.assertEqual(terminal['status'],'EXPIRED');self.assertEqual(tuple(terminal[field] for field in ('verified_at','active_from','expires_at')),before_terminal);self.assertFalse(evaluate_assessment_access_usability(fresh_terminal_uow,T,G2,expires_at).usable)
  finally:fresh_terminal_uow.rollback();fresh_terminal_uow.close()
  self.assertEqual(self.event_count('assessment_access.expired',G2),1);self.assertEqual(self.pending_outbox('assessment_access.expired',G2),1);self.assertEqual(self.event_count('assessment_access.revoked',G2),0);self.assertEqual(self.event_count('assessment_access.closed',G2),0);self.assertEqual(self.event_count('assessment_access.verified_and_activated',G2),1)
  with psycopg.connect(DSN) as c:durable=repr(c.execute('select diagnostic_payment_verification_id,provider_reference,verification_status,invalidated_at from public.avuhz_diagnostic_payment_verifications').fetchall()+c.execute('select lifecycle_event_id,event_type,idempotency_key,null from public.avuhz_lifecycle_events').fetchall()+c.execute('select outbox_delivery_id,status,null,null from public.avuhz_outbox_deliveries').fetchall()).lower()
  for forbidden in ('password','api_key','oauth','ssh_key','postgresql://','authorization:','provider_response'):self.assertNotIn(forbidden,durable)
 def test_complete_phase5a_chain_through_real_executor(self):
  self.establish();self.assertEqual(self.approval('CLIENT_DECISION_AUTHORITY','phase5a-base-client-0001','ba000000-0000-4000-8000-000000000010')['result'],'ACCEPTED');self.assertEqual(self.approval('SEKINFRA_ENGAGEMENT_AUTHORITY','phase5a-base-sek-0001','ba000000-0000-4000-8000-000000000011')['result'],'ACCEPTED');self.assertEqual(self.final('phase5a-base-final-0001')['result'],'ACCEPTED')
  scope=self.scope(); agreement={'diagnostic_agreement_authority_id':A,'engagement_id':E,'diagnostic_scope_id':S,'scope_version':1,'agreement_reference':'agreement.external-001','effective_at':'2030-01-01T00:00:00Z'}
  ar=self.phase5raw('RecordDiagnosticAgreementAuthority',agreement,'phase5a-agreement-0001','c9000000-0000-4000-8000-000000000010','DIAGNOSTIC_AGREEMENT_AUTHORITY',A,'record-diagnostic-agreement-authority');self.assertEqual(self.x.execute(ar,service('RecordDiagnosticAgreementAuthority'))['result'],'ACCEPTED')
  payment={'diagnostic_payment_verification_id':P,'engagement_id':E,'diagnostic_agreement_authority_reference':{'reference_type':'DIAGNOSTIC_AGREEMENT_AUTHORITY','reference_id':A,'reference_version':1},'amount_minor':10000,'currency':'USD','provider_reference':'payment.external-001'}
  pr=self.phase5raw('RecordDiagnosticPaymentVerification',payment,'phase5a-payment-0001','c9000000-0000-4000-8000-000000000011','DIAGNOSTIC_PAYMENT_VERIFICATION',P,'record-diagnostic-payment-verification');self.assertEqual(self.x.execute(pr,service('RecordDiagnosticPaymentVerification'))['result'],'ACCEPTED')
  proposal=copy.deepcopy(payloads()['CreateAssessmentAccessProposal']);qr=envelope('CreateAssessmentAccessProposal',proposal);qr.update(command_id='c9000000-0000-4000-8000-000000000012',idempotency_key='phase5a-proposal-0001');self.assertEqual(self.x.execute(qr,service('CreateAssessmentAccessProposal'))['result'],'ACCEPTED')
  for role,ident,principal in (('CLIENT_DECISION_AUTHORITY','c9000000-0000-4000-8000-000000000013','client'),('SEKINFRA_ENGAGEMENT_AUTHORITY','c9000000-0000-4000-8000-000000000014','sekinfra')):
   rr=self.phase5raw('RecordAssessmentAccessApproval',{'assessment_access_proposal_id':Q,'authority_role':role},'p5-'+role,ident,'ASSESSMENT_ACCESS_PROPOSAL',Q,'record-assessment-access-approval');rr['caller_type']='HUMAN';rr['caller_identity'].update(caller_type='HUMAN',capabilities=['assessment_access:approve']);self.assertEqual(self.x.execute(rr,human(role,principal))['result'],'ACCEPTED')
  approval_uow=PostgresUnitOfWork(PostgresStore(connection_factory_from_environment()),service('IssueAssessmentAccessGrant'));self.assertTrue(evaluate_assessment_access_dual_approval(approval_uow,T,Q).satisfied);approval_uow.rollback();approval_uow.close()
  gr=self.phase5raw('IssueAssessmentAccessGrant',{'assessment_access_grant_id':G,'assessment_access_proposal_id':Q},'phase5a-grant-0001','c9000000-0000-4000-8000-000000000015','ASSESSMENT_ACCESS_GRANT',G,'issue-assessment-access-grant');self.assertEqual(self.x.execute(gr,service('IssueAssessmentAccessGrant'))['result'],'ACCEPTED')
  vr=self.phase5raw('VerifyAssessmentAccess',{'assessment_access_grant_id':G},'phase5a-verify-0001','c9000000-0000-4000-8000-000000000016','ASSESSMENT_ACCESS_GRANT',G,'verify-assessment-access');self.assertEqual(self.x.execute(vr,service('VerifyAssessmentAccess'))['result'],'ACCEPTED')
  fresh=PostgresUnitOfWork(PostgresStore(connection_factory_from_environment()),service('VerifyAssessmentAccess'))
  try:
   a=fresh.diagnostic_agreement_authorities.get(T,A);p=fresh.diagnostic_payment_verifications.get(T,P);q=fresh.assessment_access_proposals.get(T,Q);g=fresh.assessment_access_grants.get(T,G)
   self.assertEqual((a['engagement_id'],a['scope_reference']['reference_id'],a['canonical_scope_digest']),(E,S,scope['canonical_scope_digest']));self.assertEqual(p['verification_status'],'VERIFIED');self.assertEqual(q['status'],'CONSUMED');self.assertEqual(g['status'],'ACTIVE');self.assertEqual(g['active_from'],g['verified_at']);self.assertLessEqual(datetime.fromisoformat(g['expires_at'].replace('Z','+00:00')),datetime.fromisoformat(g['verified_at'].replace('Z','+00:00'))+timedelta(days=30));u=evaluate_assessment_access_usability(fresh,T,G,'2030-01-16T00:00:00Z');self.assertTrue(u.usable,u.reason)
  finally:fresh.rollback();fresh.close()
  for typ,n in (('diagnostic_agreement.authority_recorded',1),('diagnostic_payment.verified',1),('assessment_access.proposal_created',1),('assessment_access.approval_recorded',2),('assessment_access.grant_issued',1),('assessment_access.verified_and_activated',1)):self.assertEqual(self.count(typ),n)
  with psycopg.connect(DSN) as c:self.assertEqual(c.execute("select count(*) from public.avuhz_outbox_deliveries where status='PENDING'").fetchone()[0],14)
if __name__=='__main__':unittest.main()
