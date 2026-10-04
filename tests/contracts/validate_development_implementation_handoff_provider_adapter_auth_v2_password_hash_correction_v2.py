#!/usr/bin/env python3
from __future__ import annotations
import json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; sys.path.insert(0,str(ROOT/'src'))
from avuhz_engineering.authorization_plan import approval_digest,initial_progress,plan_digest,validate_approval,validate_plan,validate_progress
from avuhz_runtime.implementation_handoff import canonical_digest
B=ROOT/'contracts/plans/v1'; S=ROOT/'contracts/schemas/v1'
N='development-implementation-handoff-provider-adapter-auth-v2-password-hash-correction-v2'
PLAN_ID='493ec928-e30f-40a0-9d35-29717f4debac'
PLAN_DIGEST='sha256:7754de5fed5f5b34e216173ec3d7a04515f9bf7ea54422cdfa3569c2548ea4e1'
PROGRESS_ID='cdf4cfb3-364e-457b-a45d-4dfea3b2ad2e'
PROGRESS_DIGEST='sha256:c906fd30619f4c2099afac4e3bc2953780449c3e65476a7302cc30b8b329d819'
RESOURCE_DIGEST='sha256:a394826fd6deb275330f598fbf1bea0a7b7a36933613079e8d60749e67ba9238'
PREP_DIGEST='sha256:c651e6d473c9484a9f54fa3b69628458f138cb424f58cbb4f2156c8099506fe4'
DIAG_EVIDENCE='sha256:97e7653e89729b6ead79a6f05e60270e17635b4dfd2136cffc338672e5ecf9c1'
DIAG_PROGRESS='sha256:b5dcd300960d453745c367533d843e1b36e1665fae6d1211cec7b930f828bc8f'
STEP1_EVIDENCE_DIGEST='sha256:bcd57fec2dbc2f191fbd128f0e26edd9815d521915aa59131fa89635807c6841'
STEP1_STATE_DIGEST='sha256:80cdeb6e51c372ad1f3018dac902ea23d94b21cd9b7763808e11bcb92407db3e'
STEP2_EVIDENCE_DIGEST='sha256:26a90c35357ac14b23d1b7f17e18762e958248462d53aed168985dba249cbb10'
EXECUTION_PROGRESS_DIGEST='sha256:e198535b4cfd3f2eef279f85575531853794ab477a0701cebe5d7ef0ee2290ab'
PROJECT='pwlhruwutoitnieactol'; TARGET='avuhz-implementation-handoff-provider-adapter-development@example.invalid'
def load(n): return json.loads((B/n).read_text())
def main():
 r=load(N+'.resource.json'); prep=load(N+'-preparation.evidence.json'); p=load(N+'.plan.json'); g=load(N+'.progress.json'); a=load(N+'.approval.json'); e=load(N+'-step01-success.evidence.json'); e2=load(N+'-step02-success.evidence.json'); x=load(N+'.execution-progress.json')
 validate_plan(p,S); validate_progress(p,g,S); validate_approval(p,a,S,'2026-10-03T23:30:00Z')
 assert p['plan_id']==PLAN_ID and p['plan_digest']==PLAN_DIGEST==plan_digest(p) and p['plan_version']==2
 assert p['definition_status']=='READY_FOR_APPROVAL' and p['authority_effect']=='NONE_UNTIL_SEPARATELY_APPROVED'
 assert p['target']['project_reference']==PROJECT and p['target']['responsibility']=='AUTH'
 assert p['authorization_window']=={'binding_state':'BOUND','starts_at':'2026-10-03T23:30:00Z','expires_at':'2026-10-04T03:00:00Z'}
 assert a['plan_id']==PLAN_ID and a['plan_version']==2 and a['plan_digest']==PLAN_DIGEST
 assert a['owner_identity']=='github:AnonymousKoo' and a['decision']=='APPROVE' and a['environment']=='DEVELOPMENT'
 assert a['effective_at']=='2026-10-03T23:30:00Z' and a['expires_at']=='2026-10-04T03:00:00Z'
 assert a['approved_at']=='2026-10-03T23:01:48Z' and a['status']=='ACTIVE' and a['authority_scope']=='EXACT_PLAN_ONLY'
 assert a['approval_digest']==approval_digest(a)
 assert g==initial_progress(p,S,PROGRESS_ID,p['created_at']) and g['progress_digest']==PROGRESS_DIGEST and g['overall_state']=='NOT_STARTED'
 assert x['progress_id']==PROGRESS_ID and x['progress_digest']==EXECUTION_PROGRESS_DIGEST and x['overall_state']=='COMPLETED' and x['record_version']==5
 s1x,s2x=x['step_states']; assert s1x['authorization_state']=='CONSUMED' and s1x['execution_state']=='SUCCEEDED' and s1x['verification_state']=='PASS' and s1x['authorization_consumed'] is True and s1x['safe_error_code'] is None
 assert s2x['authorization_state']=='CONSUMED' and s2x['execution_state']=='SUCCEEDED' and s2x['verification_state']=='PASS' and s2x['authorization_consumed'] is True and s2x['safe_error_code'] is None
 assert e['evidence_digest']==STEP1_EVIDENCE_DIGEST==canonical_digest({k:v for k,v in e.items() if k!='evidence_digest'})
 assert e['outcome']=='SUCCEEDED_VERIFIED' and e['classification']=='PROVIDER_ADAPTER_PASSWORD_HASH_CLEARED' and e['verified_effect']['passwordless_state_digest']==STEP1_STATE_DIGEST
 assert e['execution_observation']['approved_transaction_attempts']==1 and e['execution_observation']['provider_result']=='SUCCESS_NO_ROWS_RETURNED' and e['execution_observation']['transaction_commit_reached'] is True
 assert e['execution_observation']['preflight_guard_passed'] is True and e['execution_observation']['rowcount_guard_passed'] is True and e['execution_observation']['postcondition_guard_passed'] is True
 assert e['execution_observation']['additional_sql_executed'] is False and e['execution_observation']['prior_correction_retried'] is False and e['screenshot_retained'] is False
 assert all(v is False for v in e['security_state'].values())
 assert e2['evidence_digest']==STEP2_EVIDENCE_DIGEST==canonical_digest({k:v for k,v in e2.items() if k!='evidence_digest'})
 assert e2['outcome']=='SUCCEEDED_VERIFIED' and e2['classification']=='PROVIDER_ADAPTER_PASSWORDLESS_STATE_VERIFIED'
 assert e2['verification_observation']['expected_counts_exact'] is True and e2['verification_observation']['aggregate_only'] is True
 assert e2['sanitized_result']['target_password_null_count']==1 and e2['sanitized_result']['target_password_present_count']==0
 assert e2['sanitized_result']['session_count']==0 and e2['sanitized_result']['refresh_token_count']==0
 assert all(v is False for v in e2['security_state'].values())
 assert r['contract_digest']==RESOURCE_DIGEST==canonical_digest({k:v for k,v in r.items() if k!='contract_digest'})
 assert r['project_reference']==PROJECT and r['target_email']==TARGET and r['contract_version']=='v2'
 assert r['authorized_table']=='auth.users' and r['authorized_column']=='encrypted_password' and r['authorized_target_count']==1
 assert r['supersedes_correction_v1']['stopped_progress_digest']=='sha256:8fcfe94d1bfabbca542c6f86f98d92f1b34d4237eac74c166fe255b749a6ab3f'
 assert r['expected_preflight']=={'auth_user_count':2,'known_synthetic_user_count':1,'canonical_tenant_bound_user_count':1,'target_identity_count':1,'target_bcrypt_like_count':1,'target_password_null_count':0,'target_tenant_bound_count':0,'target_provider_metadata_exact_count':1,'target_email_identity_count':1,'session_count':0,'refresh_token_count':0}
 assert r['expected_postcondition']=={'auth_user_count':2,'known_synthetic_user_count':1,'canonical_tenant_bound_user_count':1,'target_identity_count':1,'target_password_null_count':1,'target_password_present_count':0,'target_tenant_bound_count':0,'target_provider_metadata_exact_count':1,'target_email_identity_count':1,'session_count':0,'refresh_token_count':0}
 assert r['user_metadata_read_authorized'] is False and r['user_metadata_change_authorized'] is False and r['user_metadata_precondition_authorized'] is False
 assert r['trust_boundary_review']['user_metadata_used_by_development_identity_verifier'] is False
 mutation=r['mutation_sql'].lower(); verify=r['verification_sql'].lower(); col='encrypted_'+'password'
 assert 'raw_user_meta_data' not in mutation and 'raw_user_meta_data' not in verify
 assert mutation.startswith('begin;') and mutation.rstrip().endswith('commit;') and mutation.count('update auth.users')==1 and mutation.count('set '+col+' = null')==1
 assert TARGET in mutation and 'get diagnostics v_rows = row_count' in mutation and 'v_rows <> 1' in mutation
 for forbidden in ('delete from ','insert into ','truncate ','alter table ','create table ','drop table ','grant ','revoke '): assert forbidden not in mutation
 assert verify.startswith('select') and verify.count(';')==1
 for forbidden in ('update ','delete ','insert ','alter ','create ','drop ','grant ','revoke '): assert forbidden not in verify
 assert prep['evidence_digest']==PREP_DIGEST==canonical_digest({k:v for k,v in prep.items() if k!='evidence_digest'})
 assert prep['diagnostic_v2']['evidence_digest']==DIAG_EVIDENCE and prep['diagnostic_v2']['execution_progress_digest']==DIAG_PROGRESS
 assert prep['diagnostic_v2']['sole_mismatch_field']=='target_user_metadata_exact_count' and prep['diagnostic_v2']['provider_mutation_attempted'] is False
 assert all(v is False for v in prep['security_state'].values())
 resolver=(ROOT/'src/avuhz_service/development_supabase_identity.py').read_text()
 assert 'user_metadata' not in resolver and 'claims.get("avuhz_tenant_id")' in resolver and 'self._allowlist' in resolver
 v21=(ROOT/'tests/contracts/validate_development_auth_plan_v21.py').read_text()
 assert 'user.get("user_metadata") != {"email_verified": True}' in v21
 s1,s2=p['steps']; assert s1['execution_class']=='PROVIDER_MUTATION' and s2['execution_class']=='PROVIDER_READ'
 assert s2['dependency_step_ids']==[s1['step_id']] and s1['resource']['exact_digest']==RESOURCE_DIGEST==s2['resource']['exact_digest']
 for action in ('identity.create','identity.delete','identity.recreate','user-metadata.read','user-metadata.bind','tenant-metadata.bind','server-allowlist.bind','token.issue','session.issue','data.operation','render.operation','n8n.operation','staging.target','production.target','provider-adapter-auth-v2-password-hash-correction-v1.retry'):
  assert action in p['prohibited_actions']
 assert 'provider.mutation' in s2['prohibited_actions'] and 'raw-row.read' in s2['prohibited_actions']
 rendered=''.join((B/(N+s)).read_text() for s in ('.resource.json','-preparation.evidence.json','.plan.json','.progress.json','.approval.json','-step01-success.evidence.json','-step02-success.evidence.json','.execution-progress.json'))
 for secret_shape in ('postgresql://','postgres://','password=','sb_secret_','service_role'): assert secret_shape not in rendered
 print('DEVELOPMENT provider-adapter password-hash correction v2: PASS (COMPLETED; Steps 1-2 consumed/succeeded/pass; exact state independently verified; user metadata untouched)')
if __name__=='__main__': main()
