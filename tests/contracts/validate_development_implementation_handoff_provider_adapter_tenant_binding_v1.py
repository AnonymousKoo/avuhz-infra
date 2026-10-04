#!/usr/bin/env python3
from __future__ import annotations
import hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; sys.path.insert(0,str(ROOT/'src'))
from avuhz_engineering.authorization_plan import approval_digest,initial_progress,plan_digest,validate_approval,validate_plan,validate_progress
from avuhz_runtime.implementation_handoff import canonical_digest
B=ROOT/'contracts/plans/v1';S=ROOT/'contracts/schemas/v1'
N='development-implementation-handoff-provider-adapter-tenant-binding-v1'
PLAN_ID='7c5828c6-dd2e-4dd2-a163-9e8c99d35bcb'
PLAN_DIGEST='sha256:c9b22999181030d87d2e1d3e58cbe8d75eef33d708b3eac9233fbeaebfbd3bac'
PROGRESS_ID='6e5177b5-3c9e-445d-b4be-3b1e2793d4d9'
PROGRESS_DIGEST='sha256:e612b0d0cf69fdefcf32a3fe0d77afd5b54e63f56e3f3ee9ced1d163451b882d'
RESOURCE_DIGEST='sha256:6918d0117202b883c22931c3747fd3f27f9bf7ce015af3fc5e13ed63ddfa7d7c'
PREP_DIGEST='sha256:9c6ae4cc7e8fa0ba20ac021b94d14eb71cdaf738a2986c65d9757710fc98e01c'
STEP1_EVIDENCE_DIGEST='sha256:24caf151405d2e0f72dba940c856f9484275be5f5d1d6eade9a848bcb9073f3e'
STEP1_STATE_DIGEST='sha256:8b5014499848a18c30b6c7a6e16733dd89a7f7895b7422b480aa8a84c3011ab0'
STEP2_EVIDENCE_DIGEST='sha256:42a33b97e8ab5c8fd9c7972d5d4a9cad57d06135ea9a05952ed6f669026c3936'
STEP2_RESULT_DIGEST='sha256:ac7fec8d094e2518bc9bda4b4ff818cae29eb3bf76e3e608cbc3f65aaf2e5726'
EXECUTION_PROGRESS_DIGEST='sha256:15d141c1f2571f0b95ab9ba6ba6c2589d8939f1202119a5a36b1a6fb7cda6ced'
TENANT='1ad3998c-92ab-4a36-9d1c-ed97f2fa98f0'
SUBJECT_DIGEST='sha256:21ae3658908a20bb95e6440850180d699bba96da97ee1556e0574d1b12293e7a'
PROJECT='pwlhruwutoitnieactol';TARGET='avuhz-implementation-handoff-provider-adapter-development@example.invalid'
def load(n): return json.loads((B/n).read_text())
def rawsha(p): return 'sha256:'+hashlib.sha256(Path(p).read_bytes()).hexdigest()
def main():
 r=load(N+'.resource.json');prep=load(N+'-preparation.evidence.json');p=load(N+'.plan.json');g=load(N+'.progress.json');a=load(N+'.approval.json');e=load(N+'-step01-success.evidence.json');e2=load(N+'-step02-success.evidence.json');x=load(N+'.execution-progress.json')
 validate_plan(p,S);validate_progress(p,g,S);validate_approval(p,a,S,'2026-10-04T01:15:00Z')
 assert p['plan_id']==PLAN_ID and p['plan_digest']==PLAN_DIGEST==plan_digest(p) and p['plan_version']==1
 assert p['definition_status']=='READY_FOR_APPROVAL' and p['authority_effect']=='NONE_UNTIL_SEPARATELY_APPROVED'
 assert p['target']['project_reference']==PROJECT and p['target']['responsibility']=='AUTH'
 assert p['authorization_window']=={'binding_state':'BOUND','starts_at':'2026-10-04T01:15:00Z','expires_at':'2026-10-04T03:30:00Z'}
 assert a['plan_id']==PLAN_ID and a['plan_version']==1 and a['plan_digest']==PLAN_DIGEST
 assert a['owner_identity']=='github:AnonymousKoo' and a['decision']=='APPROVE' and a['environment']=='DEVELOPMENT'
 assert a['effective_at']=='2026-10-04T01:15:00Z' and a['expires_at']=='2026-10-04T03:30:00Z'
 assert a['approved_at']=='2026-10-04T01:02:16Z' and a['status']=='ACTIVE' and a['authority_scope']=='EXACT_PLAN_ONLY'
 assert a['approval_digest']=='sha256:08e75ab1aa2e1d8987badb13c350c3a5cac9dac84449df5ff63da5fc552d6ea6'==approval_digest(a)
 assert g==initial_progress(p,S,PROGRESS_ID,p['created_at']) and g['progress_digest']==PROGRESS_DIGEST and g['overall_state']=='NOT_STARTED'
 assert x['progress_id']==PROGRESS_ID and x['progress_digest']==EXECUTION_PROGRESS_DIGEST and x['overall_state']=='COMPLETED' and x['record_version']==5
 s1x,s2x=x['step_states']; assert s1x['authorization_state']=='CONSUMED' and s1x['execution_state']=='SUCCEEDED' and s1x['verification_state']=='PASS' and s1x['authorization_consumed'] is True and s1x['safe_error_code'] is None
 assert s2x['authorization_state']=='CONSUMED' and s2x['execution_state']=='SUCCEEDED' and s2x['verification_state']=='PASS' and s2x['authorization_consumed'] is True and s2x['safe_error_code'] is None
 assert e['evidence_digest']==STEP1_EVIDENCE_DIGEST==canonical_digest({k:v for k,v in e.items() if k!='evidence_digest'})
 assert e['outcome']=='SUCCEEDED_VERIFIED' and e['classification']=='PROVIDER_ADAPTER_CANONICAL_TENANT_BOUND' and e['verified_effect']['tenant_metadata_state_digest']==STEP1_STATE_DIGEST
 assert e['execution_observation']['approved_transaction_attempts']==1 and e['execution_observation']['provider_result']=='SUCCESS_NO_ROWS_RETURNED' and e['execution_observation']['transaction_commit_reached'] is True
 assert e['execution_observation']['preflight_guard_passed'] is True and e['execution_observation']['rowcount_guard_passed'] is True and e['execution_observation']['postcondition_guard_passed'] is True
 assert e['execution_observation']['additional_sql_executed'] is False and e['execution_observation']['retry_performed'] is False and e['screenshot_retained'] is False
 assert e['verified_effect']['canonical_tenant_id']==TENANT and e['verified_effect']['separate_step2_verification_completed'] is False
 assert all(v is False for v in e['security_state'].values())
 assert e2['evidence_digest']==STEP2_EVIDENCE_DIGEST==canonical_digest({k:v for k,v in e2.items() if k!='evidence_digest'})
 assert e2['outcome']=='SUCCEEDED_VERIFIED' and e2['classification']=='PROVIDER_ADAPTER_CANONICAL_TENANT_VERIFIED' and e2['result_digest']==STEP2_RESULT_DIGEST
 assert e2['verification_observation']['result_fields_exact'] is True and e2['verification_observation']['aggregate_only'] is True and e2['verification_observation']['expected_counts_exact'] is True
 assert e2['sanitized_result']=={'auth_user_count':2,'known_synthetic_user_count':1,'canonical_tenant_bound_user_count':2,'synthetic_exact_tenant_count':1,'target_identity_count':1,'target_password_null_count':1,'target_password_present_count':0,'target_tenant_exact_count':1,'target_app_metadata_exact_count':1,'target_email_identity_count':1,'session_count':0,'refresh_token_count':0}
 assert all(v is False for v in e2['security_state'].values())
 assert r['contract_digest']==RESOURCE_DIGEST==canonical_digest({k:v for k,v in r.items() if k!='contract_digest'})
 assert r['project_reference']==PROJECT and r['target_email']==TARGET and r['provider_subject_digest']==SUBJECT_DIGEST and r['canonical_tenant_id']==TENANT
 assert r['authorized_table']=='auth.users' and r['authorized_column']=='raw_app_meta_data' and r['authorized_json_key']=='avuhz_tenant_id' and r['authorized_target_count']==1
 assert r['active_allowlist_source_digest']=='sha256:17894ed10e4faa26616b8843df96f10a3e65de77fc6c5d85007970ceabd4a367'
 assert rawsha(ROOT/r['active_allowlist_source_path'])==r['active_allowlist_source_digest']
 assert r['active_allowlist_expected']=={'entry_count':1,'provider_adapter_entry_active':False,'existing_caller_type':'HUMAN','existing_capabilities':['engagement:read'],'existing_authority_roles':[]}
 assert all(r[k] is False for k in ('user_metadata_read_authorized','user_metadata_change_authorized','non_tenant_app_metadata_change_authorized','password_change_authorized','identity_change_authorized','allowlist_binding_authorized','token_issue_authorized','session_issue_authorized','hook_change_authorized','data_operation_authorized','render_operation_authorized','n8n_operation_authorized','staging_authorized','production_authorized'))
 mutation=r['mutation_sql'].lower();verify=r['verification_sql'].lower()
 assert 'raw_user_meta_data' not in mutation and 'raw_user_meta_data' not in verify
 assert mutation.startswith('begin;') and mutation.rstrip().endswith('commit;') and mutation.count('update auth.users')==1 and mutation.count('jsonb_set(')==1
 assert "'{avuhz_tenant_id}'" in mutation and TENANT in mutation and TARGET in mutation and 'get diagnostics v_rows = row_count' in mutation
 for bad in ('delete from ','insert into ','truncate ','alter table ','create table ','drop table ','grant ','revoke '): assert bad not in mutation
 assert verify.startswith('select') and verify.count(';')==1
 for bad in ('update ','delete ','insert ','alter ','create ','drop ','grant ','revoke '): assert bad not in verify
 assert r['expected_preflight']['canonical_tenant_bound_user_count']==1 and r['expected_preflight']['target_tenant_bound_count']==0 and r['expected_preflight']['target_password_null_count']==1
 assert r['expected_postcondition']['canonical_tenant_bound_user_count']==2 and r['expected_postcondition']['target_tenant_exact_count']==1 and r['expected_postcondition']['target_password_null_count']==1
 assert prep['evidence_digest']==PREP_DIGEST==canonical_digest({k:v for k,v in prep.items() if k!='evidence_digest'})
 assert prep['identity_observation']['provider_subject_digest']==SUBJECT_DIGEST and prep['identity_observation']['passwordless_state_verified'] is True
 assert prep['canonical_tenant_observation']['tenant_id']==TENANT and prep['active_policy_observation']['provider_adapter_entry_active'] is False
 assert all(v is False for v in prep['security_state'].values())
 source=(ROOT/'src/avuhz_service/development_supabase_identity.py').read_text()
 assert 'DEVELOPMENT_IDENTITY_ALLOWLIST = DEVELOPMENT_SYNTHETIC_READ_ONLY_ALLOWLIST' in source
 assert source.count('caller_type=_PROVIDER_ADAPTER_CALLER_TYPE')==0
 s1,s2=p['steps'];assert s1['execution_class']=='PROVIDER_MUTATION' and s2['execution_class']=='PROVIDER_READ' and s2['dependency_step_ids']==[s1['step_id']]
 assert s1['resource']['exact_digest']==RESOURCE_DIGEST==s2['resource']['exact_digest']
 assert 'server-allowlist.bind' in p['prohibited_actions'] and 'token.issue' in p['prohibited_actions'] and 'session.issue' in p['prohibited_actions']
 assert 'provider.mutation' in s2['prohibited_actions'] and 'raw-row.read' in s2['prohibited_actions'] and 'tenant-metadata.bind' in s2['prohibited_actions']
 rendered=''.join((B/(N+s)).read_text() for s in ('.resource.json','-preparation.evidence.json','.plan.json','.progress.json','.approval.json','-step01-success.evidence.json','-step02-success.evidence.json','.execution-progress.json'))
 for secret in ('postgresql://','postgres://','password=','sb_secret_','service_role'): assert secret not in rendered
 print('DEVELOPMENT provider-adapter tenant binding v1: PASS (COMPLETED; Steps 1-2 consumed/succeeded/pass; canonical tenant independently verified; allowlist remains inactive)')
if __name__=='__main__': main()
