#!/usr/bin/env python3
from __future__ import annotations
import json, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; sys.path.insert(0,str(ROOT/'src'))
from avuhz_engineering.authorization_plan import initial_progress,plan_digest,validate_plan,validate_progress
from avuhz_runtime.implementation_handoff import canonical_digest
B=ROOT/'contracts/plans/v1'; S=ROOT/'contracts/schemas/v1'
N='development-implementation-handoff-provider-adapter-auth-v2-password-hash-correction-v1'
PLAN_ID='45028cec-447f-42c9-a6fa-86e23c72dc85'
PLAN_DIGEST='sha256:b4bc8d8b13cc7822a788ec46f85ee7d98a2b99862d708f5f6f09fbff00b2a8d9'
PROGRESS_ID='7e84979b-5f57-447d-8c27-d783b1d67d30'
PROGRESS_DIGEST='sha256:7e739d704fcff60307367489338c0143d6a75ef9ec919f86acb4627e2b8c5415'
V2_STOPPED='sha256:4982f77e54f43b348b560ca2a6440370240a69ac0d463b2c886df7af08b4fc9d'
V2_EVIDENCE_RAW='sha256:27223a97cdb9943ddff839826f035d4db883a78c3531ab6575a649fec87a028d'
RETIREMENT='sha256:bd660fa458b2b83918c8f90a68bbb8a79c5be83768be819c2b4c7e1f7aa4007a'
PROJECT='pwlhruwutoitnieactol'
TARGET='avuhz-implementation-handoff-provider-adapter-development@example.invalid'
def load(name): return json.loads((B/name).read_text())
def main():
 r=load(N+'.resource.json'); prep=load(N+'-preparation.evidence.json'); p=load(N+'.plan.json'); g=load(N+'.progress.json')
 validate_plan(p,S); validate_progress(p,g,S)
 assert p['plan_id']==PLAN_ID and p['plan_digest']==PLAN_DIGEST==plan_digest(p)
 assert p['definition_status']=='READY_FOR_APPROVAL' and p['authority_effect']=='NONE_UNTIL_SEPARATELY_APPROVED'
 assert p['target']['project_reference']==PROJECT and p['target']['responsibility']=='AUTH'
 assert p['authorization_window']=={'binding_state':'BOUND','starts_at':'2026-10-03T20:00:00Z','expires_at':'2026-10-04T00:00:00Z'}
 assert len(p['steps'])==2 and p['ordered_step_ids']==[x['step_id'] for x in p['steps']]
 assert not (B/(N+'.approval.json')).exists()
 assert g==initial_progress(p,S,PROGRESS_ID,p['created_at'])
 assert g['progress_digest']==PROGRESS_DIGEST and g['overall_state']=='NOT_STARTED'
 assert all(x['authorization_state']=='PENDING' and x['execution_state']=='NOT_STARTED' and x['verification_state']=='NOT_STARTED' and x['authorization_consumed'] is False for x in g['step_states'])
 assert r['contract_digest']==canonical_digest({k:v for k,v in r.items() if k!='contract_digest'})
 assert r['project_reference']==PROJECT and r['target_email']==TARGET
 assert r['interaction_surface']=='supabase.dashboard.sql-editor'
 assert r['authorized_table']=='auth.users' and r['authorized_column']=='encrypted_password' and r['authorized_target_count']==1
 assert r['expected_preflight']['auth_user_count']==2 and r['expected_preflight']['target_identity_count']==1
 assert r['expected_preflight']['target_bcrypt_like_count']==1 and r['expected_preflight']['session_count']==0 and r['expected_preflight']['refresh_token_count']==0
 assert r['expected_postcondition']['target_password_null_count']==1 and r['expected_postcondition']['target_password_present_count']==0
 assert r['expected_postcondition']['target_tenant_bound_count']==0 and r['expected_postcondition']['session_count']==0 and r['expected_postcondition']['refresh_token_count']==0
 source=r['upstream_source_review']
 assert source['admin_create_without_password_generates_random_password'] is True
 assert source['auth_users_encrypted_password_nullable'] is True
 assert source['runtime_has_password_treats_null_or_empty_as_no_password'] is True
 assert source['model_set_password_empty_sets_null'] is True
 assert source['admin_update_empty_password_is_not_selected_because_strength_validation_runs_before_set_password'] is True
 assert source['direct_sql_provider_support_beyond_current_schema_semantics_assumed'] is False
 for flag in ('identity_delete_authorized','identity_recreate_authorized','email_change_authorized','role_change_authorized','user_metadata_change_authorized','app_metadata_change_authorized','tenant_binding_authorized','allowlist_binding_authorized','token_issue_authorized','session_issue_authorized','hook_change_authorized','data_operation_authorized','render_operation_authorized','n8n_operation_authorized','staging_authorized','production_authorized','raw_provider_subject_persistence_authorized','credential_material_persistence_authorized'):
  assert r[flag] is False, flag
 mutation=r['mutation_sql'].lower(); verify=r['verification_sql'].lower()
 col='encrypted_'+'password'
 assert mutation.startswith('begin;') and mutation.rstrip().endswith('commit;')
 assert mutation.count('update auth.users')==1 and mutation.count('set '+col+' = null')==1
 assert TARGET in mutation and 'get diagnostics v_rows = row_count' in mutation and 'v_rows <> 1' in mutation
 assert 'auth.sessions' in mutation and 'auth.refresh_tokens' in mutation and 'auth.identities' in mutation
 for forbidden in ('delete from ','insert into ','truncate ','alter table ','create table ','drop table ','grant ','revoke '): assert forbidden not in mutation
 assert verify.startswith('select') and verify.count(';')==1
 for forbidden in ('update ','delete ','insert ','alter ','create ','drop ','grant ','revoke '): assert forbidden not in verify
 assert prep['evidence_digest']==canonical_digest({k:v for k,v in prep.items() if k!='evidence_digest'})
 assert prep['v2_stopped_observation']['progress_digest']==V2_STOPPED and prep['v2_stopped_observation']['stopped_evidence_raw_digest']==V2_EVIDENCE_RAW
 assert prep['credential_retirement_observation']['progress_digest']==RETIREMENT and all(v is False for v in prep['security_state'].values())
 v2=load('development-implementation-handoff-provider-adapter-auth-v2.execution-progress.json')
 stopped=load('development-implementation-handoff-provider-adapter-auth-v2-step01-stopped.evidence.json')
 retirement=load('development-implementation-handoff-provider-adapter-auth-v2-credential-retirement-v1.progress.json')
 assert v2['overall_state']=='STOPPED' and v2['progress_digest']==V2_STOPPED
 assert stopped['safe_error_code']=='SUPABASE_ADMIN_CREATE_USER_GENERATED_RANDOM_PASSWORD'
 assert stopped['postcondition_observation']['target_bcrypt_like_count']==1 and stopped['postcondition_observation']['target_tenant_bound_count']==0
 assert stopped['postcondition_observation']['session_count']==0 and stopped['postcondition_observation']['refresh_token_count']==0
 assert retirement['overall_state']=='COMPLETED' and retirement['progress_digest']==RETIREMENT
 s1,s2=p['steps']
 assert s1['operation']=='provider.auth-identity.clear-provider-generated-password-hash-one' and s1['execution_class']=='PROVIDER_MUTATION'
 assert s2['operation']=='provider.auth-identity.verify-passwordless-state-read-only' and s2['execution_class']=='PROVIDER_READ'
 assert s1['credential_policy']=={'permitted':True,'allowed_classes':['OWNER_INTERACTIVE_SESSION'],'values_stored':False}
 assert s2['credential_policy']=={'permitted':True,'allowed_classes':['OWNER_INTERACTIVE_SESSION'],'values_stored':False}
 assert s2['dependency_step_ids']==[s1['step_id']]
 assert s1['resource']['exact_digest']==r['contract_digest']==s2['resource']['exact_digest']
 for action in ('identity.create','identity.delete','identity.recreate','tenant-metadata.bind','server-allowlist.bind','token.issue','session.issue','data.operation','render.operation','n8n.operation','staging.target','production.target','password.set','password-hash.set','password-hash.read','provider-adapter-auth-v2.retry'):
  assert action in p['prohibited_actions']
 assert 'provider.mutation' in s2['prohibited_actions'] and 'raw-row.read' in s2['prohibited_actions']
 assert not list((ROOT/'.github/workflows').glob('*provider-adapter-auth-v2-password-hash-correction-v1*'))
 assert not list((ROOT/'scripts').glob('*provider-adapter-auth-v2-password-hash-correction-v1*'))
 rendered=''.join((B/(N+s)).read_text() for s in ('.resource.json','-preparation.evidence.json','.plan.json','.progress.json'))
 for secret_shape in ('postgresql://','postgres://','password=','sb_secret_','service_role'): assert secret_shape not in rendered
 print('DEVELOPMENT ImplementationHandoff provider-adapter Auth v2 password-hash correction v1: PASS (READY_FOR_APPROVAL; pristine; exact one-column mutation + separate read-only verification; no provider effect)')
if __name__=='__main__': main()
