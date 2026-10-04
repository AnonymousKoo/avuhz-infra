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
TENANT='1ad3998c-92ab-4a36-9d1c-ed97f2fa98f0'
SUBJECT_DIGEST='sha256:21ae3658908a20bb95e6440850180d699bba96da97ee1556e0574d1b12293e7a'
PROJECT='pwlhruwutoitnieactol';TARGET='avuhz-implementation-handoff-provider-adapter-development@example.invalid'
def load(n): return json.loads((B/n).read_text())
def rawsha(p): return 'sha256:'+hashlib.sha256(Path(p).read_bytes()).hexdigest()
def main():
 r=load(N+'.resource.json');prep=load(N+'-preparation.evidence.json');p=load(N+'.plan.json');g=load(N+'.progress.json');a=load(N+'.approval.json')
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
 rendered=''.join((B/(N+s)).read_text() for s in ('.resource.json','-preparation.evidence.json','.plan.json','.progress.json','.approval.json'))
 for secret in ('postgresql://','postgres://','password=','sb_secret_','service_role'): assert secret not in rendered
 print('DEVELOPMENT provider-adapter tenant binding v1: PASS (APPROVED; pristine; exact one-key tenant mutation + separate read-only verification; allowlist remains inactive)')
if __name__=='__main__': main()
