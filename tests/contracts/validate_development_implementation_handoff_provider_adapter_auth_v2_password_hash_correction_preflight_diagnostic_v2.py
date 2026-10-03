#!/usr/bin/env python3
from __future__ import annotations
import json, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; sys.path.insert(0,str(ROOT/'src'))
from avuhz_engineering.authorization_plan import approval_digest,initial_progress,plan_digest,validate_approval,validate_plan,validate_progress
from avuhz_runtime.implementation_handoff import canonical_digest
B=ROOT/'contracts/plans/v1'; S=ROOT/'contracts/schemas/v1'
N='development-implementation-handoff-provider-adapter-auth-v2-password-hash-correction-preflight-diagnostic-v2'
PLAN_ID='0e688c3c-8289-4aca-9ecd-3bb1247de5c1'
PLAN_DIGEST='sha256:da5dd996f9fb8efb9ed678d188f860130a4eb39d0e13d7974530b08e187fc12f'
PROGRESS_ID='850a41fb-089c-4735-8390-df3e5d9222c2'
PROGRESS_DIGEST='sha256:8d89510927fa2382c5dd449e3af3bf50bdc70942780c7d42bff3554ccab64c61'
RESOURCE_DIGEST='sha256:2b94773416272aab5609cff3f89f7400d8c253db3e7bf3a12f6c32c115a3fc80'
PREP_DIGEST='sha256:1b31eaa1f98341bd62111de7b12e4c7c31b72fee749c95448d6b4827c7a7a46b'
PRIOR_PROGRESS='sha256:8fcfe94d1bfabbca542c6f86f98d92f1b34d4237eac74c166fe255b749a6ab3f'
PRIOR_FAILURE='sha256:7a4a6c721e426af2d88fdc75d97528474129f6e75bc1a787ebbeea1cecf7490e'
EVIDENCE_DIGEST='sha256:97e7653e89729b6ead79a6f05e60270e17635b4dfd2136cffc338672e5ecf9c1'
EXECUTION_PROGRESS_DIGEST='sha256:b5dcd300960d453745c367533d843e1b36e1665fae6d1211cec7b930f828bc8f'
RESULT_DIGEST='sha256:a0fb61c9e355cb2f8a6300aef5dd638f96046853805e8c22adc4870eaf52cfd0'
PROJECT='pwlhruwutoitnieactol'
FIELDS=['auth_user_count','known_synthetic_user_count','canonical_tenant_bound_user_count','target_identity_count','target_bcrypt_like_count','target_password_null_count','target_tenant_bound_count','target_provider_metadata_exact_count','target_user_metadata_exact_count','target_email_identity_count','session_count','refresh_token_count']
def load(name): return json.loads((B/name).read_text())
def main():
 r=load(N+'.resource.json'); prep=load(N+'-preparation.evidence.json'); p=load(N+'.plan.json'); g=load(N+'.progress.json'); a=load(N+'.approval.json'); e=load(N+'-step01-success.evidence.json'); x=load(N+'.execution-progress.json')
 validate_plan(p,S); validate_progress(p,g,S); validate_approval(p,a,S,'2026-10-03T22:30:00Z')
 assert p['plan_id']==PLAN_ID and p['plan_digest']==PLAN_DIGEST==plan_digest(p)
 assert p['definition_status']=='READY_FOR_APPROVAL' and p['authority_effect']=='NONE_UNTIL_SEPARATELY_APPROVED'
 assert p['environment']=='DEVELOPMENT' and p['target']['project_reference']==PROJECT and p['target']['responsibility']=='AUTH'
 assert p['authorization_window']=={'binding_state':'BOUND','starts_at':'2026-10-03T22:30:00Z','expires_at':'2026-10-04T02:00:00Z'}
 assert a['plan_id']==PLAN_ID and a['plan_version']==2 and a['plan_digest']==PLAN_DIGEST
 assert a['owner_identity']=='github:AnonymousKoo' and a['decision']=='APPROVE' and a['environment']=='DEVELOPMENT'
 assert a['effective_at']=='2026-10-03T22:30:00Z' and a['expires_at']=='2026-10-04T02:00:00Z'
 assert a['approved_at']=='2026-10-03T22:08:39Z' and a['status']=='ACTIVE' and a['authority_scope']=='EXACT_PLAN_ONLY'
 assert a['approval_digest']==approval_digest(a)
 assert len(p['steps'])==1 and p['ordered_step_ids']==[p['steps'][0]['step_id']]
 assert g==initial_progress(p,S,PROGRESS_ID,p['created_at']) and g['progress_digest']==PROGRESS_DIGEST and g['overall_state']=='NOT_STARTED'
 assert x['progress_id']==PROGRESS_ID and x['progress_digest']==EXECUTION_PROGRESS_DIGEST and x['overall_state']=='COMPLETED' and x['record_version']==3
 xs=x['step_states'][0]
 assert xs['authorization_state']=='CONSUMED' and xs['execution_state']=='SUCCEEDED' and xs['verification_state']=='PASS' and xs['authorization_consumed'] is True and xs['safe_error_code'] is None
 assert xs['evidence']==[{'evidence_type':'auth.provider-adapter-password-hash-correction.preflight-diagnosed','evidence_reference':N+'-step01-success.evidence.json','evidence_digest':EVIDENCE_DIGEST,'recorded_at':'2026-10-03T22:38:30Z'}]
 assert e['evidence_digest']==EVIDENCE_DIGEST==canonical_digest({k:v for k,v in e.items() if k!='evidence_digest'})
 assert e['outcome']=='SUCCEEDED_VERIFIED' and e['classification']=='TARGET_USER_METADATA_PRECONDITION_DRIFT' and e['result_digest']==RESULT_DIGEST
 assert e['sanitized_result']=={'auth_user_count':2,'known_synthetic_user_count':1,'canonical_tenant_bound_user_count':1,'target_identity_count':1,'target_bcrypt_like_count':1,'target_password_null_count':0,'target_tenant_bound_count':0,'target_provider_metadata_exact_count':1,'target_user_metadata_exact_count':0,'target_email_identity_count':1,'session_count':0,'refresh_token_count':0}
 assert e['comparison']['mismatched_fields']=={'target_user_metadata_exact_count':{'expected':1,'observed':0}} and e['comparison']['matching_field_count']==11 and e['comparison']['mismatched_field_count']==1
 assert e['execution_observation']['approved_aggregate_select_attempts']==1 and e['execution_observation']['additional_sql_executed'] is False and e['execution_observation']['provider_mutation_attempted'] is False and e['execution_observation']['prior_correction_retried'] is False
 assert all(v is False for k,v in e['security_state'].items() if isinstance(v,bool))
 assert r['contract_digest']==RESOURCE_DIGEST==canonical_digest({k:v for k,v in r.items() if k!='contract_digest'})
 assert r['interaction_surface']=='supabase.dashboard.sql-editor' and r['diagnostic_method']=='ONE_EXACT_AGGREGATE_ONLY_AUTH_PREFLIGHT_SELECT'
 assert r['contract_version']=='v2'
 assert r['supersedes_v1']=={'plan_id':'3c468905-9d61-45ab-ae6f-34e27e310dfe','plan_digest':'sha256:d998154357799c7527319d86e6c3763dc0d493c0d1d538f986dfb010236479d3','progress_digest':'sha256:f7aaf62c9fd79377a26fc5c2ac2ff74a44639a8ba20500e112401c2b224fa159','progress_state':'NOT_STARTED','reason':'owner approval was issued at 2026-10-03T22:00:07Z, after the v1 effective_at boundary 2026-10-03T22:00:00Z; v1 remains pristine and unexecuted; forward-only v2 shifts only the authorization window'}
 assert r['result_fields']==FIELDS and r['result_value_contract'].startswith('Each field must be a nonnegative integer count.')
 for flag in ('provider_mutation_authorized','identity_change_authorized','password_state_change_authorized','tenant_binding_authorized','allowlist_binding_authorized','token_issue_authorized','session_issue_authorized','hook_change_authorized','data_operation_authorized','render_operation_authorized','n8n_operation_authorized','staging_authorized','production_authorized','raw_row_return_authorized','password_hash_value_read_authorized','credential_material_persistence_authorized'):
  assert r[flag] is False, flag
 sql=r['diagnostic_sql'].lower()
 assert sql.startswith('select') and sql.count(';')==1
 for forbidden in ('update ','delete ','insert ','alter ','create ','drop ','grant ','revoke ','truncate '): assert forbidden not in sql
 for field in FIELDS: assert field in sql
 assert 'encrypted_password' in sql and "like '$2%'" in sql
 assert prep['evidence_digest']==PREP_DIGEST==canonical_digest({k:v for k,v in prep.items() if k!='evidence_digest'})
 v1obs=prep['v1_observation']
 assert v1obs['overall_state']=='NOT_STARTED' and v1obs['progress_digest']=='sha256:f7aaf62c9fd79377a26fc5c2ac2ff74a44639a8ba20500e112401c2b224fa159'
 assert v1obs['approval_file_exists'] is False and v1obs['owner_approval_observed_at']=='2026-10-03T22:00:07Z' and v1obs['v1_effective_at']=='2026-10-03T22:00:00Z'
 assert v1obs['approval_valid_under_policy'] is False and v1obs['rejection_reason']=='APPROVAL_AFTER_EFFECTIVE_AT'
 assert all(v is False for v in prep['security_state'].values())
 failed=load('development-implementation-handoff-provider-adapter-auth-v2-password-hash-correction-v1.progress.json')
 failure=load('development-implementation-handoff-provider-adapter-auth-v2-password-hash-correction-v1-step01-failure.evidence.json')
 assert failed['overall_state']=='STOPPED' and failed['progress_digest']==PRIOR_PROGRESS
 assert failure['evidence_digest']==PRIOR_FAILURE and failure['safe_error_code']=='AVUHZ_PROVIDER_ADAPTER_PASSWORD_HASH_CORRECTION_PREFLIGHT_FAILED'
 step=p['steps'][0]
 assert step['operation']=='provider.auth-identity.inspect-correction-preflight-counts-read-only' and step['execution_class']=='PROVIDER_READ'
 assert step['credential_policy']=={'permitted':True,'allowed_classes':['OWNER_INTERACTIVE_SESSION'],'values_stored':False}
 assert step['resource']['exact_digest']==RESOURCE_DIGEST
 assert step['required_evidence'][0]['exact_digest']==PREP_DIGEST and step['required_evidence'][1]['exact_digest']==PRIOR_FAILURE and step['required_evidence'][2]['exact_digest']=='sha256:f7aaf62c9fd79377a26fc5c2ac2ff74a44639a8ba20500e112401c2b224fa159'
 for action in ('provider.mutation','identity.modify','password.set','password-hash.set','password-hash.clear','password-hash.read','tenant-metadata.bind','server-allowlist.bind','token.issue','session.issue','data.operation','render.operation','n8n.operation','staging.target','production.target','raw-row.read','prior-correction.retry','additional-sql.execute'):
  assert action in p['prohibited_actions']
 rendered=''.join((B/(N+s)).read_text() for s in ('.resource.json','-preparation.evidence.json','.plan.json','.progress.json','.approval.json','-step01-success.evidence.json','.execution-progress.json'))
 for secret_shape in ('postgresql://','postgres://','password=','sb_secret_','service_role'): assert secret_shape not in rendered
 print('DEVELOPMENT provider-adapter password-hash correction preflight diagnostic v2: PASS (COMPLETED; 11/12 preflight counts matched; only target_user_metadata_exact_count drifted 1->0; no mutation/retry authority)')
if __name__=='__main__': main()
