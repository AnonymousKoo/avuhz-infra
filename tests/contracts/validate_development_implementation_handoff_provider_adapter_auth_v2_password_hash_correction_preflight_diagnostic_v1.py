#!/usr/bin/env python3
from __future__ import annotations
import json, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; sys.path.insert(0,str(ROOT/'src'))
from avuhz_engineering.authorization_plan import initial_progress,plan_digest,validate_plan,validate_progress
from avuhz_runtime.implementation_handoff import canonical_digest
B=ROOT/'contracts/plans/v1'; S=ROOT/'contracts/schemas/v1'
N='development-implementation-handoff-provider-adapter-auth-v2-password-hash-correction-preflight-diagnostic-v1'
PLAN_ID='3c468905-9d61-45ab-ae6f-34e27e310dfe'
PLAN_DIGEST='sha256:d998154357799c7527319d86e6c3763dc0d493c0d1d538f986dfb010236479d3'
PROGRESS_ID='bafa56ed-47ed-4417-912b-e15bf4323b67'
PROGRESS_DIGEST='sha256:f7aaf62c9fd79377a26fc5c2ac2ff74a44639a8ba20500e112401c2b224fa159'
RESOURCE_DIGEST='sha256:a7f4bc259fd04a558549cb11b9900afbffad07e64b44d10ee30cc0073f789e3c'
PREP_DIGEST='sha256:60e9578e9d189eb6a1d043491f78d8bff375b1a3b84d4abb09ce7ed5f381e8b3'
PRIOR_PROGRESS='sha256:8fcfe94d1bfabbca542c6f86f98d92f1b34d4237eac74c166fe255b749a6ab3f'
PRIOR_FAILURE='sha256:7a4a6c721e426af2d88fdc75d97528474129f6e75bc1a787ebbeea1cecf7490e'
PROJECT='pwlhruwutoitnieactol'
FIELDS=['auth_user_count','known_synthetic_user_count','canonical_tenant_bound_user_count','target_identity_count','target_bcrypt_like_count','target_password_null_count','target_tenant_bound_count','target_provider_metadata_exact_count','target_user_metadata_exact_count','target_email_identity_count','session_count','refresh_token_count']
def load(name): return json.loads((B/name).read_text())
def main():
 r=load(N+'.resource.json'); prep=load(N+'-preparation.evidence.json'); p=load(N+'.plan.json'); g=load(N+'.progress.json')
 validate_plan(p,S); validate_progress(p,g,S)
 assert p['plan_id']==PLAN_ID and p['plan_digest']==PLAN_DIGEST==plan_digest(p)
 assert p['definition_status']=='READY_FOR_APPROVAL' and p['authority_effect']=='NONE_UNTIL_SEPARATELY_APPROVED'
 assert p['environment']=='DEVELOPMENT' and p['target']['project_reference']==PROJECT and p['target']['responsibility']=='AUTH'
 assert p['authorization_window']=={'binding_state':'BOUND','starts_at':'2026-10-03T22:00:00Z','expires_at':'2026-10-04T02:00:00Z'}
 assert len(p['steps'])==1 and p['ordered_step_ids']==[p['steps'][0]['step_id']]
 assert not (B/(N+'.approval.json')).exists()
 assert g==initial_progress(p,S,PROGRESS_ID,p['created_at']) and g['progress_digest']==PROGRESS_DIGEST and g['overall_state']=='NOT_STARTED'
 assert r['contract_digest']==RESOURCE_DIGEST==canonical_digest({k:v for k,v in r.items() if k!='contract_digest'})
 assert r['interaction_surface']=='supabase.dashboard.sql-editor' and r['diagnostic_method']=='ONE_EXACT_AGGREGATE_ONLY_AUTH_PREFLIGHT_SELECT'
 assert r['result_fields']==FIELDS and r['result_value_contract'].startswith('Each field must be a nonnegative integer count.')
 for flag in ('provider_mutation_authorized','identity_change_authorized','password_state_change_authorized','tenant_binding_authorized','allowlist_binding_authorized','token_issue_authorized','session_issue_authorized','hook_change_authorized','data_operation_authorized','render_operation_authorized','n8n_operation_authorized','staging_authorized','production_authorized','raw_row_return_authorized','password_hash_value_read_authorized','credential_material_persistence_authorized'):
  assert r[flag] is False, flag
 sql=r['diagnostic_sql'].lower()
 assert sql.startswith('select') and sql.count(';')==1
 for forbidden in ('update ','delete ','insert ','alter ','create ','drop ','grant ','revoke ','truncate '): assert forbidden not in sql
 for field in FIELDS: assert field in sql
 assert 'encrypted_password' in sql and "like '$2%'" in sql
 assert prep['evidence_digest']==PREP_DIGEST==canonical_digest({k:v for k,v in prep.items() if k!='evidence_digest'})
 prior=prep['prior_correction_observation']
 assert prior['overall_state']=='STOPPED' and prior['progress_digest']==PRIOR_PROGRESS and prior['failure_evidence_digest']==PRIOR_FAILURE
 assert prior['provider_mutation_attempted'] is False and prior['provider_mutation_committed'] is False and prior['retry_authorized'] is False
 assert all(v is False for v in prep['security_state'].values())
 failed=load('development-implementation-handoff-provider-adapter-auth-v2-password-hash-correction-v1.progress.json')
 failure=load('development-implementation-handoff-provider-adapter-auth-v2-password-hash-correction-v1-step01-failure.evidence.json')
 assert failed['overall_state']=='STOPPED' and failed['progress_digest']==PRIOR_PROGRESS
 assert failure['evidence_digest']==PRIOR_FAILURE and failure['safe_error_code']=='AVUHZ_PROVIDER_ADAPTER_PASSWORD_HASH_CORRECTION_PREFLIGHT_FAILED'
 step=p['steps'][0]
 assert step['operation']=='provider.auth-identity.inspect-correction-preflight-counts-read-only' and step['execution_class']=='PROVIDER_READ'
 assert step['credential_policy']=={'permitted':True,'allowed_classes':['OWNER_INTERACTIVE_SESSION'],'values_stored':False}
 assert step['resource']['exact_digest']==RESOURCE_DIGEST
 assert step['required_evidence'][0]['exact_digest']==PREP_DIGEST and step['required_evidence'][1]['exact_digest']==PRIOR_FAILURE
 for action in ('provider.mutation','identity.modify','password.set','password-hash.set','password-hash.clear','password-hash.read','tenant-metadata.bind','server-allowlist.bind','token.issue','session.issue','data.operation','render.operation','n8n.operation','staging.target','production.target','raw-row.read','prior-correction.retry','additional-sql.execute'):
  assert action in p['prohibited_actions']
 rendered=''.join((B/(N+s)).read_text() for s in ('.resource.json','-preparation.evidence.json','.plan.json','.progress.json'))
 for secret_shape in ('postgresql://','postgres://','password=','sb_secret_','service_role'): assert secret_shape not in rendered
 print('DEVELOPMENT provider-adapter password-hash correction preflight diagnostic v1: PASS (READY_FOR_APPROVAL; pristine; one aggregate SELECT only; no mutation/retry authority)')
if __name__=='__main__': main()
