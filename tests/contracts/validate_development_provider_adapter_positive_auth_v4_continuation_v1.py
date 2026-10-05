#!/usr/bin/env python3
from __future__ import annotations
import hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; sys.path.insert(0,str(ROOT)); sys.path.insert(0,str(ROOT/'src'))
from avuhz_engineering.authorization_plan import initial_progress,plan_digest,progress_digest,validate_plan,validate_progress
from avuhz_runtime.implementation_handoff import canonical_digest
from scripts import development_provider_adapter_positive_auth_v4_continuation_v1 as executor
B=ROOT/'contracts/plans/v1'; S=ROOT/'contracts/schemas/v1'; N='development-implementation-handoff-provider-adapter-positive-auth-v4-continuation-v1'
PLAN_ID='43baee79-d5ca-51de-b812-62761844aad0'; PLAN_DIGEST='sha256:ef029ff07d14620cc7e33c703d06dd40f4f3c044fb9af9843415e3072b55ee5b'; RESOURCE_DIGEST='sha256:10c9d7acc2344769edc76ee4ba2b5f3af68baf2a8a20fd6f2ec10ca97800a22a'; PREP_DIGEST='sha256:b3b6f2f96a4d1a45ea90d685b13c375c4233b41999496b422c9a40e623eb41f5'; PROGRESS_ID='2df10de6-a149-5aa4-b5ce-4c23bd300074'; PROGRESS_DIGEST='sha256:32e42f931902f537f22ca6cc968a8f111e50bd4ef4cdfaff8717686cc66c9ce9'; CREATED='2026-10-05T01:20:43Z'; START='2026-10-05T02:00:00Z'; END='2026-10-05T06:00:00Z'; PROJECT='pwlhruwutoitnieactol'; KEY='impl_handoff_provider_adapter_positive_auth_v4_ephemeral'; GH='AVUHZ_DEVELOPMENT_SUPABASE_AUTH_PROVIDER_ADAPTER_POSITIVE_AUTH_V4_EPHEMERAL'; CORR='sha256:238b4af1586b4b57d919910acdd4042ea01abe95706a7133cadd9a8a6dc5887c'; CORR_PROGRESS='sha256:6b6eb329c6b945fde6f625be46794213b8f97a5126415a79389386547e123bdc'; V4_STOP='sha256:89597fb31105b2398295ba8c0be4534c7de80e7813b673e108db83a57a301c9c'
def load(s): return json.loads((B/(N+s)).read_text())
def raw(p): return 'sha256:'+hashlib.sha256(Path(p).read_bytes()).hexdigest()
def main():
 r=load('.resource.json'); prep=load('-preparation.evidence.json'); p=load('.plan.json'); g=load('.progress.json')
 validate_plan(p,S); validate_progress(p,g,S)
 assert p['plan_id']==PLAN_ID and p['plan_digest']==PLAN_DIGEST==plan_digest(p) and p['plan_version']==1
 assert p['definition_status']=='READY_FOR_APPROVAL' and p['authority_effect']=='NONE_UNTIL_SEPARATELY_APPROVED'
 assert p['environment']=='DEVELOPMENT' and p['target']['project_reference']==PROJECT and p['target']['responsibility']=='AUTH'
 assert p['authorization_window']=={'binding_state':'BOUND','starts_at':START,'expires_at':END} and p['created_at']==CREATED
 assert r['contract_digest']==RESOURCE_DIGEST==canonical_digest({k:v for k,v in r.items() if k!='contract_digest'})
 assert r['resource_version']=='provider-adapter-positive-auth-v4-continuation.v1' and r['boundary']==N
 assert r['fresh_provider_key_reference']==KEY and r['github_secret_binding_name']==GH
 assert r['fresh_auth_admin_key_create_count_authorized']==0 and r['github_secret_binding_create_count_authorized']==0
 assert r['fresh_auth_admin_key_delete_count_authorized']==1 and r['github_secret_binding_delete_count_authorized']==1
 assert r['temporary_session_issue_count_authorized']==1 and r['temporary_token_validation_count_authorized']==1 and r['live_runtime_identity_probe_count_authorized']==1 and r['global_logout_count_authorized']==1
 assert r['retry_authorized'] is False and r['implementation_handoff_execution_authorized'] is False
 assert all(r[x] is False for x in ['data_operation_authorized','render_mutation_authorized','n8n_operation_authorized','staging_authorized','production_authorized','credential_material_agent_visible','credential_material_persistence_authorized'])
 assert r['v4_stopped_progress_digest']==V4_STOP and r['surface_correction_success_evidence_digest']==CORR and r['surface_correction_execution_progress_digest']==CORR_PROGRESS
 assert r['step1_executor_digest']==raw(ROOT/'scripts/development_provider_adapter_positive_auth_v4_continuation_v1.py')
 assert r['step1_workflow_digest']==raw(ROOT/'.github/workflows/development-provider-adapter-positive-auth-v4-continuation-v1-step1.yml')
 q=r['session_verification']; assert q['interaction_surface']=='supabase.mcp.execute_sql' and q['credential_class']=='NONE' and q['query_count']==1 and q['aggregate_only'] is True and q['expected_result']=={'session_count':0,'refresh_token_count':0} and q['retry_authorized'] is False
 assert r['retirement_interactions']['step3']['exact_name']==KEY and r['retirement_interactions']['step5']['exact_name']==KEY and r['retirement_interactions']['step4']['exact_name']==GH and r['retirement_interactions']['step6']['exact_name']==GH
 assert prep['evidence_digest']==PREP_DIGEST==canonical_digest({k:v for k,v in prep.items() if k!='evidence_digest'}) and prep['provider_authority']=='NONE' and prep['external_provider_contact']=='PROHIBITED' and prep['resource_contract_digest']==RESOURCE_DIGEST and all(v is False for v in prep['security_state'].values())
 assert g==initial_progress(p,S,PROGRESS_ID,CREATED) and g['progress_digest']==PROGRESS_DIGEST==progress_digest(g) and g['overall_state']=='NOT_STARTED'
 assert len(p['steps'])==6 and len(g['step_states'])==6 and all((s['authorization_state'],s['execution_state'],s['verification_state'],s['authorization_consumed'])==('PENDING','NOT_STARTED','NOT_STARTED',False) for s in g['step_states'])
 req={(x['evidence_type'],x['exact_digest']) for x in p['steps'][0]['required_evidence']}; assert ('auth.provider-adapter-positive-auth-v4.step4-surface-correction.counts-verified',CORR) in req and ('authorization-plan.execution-progress',V4_STOP) in req and ('authorization-plan.execution-progress',CORR_PROGRESS) in req
 assert p['steps'][1]['credential_policy']=={'permitted':False,'allowed_classes':['NONE'],'values_stored':False} and 'supabase.mcp.execute_sql' in p['steps'][1]['expected_postcondition']
 assert not (B/(N+'.approval.json')).exists() and not (B/(N+'.execution-progress.json')).exists()
 executor._validate_boundary(p,r,g)
 rendered='\n'.join((B/(N+s)).read_text() for s in ('.resource.json','-preparation.evidence.json','.plan.json','.progress.json'))
 for bad in ('Bearer eyJ','"access_token":','"refresh_token":','service_role_key'): assert bad not in rendered
 print('DEVELOPMENT provider-adapter positive-auth v4 continuation v1: PASS (READY_FOR_APPROVAL; pristine; trusted-auth lifecycle -> zero-session read -> mandatory retirement; no provider authority)')
 return 0
if __name__=='__main__': raise SystemExit(main())
