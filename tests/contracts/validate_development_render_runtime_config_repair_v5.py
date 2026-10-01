#!/usr/bin/env python3
"""Validate DEVELOPMENT Render runtime configuration repair v5 preparation."""
from __future__ import annotations
import hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'src'))
from avuhz_engineering.authorization_plan import initial_progress,plan_digest,validate_plan,validate_progress
from avuhz_runtime.implementation_handoff import canonical_digest
BASE=ROOT/'contracts/plans/v1'; SCHEMA=ROOT/'contracts/schemas/v1'
RESOURCE=BASE/'development-render-runtime-config-repair-v5.resource.json'
PLAN=BASE/'development-render-runtime-config-repair-v5.plan.json'
PROGRESS=BASE/'development-render-runtime-config-repair-v5.progress.json'
V4_EXEC=BASE/'development-render-runtime-config-repair-v4.execution-progress.json'
V4_SCOPE=BASE/'development-render-runtime-config-repair-v4-step03-scope-drift.evidence.json'
PLAN_ID='db081e9c-460d-455c-8228-c632d3c7782f'
PLAN_DIGEST='sha256:4ac4f2c9f41b5bcbee7ad7333266afe44d3923ec8e88b608c10986197782e538'
PROGRESS_ID='3c6ee8f8-e00f-4674-b0be-c8968083501d'
PROGRESS_DIGEST='sha256:b16d324d270071c13773f0cae937972df51e8f2767ea2ef0750147e916553e45'
RESOURCE_DIGEST='sha256:4c6a3350b86846c2d4f54b4302333accee18139d70776dc04e7dee5b43de9d13'
V4_SCOPE_DIGEST='sha256:7cde43655288a8b5d894fa6788489c94c6d081d2780fa0bdc676245dc2a2a327'
def load(p): return json.loads(p.read_text())
def file_digest(p): return 'sha256:'+hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 r=load(RESOURCE); p=load(PLAN); g=load(PROGRESS); x=load(V4_EXEC); s3=load(V4_SCOPE)
 validate_plan(p,SCHEMA); validate_progress(p,g,SCHEMA)
 assert file_digest(V4_SCOPE)==V4_SCOPE_DIGEST
 assert r['contract_digest']==RESOURCE_DIGEST==canonical_digest({k:v for k,v in r.items() if k!='contract_digest'})
 assert r['environment']=='DEVELOPMENT' and r['provider']=='render'
 assert r['workspace_id']=='tea-dab95hv40ujc73a7ccag' and r['service_id']=='srv-dab9n4qd0e5s73dq37mg'
 assert r['service_name']=='avuhz-command-dev' and r['environment_id']=='evm-dab96l2jobas73bp95bg'
 assert r['provider_managed_required_keys']==['PORT'] and r['protected_existing_keys']==['AVUHZ_POSTGRES_DSN']
 assert r['v4_stop_progress_digest']==x['progress_digest']=='sha256:e0a7102ac233b37126514f18250a1d710585c3b337d7c38e2f1d80916d27e1ef'
 staged={e['key']:e for e in r['preexisting_staged_variables']}
 assert staged['AVUHZ_SERVICE_ENVIRONMENT']['value']=='DEVELOPMENT'
 assert staged['AVUHZ_DATA_PROJECT_REF']['value']=='gnuqaefotwgkwurjpyik' and staged['AVUHZ_DATA_PROJECT_REF']['source_digest']==V4_SCOPE_DIGEST
 assert staged['AVUHZ_DATA_PROJECT_URL']['value']=='https://gnuqaefotwgkwurjpyik.supabase.co'
 assert staged['AVUHZ_AUTH_PROJECT_REF']['value']=='pwlhruwutoitnieactol' and staged['AVUHZ_AUTH_PROJECT_REF']['source_digest']==V4_SCOPE_DIGEST
 assert all(e['must_not_be_mutated_by_v5'] is True for e in r['preexisting_staged_variables'])
 assert s3['outcome']=='FAILED_SCOPE_DRIFT' and s3['verification_observation']['new_deploy_detected'] is False
 mech=r['provider_mechanism']; assert mech=={'surface':'RENDER_DASHBOARD_ENVIRONMENT','action':'SAVE_ONLY','single_key_per_save':True,'deployment_side_effect_allowed':False,'connected_update_environment_variables_wrapper_allowed':False}
 policy=r['mutation_policy']; assert policy['allowed_environment_variable_changes']==5 and policy['single_key_per_provider_action'] is True
 assert policy['batched_provider_action_authorized'] is False and policy['deployment_authorized'] is False and policy['secret_material_agent_visible'] is False
 expected=['AVUHZ_AUTH_ISSUER','AVUHZ_SERVICE_AUDIENCE','AVUHZ_TENANT_BRIDGE','AVUHZ_RLS_POLICY_REFERENCE','AVUHZ_COMMAND_SERVICE_IDENTITY']
 assert [e['key'] for e in r['variables']]==expected and len(r['variables'])==5
 assert all(e['update_mode']=='DASHBOARD_SAVE_ONLY_SINGLE_KEY' and e['provider_surface']=='RENDER_DASHBOARD_ENVIRONMENT_SAVE_ONLY' for e in r['variables'])
 assert p['plan_id']==PLAN_ID and p['plan_version']==5 and p['plan_digest']==PLAN_DIGEST==plan_digest(p)
 assert p['definition_status']=='DRAFT_BLOCKED' and p['authorization_window']=={'binding_state':'UNRESOLVED_BLOCKER','starts_at':None,'expires_at':None}
 assert p['authority_effect']=='NONE_UNTIL_SEPARATELY_APPROVED' and len(p['steps'])==5
 assert p['ordered_step_ids']==[s['step_id'] for s in p['steps']]
 for i,(s,e) in enumerate(zip(p['steps'],r['variables']),1):
  assert s['ordinal']==i and s['step_id'].startswith('development.render.runtime-config-repair-v5.step.')
  assert s['operation']=='provider.render.dashboard.environment-variable.save-only-single-nonsecret-exact'
  assert s['execution_class']=='PROVIDER_MUTATION' and s['credential_policy']=={'permitted':True,'allowed_classes':['OWNER_INTERACTIVE_SESSION'],'values_stored':False}
  assert 'batch.mutation' in s['prohibited_actions'] and 'connected-render-update-environment-variables-wrapper.use' in s['prohibited_actions'] and 'deployment.trigger' in s['prohibited_actions']
  assert 'scope.drift' in s['stop_conditions'] and 'deployment.detected' in s['stop_conditions']
  assert s['resource']['exact_digest']==e['entry_digest']
  if i==1:
   assert s['dependency_step_ids']==[]
   assert s['required_evidence'][0]['exact_digest']==V4_SCOPE_DIGEST
   assert s['required_evidence'][1]['exact_digest']==x['progress_digest']
  else:
   assert s['dependency_step_ids']==[p['steps'][i-2]['step_id']]
 assert g==initial_progress(p,SCHEMA,PROGRESS_ID,p['created_at']) and g['progress_digest']==PROGRESS_DIGEST
 assert g['overall_state']=='NOT_STARTED' and all(s['authorization_state']=='PENDING' and not s['authorization_consumed'] and s['execution_state']=='NOT_STARTED' for s in g['step_states'])
 rendered=RESOURCE.read_text()+PLAN.read_text()+PROGRESS.read_text()
 for forbidden in ('postgresql://','password=','op://'): assert forbidden not in rendered
 print('DEVELOPMENT Render runtime config repair v5: PASS (DRAFT_BLOCKED; four staged non-secret values; five remaining Save-only single-key steps; no execution authority)')
 return 0
if __name__=='__main__': raise SystemExit(main())
