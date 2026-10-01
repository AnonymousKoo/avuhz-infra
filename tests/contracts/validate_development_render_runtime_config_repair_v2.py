#!/usr/bin/env python3
"""Validate DEVELOPMENT Render runtime configuration repair v2 preparation."""
from __future__ import annotations
import hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'src'))
from avuhz_engineering.authorization_plan import initial_progress,plan_digest,validate_plan,validate_progress
from avuhz_runtime.implementation_handoff import canonical_digest
BASE=ROOT/'contracts/plans/v1'; SCHEMA=ROOT/'contracts/schemas/v1'
RESOURCE=BASE/'development-render-runtime-config-repair-v2.resource.json'
PLAN=BASE/'development-render-runtime-config-repair-v2.plan.json'
PROGRESS=BASE/'development-render-runtime-config-repair-v2.progress.json'
V1_STOP=BASE/'development-render-runtime-config-repair-v1-stop.evidence.json'
V1_EXEC=BASE/'development-render-runtime-config-repair-v1.execution-progress.json'
PLAN_ID='62c7adf6-a41b-45cb-9622-03b1e2032a49'
PLAN_DIGEST='sha256:73115400d79cb2b74226a4994466d4011bcf9cad14f7c333a0ff8bf5b8a860fe'
PROGRESS_ID='a28c8f6f-fc99-4415-adc1-659b8d42a72d'
PROGRESS_DIGEST='sha256:52ea612a6032153c766d71251adf9c7de28cffcf919dd062e09a570e9bb59683'
RESOURCE_DIGEST='sha256:01dde83617ddb08dd18ad8550bfa8322ad003c43bbf50da45540337f23b13ebf'
V1_STOP_DIGEST='sha256:6c3d32fcf9de9d9ff81945ae5b3dae4ee8be650c7a5a27f9fc8b506c6026ecc2'
def load(p): return json.loads(p.read_text())
def file_digest(p): return 'sha256:'+hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 r=load(RESOURCE); p=load(PLAN); g=load(PROGRESS); x=load(V1_EXEC)
 validate_plan(p,SCHEMA); validate_progress(p,g,SCHEMA)
 assert file_digest(V1_STOP)==V1_STOP_DIGEST
 assert r['contract_digest']==RESOURCE_DIGEST==canonical_digest({k:v for k,v in r.items() if k!='contract_digest'})
 assert r['environment']=='DEVELOPMENT' and r['provider']=='render'
 assert r['workspace_id']=='tea-dab95hv40ujc73a7ccag' and r['service_id']=='srv-dab9n4qd0e5s73dq37mg'
 assert r['service_name']=='avuhz-command-dev' and r['environment_id']=='evm-dab96l2jobas73bp95bg'
 assert r['provider_managed_required_keys']==['PORT'] and r['protected_existing_keys']==['AVUHZ_POSTGRES_DSN']
 staged=r['preexisting_staged_variable']
 assert staged['key']=='AVUHZ_SERVICE_ENVIRONMENT' and staged['value']=='DEVELOPMENT' and staged['must_not_be_mutated_by_v2'] is True
 assert staged['source_v1_stop_evidence_digest']==V1_STOP_DIGEST
 assert staged['source_v1_execution_progress_digest']==x['progress_digest']
 mech=r['provider_mechanism']; assert mech=={'surface':'RENDER_DASHBOARD_ENVIRONMENT','action':'SAVE_ONLY','single_key_per_save':True,'deployment_side_effect_allowed':False,'connected_update_environment_variables_wrapper_allowed':False}
 policy=r['mutation_policy']; assert policy['allowed_environment_variable_changes']==8 and policy['single_key_per_provider_action'] is True
 assert policy['deployment_authorized'] is False and policy['auto_deploy_changes_authorized'] is False and policy['secret_material_agent_visible'] is False
 assert len(r['variables'])==8 and all(e['update_mode']=='DASHBOARD_SAVE_ONLY_SINGLE_KEY' for e in r['variables'])
 assert all(e['provider_surface']=='RENDER_DASHBOARD_ENVIRONMENT_SAVE_ONLY' for e in r['variables'])
 assert [e['key'] for e in r['variables']]==['AVUHZ_DATA_PROJECT_REF','AVUHZ_DATA_PROJECT_URL','AVUHZ_AUTH_PROJECT_REF','AVUHZ_AUTH_ISSUER','AVUHZ_SERVICE_AUDIENCE','AVUHZ_TENANT_BRIDGE','AVUHZ_RLS_POLICY_REFERENCE','AVUHZ_COMMAND_SERVICE_IDENTITY']
 assert p['plan_id']==PLAN_ID and p['plan_version']==2 and p['plan_digest']==PLAN_DIGEST==plan_digest(p)
 assert p['definition_status']=='DRAFT_BLOCKED' and p['authorization_window']=={'binding_state':'UNRESOLVED_BLOCKER','starts_at':None,'expires_at':None}
 assert p['authority_effect']=='NONE_UNTIL_SEPARATELY_APPROVED' and len(p['steps'])==8
 assert p['ordered_step_ids']==[s['step_id'] for s in p['steps']]
 for i,(s,e) in enumerate(zip(p['steps'],r['variables']),1):
  assert s['ordinal']==i and s['operation']=='provider.render.dashboard.environment-variable.save-only-single-nonsecret-exact'
  assert s['execution_class']=='PROVIDER_MUTATION' and s['credential_policy']=={'permitted':True,'allowed_classes':['OWNER_INTERACTIVE_SESSION'],'values_stored':False}
  assert 'connected-render-update-environment-variables-wrapper.use' in s['prohibited_actions'] and 'deployment.trigger' in s['prohibited_actions']
  assert 'dashboard.save-only-option.missing' in s['stop_conditions'] and 'deployment.detected' in s['stop_conditions']
  assert s['resource']['exact_digest']==e['entry_digest']
  if i==1:
   assert s['dependency_step_ids']==[]
   assert s['required_evidence'][0]['exact_digest']==V1_STOP_DIGEST
   assert s['required_evidence'][1]['exact_digest']==x['progress_digest']
  else:
   assert s['dependency_step_ids']==[p['steps'][i-2]['step_id']]
   assert s['required_evidence']==[{'evidence_type':'runtime.render.nonsecret-environment-variable.bound','source_step_id':p['steps'][i-2]['step_id'],'binding_state':'DERIVED_FROM_SOURCE_STEP','exact_digest':None}]
 assert g==initial_progress(p,SCHEMA,PROGRESS_ID,p['created_at']) and g['progress_digest']==PROGRESS_DIGEST
 assert g['overall_state']=='NOT_STARTED' and all(s['authorization_state']=='PENDING' and not s['authorization_consumed'] for s in g['step_states'])
 rendered=RESOURCE.read_text()+PLAN.read_text()+PROGRESS.read_text()
 for forbidden in ('postgresql://','password=','op://'): assert forbidden not in rendered
 print('DEVELOPMENT Render runtime config repair v2: PASS (DRAFT_BLOCKED; Step 1 staged by v1 evidence; 8 Save-only single-key mutations; connected auto-deploy wrapper prohibited)')
 return 0
if __name__=='__main__': raise SystemExit(main())
