#!/usr/bin/env python3
from __future__ import annotations
import json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'src'))
from avuhz_engineering.authorization_plan import approval_digest, initial_progress, plan_digest, validate_approval, validate_plan, validate_progress
from avuhz_runtime.implementation_handoff import canonical_digest
B=ROOT/'contracts/plans/v1'; S=ROOT/'contracts/schemas/v1'
RESOURCE=B/'development-render-deployment-v2.resource.json'
PLAN=B/'development-render-deployment-v2.plan.json'
PROGRESS=B/'development-render-deployment-v2.progress.json'
APPROVAL=B/'development-render-deployment-v2.approval.json'
FINAL_EV=B/'development-render-runtime-config-final-verification-v1-success.evidence.json'
FINAL_EX=B/'development-render-runtime-config-final-verification-v1.execution-progress.json'
def load(p): return json.loads(p.read_text())
def main():
 r=load(RESOURCE); p=load(PLAN); g=load(PROGRESS); ev=load(FINAL_EV); ex=load(FINAL_EX); a=load(APPROVAL)
 validate_plan(p,S); validate_progress(p,g,S); validate_approval(p,a,S,p['authorization_window']['starts_at'])
 assert r['contract_digest']==canonical_digest({k:v for k,v in r.items() if k!='contract_digest'})
 assert r['contract_version']=='v2' and r['environment']=='DEVELOPMENT' and r['provider']=='render'
 assert r['workspace_id']=='tea-dab95hv40ujc73a7ccag'
 assert r['service_id']=='srv-dab9n4qd0e5s73dq37mg' and r['service_name']=='avuhz-command-dev'
 assert r['environment_id']=='evm-dab96l2jobas73bp95bg'
 assert r['repo']=='AnonymousKoo/avuhz-infra' and r['repo_visibility_expected']=='private'
 assert r['branch']=='main' and r['auto_deploy_expected']=='no' and r['auto_deploy_trigger_expected']=='off'
 assert r['manual_deploy_count_authorized']==1 and r['clear_cache_authorized'] is False
 assert r['deployment_head_binding']=='RESOLVED_BY_STEP_PREFLIGHT'
 assert r['private_repo_access_check']=='PROVEN_BY_DEPLOY_SOURCE_PULL'
 assert r['source_runtime_config_success_evidence_digest']=='sha256:4b44e6320c9b1572fffa9ef8a0ee273e741a887d45af9ea82ef63a4ef92e5b80'
 assert r['source_runtime_config_progress_digest']=='sha256:0aa764de2f55daa2faecfc4f57225e574a3ea45bc82d3a8bf8c53c94568b021f'
 assert r['private_repo_actions_certification']=={'run_id':36961840629,'head_sha':'108b21f15292743319f0156cbd9d8994334a3d09','conclusion':'success'}
 assert ev['outcome']=='SUCCEEDED_VERIFIED' and ev['verification_observation']['postcondition_verified'] is True
 assert ex['overall_state']=='COMPLETED' and ex['progress_digest']==r['source_runtime_config_progress_digest']
 assert r['environment_variable_changes_authorized']==0 and r['environment_group_changes_authorized']==0 and r['service_setting_changes_authorized']==0
 assert r['secret_material_agent_visible'] is False and r['supabase_operation_authorized'] is False and r['n8n_operation_authorized'] is False and r['staging_authorized'] is False and r['production_authorized'] is False
 assert p['plan_version']==2 and p['plan_digest']==plan_digest(p)
 assert p['definition_status']=='READY_FOR_APPROVAL' and p['environment']=='DEVELOPMENT'
 assert p['authorization_window']=={'binding_state':'BOUND','starts_at':'2026-10-02T05:00:00Z','expires_at':'2026-10-02T08:00:00Z'}
 assert p['authority_effect']=='NONE_UNTIL_SEPARATELY_APPROVED'
 assert len(p['steps'])==1
 st=p['steps'][0]
 assert st['step_id']=='development.render.deployment-v2.step.01.deploy-private-canonical-main'
 assert st['operation']=='provider.render.deploy.trigger-manual-latest-main' and st['execution_class']=='PROVIDER_MUTATION'
 assert st['resource']=={'resource_type':'render.service.deployment','resource_reference':'render:srv-dab9n4qd0e5s73dq37mg:deployment','binding_state':'BOUND','exact_version':'render.manual-private-source-deployment.v2','exact_digest':r['contract_digest']}
 assert st['required_evidence']==[
  {'evidence_type':'runtime.render.nonsecret-environment-config.verified','source_step_id':None,'binding_state':'BOUND','exact_digest':'sha256:4b44e6320c9b1572fffa9ef8a0ee273e741a887d45af9ea82ef63a4ef92e5b80'},
  {'evidence_type':'authorization-plan.execution-progress','source_step_id':None,'binding_state':'BOUND','exact_digest':'sha256:0aa764de2f55daa2faecfc4f57225e574a3ea45bc82d3a8bf8c53c94568b021f'}]
 assert st['credential_policy']=={'permitted':True,'allowed_classes':['OWNER_INTERACTIVE_SESSION'],'values_stored':False}
 decl={x['binding_id']:x for x in st['binding_declarations']}
 assert decl['binding.development.render.deployment-v2.canonical-main-head']['phase']=='RESOLVED_BY_STEP_PREFLIGHT'
 assert decl['binding.development.render.deployment-v2.github-repository-preflight']['evidence_type']=='github.repository-preflight.observed'
 assert decl['binding.development.render.deployment-v2.render-service-preflight']['evidence_type']=='provider.render-service-preflight.observed'
 assert decl['binding.development.render.deployment-v2.result']['phase']=='PRODUCED_BY_CURRENT_STEP'
 for x in ('deployment.retry','deployment.second-trigger','environment-variable.modify','environment-group.modify','github.repository-visibility.modify','render.auto-deploy.modify','render.branch.modify','render.clear-cache','render.service-setting.modify','supabase.operation','n8n.operation','staging.target','production.target'):
  assert x in st['prohibited_actions']
 for x in ('github.repository.not-private','private-repository-source-pull.failed','deployment.failed','deployment.commit-mismatch'):
  assert x in st['stop_conditions']
 assert g==initial_progress(p,S,g['progress_id'],p['created_at'])
 assert g['overall_state']=='NOT_STARTED' and g['step_states'][0]['authorization_state']=='PENDING' and g['step_states'][0]['execution_state']=='NOT_STARTED'
 assert a['approval_id']=='f12e132d-c6ad-49e9-92f6-a5bcec391ee7'
 assert a['plan_id']==p['plan_id'] and a['plan_version']==2 and a['plan_digest']==p['plan_digest']
 assert a['owner_identity']=='github:AnonymousKoo' and a['decision']=='APPROVE' and a['environment']=='DEVELOPMENT'
 assert a['effective_at']=='2026-10-02T05:00:00Z' and a['expires_at']=='2026-10-02T08:00:00Z' and a['approved_at']=='2026-10-02T03:58:55Z'
 assert a['status']=='ACTIVE' and a['authority_scope']=='EXACT_PLAN_ONLY'
 assert a['approval_digest']=='sha256:1c41327e5fdd69156069743067bc01b04ed2b9a70ea89164fc9afe5cf945f25d'==approval_digest(a)
 rendered=RESOURCE.read_text()+PLAN.read_text()+PROGRESS.read_text()+APPROVAL.read_text()
 for forbidden in ('postgresql://','password=','op://'): assert forbidden not in rendered
 print('DEVELOPMENT Render deployment v2: PASS (APPROVED; private repo required; exact runtime-config PASS bound; one deploy; no retry/config/visibility/secret mutation)')
 return 0
if __name__=='__main__': raise SystemExit(main())
