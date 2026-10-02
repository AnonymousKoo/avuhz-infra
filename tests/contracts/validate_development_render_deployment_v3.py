#!/usr/bin/env python3
from __future__ import annotations
import json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'src'))
from avuhz_engineering.authorization_plan import initial_progress, plan_digest, validate_plan, validate_progress
from avuhz_runtime.implementation_handoff import canonical_digest
B=ROOT/'contracts/plans/v1'; S=ROOT/'contracts/schemas/v1'
RESOURCE=B/'development-render-deployment-v3.resource.json'
PLAN=B/'development-render-deployment-v3.plan.json'
PROGRESS=B/'development-render-deployment-v3.progress.json'
FINAL_EV=B/'development-render-runtime-config-final-verification-v1-success.evidence.json'
FINAL_EX=B/'development-render-runtime-config-final-verification-v1.execution-progress.json'
V2_PLAN=B/'development-render-deployment-v2.plan.json'
V2_PROGRESS=B/'development-render-deployment-v2.progress.json'
V2_APPROVAL=B/'development-render-deployment-v2.approval.json'
def load(p): return json.loads(p.read_text())
def main():
 r=load(RESOURCE); p=load(PLAN); g=load(PROGRESS); ev=load(FINAL_EV); ex=load(FINAL_EX); v2=load(V2_PLAN); v2p=load(V2_PROGRESS); v2a=load(V2_APPROVAL)
 validate_plan(p,S); validate_progress(p,g,S)
 assert r['contract_digest']==canonical_digest({k:v for k,v in r.items() if k!='contract_digest'})
 assert r['contract_version']=='v3' and r['environment']=='DEVELOPMENT' and r['provider']=='render'
 assert r['workspace_id']=='tea-dab95hv40ujc73a7ccag'
 assert r['service_id']=='srv-dab9n4qd0e5s73dq37mg' and r['service_name']=='avuhz-command-dev'
 assert r['environment_id']=='evm-dab96l2jobas73bp95bg'
 assert r['repo']=='AnonymousKoo/avuhz-infra' and r['repo_visibility_expected']=='public'
 assert r['branch']=='main'
 assert r['branch_protection_required']=={'required_status_checks':['main-pr-gate'],'enforce_admins':True,'required_pull_request_reviews':True}
 assert r['auto_deploy_expected']=='no' and r['auto_deploy_trigger_expected']=='off'
 assert r['manual_deploy_count_authorized']==1 and r['clear_cache_authorized'] is False
 assert r['deployment_head_binding']=='RESOLVED_BY_STEP_PREFLIGHT'
 assert r['source_runtime_config_success_evidence_digest']=='sha256:4b44e6320c9b1572fffa9ef8a0ee273e741a887d45af9ea82ef63a4ef92e5b80'
 assert r['source_runtime_config_progress_digest']=='sha256:0aa764de2f55daa2faecfc4f57225e574a3ea45bc82d3a8bf8c53c94568b021f'
 assert ev['outcome']=='SUCCEEDED_VERIFIED' and ev['verification_observation']['postcondition_verified'] is True
 assert ex['overall_state']=='COMPLETED' and ex['progress_digest']==r['source_runtime_config_progress_digest']
 sup=r['supersedes_deployment_v2']
 assert sup['plan_id']==v2['plan_id'] and sup['plan_digest']==v2['plan_digest'] and sup['approval_id']==v2a['approval_id']
 assert sup['progress_state']==v2p['overall_state']=='NOT_STARTED'
 assert 'visibility changed from private to public before execution' in sup['reason']
 assert r['environment_variable_changes_authorized']==0 and r['environment_group_changes_authorized']==0 and r['service_setting_changes_authorized']==0
 assert r['github_visibility_changes_authorized']==0 and r['github_branch_protection_changes_authorized']==0
 assert r['secret_material_agent_visible'] is False and r['supabase_operation_authorized'] is False and r['n8n_operation_authorized'] is False and r['staging_authorized'] is False and r['production_authorized'] is False
 assert p['plan_version']==3 and p['plan_digest']==plan_digest(p)
 assert p['definition_status']=='READY_FOR_APPROVAL' and p['environment']=='DEVELOPMENT'
 assert p['authorization_window']=={'binding_state':'BOUND','starts_at':'2026-10-02T05:30:00Z','expires_at':'2026-10-02T08:30:00Z'}
 assert p['authority_effect']=='NONE_UNTIL_SEPARATELY_APPROVED'
 assert len(p['steps'])==1
 st=p['steps'][0]
 assert st['step_id']=='development.render.deployment-v3.step.01.deploy-public-protected-canonical-main'
 assert st['operation']=='provider.render.deploy.trigger-manual-latest-main' and st['execution_class']=='PROVIDER_MUTATION'
 assert st['resource']=={'resource_type':'render.service.deployment','resource_reference':'render:srv-dab9n4qd0e5s73dq37mg:deployment','binding_state':'BOUND','exact_version':'render.manual-public-protected-source-deployment.v3','exact_digest':r['contract_digest']}
 assert st['required_evidence']==[
  {'evidence_type':'runtime.render.nonsecret-environment-config.verified','source_step_id':None,'binding_state':'BOUND','exact_digest':'sha256:4b44e6320c9b1572fffa9ef8a0ee273e741a887d45af9ea82ef63a4ef92e5b80'},
  {'evidence_type':'authorization-plan.execution-progress','source_step_id':None,'binding_state':'BOUND','exact_digest':'sha256:0aa764de2f55daa2faecfc4f57225e574a3ea45bc82d3a8bf8c53c94568b021f'}]
 assert st['credential_policy']=={'permitted':True,'allowed_classes':['OWNER_INTERACTIVE_SESSION'],'values_stored':False}
 decl={x['binding_id']:x for x in st['binding_declarations']}
 assert decl['binding.development.render.deployment-v3.canonical-main-head']['phase']=='RESOLVED_BY_STEP_PREFLIGHT'
 assert decl['binding.development.render.deployment-v3.github-repository-protection-preflight']['evidence_type']=='github.repository-protection-preflight.observed'
 assert decl['binding.development.render.deployment-v3.render-service-preflight']['evidence_type']=='provider.render-service-preflight.observed'
 assert decl['binding.development.render.deployment-v3.result']['phase']=='PRODUCED_BY_CURRENT_STEP'
 for x in ('deployment.retry','deployment.second-trigger','environment-variable.modify','environment-group.modify','github.repository-visibility.modify','github.branch-protection.modify','render.auto-deploy.modify','render.branch.modify','render.clear-cache','render.service-setting.modify','supabase.operation','n8n.operation','staging.target','production.target','development-render-deployment-v2.execute'):
  assert x in st['prohibited_actions']
 for x in ('github.repository.not-public','github.branch-protection.missing','github.branch-protection.required-check-missing','github.branch-protection.admin-enforcement-missing','github.branch-protection.pr-review-missing','deployment.failed','deployment.commit-mismatch'):
  assert x in st['stop_conditions']
 assert g==initial_progress(p,S,g['progress_id'],p['created_at'])
 assert g['overall_state']=='NOT_STARTED' and g['step_states'][0]['authorization_state']=='PENDING' and g['step_states'][0]['execution_state']=='NOT_STARTED'
 rendered=RESOURCE.read_text()+PLAN.read_text()+PROGRESS.read_text()
 for forbidden in ('postgresql://','password=','op://'): assert forbidden not in rendered
 print('DEVELOPMENT Render deployment v3: PASS (READY_FOR_APPROVAL; public+protected repo required; v2 superseded; exact runtime-config PASS bound; one deploy; no retry/config/visibility/protection/secret mutation)')
 return 0
if __name__=='__main__': raise SystemExit(main())
