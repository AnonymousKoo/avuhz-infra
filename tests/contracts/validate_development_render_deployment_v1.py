#!/usr/bin/env python3
"""Validate bounded DEVELOPMENT Render deployment v1 preparation."""
from __future__ import annotations
import json, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'src'))
from avuhz_engineering.authorization_plan import approval_digest, initial_progress, plan_digest, validate_approval, validate_plan, validate_progress
from avuhz_runtime.implementation_handoff import canonical_digest
BASE=ROOT/'contracts/plans/v1'; SCHEMA=ROOT/'contracts/schemas/v1'
RESOURCE=BASE/'development-render-deployment-v1.resource.json'
PLAN=BASE/'development-render-deployment-v1.plan.json'
PROGRESS=BASE/'development-render-deployment-v1.progress.json'
APPROVAL=BASE/'development-render-deployment-v1.approval.json'
CORRECTION_SUCCESS=BASE/'development-render-data-secret-binding-correction-v1-success.evidence.json'
CORRECTION_EXEC=BASE/'development-render-data-secret-binding-correction-v1.execution-progress.json'
RESOURCE_DIGEST='sha256:7927f96735933c56cb33e892b48ddf32004cc50e1a0f19850acaec02a11433c5'
PLAN_ID='1653db1c-e55b-49ec-9fd5-6216d1160609'
PLAN_DIGEST='sha256:2fa09354bfc112dc43faecf3c7718e9addb570ff81b34215831881a960864e83'
PROGRESS_ID='d4423116-def4-4761-85f3-b7eba1697a12'
PROGRESS_DIGEST='sha256:4e473c2acf1ada44d82ff804becc6e25142dc71249fdd02ec0c1e937bdd12e97'
CORRECTION_SUCCESS_DIGEST='sha256:b63c47ed92d1dcbbffefba9dbb395591c16be2bfc2d8048b71edceb724993464'
CORRECTION_PROGRESS_DIGEST='sha256:3332d49e5ff1dfba01fd5e71ba0b7e81914a42de59dcb7d32bc09a73026f795f'
STEP_ID='development.render.deployment-v1.step.01.deploy-canonical-main'
APPROVAL_ID='cc604943-5b43-4116-b2d5-78a8cab062d2'
APPROVAL_DIGEST='sha256:419b9e3449a62350c517e3ae8d764e4554acb6e35c2c1b1f5b6cb8f590cb61ea'
APPROVED_AT='2026-10-01T15:12:33Z'
def load(p): return json.loads(p.read_text())
def main():
    resource=load(RESOURCE); plan=load(PLAN); progress=load(PROGRESS); approval=load(APPROVAL); correction=load(CORRECTION_SUCCESS); correction_exec=load(CORRECTION_EXEC)
    validate_plan(plan,SCHEMA); validate_progress(plan,progress,SCHEMA); validate_approval(plan,approval,SCHEMA,plan['authorization_window']['starts_at'])
    payload={k:v for k,v in resource.items() if k!='contract_digest'}
    assert resource['contract_digest']==RESOURCE_DIGEST==canonical_digest(payload)
    assert resource['environment']=='DEVELOPMENT' and resource['provider']=='render'
    assert resource['workspace_id']=='tea-dab95hv40ujc73a7ccag'
    assert resource['service_id']=='srv-dab9n4qd0e5s73dq37mg' and resource['service_name']=='avuhz-command-dev'
    assert resource['environment_id']=='evm-dab96l2jobas73bp95bg' and resource['branch']=='main'
    assert resource['auto_deploy_expected']=='no' and resource['auto_deploy_trigger_expected']=='off'
    assert resource['manual_deploy_count_authorized']==1 and resource['clear_cache_authorized'] is False
    assert resource['deployment_head_binding']=='RESOLVED_BY_STEP_PREFLIGHT'
    assert resource['environment_variable_changes_authorized']==0 and resource['environment_group_changes_authorized']==0 and resource['service_setting_changes_authorized']==0
    assert correction['outcome']=='SUCCEEDED_VERIFIED' and correction['security_state']['deployment_triggered'] is False
    assert correction_exec['progress_digest']==CORRECTION_PROGRESS_DIGEST and correction_exec['overall_state']=='COMPLETED'
    assert plan['plan_id']==PLAN_ID and plan['plan_version']==1 and plan['plan_digest']==PLAN_DIGEST==plan_digest(plan)
    assert plan['definition_status']=='READY_FOR_APPROVAL' and plan['environment']=='DEVELOPMENT'
    assert plan['target']=={'provider_class':'runtime.provider','provider_reference':'render','project_reference':'srv-dab9n4qd0e5s73dq37mg','responsibility':'RUNTIME','issuer_reference':None,'audience_reference':None}
    assert plan['authorization_window']=={'binding_state':'BOUND','starts_at':'2026-10-01T16:30:00Z','expires_at':'2026-10-01T20:30:00Z'}
    assert plan['authority_effect']=='NONE_UNTIL_SEPARATELY_APPROVED' and plan['ordered_step_ids']==[STEP_ID]
    step=plan['steps'][0]
    assert step['step_id']==STEP_ID and step['execution_class']=='PROVIDER_MUTATION'
    assert step['operation']=='provider.render.deploy.trigger-manual-latest-main'
    assert step['resource']=={'resource_type':'render.service.deployment','resource_reference':'render:srv-dab9n4qd0e5s73dq37mg:deployment','binding_state':'BOUND','exact_version':'render.manual-deployment.v1','exact_digest':RESOURCE_DIGEST}
    assert step['credential_policy']=={'permitted':True,'allowed_classes':['OWNER_INTERACTIVE_SESSION'],'values_stored':False}
    assert step['required_evidence']==[
      {'evidence_type':'runtime.render.data-secret-binding.corrective-state-verified','source_step_id':None,'binding_state':'BOUND','exact_digest':CORRECTION_SUCCESS_DIGEST},
      {'evidence_type':'authorization-plan.execution-progress','source_step_id':None,'binding_state':'BOUND','exact_digest':CORRECTION_PROGRESS_DIGEST}]
    decl={x['binding_id']:x for x in step['binding_declarations']}
    head=decl['binding.development.render.deployment-v1.canonical-main-head']
    assert head['phase']=='RESOLVED_BY_STEP_PREFLIGHT' and head['evidence_type']=='github.canonical-main-head.observed' and head['persistence_policy']=='SANITIZED_VALUE_ALLOWED'
    pre=decl['binding.development.render.deployment-v1.render-service-preflight']
    assert pre['phase']=='RESOLVED_BY_STEP_PREFLIGHT' and pre['evidence_type']=='provider.render-service-preflight.observed'
    for prohibited in ('deployment.retry','deployment.second-trigger','environment-variable.modify','environment-group.modify','render.auto-deploy.modify','render.branch.modify','render.clear-cache','render.service-setting.modify','supabase.operation','n8n.operation','staging.target','production.target'):
        assert prohibited in step['prohibited_actions']
    assert progress==initial_progress(plan,SCHEMA,PROGRESS_ID,plan['created_at']) and progress['progress_digest']==PROGRESS_DIGEST
    s=progress['step_states'][0]
    assert progress['overall_state']=='NOT_STARTED' and s['authorization_state']=='PENDING' and s['authorization_consumed'] is False and s['execution_state']=='NOT_STARTED' and s['verification_state']=='NOT_STARTED' and s['evidence']==[] and s['binding_assertions']==[]
    assert approval=={'approval_id':APPROVAL_ID,'plan_id':PLAN_ID,'plan_version':1,'plan_digest':PLAN_DIGEST,'owner_identity':'github:AnonymousKoo','decision':'APPROVE','environment':'DEVELOPMENT','effective_at':'2026-10-01T16:30:00Z','expires_at':'2026-10-01T20:30:00Z','approved_at':APPROVED_AT,'status':'ACTIVE','authority_scope':'EXACT_PLAN_ONLY','approval_digest':APPROVAL_DIGEST}
    assert approval['approval_digest']==APPROVAL_DIGEST==approval_digest(approval)
    rendered=RESOURCE.read_text()+PLAN.read_text()+PROGRESS.read_text()
    for forbidden in ('postgresql://','password=','op://'): assert forbidden not in rendered
    print('DEVELOPMENT Render deployment v1: PASS (APPROVED; one-service/one-manual-deploy scope; preflight-bound exact main SHA; clearCache=false; no config/secret execution yet)')
    return 0
if __name__=='__main__': raise SystemExit(main())
