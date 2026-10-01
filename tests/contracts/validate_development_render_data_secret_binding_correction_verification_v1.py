#!/usr/bin/env python3
"""Validate read-only DEVELOPMENT Render secret-binding correction verification v1."""
from __future__ import annotations
import json, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'src'))
from avuhz_engineering.authorization_plan import initial_progress, plan_digest, validate_plan, validate_progress
from avuhz_runtime.implementation_handoff import canonical_digest
SCHEMA=ROOT/'contracts/schemas/v1'; BASE=ROOT/'contracts/plans/v1'
RESOURCE=BASE/'development-render-data-secret-binding-correction-verification-v1.resource.json'
PLAN=BASE/'development-render-data-secret-binding-correction-verification-v1.plan.json'
PROGRESS=BASE/'development-render-data-secret-binding-correction-verification-v1.progress.json'
APPROVAL=BASE/'development-render-data-secret-binding-correction-verification-v1.approval.json'
V2_FAILURE=BASE/'development-render-data-secret-binding-v2-failure.evidence.json'
V2_EXEC=BASE/'development-render-data-secret-binding-v2.execution-progress.json'
RESOURCE_DIGEST='sha256:274a8ab5955b26ce0d49021ad0fce5fdf7392195dbe25911dda72674a810b84c'
PLAN_ID='0ff800bc-e9dd-4d32-ba2e-31f097bcda24'
PLAN_DIGEST='sha256:dde38065dd68fc87fee861ae20994ad2d29f5e8cb8234a13f09daf5807333124'
PROGRESS_ID='69387ba4-a008-422d-ad35-96771d37f076'
PROGRESS_DIGEST='sha256:623237cbab205729f2cdaf7cf4e20667956c5178bca53bf5838f6658d7d43730'
STEP_ID='development.render.data-secret-binding-correction-verification-v1.step.01.inspect-final-render-scope-read-only'
V2_FAILURE_DIGEST='sha256:276c0dcd8fff4ac1281a011b8555877ca5c20991aab234406454d5b28cd2674f'
V2_PROGRESS_DIGEST='sha256:0e0030941489fddeed94d1cb7149f61cfbb8c7cb4183a96f5cbc233bfb45c8ab'
def load(p): return json.loads(p.read_text())
def main():
    resource=load(RESOURCE); plan=load(PLAN); progress=load(PROGRESS); failure=load(V2_FAILURE); v2=load(V2_EXEC)
    validate_plan(plan,SCHEMA); validate_progress(plan,progress,SCHEMA)
    assert resource['contract_digest']==RESOURCE_DIGEST==canonical_digest({k:v for k,v in resource.items() if k!='contract_digest'})
    assert resource['environment']=='DEVELOPMENT' and resource['provider']=='render'
    assert resource['workspace']['id']=='tea-dab95hv40ujc73a7ccag'
    assert resource['service']=={
      'id':'srv-dab9n4qd0e5s73dq37mg','name':'avuhz-command-dev','environment_id':'evm-dab96l2jobas73bp95bg',
      'environment_key':'AVUHZ_POSTGRES_DSN','expected_auto_deploy':'no','expected_auto_deploy_trigger':'off',
      'expected_live_deploy_id':'dep-dabab1942hec73acamdg','expected_live_commit':'6bff57065151462fc74861c68a232454b2ef9a20'}
    assert resource['environment_group']['id']=='evg-dav5m3l9fdbs73bdmi9g' and resource['environment_group']['name']=='AVUHZ_POSTGRES'
    assert resource['verification']['provider_mutation_authorized'] is False and resource['verification']['deploy_authorized'] is False
    assert resource['verification']['secret_material_agent_visible'] is False and resource['verification']['other_attached_services_allowed'] is False
    assert failure['safe_error_code']=='RENDER_ENVIRONMENT_SCOPE_DRIFT'
    assert v2['progress_digest']==V2_PROGRESS_DIGEST and v2['overall_state']=='STOPPED'
    assert plan['plan_id']==PLAN_ID and plan['plan_version']==1 and plan['plan_digest']==PLAN_DIGEST==plan_digest(plan)
    assert plan['definition_status']=='READY_FOR_APPROVAL' and plan['environment']=='DEVELOPMENT'
    assert plan['target']=={'provider_class':'runtime.provider','provider_reference':'render','project_reference':'tea-dab95hv40ujc73a7ccag','responsibility':'RUNTIME','issuer_reference':None,'audience_reference':None}
    assert plan['authorization_window']=={'binding_state':'BOUND','starts_at':'2026-10-01T14:30:00Z','expires_at':'2026-10-01T18:30:00Z'}
    assert plan['ordered_step_ids']==[STEP_ID]
    step=plan['steps'][0]
    assert step['step_id']==STEP_ID and step['execution_class']=='PROVIDER_READ'
    assert step['resource']['resource_type']=='render.environment-scope.verification' and step['resource']['exact_digest']==RESOURCE_DIGEST
    assert step['credential_policy']=={'permitted':True,'allowed_classes':['OWNER_INTERACTIVE_SESSION'],'values_stored':False}
    assert step['required_evidence']==[
      {'evidence_type':'runtime.render.data-secret-binding.applied','source_step_id':None,'binding_state':'BOUND','exact_digest':V2_FAILURE_DIGEST},
      {'evidence_type':'authorization-plan.execution-progress','source_step_id':None,'binding_state':'BOUND','exact_digest':V2_PROGRESS_DIGEST}]
    for prohibited in ('provider.mutation','render.deploy','deployment.trigger','environment-group.modify','environment-variable.modify','environment-variable.value.reveal','secret.agent-visible','secret.return'):
        assert prohibited in step['prohibited_actions']
    assert progress==initial_progress(plan,SCHEMA,PROGRESS_ID,plan['created_at']) and progress['progress_digest']==PROGRESS_DIGEST
    state=progress['step_states'][0]
    assert progress['overall_state']=='NOT_STARTED' and state['authorization_state']=='PENDING' and state['authorization_consumed'] is False
    assert state['execution_state']=='NOT_STARTED' and state['verification_state']=='NOT_STARTED' and state['evidence']==[] and state['binding_assertions']==[]
    assert not APPROVAL.exists()
    rendered=RESOURCE.read_text()+PLAN.read_text()+PROGRESS.read_text()
    for forbidden in ('postgresql://','password=','op://'): assert forbidden not in rendered
    print('DEVELOPMENT Render DATA secret-binding correction verification v1: PASS (read-only exact service/env-group scope; v2 drift bound; no mutation/deploy/secret reveal authority)')
    return 0
if __name__=='__main__': raise SystemExit(main())
