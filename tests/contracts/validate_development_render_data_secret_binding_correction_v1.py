#!/usr/bin/env python3
"""Validate read-only corrective verification for DEVELOPMENT Render DATA secret binding."""
from __future__ import annotations
import hashlib, json, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'src'))
from avuhz_engineering.authorization_plan import approval_digest, initial_progress, plan_digest, validate_approval, validate_plan, validate_progress
from avuhz_runtime.implementation_handoff import canonical_digest
BASE=ROOT/'contracts/plans/v1'; SCHEMA=ROOT/'contracts/schemas/v1'
PLAN=BASE/'development-render-data-secret-binding-correction-v1.plan.json'
PROGRESS=BASE/'development-render-data-secret-binding-correction-v1.progress.json'
RESOURCE=BASE/'development-render-data-secret-binding-correction-v1.resource.json'
APPROVAL=BASE/'development-render-data-secret-binding-correction-v1.approval.json'
EXECUTION=BASE/'development-render-data-secret-binding-correction-v1.execution-progress.json'
SUCCESS=BASE/'development-render-data-secret-binding-correction-v1-success.evidence.json'
V2_FAILURE=BASE/'development-render-data-secret-binding-v2-failure.evidence.json'
V2_EXEC=BASE/'development-render-data-secret-binding-v2.execution-progress.json'
PLAN_ID='7c9de2be-fb23-4d5c-8f5a-fc40b1d2276d'
PROGRESS_ID='34c8bfef-a1c5-4141-9e1f-8a6c8a4b7f46'
RESOURCE_DIGEST='sha256:4afe7d5ccda59e861f7542d8762d90bf0bf179d592f06d389ce928be5cd2f4dd'
PLAN_DIGEST='sha256:8a4360bcb195c8481940fea1f7f90c8d8c341a8c7fd910c81ca19902ef49ad24'
PROGRESS_DIGEST='sha256:2f5c6752a42e471a750060c0ac0f90a5688fd67e4da2e5ec538f2cc81a6c8aae'
V2_FAILURE_DIGEST='sha256:276c0dcd8fff4ac1281a011b8555877ca5c20991aab234406454d5b28cd2674f'
V2_PROGRESS_DIGEST='sha256:0e0030941489fddeed94d1cb7149f61cfbb8c7cb4183a96f5cbc233bfb45c8ab'
STEP_ID='development.render.data-secret-binding-correction-v1.step.01.verify-final-state'
APPROVAL_ID='cd8c764b-9f9e-40c1-ab62-b7ac2f28b11a'
APPROVAL_DIGEST='sha256:7f2979b1c93d5473481d8746ef3dc1c8ac2aa1e3249e88f262a01e631657a9f2'
APPROVED_AT='2026-10-01T14:21:39Z'
EXECUTION_PROGRESS_DIGEST='sha256:3332d49e5ff1dfba01fd5e71ba0b7e81914a42de59dcb7d32bc09a73026f795f'
SUCCESS_EVIDENCE_DIGEST='sha256:b63c47ed92d1dcbbffefba9dbb395591c16be2bfc2d8048b71edceb724993464'
PREFLIGHT_DIGEST='sha256:7077f4a54b45011c3b956926c959186b11dc8817e38c62297bee024a1c90e5bb'
RESULT_DIGEST='sha256:b46d5df390a7a316ad7f60f64b99f65125da64bd8efcaef550619cd87f4e88d3'
def load(p): return json.loads(p.read_text())
def raw(p): return 'sha256:'+hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    plan=load(PLAN); progress=load(PROGRESS); resource=load(RESOURCE); approval=load(APPROVAL); execution=load(EXECUTION); success=load(SUCCESS); failure=load(V2_FAILURE); v2x=load(V2_EXEC)
    validate_plan(plan,SCHEMA); validate_progress(plan,progress,SCHEMA); validate_progress(plan,execution,SCHEMA); validate_approval(plan,approval,SCHEMA,plan['authorization_window']['starts_at'])
    assert plan['plan_id']==PLAN_ID and plan['plan_version']==1 and plan['plan_digest']==PLAN_DIGEST==plan_digest(plan)
    assert plan['definition_status']=='READY_FOR_APPROVAL' and plan['environment']=='DEVELOPMENT'
    assert plan['target']=={'provider_class':'runtime.provider','provider_reference':'render','project_reference':'srv-dab9n4qd0e5s73dq37mg','responsibility':'RUNTIME','issuer_reference':None,'audience_reference':None}
    assert plan['authorization_window']=={'binding_state':'BOUND','starts_at':'2026-10-01T14:45:00Z','expires_at':'2026-10-01T18:45:00Z'}
    assert plan['authority_effect']=='NONE_UNTIL_SEPARATELY_APPROVED'
    assert plan['ordered_step_ids']==[STEP_ID]
    step=plan['steps'][0]
    assert step['execution_class']=='PROVIDER_READ'
    assert step['operation']=='provider.render.environment-configuration.verify-owner-interactive'
    assert step['resource']['exact_digest']==RESOURCE_DIGEST==canonical_digest(resource)
    assert resource['service_reference']=='srv-dab9n4qd0e5s73dq37mg'
    assert resource['service_environment_key']=='AVUHZ_POSTGRES_DSN'
    assert resource['duplicate_environment_group_name']=='AVUHZ_POSTGRES'
    assert resource['service_level_key_presence_expected'] is True
    assert resource['duplicate_environment_group_key_presence_expected'] is False
    assert resource['secret_value_must_remain_unobserved'] is True
    assert resource['provider_mutation_authorized'] is False and resource['deployment_authorized'] is False
    assert step['credential_policy']=={'permitted':True,'allowed_classes':['OWNER_INTERACTIVE_SESSION'],'values_stored':False}
    for prohibited in ('provider.mutation','environment-variable.create','environment-variable.delete','environment-variable.modify','environment-group.modify','render.deploy','deployment.trigger','secret.agent-visible','secret.digest','secret.return'):
        assert prohibited in step['prohibited_actions'] and prohibited in plan['prohibited_actions']
    req={x['evidence_type']:x['exact_digest'] for x in step['required_evidence']}
    assert req=={'runtime.render.data-secret-binding.applied':V2_FAILURE_DIGEST,'authorization-plan.execution-progress':V2_PROGRESS_DIGEST}
    assert raw(V2_FAILURE)==V2_FAILURE_DIGEST
    assert failure['safe_error_code']=='RENDER_ENVIRONMENT_SCOPE_DRIFT'
    assert v2x['progress_digest']==V2_PROGRESS_DIGEST and v2x['overall_state']=='STOPPED'
    assert progress==initial_progress(plan,SCHEMA,PROGRESS_ID,plan['created_at'])
    assert progress['progress_digest']==PROGRESS_DIGEST and progress['overall_state']=='NOT_STARTED'
    s=progress['step_states'][0]
    assert s['authorization_state']=='PENDING' and s['execution_state']=='NOT_STARTED' and s['verification_state']=='NOT_STARTED' and s['authorization_consumed'] is False
    assert approval=={'approval_id':APPROVAL_ID,'plan_id':PLAN_ID,'plan_version':1,'plan_digest':PLAN_DIGEST,'owner_identity':'github:AnonymousKoo','decision':'APPROVE','environment':'DEVELOPMENT','effective_at':'2026-10-01T14:45:00Z','expires_at':'2026-10-01T18:45:00Z','approved_at':APPROVED_AT,'status':'ACTIVE','authority_scope':'EXACT_PLAN_ONLY','approval_digest':APPROVAL_DIGEST}
    assert approval['approval_digest']==APPROVAL_DIGEST==approval_digest(approval)
    assert execution['progress_digest']==EXECUTION_PROGRESS_DIGEST and execution['overall_state']=='COMPLETED' and execution['record_version']==3
    sx=execution['step_states'][0]
    assert sx['authorization_state']=='CONSUMED' and sx['authorization_consumed'] is True
    assert sx['execution_state']=='SUCCEEDED' and sx['verification_state']=='PASS' and sx['safe_error_code'] is None
    assert sx['observed_postcondition']==step['expected_postcondition']
    assert len(sx['evidence'])==1 and sx['evidence'][0]['evidence_type']=='runtime.render.data-secret-binding.corrective-state-verified'
    assert sx['evidence'][0]['evidence_digest']==SUCCESS_EVIDENCE_DIGEST
    assert len(sx['binding_assertions'])==2
    pre=[x for x in sx['binding_assertions'] if x['binding_id']=='binding.development.render.data-secret-binding-correction-v1.dashboard-session'][0]
    result=[x for x in sx['binding_assertions'] if x['binding_id']=='binding.development.render.data-secret-binding-correction-v1.result'][0]
    assert pre['evidence_digest']==PREFLIGHT_DIGEST and pre['value_digest']==PREFLIGHT_DIGEST
    assert result['evidence_digest']==SUCCESS_EVIDENCE_DIGEST and result['value_digest']==RESULT_DIGEST
    assert success['outcome']=='SUCCEEDED_VERIFIED' and success['classification']=='RENDER_DATA_SECRET_BINDING_CORRECTIVE_STATE_VERIFIED'
    assert success['owner_observation']['service_level_key_present'] is True
    assert success['owner_observation']['service_level_value_masked'] is True
    assert success['owner_observation']['secret_value_observed'] is False
    assert success['owner_observation']['duplicate_environment_group_key_absent'] is True
    assert success['provider_read_observation']['auto_deploy_off_verified'] is True
    assert success['provider_read_observation']['latest_live_deploy_unchanged_verified'] is True
    assert success['provider_read_observation']['provider_mutation_attempted'] is False
    assert success['provider_read_observation']['deployment_triggered'] is False
    assert success['verification_observation']['postcondition_verified'] is True
    assert success['security_state']['secret_material_recorded'] is False
    assert success['security_state']['secret_digest_recorded'] is False
    assert success['security_state']['provider_mutation_attempted'] is False
    assert success['security_state']['deployment_triggered'] is False
    assert raw(SUCCESS)==SUCCESS_EVIDENCE_DIGEST
    rendered=PLAN.read_text()+PROGRESS.read_text()+RESOURCE.read_text()+EXECUTION.read_text()+SUCCESS.read_text()
    for forbidden in ('postgresql://','password=','op://'): assert forbidden not in rendered
    print('DEVELOPMENT Render DATA secret-binding correction v1: PASS (COMPLETED/SUCCEEDED/PASS; service key owner-confirmed masked; duplicate group key absent; no deploy/mutation/secret observation)')
    return 0
if __name__=='__main__': raise SystemExit(main())
