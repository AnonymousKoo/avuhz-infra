#!/usr/bin/env python3
"""Validate read-only corrective verification for DEVELOPMENT Render DATA secret binding."""
from __future__ import annotations
import hashlib, json, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'src'))
from avuhz_engineering.authorization_plan import initial_progress, plan_digest, validate_plan, validate_progress
from avuhz_runtime.implementation_handoff import canonical_digest
BASE=ROOT/'contracts/plans/v1'; SCHEMA=ROOT/'contracts/schemas/v1'
PLAN=BASE/'development-render-data-secret-binding-correction-v1.plan.json'
PROGRESS=BASE/'development-render-data-secret-binding-correction-v1.progress.json'
RESOURCE=BASE/'development-render-data-secret-binding-correction-v1.resource.json'
APPROVAL=BASE/'development-render-data-secret-binding-correction-v1.approval.json'
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
def load(p): return json.loads(p.read_text())
def raw(p): return 'sha256:'+hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    plan=load(PLAN); progress=load(PROGRESS); resource=load(RESOURCE); failure=load(V2_FAILURE); v2x=load(V2_EXEC)
    validate_plan(plan,SCHEMA); validate_progress(plan,progress,SCHEMA)
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
    assert not APPROVAL.exists()
    rendered=PLAN.read_text()+PROGRESS.read_text()+RESOURCE.read_text()
    for forbidden in ('postgresql://','password=','op://'): assert forbidden not in rendered
    print('DEVELOPMENT Render DATA secret-binding correction v1: PASS (read-only final-state verification; v2 scope drift bound; no mutation/deploy/secret observation authority)')
    return 0
if __name__=='__main__': raise SystemExit(main())
