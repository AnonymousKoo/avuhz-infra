#!/usr/bin/env python3
"""Validate DEVELOPMENT Render non-secret runtime configuration repair v1."""
from __future__ import annotations
import hashlib, json, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'src'))
from avuhz_engineering.authorization_plan import approval_digest, initial_progress, plan_digest, validate_approval, validate_plan, validate_progress
from avuhz_runtime.implementation_handoff import canonical_digest
from avuhz_service import development as development_config
BASE=ROOT/'contracts/plans/v1'; SCHEMA=ROOT/'contracts/schemas/v1'
RESOURCE=BASE/'development-render-runtime-config-repair-v1.resource.json'
PLAN=BASE/'development-render-runtime-config-repair-v1.plan.json'
PROGRESS=BASE/'development-render-runtime-config-repair-v1.progress.json'
APPROVAL=BASE/'development-render-runtime-config-repair-v1.approval.json'
STOP=BASE/'development-render-runtime-config-repair-v1-stop.evidence.json'
EXECUTION=BASE/'development-render-runtime-config-repair-v1.execution-progress.json'
FAILURE=BASE/'development-render-deployment-v1-failure.evidence.json'
FAILURE_EXEC=BASE/'development-render-deployment-v1.execution-progress.json'
SOURCE=ROOT/'src/avuhz_service/development.py'
SOURCE_DIGEST='sha256:7e55968e667a566e2a82f9dc8b90c4e3f7ec4d69b4c0c49adc0db2994f94f972'
RESOURCE_DIGEST='sha256:ef9db4f8ee18c4861df44febda39bdbc2d30d328063241487e4ed62581eebde7'
PLAN_ID='0e5d2dc6-d0c0-4e49-bfb1-c47d9629986d'
PLAN_DIGEST='sha256:de24909e3a096dbfe7912c77849f8a353a9613a8d702554a565ce00e2bf6e3a8'
PROGRESS_ID='0b93b675-b1fe-4c86-9950-5389a21a5769'
PROGRESS_DIGEST='sha256:7eec8aba140c85164e112475d28385b88b8a45b5ef66716c64df5a3a558b44eb'
FAILURE_DIGEST='sha256:27b6c2825e43edcc17cfbe628c7f44f42c580727a2ded442ac722f04a2b8d186'
FAILURE_PROGRESS_DIGEST='sha256:4f70e9c95518844760d57d0ed6d7d89cd56ecaf5bd0a79dd355f4aa1d1f7ee15'
APPROVAL_ID='d8b5b5f2-0dba-40fc-970b-4e3a1f5de9e5'
APPROVAL_DIGEST='sha256:032e4f7fd01f07b2634fe0398b95f1a3502a197636eff07a706f2a8522352bb8'
APPROVED_AT='2026-10-01T16:51:18Z'
EXPECTED=[
 ('AVUHZ_SERVICE_ENVIRONMENT','DEVELOPMENT','DEVELOPMENT_ENVIRONMENT','sha256:0b670a3e1c67e120bd6ff3f31b081fc93b78a5eaf01bc7be071b23c048e6647b'),
 ('AVUHZ_DATA_PROJECT_REF','gnuqaefotwgkwurjpyik','DEVELOPMENT_DATA_PROJECT_REF','sha256:9855d6f60015e0d08d73e728c5e8997ae13b9f02791fe932b219abc685005179'),
 ('AVUHZ_DATA_PROJECT_URL','https://gnuqaefotwgkwurjpyik.supabase.co','DEVELOPMENT_DATA_PROJECT_URL','sha256:c78afdc6b95586a278c9964646083e1cf2a09a12c956a64716904ecd68831de5'),
 ('AVUHZ_AUTH_PROJECT_REF','pwlhruwutoitnieactol','DEVELOPMENT_AUTH_PROJECT_REF','sha256:f4d33e38f87fa126efac7a951e29670c6db7008096e23851945e30f425a21d81'),
 ('AVUHZ_AUTH_ISSUER','https://pwlhruwutoitnieactol.supabase.co/auth/v1','DEVELOPMENT_AUTH_ISSUER','sha256:547dc7c47a61515eb7563dfb7e788ffc45a38b82fe77f72cb7dea691b84523cd'),
 ('AVUHZ_SERVICE_AUDIENCE','audience.avuhz.command-service.development','DEVELOPMENT_SERVICE_AUDIENCE','sha256:2112e2df245a35003c13ecaf99d21017ab37946e9f7e2a4e89df83ffabfa401d'),
 ('AVUHZ_TENANT_BRIDGE','TrustedExecutionContext.tenant_id -> avuhz.tenant_id','DEVELOPMENT_TENANT_BRIDGE','sha256:b58193aa77ed71603ee63e568c24ba73d4b7bc005eb61f195815c468b05c6a25'),
 ('AVUHZ_RLS_POLICY_REFERENCE','policy.avuhz.tenant-rls.development.v1','DEVELOPMENT_RLS_POLICY_REFERENCE','sha256:aaf6e7b7735ee1a08649840ca857dca37e1d9120ba9501e1a5ad25f4cb256647'),
 ('AVUHZ_COMMAND_SERVICE_IDENTITY','avuhz_command_service_dev','DEVELOPMENT_COMMAND_SERVICE_IDENTITY','sha256:55ff95fbfef522d552e7c7497ce5d623a851cef44415ccff7340fb96b311104b'),
]
def load(p): return json.loads(p.read_text())
def file_digest(p): return 'sha256:'+hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    resource=load(RESOURCE); plan=load(PLAN); progress=load(PROGRESS); approval=load(APPROVAL); failure=load(FAILURE); failed_exec=load(FAILURE_EXEC); stop=load(STOP); execution=load(EXECUTION)
    validate_plan(plan,SCHEMA); validate_progress(plan,progress,SCHEMA); validate_approval(plan,approval,SCHEMA,plan['authorization_window']['starts_at'])
    # The provider plan immutably records the historical source digest that was
    # approved at execution time. Current source may evolve; the safety invariant
    # is that every authorized non-secret constant still has the exact same value.
    assert resource['source_contract']=={'path':'src/avuhz_service/development.py','file_digest':SOURCE_DIGEST}
    payload={k:v for k,v in resource.items() if k!='contract_digest'}
    assert resource['contract_digest']==RESOURCE_DIGEST==canonical_digest(payload)
    assert resource['environment']=='DEVELOPMENT' and resource['provider']=='render'
    assert resource['workspace_id']=='tea-dab95hv40ujc73a7ccag'
    assert resource['service_id']=='srv-dab9n4qd0e5s73dq37mg' and resource['service_name']=='avuhz-command-dev'
    assert resource['environment_id']=='evm-dab96l2jobas73bp95bg'
    assert resource['provider_managed_required_keys']==['PORT']
    assert resource['protected_existing_keys']==['AVUHZ_POSTGRES_DSN']
    policy=resource['mutation_policy']
    assert policy['allowed_environment_variable_changes']==9 and policy['single_key_per_provider_call'] is True
    assert policy['batched_provider_call_authorized'] is False and policy['replace_all_authorized'] is False
    assert policy['environment_group_changes_authorized'] is False and policy['service_setting_changes_authorized'] is False
    assert policy['auto_deploy_changes_authorized'] is False and policy['deployment_authorized'] is False
    assert policy['secret_material_agent_visible'] is False and policy['secret_material_persisted'] is False
    assert len(resource['variables'])==9
    for i,(entry, expected) in enumerate(zip(resource['variables'],EXPECTED),1):
        key,value,const,digest=expected
        assert entry['ordinal']==i and entry['key']==key and entry['value']==value and entry['source_constant']==const
        assert getattr(development_config, const)==value
        assert entry['value_class']=='NON_SECRET_CANONICAL_CONFIGURATION' and entry['update_mode']=='MERGE_SINGLE_KEY'
        assert entry['replace_all_environment_variables'] is False and entry['deploy_authorized'] is False
        core={k:v for k,v in entry.items() if k!='entry_digest'}
        assert entry['entry_digest']==digest==canonical_digest(core)
    assert failure['safe_error_code']=='RENDER_DEPLOYMENT_RUNTIME_CONFIGURATION_INVALID'
    assert failed_exec['progress_digest']==FAILURE_PROGRESS_DIGEST and failed_exec['overall_state']=='STOPPED'
    assert plan['plan_id']==PLAN_ID and plan['plan_version']==1 and plan['plan_digest']==PLAN_DIGEST==plan_digest(plan)
    assert plan['definition_status']=='READY_FOR_APPROVAL' and plan['environment']=='DEVELOPMENT'
    assert plan['target']=={'provider_class':'runtime.provider','provider_reference':'render','project_reference':'srv-dab9n4qd0e5s73dq37mg','responsibility':'RUNTIME','issuer_reference':None,'audience_reference':None}
    assert plan['authorization_window']=={'binding_state':'BOUND','starts_at':'2026-10-01T17:30:00Z','expires_at':'2026-10-01T21:30:00Z'}
    assert plan['authority_effect']=='NONE_UNTIL_SEPARATELY_APPROVED' and len(plan['steps'])==9
    assert plan['ordered_step_ids']==[s['step_id'] for s in plan['steps']]
    for i,(step,entry) in enumerate(zip(plan['steps'],resource['variables']),1):
        assert step['ordinal']==i and step['execution_class']=='PROVIDER_MUTATION'
        assert step['operation']=='provider.render.environment-variable.merge-single-nonsecret-exact'
        assert step['resource']=={'resource_type':'render.service.environment-variable','resource_reference':f'render:srv-dab9n4qd0e5s73dq37mg:env:{entry["key"]}','binding_state':'BOUND','exact_version':'render.nonsecret-runtime-config.v1','exact_digest':entry['entry_digest']}
        assert step['credential_policy']=={'permitted':True,'allowed_classes':['OWNER_INTERACTIVE_SESSION'],'values_stored':False}
        assert step['dependency_step_ids']==([] if i==1 else [plan['steps'][i-2]['step_id']])
        if i==1:
            assert step['required_evidence']==[
              {'evidence_type':'runtime.render.deployment.completed','source_step_id':None,'binding_state':'BOUND','exact_digest':FAILURE_DIGEST},
              {'evidence_type':'authorization-plan.execution-progress','source_step_id':None,'binding_state':'BOUND','exact_digest':FAILURE_PROGRESS_DIGEST}]
        else:
            assert step['required_evidence']==[{'evidence_type':'runtime.render.nonsecret-environment-variable.bound','source_step_id':plan['steps'][i-2]['step_id'],'binding_state':'DERIVED_FROM_SOURCE_STEP','exact_digest':None}]
        for prohibited in ('batch.mutation','deployment.trigger','environment-variable.batch-update','environment-variable.replace-all','environment-variable.secret.modify','environment-group.modify','port.modify','render.auto-deploy.modify','render.service-setting.modify','supabase.operation','n8n.operation','staging.target','production.target'):
            assert prohibited in step['prohibited_actions']
        assert len(step['produced_evidence'])==1 and step['produced_evidence'][0]['evidence_type']=='runtime.render.nonsecret-environment-variable.bound'
    assert progress==initial_progress(plan,SCHEMA,PROGRESS_ID,plan['created_at']) and progress['progress_digest']==PROGRESS_DIGEST
    assert progress['overall_state']=='NOT_STARTED' and len(progress['step_states'])==9
    for s in progress['step_states']:
        assert s['authorization_state']=='PENDING' and s['authorization_consumed'] is False
        assert s['execution_state']=='NOT_STARTED' and s['verification_state']=='NOT_STARTED'
        assert s['evidence']==[] and s['binding_assertions']==[] and s['safe_error_code'] is None
    assert approval=={'approval_id':APPROVAL_ID,'plan_id':PLAN_ID,'plan_version':1,'plan_digest':PLAN_DIGEST,'owner_identity':'github:AnonymousKoo','decision':'APPROVE','environment':'DEVELOPMENT','effective_at':'2026-10-01T17:30:00Z','expires_at':'2026-10-01T21:30:00Z','approved_at':APPROVED_AT,'status':'ACTIVE','authority_scope':'EXACT_PLAN_ONLY','approval_digest':APPROVAL_DIGEST}
    assert approval['approval_digest']==APPROVAL_DIGEST==approval_digest(approval)
    validate_progress(plan,execution,SCHEMA)
    assert execution['overall_state']=='STOPPED' and execution['record_version']==2
    first=execution['step_states'][0]
    assert first['authorization_state']=='CONSUMED' and first['authorization_consumed'] is True
    assert first['execution_state']=='FAILED' and first['verification_state']=='FAIL'
    assert first['safe_error_code']=='RENDER_ENVVAR_UPDATE_TRIGGERED_PROHIBITED_DEPLOYMENT'
    assert stop['classification']=='UNEXPECTED_PROVIDER_SIDE_EFFECT_DEPLOYMENT_TRIGGERED'
    assert stop['unexpected_deployment_observation']['deploy_id']=='dep-dav9iss1nsns73ar8eo0'
    assert stop['unexpected_deployment_observation']['status']=='update_failed'
    assert stop['post_stop_provider_state']['previous_deploy_remains_live'] is True
    assert stop['security_state']['protected_existing_key_read'] is False and stop['security_state']['protected_existing_key_modified'] is False
    assert stop['security_state']['port_modified'] is False and stop['security_state']['steps_2_through_9_attempted'] is False
    for later in execution['step_states'][1:]:
        assert later['authorization_state']=='BLOCKED' and later['authorization_consumed'] is False
        assert later['execution_state']=='NOT_STARTED' and later['verification_state']=='NOT_STARTED'
    rendered=RESOURCE.read_text()+PLAN.read_text()+PROGRESS.read_text()
    for forbidden in ('postgresql://','password=','op://'): assert forbidden not in rendered
    assert 'AVUHZ_POSTGRES_DSN' in rendered and 'PORT' in rendered
    print('DEVELOPMENT Render runtime config repair v1: PASS (STOPPED at step 1 after prohibited provider-triggered deploy; steps 2-9 blocked; prior live deploy preserved)')
    return 0
if __name__=='__main__': raise SystemExit(main())
