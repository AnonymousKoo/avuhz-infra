#!/usr/bin/env python3
"""Validate prepared DEVELOPMENT Render Supavisor session DSN correction v2."""
from __future__ import annotations
import json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'src'))
from avuhz_engineering.authorization_plan import approval_digest,initial_progress,plan_digest,validate_approval,validate_plan,validate_progress
from avuhz_runtime.implementation_handoff import canonical_digest
B=ROOT/'contracts/plans/v1'; S=ROOT/'contracts/schemas/v1'
NAME='development-render-data-supavisor-session-dsn-v2'
RESOURCE=B/f'{NAME}.resource.json'; PLAN=B/f'{NAME}.plan.json'; PROGRESS=B/f'{NAME}.progress.json'; APPROVAL=B/f'{NAME}.approval.json'
CATALOG=B/'development-data-catalog-rls-validation-v1.execution-progress.json'
SECRET=B/'development-render-data-secret-binding-correction-v1.execution-progress.json'
DEPLOY=B/'development-render-deployment-v3.execution-progress.json'
RESOURCE_DIGEST='sha256:c80ae29ae18937d06f8971f92b41ae752eaa089f6f9f912e8e402ae4a954b55e'
PLAN_ID='862d1756-bee5-48a1-8420-c2a88d032f5d'
PLAN_DIGEST='sha256:67679547732c6a0a90aae13958ce67130a1ca2cc0383fe78589a9cf3de7e3072'
PROGRESS_ID='57403053-deb7-41b1-b743-2be6f7c3e517'
PROGRESS_DIGEST='sha256:2a85be21e39dbaa862beb117d65fa6a71c9e0e2f264bde7bce0e92c0868abc26'
def load(p): return json.loads(p.read_text())
def main():
 r=load(RESOURCE); p=load(PLAN); g=load(PROGRESS); a=load(APPROVAL); cat=load(CATALOG); sec=load(SECRET); dep=load(DEPLOY)
 validate_plan(p,S); validate_progress(p,g,S); validate_approval(p,a,S,p['authorization_window']['starts_at'])
 assert r['contract_digest']==RESOURCE_DIGEST==canonical_digest({k:v for k,v in r.items() if k!='contract_digest'})
 assert r['contract_version']=='v2' and r['supersedes_v1']['progress_state']=='NOT_STARTED'
 assert r['environment']=='DEVELOPMENT' and r['provider']=='render'
 assert r['workspace_id']=='tea-dab95hv40ujc73a7ccag'
 assert r['service_id']=='srv-dab9n4qd0e5s73dq37mg' and r['service_name']=='avuhz-command-dev'
 assert r['environment_id']=='evm-dab96l2jobas73bp95bg' and r['service_environment_key']=='AVUHZ_POSTGRES_DSN'
 assert r['provider_surface']=='RENDER_DASHBOARD_ENVIRONMENT_SAVE_ONLY' and r['provider_action']=='SAVE_ONLY'
 assert r['single_key_per_save'] is True and r['connected_update_environment_variables_wrapper_allowed'] is False
 assert r['deployment_side_effect_allowed'] is False and r['deployment_authorized'] is False
 assert r['auto_deploy_expected']=='no' and r['auto_deploy_trigger_expected']=='off'
 assert r['current_live_deploy_id']=='dep-davkk6egekts73eefa40'
 assert r['current_live_commit']=='43a9e1ccec2c1a2fd3eee530dd817981303caaba'
 assert r['canonical_main_support_commit']=='e85426bccd646c8f4c9c3ccaac90a2c1a632d3db'
 assert r['canonical_main_support_requirement']=='ANCESTOR_OF_EXECUTION_MAIN'
 assert r['data_project_ref']=='gnuqaefotwgkwurjpyik' and r['runtime_login']=='avuhz_data_runtime_service_dev'
 assert r['pooler_mode']=='SESSION' and r['pooler_host']=='aws-1-us-west-2.pooler.supabase.com' and r['pooler_port']==5432
 assert r['pooler_database']=='postgres' and r['pooler_username']=='avuhz_data_runtime_service_dev.gnuqaefotwgkwurjpyik'
 assert r['sslmode']=='require' and r['password_source']=='OWNER_CONTROLLED_APPROVED_VAULT'
 assert r['secret_value_must_remain_unobserved'] is True and r['secret_value_digest_prohibited'] is True
 assert r['environment_variable_changes_authorized']==1 and r['environment_group_changes_authorized']==0 and r['service_setting_changes_authorized']==0
 assert r['supabase_operation_authorized'] is False and r['n8n_operation_authorized'] is False and r['staging_authorized'] is False and r['production_authorized'] is False
 assert r['source_catalog_progress_digest']==cat['progress_digest']=='sha256:853f5cd3c6988c3e7dcccaf9b4272f7a60e7563cfb55e998ae2ab7ce01c56d45'
 assert r['source_secret_binding_progress_digest']==sec['progress_digest']=='sha256:3332d49e5ff1dfba01fd5e71ba0b7e81914a42de59dcb7d32bc09a73026f795f'
 assert r['source_deployment_progress_digest']==dep['progress_digest']=='sha256:1f628b63d94f127877ee6b96d31e1d66134a3c8ea7dd6eb31fc69da1c0b31e1a'
 assert cat['overall_state']==sec['overall_state']==dep['overall_state']=='COMPLETED'
 assert cat['step_states'][0]['evidence'][0]['evidence_digest']==r['source_catalog_success_evidence_digest']
 assert sec['step_states'][0]['evidence'][0]['evidence_digest']==r['source_secret_binding_success_evidence_digest']
 assert dep['step_states'][0]['evidence'][0]['evidence_digest']==r['source_deployment_success_evidence_digest']
 assert p['plan_id']==PLAN_ID and p['plan_version']==2 and p['plan_digest']==PLAN_DIGEST==plan_digest(p)
 assert p['definition_status']=='READY_FOR_APPROVAL' and p['environment']=='DEVELOPMENT'
 assert p['authorization_window']=={'binding_state':'BOUND','starts_at':'2026-10-02T13:20:00Z','expires_at':'2026-10-02T17:20:00Z'}
 assert p['authority_effect']=='NONE_UNTIL_SEPARATELY_APPROVED' and len(p['steps'])==1
 st=p['steps'][0]
 assert st['step_id']=='development.render.data-supavisor-session-dsn-v2.step.01.replace-avuhz-postgres-dsn-save-only'
 assert st['operation']=='provider.render.dashboard.environment-variable.save-only-single-secret-exact'
 assert st['execution_class']=='PROVIDER_MUTATION'
 assert st['resource']=={'resource_type':'render.service.environment-variable','resource_reference':'render:srv-dab9n4qd0e5s73dq37mg:env:AVUHZ_POSTGRES_DSN','binding_state':'BOUND','exact_version':'render.dashboard-save-only.secret-supavisor-session-dsn.v2','exact_digest':RESOURCE_DIGEST}
 assert st['credential_policy']=={'permitted':True,'allowed_classes':['OWNER_INTERACTIVE_SESSION'],'values_stored':False}
 assert len(st['required_evidence'])==7
 for item in ('connected-render-update-environment-variables-wrapper.use','deployment.trigger','environment-variable.batch-update','environment-variable.other.modify','environment-variable.replace-all','secret.agent-visible','secret.digest','secret.log','secret.return','supabase.operation','n8n.operation','staging.target','production.target'):
  assert item in st['prohibited_actions']
 for item in ('dashboard.save-only-option.missing','deployment.detected','owner-vault-runtime-credential.unavailable','secret-exposure.required','support-commit.not-ancestor-of-main'):
  assert item in st['stop_conditions']
 decl={x['binding_id']:x for x in st['binding_declarations']}
 assert decl['binding.development.render.data-supavisor-session-dsn-v2.pooler-host']['preapproval_value']['value']=='aws-1-us-west-2.pooler.supabase.com'
 assert decl['binding.development.render.data-supavisor-session-dsn-v2.pooler-username']['preapproval_value']['value']=='avuhz_data_runtime_service_dev.gnuqaefotwgkwurjpyik'
 assert decl['binding.development.render.data-supavisor-session-dsn-v2.owner-vault-runtime-credential']['phase']=='RESOLVED_BY_STEP_PREFLIGHT'
 assert decl['binding.development.render.data-supavisor-session-dsn-v2.result']['evidence_type']=='runtime.render.data-supavisor-session-dsn.bound'
 assert g==initial_progress(p,S,PROGRESS_ID,p['created_at']) and g['progress_digest']==PROGRESS_DIGEST
 assert a['plan_id']==p['plan_id'] and a['plan_version']==2 and a['plan_digest']==p['plan_digest']
 assert a['owner_identity']=='github:AnonymousKoo' and a['decision']=='APPROVE' and a['environment']=='DEVELOPMENT'
 assert a['effective_at']=='2026-10-02T13:20:00Z' and a['expires_at']=='2026-10-02T17:20:00Z'
 assert a['approved_at']=='2026-10-02T13:07:05Z' and a['status']=='ACTIVE' and a['authority_scope']=='EXACT_PLAN_ONLY'
 assert a['approval_digest']==approval_digest(a)
 assert g['overall_state']=='NOT_STARTED' and g['step_states'][0]['authorization_state']=='PENDING' and g['step_states'][0]['execution_state']=='NOT_STARTED' and g['step_states'][0]['authorization_consumed'] is False
 rendered=RESOURCE.read_text()+PLAN.read_text()+PROGRESS.read_text()+APPROVAL.read_text()
 for forbidden in ('postgresql://','postgres://','password=','op://'): assert forbidden not in rendered
 print('DEVELOPMENT Render Supavisor session DSN v2: PASS (APPROVED; forward-only v2; one secret key; Dashboard Save only; exact IPv4 session pooler; no deployment/API wrapper/secret exposure)')
 return 0
if __name__=='__main__': raise SystemExit(main())
