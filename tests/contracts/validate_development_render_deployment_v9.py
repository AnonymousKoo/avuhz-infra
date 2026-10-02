#!/usr/bin/env python3
from __future__ import annotations
import hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; sys.path.insert(0,str(ROOT/'src'))
from avuhz_engineering.authorization_plan import initial_progress,plan_digest,validate_plan,validate_progress
from avuhz_runtime.implementation_handoff import canonical_digest
B=ROOT/'contracts/plans/v1'; S=ROOT/'contracts/schemas/v1'; N='development-render-deployment-v9'
RESOURCE_DIGEST='sha256:6af1b729ac5b0b8dfcd3dab7137705907c2c3d2a3792ac0a9c539eca1f4b20cb'
PLAN_ID='43a909c1-69ca-404d-af78-00f0a95433b9'; PLAN_DIGEST='sha256:29dcfed8c41ac1d1806055ccf6b9b40c64832e5f48bbdb3ce7891c4360d012ba'
PROGRESS_ID='42d7abc0-912a-42a3-979f-044e081601f9'; PROGRESS_DIGEST='sha256:13e90f432f6cc205bc0063438725784bfa0ebfd190970867ba681daa87c02e10'
V8_STEP1='sha256:b600e6020d02a99b57ef999c7c7e58927c014fce59ba5506a2e98019c7d24494'
V8_STEP2='sha256:20333eb7c7298b494c551144c575d0a1e9c9eee4fac7ecc6d73cfea4d26f5598'
V8_PROGRESS='sha256:a71d84f748a22f7fc2b01803951d4edc8a0eda47bddaf0c4609192d28d098124'
DATA_EVIDENCE='sha256:358b0a3026cf680ee622efdb30c981936683566534eccdf00a0665380f265526'
HANDOFF_COMMIT='a40e41e254f1d106d80189bb6b0e4be44f2a85bc'
def load(n): return json.load(open(B/n))
def raw(n): return 'sha256:'+hashlib.sha256((B/n).read_bytes()).hexdigest()
def main():
 r=load(N+'.resource.json'); p=load(N+'.plan.json'); g=load(N+'.progress.json'); v8=load('development-render-deployment-v8.execution-progress.json'); data=load('development-data-implementation-handoff-intake-v1-success.evidence.json')
 validate_plan(p,S); validate_progress(p,g,S)
 assert not (B/(N+'.approval.json')).exists()
 assert r['contract_digest']==RESOURCE_DIGEST==canonical_digest({k:v for k,v in r.items() if k!='contract_digest'})
 assert r['contract_version']=='v9' and r['environment']=='DEVELOPMENT' and r['provider']=='render'
 assert r['workspace_id']=='tea-dab95hv40ujc73a7ccag' and r['service_id']=='srv-dab9n4qd0e5s73dq37mg' and r['service_name']=='avuhz-command-dev'
 assert r['environment_id']=='evm-dab96l2jobas73bp95bg' and r['repo']=='AnonymousKoo/avuhz-infra' and r['branch']=='main'
 assert r['branch_protection_required']=={'required_status_checks':['main-pr-gate'],'enforce_admins':True,'pull_request_review_rule_present':True,'required_approving_review_count':0}
 assert r['auto_deploy_expected']=='no' and r['auto_deploy_trigger_expected']=='off'
 assert r['current_live_deploy_id']=='dep-db01n2navr4c73dq8700' and r['current_live_commit']=='b4cd44412e6ab02c5f7f9f7ac6eeeb7c72db2f5c'
 assert r['manual_deploy_count_authorized']==1 and r['clear_cache_authorized'] is False and r['deployment_head_binding']=='RESOLVED_BY_STEP_PREFLIGHT'
 assert r['required_implementation_handoff_runtime_commit']==HANDOFF_COMMIT and r['implementation_handoff_runtime_requirement']=='ANCESTOR_OF_EXECUTION_MAIN'
 assert raw('development-render-deployment-v8-step01-success.evidence.json')==r['source_v8_step1_deployment_success_evidence_digest']==V8_STEP1
 assert raw('development-render-deployment-v8-step02-success.evidence.json')==r['source_v8_step2_runtime_success_evidence_digest']==V8_STEP2
 assert v8['overall_state']=='COMPLETED' and v8['progress_digest']==r['source_v8_progress_digest']==V8_PROGRESS
 assert all(x['execution_state']=='SUCCEEDED' and x['verification_state']=='PASS' and x['authorization_consumed'] for x in v8['step_states'])
 assert raw('development-data-implementation-handoff-intake-v1-success.evidence.json')==r['required_data_implementation_handoff_evidence_digest']==DATA_EVIDENCE
 assert data['outcome']=='SUCCEEDED_VERIFIED' and data['project_reference']=='gnuqaefotwgkwurjpyik'
 assert data['provider_observation']['accept_implementation_handoff_command_vocab_present'] is True
 assert data['provider_observation']['security_advisor_finding_count']==0
 assert r['post_deploy_expected']=={'startup_http':200,'liveness_http':200,'readiness_http':200,'configuration':'ready','identity':'ready','data':'ready','unauthenticated_commands_http':401,'unauthenticated_queries_http':401,'unauthenticated_implementation_handoff_http':401,'unauthenticated_error':'trusted_identity_required','second_deploy_detected':False}
 assert r['implementation_handoff_execution_authorized'] is False and r['trusted_identity_policy_changes_authorized']==0
 for k in ('environment_variable_changes_authorized','environment_group_changes_authorized','service_setting_changes_authorized','github_visibility_changes_authorized','github_branch_protection_changes_authorized'): assert r[k]==0
 assert r['secret_material_agent_visible'] is False and r['supabase_operation_authorized'] is False and r['n8n_operation_authorized'] is False and r['staging_authorized'] is False and r['production_authorized'] is False
 assert p['plan_id']==PLAN_ID and p['plan_version']==9 and p['plan_digest']==PLAN_DIGEST==plan_digest(p)
 assert p['definition_status']=='READY_FOR_APPROVAL' and p['environment']=='DEVELOPMENT' and p['authority_effect']=='NONE_UNTIL_SEPARATELY_APPROVED'
 assert p['authorization_window']=={'binding_state':'BOUND','starts_at':'2026-10-02T23:00:00Z','expires_at':'2026-10-03T03:00:00Z'}
 assert len(p['steps'])==2 and p['ordered_step_ids']==[x['step_id'] for x in p['steps']]
 s1,s2=p['steps']; assert s1['operation']=='provider.render.deploy.trigger-manual-latest-main' and s1['execution_class']=='PROVIDER_MUTATION'
 assert s1['resource']=={'resource_type':'render.service.deployment','resource_reference':'render:srv-dab9n4qd0e5s73dq37mg:deployment','binding_state':'BOUND','exact_version':'render.manual-implementation-handoff-canonical-main.v9','exact_digest':RESOURCE_DIGEST}
 assert s1['required_evidence']==[
  {'evidence_type':'runtime.render.deployment.completed','source_step_id':None,'binding_state':'BOUND','exact_digest':V8_STEP1},
  {'evidence_type':'runtime.render.post-deploy-runtime.verified','source_step_id':None,'binding_state':'BOUND','exact_digest':V8_STEP2},
  {'evidence_type':'authorization-plan.execution-progress','source_step_id':None,'binding_state':'BOUND','exact_digest':V8_PROGRESS},
  {'evidence_type':'data.implementation-handoff-intake.migrated','source_step_id':None,'binding_state':'BOUND','exact_digest':DATA_EVIDENCE},
 ]
 b={x['binding_id']:x for x in s1['binding_declarations']}
 assert b['binding.development.render.deployment-v9.v8-step1']['preapproval_value']['value']==V8_STEP1
 assert b['binding.development.render.deployment-v9.v8-step2']['preapproval_value']['value']==V8_STEP2
 assert b['binding.development.render.deployment-v9.v8-progress']['preapproval_value']['value']==V8_PROGRESS
 assert b['binding.development.render.deployment-v9.data-handoff-evidence']['preapproval_value']['value']==DATA_EVIDENCE
 assert b['binding.development.render.deployment-v9.implementation-handoff-runtime']['preapproval_value']['value']=='git.commit.'+HANDOFF_COMMIT
 assert b['binding.development.render.deployment-v9.canonical-main-head']['phase']=='RESOLVED_BY_STEP_PREFLIGHT'
 assert b['binding.development.render.deployment-v9.result']['phase']=='PRODUCED_BY_CURRENT_STEP'
 for x in ('implementation-handoff-runtime.not-ancestor-of-main','data-implementation-handoff-evidence.mismatch','current-live-deploy.mismatch','v8-outcome.mismatch','deployment.commit-mismatch'): assert x in s1['stop_conditions']
 assert len(s1['stop_conditions'])<=16
 assert s2['operation']=='provider.render.verify-post-deploy-runtime-use' and s2['execution_class']=='PROVIDER_READ'
 assert s2['dependency_step_ids']==[s1['step_id']] and s2['credential_policy']=={'permitted':False,'allowed_classes':['NONE'],'values_stored':False}
 assert s2['required_evidence']==[{'evidence_type':'runtime.render.deployment.completed','source_step_id':s1['step_id'],'binding_state':'DERIVED_FROM_SOURCE_STEP','exact_digest':None}]
 for x in ('readiness.not-200','readiness.data-not-ready','commands.anonymous-not-401','queries.anonymous-not-401','implementation-handoff.anonymous-not-401','second-deploy.detected'): assert x in s2['stop_conditions']
 assert g==initial_progress(p,S,PROGRESS_ID,p['created_at']) and g['progress_digest']==PROGRESS_DIGEST and g['overall_state']=='NOT_STARTED'
 assert all(st['authorization_state']=='PENDING' and st['execution_state']=='NOT_STARTED' and st['authorization_consumed'] is False for st in g['step_states'])
 rendered=(B/(N+'.resource.json')).read_text()+(B/(N+'.plan.json')).read_text()+(B/(N+'.progress.json')).read_text()
 for forbidden in ('postgresql://','postgres://','password=','op://'): assert forbidden not in rendered
 print('DEVELOPMENT Render deployment v9: PASS (READY_FOR_APPROVAL; v8 COMPLETED + DATA handoff migration bound; one deploy + read-only handoff-aware runtime verification; no identity change/handoff execution)')
 return 0
if __name__=='__main__': raise SystemExit(main())
