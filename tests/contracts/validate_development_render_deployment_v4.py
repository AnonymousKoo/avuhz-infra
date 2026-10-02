#!/usr/bin/env python3
from __future__ import annotations
import json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; sys.path.insert(0,str(ROOT/'src'))
from avuhz_engineering.authorization_plan import initial_progress,plan_digest,validate_plan,validate_progress
from avuhz_runtime.implementation_handoff import canonical_digest
B=ROOT/'contracts/plans/v1'; S=ROOT/'contracts/schemas/v1'; N='development-render-deployment-v4'
def load(p): return json.loads(p.read_text())
def main():
 r=load(B/f'{N}.resource.json'); p=load(B/f'{N}.plan.json'); g=load(B/f'{N}.progress.json')
 dsn=load(B/'development-render-data-supavisor-session-dsn-v2-success.evidence.json'); dsnx=load(B/'development-render-data-supavisor-session-dsn-v2.execution-progress.json')
 d3=load(B/'development-render-deployment-v3-success.evidence.json'); d3x=load(B/'development-render-deployment-v3.execution-progress.json')
 validate_plan(p,S); validate_progress(p,g,S)
 assert r['contract_digest']==canonical_digest({k:v for k,v in r.items() if k!='contract_digest'})
 assert r['contract_version']=='v4' and r['environment']=='DEVELOPMENT' and r['provider']=='render'
 assert r['workspace_id']=='tea-dab95hv40ujc73a7ccag' and r['service_id']=='srv-dab9n4qd0e5s73dq37mg' and r['service_name']=='avuhz-command-dev'
 assert r['environment_id']=='evm-dab96l2jobas73bp95bg' and r['repo']=='AnonymousKoo/avuhz-infra' and r['repo_visibility_expected']=='public' and r['branch']=='main'
 assert r['branch_protection_required']=={'required_status_checks':['main-pr-gate'],'enforce_admins':True,'pull_request_review_rule_present':True,'required_approving_review_count':0}
 assert r['auto_deploy_expected']=='no' and r['auto_deploy_trigger_expected']=='off'
 assert r['current_live_deploy_id']=='dep-davkk6egekts73eefa40' and r['current_live_commit']=='43a9e1ccec2c1a2fd3eee530dd817981303caaba'
 assert r['manual_deploy_count_authorized']==1 and r['clear_cache_authorized'] is False and r['deployment_head_binding']=='RESOLVED_BY_STEP_PREFLIGHT'
 assert r['supavisor_support_commit']=='e85426bccd646c8f4c9c3ccaac90a2c1a632d3db' and r['supavisor_support_must_be_ancestor_of_execution_main'] is True
 assert canonical_digest(dsn)==r['source_supavisor_dsn_success_evidence_digest']=='sha256:626e401ab7a4521c02f02505da1f4af01d35bcf68e98046a0f5b70f6fa60b6d8'
 assert dsnx['overall_state']=='COMPLETED' and dsnx['progress_digest']==r['source_supavisor_dsn_progress_digest']=='sha256:ca2d1b6d5b1781ada04e22608db22e1947c3833063903000608fca469e33b640'
 assert d3x['step_states'][0]['evidence'][0]['evidence_digest']==r['source_deployment_v3_success_evidence_digest']=='sha256:560b8147f448e12d34e9266816a889a04aba082abec2741a91647be7c6a9fd2a'
 assert d3x['overall_state']=='COMPLETED' and d3x['progress_digest']==r['source_deployment_v3_progress_digest']=='sha256:1f628b63d94f127877ee6b96d31e1d66134a3c8ea7dd6eb31fc69da1c0b31e1a'
 assert r['post_deploy_runtime_verification_required'] is True
 assert r['post_deploy_expected']=={'startup_http':200,'liveness_http':200,'readiness_http':200,'configuration':'ready','identity':'ready','data':'ready','unauthenticated_commands_http':401,'unauthenticated_queries_http':401,'unauthenticated_error':'trusted_identity_required','second_deploy_detected':False}
 for k in ('environment_variable_changes_authorized','environment_group_changes_authorized','service_setting_changes_authorized','github_visibility_changes_authorized','github_branch_protection_changes_authorized'): assert r[k]==0
 assert r['secret_material_agent_visible'] is False and r['supabase_operation_authorized'] is False and r['n8n_operation_authorized'] is False and r['staging_authorized'] is False and r['production_authorized'] is False
 assert p['plan_version']==4 and p['plan_digest']==plan_digest(p) and p['definition_status']=='READY_FOR_APPROVAL' and p['environment']=='DEVELOPMENT'
 assert p['authorization_window']=={'binding_state':'BOUND','starts_at':'2026-10-02T15:00:00Z','expires_at':'2026-10-02T19:00:00Z'} and p['authority_effect']=='NONE_UNTIL_SEPARATELY_APPROVED'
 assert len(p['steps'])==2 and p['ordered_step_ids']==[x['step_id'] for x in p['steps']]
 s1,s2=p['steps']
 assert s1['operation']=='provider.render.deploy.trigger-manual-latest-main' and s1['execution_class']=='PROVIDER_MUTATION'
 assert s1['resource']=={'resource_type':'render.service.deployment','resource_reference':'render:srv-dab9n4qd0e5s73dq37mg:deployment','binding_state':'BOUND','exact_version':'render.manual-canonical-main-supavisor-ready.v4','exact_digest':r['contract_digest']}
 assert s1['credential_policy']=={'permitted':True,'allowed_classes':['OWNER_INTERACTIVE_SESSION'],'values_stored':False}
 assert len(s1['required_evidence'])==4
 d1={x['binding_id']:x for x in s1['binding_declarations']}
 assert d1['binding.development.render.deployment-v4.canonical-main-head']['phase']=='RESOLVED_BY_STEP_PREFLIGHT'
 assert d1['binding.development.render.deployment-v4.result']['phase']=='PRODUCED_BY_CURRENT_STEP'
 for x in ('deployment.retry','deployment.second-trigger','environment-variable.modify','environment-group.modify','github.repository-visibility.modify','github.branch-protection.modify','render.auto-deploy.modify','render.branch.modify','render.clear-cache','render.service-setting.modify','supabase.operation','n8n.operation','staging.target','production.target'): assert x in s1['prohibited_actions']
 assert s2['operation']=='provider.render.verify-post-deploy-runtime-use' and s2['execution_class']=='PROVIDER_READ'
 assert s2['dependency_step_ids']==[s1['step_id']] and s2['credential_policy']=={'permitted':False,'allowed_classes':['NONE'],'values_stored':False}
 assert s2['required_evidence']==[{'evidence_type':'runtime.render.deployment.completed','source_step_id':s1['step_id'],'binding_state':'DERIVED_FROM_SOURCE_STEP','exact_digest':None}]
 d2={x['binding_id']:x for x in s2['binding_declarations']}
 assert d2['binding.development.render.deployment-v4.result']['phase']=='DERIVED_FROM_SOURCE_STEP'
 assert d2['binding.development.render.deployment-v4.runtime-verification']['phase']=='PRODUCED_BY_CURRENT_STEP'
 for x in ('readiness.not-200','readiness.configuration-not-ready','readiness.identity-not-ready','readiness.data-not-ready','commands.anonymous-not-401','queries.anonymous-not-401','second-deploy.detected'): assert x in s2['stop_conditions']
 assert g==initial_progress(p,S,g['progress_id'],p['created_at']) and g['overall_state']=='NOT_STARTED'
 assert all(st['authorization_state']=='PENDING' and st['execution_state']=='NOT_STARTED' and st['authorization_consumed'] is False for st in g['step_states'])
 rendered=(B/f'{N}.resource.json').read_text()+(B/f'{N}.plan.json').read_text()+(B/f'{N}.progress.json').read_text()
 for forbidden in ('postgresql://','postgres://','password=','op://'): assert forbidden not in rendered
 print('DEVELOPMENT Render deployment v4: PASS (READY_FOR_APPROVAL; one canonical-main deploy + read-only runtime/use verification; readiness 200 required; no retry/config/secret/provider drift)')
 return 0
if __name__=='__main__': raise SystemExit(main())
