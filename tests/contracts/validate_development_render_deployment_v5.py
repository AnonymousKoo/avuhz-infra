#!/usr/bin/env python3
from __future__ import annotations
import hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; sys.path.insert(0,str(ROOT/'src'))
from avuhz_engineering.authorization_plan import approval_digest,initial_progress,plan_digest,validate_approval,validate_plan,validate_progress
from avuhz_runtime.implementation_handoff import canonical_digest
B=ROOT/'contracts/plans/v1'; S=ROOT/'contracts/schemas/v1'; N='development-render-deployment-v5'
RESOURCE_DIGEST='sha256:7ba460afcfb2ba307ff3c7e94a1adf46bfa93e611111e12bd2a808bbd5595cee'
PLAN_ID='fbdfdd80-ce73-4dfa-a24d-6baa4eaaaec9'; PLAN_DIGEST='sha256:102e46593d29bcd5b74c33441b21f57d6d88b64f28bda8aa6966939faccc3e77'
PROGRESS_ID='89660648-56b5-450a-ad16-dc17d34eba1f'; PROGRESS_DIGEST='sha256:0accd7fbfbfde4f98df9f1b9b66e2084d574ba4b8ca8ed27f579c5068f40419c'
V4_STEP1='sha256:b3509b9380bfbd75998e771d53926c84c590a4ade854b37fa9dd7fef001b1a3b'; V4_STEP2='sha256:b2c6eea129cb52d7955aeb96f40ccc6408938faeb83b7f00d4ff38907cfe1398'; V4_PROGRESS='sha256:44f142ec9a28b8eb503015dc795bb19e58f9194beaad112af57e1dda3d50517c'
def load(name): return json.load(open(B/name))
def raw(name): return 'sha256:'+hashlib.sha256((B/name).read_bytes()).hexdigest()
def main():
 r=load(N+'.resource.json'); p=load(N+'.plan.json'); g=load(N+'.progress.json'); a=load(N+'.approval.json'); v4=load('development-render-deployment-v4.execution-progress.json')
 validate_plan(p,S); validate_progress(p,g,S); validate_approval(p,a,S,p['authorization_window']['starts_at'])
 assert r['contract_digest']==RESOURCE_DIGEST==canonical_digest({k:v for k,v in r.items() if k!='contract_digest'})
 assert r['contract_version']=='v5' and r['environment']=='DEVELOPMENT' and r['provider']=='render'
 assert r['workspace_id']=='tea-dab95hv40ujc73a7ccag' and r['service_id']=='srv-dab9n4qd0e5s73dq37mg' and r['service_name']=='avuhz-command-dev'
 assert r['environment_id']=='evm-dab96l2jobas73bp95bg' and r['repo']=='AnonymousKoo/avuhz-infra' and r['branch']=='main'
 assert r['branch_protection_required']=={'required_status_checks':['main-pr-gate'],'enforce_admins':True,'pull_request_review_rule_present':True,'required_approving_review_count':0}
 assert r['auto_deploy_expected']=='no' and r['auto_deploy_trigger_expected']=='off'
 assert r['current_live_deploy_id']=='dep-davsr0egekts73fb61k0' and r['current_live_commit']=='640f6d10e76a4fdda3994bdd9b45b801a8887257'
 assert r['manual_deploy_count_authorized']==1 and r['clear_cache_authorized'] is False and r['deployment_head_binding']=='RESOLVED_BY_STEP_PREFLIGHT'
 assert r['required_client_tls_correction_commit']=='f9afa8857cecc5bf86b86d7f1d5f43167affd7c0' and r['client_tls_correction_requirement']=='ANCESTOR_OF_EXECUTION_MAIN'
 assert raw('development-render-deployment-v4-step01-success.evidence.json')==r['source_v4_step1_deployment_success_evidence_digest']==V4_STEP1
 assert raw('development-render-deployment-v4-step02-readiness-failure.evidence.json')==r['source_v4_step2_runtime_failure_evidence_digest']==V4_STEP2
 assert v4['overall_state']=='STOPPED' and v4['progress_digest']==r['source_v4_progress_digest']==V4_PROGRESS
 assert v4['step_states'][0]['execution_state']=='SUCCEEDED' and v4['step_states'][0]['verification_state']=='PASS'
 assert v4['step_states'][1]['execution_state']=='FAILED' and v4['step_states'][1]['verification_state']=='FAIL'
 assert r['post_deploy_expected']=={'startup_http':200,'liveness_http':200,'readiness_http':200,'configuration':'ready','identity':'ready','data':'ready','unauthenticated_commands_http':401,'unauthenticated_queries_http':401,'unauthenticated_error':'trusted_identity_required','second_deploy_detected':False}
 for k in ('environment_variable_changes_authorized','environment_group_changes_authorized','service_setting_changes_authorized','github_visibility_changes_authorized','github_branch_protection_changes_authorized'): assert r[k]==0
 assert r['secret_material_agent_visible'] is False and r['supabase_operation_authorized'] is False and r['n8n_operation_authorized'] is False and r['staging_authorized'] is False and r['production_authorized'] is False
 assert p['plan_id']==PLAN_ID and p['plan_version']==5 and p['plan_digest']==PLAN_DIGEST==plan_digest(p)
 assert p['definition_status']=='READY_FOR_APPROVAL' and p['environment']=='DEVELOPMENT' and p['authority_effect']=='NONE_UNTIL_SEPARATELY_APPROVED'
 assert p['authorization_window']=={'binding_state':'BOUND','starts_at':'2026-10-02T17:00:00Z','expires_at':'2026-10-02T21:00:00Z'}
 assert a['plan_id']==p['plan_id'] and a['plan_version']==5 and a['plan_digest']==p['plan_digest']
 assert a['owner_identity']=='github:AnonymousKoo' and a['decision']=='APPROVE' and a['environment']=='DEVELOPMENT'
 assert a['effective_at']=='2026-10-02T17:00:00Z' and a['expires_at']=='2026-10-02T21:00:00Z'
 assert a['approved_at']=='2026-10-02T16:08:56Z' and a['status']=='ACTIVE' and a['authority_scope']=='EXACT_PLAN_ONLY'
 assert a['approval_digest']==approval_digest(a)
 assert len(p['steps'])==2 and p['ordered_step_ids']==[x['step_id'] for x in p['steps']]
 s1,s2=p['steps']; assert s1['operation']=='provider.render.deploy.trigger-manual-latest-main' and s1['execution_class']=='PROVIDER_MUTATION'
 assert s1['resource']=={'resource_type':'render.service.deployment','resource_reference':'render:srv-dab9n4qd0e5s73dq37mg:deployment','binding_state':'BOUND','exact_version':'render.manual-client-tls-corrected-canonical-main.v5','exact_digest':RESOURCE_DIGEST}
 assert s1['credential_policy']=={'permitted':True,'allowed_classes':['OWNER_INTERACTIVE_SESSION'],'values_stored':False}
 assert s1['required_evidence']==[
  {'evidence_type':'runtime.render.deployment.completed','source_step_id':None,'binding_state':'BOUND','exact_digest':V4_STEP1},
  {'evidence_type':'runtime.render.post-deploy-runtime.verified','source_step_id':None,'binding_state':'BOUND','exact_digest':V4_STEP2},
  {'evidence_type':'authorization-plan.execution-progress','source_step_id':None,'binding_state':'BOUND','exact_digest':V4_PROGRESS}]
 d1={x['binding_id']:x for x in s1['binding_declarations']}; assert d1['binding.development.render.deployment-v5.canonical-main-head']['phase']=='RESOLVED_BY_STEP_PREFLIGHT'; assert d1['binding.development.render.deployment-v5.result']['phase']=='PRODUCED_BY_CURRENT_STEP'
 for x in ('deployment.retry','deployment.second-trigger','environment-variable.modify','environment-group.modify','render.clear-cache','render.service-setting.modify','supabase.operation','n8n.operation','staging.target','production.target'): assert x in s1['prohibited_actions']
 for x in ('client-tls-correction.not-ancestor-of-main','v4-outcome.mismatch','deployment.commit-mismatch'): assert x in s1['stop_conditions']
 assert s2['operation']=='provider.render.verify-post-deploy-runtime-use' and s2['execution_class']=='PROVIDER_READ'
 assert s2['dependency_step_ids']==[s1['step_id']] and s2['credential_policy']=={'permitted':False,'allowed_classes':['NONE'],'values_stored':False}
 assert s2['required_evidence']==[{'evidence_type':'runtime.render.deployment.completed','source_step_id':s1['step_id'],'binding_state':'DERIVED_FROM_SOURCE_STEP','exact_digest':None}]
 for x in ('readiness.not-200','readiness.data-not-ready','commands.anonymous-not-401','queries.anonymous-not-401','second-deploy.detected'): assert x in s2['stop_conditions']
 assert g==initial_progress(p,S,PROGRESS_ID,p['created_at']) and g['progress_digest']==PROGRESS_DIGEST and g['overall_state']=='NOT_STARTED'
 assert all(st['authorization_state']=='PENDING' and st['execution_state']=='NOT_STARTED' and st['authorization_consumed'] is False for st in g['step_states'])
 rendered=(B/(N+'.resource.json')).read_text()+(B/(N+'.plan.json')).read_text()+(B/(N+'.progress.json')).read_text()+(B/(N+'.approval.json')).read_text()
 for forbidden in ('postgresql://','postgres://','password=','op://'): assert forbidden not in rendered
 print('DEVELOPMENT Render deployment v5: PASS (APPROVED; v4 STOPPED bound; client-TLS correction ancestor required; one deploy + read-only readiness 200 verification; no retry/config/secret drift)')
 return 0
if __name__=='__main__': raise SystemExit(main())
