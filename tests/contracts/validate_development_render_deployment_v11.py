#!/usr/bin/env python3
from __future__ import annotations
import hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; sys.path.insert(0,str(ROOT/'src'))
from avuhz_engineering.authorization_plan import approval_digest,initial_progress,plan_digest,validate_approval,validate_plan,validate_progress
from avuhz_runtime.implementation_handoff import canonical_digest
B=ROOT/'contracts/plans/v1'; S=ROOT/'contracts/schemas/v1'; N='development-render-deployment-v11'
PLAN_ID='33ef8a51-ac40-4a8b-b6cb-9da7d8babdd3'
PLAN_DIGEST='sha256:a33038cd0bed5bf62c6c1f2d2f4c9f42db48f48d57dc6c2845882c492c569102'
PROGRESS_ID='b7efd116-ec46-42a8-a6da-793a1da6f0c8'
PROGRESS_DIGEST='sha256:0fe904fff35adfde151a0002744adb03e1c5e39256da3bc5c5eeb3849cebc31a'
RESOURCE_DIGEST='sha256:7ea724bdb17c2c5d8fae035296a3ffdacc5a5900821f83839304d3a94c674599'
ALLOWLIST_COMMIT='e4ee9c6016bca59d1e55b35ca616803bad91409e'
BUILD_STATE_COMMIT='d7cf12b8a18330898bec48edf3dcd3d633006e89'
V10_STEP1='sha256:9839e66d5d3b7a56e59a1d3c51c3d43d4bebcff4c70a2aea7f0c9cfa4881dc85'
V10_STEP2='sha256:fd0e493b53cdbe2a19b3ae7f59eaab9f495d5e75868ca8ea1f8a554fede82c26'
V10_PROGRESS='sha256:46728452864e373d87c12b97bf0300719607a33e09579719f07bec89a9574f24'
ALLOWLIST_EVIDENCE='sha256:07b1103c5a90a04849e4cc6c4d9c303adcf09b7a639086ae88a90979ad301325'
ALLOWLIST_PROGRESS='sha256:eef423d8cd118abf87da1d2d1f7b2a56c78570dab306cf8c94113ab923774a9c'
STEP1_EVIDENCE_DIGEST='sha256:dcbfc3328794da93c8d660145968f3fdfa84c2a42ea0abab32293221c3157806'
STEP2_EVIDENCE_DIGEST='sha256:f49f6882f2e6ec0274935137a52c7b7c942bfbe0bc72baebca143a90aedc5345'
EXECUTION_PROGRESS_DIGEST='sha256:762fc38748aeb4483a5b26179a703e687bab13e7f5c73160b29a3a77d4480e5c'
BOUND_HEAD='8e96e486d1173039a444c67849e26048282d6e9c'
def load(n): return json.loads((B/n).read_text())
def raw(n): return 'sha256:'+hashlib.sha256((B/n).read_bytes()).hexdigest()
def main():
 r=load(N+'.resource.json'); p=load(N+'.plan.json'); g=load(N+'.progress.json'); a=load(N+'.approval.json'); e=load(N+'-step01-success.evidence.json'); e2=load(N+'-step02-success.evidence.json'); x=load(N+'.execution-progress.json')
 validate_plan(p,S); validate_progress(p,g,S); validate_approval(p,a,S,'2026-10-04T03:15:00Z')
 assert p['plan_id']==PLAN_ID and p['plan_version']==11 and p['plan_digest']==PLAN_DIGEST==plan_digest(p)
 assert p['definition_status']=='READY_FOR_APPROVAL' and p['authority_effect']=='NONE_UNTIL_SEPARATELY_APPROVED'
 assert a['plan_id']==PLAN_ID and a['plan_version']==11 and a['plan_digest']==PLAN_DIGEST
 assert a['owner_identity']=='github:AnonymousKoo' and a['decision']=='APPROVE' and a['environment']=='DEVELOPMENT'
 assert a['effective_at']=='2026-10-04T03:15:00Z' and a['expires_at']=='2026-10-04T05:30:00Z'
 assert a['approved_at']=='2026-10-04T02:54:19Z' and a['status']=='ACTIVE' and a['authority_scope']=='EXACT_PLAN_ONLY'
 assert a['approval_digest']=='sha256:7f9a2be09ce2767e2bf3cc32d4ebaa2fe9d67784992c21863eb9bc9e21d24cbe'==approval_digest(a)
 assert p['authorization_window']=={'binding_state':'BOUND','starts_at':'2026-10-04T03:15:00Z','expires_at':'2026-10-04T05:30:00Z'}
 assert r['contract_digest']==RESOURCE_DIGEST==canonical_digest({k:v for k,v in r.items() if k!='contract_digest'})
 assert r['workspace_id']=='tea-dab95hv40ujc73a7ccag' and r['service_id']=='srv-dab9n4qd0e5s73dq37mg' and r['service_name']=='avuhz-command-dev'
 assert r['deployment_head_binding']=='RESOLVED_BY_STEP_PREFLIGHT' and r['required_provider_adapter_allowlist_commit']==ALLOWLIST_COMMIT and r['provider_adapter_allowlist_commit_requirement']=='ANCESTOR_OF_EXECUTION_MAIN'
 assert r['required_build_state_commit']==BUILD_STATE_COMMIT and r['build_state_commit_requirement']=='ANCESTOR_OF_EXECUTION_MAIN'
 assert r['current_live_deploy_expected']=='dep-db0645gu01pc73911b4g' and r['current_live_commit_expected']=='604e68ef8d563b28397552e4a34ce9cfe8f1b688'
 assert r['required_v10_deployment_evidence_digest']==V10_STEP1 and r['required_v10_runtime_evidence_digest']==V10_STEP2 and r['required_v10_progress_digest']==V10_PROGRESS
 assert r['required_allowlist_evidence_digest']==ALLOWLIST_EVIDENCE and r['required_allowlist_progress_digest']==ALLOWLIST_PROGRESS
 assert r['manual_deploy_count_authorized']==1 and r['clear_cache_authorized'] is False and r['workspace_confirmation_required_at_execution'] is True
 assert r['provider_adapter_positive_auth_test_authorized'] is False and r['token_issue_authorized'] is False and r['session_issue_authorized'] is False
 for k in ('supabase_operation_authorized','n8n_operation_authorized','staging_authorized','production_authorized','secret_material_agent_visible'): assert r[k] is False
 e1=load('development-render-deployment-v10-step01-success.evidence.json'); v10e2=load('development-render-deployment-v10-step02-success.evidence.json'); x10=load('development-render-deployment-v10.execution-progress.json')
 ae=load('development-implementation-handoff-provider-adapter-allowlist-binding-v1-step01-success.evidence.json'); ax=load('development-implementation-handoff-provider-adapter-allowlist-binding-v1.execution-progress.json')
 assert raw('development-render-deployment-v10-step01-success.evidence.json')==V10_STEP1 and raw('development-render-deployment-v10-step02-success.evidence.json')==V10_STEP2
 assert x10['progress_digest']==V10_PROGRESS and x10['overall_state']=='COMPLETED' and all(s['verification_state']=='PASS' for s in x10['step_states'])
 assert ae['evidence_digest']==ALLOWLIST_EVIDENCE and ax['progress_digest']==ALLOWLIST_PROGRESS and ax['overall_state']=='COMPLETED'
 s1,s2=p['steps']; assert len(p['steps'])==2
 assert s1['operation']=='provider.render.deploy.trigger-manual-exact-main' and s1['execution_class']=='PROVIDER_MUTATION'
 assert s1['credential_policy']=={'permitted':True,'allowed_classes':['OWNER_INTERACTIVE_SESSION'],'values_stored':False}
 assert s2['operation']=='provider.render.verify-post-deploy-runtime-use' and s2['execution_class']=='PROVIDER_READ'
 assert s2['credential_policy']=={'permitted':False,'allowed_classes':['NONE'],'values_stored':False}
 assert s2['dependency_step_ids']==[s1['step_id']] and s2['required_evidence'][0]['source_step_id']==s1['step_id']
 required={e['exact_digest'] for e in s1['required_evidence']}; assert {V10_STEP1,V10_STEP2,V10_PROGRESS,ALLOWLIST_EVIDENCE,ALLOWLIST_PROGRESS}<=required
 for action in ('deployment.retry','deployment.second-trigger','environment-variable.modify','supabase.operation','token.issue','session.issue','provider-adapter.positive-auth-test','n8n.operation','staging.target','production.target'):
  assert action in s1['prohibited_actions']
 for action in ('provider.mutation','token.issue','session.issue','provider-adapter.positive-auth-test','supabase.operation','n8n.operation','staging.target','production.target'):
  assert action in s2['prohibited_actions']
 b={x['binding_id']:x for x in s1['binding_declarations']}
 assert b['binding.development.render.deployment-v11.provider-adapter-allowlist-commit']['preapproval_value']['value']=='git.commit.'+ALLOWLIST_COMMIT
 assert b['binding.development.render.deployment-v11.build-state-commit']['preapproval_value']['value']=='git.commit.'+BUILD_STATE_COMMIT
 assert b['binding.development.render.deployment-v11.canonical-main-head']['phase']=='RESOLVED_BY_STEP_PREFLIGHT' and b['binding.development.render.deployment-v11.canonical-main-head']['evidence_type']=='github.canonical-main-head.observed'
 assert b['binding.development.render.deployment-v11.allowlist-evidence']['preapproval_value']['value']==ALLOWLIST_EVIDENCE
 assert b['binding.development.render.deployment-v11.allowlist-progress']['preapproval_value']['value']==ALLOWLIST_PROGRESS
 assert g==initial_progress(p,S,PROGRESS_ID,p['created_at']) and g['progress_digest']==PROGRESS_DIGEST and g['overall_state']=='NOT_STARTED'
 assert all(s['authorization_state']=='PENDING' and s['execution_state']=='NOT_STARTED' and s['verification_state']=='NOT_STARTED' and s['authorization_consumed'] is False for s in g['step_states'])
 assert x['progress_id']==PROGRESS_ID and x['progress_digest']==EXECUTION_PROGRESS_DIGEST and x['overall_state']=='COMPLETED' and x['record_version']==5
 xs1,xs2=x['step_states']
 assert xs1['authorization_state']=='CONSUMED' and xs1['execution_state']=='SUCCEEDED' and xs1['verification_state']=='PASS' and xs1['authorization_consumed'] is True and xs1['safe_error_code'] is None
 assert xs2['authorization_state']=='CONSUMED' and xs2['execution_state']=='SUCCEEDED' and xs2['verification_state']=='PASS' and xs2['authorization_consumed'] is True and xs2['safe_error_code'] is None
 assert raw(N+'-step01-success.evidence.json')==STEP1_EVIDENCE_DIGEST
 assert raw(N+'-step02-success.evidence.json')==STEP2_EVIDENCE_DIGEST
 assert e['outcome']=='SUCCEEDED_VERIFIED' and e['classification']=='MANUAL_RENDER_DEPLOYMENT_LIVE_EXACT_PREFLIGHT_BOUND_MAIN_PROVIDER_ADAPTER_ALLOWLIST_RUNTIME'
 assert e['preflight']['canonical_main_head']==BOUND_HEAD and e['preflight']['provider_adapter_allowlist_is_ancestor'] is True and e['preflight']['build_state_is_ancestor'] is True
 assert e['deployment_observation']['deploy_id']=='dep-db0saps9v7es73cqjuc0' and e['deployment_observation']['commit_id']==BOUND_HEAD and e['deployment_observation']['status']=='live'
 assert e['deployment_observation']['clear_cache'] is False and e['deployment_observation']['retry_attempted'] is False and e['deployment_observation']['second_deploy_triggered'] is False
 assert e['post_deploy_provider_state']['previous_live_deploy_id']=='dep-db0645gu01pc73911b4g' and e['post_deploy_provider_state']['previous_live_deploy_status']=='deactivated' and e['post_deploy_provider_state']['second_new_deploy_detected'] is False
 assert all(v is False for v in e['security_state'].values())
 assert e2['outcome']=='SUCCEEDED_VERIFIED' and e2['classification']=='POST_DEPLOY_PROVIDER_ADAPTER_ALLOWLIST_RUNTIME_READY_ANONYMOUS_FAIL_CLOSED'
 assert e2['deployment_observation']['deploy_id']=='dep-db0saps9v7es73cqjuc0' and e2['deployment_observation']['commit_id']==BOUND_HEAD and e2['deployment_observation']['status']=='live' and e2['deployment_observation']['latest_and_only_new_deploy'] is True
 assert e2['deployment_observation']['branch']=='main' and e2['deployment_observation']['auto_deploy']=='no' and e2['deployment_observation']['auto_deploy_trigger']=='off'
 ro=e2['runtime_observation']
 assert ro=={'startup_http':200,'startup_status':'started','liveness_http':200,'liveness_status':'alive','readiness_http':200,'configuration':'ready','identity':'ready','data':'ready','readiness_status':'ready','unauthenticated_commands_http':401,'unauthenticated_queries_http':401,'unauthenticated_implementation_handoff_http':401,'unauthenticated_error':'trusted_identity_required'}
 assert all(v is False for v in e2['security_state'].values())
 rendered=''.join((B/(N+s)).read_text() for s in ('.resource.json','.plan.json','.progress.json','.approval.json','-step01-success.evidence.json','-step02-success.evidence.json','.execution-progress.json'))
 for forbidden in ('postgresql://','postgres://','password=','op://','sb_secret_','service_role'): assert forbidden not in rendered
 print('DEVELOPMENT Render deployment v11: PASS (COMPLETED; Steps 1-2 consumed/succeeded/pass; runtime ready; anonymous fail-closed; one deploy/no retry; positive adapter auth excluded)')
if __name__=='__main__': main()
