#!/usr/bin/env python3
from __future__ import annotations
import hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; sys.path.insert(0,str(ROOT/'src'))
from avuhz_engineering.authorization_plan import approval_digest,initial_progress,plan_digest,validate_approval,validate_plan,validate_progress
from avuhz_runtime.implementation_handoff import canonical_digest
B=ROOT/'contracts/plans/v1'; S=ROOT/'contracts/schemas/v1'; N='development-render-deployment-v8'
RESOURCE_DIGEST='sha256:493a00e292e5ebdf32e30e755f7f03ac8502a9c23cb1085794df2be7e386fcbf'
PLAN_ID='003ad8fb-3200-467b-aeb3-2c6ddd533bf2'; PLAN_DIGEST='sha256:0eae523081e31639758370843b61bf1bf76a43c4a427a871eff7b0877a961088'
PROGRESS_ID='8e3a0acd-97df-4b3d-b1ce-f3ec70903780'; PROGRESS_DIGEST='sha256:c7f15277c2faff58be13bfcbddaa8519504ee8f651fefe16511da0dc65220009'
V7_STEP1='sha256:d2e30bb5414eb33c95f04dafdb0f7210735f6ed86c7416185756e41910170552'
V7_STEP2='sha256:8e01e90c84e4bb05630b5c45ce5831154b4a25976afaddc887aa8ff9ecdf9c31'
V7_PROGRESS='sha256:f73efc7fc0da8a7b1279eec444e8c82bbae97fffc6e69643e5afbdfc9a70501e'
def load(n): return json.load(open(B/n))
def raw(n): return 'sha256:'+hashlib.sha256((B/n).read_bytes()).hexdigest()
def main():
    r=load(N+'.resource.json'); p=load(N+'.plan.json'); g=load(N+'.progress.json'); a=load(N+'.approval.json'); v7=load('development-render-deployment-v7.execution-progress.json')
    validate_plan(p,S); validate_progress(p,g,S); validate_approval(p,a,S,p['authorization_window']['starts_at'])
    assert r['contract_digest']==RESOURCE_DIGEST==canonical_digest({k:v for k,v in r.items() if k!='contract_digest'})
    assert r['contract_version']=='v8' and r['environment']=='DEVELOPMENT' and r['provider']=='render'
    assert r['workspace_id']=='tea-dab95hv40ujc73a7ccag' and r['service_id']=='srv-dab9n4qd0e5s73dq37mg' and r['service_name']=='avuhz-command-dev'
    assert r['environment_id']=='evm-dab96l2jobas73bp95bg' and r['repo']=='AnonymousKoo/avuhz-infra' and r['branch']=='main'
    assert r['branch_protection_required']=={'required_status_checks':['main-pr-gate'],'enforce_admins':True,'pull_request_review_rule_present':True,'required_approving_review_count':0}
    assert r['auto_deploy_expected']=='no' and r['auto_deploy_trigger_expected']=='off'
    assert r['current_live_deploy_id']=='dep-db00ul3ncjis7382bqm0' and r['current_live_commit']=='0eeb35a1763cdc06599c8889c315b597ef259dcf'
    assert r['required_client_tls_correction_commit']=='f9afa8857cecc5bf86b86d7f1d5f43167affd7c0'
    assert r['required_probe_percent_escape_commit']=='1ac034de34503739839a8cdb8c7f9ce4eb01c60f'
    assert r['required_probe_like_percent_escape_commit']=='8856a817be68cd0afb37fcde56852d2041f3a5a6'
    assert raw('development-render-deployment-v7-step01-success.evidence.json')==r['source_v7_step1_deployment_success_evidence_digest']==V7_STEP1
    assert raw('development-render-deployment-v7-step02-readiness-failure.evidence.json')==r['source_v7_step2_runtime_failure_evidence_digest']==V7_STEP2
    assert v7['overall_state']=='STOPPED' and v7['progress_digest']==r['source_v7_progress_digest']==V7_PROGRESS
    assert v7['step_states'][0]['execution_state']=='SUCCEEDED' and v7['step_states'][0]['verification_state']=='PASS'
    assert v7['step_states'][1]['execution_state']=='FAILED' and v7['step_states'][1]['verification_state']=='FAIL'
    assert r['manual_deploy_count_authorized']==1 and r['clear_cache_authorized'] is False
    assert r['post_deploy_expected']['readiness_http']==200 and r['post_deploy_expected']['data']=='ready'
    for k in ('environment_variable_changes_authorized','environment_group_changes_authorized','service_setting_changes_authorized','github_visibility_changes_authorized','github_branch_protection_changes_authorized'): assert r[k]==0
    assert r['secret_material_agent_visible'] is False and r['supabase_operation_authorized'] is False and r['n8n_operation_authorized'] is False and r['staging_authorized'] is False and r['production_authorized'] is False
    assert p['plan_id']==PLAN_ID and p['plan_version']==8 and p['plan_digest']==PLAN_DIGEST==plan_digest(p)
    assert p['definition_status']=='READY_FOR_APPROVAL' and p['environment']=='DEVELOPMENT' and p['authority_effect']=='NONE_UNTIL_SEPARATELY_APPROVED'
    assert p['authorization_window']=={'binding_state':'BOUND','starts_at':'2026-10-02T21:00:00Z','expires_at':'2026-10-03T01:00:00Z'}
    assert a['plan_id']==p['plan_id'] and a['plan_version']==8 and a['plan_digest']==p['plan_digest']
    assert a['owner_identity']=='github:AnonymousKoo' and a['decision']=='APPROVE' and a['environment']=='DEVELOPMENT'
    assert a['effective_at']=='2026-10-02T21:00:00Z' and a['expires_at']=='2026-10-03T01:00:00Z'
    assert a['approved_at']=='2026-10-02T20:35:30Z' and a['status']=='ACTIVE' and a['authority_scope']=='EXACT_PLAN_ONLY'
    assert a['approval_digest']==approval_digest(a)
    assert len(p['steps'])==2 and p['ordered_step_ids']==[x['step_id'] for x in p['steps']]
    s1,s2=p['steps']; assert s1['operation']=='provider.render.deploy.trigger-manual-latest-main' and s1['execution_class']=='PROVIDER_MUTATION'
    assert s1['resource']=={'resource_type':'render.service.deployment','resource_reference':'render:srv-dab9n4qd0e5s73dq37mg:deployment','binding_state':'BOUND','exact_version':'render.manual-probe-percent-escaped-canonical-main.v8','exact_digest':RESOURCE_DIGEST}
    assert s1['required_evidence']==[{'evidence_type':'runtime.render.deployment.completed','source_step_id':None,'binding_state':'BOUND','exact_digest':V7_STEP1},{'evidence_type':'runtime.render.post-deploy-runtime.verified','source_step_id':None,'binding_state':'BOUND','exact_digest':V7_STEP2},{'evidence_type':'authorization-plan.execution-progress','source_step_id':None,'binding_state':'BOUND','exact_digest':V7_PROGRESS}]
    b={x['binding_id']:x for x in s1['binding_declarations']}
    assert b['binding.development.render.deployment-v8.v7-step1']['preapproval_value']['value']==V7_STEP1
    assert b['binding.development.render.deployment-v8.v7-step2']['preapproval_value']['value']==V7_STEP2
    assert b['binding.development.render.deployment-v8.v7-progress']['preapproval_value']['value']==V7_PROGRESS
    assert b['binding.development.render.deployment-v8.probe-like-percent-escape']['preapproval_value']['value']=='git.commit.8856a817be68cd0afb37fcde56852d2041f3a5a6'
    assert b['binding.development.render.deployment-v8.canonical-main-head']['phase']=='RESOLVED_BY_STEP_PREFLIGHT'
    assert b['binding.development.render.deployment-v8.result']['phase']=='PRODUCED_BY_CURRENT_STEP'
    for x in ('client-tls-correction.not-ancestor-of-main','probe-percent-escape.not-ancestor-of-main','probe-like-percent-escape.not-ancestor-of-main','v7-outcome.mismatch','deployment.commit-mismatch'): assert x in s1['stop_conditions']
    assert len(s1['stop_conditions'])<=16
    assert s2['operation']=='provider.render.verify-post-deploy-runtime-use' and s2['execution_class']=='PROVIDER_READ'
    assert s2['dependency_step_ids']==[s1['step_id']] and s2['credential_policy']=={'permitted':False,'allowed_classes':['NONE'],'values_stored':False}
    for x in ('readiness.not-200','readiness.data-not-ready','commands.anonymous-not-401','queries.anonymous-not-401','second-deploy.detected'): assert x in s2['stop_conditions']
    assert g==initial_progress(p,S,PROGRESS_ID,p['created_at']) and g['progress_digest']==PROGRESS_DIGEST and g['overall_state']=='NOT_STARTED'
    assert all(st['authorization_state']=='PENDING' and st['execution_state']=='NOT_STARTED' and st['authorization_consumed'] is False for st in g['step_states'])
    rendered=(B/(N+'.resource.json')).read_text()+(B/(N+'.plan.json')).read_text()+(B/(N+'.progress.json')).read_text()+(B/(N+'.approval.json')).read_text()
    for forbidden in ('postgresql://','postgres://','password=','op://'): assert forbidden not in rendered
    print('DEVELOPMENT Render deployment v8: PASS (APPROVED; v7 STOPPED bound; all three readiness fixes required; one deploy + read-only readiness 200 verification)')
    return 0
if __name__=='__main__': raise SystemExit(main())
