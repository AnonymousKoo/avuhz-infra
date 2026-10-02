#!/usr/bin/env python3
from __future__ import annotations
import json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; sys.path.insert(0,str(ROOT/'src'))
from avuhz_engineering.authorization_plan import approval_digest,initial_progress,plan_digest,validate_approval,validate_plan,validate_progress
from avuhz_runtime.implementation_handoff import canonical_digest
B=ROOT/'contracts/plans/v1'; S=ROOT/'contracts/schemas/v1'; N='development-render-deployment-v7'
def load(n): return json.load(open(B/n))
def main():
 r=load(N+'.resource.json'); p=load(N+'.plan.json'); g=load(N+'.progress.json'); a=load(N+'.approval.json'); p6=load('development-render-deployment-v6.plan.json'); g6=load('development-render-deployment-v6.progress.json')
 validate_plan(p,S); validate_progress(p,g,S); validate_approval(p,a,S,p['authorization_window']['starts_at'])
 assert r['contract_version']=='v7' and r['contract_digest']=='sha256:17f7008872973ae546867bfb82eb791d579b0dc2df519905388bf7e4a9e8737c'==canonical_digest({k:v for k,v in r.items() if k!='contract_digest'})
 assert r['supersedes_v6']=={'plan_id':p6['plan_id'],'plan_digest':p6['plan_digest'],'progress_digest':g6['progress_digest'],'progress_state':'NOT_STARTED','reason':'owner approval was issued after the v6 effective_at boundary; v6 remains pristine and unexecuted; forward-only v7 shifts only the authorization window'}
 assert g6['overall_state']=='NOT_STARTED' and all(s['authorization_state']=='PENDING' and s['execution_state']=='NOT_STARTED' and s['authorization_consumed'] is False for s in g6['step_states'])
 assert p['plan_id']=='857fa481-a358-4532-87a3-2a3c2300f1a5' and p['plan_version']==7 and p['plan_digest']=='sha256:c0008aee6ffa0df3c6044622d632ab938357b868ac82cc15c6077bbc9db4ea95'==plan_digest(p)
 assert p['authorization_window']=={'binding_state':'BOUND','starts_at':'2026-10-02T20:00:00Z','expires_at':'2026-10-03T00:00:00Z'}
 assert a['plan_id']==p['plan_id'] and a['plan_version']==7 and a['plan_digest']==p['plan_digest']
 assert a['owner_identity']=='github:AnonymousKoo' and a['decision']=='APPROVE' and a['environment']=='DEVELOPMENT'
 assert a['effective_at']=='2026-10-02T20:00:00Z' and a['expires_at']=='2026-10-03T00:00:00Z'
 assert a['approved_at']=='2026-10-02T19:27:36Z' and a['status']=='ACTIVE' and a['authority_scope']=='EXACT_PLAN_ONLY'
 assert a['approval_digest']==approval_digest(a)
 assert p['authority_effect']=='NONE_UNTIL_SEPARATELY_APPROVED' and p['definition_status']=='READY_FOR_APPROVAL'
 s1,s2=p['steps']; assert len(p['steps'])==2
 assert s1['operation']=='provider.render.deploy.trigger-manual-latest-main' and s1['execution_class']=='PROVIDER_MUTATION'
 assert s2['operation']=='provider.render.verify-post-deploy-runtime-use' and s2['execution_class']=='PROVIDER_READ'
 assert s1['resource']['exact_version']=='render.manual-probe-percent-escaped-canonical-main.v7' and s2['resource']['exact_version']=='render.post-deploy-runtime-use.v7'
 assert s1['resource']['exact_digest']==s2['resource']['exact_digest']==r['contract_digest']
 assert {e['exact_digest'] for e in s1['required_evidence'] if e['exact_digest']} >= {g6['progress_digest']}
 b={x['binding_id']:x for x in s1['binding_declarations']}
 assert b['binding.development.render.deployment-v7.v6-plan']['preapproval_value']['value']==p6['plan_digest']
 assert b['binding.development.render.deployment-v7.v6-progress']['preapproval_value']['value']==g6['progress_digest']
 # unchanged technical scope
 for key in ('environment_variable_changes_authorized','environment_group_changes_authorized','service_setting_changes_authorized','github_visibility_changes_authorized','github_branch_protection_changes_authorized'): assert r[key]==0
 assert r['manual_deploy_count_authorized']==1 and r['clear_cache_authorized'] is False
 assert r['current_live_deploy_id']=='dep-davu68qd0e5s739d8eo0' and r['current_live_commit']=='c18813faf3539beb1516585db0e13926a6efd12d'
 assert r['required_client_tls_correction_commit']=='f9afa8857cecc5bf86b86d7f1d5f43167affd7c0'
 assert r['required_probe_percent_escape_commit']=='1ac034de34503739839a8cdb8c7f9ce4eb01c60f'
 assert r['post_deploy_expected']['readiness_http']==200 and r['post_deploy_expected']['data']=='ready'
 assert g==initial_progress(p,S,'30b02ef2-9f54-4edb-a825-26da369d5c5d',p['created_at']) and g['progress_digest']=='sha256:fa69df6aaefc8632df062fe692652427edc3f60a244b5fa70545e1022e7f98ac' and g['overall_state']=='NOT_STARTED'
 assert all(s['authorization_state']=='PENDING' and s['execution_state']=='NOT_STARTED' and s['authorization_consumed'] is False for s in g['step_states'])
 rendered=(B/(N+'.resource.json')).read_text()+(B/(N+'.plan.json')).read_text()+(B/(N+'.progress.json')).read_text()+(B/(N+'.approval.json')).read_text()
 for forbidden in ('postgresql://','postgres://','password=','op://'): assert forbidden not in rendered
 print('DEVELOPMENT Render deployment v7: PASS (APPROVED; forward-only timing correction from pristine v6; unchanged one-deploy/readiness scope)')
 return 0
if __name__=='__main__': raise SystemExit(main())
