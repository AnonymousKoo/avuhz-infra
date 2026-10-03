#!/usr/bin/env python3
from __future__ import annotations
import hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; sys.path.insert(0,str(ROOT/'src'))
from avuhz_engineering.authorization_plan import initial_progress,plan_digest,validate_plan,validate_progress
from avuhz_runtime.implementation_handoff import canonical_digest
B=ROOT/'contracts/plans/v1'; S=ROOT/'contracts/schemas/v1'; N='development-render-deployment-v10'
RESOURCE_DIGEST='sha256:449ce1a8dd59013d58212e784310a927c9f3fa12a666ee64c40b4506a399007a'
PLAN_ID='774f53c5-d5e5-40be-a391-ad9e4cd26722'; PLAN_DIGEST='sha256:b5980675fbe38798c77b30d08b63053e3864f6373830fddd34d90301eb9e2206'
PROGRESS_ID='2b004c13-e332-43ba-a7fc-8a661ff88fb5'; PROGRESS_DIGEST='sha256:9152481c557f123327d62ff696321bfa0deff7a3d8554507f2ce6a9ae8e72140'
V9_PLAN='sha256:29dcfed8c41ac1d1806055ccf6b9b40c64832e5f48bbdb3ce7891c4360d012ba'
V9_PROGRESS='sha256:13e90f432f6cc205bc0063438725784bfa0ebfd190970867ba681daa87c02e10'
def load(n): return json.load(open(B/n))
def main():
 r=load(N+'.resource.json'); p=load(N+'.plan.json'); g=load(N+'.progress.json'); p9=load('development-render-deployment-v9.plan.json'); g9=load('development-render-deployment-v9.progress.json')
 validate_plan(p,S); validate_progress(p,g,S)
 assert not (B/(N+'.approval.json')).exists()
 assert not (B/'development-render-deployment-v9.approval.json').exists()
 assert r['contract_version']=='v10' and r['contract_digest']==RESOURCE_DIGEST==canonical_digest({k:v for k,v in r.items() if k!='contract_digest'})
 assert r['supersedes_v9']=={'plan_id':p9['plan_id'],'plan_digest':p9['plan_digest'],'progress_digest':g9['progress_digest'],'progress_state':'NOT_STARTED','reason':'owner approval was issued after the v9 effective_at boundary; v9 remains pristine and unexecuted; forward-only v10 shifts only the authorization window'}
 assert p9['plan_id']=='43a909c1-69ca-404d-af78-00f0a95433b9' and p9['plan_digest']==V9_PLAN
 assert g9['progress_digest']==V9_PROGRESS and g9['overall_state']=='NOT_STARTED'
 assert all(x['authorization_state']=='PENDING' and x['execution_state']=='NOT_STARTED' and not x['authorization_consumed'] for x in g9['step_states'])
 assert p['plan_id']==PLAN_ID and p['plan_version']==10 and p['plan_digest']==PLAN_DIGEST==plan_digest(p)
 assert p['authorization_window']=={'binding_state':'BOUND','starts_at':'2026-10-03T02:00:00Z','expires_at':'2026-10-03T06:00:00Z'}
 assert p['definition_status']=='READY_FOR_APPROVAL' and p['authority_effect']=='NONE_UNTIL_SEPARATELY_APPROVED'
 assert r['workspace_id']=='tea-dab95hv40ujc73a7ccag' and r['service_id']=='srv-dab9n4qd0e5s73dq37mg' and r['service_name']=='avuhz-command-dev'
 assert r['current_live_deploy_id']=='dep-db01n2navr4c73dq8700' and r['current_live_commit']=='b4cd44412e6ab02c5f7f9f7ac6eeeb7c72db2f5c'
 assert r['manual_deploy_count_authorized']==1 and r['clear_cache_authorized'] is False
 assert r['implementation_handoff_execution_authorized'] is False and r['trusted_identity_policy_changes_authorized']==0
 for k in ('environment_variable_changes_authorized','environment_group_changes_authorized','service_setting_changes_authorized','github_visibility_changes_authorized','github_branch_protection_changes_authorized'): assert r[k]==0
 assert r['secret_material_agent_visible'] is False and r['supabase_operation_authorized'] is False and r['n8n_operation_authorized'] is False and r['staging_authorized'] is False and r['production_authorized'] is False
 s1,s2=p['steps']; assert len(p['steps'])==2
 assert s1['operation']=='provider.render.deploy.trigger-manual-latest-main' and s1['execution_class']=='PROVIDER_MUTATION'
 assert s2['operation']=='provider.render.verify-post-deploy-runtime-use' and s2['execution_class']=='PROVIDER_READ'
 assert s1['resource']['exact_version']=='render.manual-implementation-handoff-canonical-main.v10' and s2['resource']['exact_version']=='render.post-deploy-implementation-handoff-runtime.v10'
 assert s1['resource']['exact_digest']==s2['resource']['exact_digest']==RESOURCE_DIGEST
 assert s2['dependency_step_ids']==[s1['step_id']] and s2['required_evidence'][0]['source_step_id']==s1['step_id']
 b={x['binding_id']:x for x in s1['binding_declarations']}
 assert b['binding.development.render.deployment-v10.v9-plan']['preapproval_value']['value']==V9_PLAN
 assert b['binding.development.render.deployment-v10.v9-progress']['preapproval_value']['value']==V9_PROGRESS
 assert any(e['exact_digest']==V9_PROGRESS for e in s1['required_evidence'])
 assert 'v9-outcome.mismatch' in s1['stop_conditions'] and len(s1['stop_conditions'])<=16
 assert g==initial_progress(p,S,PROGRESS_ID,p['created_at']) and g['progress_digest']==PROGRESS_DIGEST and g['overall_state']=='NOT_STARTED'
 assert all(x['authorization_state']=='PENDING' and x['execution_state']=='NOT_STARTED' and not x['authorization_consumed'] for x in g['step_states'])
 rendered=''.join((B/(N+s)).read_text() for s in ('.resource.json','.plan.json','.progress.json'))
 for forbidden in ('postgresql://','postgres://','password=','op://'): assert forbidden not in rendered
 print('DEVELOPMENT Render deployment v10: PASS (READY_FOR_APPROVAL; forward-only timing correction from pristine v9; identical one-deploy/handoff-aware verification scope)')
 return 0
if __name__=='__main__': raise SystemExit(main())
