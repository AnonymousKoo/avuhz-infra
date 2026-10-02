#!/usr/bin/env python3
from __future__ import annotations
import hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; sys.path.insert(0,str(ROOT/'src'))
from avuhz_engineering.authorization_plan import validate_plan,validate_progress
B=ROOT/'contracts/plans/v1'; S=ROOT/'contracts/schemas/v1'; N='development-render-deployment-v8'
load=lambda n: json.load(open(B/n)); raw=lambda p:'sha256:'+hashlib.sha256(p.read_bytes()).hexdigest()
p=load(N+'.plan.json'); g=load(N+'.execution-progress.json')
e1=load(N+'-step01-success.evidence.json'); e2=load(N+'-step02-success.evidence.json')
validate_plan(p,S); validate_progress(p,g,S)
assert g['overall_state']=='COMPLETED' and g['record_version']==2
s1,s2=g['step_states']
assert (s1['authorization_state'],s1['execution_state'],s1['verification_state'],s1['authorization_consumed'])==('CONSUMED','SUCCEEDED','PASS',True)
assert (s2['authorization_state'],s2['execution_state'],s2['verification_state'],s2['authorization_consumed'])==('CONSUMED','SUCCEEDED','PASS',True)
assert raw(B/(N+'-step01-success.evidence.json'))==s1['evidence'][0]['evidence_digest']
assert raw(B/(N+'-step02-success.evidence.json'))==s2['evidence'][0]['evidence_digest']
assert e1['deployment_observation']['deploy_id']=='dep-db01n2navr4c73dq8700'
assert e1['deployment_observation']['commit_id']=='b4cd44412e6ab02c5f7f9f7ac6eeeb7c72db2f5c'
assert e1['deployment_observation']['status']=='live'
assert e1['deployment_observation']['clear_cache'] is False
assert e1['deployment_observation']['retry_attempted'] is False
assert e1['deployment_observation']['second_deploy_triggered'] is False
assert e1['post_deploy_provider_state']['second_new_deploy_detected'] is False
r=e2['runtime_observation']
assert r['startup_http']==200 and r['startup_status']=='started'
assert r['liveness_http']==200 and r['liveness_status']=='alive'
assert r['readiness_http']==200 and r['readiness_status']=='ready'
assert r['configuration']==r['identity']==r['data']=='ready'
assert r['unauthenticated_commands_http']==401 and r['unauthenticated_queries_http']==401
assert r['unauthenticated_error']=='trusted_identity_required'
assert e2['deployment_observation']['latest_and_only_new_deploy'] is True
assert e2['deployment_observation']['deploy_id']=='dep-db01n2navr4c73dq8700'
assert e2['deployment_observation']['commit_id']=='b4cd44412e6ab02c5f7f9f7ac6eeeb7c72db2f5c'
for ev in (e1,e2):
    sec=ev['security_state']
    for key in ('secret_material_observed','secret_material_recorded','environment_variable_mutation_attempted','service_setting_mutation_attempted','supabase_mutation_performed','n8n_touched','staging_touched','production_touched','retry_attempted','second_deploy_triggered'):
        assert sec[key] is False
bind1={x['binding_id']:x for x in s1['binding_assertions']}
bind2={x['binding_id']:x for x in s2['binding_assertions']}
assert bind1['binding.development.render.deployment-v8.canonical-main-head']['sanitized_value']=='github.commit.sha-b4cd44412e6ab02c5f7f9f7ac6eeeb7c72db2f5c'
assert bind1['binding.development.render.deployment-v8.result']['evidence_digest']==s1['evidence'][0]['evidence_digest']
assert bind2['binding.development.render.deployment-v8.result']['evidence_digest']==s1['evidence'][0]['evidence_digest']
assert bind2['binding.development.render.deployment-v8.runtime-verification']['evidence_digest']==s2['evidence'][0]['evidence_digest']
rendered=(B/(N+'.execution-progress.json')).read_text()+(B/(N+'-step01-success.evidence.json')).read_text()+(B/(N+'-step02-success.evidence.json')).read_text()
for forbidden in ('password=','postgresql://','postgres://','op://'): assert forbidden not in rendered
print('DEVELOPMENT Render deployment v8 execution: PASS (COMPLETED; exact canonical main live; readiness 200 all ready; anonymous auth 401; one deploy; no retry/config/secret mutation)')
