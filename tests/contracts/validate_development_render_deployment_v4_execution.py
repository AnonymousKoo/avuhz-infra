#!/usr/bin/env python3
from __future__ import annotations
import hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; sys.path.insert(0,str(ROOT/'src'))
from avuhz_engineering.authorization_plan import validate_plan,validate_progress
B=ROOT/'contracts/plans/v1'; S=ROOT/'contracts/schemas/v1'; N='development-render-deployment-v4'
load=lambda n: json.load(open(B/n)); raw=lambda p:'sha256:'+hashlib.sha256(p.read_bytes()).hexdigest()
p=load(N+'.plan.json'); g=load(N+'.execution-progress.json'); e1=load(N+'-step01-success.evidence.json'); e2=load(N+'-step02-readiness-failure.evidence.json')
validate_plan(p,S); validate_progress(p,g,S)
assert g['overall_state']=='STOPPED' and g['record_version']==3
s1,s2=g['step_states']; assert (s1['authorization_state'],s1['execution_state'],s1['verification_state'],s1['authorization_consumed'])==('CONSUMED','SUCCEEDED','PASS',True)
assert (s2['authorization_state'],s2['execution_state'],s2['verification_state'],s2['authorization_consumed'])==('CONSUMED','FAILED','FAIL',True)
assert raw(B/(N+'-step01-success.evidence.json'))==s1['evidence'][0]['evidence_digest']; assert raw(B/(N+'-step02-readiness-failure.evidence.json'))==s2['evidence'][0]['evidence_digest']
assert e1['deployment_observation']['deploy_id']=='dep-davsr0egekts73fb61k0' and e1['deployment_observation']['commit_id']=='640f6d10e76a4fdda3994bdd9b45b801a8887257' and e1['deployment_observation']['status']=='live'
assert e1['security_state']['retry_attempted'] is False and e1['security_state']['second_deploy_triggered'] is False
assert e2['runtime_observation']['readiness_http']==503 and e2['runtime_observation']['data']=='unavailable'
assert e2['supavisor_observation']['client_connection_authenticated'] is True and e2['supavisor_observation']['backend_authenticated'] is True and e2['supavisor_observation']['backend_ssl'] is False
assert e2['data_role_observation']['avuhz_tables']==e2['data_role_observation']['rls_tables']==e2['data_role_observation']['tenant_policies']==16
assert e2['data_role_observation']['selectable_tables']==16 and e2['data_role_observation']['deletable_tables']==0
assert e2['code_diagnostic']['current_tls_check']=='pg_stat_ssl on Postgres backend PID'
assert e2['security_state']['retry_attempted'] is False and e2['security_state']['second_deploy_triggered'] is False
assert s2['safe_error_code']=='RENDER_POST_DEPLOY_DATA_READINESS_NOT_READY'
rendered=(B/(N+'.execution-progress.json')).read_text()+(B/(N+'-step01-success.evidence.json')).read_text()+(B/(N+'-step02-readiness-failure.evidence.json')).read_text()
for forbidden in ('password=','postgresql://','postgres://','op://'): assert forbidden not in rendered
print('DEVELOPMENT Render deployment v4 execution: PASS (Step 1 live exact canonical main; Step 2 STOPPED on Supavisor backend-SSL/client-TLS mismatch; no retry/second deploy)')
