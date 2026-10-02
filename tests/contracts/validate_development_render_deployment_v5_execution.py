#!/usr/bin/env python3
from __future__ import annotations
import hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; sys.path.insert(0,str(ROOT/'src'))
from avuhz_engineering.authorization_plan import validate_plan,validate_progress
B=ROOT/'contracts/plans/v1'; S=ROOT/'contracts/schemas/v1'; N='development-render-deployment-v5'
load=lambda n: json.load(open(B/n)); raw=lambda p:'sha256:'+hashlib.sha256(p.read_bytes()).hexdigest()
p=load(N+'.plan.json'); g=load(N+'.execution-progress.json'); e1=load(N+'-step01-success.evidence.json'); e2=load(N+'-step02-readiness-failure.evidence.json')
validate_plan(p,S); validate_progress(p,g,S)
assert g['overall_state']=='STOPPED' and g['record_version']==2
s1,s2=g['step_states']
assert (s1['authorization_state'],s1['execution_state'],s1['verification_state'],s1['authorization_consumed'])==('CONSUMED','SUCCEEDED','PASS',True)
assert (s2['authorization_state'],s2['execution_state'],s2['verification_state'],s2['authorization_consumed'])==('CONSUMED','FAILED','FAIL',True)
assert raw(B/(N+'-step01-success.evidence.json'))==s1['evidence'][0]['evidence_digest']
assert raw(B/(N+'-step02-readiness-failure.evidence.json'))==s2['evidence'][0]['evidence_digest']
assert e1['deployment_observation']['deploy_id']=='dep-davu68qd0e5s739d8eo0'
assert e1['deployment_observation']['commit_id']=='c18813faf3539beb1516585db0e13926a6efd12d'
assert e1['deployment_observation']['status']=='live'
assert e1['security_state']['retry_attempted'] is False and e1['security_state']['second_deploy_triggered'] is False
assert e2['runtime_observation']['readiness_http']==503 and e2['runtime_observation']['data']=='unavailable'
assert e2['runtime_observation']['unauthenticated_commands_http']==401 and e2['runtime_observation']['unauthenticated_queries_http']==401
trace=e2['sql_trace_observation']
assert trace['sample_size']==5 and trace['runtime_identity_delta']==5 and trace['effective_role_delta']==5
assert trace['final_probe_completed_statement_observed'] is False
pred=e2['data_predicate_observation']
assert pred['runtime_ready'] is True and pred['effective_ready'] is True and pred['probe_ready'] is True
assert pred['avuhz_tables']==pred['rls_tables']==pred['tenant_policies']==pred['selectable_tables']==16
assert pred['deletable_tables']==0 and pred['command_catalog_select_privileges'] is True and pred['command_builtin_privileges'] is True
diag=e2['code_diagnostic']
assert diag['failing_boundary']=='DevelopmentPostgresDataProbe.ready parameterized execute before server execution'
assert diag['offending_sql_fragment']=="format('%I.%I',table_info.schemaname,table_info.tablename)"
assert '%%' in diag['psycopg_rule']
assert s2['safe_error_code']=='RENDER_POST_DEPLOY_DATA_READINESS_NOT_READY'
assert e2['security_state']['retry_attempted'] is False and e2['security_state']['second_deploy_triggered'] is False
rendered=(B/(N+'.execution-progress.json')).read_text()+(B/(N+'-step01-success.evidence.json')).read_text()+(B/(N+'-step02-readiness-failure.evidence.json')).read_text()
for forbidden in ('password=','postgresql://','postgres://','op://'): assert forbidden not in rendered
print('DEVELOPMENT Render deployment v5 execution: PASS (Step 1 live exact canonical main; Step 2 STOPPED on Psycopg literal-percent probe error; no retry/second deploy)')
