#!/usr/bin/env python3
from __future__ import annotations
import hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; sys.path.insert(0,str(ROOT/'src'))
from avuhz_engineering.authorization_plan import validate_plan,validate_progress
B=ROOT/'contracts/plans/v1'; S=ROOT/'contracts/schemas/v1'; N='development-render-deployment-v7'
load=lambda n: json.load(open(B/n)); raw=lambda p:'sha256:'+hashlib.sha256(p.read_bytes()).hexdigest()
p=load(N+'.plan.json'); g=load(N+'.execution-progress.json'); e1=load(N+'-step01-success.evidence.json'); e2=load(N+'-step02-readiness-failure.evidence.json')
validate_plan(p,S); validate_progress(p,g,S)
assert g['overall_state']=='STOPPED' and g['record_version']==2
s1,s2=g['step_states']
assert (s1['authorization_state'],s1['execution_state'],s1['verification_state'],s1['authorization_consumed'])==('CONSUMED','SUCCEEDED','PASS',True)
assert (s2['authorization_state'],s2['execution_state'],s2['verification_state'],s2['authorization_consumed'])==('CONSUMED','FAILED','FAIL',True)
assert raw(B/(N+'-step01-success.evidence.json'))==s1['evidence'][0]['evidence_digest']
assert raw(B/(N+'-step02-readiness-failure.evidence.json'))==s2['evidence'][0]['evidence_digest']
assert e1['deployment_observation']['deploy_id']=='dep-db00ul3ncjis7382bqm0' and e1['deployment_observation']['commit_id']=='0eeb35a1763cdc06599c8889c315b597ef259dcf' and e1['deployment_observation']['status']=='live'
assert e1['security_state']['retry_attempted'] is False and e1['security_state']['second_deploy_triggered'] is False
assert e2['runtime_observation']['readiness_http']==503 and e2['runtime_observation']['data']=='unavailable'
assert e2['runtime_observation']['unauthenticated_commands_http']==401 and e2['runtime_observation']['unauthenticated_queries_http']==401
trace=e2['sql_trace_observation']; assert trace['sample_size']==3 and trace['runtime_identity_delta']==3 and trace['effective_role_delta']==3 and trace['final_probe_completed_statement_observed'] is False
pred=e2['data_predicate_observation']; assert pred=={'avuhz_tables':16,'rls_tables':16,'tenant_policies':16,'selectable_tables':16,'deletable_tables':0,'public_usage':True,'public_create':False}
diag=e2['code_diagnostic']; assert diag['remaining_literal_percent_fragments']==5 and diag['remaining_pattern']=="like 'avuhz_%'" and "'avuhz_%%'" in diag['security_preserving_correction']
assert s2['safe_error_code']=='RENDER_POST_DEPLOY_DATA_READINESS_NOT_READY'
assert e2['security_state']['retry_attempted'] is False and e2['security_state']['second_deploy_triggered'] is False
rendered=(B/(N+'.execution-progress.json')).read_text()+(B/(N+'-step01-success.evidence.json')).read_text()+(B/(N+'-step02-readiness-failure.evidence.json')).read_text()
for forbidden in ('password=','postgresql://','postgres://','op://'): assert forbidden not in rendered
print('DEVELOPMENT Render deployment v7 execution: PASS (Step 1 live exact canonical main; Step 2 STOPPED on remaining Psycopg LIKE literal-percent error; no retry/second deploy)')
