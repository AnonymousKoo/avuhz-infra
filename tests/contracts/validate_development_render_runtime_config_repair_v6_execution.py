#!/usr/bin/env python3
import hashlib, json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
B=ROOT/'contracts/plans/v1'
def load(name): return json.loads((B/name).read_text())
def digest(name): return 'sha256:'+hashlib.sha256((B/name).read_bytes()).hexdigest()
ex=load('development-render-runtime-config-repair-v6.execution-progress.json')
e1=load('development-render-runtime-config-repair-v6-step01-success.evidence.json')
e2=load('development-render-runtime-config-repair-v6-step02-success.evidence.json')
e3=load('development-render-runtime-config-repair-v6-step03-success.evidence.json')
e4=load('development-render-runtime-config-repair-v6-step04-scope-drift.evidence.json')
assert ex['overall_state']=='STOPPED'
for i in (0,1,2):
    st=ex['step_states'][i]
    assert st['authorization_state']=='CONSUMED'
    assert st['execution_state']=='SUCCEEDED'
    assert st['verification_state']=='PASS'
assert ex['step_states'][3]['authorization_state']=='CONSUMED'
assert ex['step_states'][3]['execution_state']=='FAILED'
assert ex['step_states'][3]['verification_state']=='FAIL'
assert ex['step_states'][3]['safe_error_code']=='RENDER_ENVIRONMENT_SCOPE_DRIFT'
assert ex['step_states'][4]['authorization_state']=='BLOCKED'
assert ex['step_states'][0]['evidence'][0]['evidence_digest']==digest('development-render-runtime-config-repair-v6-step01-success.evidence.json')
assert ex['step_states'][1]['evidence'][0]['evidence_digest']==digest('development-render-runtime-config-repair-v6-step02-success.evidence.json')
assert ex['step_states'][2]['evidence'][0]['evidence_digest']==digest('development-render-runtime-config-repair-v6-step03-success.evidence.json')
assert ex['step_states'][3]['evidence'][0]['evidence_digest']==digest('development-render-runtime-config-repair-v6-step04-scope-drift.evidence.json')
assert e1['owner_observation']['key']=='AVUHZ_AUTH_ISSUER'
assert e2['owner_observation']['key']=='AVUHZ_SERVICE_AUDIENCE'
assert e3['owner_observation']['key']=='AVUHZ_TENANT_BRIDGE'
assert e4['outcome']=='FAILED_SCOPE_DRIFT'
assert e4['owner_observation']['authorized_step_key']=='AVUHZ_RLS_POLICY_REFERENCE'
assert e4['owner_observation']['out_of_scope_key_changed']=='AVUHZ_DATA_PROJECT_URL'
assert e4['verification_observation']['new_deploy_detected'] is False
print('DEVELOPMENT Render runtime config repair v6 execution: PASS (STOPPED at Step 4 scope drift; no deployment)')
