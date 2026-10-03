import hashlib
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
BASE=ROOT/'contracts/plans/v1'
E=BASE/'development-implementation-handoff-provider-adapter-auth-v1-step01-failure.evidence.json'
P=BASE/'development-implementation-handoff-provider-adapter-auth-v1.execution-progress.json'
e=json.loads(E.read_text())
p=json.loads(P.read_text())
assert 'sha256:'+hashlib.sha256(E.read_bytes()).hexdigest()=='sha256:1e31607337b069824b2a444313c7394c4ade0575139e90d9726b0a651bf44956'
assert p['overall_state']=='STOPPED'
s=p['step_states'][0]
assert (s['authorization_state'],s['execution_state'],s['verification_state'],s['authorization_consumed'])==('CONSUMED','FAILED','FAIL',True)
assert s['safe_error_code']=='AUTH_ADMIN_EXECUTOR_CREDENTIAL_UNAVAILABLE'
assert s['evidence'][0]['evidence_digest']=='sha256:1e31607337b069824b2a444313c7394c4ade0575139e90d9726b0a651bf44956'
assert p['progress_digest']=='sha256:f4c4a299b032e3cb4460bf6d6c756de88a34cfad6d52e5cf9f645158e49d50fd'
assert e['execution_observation']['workflow_run_id']==37094133061
assert e['execution_observation']['provider_contact_attempted'] is False
assert e['execution_observation']['provider_mutation_attempted'] is False
assert e['execution_observation']['identity_create_attempted'] is False
assert e['authority_state']['retry_authorized'] is False
print('ImplementationHandoff provider-adapter Auth v1 failure record: PASS')
