#!/usr/bin/env python3
import hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
B=ROOT/'contracts/plans/v1'
def load(n): return json.loads((B/n).read_text())
def digest(n): return 'sha256:'+hashlib.sha256((B/n).read_bytes()).hexdigest()
ex=load('development-render-runtime-config-final-verification-v1.execution-progress.json')
ev=load('development-render-runtime-config-final-verification-v1-success.evidence.json')
assert ex['overall_state']=='COMPLETED'
st=ex['step_states'][0]
assert st['authorization_state']=='CONSUMED'
assert st['authorization_consumed'] is True
assert st['execution_state']=='SUCCEEDED'
assert st['verification_state']=='PASS'
assert st['safe_error_code'] is None
assert st['evidence'][0]['evidence_digest']==digest('development-render-runtime-config-final-verification-v1-success.evidence.json')
assert ev['outcome']=='SUCCEEDED_VERIFIED'
assert ev['verification_observation']['all_nine_nonsecret_values_match'] is True
assert ev['verification_observation']['no_duplicate_keys_verified'] is True
assert ev['verification_observation']['secret_value_observed'] is False
assert ev['verification_observation']['provider_api_environment_enumeration_performed'] is False
assert ev['verification_observation']['provider_mutation_attempted'] is False
assert ev['verification_observation']['deployment_triggered'] is False
assert ev['verification_observation']['postcondition_verified'] is True
assert ev['security_state']['screenshot_persisted'] is False
assert ev['security_state']['screenshot_committed'] is False
assert ev['owner_visual_observation']['full_list_expanded'] is True
assert ev['owner_visual_observation']['show_less_visible'] is True
assert ev['owner_visual_observation']['duplicate_keys']==[]
assert ev['owner_visual_observation']['postgres_dsn_masked'] is True
assert ev['owner_visual_observation']['port_observed']=='10000'
assert ev['provider_read_observation']['branch']=='main'
assert ev['provider_read_observation']['auto_deploy']=='no'
assert ev['provider_read_observation']['auto_deploy_trigger']=='off'
assert ev['provider_read_observation']['new_deploy_detected'] is False
assert ev['provider_read_observation']['live_deploy_status']=='live'
print('DEVELOPMENT Render runtime config final verification v1 execution: PASS (COMPLETED/SUCCEEDED/PASS; exact nine nonsecret values; no duplicates; secret masked; no deploy)')
