#!/usr/bin/env python3
from __future__ import annotations
import json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; sys.path.insert(0,str(ROOT/'src'))
from avuhz_runtime.implementation_handoff import canonical_digest
from avuhz_engineering.authorization_plan import validate_plan,validate_progress
B=ROOT/'contracts/plans/v1'; S=ROOT/'contracts/schemas/v1'; N='development-render-data-supavisor-session-dsn-v2'
load=lambda s: json.load(open(B/s))
p=load(N+'.plan.json'); g=load(N+'.execution-progress.json'); e=load(N+'-success.evidence.json')
validate_plan(p,S); validate_progress(p,g,S)
assert g['overall_state']=='COMPLETED' and g['record_version']==2
st=g['step_states'][0]; assert (st['authorization_state'],st['execution_state'],st['verification_state'],st['authorization_consumed'])==('CONSUMED','SUCCEEDED','PASS',True)
assert st['evidence'][0]['evidence_type']=='runtime.render.data-supavisor-session-dsn.bound'
assert st['evidence'][0]['evidence_digest']==canonical_digest(e)
assert e['outcome']=='SUCCEEDED_VERIFIED' and e['classification']=='RENDER_DATA_SUPAVISOR_SESSION_DSN_SAVE_ONLY_BOUND_NO_DEPLOY'
assert e['provider_read_observation']['latest_live_deploy_id']=='dep-davkk6egekts73eefa40'
assert e['provider_read_observation']['latest_live_commit']=='43a9e1ccec2c1a2fd3eee530dd817981303caaba'
assert e['provider_read_observation']['second_deploy_detected'] is False
assert e['security_state']['credential_material_observed'] is False and e['security_state']['secret_material_recorded'] is False
assert e['runtime_verification']['readiness_http']==503 and e['runtime_verification']['readiness_data']=='unavailable'
assert e['runtime_verification']['runtime_readiness_deferred_reason']=='LIVE_ARTIFACT_PREDATES_SUPAVISOR_ENDPOINT_SUPPORT'
assert e['runtime_verification']['unauthenticated_commands_http']==401 and e['runtime_verification']['unauthenticated_queries_http']==401
assert e['postcondition_verification']['runtime_readiness_not_part_of_this_configuration_step_postcondition'] is True
rendered=(B/(N+'-success.evidence.json')).read_text()+(B/(N+'.execution-progress.json')).read_text()
for forbidden in ('password=', 'postgresql://', 'postgres://', 'op://'): assert forbidden not in rendered
print('DEVELOPMENT Render Supavisor session DSN v2 execution: PASS (COMPLETED/CONSUMED/SUCCEEDED/PASS; Save-only; no deploy; secret unobserved; runtime readiness deferred to deployment boundary)')
