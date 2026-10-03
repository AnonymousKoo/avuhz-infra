#!/usr/bin/env python3
from __future__ import annotations
import hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; sys.path.insert(0,str(ROOT/'src'))
from avuhz_engineering.authorization_plan import initial_progress,plan_digest,validate_plan,validate_progress
from avuhz_runtime.implementation_handoff import canonical_digest
B=ROOT/'contracts/plans/v1'; S=ROOT/'contracts/schemas/v1'; N='development-auth-implementation-handoff-provider-adapter-v1'
PLAN_ID='d9355efd-9d44-4702-93f6-c4a1edbe35b2'; PLAN_DIGEST='sha256:e321c789f7297da00167fefbab98cb1b1590ad51b20a9bafc90e9f9c87205bdb'
PROGRESS_ID='f9001e59-4d71-4ff3-a610-cc2f2bacae8e'; PROGRESS_DIGEST='sha256:8bbf60d38ef8b18e6c91cea5a9d31a1d454d55d03e3a58d504f0c0783ca2caf3'
RESOURCE_DIGEST='sha256:8f2400b60c7eab426333397ee3c57fe471e91cd0e14a37d2bcca602b9ed6e7d1'
ALLOWLIST='sha256:15d05b54d2f337ead4b4ed6f9881aef33c6063de29ed4501a805255e7999c2ba'
HOOK='sha256:d756b6baa3fbd4fc743b80d436e6578e66806658855b3c669690eb95dc79814c'
RUNTIME='sha256:fd0e493b53cdbe2a19b3ae7f59eaab9f495d5e75868ca8ea1f8a554fede82c26'
POLICY_COMMIT='86413b7bbbf8f4532f56962f9d4c45a2b84cc2f0'
def load(name): return json.loads((B/name).read_text())
def raw(name): return 'sha256:'+hashlib.sha256((B/name).read_bytes()).hexdigest()
def main():
 r=load(N+'.resource.json'); p=load(N+'.plan.json'); g=load(N+'.progress.json'); prep=load(N+'-preparation.evidence.json')
 validate_plan(p,S); validate_progress(p,g,S)
 assert not (B/(N+'.approval.json')).exists()
 assert r['contract_digest']==RESOURCE_DIGEST==canonical_digest({k:v for k,v in r.items() if k!='contract_digest'})
 assert r['environment']=='DEVELOPMENT' and r['provider']=='supabase' and r['responsibility']=='AUTH'
 assert r['project_reference']=='pwlhruwutoitnieactol'
 assert r['resource_reference']=='identity.development.implementation-handoff-provider-adapter'
 assert r['target_email']=='implementation-handoff-development-provider-adapter@example.invalid'
 assert r['provider_adapter_principal_reference']=='provider-adapter.implementation-handoff-development'
 assert r['target_caller_type']=='PROVIDER_ADAPTER'
 assert r['future_capability_exact']==['implementation_handoff:accept'] and r['future_authority_roles']==[]
 assert r['tenant_metadata_bound_by_this_plan'] is False and r['server_allowlist_bound_by_this_plan'] is False
 assert r['session_or_token_issue_authorized'] is False and r['hook_change_authorized'] is False
 assert r['data_operation_authorized'] is False and r['render_operation_authorized'] is False and r['n8n_operation_authorized'] is False
 assert r['staging_authorized'] is False and r['production_authorized'] is False
 assert r['required_provider_adapter_policy_commit']==POLICY_COMMIT
 assert raw('development-auth-step1-v26-success.evidence.json')==r['required_current_allowlist_evidence_digest']==ALLOWLIST
 assert raw('development-auth-step1-v28-success.evidence.json')==r['required_enabled_hook_evidence_digest']==HOOK
 assert raw('development-render-deployment-v10-step02-success.evidence.json')==r['required_live_handoff_runtime_evidence_digest']==RUNTIME
 assert r['password_material_policy']=={'required':True,'source':'OWNER_APPROVED_VAULT','agent_visibility':'PROHIBITED','repository_persistence':'PROHIBITED','logging':'PROHIBITED','digest':'PROHIBITED','return':'PROHIBITED','provider_entry':'OWNER_INTERACTIVE_ONLY'}
 assert p['plan_id']==PLAN_ID and p['plan_version']==1 and p['plan_digest']==PLAN_DIGEST==plan_digest(p)
 assert p['definition_status']=='READY_FOR_APPROVAL' and p['authority_effect']=='NONE_UNTIL_SEPARATELY_APPROVED'
 assert p['authorization_window']=={'binding_state':'BOUND','starts_at':'2026-10-03T03:30:00Z','expires_at':'2026-10-03T07:00:00Z'}
 assert len(p['steps'])==1 and p['ordered_step_ids']==[p['steps'][0]['step_id']]
 s=p['steps'][0]
 assert s['operation']=='provider.auth-identity.create-one' and s['execution_class']=='PROVIDER_MUTATION'
 assert s['credential_policy']=={'permitted':True,'allowed_classes':['OWNER_INTERACTIVE_SESSION'],'values_stored':False}
 assert s['resource']=={'resource_type':'auth.provider-adapter-identity','resource_reference':'identity.development.implementation-handoff-provider-adapter','binding_state':'BOUND','exact_version':'version.1','exact_digest':RESOURCE_DIGEST}
 assert [e['exact_digest'] for e in s['required_evidence']]==[
   raw('development-auth-integration-v26.execution-progress.json'),ALLOWLIST,HOOK,RUNTIME]
 for forbidden in ('tenant-metadata.bind','server-allowlist.bind','token.issue','session.issue','data.operation','render.operation','n8n.operation','production.target'):
  assert forbidden in s['prohibited_actions']
 for stop in ('identity.target-exists','session-state.drift','refresh-token-state.drift','hook.state.drift','allowlist.state.drift','password.vault-source-unconfirmed','credential-material.agent-visible'):
  assert stop in s['stop_conditions']
 b={x['binding_id']:x for x in s['binding_declarations']}
 assert b['binding.development.auth.implementation-handoff-provider-adapter-v1.current-allowlist']['preapproval_value']['value']==ALLOWLIST
 assert b['binding.development.auth.implementation-handoff-provider-adapter-v1.enabled-hook']['preapproval_value']['value']==HOOK
 assert b['binding.development.auth.implementation-handoff-provider-adapter-v1.live-handoff-runtime']['preapproval_value']['value']==RUNTIME
 assert b['binding.development.auth.implementation-handoff-provider-adapter-v1.policy-commit']['preapproval_value']['value']=='git.commit.'+POLICY_COMMIT
 assert b['binding.development.auth.implementation-handoff-provider-adapter-v1.live-preflight']['phase']=='RESOLVED_BY_STEP_PREFLIGHT'
 assert b['binding.development.auth.implementation-handoff-provider-adapter-v1.provider-subject']['phase']=='PRODUCED_BY_CURRENT_STEP'
 assert g==initial_progress(p,S,PROGRESS_ID,p['created_at']) and g['progress_digest']==PROGRESS_DIGEST and g['overall_state']=='NOT_STARTED'
 assert all(x['authorization_state']=='PENDING' and x['execution_state']=='NOT_STARTED' and not x['authorization_consumed'] for x in g['step_states'])
 o=prep['observation']
 assert (o['auth_user_count'],o['known_synthetic_user_count'],o['other_auth_user_count'])==(1,1,0)
 assert o['session_count']==0 and o['refresh_token_count']==0
 assert o['oidc_grant_types_supported']==['authorization_code','refresh_token'] and o['oidc_client_credentials_supported'] is False
 assert o['custom_access_token_hook_auth_admin_execute'] is True
 for key in ('custom_access_token_hook_anon_execute','custom_access_token_hook_authenticated_execute','custom_access_token_hook_service_role_execute','custom_access_token_hook_public_execute'): assert o[key] is False
 assert all(value is False for value in prep['security_state'].values())
 rendered=''.join((B/(N+suf)).read_text() for suf in ('.resource.json','.plan.json','.progress.json','-preparation.evidence.json'))
 for forbidden in ('password=','postgresql://','postgres://','sb_secret_','op://'): assert forbidden not in rendered
 print('DEVELOPMENT ImplementationHandoff provider-adapter identity v1: PASS (READY_FOR_APPROVAL; one dormant AUTH identity only; Vault/owner-interactive password; no tenant/allowlist/session/token/provider-spillover)')
 return 0
if __name__=='__main__': raise SystemExit(main())
