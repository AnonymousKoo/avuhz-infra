#!/usr/bin/env python3
from __future__ import annotations
import hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; sys.path.insert(0,str(ROOT/'src'))
from avuhz_engineering.authorization_plan import initial_progress,plan_digest,validate_plan,validate_progress
from avuhz_runtime.implementation_handoff import canonical_digest
from avuhz_service.development_supabase_identity import DEVELOPMENT_IDENTITY_ALLOWLIST
B=ROOT/'contracts/plans/v1'; S=ROOT/'contracts/schemas/v1'; N='development-implementation-handoff-provider-adapter-auth-v1'
PLAN_ID='644f239b-c7cb-4c30-85a4-95efbfe85ae4'
PLAN_DIGEST='sha256:67b9ebbcd55612edbfbdc3f51f6b8288abd92d3ecef2c35c88cddfa72f5d49fb'
PROGRESS_ID='3f600043-dc92-46a4-bdcf-db5d7924adc2'
PROGRESS_DIGEST='sha256:59dc64ce68a40e234e1426fc3cd0ee8ede0ce36509817e1ca65709777995cda1'
RESOURCE_DIGEST='sha256:fd3c01a78d49a500dd576f888cc4ad60d2da1af304286cd844f4a8b40a362510'
PREP='sha256:e4c194acf40408cff3b0063654dbead723d247415823777fc35cc2c077ac7456'
V28='sha256:d756b6baa3fbd4fc743b80d436e6578e66806658855b3c669690eb95dc79814c'
POLICY='86413b7bbbf8f4532f56962f9d4c45a2b84cc2f0'
EMAIL='avuhz-implementation-handoff-provider-adapter-development@example.invalid'
def load(n): return json.loads((B/n).read_text())
def raw(n): return 'sha256:'+hashlib.sha256((B/n).read_bytes()).hexdigest()
def main():
 r=load(N+'.resource.json'); p=load(N+'.plan.json'); g=load(N+'.progress.json'); prep=load(N+'-preparation.evidence.json'); v28=load('development-auth-step1-v28-success.evidence.json')
 validate_plan(p,S); validate_progress(p,g,S)
 assert not (B/(N+'.approval.json')).exists()
 assert raw(N+'-preparation.evidence.json')==PREP==r['required_preparation_evidence_digest']
 assert r['contract_digest']==RESOURCE_DIGEST==canonical_digest({k:v for k,v in r.items() if k!='contract_digest'})
 assert r['project_reference']=='pwlhruwutoitnieactol' and r['responsibility']=='AUTH' and r['target_email']==EMAIL
 assert r['provider_identity_create_count_authorized']==1 and r['email_confirmed_required'] is True
 assert r['future_principal_reference']=='provider-adapter.implementation-handoff-development' and r['future_caller_type']=='PROVIDER_ADAPTER'
 assert r['future_capabilities']==['implementation_handoff:accept'] and r['future_authority_roles']==[]
 assert r['future_tenant_binding']=='SEPARATE_AUTHORIZATION_REQUIRED'
 assert r['fresh_preflight_expected']=={'auth_user_count':1,'target_identity_count':0,'known_synthetic_user_count':1,'other_auth_user_count':0,'canonical_tenant_bound_user_count':1,'session_count':0,'refresh_token_count':0}
 for k in ('password_creation_authorized','password_hash_creation_authorized','app_metadata_change_authorized','user_metadata_change_authorized','tenant_binding_authorized','allowlist_binding_authorized','token_issue_authorized','session_issue_authorized','hook_change_authorized','data_operation_authorized','render_operation_authorized','n8n_operation_authorized','staging_authorized','production_authorized','raw_provider_subject_persistence_authorized','credential_material_persistence_authorized'): assert r[k] is False
 assert raw('development-auth-step1-v28-success.evidence.json')==V28==r['required_hook_success_evidence_digest']
 assert v28['outcome']=='SUCCEEDED_VERIFIED' and v28['provider_observation']['custom_access_token_hook_enabled'] is True
 assert r['required_provider_adapter_policy_commit']==POLICY
 assert p['plan_id']==PLAN_ID and p['plan_version']==1 and p['plan_digest']==PLAN_DIGEST==plan_digest(p)
 assert p['authorization_window']=={'binding_state':'BOUND','starts_at':'2026-10-03T03:30:00Z','expires_at':'2026-10-03T07:30:00Z'}
 assert p['definition_status']=='READY_FOR_APPROVAL' and p['authority_effect']=='NONE_UNTIL_SEPARATELY_APPROVED'
 assert len(p['steps'])==1; s=p['steps'][0]
 assert s['operation']=='provider.auth-identity.create-one' and s['execution_class']=='PROVIDER_MUTATION'
 assert s['resource']=={'resource_type':'auth.provider-adapter-identity','resource_reference':'identity.development.provider-adapter.implementation-handoff','binding_state':'BOUND','exact_version':'version.1','exact_digest':RESOURCE_DIGEST}
 assert s['required_evidence']==[
  {'evidence_type':'auth.provider-adapter.preparation.observed','source_step_id':None,'binding_state':'BOUND','exact_digest':PREP},
  {'evidence_type':'hook.enablement.verified','source_step_id':None,'binding_state':'BOUND','exact_digest':V28},
 ]
 assert s['credential_policy']['allowed_classes']==['SUPABASE_AUTH_ADMIN_EPHEMERAL'] and s['credential_policy']['values_stored'] is False
 assert s['credential_policy']['ephemeral_handling']['control_plane_visibility']=='CLASS_LABEL_ONLY'
 for x in ('password.set','password-hash.set','tenant-metadata.bind','server-allowlist.bind','token.issue','session.issue','data.operation','render.operation','n8n.operation','production.target','credential.persist','credential.expose','credential.log','credential.return','credential.digest','credential.copy','credential.create','credential.rotate','credential.export'): assert x in s['prohibited_actions']
 for x in ('target.identity.already-exists','auth-user-count.mismatch','known-synthetic-identity.mismatch','canonical-tenant-binding.mismatch','session-state.drift','refresh-token-state.drift','hook-state.drift','allowlist-state.drift','provider-adapter-policy.not-ancestor-of-main','executor-capability.attestation.missing','credential-material.observed'): assert x in s['stop_conditions']
 b={x['binding_id']:x for x in s['binding_declarations']}
 assert b['binding.development.implementation-handoff.provider-adapter-auth-v1.preparation']['preapproval_value']['value']==PREP
 assert b['binding.development.implementation-handoff.provider-adapter-auth-v1.hook-v28']['preapproval_value']['value']==V28
 assert b['binding.development.implementation-handoff.provider-adapter-auth-v1.policy-commit']['preapproval_value']['value']=='git.commit.'+POLICY
 assert b['binding.development.implementation-handoff.provider-adapter-auth-v1.admin-executor-capability']['phase']=='RESOLVED_BY_STEP_PREFLIGHT'
 assert b['binding.development.implementation-handoff.provider-adapter-auth-v1.identity-create-preflight']['phase']=='RESOLVED_BY_STEP_PREFLIGHT'
 assert b['binding.development.implementation-handoff.provider-adapter-auth-v1.identity']['phase']=='PRODUCED_BY_CURRENT_STEP'
 assert g==initial_progress(p,S,PROGRESS_ID,p['created_at']) and g['progress_digest']==PROGRESS_DIGEST and g['overall_state']=='NOT_STARTED'
 assert len(DEVELOPMENT_IDENTITY_ALLOWLIST)==1 and DEVELOPMENT_IDENTITY_ALLOWLIST[0].caller_type=='HUMAN' and DEVELOPMENT_IDENTITY_ALLOWLIST[0].capabilities==frozenset({'engagement:read'})
 o=prep['observation']
 assert (o['auth_user_count'],o['target_identity_count'],o['known_synthetic_user_count'],o['other_auth_user_count'],o['canonical_tenant_bound_user_count'])==(1,0,1,0,1)
 assert o['session_count']==0 and o['refresh_token_count']==0
 assert o['custom_access_token_hook_live_function']=='public.avuhz_development_custom_access_token_hook_v1(jsonb)'
 assert o['custom_access_token_hook_live_function_owner']=='avuhz_migration_service_dev' and o['custom_access_token_hook_live_security_definer'] is False and o['custom_access_token_hook_live_search_path']=='pg_catalog' and o['custom_access_token_hook_live_volatility']=='STABLE'
 assert o['custom_access_token_hook_auth_admin_execute'] is True
 for k in ('custom_access_token_hook_anon_execute','custom_access_token_hook_authenticated_execute','custom_access_token_hook_service_role_execute','custom_access_token_hook_public_execute'): assert o[k] is False
 assert o['oidc_issuer']=='https://pwlhruwutoitnieactol.supabase.co/auth/v1' and o['oidc_grant_types_supported']==['authorization_code','refresh_token'] and o['oidc_response_types_supported']==['code'] and o['oidc_client_credentials_supported'] is False
 d=prep['design_consequence']; assert d['existing_synthetic_human_identity_reused'] is False and d['credential_binding_deferred'] is True and d['tenant_binding_deferred'] is True and d['server_allowlist_binding_deferred'] is True
 assert all(v is False for v in prep['security_state'].values())
 rendered=''.join((B/(N+suf)).read_text() for suf in ('.resource.json','.plan.json','.progress.json','-preparation.evidence.json'))
 for forbidden in ('postgresql://','postgres://','password=','op://','service_role_key','sb_secret_'): assert forbidden not in rendered
 print('DEVELOPMENT ImplementationHandoff provider-adapter Auth v1: PASS (READY_FOR_APPROVAL; one passwordless confirmed AUTH identity only; no tenant/allowlist/password/token/session/downstream provider effect)')
 return 0
if __name__=='__main__': raise SystemExit(main())
