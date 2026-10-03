#!/usr/bin/env python3
from __future__ import annotations
import hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; sys.path.insert(0,str(ROOT/'src'))
from avuhz_engineering.authorization_plan import approval_digest,initial_progress,plan_digest,validate_approval,validate_plan,validate_progress
from avuhz_runtime.implementation_handoff import canonical_digest
from avuhz_service.development_supabase_identity import DEVELOPMENT_IDENTITY_ALLOWLIST
B=ROOT/'contracts/plans/v1'; S=ROOT/'contracts/schemas/v1'; N='development-implementation-handoff-provider-adapter-auth-v2'
PLAN_ID='305d2d98-0d87-42bc-90a4-f0cd5e66ea7c'
PLAN_DIGEST='sha256:bef8d098f593a67bf476a17e76fcf17fbda9986c76ac765c2e2253d5904672b4'
PROGRESS_ID='2cd99bc6-ac29-4d11-b6ed-b60a10cb9385'
PROGRESS_DIGEST='sha256:b154f17aa4046480231c842409644bb02869d18500994c5bab51623e173aaea2'
EXECUTION_PROGRESS_DIGEST='sha256:4982f77e54f43b348b560ca2a6440370240a69ac0d463b2c886df7af08b4fc9d'
STOPPED_EVIDENCE_DIGEST='sha256:27223a97cdb9943ddff839826f035d4db883a78c3531ab6575a649fec87a028d'
PREP='sha256:87d896a8d669124728e1456f7a72cce2ceb0a38f666fee60ce9a7592de8a8ee1'
RESOURCE='sha256:aeb1e2d03130dc5d08c8fd733fd119149371ab695cd98e1c59b6326cdb4336ce'
REPAIR='sha256:6855a85f4d83696cab4d1de32af7f748ff443cb424f8330ad7cdd6e091219d1c'
BINDING='sha256:8ae9819436b467f9cef33b1aee8d363928643015e77d8014b2bef7bba4d49425'
V1='sha256:f4c4a299b032e3cb4460bf6d6c756de88a34cfad6d52e5cf9f645158e49d50fd'
HOOK='sha256:d756b6baa3fbd4fc743b80d436e6578e66806658855b3c669690eb95dc79814c'
SECRET='AVUHZ_DEVELOPMENT_SUPABASE_AUTH_IMPLEMENTATION_HANDOFF_ADAPTER_V2_EPHEMERAL'
def load(n): return json.loads((B/n).read_text())
def raw(n): return 'sha256:'+hashlib.sha256((B/n).read_bytes()).hexdigest()
def main():
 r=load(N+'.resource.json'); p=load(N+'.plan.json'); g=load(N+'.progress.json'); execp=load(N+'.execution-progress.json'); a=load(N+'.approval.json'); prep=load(N+'-preparation.evidence.json'); stopped=load(N+'-step01-stopped.evidence.json')
 validate_plan(p,S); validate_progress(p,g,S); validate_progress(p,execp,S); validate_approval(p,a,S,p['authorization_window']['starts_at'])
 assert raw(N+'-preparation.evidence.json')==PREP==r['required_preparation_evidence_digest']
 assert r['contract_digest']==RESOURCE==canonical_digest({k:v for k,v in r.items() if k!='contract_digest'})
 assert r['required_prior_v1_stopped_progress_digest']==V1
 assert r['required_credential_repair_completed_progress_digest']==REPAIR
 assert r['required_credential_repair_binding_evidence_digest']==BINDING
 assert r['required_hook_success_evidence_digest']==HOOK
 assert r['execution_secret_reference']==SECRET
 assert r['provider_identity_create_count_authorized']==1
 assert r['future_caller_type']=='PROVIDER_ADAPTER'
 assert r['future_capabilities']==['implementation_handoff:accept']
 assert r['future_authority_roles']==[]
 assert r['future_tenant_binding']=='SEPARATE_AUTHORIZATION_REQUIRED'
 for k in ('password_creation_authorized','password_hash_creation_authorized','app_metadata_change_authorized','user_metadata_change_authorized','tenant_binding_authorized','allowlist_binding_authorized','token_issue_authorized','session_issue_authorized','hook_change_authorized','data_operation_authorized','render_operation_authorized','n8n_operation_authorized','staging_authorized','production_authorized','raw_provider_subject_persistence_authorized','credential_material_persistence_authorized'):
  assert r[k] is False
 assert p['plan_id']==PLAN_ID and p['plan_version']==2 and p['plan_digest']==PLAN_DIGEST==plan_digest(p)
 assert p['authorization_window']=={'binding_state':'BOUND','starts_at':'2026-10-03T15:00:00Z','expires_at':'2026-10-03T19:00:00Z'}
 assert p['definition_status']=='READY_FOR_APPROVAL' and p['authority_effect']=='NONE_UNTIL_SEPARATELY_APPROVED'
 assert a['plan_id']==PLAN_ID and a['plan_version']==2 and a['plan_digest']==PLAN_DIGEST
 assert a['owner_identity']=='github:AnonymousKoo' and a['decision']=='APPROVE' and a['environment']=='DEVELOPMENT'
 assert a['effective_at']=='2026-10-03T15:00:00Z' and a['expires_at']=='2026-10-03T19:00:00Z'
 assert a['approved_at']=='2026-10-03T14:48:41Z' and a['status']=='ACTIVE' and a['authority_scope']=='EXACT_PLAN_ONLY'
 assert a['approval_digest']==approval_digest(a)
 assert len(p['steps'])==1
 s=p['steps'][0]
 assert s['operation']=='provider.auth-identity.create-one'
 assert s['execution_class']=='PROVIDER_MUTATION'
 assert s['resource']['exact_digest']==RESOURCE
 assert s['required_evidence']==[
  {'evidence_type':'auth.provider-adapter-v2.preparation.observed','source_step_id':None,'binding_state':'BOUND','exact_digest':PREP},
  {'evidence_type':'hook.enablement.verified','source_step_id':None,'binding_state':'BOUND','exact_digest':HOOK},
  {'evidence_type':'auth.provider-adapter-admin-github-binding.verified','source_step_id':None,'binding_state':'BOUND','exact_digest':BINDING},
  {'evidence_type':'authorization-plan.execution-progress','source_step_id':None,'binding_state':'BOUND','exact_digest':REPAIR},
 ]
 assert s['credential_policy']['allowed_classes']==['SUPABASE_AUTH_ADMIN_EPHEMERAL']
 assert s['credential_policy']['values_stored'] is False
 for x in ('password.set','password-hash.set','tenant-metadata.bind','server-allowlist.bind','token.issue','session.issue','v1.retry','credential-repair.modify','credential-retire'):
  assert x in s['prohibited_actions']
 for x in ('target.identity.already-exists','auth-user-count.mismatch','credential-repair.not-completed','credential-binding.absent','executor-capability.attestation.missing','credential-material.observed'):
  assert x in s['stop_conditions']
 b={x['binding_id']:x for x in s['binding_declarations']}
 assert b['binding.development.implementation-handoff.provider-adapter-auth-v2.v1-stopped-progress']['preapproval_value']['value']==V1
 assert b['binding.development.implementation-handoff.provider-adapter-auth-v2.credential-repair-progress']['preapproval_value']['value']==REPAIR
 assert b['binding.development.implementation-handoff.provider-adapter-auth-v2.credential-binding-evidence']['preapproval_value']['value']==BINDING
 assert b['binding.development.implementation-handoff.provider-adapter-auth-v2.execution-secret-reference']['preapproval_value']['value']==SECRET
 assert g==initial_progress(p,S,PROGRESS_ID,p['created_at'])
 assert g['progress_digest']==PROGRESS_DIGEST and g['overall_state']=='NOT_STARTED'
 assert execp['overall_state']=='STOPPED' and execp['progress_digest']==EXECUTION_PROGRESS_DIGEST and execp['record_version']==3
 st=execp['step_states'][0]
 assert st['authorization_state']=='CONSUMED' and st['execution_state']=='SUCCEEDED' and st['verification_state']=='FAIL' and st['authorization_consumed'] is True
 assert st['safe_error_code']=='SUPABASE_ADMIN_CREATE_USER_GENERATED_RANDOM_PASSWORD'
 assert raw(N+'-step01-stopped.evidence.json')==STOPPED_EVIDENCE_DIGEST
 assert st['evidence'][0]['evidence_digest']==STOPPED_EVIDENCE_DIGEST
 assert stopped['classification']=='IDENTITY_CREATED_WITH_PROVIDER_GENERATED_PASSWORD_HASH'
 assert stopped['primary_execution']['provider_mutation_succeeded'] is True and stopped['primary_execution']['password_supplied_by_executor'] is False
 assert stopped['duplicate_dispatch_observation']['create_step_skipped'] is True and stopped['duplicate_dispatch_observation']['provider_mutation_attempted'] is False
 assert stopped['postcondition_observation']['auth_user_count']==2 and stopped['postcondition_observation']['target_identity_count']==1
 assert stopped['postcondition_observation']['session_count']==0 and stopped['postcondition_observation']['refresh_token_count']==0
 assert stopped['postcondition_observation']['target_bcrypt_like_count']==1 and stopped['postcondition_observation']['target_encrypted_password_length']==60
 assert stopped['postcondition_observation']['target_tenant_bound_count']==0
 assert stopped['implementation_behavior']['admin_create_user_without_password_generates_random_password'] is True
 assert stopped['implementation_behavior']['generated_password_observed'] is False and stopped['implementation_behavior']['generated_password_hash_value_observed'] is False
 assert prep['auth_observation']=={'auth_user_count':1,'target_identity_count':0,'known_synthetic_user_count':1,'other_auth_user_count':0,'canonical_tenant_bound_user_count':1,'session_count':0,'refresh_token_count':0}
 assert prep['credential_repair_observation']['overall_state']=='COMPLETED'
 assert prep['credential_repair_observation']['all_steps_consumed_succeeded_pass'] is True
 assert prep['credential_repair_observation']['exact_reference_count']==1
 assert prep['credential_repair_observation']['secret_value_observed'] is False
 assert prep['prior_v1_observation']['overall_state']=='STOPPED'
 assert prep['prior_v1_observation']['retry_authorized'] is False
 assert prep['active_policy_observation']['provider_adapter_entry_active'] is False
 assert all(v is False for v in prep['security_state'].values())
 assert len(DEVELOPMENT_IDENTITY_ALLOWLIST)==1
 assert DEVELOPMENT_IDENTITY_ALLOWLIST[0].caller_type=='HUMAN'
 assert DEVELOPMENT_IDENTITY_ALLOWLIST[0].capabilities==frozenset({'engagement:read'})
 rendered=''.join((B/(N+suf)).read_text() for suf in ('.resource.json','.plan.json','.progress.json','.execution-progress.json','.approval.json','-preparation.evidence.json','-step01-stopped.evidence.json'))
 for forbidden in ('postgresql://','postgres://','password=','op://'):
  assert forbidden not in rendered
 assert 'sekinfra' not in rendered.lower()
 print('DEVELOPMENT ImplementationHandoff provider-adapter Auth v2: PASS (STOPPED; identity created but provider-generated password hash violated passwordless postcondition; retry unauthorized)')
if __name__=='__main__': main()
