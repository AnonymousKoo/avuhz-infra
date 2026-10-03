#!/usr/bin/env python3
from __future__ import annotations
import hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; sys.path.insert(0,str(ROOT/'src'))
from avuhz_engineering.authorization_plan import initial_progress,plan_digest,validate_plan,validate_progress
from avuhz_runtime.implementation_handoff import canonical_digest
from avuhz_service.development_supabase_identity import DEVELOPMENT_IDENTITY_ALLOWLIST
B=ROOT/'contracts/plans/v1'; S=ROOT/'contracts/schemas/v1'; N='development-implementation-handoff-provider-adapter-auth-v2'
PLAN_ID='305d2d98-0d87-42bc-90a4-f0cd5e66ea7c'
PLAN_DIGEST='sha256:bef8d098f593a67bf476a17e76fcf17fbda9986c76ac765c2e2253d5904672b4'
PROGRESS_ID='2cd99bc6-ac29-4d11-b6ed-b60a10cb9385'
PROGRESS_DIGEST='sha256:b154f17aa4046480231c842409644bb02869d18500994c5bab51623e173aaea2'
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
 r=load(N+'.resource.json'); p=load(N+'.plan.json'); g=load(N+'.progress.json'); prep=load(N+'-preparation.evidence.json')
 validate_plan(p,S); validate_progress(p,g,S)
 assert not (B/(N+'.approval.json')).exists()
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
 rendered=''.join((B/(N+suf)).read_text() for suf in ('.resource.json','.plan.json','.progress.json','-preparation.evidence.json'))
 for forbidden in ('postgresql://','postgres://','password=','op://'):
  assert forbidden not in rendered
 assert 'sekinfra' not in rendered.lower()
 print('DEVELOPMENT ImplementationHandoff provider-adapter Auth v2: PASS (READY_FOR_APPROVAL; repaired credential bound; one passwordless identity only; tenant/allowlist/token/session deferred)')
if __name__=='__main__': main()
