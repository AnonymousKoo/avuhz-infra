#!/usr/bin/env python3
from __future__ import annotations
import hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; sys.path.insert(0,str(ROOT/'src'))
from avuhz_engineering.authorization_plan import approval_digest,initial_progress,plan_digest,validate_approval,validate_plan,validate_progress
from avuhz_runtime.implementation_handoff import canonical_digest
B=ROOT/'contracts/plans/v1'; S=ROOT/'contracts/schemas/v1'; N='development-implementation-handoff-provider-adapter-auth-credential-repair-v1'
PLAN_ID='b2b5dbda-4731-4719-bbea-eda18500a500'
PLAN_DIGEST='sha256:2165ef7e1ccff8b569803c239cf5212fd15b97433c47eaf9cc871813a841c90a'
PROGRESS_ID='f7c411a8-cba2-40df-a4ef-c618f8d544aa'
PROGRESS_DIGEST='sha256:52accaa6ed39056d0c56f07e1106988085d59a68598506b4d611cbd187a4d11c'
EXECUTION_PROGRESS_DIGEST='sha256:6855a85f4d83696cab4d1de32af7f748ff443cb424f8330ad7cdd6e091219d1c'
STEP_EVIDENCE_DIGESTS=['sha256:7a6c392545895f25635b1e65e3ec57f596407448564badb1200b02feb5529bfb','sha256:ef08267a86fdff18eddbba499275110ece6259988d55e2323dffb05bb41fc823','sha256:8ae9819436b467f9cef33b1aee8d363928643015e77d8014b2bef7bba4d49425','sha256:71691825841af99b46e16a9c00699afe28dfc8436246b53448d24e6c87979a6e']
PREP='sha256:22b28735f92cc861a5ec8a8bb675fa89b2c3cb47e4231f7ddf4889ffc20248bf'
FAIL='sha256:1e31607337b069824b2a444313c7394c4ade0575139e90d9726b0a651bf44956'
V1_PROGRESS='sha256:f4c4a299b032e3cb4460bf6d6c756de88a34cfad6d52e5cf9f645158e49d50fd'
SECRET='AVUHZ_DEVELOPMENT_SUPABASE_AUTH_IMPLEMENTATION_HANDOFF_ADAPTER_V2_EPHEMERAL'
def load(n): return json.loads((B/n).read_text())
def raw(n): return 'sha256:'+hashlib.sha256((B/n).read_bytes()).hexdigest()
def main():
 p=load(N+'.plan.json'); g=load(N+'.progress.json'); x=load(N+'.execution-progress.json'); a=load(N+'.approval.json'); prep=load(N+'-preparation.evidence.json'); v1=load('development-implementation-handoff-provider-adapter-auth-v1.execution-progress.json')
 validate_plan(p,S); validate_progress(p,g,S); validate_progress(p,x,S); validate_approval(p,a,S,p['authorization_window']['starts_at'])
 assert raw(N+'-preparation.evidence.json')==PREP
 assert raw('development-implementation-handoff-provider-adapter-auth-v1-step01-failure.evidence.json')==FAIL
 assert v1['overall_state']=='STOPPED' and v1['progress_digest']==V1_PROGRESS
 assert v1['step_states'][0]['authorization_state']=='CONSUMED' and v1['step_states'][0]['execution_state']=='FAILED' and v1['step_states'][0]['authorization_consumed'] is True
 assert p['plan_id']==PLAN_ID and p['plan_version']==1 and p['plan_digest']==PLAN_DIGEST==plan_digest(p)
 assert p['definition_status']=='READY_FOR_APPROVAL' and p['authority_effect']=='NONE_UNTIL_SEPARATELY_APPROVED'
 assert a['plan_id']==PLAN_ID and a['plan_version']==1 and a['plan_digest']==PLAN_DIGEST
 assert a['owner_identity']=='github:AnonymousKoo' and a['decision']=='APPROVE' and a['environment']=='DEVELOPMENT'
 assert a['effective_at']=='2026-10-03T11:30:00Z' and a['expires_at']=='2026-10-03T15:30:00Z'
 assert a['approved_at']=='2026-10-03T10:14:43Z' and a['status']=='ACTIVE' and a['authority_scope']=='EXACT_PLAN_ONLY'
 assert a['approval_digest']==approval_digest(a)
 assert p['authorization_window']=={'binding_state':'BOUND','starts_at':'2026-10-03T11:30:00Z','expires_at':'2026-10-03T15:30:00Z'}
 assert len(p['steps'])==4 and p['ordered_step_ids']==[x['step_id'] for x in p['steps']]
 s1,s2,s3,s4=p['steps']
 assert s1['operation']=='provider.auth-admin-credential.create-dedicated-secret-key' and s1['execution_class']=='PROVIDER_MUTATION'
 assert s2['operation']=='provider.auth-secret-binding.create-github-environment-reference' and s2['execution_class']=='PROVIDER_MUTATION'
 assert s3['operation']=='provider.auth-secret-binding.verify-github-environment-reference' and s3['execution_class']=='PROVIDER_READ'
 assert s4['operation']=='local.auth-credential-retirement-requirement.seal' and s4['execution_class']=='LOCAL_ONLY'
 assert s2['dependency_step_ids']==[s1['step_id']] and s3['dependency_step_ids']==[s2['step_id']] and s4['dependency_step_ids']==[s3['step_id']]
 assert s1['required_evidence']==[
  {'evidence_type':'auth.provider-adapter-credential-repair.preparation.observed','source_step_id':None,'binding_state':'BOUND','exact_digest':PREP},
  {'evidence_type':'auth.provider-adapter-identity.created','source_step_id':None,'binding_state':'BOUND','exact_digest':FAIL},
  {'evidence_type':'authorization-plan.execution-progress','source_step_id':None,'binding_state':'BOUND','exact_digest':V1_PROGRESS},
 ]
 assert SECRET in s2['resource']['resource_reference'] and SECRET in s3['resource']['resource_reference'] and SECRET in s2['expected_postcondition'] and SECRET in s4['expected_postcondition']
 assert 'identity.create' in s1['prohibited_actions'] and 'identity.create' in p['prohibited_actions']
 assert 'retired-credential.reuse' in s1['prohibited_actions'] and 'service-role.use' in s1['prohibited_actions']
 assert s1['credential_policy']=={'permitted':True,'allowed_classes':['OWNER_INTERACTIVE_SESSION'],'values_stored':False}
 assert s2['credential_policy']=={'permitted':True,'allowed_classes':['OWNER_INTERACTIVE_SESSION'],'values_stored':False}
 assert s3['credential_policy']=={'permitted':True,'allowed_classes':['OWNER_INTERACTIVE_SESSION'],'values_stored':False}
 assert s4['credential_policy']=={'permitted':False,'allowed_classes':['NONE'],'values_stored':False}
 assert g==initial_progress(p,S,PROGRESS_ID,p['created_at']) and g['progress_digest']==PROGRESS_DIGEST and g['overall_state']=='NOT_STARTED'
 assert all(x['authorization_state']=='PENDING' and x['execution_state']=='NOT_STARTED' and not x['authorization_consumed'] for x in g['step_states'])
 assert x['overall_state']=='COMPLETED' and x['progress_digest']==EXECUTION_PROGRESS_DIGEST and x['record_version']==9
 assert all(st['authorization_state']=='CONSUMED' and st['execution_state']=='SUCCEEDED' and st['verification_state']=='PASS' and st['authorization_consumed'] is True for st in x['step_states'])
 for i,d in enumerate(STEP_EVIDENCE_DIGESTS,1):
  assert raw(f'{N}-step{i:02d}-success.evidence.json')==d
  assert x['step_states'][i-1]['evidence'][0]['evidence_digest']==d
 assert load(N+'-step03-success.evidence.json')['sanitized_result']['exact_reference_count']==1
 assert load(N+'-step04-success.evidence.json')['sanitized_result']['retirement_performed'] is False
 assert prep['prior_boundary']['safe_error_code']=='AUTH_ADMIN_EXECUTOR_CREDENTIAL_UNAVAILABLE' and prep['prior_boundary']['provider_contact_attempted'] is False and prep['prior_boundary']['provider_mutation_attempted'] is False and prep['prior_boundary']['identity_created'] is False
 assert prep['github_observation']['target_secret_reference']==SECRET and prep['github_observation']['target_secret_reference_present'] is False
 assert prep['github_observation']['retired_bootstrap_reference_present'] is False and prep['github_observation']['secret_values_requested'] is False and prep['github_observation']['secret_values_observed'] is False
 assert prep['auth_observation']=={'auth_user_count':1,'target_identity_count':0,'session_count':0,'refresh_token_count':0}
 assert prep['design_consequence']['retired_bootstrap_reuse_allowed'] is False and prep['design_consequence']['fresh_dedicated_key_required'] is True and prep['design_consequence']['identity_creation_deferred'] is True and prep['design_consequence']['retirement_required_after_continuation'] is True
 assert all(v is False for v in prep['security_state'].values())
 rendered=''.join((B/(N+suf)).read_text() for suf in ('.plan.json','.progress.json','.execution-progress.json','.approval.json','-preparation.evidence.json')) + ''.join((B/f'{N}-step{i:02d}-success.evidence.json').read_text() for i in range(1,5))
 for forbidden in ('postgresql://','postgres://','password=','op://','sb_secret_'):
  if forbidden=='sb_secret_':
   # shape-only contract mention is allowed; no credential value may exist.
   assert rendered.count('sb_secret_*')>=1 and 'sb_secret_' not in rendered.replace('sb_secret_*','')
  else: assert forbidden not in rendered
 assert 'sekinfra' not in rendered.lower()
 print('DEVELOPMENT ImplementationHandoff provider-adapter Auth credential repair v1: PASS (COMPLETED; dedicated key created, exact GitHub binding present, names-only verification passed, retirement obligation sealed; identity creation still deferred)')
 return 0
if __name__=='__main__': raise SystemExit(main())
