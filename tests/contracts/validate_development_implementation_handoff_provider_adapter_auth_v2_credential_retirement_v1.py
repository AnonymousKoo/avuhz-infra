#!/usr/bin/env python3
from __future__ import annotations
import hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; sys.path.insert(0,str(ROOT/'src'))
from avuhz_engineering.authorization_plan import initial_progress,plan_digest,validate_plan,validate_progress
B=ROOT/'contracts/plans/v1'; S=ROOT/'contracts/schemas/v1'; N='development-implementation-handoff-provider-adapter-auth-v2-credential-retirement-v1'
PLAN_ID='daffe337-37e8-468e-a913-e751ccd282be'
PLAN_DIGEST='sha256:24b47e7b19e9471c333ac26720e9f82555aa670b4440277001ecc82211864972'
PROGRESS_ID='184f1b29-4141-4351-8b00-5dbbb5469546'
PROGRESS_DIGEST='sha256:b3f7317d7b07f5bd3216016fe2f12002979194d7b9cff15ab3ade4b063c33858'
PREP='sha256:1711c63785c277ddd44e16a2b7f3f23db62ec0cf2c84749b7fc63ccc57cbe68e'
V2='sha256:4982f77e54f43b348b560ca2a6440370240a69ac0d463b2c886df7af08b4fc9d'
V2_EVIDENCE='sha256:27223a97cdb9943ddff839826f035d4db883a78c3531ab6575a649fec87a028d'
OBLIGATION='sha256:71691825841af99b46e16a9c00699afe28dfc8436246b53448d24e6c87979a6e'
BINDING='sha256:8ae9819436b467f9cef33b1aee8d363928643015e77d8014b2bef7bba4d49425'
SECRET='AVUHZ_DEVELOPMENT_SUPABASE_AUTH_IMPLEMENTATION_HANDOFF_ADAPTER_V2_EPHEMERAL'
KEY='implementation-handoff-provider-adapter-auth-v2-ephemeral'
def load(n): return json.loads((B/n).read_text())
def raw(n): return 'sha256:'+hashlib.sha256((B/n).read_bytes()).hexdigest()
def main():
 p=load(N+'.plan.json'); g=load(N+'.progress.json'); prep=load(N+'-preparation.evidence.json')
 validate_plan(p,S); validate_progress(p,g,S)
 assert not (B/(N+'.approval.json')).exists()
 assert raw(N+'-preparation.evidence.json')==PREP
 assert p['plan_id']==PLAN_ID and p['plan_version']==1 and p['plan_digest']==PLAN_DIGEST==plan_digest(p)
 assert p['definition_status']=='READY_FOR_APPROVAL' and p['authority_effect']=='NONE_UNTIL_SEPARATELY_APPROVED'
 assert p['authorization_window']=={'binding_state':'BOUND','starts_at':'2026-10-03T16:00:00Z','expires_at':'2026-10-03T20:00:00Z'}
 assert len(p['steps'])==4 and p['ordered_step_ids']==[s['step_id'] for s in p['steps']]
 s1,s2,s3,s4=p['steps']
 assert s1['operation']=='provider.auth-admin-credential.delete-dedicated-secret-key' and s1['execution_class']=='PROVIDER_MUTATION'
 assert s2['operation']=='provider.auth-secret-binding.delete-github-environment-reference' and s2['execution_class']=='PROVIDER_MUTATION'
 assert s3['operation']=='provider.auth-admin-credential.verify-dedicated-secret-key-absent' and s3['execution_class']=='PROVIDER_READ'
 assert s4['operation']=='provider.auth-secret-binding.verify-github-environment-reference-absent' and s4['execution_class']=='PROVIDER_READ'
 assert s2['dependency_step_ids']==[s1['step_id']] and s3['dependency_step_ids']==[s2['step_id']] and s4['dependency_step_ids']==[s3['step_id']]
 assert KEY in s1['resource']['resource_reference'] and KEY in s3['resource']['resource_reference']
 assert SECRET in s2['resource']['resource_reference'] and SECRET in s4['resource']['resource_reference']
 for s in p['steps']:
  for forbidden in ('identity.create','identity.delete','identity.modify','token.issue','session.issue','tenant-metadata.modify','data.operation','render.operation','n8n.operation','production.target'):
   assert forbidden in s['prohibited_actions']
 assert 'provider-adapter-auth-v2.retry' in p['prohibited_actions'] and 'provider-adapter-auth-correction.execute' in p['prohibited_actions']
 assert g==initial_progress(p,S,PROGRESS_ID,p['created_at']) and g['progress_digest']==PROGRESS_DIGEST and g['overall_state']=='NOT_STARTED'
 assert all(st['authorization_state']=='PENDING' and st['execution_state']=='NOT_STARTED' and st['authorization_consumed'] is False for st in g['step_states'])
 assert prep['v2_observation']['overall_state']=='STOPPED' and prep['v2_observation']['progress_digest']==V2 and prep['v2_observation']['safe_error_code']=='SUPABASE_ADMIN_CREATE_USER_GENERATED_RANDOM_PASSWORD'
 assert prep['v2_observation']['identity_exists'] is True and prep['v2_observation']['identity_mutation_authorized_by_retirement'] is False
 assert prep['retirement_obligation']['evidence_digest']==OBLIGATION and prep['retirement_obligation']['trigger_satisfied']=='provider-adapter-auth-v2-permanently-stopped'
 assert prep['credential_reference']['supabase_key_label']==KEY and prep['credential_reference']['github_secret_reference']==SECRET and prep['credential_reference']['github_exact_reference_count']==1
 assert prep['credential_reference']['secret_value_requested'] is False and prep['credential_reference']['secret_value_observed'] is False and prep['credential_reference']['credential_material_digest_recorded'] is False
 assert all(v is False for v in prep['security_state'].values())
 rendered=''.join((B/(N+suf)).read_text() for suf in ('.plan.json','.progress.json','-preparation.evidence.json'))
 for forbidden in ('postgresql://','postgres://','password=','op://','sb_secret_'):
  assert forbidden not in rendered
 assert 'sekinfra' not in rendered.lower()
 print('DEVELOPMENT ImplementationHandoff provider-adapter Auth v2 credential retirement v1: PASS (READY_FOR_APPROVAL; four-step exact retirement; identity untouched)')
if __name__=='__main__': main()
