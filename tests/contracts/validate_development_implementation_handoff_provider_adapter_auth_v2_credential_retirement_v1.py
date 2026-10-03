#!/usr/bin/env python3
from __future__ import annotations
import hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; sys.path.insert(0,str(ROOT/'src'))
from avuhz_engineering.authorization_plan import approval_digest,canonical_digest,plan_digest,validate_approval,validate_plan,validate_progress
B=ROOT/'contracts/plans/v1'; S=ROOT/'contracts/schemas/v1'; N='development-implementation-handoff-provider-adapter-auth-v2-credential-retirement-v1'
PLAN_ID='daffe337-37e8-468e-a913-e751ccd282be'
PLAN_DIGEST='sha256:24b47e7b19e9471c333ac26720e9f82555aa670b4440277001ecc82211864972'
PROGRESS_ID='184f1b29-4141-4351-8b00-5dbbb5469546'
PROGRESS_DIGEST='sha256:dd76c23ff68cf784525699a53433c932f99221bc313ce99d031c1c3ef3889472'
STEP1_EVIDENCE='sha256:dabc212c5294062f269d67a27ac5b8f657305a38f8f5dd00203d6200b756e521'
STEP2_EVIDENCE='sha256:ac19e746e093e01e2c4bc139c50210d004daddb8e4ecfc90f3ed6a02a7766772'
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
 p=load(N+'.plan.json'); g=load(N+'.progress.json'); a=load(N+'.approval.json'); prep=load(N+'-preparation.evidence.json'); e1=load(N+'-step01-success.evidence.json'); e2=load(N+'-step02-success.evidence.json')
 validate_plan(p,S); validate_progress(p,g,S); validate_approval(p,a,S,p['authorization_window']['starts_at'])
 assert raw(N+'-preparation.evidence.json')==PREP
 assert p['plan_id']==PLAN_ID and p['plan_version']==1 and p['plan_digest']==PLAN_DIGEST==plan_digest(p)
 assert p['definition_status']=='READY_FOR_APPROVAL' and p['authority_effect']=='NONE_UNTIL_SEPARATELY_APPROVED'
 assert p['authorization_window']=={'binding_state':'BOUND','starts_at':'2026-10-03T16:00:00Z','expires_at':'2026-10-03T20:00:00Z'}
 assert a['plan_id']==PLAN_ID and a['plan_version']==1 and a['plan_digest']==PLAN_DIGEST
 assert a['owner_identity']=='github:AnonymousKoo' and a['decision']=='APPROVE' and a['environment']=='DEVELOPMENT'
 assert a['effective_at']=='2026-10-03T16:00:00Z' and a['expires_at']=='2026-10-03T20:00:00Z'
 assert a['approved_at']=='2026-10-03T15:50:52Z' and a['status']=='ACTIVE' and a['authority_scope']=='EXACT_PLAN_ONLY'
 assert a['approval_digest']==approval_digest(a)
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
 assert g['progress_id']==PROGRESS_ID and g['progress_digest']==PROGRESS_DIGEST and g['record_version']==5 and g['overall_state']=='IN_PROGRESS'
 st1,st2,st3,st4=g['step_states']
 assert st1['authorization_state']=='CONSUMED' and st1['execution_state']=='SUCCEEDED' and st1['verification_state']=='PASS' and st1['authorization_consumed'] is True
 assert st1['evidence']==[{'evidence_type':'auth.provider-adapter-admin-credential.retired','evidence_reference':N+'-step01-success.evidence.json','evidence_digest':STEP1_EVIDENCE,'recorded_at':'2026-10-03T16:13:47Z'}]
 assert st1['safe_error_code'] is None and st1['observed_postcondition']==s1['expected_postcondition']
 assert st2['authorization_state']=='CONSUMED' and st2['execution_state']=='SUCCEEDED' and st2['verification_state']=='PASS' and st2['authorization_consumed'] is True
 assert st2['evidence']==[{'evidence_type':'auth.provider-adapter-admin-github-binding.retired','evidence_reference':N+'-step02-success.evidence.json','evidence_digest':STEP2_EVIDENCE,'recorded_at':'2026-10-03T16:22:24Z'}]
 assert st2['safe_error_code'] is None and st2['observed_postcondition']==s2['expected_postcondition']
 assert all(st['authorization_state']=='PENDING' and st['execution_state']=='NOT_STARTED' and st['verification_state']=='NOT_STARTED' and st['authorization_consumed'] is False and st['evidence']==[] for st in (st3,st4))
 assert e1['evidence_digest']==STEP1_EVIDENCE==canonical_digest({k:v for k,v in e1.items() if k!='evidence_digest'})
 assert e1['project_reference']=='pwlhruwutoitnieactol' and e1['exact_key_name']==KEY and e1['owner_confirmed_deleted'] is True
 assert e1['postcondition_screenshot_observed'] is True and e1['provider_mutation_observed_by_agent'] is False and e1['other_key_mutation_observed'] is False
 assert e1['credential_material_read'] is False and e1['credential_material_retained'] is False and e1['credential_fragments_retained'] is False and e1['pii_retained'] is False and e1['screenshot_retained'] is False
 assert e2['evidence_digest']==STEP2_EVIDENCE==canonical_digest({k:v for k,v in e2.items() if k!='evidence_digest'})
 assert e2['repository']=='AnonymousKoo/avuhz-infra' and e2['environment_name']=='development' and e2['exact_secret_name']==SECRET
 assert e2['delete_command_accepted'] is True and e2['independent_absence_verified'] is False and e2['other_secret_mutation_performed'] is False
 assert e2['credential_material_read'] is False and e2['credential_material_retained'] is False and e2['pii_retained'] is False and e2['retry_performed'] is False
 assert prep['v2_observation']['overall_state']=='STOPPED' and prep['v2_observation']['progress_digest']==V2 and prep['v2_observation']['safe_error_code']=='SUPABASE_ADMIN_CREATE_USER_GENERATED_RANDOM_PASSWORD'
 assert prep['v2_observation']['identity_exists'] is True and prep['v2_observation']['identity_mutation_authorized_by_retirement'] is False
 assert prep['retirement_obligation']['evidence_digest']==OBLIGATION and prep['retirement_obligation']['trigger_satisfied']=='provider-adapter-auth-v2-permanently-stopped'
 assert prep['credential_reference']['supabase_key_label']==KEY and prep['credential_reference']['github_secret_reference']==SECRET and prep['credential_reference']['github_exact_reference_count']==1
 assert prep['credential_reference']['secret_value_requested'] is False and prep['credential_reference']['secret_value_observed'] is False and prep['credential_reference']['credential_material_digest_recorded'] is False
 assert all(v is False for v in prep['security_state'].values())
 rendered=''.join((B/(N+suf)).read_text() for suf in ('.plan.json','.progress.json','.approval.json','-preparation.evidence.json','-step01-success.evidence.json','-step02-success.evidence.json'))
 for forbidden in ('postgresql://','postgres://','password=','op://','sb_secret_'):
  assert forbidden not in rendered
 assert 'sekinfra' not in rendered.lower()
 print('DEVELOPMENT ImplementationHandoff provider-adapter Auth v2 credential retirement v1: PASS (STEPS 1-2 CONSUMED/SUCCEEDED/PASS; Steps 3-4 pending; identity untouched)')
if __name__=='__main__': main()
