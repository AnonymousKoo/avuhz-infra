#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'src'))
sys.path.insert(0,str(ROOT))

from avuhz_engineering.authorization_plan import approval_digest, plan_digest, progress_digest, validate_approval, validate_plan, validate_progress
from avuhz_runtime.implementation_handoff import canonical_digest

ROOT=Path(__file__).resolve().parents[2]
B=ROOT/'contracts/plans/v1'
S=ROOT/'contracts/schemas/v1'
N='development-implementation-handoff-provider-adapter-positive-auth-v4-stale-credential-retirement-v2'
RESOURCE='sha256:f64da257fe32bb578bdb2936e6251675e4e61b429db87013b3c2ee53bb823f97'
PREP='sha256:6279108dd1dbf7dad319d977a82c954b7fcc768916af058fbfc2a14d59000bdd'
PLAN='sha256:b012b3340f63afc8838d0516ca83c3a7b51d8c829528c40be0050a4cd48cef15'
PROGRESS='sha256:2deb6de046900a2b061cd2201f401f07f5b96f7db71e0df8923bb60c08abd3b8'
STEP1_EVIDENCE='sha256:be725bbc76a0a601dcf6fec23a34fa7e32a94a672074056f57c1d81764db0d40'
STEP1_PROGRESS='sha256:5b58118b2f4b06a21f759f213fb1539ff51f7a6a8ce9a7517ee1dd8f8e77434b'
STEP2_EVIDENCE='sha256:89596d6e8895213059840d3af8b84202bee52b4069365afa5df8e75ec11d9a7e'
STEP3_EVIDENCE='sha256:6248e91633b2274b7d4e953426fc2dbb542df7d2ea051d801a3252ea3bef0da0'
STEP4_EVIDENCE='sha256:c9da22e43c568c9f276eb86c78ce730b394740bb02161afc9adbd4cd6c66b98f'
EXECUTION_PROGRESS='sha256:d6a071034f35d1ddf55f3265286e964687f9879a711c02e4fd63f6f2644be0c1'
STEP4_RECORDED_AT='2026-10-05T13:40:36Z'
STEP3_RECORDED_AT='2026-10-05T13:32:42Z'
STEP2_RECORDED_AT='2026-10-05T13:16:06Z'
STEP1_RECORDED_AT='2026-10-05T13:05:10Z'
APPROVAL_ID='1106bbbb-87c1-5a96-8df7-a2a065e87286'
APPROVAL='sha256:ec2550fa0937ef31b17ac1579713509bf0e14abfb75e7714a390c83a50080ca1'
APPROVAL_FILE='sha256:a6401b89349955a1f0a048239de908925aac688f2c2803c4d616fa4e60a600b8'
APPROVED_AT='2026-10-05T12:07:29Z'
ZERO='sha256:15a15f8d6ad651d2140423e63fa5de42c42c9e6a6f18187e875b5386a6c9315d'
ZERO_PROGRESS='sha256:4c99f4933785fe8cc77c6379c957bb2e76a0bd7ec94be7b20dc8a2c84bcf93c1'
START='2026-10-05T13:00:00Z'
END='2026-10-05T17:00:00Z'

def load(suffix: str) -> dict:
    return json.loads((B/(N+suffix)).read_text())

def main() -> None:
    r=load('.resource.json'); e=load('-preparation.evidence.json'); p=load('.plan.json'); g=load('.progress.json'); a=load('.approval.json')
    assert r['contract_digest']==RESOURCE==canonical_digest({k:v for k,v in r.items() if k!='contract_digest'})
    assert e['evidence_digest']==PREP==canonical_digest({k:v for k,v in e.items() if k!='evidence_digest'})
    assert p['plan_digest']==PLAN==plan_digest(p)
    assert g['progress_digest']==PROGRESS==progress_digest(g)
    validate_plan(p,S); validate_progress(p,g,S); validate_approval(p,a,S,START)
    assert p['environment']=='DEVELOPMENT' and p['target']['project_reference']=='pwlhruwutoitnieactol' and p['target']['responsibility']=='AUTH'
    assert p['authorization_window']=={'binding_state':'BOUND','starts_at':START,'expires_at':END}
    assert p['authority_effect']=='NONE_UNTIL_SEPARATELY_APPROVED' and p['definition_status']=='READY_FOR_APPROVAL'
    assert g['overall_state']=='NOT_STARTED'
    assert len(p['steps'])==4 and len(g['step_states'])==4
    assert all((s['authorization_state'],s['execution_state'],s['verification_state'],s['authorization_consumed'])==('PENDING','NOT_STARTED','NOT_STARTED',False) for s in g['step_states'])
    assert r['lineage']['corrective_zero_state_evidence_digest']==ZERO and r['lineage']['corrective_zero_state_execution_progress_digest']==ZERO_PROGRESS
    assert r['lineage']['corrective_zero_state_result']=={'session_count':0,'refresh_token_count':0}
    assert r['authorized_counts']=={'supabase_key_delete':1,'supabase_key_absence_read':1,'github_environment_secret_delete':1,'github_secret_absence_read':1,'credential_create':0,'session_issue':0,'token_issue':0,'implementation_handoff_execute':0,'auth_retry':0}
    assert r['retirement_interactions']['step1']['interaction_surface']=='supabase.dashboard.settings.api-keys'
    assert r['retirement_interactions']['step1']['execution_actor']=='OWNER_MANUAL_FIREFOX'
    assert r['retirement_interactions']['step2']['interaction_surface']=='supabase.dashboard.settings.api-keys'
    assert r['retirement_interactions']['step2']['execution_actor']=='OWNER_MANUAL_FIREFOX'
    assert r['retirement_interactions']['step3']['interaction_surface']=='github.cli.gh-secret-delete'
    assert r['retirement_interactions']['step3']['execution_actor']=='AGENT_AUTHENTICATED_GH_CLI'
    assert r['retirement_interactions']['step4']['interaction_surface']=='github.cli.gh-secret-list'
    assert r['retirement_interactions']['step4']['execution_actor']=='AGENT_AUTHENTICATED_GH_CLI'
    required={(x['evidence_type'],x['exact_digest']) for x in p['steps'][0]['required_evidence']}
    assert ('auth.provider-adapter-positive-auth.cleanup.verified',ZERO) in required
    assert ('authorization-plan.execution-progress',ZERO_PROGRESS) in required
    assert ('auth.provider-adapter-positive-auth.stale-credential-retirement.prepared',PREP) in required
    rendered='\n'.join((B/(N+s)).read_text() for s in ('.resource.json','-preparation.evidence.json','.plan.json','.progress.json','.approval.json','-step1-success.evidence.json','-step2-success.evidence.json','-step3-success.evidence.json','-step4-success.evidence.json','.execution-progress.json'))
    for forbidden in ('service_role','sb_secret_','access-material','refresh-material','Bearer eyJ'):
        assert forbidden not in rendered
    assert a['approval_id']==APPROVAL_ID and a['plan_id']==p['plan_id'] and a['plan_version']==2 and a['plan_digest']==PLAN
    assert a['owner_identity']=='github:AnonymousKoo' and a['decision']=='APPROVE' and a['environment']=='DEVELOPMENT'
    assert a['effective_at']==START and a['expires_at']==END and a['approved_at']==APPROVED_AT and APPROVED_AT < START
    assert a['status']=='ACTIVE' and a['authority_scope']=='EXACT_PLAN_ONLY' and a['approval_digest']==APPROVAL==approval_digest(a)
    assert 'sha256:'+hashlib.sha256((B/(N+'.approval.json')).read_bytes()).hexdigest()==APPROVAL_FILE
    s1=load('-step1-success.evidence.json'); s2=load('-step2-success.evidence.json'); s3=load('-step3-success.evidence.json'); s4=load('-step4-success.evidence.json'); x=load('.execution-progress.json')
    assert canonical_digest(s1)==STEP1_EVIDENCE and s1['evidence_type']=='auth.provider-adapter-positive-auth.admin-credential.retired'
    assert s1['record_basis']=='OWNER_CONFIRMED_SANITIZED_EXECUTION_OUTCOME' and s1['independent_absence_verification_required'] is True
    assert s1['sanitized_result']=={'key_name':'impl_handoff_provider_adapter_positive_auth_v4_ephemeral','retirement_reported_by_owner':True,'credential_material_observed':False,'other_key_change_reported':False}
    assert s1['authorization_observation']['interaction_surface']=='supabase.dashboard.settings.api-keys' and s1['authorization_observation']['execution_actor']=='OWNER_MANUAL_FIREFOX'
    assert s1['recorded_at']==STEP1_RECORDED_AT and all(v is False for k,v in s1['security_state'].items() if k!='credential_material_observed') and s1['security_state']['credential_material_observed'] is False
    assert x['progress_digest']==EXECUTION_PROGRESS==progress_digest(x) and x['overall_state']=='COMPLETED' and x['record_version']==6
    assert (x['step_states'][0]['authorization_state'],x['step_states'][0]['execution_state'],x['step_states'][0]['verification_state'],x['step_states'][0]['authorization_consumed'])==('CONSUMED','SUCCEEDED','PASS',True)
    assert x['step_states'][0]['evidence']==[{'evidence_type':'auth.provider-adapter-positive-auth.admin-credential.retired','evidence_reference':N+'-step1-success.evidence.json','evidence_digest':STEP1_EVIDENCE,'recorded_at':STEP1_RECORDED_AT}]
    assert (x['step_states'][1]['authorization_state'],x['step_states'][1]['execution_state'],x['step_states'][1]['verification_state'],x['step_states'][1]['authorization_consumed'])==('CONSUMED','SUCCEEDED','PASS',True)
    assert x['step_states'][1]['evidence']==[{'evidence_type':'auth.provider-adapter-positive-auth.admin-credential.absence-verified','evidence_reference':N+'-step2-success.evidence.json','evidence_digest':STEP2_EVIDENCE,'recorded_at':STEP2_RECORDED_AT}]
    assert canonical_digest(s2)==STEP2_EVIDENCE and s2['record_basis']=='OWNER_CONFIRMED_SEPARATE_NAMES_ONLY_ABSENCE_INSPECTION' and s2['sanitized_result']['absence_reported_by_owner'] is True
    assert s2['authorization_observation']['interaction_surface']=='supabase.dashboard.settings.api-keys' and s2['authorization_observation']['execution_actor']=='OWNER_MANUAL_FIREFOX'
    assert canonical_digest(s3)==STEP3_EVIDENCE and s3['evidence_type']=='auth.provider-adapter-positive-auth.github-binding.retired'
    assert s3['record_basis']=='AGENT_AUTHENTICATED_GH_CLI_SANITIZED_EXECUTION_OUTCOME' and s3['independent_absence_verification_required'] is True
    assert s3['authorization_observation']['interaction_surface']=='github.cli.gh-secret-delete' and s3['authorization_observation']['execution_actor']=='AGENT_AUTHENTICATED_GH_CLI'
    assert s3['sanitized_result']=={'repository':'AnonymousKoo/avuhz-infra','environment':'development','secret_name':'AVUHZ_DEVELOPMENT_SUPABASE_AUTH_PROVIDER_ADAPTER_POSITIVE_AUTH_V4_EPHEMERAL','retired':True,'secret_value_observed':False,'other_secret_changed':False}
    assert s3['recorded_at']==STEP3_RECORDED_AT
    assert (x['step_states'][2]['authorization_state'],x['step_states'][2]['execution_state'],x['step_states'][2]['verification_state'],x['step_states'][2]['authorization_consumed'])==('CONSUMED','SUCCEEDED','PASS',True)
    assert x['step_states'][2]['evidence']==[{'evidence_type':'auth.provider-adapter-positive-auth.github-binding.retired','evidence_reference':N+'-step3-success.evidence.json','evidence_digest':STEP3_EVIDENCE,'recorded_at':STEP3_RECORDED_AT}]
    assert canonical_digest(s4)==STEP4_EVIDENCE and s4['evidence_type']=='auth.provider-adapter-positive-auth.github-binding.absence-verified'
    assert s4['record_basis']=='AGENT_AUTHENTICATED_GH_CLI_SANITIZED_NAMES_ONLY_READ_OUTCOME'
    assert s4['authorization_observation']['interaction_surface']=='github.cli.gh-secret-list' and s4['authorization_observation']['execution_actor']=='AGENT_AUTHENTICATED_GH_CLI'
    assert s4['sanitized_result']=={'repository':'AnonymousKoo/avuhz-infra','environment':'development','secret_name':'AVUHZ_DEVELOPMENT_SUPABASE_AUTH_PROVIDER_ADAPTER_POSITIVE_AUTH_V4_EPHEMERAL','exact_secret_reference_count':0,'absent':True,'secret_value_requested':False,'secret_value_observed':False,'provider_mutation_performed':False}
    assert s4['recorded_at']==STEP4_RECORDED_AT
    assert all(v is False for v in s4['security_state'].values())
    assert (x['step_states'][3]['authorization_state'],x['step_states'][3]['execution_state'],x['step_states'][3]['verification_state'],x['step_states'][3]['authorization_consumed'])==('CONSUMED','SUCCEEDED','PASS',True)
    assert x['step_states'][3]['evidence']==[{'evidence_type':'auth.provider-adapter-positive-auth.github-binding.absence-verified','evidence_reference':N+'-step4-success.evidence.json','evidence_digest':STEP4_EVIDENCE,'recorded_at':STEP4_RECORDED_AT}]
    assert all((z['authorization_state'],z['execution_state'],z['verification_state'],z['authorization_consumed'])==('CONSUMED','SUCCEEDED','PASS',True) for z in x['step_states'])
    print('DEVELOPMENT provider-adapter positive-auth v4 stale credential retirement v2: PASS (COMPLETED; Steps 1-4 CONSUMED/SUCCEEDED/PASS; exact v4 Supabase key and GitHub binding retired and independently verified absent; no auth retry/session/handoff authority)')

if __name__=='__main__':
    main()
