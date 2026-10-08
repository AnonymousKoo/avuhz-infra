#!/usr/bin/env python3
from __future__ import annotations
import json,re,sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT)); sys.path.insert(0,str(ROOT/'src'))

from avuhz_engineering.authorization_plan import approval_digest, initial_progress, plan_digest, progress_digest, validate_approval, validate_plan, validate_progress
from avuhz_runtime.implementation_handoff import canonical_digest

B=ROOT/'contracts/plans/v1'; S=ROOT/'contracts/schemas/v1'
N='development-implementation-handoff-provider-adapter-positive-auth-v6-key-retirement-v4'
V1='development-implementation-handoff-provider-adapter-positive-auth-v6-key-retirement-v1'
V2='development-implementation-handoff-provider-adapter-positive-auth-v6-key-retirement-v2'
V3='development-implementation-handoff-provider-adapter-positive-auth-v6-key-retirement-v3'
OBS='2026-10-05T22:07:03Z'
START='2026-10-06T01:00:00Z'
END='2026-10-06T05:00:00Z'
V1_LATE='sha256:92b07fb7f7fec8c93603160f9404def011256eb0cbd243068c8e0090905074b4'
V2_REJECT='sha256:40395a1c082cc8b196c63ee6e71e2274580d5dd25a2b1673f97bf09058444014'
V3_REJECT='sha256:0db6b200bec1d29f5f7e344c4de6cb5ac365fae04de841a8316c32e781f72fca'
RESOURCE='sha256:13172fb5a72750c8a4aa8ca3bbef5611c5d54f2b25447224e5ffd2989e306791'
PREP='sha256:39ca6455cdb6ec5692c197c0092aa93462bc77a2a1210aad7e514bdbb35ae1a6'
PLAN='sha256:c86243c50bfbb681207c01705d1b75ee3e4024c7dcd9688ceb8b34e31027eeff'
PROGRESS='sha256:60e057d4e3c260dbef3f9daf659e5a7cc3ec4e6f845379f4c0c518fef7f21a95'
APPROVED='2026-10-05T22:27:46Z'
APPROVAL='sha256:41bd085fab6bb06980fbfc0f5aacc772a92b505b762aa11c66b620b4c913d4b2'
STEP1='sha256:9c59ea56aa247f9d576280a4cc050e4d9db972bffae247c7b3d6e243527b57a2'
EXECUTION='sha256:cd7b82bb271e8e93bd9b434704a45caac9f700a8ee450c757dfdcc629a3a58b0'
STEP1_RECORDED='2026-10-06T01:09:42Z'
STEP2='sha256:96e9371c01dcf15e061823c35df159d4627f79b06884af3c4edf6c48d08e2770'
EXECUTION_STEP2='sha256:e4dbe07a5a38957e5125a8257a9a1bd73bad646eb7d6e7d0e34bd02fb9dbd0cc'
STEP2_RECORDED='2026-10-06T01:19:46Z'
STEP3='sha256:a92e3926482aaed1ac19c241aef6d23b0079f47e1087c77bc65797dd11f99d76'
EXECUTION_STEP3='sha256:b988dd98a2623e5831f007d65238940095725050a9cb8fc32e0dcba0cdb7ef0a'
STEP3_RECORDED='2026-10-06T01:38:34Z'

def load(name): return json.loads((B/name).read_text())

def main():
    r=load(N+'.resource.json')
    prep=load(N+'-preparation.evidence.json')
    p=load(N+'.plan.json')
    g=load(N+'.progress.json')
    a=load(N+'.approval.json')
    e1=load(N+'-step1-success.evidence.json')
    e2=load(N+'-step2-success.evidence.json')
    e3=load(N+'-step3-success.evidence.json')
    x=load(N+'.execution-progress.json')
    late=load(V1+'-late-window-rejection.evidence.json')
    reject2=load(V2+'-binding-integrity-rejection.evidence.json')
    reject3=load(V3+'-effective-time-rejection.evidence.json')

    validate_plan(p,S); validate_progress(p,g,S); validate_approval(p,a,S,START); validate_progress(p,x,S)

    assert r['contract_digest']==RESOURCE==canonical_digest({k:v for k,v in r.items() if k!='contract_digest'})
    assert prep['evidence_digest']==PREP==canonical_digest({k:v for k,v in prep.items() if k!='evidence_digest'})
    assert late['evidence_digest']==V1_LATE==canonical_digest({k:v for k,v in late.items() if k!='evidence_digest'})
    assert reject2['evidence_digest']==V2_REJECT==canonical_digest({k:v for k,v in reject2.items() if k!='evidence_digest'})
    assert reject3['evidence_digest']==V3_REJECT==canonical_digest({k:v for k,v in reject3.items() if k!='evidence_digest'})
    assert reject3['outcome']=='REJECTED_PREAPPROVAL_EFFECTIVE_TIME_PASSED'
    assert reject3['safe_error_code']=='PLAN_AUTHORIZATION_EXPIRED'
    assert reject3['candidate_plan_canonicalized_before_effective_time'] is False
    assert reject3['approval_instruction_received'] is False
    assert reject3['approval_artifact_created'] is False and reject3['approval_canonicalized'] is False
    assert reject3['candidate_plan_digest']=='sha256:ebfd8c2f6978f54e7503adba98cbcd8d6d0d816b015768fe6504594fa9178504'
    assert all(v is False for v in reject3['provider_effects'].values())

    assert p['plan_id']=='a72084f5-f9a9-4ffc-89a5-4fbb0634414c'
    assert p['plan_version']==4 and p['plan_digest']==PLAN==plan_digest(p)
    assert p['definition_status']=='READY_FOR_APPROVAL'
    assert p['authority_effect']=='NONE_UNTIL_SEPARATELY_APPROVED'
    assert p['environment']=='DEVELOPMENT'
    assert p['target']['project_reference']=='pwlhruwutoitnieactol'
    assert p['target']['responsibility']=='AUTH'
    assert p['authorization_window']=={'binding_state':'BOUND','starts_at':START,'expires_at':END}

    assert r['resource_id']=='b6f6a014-565c-4d31-8c66-6386f390e3c8'
    assert r['resource_version']=='provider-adapter-positive-auth-v6-key-retirement.v4'
    assert r['boundary']==N
    assert r['target_key_reference']=='impl_handoff_provider_adapter_positive_auth_v6_ephemeral'
    assert r['github_secret_binding_name']=='AVUHZ_DEVELOPMENT_SUPABASE_AUTH_PROVIDER_ADAPTER_POSITIVE_AUTH_V6_EPHEMERAL'
    assert r['lineage']['v3_retirement_plan_id']=='d8e7c977-56f9-52c9-8313-476bfebb3421'
    assert r['lineage']['v3_retirement_plan_digest']=='sha256:ebfd8c2f6978f54e7503adba98cbcd8d6d0d816b015768fe6504594fa9178504'
    assert r['lineage']['v3_preparation_evidence_digest']=='sha256:6c95b986b935593afa5f931fd89b3e7635a5913490074c98c2cc55f356001662'
    assert r['lineage']['v3_preapproval_effective_time_rejection_evidence_digest']==V3_REJECT
    assert r['lineage']['v3_plan_canonicalized_before_effective_time'] is False
    assert r['lineage']['v3_approval_canonicalized'] is False
    assert r['authorized_counts']=={
        'supabase_key_delete':1,'supabase_key_absence_read':1,'github_secret_absence_read':1,
        'github_environment_secret_delete':0,'credential_create':0,'session_issue':0,
        'token_issue':0,'implementation_handoff_execute':0
    }
    assert all(v is False for v in r['security_rules'].values())

    step1=p['steps'][0]
    prep_bindings=[x for x in step1['required_evidence'] if x['evidence_type']=='auth.provider-adapter-positive-auth-v6.key-retirement-v4.prepared']
    assert prep_bindings==[{
        'evidence_type':'auth.provider-adapter-positive-auth-v6.key-retirement-v4.prepared',
        'source_step_id':None,'binding_state':'BOUND','exact_digest':PREP
    }]
    v3_bindings=[x for x in step1['required_evidence'] if x['evidence_type']=='auth.provider-adapter-positive-auth-v6.key-retirement-v3.preapproval-effective-time-passed']
    assert v3_bindings==[{
        'evidence_type':'auth.provider-adapter-positive-auth-v6.key-retirement-v3.preapproval-effective-time-passed',
        'source_step_id':None,'binding_state':'BOUND','exact_digest':V3_REJECT
    }]
    assert all(s['resource']['exact_version']=='provider-adapter-positive-auth-v6-key-retirement.v4' and s['resource']['exact_digest']==RESOURCE for s in p['steps'])
    assert [s['operation'] for s in p['steps']]==[
        'provider.auth-admin-credential.delete-dedicated-secret-key',
        'provider.auth-admin-credential.verify-dedicated-secret-key-absent',
        'provider.auth-secret-binding.verify-github-environment-reference-absent',
    ]

    assert g['progress_id']=='a1b735e5-5a59-4a1d-afb5-40a4bb38e00b'
    assert g['progress_digest']==PROGRESS==progress_digest(g)
    assert g['overall_state']=='NOT_STARTED' and g['record_version']==1
    assert g==initial_progress(p,S,g['progress_id'],OBS)
    assert a['approval_id']=='b775a844-8b87-508f-a84a-f9fe0a869cd1'
    assert a['plan_id']==p['plan_id'] and a['plan_version']==4 and a['plan_digest']==p['plan_digest']
    assert a['owner_identity']==p['owner_identity'] and a['environment']==p['environment']
    assert a['decision']=='APPROVE' and a['status']=='ACTIVE' and a['authority_scope']=='EXACT_PLAN_ONLY'
    assert a['approved_at']==APPROVED and a['effective_at']==START and a['expires_at']==END
    assert a['approval_digest']==APPROVAL==approval_digest(a)

    assert canonical_digest(e1)==STEP1
    assert e1['evidence_type']=='auth.provider-adapter-positive-auth.admin-credential.retired'
    assert e1['plan_id']==p['plan_id'] and e1['plan_version']==4 and e1['plan_digest']==p['plan_digest']
    assert e1['approval_id']==a['approval_id'] and e1['approval_digest']==a['approval_digest']
    assert e1['step_id']==p['ordered_step_ids'][0] and e1['attempt']==1
    assert e1['outcome']=='SUCCEEDED_RECORDED'
    assert e1['classification']=='EXACT_V6_EPHEMERAL_AUTH_KEY_RETIREMENT_REPORTED_BY_OWNER'
    assert e1['authorization_observation']['project_reference']=='pwlhruwutoitnieactol'
    assert e1['authorization_observation']['approval_exact'] is True
    assert e1['authorization_observation']['authorization_window_active'] is True
    assert e1['authorization_observation']['credential_material_observed'] is False
    assert e1['authorization_observation']['other_key_mutation_reported'] is False
    assert e1['sanitized_result']=={
        'key_name':'impl_handoff_provider_adapter_positive_auth_v6_ephemeral',
        'retirement_reported_by_owner':True,
        'credential_material_observed':False,
        'other_key_change_reported':False,
    }
    assert e1['execution_observation']['credential_value_read'] is False
    assert e1['execution_observation']['retry_occurred'] is False
    assert all(v is False for v in e1['security_state'].values())
    assert e1['record_basis']=='OWNER_CONFIRMED_SANITIZED_EXECUTION_OUTCOME'
    assert e1['independent_absence_verification_required'] is True
    assert e1['recorded_at']==STEP1_RECORDED

    assert canonical_digest(e2)==STEP2
    assert e2['evidence_type']=='auth.provider-adapter-positive-auth.admin-credential.absence-verified'
    assert e2['plan_id']==p['plan_id'] and e2['plan_version']==4 and e2['plan_digest']==p['plan_digest']
    assert e2['approval_id']==a['approval_id'] and e2['approval_digest']==a['approval_digest']
    assert e2['step_id']==p['ordered_step_ids'][1] and e2['attempt']==1
    assert e2['outcome']=='SUCCEEDED_VERIFIED'
    assert e2['classification']=='EXACT_V6_EPHEMERAL_AUTH_KEY_ABSENCE_REPORTED_BY_OWNER'
    assert e2['authorization_observation']['project_reference']=='pwlhruwutoitnieactol'
    assert e2['authorization_observation']['approval_exact'] is True
    assert e2['authorization_observation']['authorization_window_active'] is True
    assert e2['authorization_observation']['credential_material_observed'] is False
    assert e2['authorization_observation']['provider_mutation_attempted'] is False
    assert e2['sanitized_result']=={
        'key_name':'impl_handoff_provider_adapter_positive_auth_v6_ephemeral',
        'absence_reported_by_owner':True,
        'credential_material_observed':False,
        'other_key_inspected':False,
        'provider_mutation_performed':False,
    }
    assert e2['execution_observation']['credential_value_read'] is False
    assert e2['execution_observation']['other_key_inspected'] is False
    assert e2['execution_observation']['provider_mutation_attempted'] is False
    assert e2['execution_observation']['retry_occurred'] is False
    assert all(v is False for v in e2['security_state'].values())
    assert e2['record_basis']=='OWNER_CONFIRMED_SEPARATE_NAMES_ONLY_ABSENCE_INSPECTION'
    assert e2['recorded_at']==STEP2_RECORDED

    assert canonical_digest(e3)==STEP3
    assert e3['evidence_type']=='auth.provider-adapter-positive-auth.github-binding.absence-verified'
    assert e3['plan_id']==p['plan_id'] and e3['plan_version']==4 and e3['plan_digest']==p['plan_digest']
    assert e3['approval_id']==a['approval_id'] and e3['approval_digest']==a['approval_digest']
    assert e3['step_id']==p['ordered_step_ids'][2] and e3['attempt']==1
    assert e3['outcome']=='SUCCEEDED_VERIFIED'
    assert e3['classification']=='EXACT_V6_GITHUB_BINDING_ABSENCE_OWNER_VERIFIED'
    assert e3['repository']=='AnonymousKoo/avuhz-infra' and e3['github_environment']=='development'
    assert e3['authorization_observation']['approval_exact'] is True
    assert e3['authorization_observation']['authorization_window_active'] is True
    assert e3['authorization_observation']['secret_value_requested'] is False
    assert e3['authorization_observation']['secret_value_observed'] is False
    assert e3['authorization_observation']['provider_mutation_attempted'] is False
    assert e3['sanitized_result']=={
        'repository':'AnonymousKoo/avuhz-infra',
        'environment':'development',
        'secret_name':'AVUHZ_DEVELOPMENT_SUPABASE_AUTH_PROVIDER_ADAPTER_POSITIVE_AUTH_V6_EPHEMERAL',
        'exact_secret_reference_count':0,
        'absent':True,
        'secret_value_requested':False,
        'secret_value_observed':False,
        'provider_mutation_performed':False,
    }
    assert e3['execution_observation']['secret_value_requested'] is False
    assert e3['execution_observation']['secret_value_read'] is False
    assert e3['execution_observation']['provider_mutation_attempted'] is False
    assert e3['execution_observation']['retry_occurred'] is False
    assert all(v is False for v in e3['security_state'].values())
    assert e3['record_basis']=='OWNER_CONFIRMED_SCREENSHOT_NAMES_ONLY_ABSENCE_INSPECTION'
    assert e3['recorded_at']==STEP3_RECORDED

    assert x['progress_id']==g['progress_id']
    assert x['plan_id']==p['plan_id'] and x['plan_version']==4 and x['plan_digest']==p['plan_digest']
    assert x['record_version']==7 and x['overall_state']=='COMPLETED'
    assert x['updated_at']==STEP3_RECORDED
    assert x['progress_digest']==EXECUTION_STEP3==progress_digest(x)
    s1=x['step_states'][0]
    s2=x['step_states'][1]
    s3=x['step_states'][2]
    for s in (s1,s2,s3):
        assert (s['authorization_state'],s['execution_state'],s['verification_state'],s['authorization_consumed'])==('CONSUMED','SUCCEEDED','PASS',True)
        assert s['safe_error_code'] is None
    assert s1['observed_postcondition']==p['steps'][0]['expected_postcondition']
    assert s2['observed_postcondition']==p['steps'][1]['expected_postcondition']
    assert s3['observed_postcondition']==p['steps'][2]['expected_postcondition']
    assert s1['evidence']==[{
        'evidence_type':'auth.provider-adapter-positive-auth.admin-credential.retired',
        'evidence_reference':N+'-step1-success.evidence.json',
        'evidence_digest':STEP1,
        'recorded_at':STEP1_RECORDED,
    }]
    assert s2['evidence']==[{
        'evidence_type':'auth.provider-adapter-positive-auth.admin-credential.absence-verified',
        'evidence_reference':N+'-step2-success.evidence.json',
        'evidence_digest':STEP2,
        'recorded_at':STEP2_RECORDED,
    }]
    assert s3['evidence']==[{
        'evidence_type':'auth.provider-adapter-positive-auth.github-binding.absence-verified',
        'evidence_reference':N+'-step3-success.evidence.json',
        'evidence_digest':STEP3,
        'recorded_at':STEP3_RECORDED,
    }]
    assert len(s1['binding_assertions'])==2 and len(s2['binding_assertions'])==3 and len(s3['binding_assertions'])==3
    derived2=[b for b in s2['binding_assertions'] if b['phase']=='DERIVED_FROM_SOURCE_STEP']
    derived3=[b for b in s3['binding_assertions'] if b['phase']=='DERIVED_FROM_SOURCE_STEP']
    assert len(derived2)==1 and derived2[0]['source_step_id']==p['ordered_step_ids'][0] and derived2[0]['evidence_digest']==STEP1
    assert len(derived3)==1 and derived3[0]['source_step_id']==p['ordered_step_ids'][1] and derived3[0]['evidence_digest']==STEP2

    rendered='\n'.join((B/(N+s)).read_text() for s in ('.resource.json','-preparation.evidence.json','.plan.json','.progress.json','.approval.json','-step1-success.evidence.json','-step2-success.evidence.json','-step3-success.evidence.json','.execution-progress.json'))
    assert re.search(r'sb_secret_[A-Za-z0-9._-]{8,}',rendered) is None
    assert 'gnuqaefotwgkwurjpyik' not in rendered

    print('DEVELOPMENT provider-adapter positive-auth v6 key retirement v4: PASS (COMPLETED; Steps 1-3 CONSUMED / SUCCEEDED / PASS; no secret value or out-of-scope mutation recorded)')

if __name__=='__main__': main()
