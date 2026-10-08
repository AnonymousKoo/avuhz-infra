#!/usr/bin/env python3
from __future__ import annotations
import json,re,sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT)); sys.path.insert(0,str(ROOT/'src'))

from avuhz_engineering.authorization_plan import approval_digest, initial_progress, plan_digest, progress_digest, validate_approval, validate_plan, validate_progress
from avuhz_runtime.implementation_handoff import canonical_digest

B=ROOT/'contracts/plans/v1'; S=ROOT/'contracts/schemas/v1'
N='development-implementation-handoff-provider-adapter-positive-auth-v8-key-retirement-v2'
V8='development-implementation-handoff-provider-adapter-positive-auth-v8'
V1='development-implementation-handoff-provider-adapter-positive-auth-v8-key-retirement-v1'
OBS='2026-10-06T13:13:38Z'
START='2026-10-06T14:00:00Z'
END='2026-10-06T17:00:00Z'
APPROVED='2026-10-06T13:37:15Z'
APPROVAL='sha256:e7ac6e84c8035e9253f1f4fe3337e55f4f7841d08738b8de028e85ec31d37beb'
RESOURCE='sha256:6d72f77f2511242ef0053f490bdb1fddf2132d6d891cf2d009f02f2184cad698'
PREP='sha256:b1f1b2b444ae579e1f001d14523059e4ed97c362290519ef39fd7e93a19ae0fb'
PLAN='sha256:87d7c13f5fd8ac19642375eb7d876ae690832633ae5a55eacb051cdf336fa10a'
PROGRESS='sha256:9ed63e5824face043558ed1553e5bd0aeb07bbf655b4783b655a7c7079c01c6c'
V8_STOP='sha256:45c6d902458eee68f2f2782aaac82598d8cef7a2c022124691d3db4f08222b8d'
V8_STEP1='sha256:e2f4cc24eb5bbe974ee51d2086262af68314a29a136c5f630f949bbf6699c420'
V8_STEP2_FAIL='sha256:eb2138a99751165302f01b9e063fdd883919c69c1df3f67db040c001879d9ae5'
V8_CORRECTION='sha256:8ec18cfe0586881e072aa6157012c15fcc9be3cd80d359731e12f3f99e7d75a0'
V1_INVALIDATION='sha256:6664a48710ed032272b0236e81c901ccdde1548fd185c26e2f0248f8a39b4b47'
V1_POST_DELETE='sha256:6f9fe1bd43637cf64002c7758846f56fdb6959aa254fc5228468b368656ce3b4'
STEP1_RECORDED='2026-10-06T14:01:49Z'
STEP1='sha256:4568bc1310f24c0e2db15dc9922b751bfff0565fd2c811e8477ca433aaa9046f'
EXECUTION_STEP1='sha256:ab8177660380aad1538a9aee377b03d07c6fa2a6de3d24caa33dc9352e6122ec'
STEP2_RECORDED='2026-10-06T14:36:00Z'
STEP2='sha256:4d4e4f695b60e90c5c6e230a10004bade558e22c69aa4c9fe3d477518d50015a'
STEP2_OBS='sha256:262e8dcc5d1bc70fab1a1b81edd078aaedd4c0c997f67c785e398d36466ee62b'
STEP2_RESULT='sha256:08b04d8663eeb1e174a90c8c9b3c69ca28e138a75b7ce4b3ddf3ec8a80ec0a14'
TERMINAL='sha256:dda26efb46d17998b71072edfec3ce3490478b595e92e31ce58ee645b211bade'

def load(name): return json.loads((B/name).read_text())

def main():
    r=load(N+'.resource.json')
    prep=load(N+'-preparation.evidence.json')
    p=load(N+'.plan.json')
    g=load(N+'.progress.json')
    a=load(N+'.approval.json')
    v8x=load(V8+'.execution-progress.json')
    v8e1=load(V8+'-step01-success.evidence.json')
    v8e2=load(V8+'-step02-plan-integrity-failure.evidence.json')
    correction=load(V8+'-recording-step-id-correction-v1.evidence.json')
    invalidation=load(V1+'-preexecution-invalidation.evidence.json')
    post_delete=load(V1+'-post-invalidation-delete.evidence.json')
    e1=load(N+'-step1-success.evidence.json')
    e2=load(N+'-step2-success.evidence.json')
    x=load(N+'.execution-progress.json')

    validate_plan(p,S); validate_progress(p,g,S); validate_approval(p,a,S,START); validate_progress(p,x,S)

    assert r['contract_digest']==RESOURCE==canonical_digest({k:v for k,v in r.items() if k!='contract_digest'})
    assert prep['evidence_digest']==PREP==canonical_digest({k:v for k,v in prep.items() if k!='evidence_digest'})
    assert p['plan_id']=='04b2fa4b-ed7b-488e-a230-9aba210ed68e'
    assert p['plan_version']==2 and p['plan_digest']==PLAN==plan_digest(p)
    assert p['definition_status']=='READY_FOR_APPROVAL'
    assert p['authority_effect']=='NONE_UNTIL_SEPARATELY_APPROVED'
    assert p['environment']=='DEVELOPMENT'
    assert p['target']['project_reference']=='pwlhruwutoitnieactol'
    assert p['target']['responsibility']=='AUTH'
    assert p['authorization_window']=={'binding_state':'BOUND','starts_at':START,'expires_at':END}

    assert a['approval_id']=='cdae2537-3734-4150-8399-e2fd20ce41b2'
    assert a['plan_id']==p['plan_id'] and a['plan_version']==2 and a['plan_digest']==p['plan_digest']
    assert a['owner_identity']==p['owner_identity'] and a['decision']=='APPROVE' and a['environment']=='DEVELOPMENT'
    assert a['approved_at']==APPROVED and APPROVED < START
    assert a['effective_at']==START and a['expires_at']==END
    assert a['status']=='ACTIVE' and a['authority_scope']=='EXACT_PLAN_ONLY'
    assert a['approval_digest']==APPROVAL==approval_digest(a)

    assert r['resource_id']=='c4abb14a-df30-4bd9-8708-4c97e14f913e'
    assert r['resource_version']=='provider-adapter-positive-auth-v8-key-retirement.v2'
    assert r['boundary']==N
    assert r['target_key_reference']=='impl_handoff_provider_adapter_positive_auth_v8_ephemeral'
    assert r['github_secret_binding_name']=='AVUHZ_DEVELOPMENT_SUPABASE_AUTH_PROVIDER_ADAPTER_POSITIVE_AUTH_V8_EPHEMERAL'
    assert r['lineage']['v8_corrected_execution_progress_digest']==V8_STOP
    assert r['lineage']['v8_corrected_step1_key_creation_evidence_digest']==V8_STEP1
    assert r['lineage']['v8_corrected_step2_plan_integrity_failure_evidence_digest']==V8_STEP2_FAIL
    assert r['lineage']['v8_recording_correction_evidence_digest']==V8_CORRECTION
    assert r['lineage']['v1_preexecution_invalidation_evidence_digest']==V1_INVALIDATION
    assert r['lineage']['v1_post_invalidation_delete_evidence_digest']==V1_POST_DELETE
    assert r['lineage']['v1_authority_state']=='APPROVED_BUT_NONEXECUTABLE'
    assert r['lineage']['v1_execution_conforming'] is False
    assert r['authorized_counts']=={
        'supabase_key_delete':0,'supabase_key_absence_read':1,'github_secret_absence_read':1,
        'github_environment_secret_delete':0,'credential_create':0,'session_issue':0,
        'token_issue':0,'implementation_handoff_execute':0
    }
    assert all(v is False for v in r['security_rules'].values())
    assert r['failure_handling']['v8_execution_must_remain_blocked'] is True
    assert r['failure_handling']['retirement_v1_must_remain_preexecution_invalidated'] is True
    assert r['failure_handling']['history_rewrite_authorized'] is False
    assert r['failure_handling']['provider_mutation_authorized'] is False
    assert r['failure_handling']['github_binding_mutation_authorized'] is False
    assert r['failure_handling']['retry_authorized'] is False

    assert v8x['overall_state']=='STOPPED' and v8x['progress_digest']==V8_STOP==progress_digest(v8x)
    assert canonical_digest(v8e1)==V8_STEP1
    assert canonical_digest(v8e2)==V8_STEP2_FAIL
    assert correction['evidence_digest']==V8_CORRECTION==canonical_digest({k:v for k,v in correction.items() if k!='evidence_digest'})
    assert invalidation['evidence_digest']==V1_INVALIDATION==canonical_digest({k:v for k,v in invalidation.items() if k!='evidence_digest'})
    assert invalidation['approval_state']=='APPROVED_BUT_NONEXECUTABLE'
    assert invalidation['continuation_rule']=='PREPARE_FRESH_FORWARD_ONLY_V8_KEY_RETIREMENT_V2'
    assert post_delete['evidence_digest']==V1_POST_DELETE==canonical_digest({k:v for k,v in post_delete.items() if k!='evidence_digest'})
    assert post_delete['outcome']=='NONCONFORMING_PROVIDER_MUTATION_AFTER_PREEXECUTION_INVALIDATION'
    assert post_delete['provider_effects']['provider_key_delete_reported'] is True
    assert post_delete['continuation_rule']=='PREPARE_FRESH_FORWARD_ONLY_V8_KEY_RETIREMENT_V2_ABSENCE_RECONCILIATION'

    assert prep['canonical_main_at_preparation']=='cff75ef3dfe68135f89e22977f850df7febacbbc'
    assert prep['resource_contract_digest']==RESOURCE
    assert prep['authorization_window']=={'starts_at':START,'expires_at':END}
    assert prep['prerequisites']=={
        'v8_corrected_stopped_progress':V8_STOP,
        'v8_corrected_step1_key_creation':V8_STEP1,
        'v8_corrected_step2_plan_integrity_failure':V8_STEP2_FAIL,
        'v8_recording_correction':V8_CORRECTION,
        'v1_preexecution_invalidation':V1_INVALIDATION,
        'v1_post_invalidation_delete':V1_POST_DELETE,
        'v1_authority_state':'APPROVED_BUT_NONEXECUTABLE',
        'v1_execution_conforming':False,
    }
    assert all(v is False for v in prep['security_state'].values())

    assert [s['operation'] for s in p['steps']]==[
        'provider.auth-admin-credential.verify-dedicated-secret-key-absent',
        'provider.auth-secret-binding.verify-github-environment-reference-absent',
    ]
    assert all(s['execution_class']=='PROVIDER_READ' for s in p['steps'])
    assert all(s['resource']['exact_version']=='provider-adapter-positive-auth-v8-key-retirement.v2' and s['resource']['exact_digest']==RESOURCE for s in p['steps'])
    assert all('provider.mutation' in s['prohibited_actions'] for s in p['steps'])
    assert all(s['correction_reference']=='correction.stop-for-owner-review-no-retry' for s in p['steps'])

    step1=p['steps'][0]
    bound={(e['evidence_type'],e['exact_digest']) for e in step1['required_evidence']}
    assert ('authorization-plan.execution-progress',V8_STOP) in bound
    assert ('auth.provider-adapter-positive-auth.admin-credential.created',V8_STEP1) in bound
    assert ('auth.provider-adapter-positive-auth.github-binding.created',V8_STEP2_FAIL) in bound
    assert ('authorization-plan.repository-recording-correction',V8_CORRECTION) in bound
    assert ('authorization-plan.preexecution-invalidated',V1_INVALIDATION) in bound
    assert ('auth.provider-adapter-positive-auth-v8.key-retirement-v1.post-invalidation-delete-observed',V1_POST_DELETE) in bound
    assert ('auth.provider-adapter-positive-auth-v8.key-retirement-v2.prepared',PREP) in bound

    assert g['progress_id']=='f533b49a-3b24-41fb-b33c-2c5de1c4659e'
    assert g['progress_digest']==PROGRESS==progress_digest(g)
    assert g['overall_state']=='NOT_STARTED' and g['record_version']==1
    assert g==initial_progress(p,S,g['progress_id'],OBS)

    assert canonical_digest(e1)==STEP1
    assert e1['evidence_type']=='auth.provider-adapter-positive-auth.admin-credential.absence-verified'
    assert e1['plan_id']==p['plan_id'] and e1['plan_version']==2 and e1['plan_digest']==p['plan_digest']
    assert e1['approval_id']==a['approval_id'] and e1['approval_digest']==a['approval_digest']
    assert e1['step_id']==p['ordered_step_ids'][0] and e1['attempt']==1
    assert e1['outcome']=='SUCCEEDED_VERIFIED'
    assert e1['classification']=='EXACT_V8_EPHEMERAL_AUTH_KEY_ABSENCE_REPORTED_BY_OWNER'
    assert e1['authorization_observation']['project_reference']=='pwlhruwutoitnieactol'
    assert e1['authorization_observation']['approval_exact'] is True
    assert e1['authorization_observation']['authorization_window_active'] is True
    assert e1['authorization_observation']['credential_material_observed'] is False
    assert e1['authorization_observation']['provider_mutation_attempted'] is False
    assert e1['authorization_observation_digest']=='sha256:b6ba35bc0c04b4ced20fcc5af975955f96df700f7f7d3b26ee75a2cffdec72ce'
    assert e1['sanitized_result']=={
        'key_name':'impl_handoff_provider_adapter_positive_auth_v8_ephemeral',
        'absence_reported_by_owner':True,
        'credential_material_observed':False,
        'other_key_inspected':False,
        'provider_mutation_performed':False,
    }
    assert e1['result_digest']=='sha256:27d92e5c806c4cc58aee384a4f3451baf73e83162e5a08ccc440e623a6168aad'
    assert e1['execution_observation']['execution_class']=='PROVIDER_READ'
    assert e1['execution_observation']['credential_value_read'] is False
    assert e1['execution_observation']['other_key_inspected'] is False
    assert e1['execution_observation']['provider_mutation_attempted'] is False
    assert e1['execution_observation']['retry_occurred'] is False
    assert all(v is False for v in e1['security_state'].values())
    assert e1['record_basis']=='OWNER_CONFIRMED_SEPARATE_NAMES_ONLY_ABSENCE_INSPECTION'
    assert e1['recorded_at']==STEP1_RECORDED

    assert canonical_digest(e2)==STEP2
    assert e2['evidence_type']=='auth.provider-adapter-positive-auth.github-binding.absence-verified'
    assert e2['plan_id']==p['plan_id'] and e2['plan_version']==2 and e2['plan_digest']==p['plan_digest']
    assert e2['approval_id']==a['approval_id'] and e2['approval_digest']==a['approval_digest']
    assert e2['step_id']==p['ordered_step_ids'][1] and e2['attempt']==1
    assert e2['outcome']=='SUCCEEDED_VERIFIED'
    assert e2['classification']=='EXACT_V8_GITHUB_BINDING_ABSENCE_REPORTED_BY_OWNER'
    assert e2['authorization_observation']['repository']=='AnonymousKoo/avuhz-infra'
    assert e2['authorization_observation']['environment']=='development'
    assert e2['authorization_observation']['approval_exact'] is True
    assert e2['authorization_observation']['authorization_window_active'] is True
    assert e2['authorization_observation']['secret_value_requested'] is False
    assert e2['authorization_observation']['secret_value_observed'] is False
    assert e2['authorization_observation']['provider_mutation_attempted'] is False
    assert e2['authorization_observation_digest']==STEP2_OBS
    assert e2['sanitized_result']=={
        'secret_name':'AVUHZ_DEVELOPMENT_SUPABASE_AUTH_PROVIDER_ADAPTER_POSITIVE_AUTH_V8_EPHEMERAL',
        'absence_reported_by_owner':True,
        'secret_value_observed':False,
        'provider_mutation_performed':False,
    }
    assert e2['result_digest']==STEP2_RESULT
    assert e2['execution_observation']['execution_class']=='PROVIDER_READ'
    assert e2['execution_observation']['secret_value_requested'] is False
    assert e2['execution_observation']['secret_value_observed'] is False
    assert e2['execution_observation']['provider_mutation_attempted'] is False
    assert e2['execution_observation']['retry_occurred'] is False
    assert all(v is False for v in e2['security_state'].values())
    assert e2['record_basis']=='OWNER_CONFIRMED_SEPARATE_NAMES_ONLY_GITHUB_ABSENCE_INSPECTION'
    assert e2['recorded_at']==STEP2_RECORDED

    assert x['progress_id']==g['progress_id']
    assert x['plan_id']==p['plan_id'] and x['plan_version']==2 and x['plan_digest']==p['plan_digest']
    assert x['record_version']==5 and x['overall_state']=='COMPLETED'
    assert x['updated_at']==STEP2_RECORDED
    assert x['progress_digest']==TERMINAL==progress_digest(x)
    sx1,sx2=x['step_states']
    assert (sx1['authorization_state'],sx1['execution_state'],sx1['verification_state'],sx1['authorization_consumed'])==('CONSUMED','SUCCEEDED','PASS',True)
    assert sx1['safe_error_code'] is None
    assert sx1['observed_postcondition']==p['steps'][0]['expected_postcondition']
    assert sx1['evidence']==[{
        'evidence_type':'auth.provider-adapter-positive-auth.admin-credential.absence-verified',
        'evidence_reference':N+'-step1-success.evidence.json',
        'evidence_digest':STEP1,
        'recorded_at':STEP1_RECORDED,
    }]
    assert len(sx1['binding_assertions'])==2
    assert (sx2['authorization_state'],sx2['execution_state'],sx2['verification_state'],sx2['authorization_consumed'])==('CONSUMED','SUCCEEDED','PASS',True)
    assert sx2['safe_error_code'] is None
    assert sx2['observed_postcondition']==p['steps'][1]['expected_postcondition']
    assert sx2['evidence']==[{
        'evidence_type':'auth.provider-adapter-positive-auth.github-binding.absence-verified',
        'evidence_reference':N+'-step2-success.evidence.json',
        'evidence_digest':STEP2,
        'recorded_at':STEP2_RECORDED,
    }]
    assert len(sx2['binding_assertions'])==3

    rendered='\n'.join((B/(N+s)).read_text() for s in ('.resource.json','-preparation.evidence.json','.plan.json','.progress.json','.approval.json','-step1-success.evidence.json','-step2-success.evidence.json','.execution-progress.json'))
    assert re.search(r'sb_secret_[A-Za-z0-9._-]{8,}',rendered) is None
    assert 'gnuqaefotwgkwurjpyik' not in rendered
    assert 'service_role' not in rendered and 'Bearer eyJ' not in rendered

    print('DEVELOPMENT provider-adapter positive-auth v8 key retirement v2: PASS (COMPLETED; both absence checks SUCCEEDED / PASS; read-only reconciliation complete)')

if __name__=='__main__': main()
