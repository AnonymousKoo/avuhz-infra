#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
sys.path.insert(0,str(ROOT/'src'))

from avuhz_engineering.authorization_plan import approval_digest, initial_progress, plan_digest, progress_digest, validate_approval, validate_plan, validate_progress
from avuhz_runtime.implementation_handoff import canonical_digest

B=ROOT/'contracts/plans/v1'
S=ROOT/'contracts/schemas/v1'
N='development-implementation-handoff-provider-adapter-positive-auth-v4-github-binding-drift-retirement-v1'
DRIFT='sha256:d3f503921d8b27d698e95dcb05651a8c42b20403267673720643e25e28b5944c'
RESOURCE='sha256:07c9dd7dafcb46608aeab41825b5512835ea7cb1575aafac4412bb3d1727e3d4'
PREP='sha256:fa66101a194f32f8387b0b589832cd2938e8d6e4520761dca7324a0480dd7277'
PLAN='sha256:f1ba176e1b42cb6563c42ddc57db98cf5c5ccefd0deb6d436fe3bec24d72b590'
PROGRESS='sha256:2bd2a2e1b15c70439f616480aa8afb09dc6295cf40d8a98492fadaf0085ed80e'
OLD_KEY_ABSENCE='sha256:89596d6e8895213059840d3af8b84202bee52b4069365afa5df8e75ec11d9a7e'
OLD_GITHUB_ABSENCE='sha256:c9da22e43c568c9f276eb86c78ce730b394740bb02161afc9adbd4cd6c66b98f'
OLD_RETIREMENT_PROGRESS='sha256:d6a071034f35d1ddf55f3265286e964687f9879a711c02e4fd63f6f2644be0c1'
V5_REJECTION='sha256:e29e56af04b0b2664aa8d6749c367184f2c06446c2eb50fa1cbad4e394c09468'
V6_STEP2_FAILURE='sha256:fdd233c078ee3e60bae0dd95128535526dc073759c54ee5cd21c8070cac15937'
V6_RETIREMENT_COMPLETE='sha256:b988dd98a2623e5831f007d65238940095725050a9cb8fc32e0dcba0cdb7ef0a'
OBS='2026-10-06T01:47:32Z'
START='2026-10-06T02:45:00Z'
END='2026-10-06T06:00:00Z'
APPROVED='2026-10-06T02:00:48Z'
APPROVAL='sha256:fcdd5aec1c03ed18b98bf6c9b5dc7cd58c21968d8cdde5d35a243281a50c8d9e'
STEP1='sha256:7e30a4d2e973a4e5cab4e2a97e76e11b3deda2b49ee682721d7c6f8aebc83bd4'
EXECUTION_STEP1='sha256:353cba4358b464a418ca642e76f3c40781ab461b1b18e47998a69593f92f58ae'
STEP1_RECORDED='2026-10-06T03:30:27Z'
STEP2_FAILURE='sha256:5b46a52a3881eb6afdb094825a012ccd2cc54d045ca80c29c1eb68ec9a1b77d2'
EXECUTION_STEP2_STOP='sha256:fc38e77792c472d6e135a3e9310c4f78af988acba36748df45946b6f00c4d48b'
STEP2_RECORDED='2026-10-06T03:37:56Z'
STEP2_STOP='STOP_REQUIRES_FORWARD_ONLY_GITHUB_BINDING_ABSENCE_RECONCILIATION'

def load(name):
    return json.loads((B/name).read_text())

def main():
    drift=load('development-implementation-handoff-provider-adapter-positive-auth-v4-github-binding-drift-observation.evidence.json')
    r=load(N+'.resource.json')
    prep=load(N+'-preparation.evidence.json')
    p=load(N+'.plan.json')
    g=load(N+'.progress.json')
    a=load(N+'.approval.json')
    e1=load(N+'-step1-success.evidence.json')
    e2=load(N+'-step2-failure.evidence.json')
    x=load(N+'.execution-progress.json')
    old_key=load('development-implementation-handoff-provider-adapter-positive-auth-v4-stale-credential-retirement-v2-step2-success.evidence.json')
    old_gh=load('development-implementation-handoff-provider-adapter-positive-auth-v4-stale-credential-retirement-v2-step4-success.evidence.json')
    old_x=load('development-implementation-handoff-provider-adapter-positive-auth-v4-stale-credential-retirement-v2.execution-progress.json')
    v5=load('development-implementation-handoff-provider-adapter-positive-auth-v5-preactivation-integrity-rejection.evidence.json')
    v6=load('development-implementation-handoff-provider-adapter-positive-auth-v6-step02-plan-integrity-failure.evidence.json')
    v6_retire=load('development-implementation-handoff-provider-adapter-positive-auth-v6-key-retirement-v4.execution-progress.json')

    validate_plan(p,S)
    validate_progress(p,g,S)
    validate_approval(p,a,S,START)
    validate_progress(p,x,S)

    assert drift['evidence_digest']==DRIFT==canonical_digest({k:v for k,v in drift.items() if k!='evidence_digest'})
    assert r['contract_digest']==RESOURCE==canonical_digest({k:v for k,v in r.items() if k!='contract_digest'})
    assert prep['evidence_digest']==PREP==canonical_digest({k:v for k,v in prep.items() if k!='evidence_digest'})
    assert p['plan_digest']==PLAN==plan_digest(p)
    assert g['progress_digest']==PROGRESS==progress_digest(g)
    assert g==initial_progress(p,S,g['progress_id'],OBS)

    assert canonical_digest(old_key)==OLD_KEY_ABSENCE
    assert old_key['sanitized_result']['absence_reported_by_owner'] is True
    assert canonical_digest(old_gh)==OLD_GITHUB_ABSENCE
    assert old_gh['sanitized_result']['absent'] is True
    assert old_x['progress_digest']==OLD_RETIREMENT_PROGRESS==progress_digest(old_x)
    assert old_x['overall_state']=='COMPLETED'

    assert v5['evidence_digest']==V5_REJECTION==canonical_digest({k:v for k,v in v5.items() if k!='evidence_digest'})
    assert v5['outcome']=='REJECTED_PREACTIVATION_UNEXECUTED'
    assert v5['effects']['github_secret_changed'] is False
    assert canonical_digest(v6)==V6_STEP2_FAILURE
    assert v6['outcome']=='FAILED_PREEXECUTION_PLAN_INTEGRITY'
    assert v6['authorization_observation']['github_secret_mutation_attempted'] is False
    assert v6_retire['progress_digest']==V6_RETIREMENT_COMPLETE==progress_digest(v6_retire)
    assert v6_retire['overall_state']=='COMPLETED'

    assert drift['classification']=='POST_RETIREMENT_GITHUB_BINDING_DRIFT'
    assert drift['sanitized_observation']=={
        'secret_name':'AVUHZ_DEVELOPMENT_SUPABASE_AUTH_PROVIDER_ADAPTER_POSITIVE_AUTH_V4_EPHEMERAL',
        'exact_secret_reference_count':1,
        'present':True,
        'secret_value_requested':False,
        'secret_value_observed':False,
        'provider_mutation_performed':False,
        'other_secret_names_retained':False,
    }
    assert drift['later_authorized_recreation_review']['authorized_recreation_found'] is False
    assert all(v is False for v in drift['security_state'].values())

    assert r['resource_id']=='e8bd7154-9521-4f7d-90db-25e1d75f3e42'
    assert r['resource_version']=='provider-adapter-positive-auth-v4-github-binding-drift-retirement.v1'
    assert r['boundary']==N
    assert r['project_reference']=='pwlhruwutoitnieactol'
    assert r['target_key_reference']=='impl_handoff_provider_adapter_positive_auth_v4_ephemeral'
    assert r['github_repository']=='AnonymousKoo/avuhz-infra'
    assert r['github_environment']=='development'
    assert r['github_secret_binding_name']=='AVUHZ_DEVELOPMENT_SUPABASE_AUTH_PROVIDER_ADAPTER_POSITIVE_AUTH_V4_EPHEMERAL'
    assert r['authorized_counts']=={
        'supabase_key_delete':0,'supabase_key_absence_read':1,
        'github_environment_secret_delete':1,'github_secret_absence_read':1,
        'credential_create':0,'session_issue':0,'token_issue':0,
        'implementation_handoff_execute':0,'auth_retry':0,
    }
    assert all(v is False for v in r['security_rules'].values())
    assert r['execution_rules']['provider_key_absence_must_be_reverified_before_github_delete'] is True
    assert r['execution_rules']['window_starts_at']==START and r['execution_rules']['window_expires_at']==END

    assert prep['provider_authority']=='NONE'
    assert prep['external_provider_contact']=='PROHIBITED'
    assert prep['resource_contract_digest']==RESOURCE
    assert prep['drift_observation_evidence_digest']==DRIFT
    assert prep['authorization_window']=={'starts_at':START,'expires_at':END}
    assert all(v is False for v in prep['security_state'].values())

    assert p['plan_id']=='5d4f3b8a-1c69-4c18-b0f1-0c70b511f54e'
    assert p['plan_version']==1 and p['definition_status']=='READY_FOR_APPROVAL'
    assert p['environment']=='DEVELOPMENT'
    assert p['target']['project_reference']=='pwlhruwutoitnieactol' and p['target']['responsibility']=='AUTH'
    assert p['authorization_window']=={'binding_state':'BOUND','starts_at':START,'expires_at':END}
    assert p['authority_effect']=='NONE_UNTIL_SEPARATELY_APPROVED'
    assert [s['operation'] for s in p['steps']]==[
        'provider.auth-admin-credential.verify-dedicated-secret-key-absent',
        'provider.auth-secret-binding.delete-github-environment-reference',
        'provider.auth-secret-binding.verify-github-environment-reference-absent',
    ]
    assert len(p['steps'])==3 and len(g['step_states'])==3
    assert all(s['resource']['exact_version']=='provider-adapter-positive-auth-v4-github-binding-drift-retirement.v1' and s['resource']['exact_digest']==RESOURCE for s in p['steps'])
    assert p['steps'][0]['execution_class']=='PROVIDER_READ'
    assert p['steps'][1]['execution_class']=='PROVIDER_MUTATION'
    assert p['steps'][2]['execution_class']=='PROVIDER_READ'
    assert p['steps'][1]['dependency_step_ids']==[p['ordered_step_ids'][0]]
    assert p['steps'][2]['dependency_step_ids']==[p['ordered_step_ids'][1]]
    assert 'key-reference.present' in p['steps'][0]['stop_conditions']

    assert g['overall_state']=='NOT_STARTED' and g['record_version']==1
    assert all((s['authorization_state'],s['execution_state'],s['verification_state'],s['authorization_consumed'])==('PENDING','NOT_STARTED','NOT_STARTED',False) for s in g['step_states'])
    assert a['approval_id']=='1c0d41c7-5fd0-4eb7-957a-8c57f2a8e537'
    assert a['plan_id']==p['plan_id'] and a['plan_version']==1 and a['plan_digest']==p['plan_digest']
    assert a['owner_identity']==p['owner_identity'] and a['decision']=='APPROVE' and a['environment']=='DEVELOPMENT'
    assert a['approved_at']==APPROVED and a['effective_at']==START and a['expires_at']==END
    assert a['status']=='ACTIVE' and a['authority_scope']=='EXACT_PLAN_ONLY'
    assert a['approval_digest']==APPROVAL==approval_digest(a)
    assert canonical_digest(e1)==STEP1
    assert e1['evidence_type']=='auth.provider-adapter-positive-auth.admin-credential.absence-verified'
    assert e1['plan_id']==p['plan_id'] and e1['plan_version']==1 and e1['plan_digest']==p['plan_digest']
    assert e1['approval_id']==a['approval_id'] and e1['approval_digest']==a['approval_digest']
    assert e1['step_id']==p['ordered_step_ids'][0] and e1['attempt']==1
    assert e1['outcome']=='SUCCEEDED_VERIFIED'
    assert e1['classification']=='EXACT_V4_EPHEMERAL_AUTH_KEY_ABSENCE_REPORTED_BY_OWNER'
    assert e1['authorization_observation']['project_reference']=='pwlhruwutoitnieactol'
    assert e1['authorization_observation']['approval_exact'] is True
    assert e1['authorization_observation']['authorization_window_active'] is True
    assert e1['authorization_observation']['credential_material_observed'] is False
    assert e1['authorization_observation']['provider_mutation_attempted'] is False
    assert e1['sanitized_result']=={
        'key_name':'impl_handoff_provider_adapter_positive_auth_v4_ephemeral',
        'absence_reported_by_owner':True,
        'credential_material_observed':False,
        'other_key_inspected':False,
        'provider_mutation_performed':False,
    }
    assert e1['execution_observation']['credential_value_read'] is False
    assert e1['execution_observation']['provider_mutation_attempted'] is False
    assert e1['execution_observation']['retry_occurred'] is False
    assert all(v is False for v in e1['security_state'].values())
    assert e1['record_basis']=='OWNER_CONFIRMED_SEPARATE_NAMES_ONLY_ABSENCE_INSPECTION'
    assert e1['recorded_at']==STEP1_RECORDED

    assert canonical_digest(e2)==STEP2_FAILURE
    assert e2['evidence_type']=='auth.provider-adapter-positive-auth.github-binding.retired'
    assert e2['plan_id']==p['plan_id'] and e2['plan_version']==1 and e2['plan_digest']==p['plan_digest']
    assert e2['approval_id']==a['approval_id'] and e2['approval_digest']==a['approval_digest']
    assert e2['step_id']==p['ordered_step_ids'][1] and e2['attempt']==1
    assert e2['outcome']=='FAILED_NONCONFORMING_RETRY'
    assert e2['safe_error_code']==STEP2_STOP and e2['classification']==STEP2_STOP
    assert e2['authorization_observation']['approval_exact'] is True
    assert e2['authorization_observation']['authorization_window_active'] is True
    assert e2['authorization_observation']['secret_value_requested'] is False
    assert e2['authorization_observation']['secret_value_observed'] is False
    assert e2['authorization_observation']['initial_delete_attempt_failed'] is True
    assert e2['authorization_observation']['retry_occurred'] is True
    assert e2['sanitized_runtime_outcome']['initial_delete_result']=='FAILED_UI_REPORTED'
    assert e2['sanitized_runtime_outcome']['retry_occurred'] is True
    assert e2['sanitized_runtime_outcome']['later_absence_reported_by_owner'] is True
    assert e2['sanitized_runtime_outcome']['fresh_reconciliation_required'] is True
    assert e2['authority_state']['authorization_consumed'] is True
    assert e2['authority_state']['retry_authorized'] is False
    assert e2['authority_state']['step3_authorized'] is False
    assert e2['execution_observation']['authorized_initial_delete_attempts']==1
    assert e2['execution_observation']['observed_ui_delete_submission_count']==2
    assert e2['execution_observation']['retry_occurred'] is True
    assert all(v is False for v in e2['security_state'].values())
    assert e2['record_basis']=='OWNER_REPORTED_UI_DELETE_FAILURE_AND_LATER_NAMES_ONLY_ABSENCE'
    assert e2['recorded_at']==STEP2_RECORDED

    assert x['progress_id']==g['progress_id']
    assert x['plan_id']==p['plan_id'] and x['plan_version']==1 and x['plan_digest']==p['plan_digest']
    assert x['record_version']==5 and x['overall_state']=='STOPPED'
    assert x['updated_at']==STEP2_RECORDED
    assert x['progress_digest']==EXECUTION_STEP2_STOP==progress_digest(x)
    s1=x['step_states'][0]
    s2=x['step_states'][1]
    s3=x['step_states'][2]
    assert (s1['authorization_state'],s1['execution_state'],s1['verification_state'],s1['authorization_consumed'])==('CONSUMED','SUCCEEDED','PASS',True)
    assert s1['observed_postcondition']==p['steps'][0]['expected_postcondition'] and s1['safe_error_code'] is None
    assert s1['evidence']==[{
        'evidence_type':'auth.provider-adapter-positive-auth.admin-credential.absence-verified',
        'evidence_reference':N+'-step1-success.evidence.json',
        'evidence_digest':STEP1,
        'recorded_at':STEP1_RECORDED,
    }]
    assert len(s1['binding_assertions'])==2
    assert (s2['authorization_state'],s2['execution_state'],s2['verification_state'],s2['authorization_consumed'])==('CONSUMED','FAILED','FAIL',True)
    assert s2['safe_error_code']==STEP2_STOP
    assert s2['evidence']==[{
        'evidence_type':'auth.provider-adapter-positive-auth.github-binding.retired',
        'evidence_reference':N+'-step2-failure.evidence.json',
        'evidence_digest':STEP2_FAILURE,
        'recorded_at':STEP2_RECORDED,
    }]
    assert len(s2['binding_assertions'])==2
    derived=[b for b in s2['binding_assertions'] if b['phase']=='DERIVED_FROM_SOURCE_STEP']
    assert len(derived)==1 and derived[0]['source_step_id']==p['ordered_step_ids'][0] and derived[0]['evidence_digest']==STEP1
    assert (s3['authorization_state'],s3['execution_state'],s3['verification_state'],s3['authorization_consumed'])==('BLOCKED','NOT_STARTED','NOT_STARTED',False)
    assert s3['evidence']==[] and s3['binding_assertions']==[] and s3['observed_postcondition'] is None and s3['safe_error_code'] is None
    assert not (B/(N+'-step2-success.evidence.json')).exists()
    assert not (B/(N+'-step3-success.evidence.json')).exists()

    rendered='\n'.join((B/(N+s)).read_text() for s in ('.resource.json','-preparation.evidence.json','.plan.json','.progress.json','.approval.json','-step1-success.evidence.json','-step2-failure.evidence.json','.execution-progress.json'))
    rendered+='\n'+(B/'development-implementation-handoff-provider-adapter-positive-auth-v4-github-binding-drift-observation.evidence.json').read_text()
    assert re.search(r'sb_secret_[A-Za-z0-9._-]{8,}',rendered) is None
    assert 'gnuqaefotwgkwurjpyik' not in rendered
    for forbidden in ('service_role','Bearer eyJ'):
        assert forbidden not in rendered

    print('DEVELOPMENT provider-adapter positive-auth v4 GitHub binding drift retirement v1: PASS (STOPPED; Step 1 PASS; Step 2 consumed/failed after nonconforming retry; Step 3 blocked; fresh read-only reconciliation required)')

if __name__=='__main__':
    main()
