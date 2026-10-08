#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
sys.path.insert(0,str(ROOT/'src'))

from avuhz_engineering.authorization_plan import approval_digest, authorize_step, initial_progress, plan_digest, progress_digest, record_step_outcome, validate_approval, validate_plan, validate_progress
from avuhz_runtime.implementation_handoff import canonical_digest

B=ROOT/'contracts/plans/v1'
S=ROOT/'contracts/schemas/v1'
N='development-implementation-handoff-provider-adapter-positive-auth-v4-github-binding-absence-reconciliation-v1'
PREDECESSOR='development-implementation-handoff-provider-adapter-positive-auth-v4-github-binding-drift-retirement-v1'
RESOURCE='sha256:afc2833fb1cc19192cefb6f217cf1263e6ac08416c9fcc9e6d7b758166dad3aa'
PREP='sha256:8cbcc7f324280d9eec3198311759af9592c0db8993814093c4f91edad083e935'
PLAN='sha256:3623489701b2af869a2c82e20eb9e1a2dd90814df7a5b714ca8e287b26ee68df'
PROGRESS='sha256:6c826ae60f80a84b4095136ca10d5dd62ca95210fa3993fc96e4ceb7e55130bc'
PREDECESSOR_STEP1='sha256:7e30a4d2e973a4e5cab4e2a97e76e11b3deda2b49ee682721d7c6f8aebc83bd4'
PREDECESSOR_STEP2_FAILURE='sha256:5b46a52a3881eb6afdb094825a012ccd2cc54d045ca80c29c1eb68ec9a1b77d2'
PREDECESSOR_STOPPED='sha256:fc38e77792c472d6e135a3e9310c4f78af988acba36748df45946b6f00c4d48b'
CREATED='2026-10-06T03:45:28Z'
START='2026-10-06T04:15:00Z'
END='2026-10-06T06:00:00Z'
APPROVED='2026-10-06T03:53:35Z'
APPROVAL='sha256:d9a2f072a0513e62bc5bc45cecb387effaa0d64c125ea05d0a3d092177d6b823'
RECORDED='2026-10-06T04:22:51Z'
AUTH_OBS='sha256:44db0a2e89b335c72fdb4b383c423e189a588b142d303afb21a2e97e317e4376'
RESULT='sha256:027fdc476ca7df7e60727a07da5b9cc3395c9c1ca7bdd58a31928b2048f303ff'
SUCCESS='sha256:1c0b6abf5a3e49ffd9dec1b2573918f4e7046ae7dd0144e6d31645d09bcf2773'
COMPLETED='sha256:57365c1791a9548568bb19515f70270e80b4ff1e4f3fa26f4560ebb6a3a572e9'

def load(name):
    return json.loads((B/name).read_text())

def main():
    e1=load(PREDECESSOR+'-step1-success.evidence.json')
    e2=load(PREDECESSOR+'-step2-failure.evidence.json')
    old_x=load(PREDECESSOR+'.execution-progress.json')
    r=load(N+'.resource.json')
    prep=load(N+'-preparation.evidence.json')
    p=load(N+'.plan.json')
    g=load(N+'.progress.json')
    a=load(N+'.approval.json')
    success=load(N+'-step1-success.evidence.json')
    x=load(N+'.execution-progress.json')

    validate_plan(p,S)
    validate_progress(p,g,S)
    validate_approval(p,a,S,START)
    validate_approval(p,a,S,RECORDED)
    validate_progress(p,x,S)

    assert canonical_digest(e1)==PREDECESSOR_STEP1
    assert e1['sanitized_result']['absence_reported_by_owner'] is True
    assert canonical_digest(e2)==PREDECESSOR_STEP2_FAILURE
    assert e2['outcome']=='FAILED_NONCONFORMING_RETRY'
    assert e2['authority_state']['retry_authorized'] is False
    assert e2['sanitized_runtime_outcome']['fresh_reconciliation_required'] is True
    assert old_x['progress_digest']==PREDECESSOR_STOPPED==progress_digest(old_x)
    assert old_x['overall_state']=='STOPPED'
    assert old_x['step_states'][1]['execution_state']=='FAILED'
    assert old_x['step_states'][2]['authorization_state']=='BLOCKED'

    assert r['contract_digest']==RESOURCE==canonical_digest({k:v for k,v in r.items() if k!='contract_digest'})
    assert r['environment']=='DEVELOPMENT' and r['provider']=='github' and r['responsibility']=='AUTH'
    assert r['repository']=='AnonymousKoo/avuhz-infra' and r['github_environment']=='development'
    assert r['source_auth_project_reference']=='pwlhruwutoitnieactol'
    assert r['target_secret_binding_name']=='AVUHZ_DEVELOPMENT_SUPABASE_AUTH_PROVIDER_ADAPTER_POSITIVE_AUTH_V4_EPHEMERAL'
    assert r['authorized_counts']=={
        'github_secret_absence_read':1,
        'github_environment_secret_delete':0,
        'github_environment_secret_create':0,
        'supabase_key_read':0,
        'supabase_key_delete':0,
        'credential_create':0,
        'session_issue':0,
        'token_issue':0,
        'implementation_handoff_execute':0,
    }
    assert all(v is False for v in r['security_rules'].values())
    assert r['execution_rules']['read_only_names_only'] is True
    assert r['execution_rules']['provider_mutation_authorized'] is False
    assert r['execution_rules']['window_starts_at']==START and r['execution_rules']['window_expires_at']==END

    assert prep['evidence_digest']==PREP==canonical_digest({k:v for k,v in prep.items() if k!='evidence_digest'})
    assert prep['resource_contract_digest']==RESOURCE
    assert prep['stopped_retirement_step2_failure_evidence_digest']==PREDECESSOR_STEP2_FAILURE
    assert prep['stopped_retirement_execution_progress_digest']==PREDECESSOR_STOPPED
    assert prep['provider_authority']=='NONE' and prep['external_provider_contact']=='PROHIBITED'
    assert prep['authorization_window']=={'starts_at':START,'expires_at':END}
    assert all(v is False for v in prep['security_state'].values())

    assert p['plan_id']=='aa947bad-a7be-4460-bbb5-dbfa4f8a7250'
    assert p['plan_version']==1 and p['definition_status']=='READY_FOR_APPROVAL'
    assert p['environment']=='DEVELOPMENT'
    assert p['plan_digest']==PLAN==plan_digest(p)
    assert p['authorization_window']=={'binding_state':'BOUND','starts_at':START,'expires_at':END}
    assert p['authority_effect']=='NONE_UNTIL_SEPARATELY_APPROVED'
    assert len(p['steps'])==1
    step=p['steps'][0]
    assert step['operation']=='provider.auth-secret-binding.verify-github-environment-reference-absent'
    assert step['execution_class']=='PROVIDER_READ'
    assert step['credential_policy']=={'permitted':True,'allowed_classes':['OWNER_INTERACTIVE_SESSION'],'values_stored':False}
    assert step['resource']['exact_digest']==RESOURCE
    assert step['dependency_step_ids']==[]
    assert [e['exact_digest'] for e in step['required_evidence']]==[
        PREDECESSOR_STEP1,PREDECESSOR_STEP2_FAILURE,PREDECESSOR_STOPPED
    ]
    assert 'github-secret.mutate' in step['prohibited_actions']
    assert 'github-secret.delete' in step['prohibited_actions']
    assert 'provider.mutation' in step['prohibited_actions']
    assert 'supabase.operation' in step['prohibited_actions']
    assert 'secret-reference.present' in step['stop_conditions']
    assert step['correction_reference']=='correction.stop-for-owner-review-no-retry'
    assert len(step['binding_declarations'])==5
    assert sum(1 for b in step['binding_declarations'] if b['phase']=='PREAPPROVAL_BOUND')==3

    assert g['progress_digest']==PROGRESS==progress_digest(g)
    assert g==initial_progress(p,S,g['progress_id'],CREATED)
    assert g['overall_state']=='NOT_STARTED' and g['record_version']==1
    assert all((s['authorization_state'],s['execution_state'],s['verification_state'],s['authorization_consumed'])==('PENDING','NOT_STARTED','NOT_STARTED',False) for s in g['step_states'])
    assert a['approval_id']=='348b2bd4-2c3c-4288-b886-4f3b0e926452'
    assert a['plan_id']==p['plan_id'] and a['plan_version']==1 and a['plan_digest']==p['plan_digest']
    assert a['owner_identity']==p['owner_identity'] and a['decision']=='APPROVE' and a['environment']=='DEVELOPMENT'
    assert a['approved_at']==APPROVED and a['effective_at']==START and a['expires_at']==END
    assert a['status']=='ACTIVE' and a['authority_scope']=='EXACT_PLAN_ONLY'
    assert a['approval_digest']==APPROVAL==approval_digest(a)
    assert APPROVED < START

    auth_obs={
        'interaction_surface':'github.web.settings.environments.development.secrets',
        'execution_actor':'OWNER_MANUAL_FIREFOX',
        'repository':'AnonymousKoo/avuhz-infra',
        'environment':'development',
        'responsibility':'AUTH',
        'approval_exact':True,
        'authorization_window_active':True,
        'credential_class':'OWNER_INTERACTIVE_SESSION',
        'secret_value_requested':False,
        'secret_value_observed':False,
        'provider_mutation_attempted':False,
    }
    result={
        'repository':'AnonymousKoo/avuhz-infra',
        'environment':'development',
        'secret_name':'AVUHZ_DEVELOPMENT_SUPABASE_AUTH_PROVIDER_ADAPTER_POSITIVE_AUTH_V4_EPHEMERAL',
        'exact_secret_reference_count':0,
        'absent':True,
        'secret_value_requested':False,
        'secret_value_observed':False,
        'provider_mutation_performed':False,
    }
    assert canonical_digest(auth_obs)==AUTH_OBS
    assert canonical_digest(result)==RESULT
    assert canonical_digest(success)==SUCCESS
    assert success['outcome']=='SUCCEEDED_VERIFIED'
    assert success['classification']=='EXACT_V4_GITHUB_BINDING_ABSENCE_OWNER_VERIFIED'
    assert success['authorization_observation']==auth_obs
    assert success['authorization_observation_digest']==AUTH_OBS
    assert success['sanitized_result']==result
    assert success['result_digest']==RESULT
    assert success['execution_observation']=={
        'execution_class':'PROVIDER_READ',
        'execution_timestamp_retained':False,
        'recorded_at_is_execution_timestamp':False,
        'approved_absence_read_attempts':1,
        'secret_value_requested':False,
        'secret_value_read':False,
        'provider_mutation_attempted':False,
        'retry_occurred':False,
    }
    assert success['verification_observation']=={
        'exact_reference_absent':True,
        'name_only':True,
        'postcondition_verified':True,
    }
    assert all(v is False for v in success['security_state'].values())
    assert success['record_basis']=='OWNER_CONFIRMED_NAMES_ONLY_ABSENCE_INSPECTION'
    assert success['recorded_at']==RECORDED

    preflight={
        'binding_id':N+'.github-read-session',
        'phase':'RESOLVED_BY_STEP_PREFLIGHT',
        'value_class':'CONFIGURATION_REFERENCE',
        'source_step_id':None,
        'evidence_type':'provider.owner-interactive-session.observed',
        'evidence_digest':AUTH_OBS,
        'digest_policy':'REQUIRED',
        'persistence_policy':'DIGEST_ONLY',
        'sanitized_value':None,
        'value_digest':AUTH_OBS,
        'recorded_at':RECORDED,
    }
    request={
        'plan_id':p['plan_id'],
        'plan_version':p['plan_version'],
        'plan_digest':p['plan_digest'],
        'environment':p['environment'],
        'provider_reference':p['target']['provider_reference'],
        'project_reference':p['target']['project_reference'],
        'responsibility':p['target']['responsibility'],
        'issuer_reference':p['target']['issuer_reference'],
        'audience_reference':p['target']['audience_reference'],
        'step_id':step['step_id'],
        'resource_reference':step['resource']['resource_reference'],
        'resource_version':step['resource']['exact_version'],
        'resource_digest':step['resource']['exact_digest'],
        'operation':step['operation'],
        'execution_class':step['execution_class'],
        'credential_class':'OWNER_INTERACTIVE_SESSION',
        'required_evidence':[
            {'evidence_type':e['evidence_type'],'evidence_digest':e['exact_digest']}
            for e in step['required_evidence']
        ],
        'prior_evidence_digests':[],
        'unexpected_remote_state':False,
        'extra_privileges':False,
        'unauthorized_migration_surface':False,
        'scope_expansion':False,
    }
    authorized=authorize_step(p,a,g,request,S,RECORDED,trusted_preflight_assertions=[preflight])
    outcome_evidence=[{
        'evidence_type':'auth.provider-adapter-positive-auth.github-binding.absence-verified',
        'evidence_reference':N+'-step1-success.evidence.json',
        'evidence_digest':SUCCESS,
        'recorded_at':RECORDED,
    }]
    produced={
        'binding_id':N+'.github-binding-absence',
        'phase':'PRODUCED_BY_CURRENT_STEP',
        'value_class':'CONTENT_DIGEST',
        'source_step_id':None,
        'evidence_type':'auth.provider-adapter-positive-auth.github-binding.absence-verified',
        'evidence_digest':SUCCESS,
        'digest_policy':'REQUIRED',
        'persistence_policy':'DIGEST_ONLY',
        'sanitized_value':None,
        'value_digest':RESULT,
        'recorded_at':RECORDED,
    }
    expected=record_step_outcome(
        p,a,authorized,step['step_id'],'SUCCEEDED','PASS',outcome_evidence,
        step['expected_postcondition'],None,S,RECORDED,binding_assertions=[produced],
    )
    assert x==expected
    assert x['progress_digest']==COMPLETED==progress_digest(x)
    assert x['overall_state']=='COMPLETED' and x['record_version']==3
    state=x['step_states'][0]
    assert (state['authorization_state'],state['execution_state'],state['verification_state'],state['authorization_consumed'])==('CONSUMED','SUCCEEDED','PASS',True)
    assert state['safe_error_code'] is None
    assert state['evidence']==outcome_evidence
    assert state['binding_assertions']==[preflight,produced]

    rendered='\n'.join((B/(N+s)).read_text() for s in ('.resource.json','-preparation.evidence.json','.plan.json','.progress.json','.approval.json','-step1-success.evidence.json','.execution-progress.json'))
    assert re.search(r'sb_secret_[A-Za-z0-9._-]{8,}',rendered) is None
    assert 'gnuqaefotwgkwurjpyik' not in rendered
    for forbidden in ('service_role','Bearer eyJ'):
        assert forbidden not in rendered

    print('DEVELOPMENT provider-adapter positive-auth v4 GitHub binding absence reconciliation v1: PASS (COMPLETED; exact GitHub development secret reference absent by name only)')

if __name__=='__main__':
    main()
