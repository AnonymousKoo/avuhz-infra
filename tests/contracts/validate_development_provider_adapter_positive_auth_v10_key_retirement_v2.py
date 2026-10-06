#!/usr/bin/env python3
from __future__ import annotations
import json,re,sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT)); sys.path.insert(0,str(ROOT/'src'))

from avuhz_engineering.authorization_plan import approval_digest, authorize_step, initial_progress, plan_digest, progress_digest, record_step_outcome, validate_approval, validate_plan, validate_progress
from avuhz_runtime.implementation_handoff import canonical_digest

B=ROOT/'contracts/plans/v1'; S=ROOT/'contracts/schemas/v1'
N='development-implementation-handoff-provider-adapter-positive-auth-v10-key-retirement-v2'
V1='development-implementation-handoff-provider-adapter-positive-auth-v10-key-retirement-v1'
OBS='2026-10-06T23:13:55Z'
START='2026-10-06T23:45:00Z'
END='2026-10-07T01:00:00Z'
APPROVED='2026-10-06T23:21:05Z'
APPROVAL='sha256:c6bc8054465dbd808d3f30c1f49727791e7a7550a4ff04e0078c7b67ffc40b35'
RECORDED='2026-10-06T23:51:29Z'
AUTH_OBS='sha256:18a867872c30017c6c083b223dbe1cd6f98b8902fc1468886317c80c6a71cd7f'
RESULT='sha256:eed04c4ce32ce7cd31e6424cd362da72c0569263130c2abcb0e84bf537791b9b'
SUCCESS='sha256:1bef85f2ce88601d1a895ea9cb0ce5c9d2bb35a61ffcb05dbf15ecb9d15eacea'
COMPLETED='sha256:edc6600fb780bdff9b9b699d884d2fe739abcf1876f9af2cee27b246b1b5fd4a'
RESOURCE='sha256:48b4b14ffa86294ef442bb0b72855abb3bcf5d892247dd82958195a33a96f4f3'
PREP='sha256:486acbf417a1677d11eecce754aa8301e7c0401fedcdb89167701066466b3bc6'
PLAN='sha256:bb5219953b0b35735b99ec7078350fc039df19210456bdd67e2cc4d1f8a8eb73'
PROGRESS='sha256:9e8071ce2caa8e168d7b7a725b416f06faad031a474fa308ff5dffeee129b048'
V1_STEP1='sha256:35044d1166daa983e06781334c05d0002f877992cc9d9ca2ebe6a8bff597815e'
V1_STEP2='sha256:cfaeca271afa9a51db7ff0390f45548a6e7b9e1864436c51e7d3acd1a89ae0e7'
V1_PROGRESS='sha256:980bd163d03623f901d1f80e0fd25fbb70a8e06f1e3de1620af29cfb56c6e5a2'
INCIDENT='sha256:45c5a8f402d6d675ef25e1b4d77c1ad4c6a9f2a5090d1d11e36ed00bea873355'
SECRET='AVUHZ_DEVELOPMENT_SUPABASE_AUTH_PROVIDER_ADAPTER_POSITIVE_AUTH_V10_EPHEMERAL'

def load(name): return json.loads((B/name).read_text())

def main():
    r=load(N+'.resource.json'); prep=load(N+'-preparation.evidence.json')
    p=load(N+'.plan.json'); g=load(N+'.progress.json'); a=load(N+'.approval.json'); success=load(N+'-step1-success.evidence.json'); x=load(N+'.execution-progress.json')
    v1e1=load(V1+'-step1-success.evidence.json'); v1e2=load(V1+'-step2-success.evidence.json')
    v1x=load(V1+'.execution-progress.json'); incident=load(V1+'-post-window-github-outcome.evidence.json')

    validate_plan(p,S); validate_progress(p,g,S); validate_approval(p,a,S,START); validate_approval(p,a,S,RECORDED); validate_progress(p,x,S)
    assert r['contract_digest']==RESOURCE==canonical_digest({k:v for k,v in r.items() if k!='contract_digest'})
    assert prep['evidence_digest']==PREP==canonical_digest({k:v for k,v in prep.items() if k!='evidence_digest'})
    assert p['plan_digest']==PLAN==plan_digest(p)
    assert g['progress_digest']==PROGRESS==progress_digest(g)
    assert g==initial_progress(p,S,g['progress_id'],OBS)

    assert p['plan_id']=='6e4b2d91-8c35-4fa7-b120-5d9e3c6a7f42' and p['plan_version']==2
    assert p['definition_status']=='READY_FOR_APPROVAL' and p['authority_effect']=='NONE_UNTIL_SEPARATELY_APPROVED'
    assert p['authorization_window']=={'binding_state':'BOUND','starts_at':START,'expires_at':END}
    assert p['target']['provider_reference']=='github'
    assert p['target']['project_reference']=='pwlhruwutoitnieactol' and p['target']['responsibility']=='AUTH'
    assert len(p['steps'])==1 and p['steps'][0]['execution_class']=='PROVIDER_READ'
    assert p['steps'][0]['operation']=='provider.auth-secret-binding.verify-github-environment-reference-absent'
    assert SECRET in p['steps'][0]['resource']['resource_reference']
    assert 'github-secret.mutate' in p['steps'][0]['prohibited_actions']
    assert 'provider.mutation' in p['steps'][0]['prohibited_actions']

    assert canonical_digest(v1e1)==V1_STEP1
    assert canonical_digest(v1e2)==V1_STEP2
    assert v1x['progress_digest']==V1_PROGRESS==progress_digest(v1x)
    assert v1x['step_states'][0]['verification_state']=='PASS' and v1x['step_states'][1]['verification_state']=='PASS'
    assert v1x['step_states'][2]['authorization_state']=='PENDING' and v1x['step_states'][3]['authorization_state']=='PENDING'
    assert incident['evidence_digest']==INCIDENT==canonical_digest({k:v for k,v in incident.items() if k!='evidence_digest'})
    assert incident['authorization_assessment']['step3_recordable_as_authorized'] is False
    assert incident['authorization_assessment']['step4_recordable_as_authorized'] is False
    assert incident['authorization_assessment']['retirement_v1_execution_progress_may_be_retroactively_advanced'] is False

    assert r['lineage']['v1_step1_key_retirement_evidence_digest']==V1_STEP1
    assert r['lineage']['v1_step2_key_absence_evidence_digest']==V1_STEP2
    assert r['lineage']['v1_steps1_2_execution_progress_digest']==V1_PROGRESS
    assert r['lineage']['v1_post_window_github_outcome_evidence_digest']==INCIDENT
    assert r['authorized_counts']=={
        'supabase_key_delete':0,'supabase_key_absence_read':0,'github_secret_absence_read':1,
        'github_environment_secret_delete':0,'credential_create':0,'session_issue':0,
        'token_issue':0,'implementation_handoff_execute':0
    }
    assert all(v is False for v in r['security_rules'].values())
    assert r['failure_handling']['retirement_v1_steps3_4_must_not_be_retroactively_advanced'] is True
    assert r['failure_handling']['provider_mutation_authorized'] is False
    assert r['failure_handling']['github_binding_mutation_authorized'] is False

    assert prep['canonical_main_at_preparation']=='6f11525b6e7877f190f2b5b0402da781cd36f57e'
    assert prep['resource_contract_digest']==RESOURCE
    assert prep['authorization_window']=={'starts_at':START,'expires_at':END}
    assert all(v is False for v in prep['security_state'].values())

    assert g['overall_state']=='NOT_STARTED' and g['record_version']==1
    assert a['approval_id']=='9c5e2a71-4d63-4b8f-a120-7e3d6c9b5f42'
    assert a['plan_id']==p['plan_id'] and a['plan_version']==2 and a['plan_digest']==p['plan_digest']
    assert a['owner_identity']==p['owner_identity'] and a['decision']=='APPROVE' and a['environment']=='DEVELOPMENT'
    assert a['approved_at']==APPROVED and APPROVED < START
    assert a['effective_at']==START and a['expires_at']==END
    assert a['status']=='ACTIVE' and a['authority_scope']=='EXACT_PLAN_ONLY'
    assert a['approval_digest']==APPROVAL==approval_digest(a)
    auth_obs={
        'interaction_surface':'github.repository.settings.environments.development.secrets',
        'execution_actor':'OWNER_MANUAL_UI',
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
        'secret_name':SECRET,
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
    assert success['classification']=='EXACT_V10_GITHUB_BINDING_ABSENCE_OWNER_VERIFIED'
    assert success['authorization_observation']==auth_obs
    assert success['authorization_observation_digest']==AUTH_OBS
    assert success['sanitized_result']==result
    assert success['result_digest']==RESULT
    assert success['verification_observation']=={
        'exact_reference_absent':True,
        'name_only':True,
        'postcondition_verified':True,
    }
    assert all(v is False for v in success['security_state'].values())
    assert success['record_basis']=='OWNER_CONFIRMED_NAMES_ONLY_ABSENCE_INSPECTION'
    assert success['recorded_at']==RECORDED

    preflight={
        'binding_id':N+'.step1-owner-session',
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
        'step_id':p['steps'][0]['step_id'],
        'resource_reference':p['steps'][0]['resource']['resource_reference'],
        'resource_version':p['steps'][0]['resource']['exact_version'],
        'resource_digest':p['steps'][0]['resource']['exact_digest'],
        'operation':p['steps'][0]['operation'],
        'execution_class':p['steps'][0]['execution_class'],
        'credential_class':'OWNER_INTERACTIVE_SESSION',
        'required_evidence':[
            {'evidence_type':e['evidence_type'],'evidence_digest':e['exact_digest']}
            for e in p['steps'][0]['required_evidence']
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
        p,a,authorized,p['steps'][0]['step_id'],'SUCCEEDED','PASS',outcome_evidence,
        p['steps'][0]['expected_postcondition'],None,S,RECORDED,binding_assertions=[produced],
    )
    assert x==expected
    assert x['progress_digest']==COMPLETED==progress_digest(x)
    assert x['overall_state']=='COMPLETED' and x['record_version']==3
    state=x['step_states'][0]
    assert (state['authorization_state'],state['execution_state'],state['verification_state'],state['authorization_consumed'])==('CONSUMED','SUCCEEDED','PASS',True)

    rendered='\n'.join((B/(N+s)).read_text() for s in ('.resource.json','-preparation.evidence.json','.plan.json','.progress.json','.approval.json','-step1-success.evidence.json','.execution-progress.json'))
    assert re.search(r'sb_secret_[A-Za-z0-9._-]{8,}',rendered) is None
    assert 'gnuqaefotwgkwurjpyik' not in rendered
    assert 'service_role' not in rendered and 'Bearer eyJ' not in rendered
    print('DEVELOPMENT provider-adapter positive-auth v10 key retirement v2: PASS (COMPLETED; exact GitHub development secret reference absent by name only; no mutation)')

if __name__=='__main__': main()
