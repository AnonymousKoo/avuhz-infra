#!/usr/bin/env python3
from __future__ import annotations
import json,re,sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT)); sys.path.insert(0,str(ROOT/'src'))

from avuhz_engineering.authorization_plan import initial_progress, plan_digest, progress_digest, validate_plan, validate_progress
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

def load(name): return json.loads((B/name).read_text())

def main():
    r=load(N+'.resource.json')
    prep=load(N+'-preparation.evidence.json')
    p=load(N+'.plan.json')
    g=load(N+'.progress.json')
    late=load(V1+'-late-window-rejection.evidence.json')
    reject2=load(V2+'-binding-integrity-rejection.evidence.json')
    reject3=load(V3+'-preapproval-effective-time-rejection.evidence.json')

    validate_plan(p,S); validate_progress(p,g,S)

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
    assert not (B/(N+'.approval.json')).exists()
    assert not (B/(N+'.execution-progress.json')).exists()

    rendered='\n'.join((B/(N+s)).read_text() for s in ('.resource.json','-preparation.evidence.json','.plan.json','.progress.json'))
    assert re.search(r'sb_secret_[A-Za-z0-9._-]{8,}',rendered) is None
    assert 'gnuqaefotwgkwurjpyik' not in rendered

    print('DEVELOPMENT provider-adapter positive-auth v6 key retirement v4: PASS (PREPARED / UNAPPROVED / UNEXECUTED; v3 preapproval expiry preserved; one-key retirement scope only)')

if __name__=='__main__': main()
