#!/usr/bin/env python3
from __future__ import annotations
import json,re,sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT)); sys.path.insert(0,str(ROOT/'src'))

from avuhz_engineering.authorization_plan import initial_progress, plan_digest, progress_digest, validate_plan, validate_progress
from avuhz_runtime.implementation_handoff import canonical_digest

B=ROOT/'contracts/plans/v1'; S=ROOT/'contracts/schemas/v1'
N='development-implementation-handoff-provider-adapter-positive-auth-v6-key-retirement-v3'
V1='development-implementation-handoff-provider-adapter-positive-auth-v6-key-retirement-v1'
V2='development-implementation-handoff-provider-adapter-positive-auth-v6-key-retirement-v2'
OBS='2026-10-05T19:48:49Z'
START='2026-10-05T22:00:00Z'
END='2026-10-06T02:00:00Z'
V1_LATE='sha256:92b07fb7f7fec8c93603160f9404def011256eb0cbd243068c8e0090905074b4'
V2_REJECT='sha256:40395a1c082cc8b196c63ee6e71e2274580d5dd25a2b1673f97bf09058444014'
RESOURCE='sha256:8c15a7f9f7087f28dc02db9ddbb9fcc99b15fa34a337c6e6ec6fda4373fc8744'
PREP='sha256:6c95b986b935593afa5f931fd89b3e7635a5913490074c98c2cc55f356001662'
PLAN='sha256:ebfd8c2f6978f54e7503adba98cbcd8d6d0d816b015768fe6504594fa9178504'
PROGRESS='sha256:0c4dc0da685d489c8e1f5c2cf96d79f0f8ce66cf05eae3b8ba0e2abc05fa371a'

def load(name): return json.loads((B/name).read_text())

def main():
    r=load(N+'.resource.json')
    prep=load(N+'-preparation.evidence.json')
    p=load(N+'.plan.json')
    g=load(N+'.progress.json')
    late=load(V1+'-late-window-rejection.evidence.json')
    reject=load(V2+'-binding-integrity-rejection.evidence.json')

    validate_plan(p,S); validate_progress(p,g,S)

    assert r['contract_digest']==RESOURCE==canonical_digest({k:v for k,v in r.items() if k!='contract_digest'})
    assert prep['evidence_digest']==PREP==canonical_digest({k:v for k,v in prep.items() if k!='evidence_digest'})
    assert late['evidence_digest']==V1_LATE==canonical_digest({k:v for k,v in late.items() if k!='evidence_digest'})
    assert reject['evidence_digest']==V2_REJECT==canonical_digest({k:v for k,v in reject.items() if k!='evidence_digest'})
    assert reject['outcome']=='REJECTED_PREACTIVATION_BINDING_INTEGRITY'
    assert reject['approval_artifact_created'] is False and reject['approval_canonicalized'] is False
    assert all(v is False for v in reject['provider_effects'].values())
    assert reject['findings']['binding_matches'] is False

    assert p['plan_id']=='d8e7c977-56f9-52c9-8313-476bfebb3421'
    assert p['plan_version']==3 and p['plan_digest']==PLAN==plan_digest(p)
    assert p['definition_status']=='READY_FOR_APPROVAL'
    assert p['authority_effect']=='NONE_UNTIL_SEPARATELY_APPROVED'
    assert p['environment']=='DEVELOPMENT'
    assert p['target']['project_reference']=='pwlhruwutoitnieactol'
    assert p['target']['responsibility']=='AUTH'
    assert p['authorization_window']=={'binding_state':'BOUND','starts_at':START,'expires_at':END}

    assert r['resource_id']=='eb27ac6d-c208-5c58-a2d1-2b3cdf52c794'
    assert r['resource_version']=='provider-adapter-positive-auth-v6-key-retirement.v3'
    assert r['boundary']==N
    assert r['target_key_reference']=='impl_handoff_provider_adapter_positive_auth_v6_ephemeral'
    assert r['github_secret_binding_name']=='AVUHZ_DEVELOPMENT_SUPABASE_AUTH_PROVIDER_ADAPTER_POSITIVE_AUTH_V6_EPHEMERAL'
    assert r['lineage']['v2_retirement_plan_id']=='bd21e7ce-1c20-5029-abe6-fb0ba566308f'
    assert r['lineage']['v2_retirement_plan_digest']=='sha256:730fe1527d88b35b8ec4ef29c46f87f2e2c840e6a6c74d21284e37dcee48e2fb'
    assert r['lineage']['v2_binding_integrity_rejection_evidence_digest']==V2_REJECT
    assert r['lineage']['v2_approval_canonicalized'] is False
    assert r['authorized_counts']=={
        'supabase_key_delete':1,'supabase_key_absence_read':1,'github_secret_absence_read':1,
        'github_environment_secret_delete':0,'credential_create':0,'session_issue':0,
        'token_issue':0,'implementation_handoff_execute':0
    }
    assert all(v is False for v in r['security_rules'].values())

    step1=p['steps'][0]
    prep_bindings=[x for x in step1['required_evidence'] if x['evidence_type']=='auth.provider-adapter-positive-auth-v6.key-retirement-v3.prepared']
    assert prep_bindings==[{
        'evidence_type':'auth.provider-adapter-positive-auth-v6.key-retirement-v3.prepared',
        'source_step_id':None,'binding_state':'BOUND','exact_digest':PREP
    }]
    reject_bindings=[x for x in step1['required_evidence'] if x['evidence_type']=='auth.provider-adapter-positive-auth-v6.key-retirement-v2.preactivation-binding-integrity-rejected']
    assert reject_bindings==[{
        'evidence_type':'auth.provider-adapter-positive-auth-v6.key-retirement-v2.preactivation-binding-integrity-rejected',
        'source_step_id':None,'binding_state':'BOUND','exact_digest':V2_REJECT
    }]
    assert all(s['resource']['exact_version']=='provider-adapter-positive-auth-v6-key-retirement.v3' and s['resource']['exact_digest']==RESOURCE for s in p['steps'])
    assert [s['operation'] for s in p['steps']]==[
        'provider.auth-admin-credential.delete-dedicated-secret-key',
        'provider.auth-admin-credential.verify-dedicated-secret-key-absent',
        'provider.auth-secret-binding.verify-github-environment-reference-absent',
    ]

    assert g['progress_id']=='ff25120d-f443-58ac-8e9e-6eb066486aab'
    assert g['progress_digest']==PROGRESS==progress_digest(g)
    assert g['overall_state']=='NOT_STARTED' and g['record_version']==1
    assert g==initial_progress(p,S,g['progress_id'],OBS)
    assert not (B/(N+'.approval.json')).exists()
    assert not (B/(N+'.execution-progress.json')).exists()

    rendered='\n'.join((B/(N+s)).read_text() for s in ('.resource.json','-preparation.evidence.json','.plan.json','.progress.json'))
    assert re.search(r'sb_secret_[A-Za-z0-9._-]{8,}',rendered) is None
    assert 'gnuqaefotwgkwurjpyik' not in rendered

    print('DEVELOPMENT provider-adapter positive-auth v6 key retirement v3: PASS (PREPARED / UNAPPROVED / UNEXECUTED; exact v3 preparation binding; one-key retirement scope only)')

if __name__=='__main__': main()
