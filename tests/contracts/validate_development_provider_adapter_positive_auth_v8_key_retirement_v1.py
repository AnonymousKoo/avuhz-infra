#!/usr/bin/env python3
from __future__ import annotations
import json,re,sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT)); sys.path.insert(0,str(ROOT/'src'))

from avuhz_engineering.authorization_plan import approval_digest, initial_progress, plan_digest, progress_digest, validate_approval, validate_plan, validate_progress
from avuhz_runtime.implementation_handoff import canonical_digest

B=ROOT/'contracts/plans/v1'; S=ROOT/'contracts/schemas/v1'
N='development-implementation-handoff-provider-adapter-positive-auth-v8-key-retirement-v1'
V8='development-implementation-handoff-provider-adapter-positive-auth-v8'
OBS='2026-10-06T12:28:13Z'
START='2026-10-06T13:00:00Z'
END='2026-10-06T17:00:00Z'
APPROVED='2026-10-06T12:41:53Z'
APPROVAL='sha256:943468fef4816fd40d38ffa3f75c105e23ced952a329e72a44fce5773c9d5645'
RESOURCE='sha256:cbd92eb0848549c21be7ae0d7a68ad12e1c61e332511c7e0c39d6c24ae63ea50'
PREP='sha256:7a127efc5018002f2c1a258cca5ac9d1b14b7212e595d42adead2de27822a548'
PLAN='sha256:0675583489849cb3f93063e13aa3a1691e864bef4f9410375ab967dc9e1207a2'
PROGRESS='sha256:3c01c7db130cd08e5e1a0810bd4d3986d39d8055be754299e0d9a5caf9aa8f7c'
V8_STOP='sha256:f84949e6a754181aae0d32b37b4426d849b418fe7ea670f97a294716f5731f4a'
V8_STEP1='sha256:45716b85ea5732486e6bc81319a8aa24b8cfce25a26cfd6775740fd35c3ca6da'
V8_STEP2_FAIL='sha256:2b80c361d731a38a406729136fd6b0f21f94e9e6eb582efbdb3e46a988bd68d1'

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

    validate_plan(p,S); validate_progress(p,g,S); validate_approval(p,a,S,START)

    assert r['contract_digest']==RESOURCE==canonical_digest({k:v for k,v in r.items() if k!='contract_digest'})
    assert prep['evidence_digest']==PREP==canonical_digest({k:v for k,v in prep.items() if k!='evidence_digest'})
    assert p['plan_id']=='71372198-c690-4886-bfb4-ebe201d4c83a'
    assert p['plan_version']==1 and p['plan_digest']==PLAN==plan_digest(p)
    assert p['definition_status']=='READY_FOR_APPROVAL'
    assert p['authority_effect']=='NONE_UNTIL_SEPARATELY_APPROVED'
    assert p['environment']=='DEVELOPMENT'
    assert p['target']['project_reference']=='pwlhruwutoitnieactol'
    assert p['target']['responsibility']=='AUTH'
    assert p['authorization_window']=={'binding_state':'BOUND','starts_at':START,'expires_at':END}

    assert a['approval_id']=='b1fd38d3-fdb6-4a66-9507-25e6b401e271'
    assert a['plan_id']==p['plan_id'] and a['plan_version']==1 and a['plan_digest']==p['plan_digest']
    assert a['owner_identity']==p['owner_identity'] and a['decision']=='APPROVE' and a['environment']=='DEVELOPMENT'
    assert a['approved_at']==APPROVED and APPROVED < START
    assert a['effective_at']==START and a['expires_at']==END
    assert a['status']=='ACTIVE' and a['authority_scope']=='EXACT_PLAN_ONLY'
    assert a['approval_digest']==APPROVAL==approval_digest(a)

    assert r['resource_id']=='832f9872-e758-464f-aacd-c458630bfd25'
    assert r['resource_version']=='provider-adapter-positive-auth-v8-key-retirement.v1'
    assert r['boundary']==N
    assert r['target_key_reference']=='impl_handoff_provider_adapter_positive_auth_v8_ephemeral'
    assert r['github_secret_binding_name']=='AVUHZ_DEVELOPMENT_SUPABASE_AUTH_PROVIDER_ADAPTER_POSITIVE_AUTH_V8_EPHEMERAL'
    assert r['lineage']['v8_execution_progress_digest']==V8_STOP
    assert r['lineage']['v8_step1_key_creation_evidence_digest']==V8_STEP1
    assert r['lineage']['v8_step2_plan_integrity_failure_evidence_digest']==V8_STEP2_FAIL
    assert r['lineage']['v8_overall_state']=='STOPPED'
    assert r['lineage']['v8_github_binding_created'] is False
    assert r['authorized_counts']=={
        'supabase_key_delete':1,'supabase_key_absence_read':1,'github_secret_absence_read':1,
        'github_environment_secret_delete':0,'credential_create':0,'session_issue':0,
        'token_issue':0,'implementation_handoff_execute':0
    }
    assert all(v is False for v in r['security_rules'].values())
    assert r['failure_handling']['v8_execution_must_remain_blocked'] is True
    assert r['failure_handling']['retirement_obligation_remains'] is True
    assert r['failure_handling']['github_binding_mutation_authorized'] is False
    assert r['failure_handling']['retry_v8_authorized'] is False

    assert v8x['overall_state']=='STOPPED' and v8x['progress_digest']==V8_STOP==progress_digest(v8x)
    assert canonical_digest(v8e1)==V8_STEP1
    assert canonical_digest(v8e2)==V8_STEP2_FAIL
    assert v8e1['owner_confirmed_created'] is True and v8e1['credential_material_retained'] is False
    assert v8e2['outcome']=='FAILED_PREEXECUTION_PLAN_INTEGRITY'
    assert v8e2['sanitized_result']['binding_created'] is False

    assert prep['canonical_main_at_preparation']=='cc8c41d6e0b068daf30cfc5091cf2be5d883a852'
    assert prep['resource_contract_digest']==RESOURCE
    assert prep['authorization_window']=={'starts_at':START,'expires_at':END}
    assert prep['prerequisites']=={
        'v8_stopped_progress':V8_STOP,
        'v8_step1_key_creation':V8_STEP1,
        'v8_step2_plan_integrity_failure':V8_STEP2_FAIL,
        'v8_overall_state':'STOPPED',
        'v8_github_binding_created':False,
    }
    assert all(v is False for v in prep['security_state'].values())

    assert [s['operation'] for s in p['steps']]==[
        'provider.auth-admin-credential.delete-dedicated-secret-key',
        'provider.auth-admin-credential.verify-dedicated-secret-key-absent',
        'provider.auth-secret-binding.verify-github-environment-reference-absent',
    ]
    assert all(s['resource']['exact_version']=='provider-adapter-positive-auth-v8-key-retirement.v1' and s['resource']['exact_digest']==RESOURCE for s in p['steps'])
    step1=p['steps'][0]
    assert any(e['evidence_type']=='auth.provider-adapter-positive-auth.admin-credential.created' and e['exact_digest']==V8_STEP1 for e in step1['required_evidence'])
    assert any(e['evidence_type']=='authorization-plan.execution-progress' and e['exact_digest']==V8_STOP for e in step1['required_evidence'])
    assert any(e['evidence_type']=='auth.provider-adapter-positive-auth.github-binding.created' and e['exact_digest']==V8_STEP2_FAIL for e in step1['required_evidence'])
    assert any(e['evidence_type']=='auth.provider-adapter-positive-auth-v8.key-retirement-v1.prepared' and e['exact_digest']==PREP for e in step1['required_evidence'])

    assert g['progress_id']=='05a084cc-6862-42d3-872a-01d51b59efdc'
    assert g['progress_digest']==PROGRESS==progress_digest(g)
    assert g['overall_state']=='NOT_STARTED' and g['record_version']==1
    assert g==initial_progress(p,S,g['progress_id'],OBS)
    assert not (B/(N+'.execution-progress.json')).exists()

    rendered='\n'.join((B/(N+s)).read_text() for s in ('.resource.json','-preparation.evidence.json','.plan.json','.progress.json','.approval.json'))
    assert re.search(r'sb_secret_[A-Za-z0-9._-]{8,}',rendered) is None
    assert 'gnuqaefotwgkwurjpyik' not in rendered
    assert 'service_role' not in rendered and 'Bearer eyJ' not in rendered

    print('DEVELOPMENT provider-adapter positive-auth v8 key retirement v1: PASS (APPROVED / UNEXECUTED; exact v8 key retirement only)')

if __name__=='__main__': main()
