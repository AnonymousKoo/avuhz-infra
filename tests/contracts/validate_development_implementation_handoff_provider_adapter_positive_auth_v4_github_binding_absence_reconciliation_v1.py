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

    validate_plan(p,S)
    validate_progress(p,g,S)
    validate_approval(p,a,S,START)

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
    assert not (B/(N+'.execution-progress.json')).exists()

    rendered='\n'.join((B/(N+s)).read_text() for s in ('.resource.json','-preparation.evidence.json','.plan.json','.progress.json','.approval.json'))
    assert re.search(r'sb_secret_[A-Za-z0-9._-]{8,}',rendered) is None
    assert 'gnuqaefotwgkwurjpyik' not in rendered
    for forbidden in ('service_role','Bearer eyJ'):
        assert forbidden not in rendered

    print('DEVELOPMENT provider-adapter positive-auth v4 GitHub binding absence reconciliation v1: PASS (APPROVED / UNEXECUTED; read-only names-only GitHub absence verification only)')

if __name__=='__main__':
    main()
