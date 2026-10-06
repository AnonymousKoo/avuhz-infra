#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
sys.path.insert(0,str(ROOT/'src'))

from avuhz_engineering.authorization_plan import initial_progress, plan_digest, progress_digest, validate_plan, validate_progress
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

def load(name):
    return json.loads((B/name).read_text())

def main():
    drift=load('development-implementation-handoff-provider-adapter-positive-auth-v4-github-binding-drift-observation.evidence.json')
    r=load(N+'.resource.json')
    prep=load(N+'-preparation.evidence.json')
    p=load(N+'.plan.json')
    g=load(N+'.progress.json')
    old_key=load('development-implementation-handoff-provider-adapter-positive-auth-v4-stale-credential-retirement-v2-step2-success.evidence.json')
    old_gh=load('development-implementation-handoff-provider-adapter-positive-auth-v4-stale-credential-retirement-v2-step4-success.evidence.json')
    old_x=load('development-implementation-handoff-provider-adapter-positive-auth-v4-stale-credential-retirement-v2.execution-progress.json')
    v5=load('development-implementation-handoff-provider-adapter-positive-auth-v5-preactivation-integrity-rejection.evidence.json')
    v6=load('development-implementation-handoff-provider-adapter-positive-auth-v6-step02-plan-integrity-failure.evidence.json')
    v6_retire=load('development-implementation-handoff-provider-adapter-positive-auth-v6-key-retirement-v4.execution-progress.json')

    validate_plan(p,S)
    validate_progress(p,g,S)

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
    assert not (B/(N+'.approval.json')).exists()
    assert not (B/(N+'.execution-progress.json')).exists()

    rendered='\n'.join((B/(N+s)).read_text() for s in ('.resource.json','-preparation.evidence.json','.plan.json','.progress.json'))
    rendered+='\n'+(B/'development-implementation-handoff-provider-adapter-positive-auth-v4-github-binding-drift-observation.evidence.json').read_text()
    assert re.search(r'sb_secret_[A-Za-z0-9._-]{8,}',rendered) is None
    assert 'gnuqaefotwgkwurjpyik' not in rendered
    for forbidden in ('service_role','Bearer eyJ'):
        assert forbidden not in rendered

    print('DEVELOPMENT provider-adapter positive-auth v4 GitHub binding drift retirement v1: PASS (PREPARED / UNAPPROVED / UNEXECUTED; provider key recheck required before exact GitHub binding retirement)')

if __name__=='__main__':
    main()
