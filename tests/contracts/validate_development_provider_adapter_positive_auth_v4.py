#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'src'))

from avuhz_engineering.authorization_plan import approval_digest, initial_progress, plan_digest, progress_digest, validate_approval, validate_plan, validate_progress
from avuhz_runtime.implementation_handoff import canonical_digest

B = ROOT / 'contracts/plans/v1'
S = ROOT / 'contracts/schemas/v1'
N = 'development-implementation-handoff-provider-adapter-positive-auth-v4'
PLAN_ID = 'dd18445f-1bde-5523-9f5f-82231b39abde'
PLAN_DIGEST = 'sha256:77d92723177eae2dc690566496710c3a7520bf3d329926ddf1b5894929d7ed5a'
PROGRESS_ID = '8b032ad0-77d1-5eda-a5ae-d4966d6a7806'
PROGRESS_DIGEST = 'sha256:fcd4f6f57c1572ddac6a9d75179a4244bca8be0d73c48f1a5cf2e0ba768dad5e'
RESOURCE_DIGEST = 'sha256:f9212335059992f50b1d6c1f50c227495e97796962b8f67f843f81f6465a9d34'
PREP_DIGEST = 'sha256:5f0289997a8dd36c3c03eff391a95a06b308ebf04d4fa96d1274d879758eed9b'
QUERY_DIGEST = 'sha256:0d785af10877d43bd4d886a534438dc21a6dd4471ac80194630feef29af73f8e'
CREATED_AT = '2026-10-04T21:43:57Z'
WINDOW_START = '2026-10-04T23:00:00Z'
WINDOW_END = '2026-10-05T03:00:00Z'
PROJECT = 'pwlhruwutoitnieactol'
DATA_PROJECT = 'gnuqaefotwgkwurjpyik'
KEY = 'impl_handoff_provider_adapter_positive_auth_v4_ephemeral'
GH = 'AVUHZ_DEVELOPMENT_SUPABASE_AUTH_PROVIDER_ADAPTER_POSITIVE_AUTH_V4_EPHEMERAL'
PASSWORDLESS = 'sha256:26a90c35357ac14b23d1b7f17e18762e958248462d53aed168985dba249cbb10'
TENANT = 'sha256:42a33b97e8ab5c8fd9c7972d5d4a9cad57d06135ea9a05952ed6f669026c3936'
ALLOWLIST = 'sha256:07b1103c5a90a04849e4cc6c4d9c303adcf09b7a639086ae88a90979ad301325'
RUNTIME = 'sha256:f49f6882f2e6ec0274935137a52c7b7c942bfbe0bc72baebca143a90aedc5345'
RUNTIME_PROGRESS = 'sha256:762fc38748aeb4483a5b26179a703e687bab13e7f5c73160b29a3a77d4480e5c'
FAILURE = 'sha256:27c324aa9f0c155fb5c75125cdc4ce24bb160e1bf06af1fd2d08bd75039180c9'
STOPPED = 'sha256:730f4c0a7b6393223c85cd5746472e1227bb9c77d174e8644075c4dc1722bd6b'
CLEAN_ZERO = 'sha256:5a4183d202fc94f948b25e9c60a59136e9b81687728bf02ecb116ceba25709d1'
CLEAN_KEY_ABSENT = 'sha256:338e9648389d857871c816d9e4ad5c814300c3a92de45671da77e2564274a60f'
CLEAN_GH_ABSENT = 'sha256:318709e7c83d2e701552b4daaa9769120ccade381c3aeaf179132489f9ff3de4'
CLEAN_PROGRESS = 'sha256:e48fe89e45b47e31b5439ccefe2240ab0edc3e9f2e377d10c2f799e617bc08a4'
V3_INCIDENT_RAW = 'sha256:1626e91cafb4bdffd60553c6b0b6805bf5a97d5ba70d02670627999bf231a8b3'
V3_RETIRE_GH_ABSENT_RAW = 'sha256:8fe9637d3b9c559063eca8e732a7b3a07b694d696a44315f3ac8eca24dd2c5bd'
V3_RETIRE_PROGRESS = 'sha256:5ac3af0f64d33027fd62b54a5c4c34d8a2255dc94f377080225b03034655c143'
APPROVAL_ID = '976971bf-f20c-5dc3-8895-d4e7cd2d1d16'
APPROVAL_DIGEST = 'sha256:31ede5908db0a9b29a21f27602ca3dd7708bdbaafcb9bb5ae25c829999eb81d6'
APPROVAL_FILE_DIGEST = 'sha256:321091ca7bfa7727eb35fd5df30bbb6845cbfab317e3ddd5c90cd42619f18141'
APPROVED_AT = '2026-10-04T21:57:20Z'


def load(name: str) -> dict:
    value = json.loads((B / name).read_text())
    assert isinstance(value, dict)
    return value


def raw(path: Path) -> str:
    return 'sha256:' + hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    r = load(N + '.resource.json')
    prep = load(N + '-preparation.evidence.json')
    p = load(N + '.plan.json')
    g = load(N + '.progress.json')
    a = load(N + '.approval.json')

    validate_plan(p, S)
    validate_progress(p, g, S)
    validate_approval(p, a, S, WINDOW_START)
    assert p['plan_id'] == PLAN_ID and p['plan_version'] == 4
    assert p['plan_digest'] == PLAN_DIGEST == plan_digest(p)
    assert p['definition_status'] == 'READY_FOR_APPROVAL'
    assert p['authority_effect'] == 'NONE_UNTIL_SEPARATELY_APPROVED'
    assert p['environment'] == 'DEVELOPMENT'
    assert p['target']['project_reference'] == PROJECT and p['target']['responsibility'] == 'AUTH'
    assert p['created_at'] == CREATED_AT
    assert p['authorization_window'] == {'binding_state':'BOUND','starts_at':WINDOW_START,'expires_at':WINDOW_END}
    assert raw(B / (N + '.approval.json')) == APPROVAL_FILE_DIGEST
    assert a['approval_id'] == APPROVAL_ID
    assert a['plan_id'] == PLAN_ID and a['plan_version'] == 4 and a['plan_digest'] == PLAN_DIGEST
    assert a['owner_identity'] == 'github:AnonymousKoo' and a['decision'] == 'APPROVE'
    assert a['environment'] == 'DEVELOPMENT' and a['authority_scope'] == 'EXACT_PLAN_ONLY'
    assert a['effective_at'] == WINDOW_START and a['expires_at'] == WINDOW_END
    assert a['approved_at'] == APPROVED_AT and a['status'] == 'ACTIVE'
    assert a['approval_digest'] == APPROVAL_DIGEST == approval_digest(a)
    assert APPROVED_AT < WINDOW_START
    assert not (B / (N + '.execution-progress.json')).exists()
    assert not list(B.glob(N + '-step*-*.evidence.json'))

    assert r['contract_digest'] == RESOURCE_DIGEST == canonical_digest({k:v for k,v in r.items() if k != 'contract_digest'})
    assert r['resource_version'] == 'provider-adapter-positive-auth.v4' and r['boundary'] == N
    assert r['project_reference'] == PROJECT and DATA_PROJECT not in json.dumps(r)
    assert r['fresh_provider_key_reference'] == KEY and len(KEY) <= 64 and re.fullmatch(r'[a-z0-9_]+', KEY)
    assert r['github_secret_binding_name'] == GH
    assert r['step5_executor_digest'] == raw(ROOT / 'scripts/development_provider_adapter_positive_auth_v4.py')
    assert r['step5_workflow_digest'] == raw(ROOT / '.github/workflows/development-provider-adapter-positive-auth-v4-step5.yml')
    assert r['token_lifecycle_source_digest'] == raw(ROOT / 'src/avuhz_engineering/development_auth_token_lifecycle.py')
    assert r['identity_policy_source_digest'] == raw(ROOT / 'src/avuhz_service/development_supabase_identity.py')
    assert r['jwt_verifier_source_digest'] == raw(ROOT / 'src/avuhz_service/development_supabase_jwt.py')
    assert r['execution_rules']['owner_approval_deadline'] == WINDOW_START
    assert r['execution_rules']['window_expiry'] == WINDOW_END
    assert r['retry_authorized'] is False and r['implementation_handoff_execution_authorized'] is False

    pre = r['preflight_contract']
    assert pre['query_sha256'] == QUERY_DIGEST == 'sha256:' + hashlib.sha256(pre['query'].encode()).hexdigest()
    assert pre['query_count'] == 1 and pre['aggregate_only'] is True
    assert pre['raw_rows_authorized'] is False and pre['additional_sql_authorized'] is False and pre['retry_authorized'] is False
    assert pre['expected_result'] == {
        'auth_user_count':2,'target_identity_count':1,'target_password_null_count':1,
        'target_tenant_exact_count':1,'session_count':0,'refresh_token_count':0,
    }

    diagnostics = r['failure_diagnostics']
    assert diagnostics['safe_error_code_retained'] is True
    assert diagnostics['exception_text_retained'] is False
    assert diagnostics['provider_payload_retained'] is False
    assert diagnostics['credential_or_token_material_retained'] is False
    for code in ('ACCESS_JWT_VALIDATION_FAILED','LIVE_AUTH_PROBE_FAILED','POSITIVE_AUTH_FAILED_LOGOUT_UNVERIFIED'):
        assert code in diagnostics['allowed_safe_codes']

    assert prep['evidence_digest'] == PREP_DIGEST == canonical_digest({k:v for k,v in prep.items() if k != 'evidence_digest'})
    assert prep['evidence_type'] == 'auth.provider-adapter-positive-auth-v4.preparation.observed'
    assert prep['resource_contract_digest'] == RESOURCE_DIGEST and prep['observation_only'] is True
    assert prep['prerequisites'] == {
        'passwordless':PASSWORDLESS,'tenant_binding':TENANT,'allowlist':ALLOWLIST,
        'render_v11_runtime':RUNTIME,'render_v11_progress':RUNTIME_PROGRESS,
        'failed_continuation_evidence':FAILURE,'failed_continuation_progress':STOPPED,
        'corrective_cleanup_zero_state':CLEAN_ZERO,'corrective_cleanup_key_absence':CLEAN_KEY_ABSENT,
        'corrective_cleanup_github_absence':CLEAN_GH_ABSENT,'corrective_cleanup_progress':CLEAN_PROGRESS,
        'v3_prewindow_incident':V3_INCIDENT_RAW,
        'v3_prewindow_retirement_github_absence':V3_RETIRE_GH_ABSENT_RAW,
        'v3_prewindow_retirement_progress':V3_RETIRE_PROGRESS,
    }
    assert all(value is False for value in prep['security_state'].values())

    v3_incident = 'development-implementation-handoff-provider-adapter-positive-auth-v3-prewindow-key-retirement-v1-incident.evidence.json'
    v3_step3 = 'development-implementation-handoff-provider-adapter-positive-auth-v3-prewindow-key-retirement-v1-step3-success.evidence.json'
    v3_retire = load('development-implementation-handoff-provider-adapter-positive-auth-v3-prewindow-key-retirement-v1.execution-progress.json')
    assert raw(B / v3_incident) == V3_INCIDENT_RAW
    assert raw(B / v3_step3) == V3_RETIRE_GH_ABSENT_RAW
    assert v3_retire['overall_state'] == 'COMPLETED'
    assert v3_retire['progress_digest'] == V3_RETIRE_PROGRESS == progress_digest(v3_retire)
    assert all((s['authorization_state'],s['execution_state'],s['verification_state'],s['authorization_consumed']) == ('CONSUMED','SUCCEEDED','PASS',True) for s in v3_retire['step_states'])

    assert len(p['steps']) == 10
    assert p['ordered_step_ids'] == [s['step_id'] for s in p['steps']]
    assert [s['ordinal'] for s in p['steps']] == list(range(1,11))
    assert all('positive-auth-v4' in s['step_id'] for s in p['steps'])
    assert all(s['resource']['exact_version'] == 'provider-adapter-positive-auth.v4' for s in p['steps'])
    assert all(s['resource']['exact_digest'] == RESOURCE_DIGEST for s in p['steps'])
    assert [s['execution_class'] for s in p['steps']] == [
        'PROVIDER_MUTATION','PROVIDER_MUTATION','PROVIDER_READ','PROVIDER_READ','PROVIDER_MUTATION',
        'PROVIDER_READ','PROVIDER_MUTATION','PROVIDER_MUTATION','PROVIDER_READ','PROVIDER_READ']
    assert 'bound in the v4 resource' in p['steps'][3]['expected_postcondition']
    assert 'fresh v4 GitHub environment credential' in p['steps'][4]['expected_postcondition']
    assert 'ImplementationHandoff execution' in p['steps'][4]['expected_postcondition']
    for s in (p['steps'][0],p['steps'][6],p['steps'][8]): assert KEY in s['resource']['resource_reference']
    for s in (p['steps'][1],p['steps'][2],p['steps'][7],p['steps'][9]): assert GH in s['resource']['resource_reference']

    first = {(x['evidence_type'],x['exact_digest']) for x in p['steps'][0]['required_evidence']}
    for item in (
        ('auth.provider-adapter-positive-auth-v4.preparation.observed',PREP_DIGEST),
        ('auth.provider-adapter-passwordless-state.verified',PASSWORDLESS),
        ('auth.provider-adapter-tenant-metadata.verified',TENANT),
        ('server.capability-policy.verified',ALLOWLIST),
        ('runtime.render.post-deploy-runtime.verified',RUNTIME),
        ('auth.provider-adapter-positive-auth.live-verified-logout-accepted',FAILURE),
        ('auth.provider-adapter-positive-auth.cleanup.verified',CLEAN_ZERO),
        ('auth.provider-adapter-positive-auth.admin-credential.absence-verified',CLEAN_KEY_ABSENT),
        ('auth.provider-adapter-positive-auth.github-binding.absence-verified',CLEAN_GH_ABSENT),
        ('auth.provider-adapter-positive-auth-v3.prewindow-key-creation.observed',V3_INCIDENT_RAW),
        ('auth.provider-adapter-positive-auth.github-binding.absence-verified',V3_RETIRE_GH_ABSENT_RAW),
        ('authorization-plan.execution-progress',V3_RETIRE_PROGRESS),
    ): assert item in first
    fourth = {(x['evidence_type'],x['exact_digest']) for x in p['steps'][3]['required_evidence'] if x['binding_state'] == 'BOUND'}
    for item in (
        ('auth.provider-adapter-positive-auth-v3.prewindow-key-creation.observed',V3_INCIDENT_RAW),
        ('auth.provider-adapter-positive-auth.github-binding.absence-verified',V3_RETIRE_GH_ABSENT_RAW),
        ('authorization-plan.execution-progress',V3_RETIRE_PROGRESS),
    ): assert item in fourth

    assert g == initial_progress(p,S,PROGRESS_ID,CREATED_AT)
    assert g['progress_digest'] == PROGRESS_DIGEST == progress_digest(g)
    assert g['overall_state'] == 'NOT_STARTED'
    assert all((s['authorization_state'],s['execution_state'],s['verification_state'],s['authorization_consumed']) == ('PENDING','NOT_STARTED','NOT_STARTED',False) and not s['evidence'] and not s['binding_assertions'] for s in g['step_states'])

    rendered='\n'.join((B/(N+suffix)).read_text() for suffix in ('.resource.json','-preparation.evidence.json','.plan.json','.progress.json','.approval.json'))
    for forbidden in ('Bearer eyJ','"access_token":','"refresh_token":','service_role_key'): assert forbidden not in rendered
    assert re.search(r'sb_secret_[A-Za-z0-9._-]{8,}',rendered) is None
    assert re.search(r'postgres(?:ql)?://[^\s/:]+:[^\s/@]+@',rendered,re.I) is None

    print('DEVELOPMENT provider-adapter positive-auth v4: PASS (APPROVED; pristine; effective 7-11 PM ET; v3 retirement complete and bound; fresh v4 credential lifecycle; no provider execution)')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
