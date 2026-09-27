#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'src'))

from avuhz_engineering.authorization_plan import initial_progress, plan_digest, progress_digest, validate_plan, validate_progress  # noqa: E402

BASE = ROOT / 'contracts/plans/v1'
SCHEMA_ROOT = ROOT / 'contracts/schemas/v1'
BOUNDARY = 'development-auth-v32-synthetic-session-cleanup-credential-retirement-v1'
PLAN_PATH = BASE / f'{BOUNDARY}.plan.json'
PROGRESS_PATH = BASE / f'{BOUNDARY}.progress.json'
PLAN_ID = 'a5f97c50-5839-4d25-a2d2-c5b6eb11ef08'
PLAN_DIGEST = 'sha256:75e2ba1d526e50ec621a6130c3df466ba5287c5869cb55af3c6e1530b771528b'
PROGRESS_ID = '8a3a6859-a151-428d-96ac-c6966a6c6430'
PROGRESS_DIGEST = 'sha256:9e80c7a42f3f92070cd7fb4e744fb1892934108386a6f03194683eeca5739a10'
CREATED_AT = '2026-09-27T19:39:59Z'
WINDOW_START = '2026-09-27T21:00:00Z'
WINDOW_END = '2026-09-28T03:00:00Z'
PROJECT = 'pwlhruwutoitnieactol'
DATA_PROJECT = 'gnuqaefotwgkwurjpyik'
KEY_NAME = 'cleanup-v2-ephemeral'
KEY_REF = f'supabase:{PROJECT}:secret-key:{KEY_NAME}'
GH_SECRET = 'AVUHZ_DEVELOPMENT_SUPABASE_AUTH_SESSION_CLEANUP_V2_EPHEMERAL'
GH_REF = f'github:AnonymousKoo/avuhz-infra:environment:development:secret:{GH_SECRET}'
RETIREMENT = 'sha256:38ebcc897696f11284c540994c4a6144f08530ad8c4ec7e42c84a64f01559b8f'
KEY_CREATED = 'sha256:29fa0e715118b6cb70d6c08b28466b79407319bc5177947851b87b86c10dc47d'
GH_CREATED = 'sha256:de7daf8b0c913f713225d292adae404bc877b298368c9fbedc5e451f6190e574'
GH_VERIFIED = 'sha256:a431c44cac5069898b98784c82244f3b9335f124ee348666da0bb83894f3fce9'
V4_FAILURE = 'sha256:60f2bc12d01f788a32dfef1ff274172ffe3148dfd23c0b903f9a1fb52a88d50d'
V4_STOPPED = 'sha256:6a4a98913c7d7c0490fcc1c03f6b5a8b599ad29c1c2c7284ef58145128cbdb41'
RESOURCE_DIGESTS = [
    'sha256:e1fb3d4655e7f2c3ac24f505a77623ae3bb422355dc1f1e22199fc805dab1764',
    'sha256:f441b18dd732416b403c88802b68923d35b7b8d8421c6243d3bcbcfbf12bf104',
    'sha256:9df91863b2de1aada1d5fc837f0691c5f46469fd39e9103a93371bb4e2a0c1f9',
    'sha256:5b40a715da38b85f0dc5af152b8941604b4711589a29f90ed31e67e46a0a3c6f',
]


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding='utf-8'))


def raw_digest(path: Path) -> str:
    return 'sha256:' + hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    plan = load(PLAN_PATH)
    progress = load(PROGRESS_PATH)
    validate_plan(plan, SCHEMA_ROOT)
    validate_progress(plan, progress, SCHEMA_ROOT)
    assert plan['plan_id'] == PLAN_ID
    assert plan['plan_version'] == 1
    assert plan['plan_digest'] == PLAN_DIGEST == plan_digest(plan)
    assert plan['created_at'] == CREATED_AT
    assert plan['definition_status'] == 'READY_FOR_APPROVAL'
    assert plan['authority_effect'] == 'NONE_UNTIL_SEPARATELY_APPROVED'
    assert plan['environment'] == 'DEVELOPMENT'
    assert plan['target']['responsibility'] == 'AUTH'
    assert plan['target']['project_reference'] == PROJECT
    assert plan['authorization_window'] == {'binding_state': 'BOUND', 'starts_at': WINDOW_START, 'expires_at': WINDOW_END}
    assert DATA_PROJECT not in json.dumps(plan)

    steps = plan['steps']
    assert len(steps) == 4
    assert [s['ordinal'] for s in steps] == [1, 2, 3, 4]
    assert [s['execution_class'] for s in steps] == ['PROVIDER_MUTATION', 'PROVIDER_MUTATION', 'PROVIDER_READ', 'PROVIDER_READ']
    assert [s['resource']['resource_reference'] for s in steps] == [KEY_REF, GH_REF, KEY_REF, GH_REF]
    assert [s['resource']['exact_digest'] for s in steps] == RESOURCE_DIGESTS
    assert steps[0]['dependency_step_ids'] == []
    for idx in range(1, 4):
        assert steps[idx]['dependency_step_ids'] == [steps[idx - 1]['step_id']]
    for step in steps:
        assert step['credential_policy'] == {'permitted': True, 'allowed_classes': ['OWNER_INTERACTIVE_SESSION'], 'values_stored': False}
        assert 'sql.execute' in step['prohibited_actions']
        assert 'data.operation' in step['prohibited_actions']
        assert 'production.target' in step['prohibited_actions']
        assert 'staging.target' in step['prohibited_actions']
    assert 'api-key.reveal' in steps[0]['prohibited_actions']
    assert 'api-key.reveal' in steps[2]['prohibited_actions']
    assert 'secret-value.read' in steps[1]['prohibited_actions']
    assert 'secret-value.read' in steps[3]['prohibited_actions']
    assert 'provider-key.other.delete' in plan['prohibited_actions']
    assert 'github-secret.other.delete' in plan['prohibited_actions']
    assert 'retirement-resource.recreate' in plan['prohibited_actions']

    serialized = json.dumps(plan, sort_keys=True)
    for digest in (RETIREMENT, KEY_CREATED, GH_CREATED, GH_VERIFIED, V4_FAILURE, V4_STOPPED):
        assert digest in serialized
    assert KEY_NAME in serialized and GH_SECRET in serialized
    assert re.search(r'sb_secret_[A-Za-z0-9._-]{8,}', serialized) is None
    assert 'service_role' not in serialized.lower()
    assert 'api-key.reveal' in serialized
    assert 'do not reveal key material' in serialized.lower()

    assert progress == initial_progress(plan, SCHEMA_ROOT, PROGRESS_ID, CREATED_AT)
    assert progress['progress_digest'] == PROGRESS_DIGEST == progress_digest(progress)
    assert progress['overall_state'] == 'NOT_STARTED'
    assert all((s['authorization_state'], s['execution_state'], s['verification_state'], s['authorization_consumed']) == ('PENDING', 'NOT_STARTED', 'NOT_STARTED', False) for s in progress['step_states'])
    assert not (BASE / f'{BOUNDARY}.approval.json').exists()
    assert not (BASE / f'{BOUNDARY}.execution-progress.json').exists()
    assert not list(BASE.glob(f'{BOUNDARY}-step*.evidence.json'))
    assert not (ROOT / f'scripts/{BOUNDARY.replace("-", "_")}.py').exists()
    assert not (ROOT / f'.github/workflows/{BOUNDARY}.yml').exists()

    assert raw_digest(BASE / 'development-auth-v32-synthetic-session-cleanup-credential-repair-v1-step4-success.evidence.json') == RETIREMENT
    assert raw_digest(BASE / 'development-auth-v32-synthetic-session-cleanup-credential-repair-v1-step1-success.evidence.json') == KEY_CREATED
    assert raw_digest(BASE / 'development-auth-v32-synthetic-session-cleanup-credential-repair-v1-step2-success.evidence.json') == GH_CREATED
    assert raw_digest(BASE / 'development-auth-v32-synthetic-session-cleanup-credential-repair-v1-step3-success.evidence.json') == GH_VERIFIED
    assert raw_digest(BASE / 'development-auth-v32-synthetic-session-cleanup-v4-step1-failure.evidence.json') == V4_FAILURE
    v4 = load(BASE / 'development-auth-v32-synthetic-session-cleanup-v4.execution-progress.json')
    assert v4['progress_digest'] == V4_STOPPED and progress_digest(v4) == V4_STOPPED
    assert v4['overall_state'] == 'STOPPED'
    assert (v4['step_states'][0]['authorization_state'], v4['step_states'][0]['execution_state'], v4['step_states'][0]['verification_state'], v4['step_states'][0]['authorization_consumed']) == ('CONSUMED', 'FAILED', 'FAIL', True)
    assert (v4['step_states'][1]['authorization_state'], v4['step_states'][1]['execution_state'], v4['step_states'][1]['verification_state'], v4['step_states'][1]['authorization_consumed']) == ('BLOCKED', 'NOT_STARTED', 'NOT_STARTED', False)

    print('DEVELOPMENT AUTH cleanup credential retirement v1 prep: PASS (exact two resources; four one-resource steps; no current execution authority)')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
