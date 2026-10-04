#!/usr/bin/env python3
"""Offline preparation guard; never connects to a provider or records execution."""
from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'src'))
from avuhz_engineering.authorization_plan import (
    approval_digest, initial_progress, plan_digest, progress_digest, validate_approval, validate_plan, validate_progress,
)
from avuhz_runtime.implementation_handoff import canonical_digest

B = ROOT / 'contracts/plans/v1'
S = ROOT / 'contracts/schemas/v1'
N = 'development-implementation-handoff-provider-adapter-positive-auth-v2-step4-correction-v1'
PRIOR = 'development-implementation-handoff-provider-adapter-positive-auth-v2'
PLAN_ID = '6b458b63-542c-5eb5-8b24-1e3b781f5957'
PLAN_DIGEST = 'sha256:13937ab14140c977dca4829342c6237988ef11106306012082dce01321ff2430'
PROGRESS_ID = '221ec3e1-7852-5c0e-b141-f65bd21216ed'
PROGRESS_DIGEST = 'sha256:40f5f9f92cf023acf73ac21ebd200d99115afa953894929953d4091693287860'
RESOURCE_DIGEST = 'sha256:290d903ca9b96e6325f05698c86f050a60f5f052344703be018cea40231a0fd0'
PREP_DIGEST = 'sha256:14a15edda3d731c46bd75ff949a7889191c4018fb5e51be31bd5fc4710d905a5'
APPROVAL_ID = '472c2bfb-8430-57f0-aeca-a1b6db954c74'
APPROVAL_DIGEST = 'sha256:7ec0d0eefb249767a422d6e3df302ba3a877a74667e8cbab33f73f65e11a36d7'
APPROVED_AT = '2026-10-04T06:32:26Z'
PROJECT = 'pwlhruwutoitnieactol'
EXPECTED = dict(auth_user_count=2, target_identity_count=1, target_password_null_count=1,
                target_tenant_exact_count=1, session_count=0, refresh_token_count=0)
LINEAGE = {
    'v2_plan_id': '58c9c75c-6488-54e2-924e-d87c3d99432b',
    'v2_plan_digest': 'sha256:03cb244d3ee92cde2e279c27f74a6d6ac36d22ed83d988e5c06bcd5ebd320edd',
    'v2_approval_id': 'af3e10e7-2319-5462-9b6c-a17063a29206',
    'v2_approval_digest': 'sha256:faf96f4b6bac4e62fa96f7739c5e47959eed9f29a6ee0f5a5d4b629210ea5f10',
    'v2_execution_progress_digest_after_steps_1_3': 'sha256:656af77ba698ebaf159b0ce812f627e4a54e26472fd0ba69d0bdf97f52ed4060',
    'v2_step3_verified_github_binding_evidence_digest': 'sha256:1949474314c7486e178e465e0e1436b6127c2da20260997daaf70bfb42a1d3d5',
}
EMAIL = 'avuhz-implementation-handoff-provider-adapter-development@example.invalid'
TENANT = '1ad3998c-92ab-4a36-9d1c-ed97f2fa98f0'
SQL = (
    'select\n'
    '  (select count(*) from auth.users) as auth_user_count,\n'
    f"  (select count(*) from auth.users where email = '{EMAIL}') as target_identity_count,\n"
    f"  (select count(*) from auth.users where email = '{EMAIL}' and encrypted_password is null) as target_password_null_count,\n"
    f"  (select count(*) from auth.users where email = '{EMAIL}' and raw_app_meta_data ->> 'avuhz_tenant_id' = '{TENANT}') as target_tenant_exact_count,\n"
    '  (select count(*) from auth.sessions) as session_count,\n'
    '  (select count(*) from auth.refresh_tokens) as refresh_token_count;'
)


def load(name):
    return json.loads((B / name).read_text())


def check_result_shape(rows):
    """Exercise the contract with synthetic counts only; not an execution API."""
    assert type(rows) is list and len(rows) == 1
    row = rows[0]
    assert type(row) is dict and set(row) == set(EXPECTED)
    assert all(type(value) is int and value >= 0 for value in row.values())
    assert row == EXPECTED


def check_query_contract(resource):
    assert resource['diagnostic_sql'] == SQL
    assert resource['query_count'] == 1 and type(resource['query_count']) is int
    assert resource['aggregate_only'] is True
    assert resource['result_fields'] == list(EXPECTED)
    assert resource['expected_result'] == EXPECTED
    check_result_shape([resource['expected_result']])


def expect_rejected(check, value):
    try:
        check(value)
    except AssertionError:
        return
    raise AssertionError('unsafe synthetic case accepted')


def main():
    r, prep, p, g, a = (load(N + suffix) for suffix in
                        ('.resource.json', '-preparation.evidence.json', '.plan.json', '.progress.json', '.approval.json'))
    validate_plan(p, S)
    validate_progress(p, g, S)
    validate_approval(p, a, S, '2026-10-04T06:45:00Z')
    assert p['plan_id'] == PLAN_ID and p['plan_digest'] == PLAN_DIGEST == plan_digest(p)
    assert p['definition_status'] == 'READY_FOR_APPROVAL'
    assert p['authority_effect'] == 'NONE_UNTIL_SEPARATELY_APPROVED'
    assert p['authorization_window'] == dict(binding_state='BOUND', starts_at='2026-10-04T06:45:00Z', expires_at='2026-10-04T10:45:00Z')
    assert len(p['steps']) == 1 and p['ordered_step_ids'] == [p['steps'][0]['step_id']]
    assert g == initial_progress(p, S, PROGRESS_ID, p['created_at'])
    assert g['progress_digest'] == PROGRESS_DIGEST and g['overall_state'] == 'NOT_STARTED'
    assert a == {
        'approval_id': APPROVAL_ID,
        'plan_id': PLAN_ID,
        'plan_version': 1,
        'plan_digest': PLAN_DIGEST,
        'owner_identity': 'github:AnonymousKoo',
        'decision': 'APPROVE',
        'environment': 'DEVELOPMENT',
        'effective_at': '2026-10-04T06:45:00Z',
        'expires_at': '2026-10-04T10:45:00Z',
        'approved_at': APPROVED_AT,
        'status': 'ACTIVE',
        'authority_scope': 'EXACT_PLAN_ONLY',
        'approval_digest': APPROVAL_DIGEST,
    }
    assert approval_digest(a) == APPROVAL_DIGEST
    assert APPROVED_AT < a['effective_at']
    assert not (B / (N + '.execution-progress.json')).exists()
    assert not list(B.glob(N + '-step*-*.evidence.json'))
    for obj in (r, prep, p):
        assert obj['environment'] == 'DEVELOPMENT'
        target = obj.get('target', obj)
        assert target['responsibility'] == 'AUTH' and target['project_reference'] == PROJECT
    assert r['contract_digest'] == RESOURCE_DIGEST == canonical_digest({k: v for k, v in r.items() if k != 'contract_digest'})
    assert prep['evidence_digest'] == PREP_DIGEST == canonical_digest({k: v for k, v in prep.items() if k != 'evidence_digest'})
    assert r['lineage'] == prep['lineage'] == LINEAGE
    assert all(value is False for value in prep['security_state'].values())
    assert prep['action_class'] == 'REPOSITORY_LOCAL' and prep['provider_authority'] == 'NONE'
    assert prep['external_provider_contact'] == 'PROHIBITED'
    assert prep['selected_diagnostic']['resource_digest'] == RESOURCE_DIGEST
    assert r['interaction_surface'] == 'supabase.dashboard.sql-editor'
    assert all(value is False for key, value in r.items() if key.endswith('_authorized'))
    check_query_contract(r)
    st = p['steps'][0]
    assert st['execution_class'] == 'PROVIDER_READ'
    assert st['operation'] == 'provider.auth-identity.inspect-positive-auth-step4-counts-read-only'
    assert st['dependency_step_ids'] == [] and st['unresolved_bindings'] == []
    assert st['credential_policy'] == dict(permitted=True, allowed_classes=['OWNER_INTERACTIVE_SESSION'], values_stored=False)
    assert st['resource']['exact_digest'] == RESOURCE_DIGEST
    assert st['required_evidence'][0]['exact_digest'] == PREP_DIGEST
    assert st['required_evidence'][1]['exact_digest'] == LINEAGE['v2_step3_verified_github_binding_evidence_digest']
    bound = [b['preapproval_value']['value'] for b in st['binding_declarations'] if b['phase'] == 'PREAPPROVAL_BOUND']
    assert set(bound) == {PREP_DIGEST, *(v for k, v in LINEAGE.items() if 'digest' in k)}
    for action in ('provider.mutation', 'credential.read', 'credential.verify', 'credential.retire',
                   'credential.recreate', 'github-binding.read', 'github-binding.verify', 'github-binding.modify',
                   'query.retry', 'additional-sql.execute', 'positive-auth-v2.progress.advance',
                   'positive-auth-v2.step4.mark-success', 'positive-auth.step5-or-later.execute'):
        assert action in st['prohibited_actions'] and action in p['prohibited_actions']
    for stop in ('project.mismatch', 'sql.text.mismatch', 'result-fields.mismatch', 'count.malformed',
                 'count.non-integer', 'count.negative', 'count.mismatch', 'raw-row.returned',
                 'result.unavailable', 'verification.ambiguous', 'provider.effect.unexpected', 'additional-sql.requested'):
        assert stop in st['stop_conditions'] and stop in p['stop_conditions']
    prior_plan, approval, progress = (load(PRIOR + suffix) for suffix in ('.plan.json', '.approval.json', '.execution-progress.json'))
    assert prior_plan['plan_id'] == LINEAGE['v2_plan_id']
    assert prior_plan['plan_digest'] == plan_digest(prior_plan) == LINEAGE['v2_plan_digest']
    assert approval['approval_id'] == LINEAGE['v2_approval_id']
    assert approval['approval_digest'] == approval_digest(approval) == LINEAGE['v2_approval_digest']
    assert progress['progress_digest'] == progress_digest(progress) == LINEAGE['v2_execution_progress_digest_after_steps_1_3']
    step3_path = B / (PRIOR + '-step03-success.evidence.json')
    assert 'sha256:' + hashlib.sha256(step3_path.read_bytes()).hexdigest() == LINEAGE['v2_step3_verified_github_binding_evidence_digest']
    assert load(step3_path.name)['evidence_type'] == 'auth.provider-adapter-positive-auth.github-binding.verified'
    for state in progress['step_states'][3:]:
        assert (state['authorization_state'], state['execution_state'], state['verification_state'], state['authorization_consumed']) == ('PENDING', 'NOT_STARTED', 'NOT_STARTED', False)
        assert state['evidence'] == []
    for bad in (None, [], [EXPECTED, EXPECTED], [dict(EXPECTED, extra_count=0)]):
        expect_rejected(check_result_shape, bad)
    for field in EXPECTED:
        for bad in (True, False, 0.0, '1', None, -1, EXPECTED[field] + 1):
            expect_rejected(check_result_shape, [dict(EXPECTED, **{field: bad})])
        missing = dict(EXPECTED)
        del missing[field]
        expect_rejected(check_result_shape, [missing])
    for query in (SQL + '\nselect count(*) from auth.users;', SQL.replace('count(*)', '*', 1), SQL.replace(TENANT, 'different-tenant'), SQL.replace(' is null', ' is not null')):
        changed = copy.deepcopy(r)
        changed['diagnostic_sql'] = query
        expect_rejected(check_query_contract, changed)
    check_result_shape([EXPECTED])
    print('DEVELOPMENT positive-auth v2 Step 4 correction v1: PASS (APPROVED; pristine; exact six-count SELECT; v2 unchanged; synthetic denial cases pass; provider read not yet executed)')


if __name__ == '__main__':
    main()
