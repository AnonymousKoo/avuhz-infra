#!/usr/bin/env python3
"""Offline timing-only replacement guard; no provider or approval writer."""
from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime

import validate_development_provider_adapter_positive_auth_v2_step4_correction_v1 as prior
from avuhz_engineering.authorization_plan import (
    AuthorizationPlanError, approval_digest, authorize_step, initial_progress,
    plan_digest, record_step_outcome, validate_approval, validate_plan, validate_progress,
)
from avuhz_runtime.implementation_handoff import canonical_digest

B, S = prior.B, prior.S
N = prior.N[:-1] + '2'
PLAN_ID = 'd9e3cdb3-f889-5264-92b5-0d83db9f6b38'
PLAN_DIGEST = 'sha256:d82b740665733e825d28c980c5753e6eb38970690167fc785298cc6d0e09fc2b'
PROGRESS_ID = 'faf51c2d-4af0-54d2-8f43-e1d0d5f2936c'
PROGRESS_DIGEST = 'sha256:2328b9f70e5525a120e82c25a0f1a8ddd35e1aa8c3f43456329c9c8da8189325'
PREP_DIGEST = 'sha256:e81a6f58dfdbddd83ef73f51f62a7f27c798d96f237a71f6c093699f87d8dc93'
APPROVAL_ID = '2253c1f9-5408-56be-86c7-53a6a1d07620'
APPROVAL_DIGEST = 'sha256:6c19f7b444f1824ad6e53be2987f22efc3aabc3e44c272816ed49ade882f15ca'
APPROVED_AT = '2026-10-04T12:27:56Z'
RECORDED_AT = '2026-10-04T13:07:36Z'
AUTHORIZATION_OBSERVATION_DIGEST = 'sha256:5978bd396f8855dce3b3ee2d79a076098498ca57ce039da16c88c9958f1d8102'
RESULT_DIGEST = 'sha256:7ab8f21ff7442882eca413794bfc85c1145bc9d1856648fd3482d9b554f8edbb'
SUCCESS_EVIDENCE_DIGEST = 'sha256:29b5a66afbae1a36ef4893917d8c7ccbe43537c04523111380884e6c26892fa9'
COMPLETED_PROGRESS_DIGEST = 'sha256:d12057f621c8ee3b7d0d998a0b8d1865467e84dd796511558ee510d4d09636e6'
WINDOW = dict(binding_state='BOUND', starts_at='2026-10-04T13:00:00Z', expires_at='2026-10-04T17:00:00Z')


def denied(call, code):
    try:
        call()
    except AuthorizationPlanError as error:
        assert str(error) == code, (str(error), code)
        return
    raise AssertionError('unsafe authorization accepted')


def expected_replacement(old, prep, plan):
    """Allow only identity/timing/preparation and extra immutable lineage bindings."""
    expected = json.loads(json.dumps(old).replace('step4-correction-v1', 'step4-correction-v2'))
    expected.update(plan_id=PLAN_ID, plan_version=2, created_at=prep['observed_at'],
                    authorization_window=WINDOW, plan_digest=PLAN_DIGEST)
    step = expected['steps'][0]
    step['resource'] = copy.deepcopy(old['steps'][0]['resource'])
    step['required_evidence'][0]['exact_digest'] = PREP_DIGEST
    step['binding_declarations'][0]['preapproval_value'] = {
        'value': PREP_DIGEST, 'exact_digest': canonical_digest(PREP_DIGEST),
    }
    for key, value in prep['lineage'].items():
        if key.startswith('correction_v1') and key.endswith('digest'):
            step['binding_declarations'].append({
                'binding_id': 'binding.' + N + '.' + key.replace('_', '-'),
                'phase': 'PREAPPROVAL_BOUND', 'value_class': 'CONTENT_DIGEST',
                'source_step_id': None, 'evidence_type': None,
                'digest_policy': 'REQUIRED', 'persistence_policy': 'DIGEST_ONLY',
                'preapproval_value': {'value': value, 'exact_digest': canonical_digest(value)},
            })
    assert plan == expected, 'timing replacement changed non-timing semantics'


def main():
    prior.main()  # Exact SQL/counts, all stop conditions, pristine v1 and pending original Step 4.
    old, old_approval = (prior.load(prior.N + suffix) for suffix in ('.plan.json', '.approval.json'))
    plan, progress, prep, approval, success, execution = (prior.load(N + suffix) for suffix in
        ('.plan.json', '.progress.json', '-preparation.evidence.json', '.approval.json', '-success.evidence.json', '.execution-progress.json'))
    validate_plan(plan, S)
    validate_progress(plan, progress, S)
    validate_approval(plan, approval, S, WINDOW['starts_at'])
    assert plan['plan_id'] == PLAN_ID and plan['plan_digest'] == PLAN_DIGEST == plan_digest(plan)
    assert progress == initial_progress(plan, S, PROGRESS_ID, plan['created_at'])
    assert progress['progress_digest'] == PROGRESS_DIGEST
    assert prep['evidence_digest'] == PREP_DIGEST == canonical_digest({k: v for k, v in prep.items() if k != 'evidence_digest'})
    assert prep['boundary'] == N
    assert prep['lineage'] == dict(prior.LINEAGE,
        correction_v1_plan_id=prior.PLAN_ID, correction_v1_plan_digest=prior.PLAN_DIGEST,
        correction_v1_approval_id=prior.APPROVAL_ID, correction_v1_approval_digest=prior.APPROVAL_DIGEST,
        correction_v1_pristine_progress_digest=prior.PROGRESS_DIGEST,
        correction_v1_resource_digest=prior.RESOURCE_DIGEST)
    old_prep = prior.load(prior.N + '-preparation.evidence.json')
    for key in ('evidence_type', 'environment', 'responsibility', 'provider_reference',
                'project_reference', 'action_class', 'provider_authority', 'external_provider_contact',
                'selected_diagnostic', 'result_use', 'security_state'):
        assert prep[key] == old_prep[key]
    replacement = prep['timing_replacement']
    assert replacement['prior_window'] == old['authorization_window']
    assert replacement['new_window'] == WINDOW
    assert replacement['prior_overall_state'] == 'NOT_STARTED'
    assert replacement['prior_approval_expired_at_observation'] is True
    assert replacement['prior_execution_progress_exists'] is False
    assert replacement['prior_step_result_evidence_exists'] is False
    assert replacement['resource_path'] == str((B / (prior.N + '.resource.json')).relative_to(prior.ROOT))
    assert datetime.fromisoformat(old_approval['expires_at']) < datetime.fromisoformat(prep['observed_at']) < datetime.fromisoformat(WINDOW['starts_at'])
    expected_replacement(old, prep, plan)
    # This complete comparison denies SQL/credential/scope/stop-condition drift,
    # while the unchanged v1 resource and validator enforce the exact six counts.
    for mutate in (
        lambda p: p['steps'][0]['credential_policy']['allowed_classes'].append('NONE'),
        lambda p: p['steps'][0]['stop_conditions'].clear(),
        lambda p: p['prohibited_actions'].remove('positive-auth.step5-or-later.execute'),
        lambda p: p['target'].update(project_reference='gnuqaefotwgkwurjpyik'),
        lambda p: p['steps'][0]['resource'].update(exact_version='positive-auth-v2-step4-correction.v2'),
    ):
        changed = copy.deepcopy(plan)
        mutate(changed)
        prior.expect_rejected(lambda candidate: expected_replacement(old, prep, candidate), changed)
    paths = {str(p.relative_to(prior.ROOT)): p for p in B.glob(prior.PRIOR + '*')
             if not p.name.startswith(N)}
    assert set(paths) == set(prep['preserved_artifact_sha256'])
    for name, path in paths.items():
        assert 'sha256:' + hashlib.sha256(path.read_bytes()).hexdigest() == prep['preserved_artifact_sha256'][name], name
    assert {p.name for p in B.glob(N + '*')} == {
        N + '.plan.json', N + '.progress.json', N + '-preparation.evidence.json',
        N + '.approval.json', N + '-success.evidence.json', N + '.execution-progress.json',
    }  # Completed one-read boundary; no replacement resource artifact.
    denied(lambda: validate_approval(old, old_approval, S, prep['observed_at']), 'PLAN_AUTHORIZATION_EXPIRED')
    assert approval == {
        'approval_id': APPROVAL_ID,
        'plan_id': PLAN_ID,
        'plan_version': 2,
        'plan_digest': PLAN_DIGEST,
        'owner_identity': 'github:AnonymousKoo',
        'decision': 'APPROVE',
        'environment': 'DEVELOPMENT',
        'effective_at': WINDOW['starts_at'],
        'expires_at': WINDOW['expires_at'],
        'approved_at': APPROVED_AT,
        'status': 'ACTIVE',
        'authority_scope': 'EXACT_PLAN_ONLY',
        'approval_digest': APPROVAL_DIGEST,
    }
    assert approval_digest(approval) == APPROVAL_DIGEST
    assert APPROVED_AT < WINDOW['starts_at']

    authorization_observation = {
        'interaction_surface': 'supabase.dashboard.sql-editor',
        'project_reference': 'pwlhruwutoitnieactol',
        'responsibility': 'AUTH',
        'approval_exact': True,
        'authorization_window_execution_owner_confirmed': True,
        'credential_class': 'OWNER_INTERACTIVE_SESSION',
        'credential_material_observed': False,
    }
    sanitized_result = {
        'classification': 'EXPECTED_PRECHECK_COUNTS_MATCHED',
        'auth_user_count': 2,
        'target_identity_count': 1,
        'target_password_null_count': 1,
        'target_tenant_exact_count': 1,
        'session_count': 0,
        'refresh_token_count': 0,
    }
    assert canonical_digest(authorization_observation) == AUTHORIZATION_OBSERVATION_DIGEST
    assert canonical_digest(sanitized_result) == RESULT_DIGEST
    success_path = B / (N + '-success.evidence.json')
    assert 'sha256:' + hashlib.sha256(success_path.read_bytes()).hexdigest() == SUCCESS_EVIDENCE_DIGEST
    assert success['evidence_type'] == 'auth.provider-adapter-positive-auth-v2.step4-correction.counts-verified'
    assert success['environment'] == 'DEVELOPMENT'
    assert success['responsibility'] == 'AUTH'
    assert success['project_reference'] == 'pwlhruwutoitnieactol'
    assert success['plan_id'] == PLAN_ID and success['plan_digest'] == PLAN_DIGEST
    assert success['approval_id'] == APPROVAL_ID and success['approval_digest'] == APPROVAL_DIGEST
    assert success['step_id'] == plan['steps'][0]['step_id'] and success['attempt'] == 1
    assert success['outcome'] == 'SUCCEEDED_VERIFIED'
    assert success['classification'] == 'EXPECTED_PRECHECK_COUNTS_MATCHED'
    assert success['authorization_observation'] == authorization_observation
    assert success['authorization_observation_digest'] == AUTHORIZATION_OBSERVATION_DIGEST
    assert success['sanitized_result'] == sanitized_result
    assert success['result_digest'] == RESULT_DIGEST
    assert success['record_basis'] == 'OWNER_CONFIRMED_SANITIZED_EXECUTION_OUTCOME'
    assert success['recorded_at'] == RECORDED_AT
    assert success['execution_observation'] == {
        'execution_class': 'PROVIDER_READ',
        'execution_timestamp_retained': False,
        'recorded_at_is_execution_timestamp': False,
        'approved_aggregate_select_attempts': 1,
        'additional_sql_executed': False,
        'provider_mutation_attempted': False,
        'credential_or_binding_read_attempted': False,
        'positive_auth_v2_progress_advanced': False,
        'step5_or_later_attempted': False,
    }
    assert success['verification_observation'] == {
        'one_row_only': True,
        'exact_six_fields_only': True,
        'all_counts_nonnegative_integers': True,
        'all_expected_counts_matched': True,
        'raw_rows_returned': False,
        'sensitive_values_returned': False,
    }
    assert all(value is False for value in success['security_state'].values())
    assert success['result_use'] == prior.load(prior.N + '.resource.json')['result_use']
    success_text = success_path.read_text()
    assert 'avuhz-implementation-handoff-provider-adapter-development@example.invalid' not in success_text
    assert '1ad3998c-92ab-4a36-9d1c-ed97f2fa98f0' not in success_text

    step = plan['steps'][0]
    preflight_assertion = {
        'binding_id': 'binding.development.implementation-handoff.provider-adapter-positive-auth-v2-step4-correction-v2.dashboard-session',
        'phase': 'RESOLVED_BY_STEP_PREFLIGHT',
        'value_class': 'CONFIGURATION_REFERENCE',
        'source_step_id': None,
        'evidence_type': 'provider.owner-interactive-dashboard-session.observed',
        'evidence_digest': AUTHORIZATION_OBSERVATION_DIGEST,
        'digest_policy': 'REQUIRED',
        'persistence_policy': 'DIGEST_ONLY',
        'sanitized_value': None,
        'value_digest': AUTHORIZATION_OBSERVATION_DIGEST,
        'recorded_at': RECORDED_AT,
    }
    request = {
        'plan_id': PLAN_ID,
        'plan_version': 2,
        'plan_digest': PLAN_DIGEST,
        'environment': 'DEVELOPMENT',
        'provider_reference': 'supabase',
        'project_reference': 'pwlhruwutoitnieactol',
        'responsibility': 'AUTH',
        'issuer_reference': 'https://pwlhruwutoitnieactol.supabase.co/auth/v1',
        'audience_reference': 'audience.avuhz.command-service.development',
        'step_id': step['step_id'],
        'resource_reference': step['resource']['resource_reference'],
        'resource_version': step['resource']['exact_version'],
        'resource_digest': step['resource']['exact_digest'],
        'operation': step['operation'],
        'execution_class': 'PROVIDER_READ',
        'credential_class': 'OWNER_INTERACTIVE_SESSION',
        'required_evidence': [
            {'evidence_type': item['evidence_type'], 'evidence_digest': item['exact_digest']}
            for item in step['required_evidence']
        ],
        'prior_evidence_digests': [],
        'unexpected_remote_state': False,
        'extra_privileges': False,
        'unauthorized_migration_surface': False,
        'scope_expansion': False,
    }
    authorized = authorize_step(
        plan, approval, progress, request, S, RECORDED_AT,
        trusted_preflight_assertions=[preflight_assertion],
    )
    outcome_evidence = [{
        'evidence_type': success['evidence_type'],
        'evidence_reference': N + '-success.evidence.json',
        'evidence_digest': SUCCESS_EVIDENCE_DIGEST,
        'recorded_at': RECORDED_AT,
    }]
    produced_binding = {
        'binding_id': 'binding.development.implementation-handoff.provider-adapter-positive-auth-v2-step4-correction-v2.result',
        'phase': 'PRODUCED_BY_CURRENT_STEP',
        'value_class': 'CONTENT_DIGEST',
        'source_step_id': None,
        'evidence_type': success['evidence_type'],
        'evidence_digest': SUCCESS_EVIDENCE_DIGEST,
        'digest_policy': 'REQUIRED',
        'persistence_policy': 'DIGEST_ONLY',
        'sanitized_value': None,
        'value_digest': RESULT_DIGEST,
        'recorded_at': RECORDED_AT,
    }
    expected_execution = record_step_outcome(
        plan, approval, authorized, step['step_id'], 'SUCCEEDED', 'PASS',
        outcome_evidence, step['expected_postcondition'], None, S, RECORDED_AT,
        binding_assertions=[produced_binding],
    )
    validate_progress(plan, execution, S)
    assert execution == expected_execution
    assert execution['progress_digest'] == COMPLETED_PROGRESS_DIGEST
    assert execution['overall_state'] == 'COMPLETED'
    state = execution['step_states'][0]
    assert (state['authorization_state'], state['execution_state'], state['verification_state'], state['authorization_consumed']) == (
        'CONSUMED', 'SUCCEEDED', 'PASS', True
    )
    assert state['safe_error_code'] is None
    assert state['evidence'] == outcome_evidence
    assert state['binding_assertions'] == [preflight_assertion, produced_binding]

    denied(lambda: authorize_step(plan, {}, progress, {}, S, WINDOW['starts_at']), 'SCHEMA_INVALID')
    denied(lambda: authorize_step(plan, old_approval, progress, {}, S, WINDOW['starts_at']), 'APPROVAL_BINDING_MISMATCH')
    for when in ('2026-10-04T12:59:59Z', WINDOW['expires_at'], '2026-10-04T17:00:01Z'):
        denied(lambda: authorize_step(plan, approval, progress, {}, S, when), 'PLAN_AUTHORIZATION_EXPIRED')
    late = dict(approval, approved_at='2026-10-04T13:00:01Z')
    late['approval_digest'] = approval_digest(late)
    denied(lambda: validate_approval(plan, late, S, '2026-10-04T13:00:02Z'), 'PLAN_AUTHORIZATION_EXPIRED')
    print('DEVELOPMENT positive-auth v2 Step 4 correction v2: PASS (COMPLETED/CONSUMED/SUCCEEDED/PASS; exact six counts matched; one aggregate read; no retry/mutation; original v2 Step 4 still pending)')


if __name__ == '__main__':
    main()
