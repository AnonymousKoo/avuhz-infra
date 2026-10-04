#!/usr/bin/env python3
"""Fresh, one-shot DEVELOPMENT AUTH continuation; historical evidence is immutable.

No network is used by authority preflight. Only main() after exact approval may
resolve runner secrets and invoke the shared lifecycle. Any attempted lifecycle
failure stops normal progress and requires separately authorized forward-only
cleanup AND retirement; lack of a parsed session never proves no session exists.
"""
from __future__ import annotations

import json
import os
import urllib.request
from collections.abc import Mapping
from functools import partial
from pathlib import Path

from scripts import development_provider_adapter_positive_auth_v1 as prior
from avuhz_engineering.authorization_plan import (
    AuthorizationPlanError, AuthorizationPlanStop, authorize_step,
    validate_approval, validate_plan, validate_progress,
)
from avuhz_runtime.implementation_handoff import canonical_digest

ROOT = prior.ROOT
BASE = prior.BASE
SCHEMA_ROOT = prior.SCHEMA_ROOT
BOUNDARY = 'development-implementation-handoff-provider-adapter-positive-auth-continuation-v1'
PLAN_PATH = BASE / f'{BOUNDARY}.plan.json'
APPROVAL_PATH = BASE / f'{BOUNDARY}.approval.json'
PROGRESS_PATH = BASE / f'{BOUNDARY}.progress.json'
RESOURCE_PATH = BASE / f'{BOUNDARY}.resource.json'
WORKFLOW_PATH = ROOT / '.github/workflows/development-provider-adapter-positive-auth-continuation-v1-step1.yml'
STEP_ID = 'development.implementation-handoff.provider-adapter-positive-auth-continuation-v1.step.01.authenticate-live-and-logout-global'
CONFIRMATION = 'RUN_PROVIDER_ADAPTER_POSITIVE_AUTH_CONTINUATION_V1_STEP1'
PROJECT = prior.PROJECT
ADMIN_ENV = prior.ADMIN_ENV
PUBLISHABLE_ENV = prior.PUBLISHABLE_ENV
CORRECTION = 'development-implementation-handoff-provider-adapter-positive-auth-v2-step4-correction-v2'
CORRECTION_EVIDENCE = 'sha256:29b5a66afbae1a36ef4893917d8c7ccbe43537c04523111380884e6c26892fa9'
CORRECTION_PROGRESS = 'sha256:d12057f621c8ee3b7d0d998a0b8d1865467e84dd796511558ee510d4d09636e6'
HISTORICAL_RESOURCE = 'sha256:45c912a3364d8568b03b962eaae774a3de9183d9c80efb36f1004d978feb4556'
SOURCE_PATHS = (
    'scripts/development_provider_adapter_positive_auth_v1.py',
    'src/avuhz_engineering/development_auth_token_lifecycle.py',
    'src/avuhz_engineering/authorization_plan.py',
    'src/avuhz_service/development_supabase_identity.py',
    'src/avuhz_service/development_supabase_jwt.py',
)


def _deny() -> None:
    raise AuthorizationPlanStop('AUTHORITY_INVALID')


def _validate_invocation(env: Mapping[str, str]) -> None:
    if any(env.get(key) != value for key, value in {
        'GITHUB_REF': 'refs/heads/main', 'GITHUB_RUN_ATTEMPT': '1',
        'GITHUB_RUN_NUMBER': '1', 'GITHUB_REPOSITORY': 'AnonymousKoo/avuhz-infra',
        'GITHUB_EVENT_NAME': 'workflow_dispatch', 'AVUHZ_ENVIRONMENT': 'development',
        'AVUHZ_CONFIRMATION': CONFIRMATION,
    }.items()):
        raise AuthorizationPlanStop('WORKFLOW_BINDING_MISMATCH')


def _validate_boundary(plan: dict, resource: dict, progress: dict) -> None:
    historical = prior._load(BASE / 'development-implementation-handoff-provider-adapter-positive-auth-v2.resource.json')
    if (historical.get('contract_digest') != HISTORICAL_RESOURCE
        or canonical_digest({k: v for k, v in historical.items() if k != 'contract_digest'}) != HISTORICAL_RESOURCE
        or resource.get('contract_digest') != canonical_digest({k: v for k, v in resource.items() if k != 'contract_digest'})):
        _deny()
    # Preserve every previously proven policy and authority limitation. Only the
    # two creation counts and the explicitly replaced source bindings differ.
    replaced = {'contract_digest', 'step5_executor_digest', 'step5_workflow_digest',
                'fresh_auth_admin_key_create_count_authorized', 'github_secret_binding_create_count_authorized'}
    if any(resource.get(k) != v for k, v in historical.items() if k not in replaced):
        _deny()
    if any(resource.get(k) != 0 for k in ('fresh_auth_admin_key_create_count_authorized', 'github_secret_binding_create_count_authorized')):
        _deny()
    if (resource.get('step1_executor_digest') != prior._raw_digest(Path(__file__))
        or resource.get('step1_workflow_digest') != prior._raw_digest(WORKFLOW_PATH)
        or resource.get('original_positive_auth_v2_resource_digest') != HISTORICAL_RESOURCE
        or resource.get('correction_v2_success_evidence_digest') != CORRECTION_EVIDENCE
        or resource.get('correction_v2_execution_progress_digest') != CORRECTION_PROGRESS):
        _deny()
    sources = resource.get('source_artifact_sha256', {})
    if any(sources.get(path) != prior._raw_digest(ROOT / path) for path in SOURCE_PATHS):
        _deny()
    if (plan.get('environment') != 'DEVELOPMENT'
        or plan.get('target', {}).get('project_reference') != PROJECT
        or plan.get('target', {}).get('responsibility') != 'AUTH'
        or plan.get('target', {}).get('provider_reference') != 'supabase'
        or plan.get('authorization_window', {}).get('starts_at') != '2026-10-04T16:00:00Z'
        or plan.get('authorization_window', {}).get('expires_at') != '2026-10-04T20:00:00Z'):
        _deny()
    old_plan = prior._load(BASE / 'development-implementation-handoff-provider-adapter-positive-auth-v2.plan.json')
    steps = plan.get('steps', [])
    if len(steps) != 6 or steps[0].get('step_id') != STEP_ID:
        _deny()
    for step, old in zip(steps, old_plan['steps'][4:]):
        if (step.get('operation') != old['operation']
            or step.get('execution_class') != old['execution_class']
            or step.get('credential_policy') != old['credential_policy']
            or not set(old['prohibited_actions']) <= set(step.get('prohibited_actions', []))
            or step.get('resource', {}).get('exact_digest') != resource['contract_digest']):
            _deny()
    required = steps[0].get('required_evidence', [])
    if not any(item == {
        'evidence_type': 'auth.provider-adapter-positive-auth-v2.step4-correction.counts-verified',
        'source_step_id': None, 'binding_state': 'BOUND', 'exact_digest': CORRECTION_EVIDENCE,
    } for item in required):
        _deny()
    if any(item.get('binding_state') != 'BOUND' or item.get('source_step_id') is not None for item in required):
        _deny()
    evidence_path = BASE / f'{CORRECTION}-success.evidence.json'
    evidence = prior._load(evidence_path)
    correction_progress = prior._load(BASE / f'{CORRECTION}.execution-progress.json')
    correction_plan = prior._load(BASE / f'{CORRECTION}.plan.json')
    validate_progress(correction_plan, correction_progress, SCHEMA_ROOT)
    if (prior._raw_digest(evidence_path) != CORRECTION_EVIDENCE
        or correction_progress.get('progress_digest') != CORRECTION_PROGRESS
        or correction_progress.get('overall_state') != 'COMPLETED'
        or evidence.get('outcome') != 'SUCCEEDED_VERIFIED'):
        _deny()
    states = progress.get('step_states', [])
    if len(states) != 6 or progress.get('overall_state') != 'NOT_STARTED':
        _deny()
    for state in states:
        if any(state.get(k) != v for k, v in {
            'authorization_state': 'PENDING', 'execution_state': 'NOT_STARTED',
            'verification_state': 'NOT_STARTED', 'authorization_consumed': False,
            'evidence': [], 'binding_assertions': [], 'safe_error_code': None,
            'observed_postcondition': None,
        }.items()):
            _deny()


def _load_and_authorize(moment: str) -> tuple[dict, dict]:
    plan, approval, progress, resource = (prior._load(path) for path in
        (PLAN_PATH, APPROVAL_PATH, PROGRESS_PATH, RESOURCE_PATH))
    validate_plan(plan, SCHEMA_ROOT)
    validate_progress(plan, progress, SCHEMA_ROOT)
    validate_approval(plan, approval, SCHEMA_ROOT, moment)
    if approval.get('decision') != 'APPROVE' or approval.get('authority_scope') != 'EXACT_PLAN_ONLY':
        _deny()
    _validate_boundary(plan, resource, progress)
    # The common request builder only depends on its module STEP_ID; avoid
    # mutating historical module globals by constructing this request directly.
    step = plan['steps'][0]
    evidence = [{'evidence_type': item['evidence_type'], 'evidence_digest': item['exact_digest']} for item in step['required_evidence']]
    request = {
        **{k: plan[k] for k in ('plan_id', 'plan_version', 'plan_digest', 'environment')},
        **{k: plan['target'][k] for k in ('provider_reference', 'project_reference', 'responsibility', 'issuer_reference', 'audience_reference')},
        'step_id': STEP_ID, 'resource_reference': step['resource']['resource_reference'],
        'resource_version': step['resource']['exact_version'], 'resource_digest': step['resource']['exact_digest'],
        'operation': step['operation'], 'execution_class': step['execution_class'],
        'credential_class': 'SUPABASE_AUTH_ADMIN_EPHEMERAL', 'required_evidence': evidence,
        'prior_evidence_digests': [],
        'unexpected_remote_state': False, 'extra_privileges': False,
        'unauthorized_migration_surface': False, 'scope_expansion': False,
    }
    config = {'step_id': STEP_ID, 'resource_digest': resource['contract_digest'],
              'executor_source_digest': resource['step1_executor_digest'],
              'workflow_source_digest': resource['step1_workflow_digest'],
              'admin_binding_name': ADMIN_ENV, 'publishable_binding_name': PUBLISHABLE_ENV}
    assertion = {
        'binding_id': 'binding.development.provider-adapter-positive-auth-continuation-v1.admin-executor-capability',
        'phase': 'RESOLVED_BY_STEP_PREFLIGHT', 'value_class': 'CONFIGURATION_REFERENCE',
        'source_step_id': None, 'evidence_type': 'auth.admin-executor-capability.observed',
        'evidence_digest': canonical_digest(config), 'digest_policy': 'REQUIRED',
        'persistence_policy': 'DIGEST_ONLY', 'sanitized_value': None,
        'value_digest': canonical_digest(config), 'recorded_at': moment,
    }
    authorized = authorize_step(plan, approval, progress, request, SCHEMA_ROOT, moment,
                                trusted_preflight_assertions=[assertion])
    if authorized['step_states'][0]['authorization_state'] != 'AUTHORIZED':
        _deny()
    return plan, authorized


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def execute_positive_auth(**overrides) -> dict:
    """Compose shared lifecycle without redirects or additional auth operations."""
    opener = urllib.request.build_opener(_RejectRedirects()).open
    defaults = {
        'generate': partial(prior.request_generate_recovery_credential, urlopen=opener),
        'verify': partial(prior.request_direct_recovery_verification, urlopen=opener),
        'live_probe': partial(prior._live_identity_probe, urlopen=opener),
        'logout_global': partial(prior.request_global_session_logout, urlopen=opener),
    }
    defaults.update(overrides)
    result = prior.execute_positive_auth(**defaults)
    result.pop('step6_readback_required')
    result['step2_readback_required'] = True
    result['retirement_required'] = True
    return result


def main(environment: Mapping[str, str] | None = None, *, preflight_only: bool = False) -> int:
    env = os.environ if environment is None else environment
    attempted = False
    admin_secret = publishable_key = None
    try:
        _validate_invocation(env)
        _load_and_authorize(prior._now())
        if preflight_only:
            print(json.dumps({'preflight': 'PASS', 'step_id': STEP_ID}, sort_keys=True))
            return 0
        admin_secret, publishable_key = env.get(ADMIN_ENV), env.get(PUBLISHABLE_ENV)
        if (not isinstance(admin_secret, str) or not admin_secret.startswith('sb_secret_') or len(admin_secret) < 26
            or not isinstance(publishable_key, str) or not publishable_key.startswith('sb_publishable_') or len(publishable_key) < 31):
            raise AuthorizationPlanStop('CREDENTIAL_UNAVAILABLE')
        attempted = True
        result = execute_positive_auth(admin_secret=admin_secret, publishable_key=publishable_key)
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception:
        # No exception text, provider payload, or credential-derived data escapes.
        print(json.dumps({
            'classification': 'STOP_REQUIRES_FORWARD_ONLY_CORRECTIVE_CLEANUP_AND_RETIREMENT' if attempted else 'AUTHORITY_OR_BINDING_REJECTED',
            'provider_mutation_attempted': attempted, 'cleanup_verified': False,
            'global_logout_accepted': False, 'global_logout_acceptance_proven': False,
            'temporary_session_state': 'UNKNOWN' if attempted else 'NOT_OBSERVED',
            'separately_authorized_corrective_cleanup_required': attempted,
            'credential_retirement_obligation_remains': True,
            'ordinary_later_steps_authorized': False, 'retry_authorized': False,
            'credential_material_retained': False, 'token_material_retained': False,
            'pii_retained': False,
        }, sort_keys=True))
        return 1
    finally:
        admin_secret = publishable_key = None


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--preflight-only', action='store_true')
    raise SystemExit(main(preflight_only=parser.parse_args().preflight_only))
