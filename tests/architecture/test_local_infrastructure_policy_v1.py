"""Offline adversarial fixtures, independently provisioned from wire requests."""
from dataclasses import FrozenInstanceError, fields, replace
from datetime import timedelta
from pathlib import Path
import ast
import unittest
from unittest.mock import patch

from avuhz_runtime.local_infrastructure_authority import (
    LocalInfrastructureDenied, ReplayEntry, TrustedReplaySnapshot,
)
from avuhz_runtime.local_infrastructure_policy import (
    ConsumptionEntry, ConsumptionSnapshot, EvidencePins, ExplicitApproval,
    HumanGrant, LocalTestInfrastructurePolicyAdapter, PolicyRule,
    policy_decision_digest, source_observation_digest,
)
from avuhz_runtime.local_infrastructure_trust import LocalTrustAdapter
from tests.architecture import test_local_infrastructure_trust_v1 as fixtures


class PolicyTests(unittest.TestCase):
    def setUp(self):
        base = fixtures.LocalInfrastructureTrustTests()
        base.setUp()
        self.sources = base.fixture
        self.request = base.request.copy()
        self.scope = base.scope
        # Harness prepares evidence before giving the requester any handles.
        trust = LocalTrustAdapter(**self.sources)
        digest = trust.compare(self.request, principal_handle=trust.identity_handles[0],
                               comparison_handle=trust.comparison_handles[0]).operation_digest
        self.pins = EvidencePins(self.sources['manifests'][0], self.sources['observations'][0],
                                 self.sources['slots'][0], source_observation_digest(
                                     self.sources['observations'][0], self.sources['grants'][1]), digest)
        self.policy = PolicyRule('policy01', 1, self.pins, 'ALLOW')
        self.human = HumanGrant(replace(self.scope, identity_id='fictional.human01'), 'HUMAN',
                                'REVIEW_FICTIONAL_POLICY', 'ACTIVE', fixtures.START, fixtures.END)
        self.approval = ExplicitApproval(
            'approval01', 1, 'fictional.human01', self.pins, 'policy01', 1,
            policy_decision_digest(self.policy), 'APPROVE', 'fictional.executor01',
            fixtures.START, fixtures.END, 1, 0)
        self.config = dict(**self.sources, policies=(self.policy,), humans=(self.human,),
                           approvals=(self.approval,), consumption=ConsumptionSnapshot(()))

    def adapter(self, **changes):
        return LocalTestInfrastructurePolicyAdapter(**{**self.config, **changes})

    def call(self, adapter=None, review=False, **changes):
        a = self.adapter() if adapter is None else adapter
        kwargs = dict(principal_handle=a.principal_handles[0], comparison_handle=a.comparison_handles[0])
        if review:
            kwargs.update(approver_handle=a.approver_handles[0], approval_handle=a.approval_handles[0])
        kwargs.update(changes)
        return (a.review_approval if review else a.evaluate_policy)(self.request, **kwargs)

    def denied(self, code, action):
        with self.assertRaises(LocalInfrastructureDenied) as caught:
            action()
        self.assertEqual(str(caught.exception), code)

    def test_positive_policy_and_approval_are_only_diagnostics(self):
        for review, code in ((False, 'POLICY_ALLOW_DIAGNOSTIC'), (True, 'APPROVAL_MATCH_DIAGNOSTIC')):
            result = self.call(review=review)
            self.assertEqual(result.reason_code, code)
            self.assertEqual(result.authority_effect, 'NONE')
            self.assertEqual(result.operation_digest, self.pins.operation_digest)
            self.assertFalse(hasattr(result, 'execution_token'))

    def test_compare_is_recomputed_internally(self):
        original = LocalTrustAdapter.compare
        calls = []
        def compare(instance, request, **kwargs):
            calls.append(request.copy())
            return original(instance, request, **kwargs)
        with patch.object(LocalTrustAdapter, 'compare', compare):
            a = self.adapter()
            self.call(a)
            self.call(a, review=True)
        self.assertEqual(calls, [self.request, self.request])

    def test_missing_policy_no_drift_bypass(self):
        self.assertNotEqual(self.pins.manifest.desired_digest, self.pins.observation.current_digest)
        self.assertEqual(self.call(self.adapter(policies=())).reason_code, 'POLICY_MISSING')

    def test_unknown_policy_version(self):
        a = self.adapter(policies=(replace(self.policy, policy_version=2),))
        self.assertEqual(self.call(a, review=True).reason_code, 'POLICY_VERSION_UNKNOWN')

    def test_policy_deny_overrides_explicit_approval(self):
        a = self.adapter(policies=(replace(self.policy, decision='DENY'),))
        self.assertEqual(self.call(a, review=True).reason_code, 'POLICY_DENIED')

    def test_every_manifest_digest_version_and_identity_pinned(self):
        changes = dict(manifest_id='manifest02', manifest_digest=fixtures.C, manifest_version=8,
                       desired_digest=fixtures.M, desired_version=8,
                       expected_current_digest=fixtures.D, expected_current_version=8)
        for key, value in changes.items():
            with self.subTest(key=key):
                pins = replace(self.pins, manifest=replace(self.pins.manifest, **{key: value}))
                a = self.adapter(policies=(replace(self.policy, pins=pins),))
                self.assertEqual(self.call(a).reason_code, 'POLICY_PIN_MISMATCH')

    def test_every_scope_dimension_pinned(self):
        for key, value in dict(identity_id='other01', tenant_id='tenant02', owner_id='owner02',
                               environment='LOCAL').items():
            pins = replace(self.pins, manifest=replace(self.pins.manifest,
                           scope=replace(self.scope, **{key: value})))
            self.assertEqual(self.call(self.adapter(policies=(replace(self.policy, pins=pins),))).reason_code,
                             'POLICY_PIN_MISMATCH')

    def test_observation_state_identity_and_times_pinned(self):
        for key, value in dict(observation_id='other01', current_digest=fixtures.D, current_version=8,
                               observer_id='observer02', observed_at=fixtures.START,
                               expires_at=fixtures.END).items():
            pins = replace(self.pins, observation=replace(self.pins.observation, **{key: value}))
            self.assertEqual(self.call(self.adapter(policies=(replace(self.policy, pins=pins),))).reason_code,
                             'POLICY_PIN_MISMATCH')

    def test_changed_observer_same_operation_digest_denied(self):
        p, o = self.sources['grants']
        obs = replace(self.pins.observation, observer_id='observer02')
        a = self.adapter(grants=(p, replace(o, scope=replace(o.scope, identity_id='observer02'))),
                         observations=(obs,))
        result = self.call(a, review=True)
        self.assertEqual(result.operation_digest, self.pins.operation_digest)
        self.assertNotEqual(result.source_digest, self.pins.source_digest)
        self.assertEqual(result.reason_code, 'POLICY_PIN_MISMATCH')

    def test_changed_observation_time_same_operation_digest_denied(self):
        a = self.adapter(observations=(replace(self.pins.observation, observed_at=fixtures.START),))
        result = self.call(a)
        self.assertEqual(result.operation_digest, self.pins.operation_digest)
        self.assertNotEqual(result.source_digest, self.pins.source_digest)
        self.assertEqual(result.reason_code, 'POLICY_PIN_MISMATCH')

    def test_changed_observer_grant_provenance_denied(self):
        p, o = self.sources['grants']
        a = self.adapter(grants=(p, replace(o, issued_at=fixtures.START + timedelta(seconds=1))))
        self.assertEqual(self.call(a).reason_code, 'POLICY_PIN_MISMATCH')

    def test_pin_digest_and_slot_changes(self):
        variants = [replace(self.pins, source_digest=fixtures.M),
                    replace(self.pins, operation_digest=fixtures.D)]
        for key, value in dict(request_id='request02', challenge='challenge02', principal_id='other01',
                               manifest_id='manifest02', observation_id='observation02',
                               issued_at=fixtures.START + timedelta(seconds=1),
                               expires_at=fixtures.END - timedelta(seconds=1)).items():
            variants.append(replace(self.pins, slot=replace(self.pins.slot, **{key: value})))
        for pins in variants:
            self.assertIn(self.call(self.adapter(policies=(replace(self.policy, pins=pins),))).reason_code,
                          ('POLICY_PIN_MISMATCH', 'POLICY_MISSING'))

    def test_no_self_observer_or_executor_approval(self):
        for identity in ('principal01', 'observer01', 'fictional.executor01'):
            human = replace(self.human, scope=replace(self.scope, identity_id=identity))
            approval = replace(self.approval, human_id=identity)
            result = self.call(self.adapter(humans=(human,), approvals=(approval,)), review=True)
            self.assertEqual(result.reason_code, 'HUMAN_SCOPE_OR_SEPARATION_DENIED')

    def test_wrong_tenant_human(self):
        h = replace(self.human, scope=replace(self.human.scope, tenant_id='tenant02'))
        self.assertEqual(self.call(self.adapter(humans=(h,)), review=True).reason_code,
                         'HUMAN_SCOPE_OR_SEPARATION_DENIED')

    def test_wrong_role_capability_and_status(self):
        for change in ({'role': 'PRINCIPAL'}, {'capability': 'DEPLOY'}, {'status': 'CONSUMED'}):
            self.denied('INVALID_POLICY_RECORD', lambda: self.adapter(humans=(replace(self.human, **change),)))

    def test_revoked_expired_future_overlong_human_grants(self):
        for change in ({'status': 'REVOKED'}, {'expires_at': fixtures.NOW},
                       {'issued_at': fixtures.NOW + timedelta(seconds=1)},
                       {'issued_at': fixtures.NOW - timedelta(seconds=301)}):
            self.assertEqual(self.call(self.adapter(humans=(replace(self.human, **change),)),
                                       review=True).reason_code, 'HUMAN_GRANT_INACTIVE')

    def test_explicit_deny(self):
        self.assertEqual(self.call(self.adapter(approvals=(replace(self.approval, decision='DENY'),)),
                                   review=True).reason_code, 'HUMAN_DENIED')

    def test_approval_complete_bindings(self):
        variants = [replace(self.approval, policy_id='other01'),
                    replace(self.approval, policy_version=2),
                    replace(self.approval, policy_decision_digest=fixtures.M)]
        for name in ('manifest', 'observation', 'slot'):
            record = getattr(self.pins, name)
            for f in fields(record):
                value = getattr(record, f.name)
                if f.name == 'scope':
                    altered = replace(value, tenant_id='tenant02')
                elif type(value) is int:
                    altered = value + 1
                elif f.name.endswith('_digest'):
                    altered = 'sha256:' + '9' * 64
                elif f.name.endswith('_at'):
                    altered = value + timedelta(seconds=1)
                else:
                    altered = 'other01'
                pins = replace(self.pins, **{name: replace(record, **{f.name: altered})})
                variants.append(replace(self.approval, pins=pins))
        for name in ('source_digest', 'operation_digest'):
            variants.append(replace(self.approval, pins=replace(self.pins, **{name: fixtures.M})))
        for approval in variants:
            self.assertEqual(self.call(self.adapter(approvals=(approval,)), review=True).reason_code,
                             'APPROVAL_BINDING_MISMATCH')

    def test_approval_expired_future_and_overlong(self):
        for change in ({'expires_at': fixtures.NOW}, {'issued_at': fixtures.NOW + timedelta(seconds=1)},
                       {'issued_at': fixtures.NOW - timedelta(seconds=301)}):
            self.assertEqual(self.call(self.adapter(approvals=(replace(self.approval, **change),)),
                                       review=True).reason_code, 'APPROVAL_TIME_INVALID')

    def test_approval_exact_300_second_window(self):
        approval = replace(self.approval, issued_at=fixtures.NOW,
                           expires_at=fixtures.NOW + timedelta(seconds=300))
        self.assertEqual(self.call(self.adapter(approvals=(approval,)), review=True).reason_code,
                         'APPROVAL_MATCH_DIAGNOSTIC')

    def test_invalid_counters_versions_executor_decision(self):
        for change in ({'max_attempts': True}, {'max_attempts': 2}, {'max_recoveries': False},
                       {'max_recoveries': 1}, {'approval_version': True}, {'policy_version': True},
                       {'executor_id': 'other01'}, {'decision': 'ALLOW'}):
            self.denied('INVALID_POLICY_RECORD', lambda: self.adapter(approvals=(replace(self.approval, **change),)))
        self.denied('INVALID_POLICY_RECORD', lambda: self.adapter(policies=(replace(self.policy, policy_version=True),)))

    def test_consumed_revoked_and_alias_replay(self):
        for status in ('CONSUMED', 'REVOKED'):
            for change in ({}, {'approval_id': 'other01', 'approval_version': 2},
                           {'request_id': 'other01', 'challenge': 'otherchallenge01'},
                           {'approval_id': 'other01', 'request_id': 'other01',
                            'challenge': 'otherchallenge01'}):
                entry = ConsumptionEntry('approval01', 1, 'request01', 'challenge01',
                                         self.pins.operation_digest, status)
                snapshot = ConsumptionSnapshot((replace(entry, **change),))
                self.assertEqual(self.call(self.adapter(consumption=snapshot), review=True).reason_code,
                                 'APPROVAL_UNAVAILABLE')

    def test_pr761_replay_snapshot_is_still_enforced(self):
        snapshot = TrustedReplaySnapshot((ReplayEntry('request01', 'challenge01', self.pins.operation_digest),))
        self.denied('REPLAY_DETECTED', lambda: self.call(self.adapter(replay=snapshot), review=True))

    def test_repeat_empty_snapshot_is_not_consumption(self):
        a = self.adapter()
        self.assertEqual(self.call(a, review=True), self.call(a, review=True))
        self.assertEqual(self.config['consumption'].entries, ())

    def test_unknown_cross_instance_swapped_hostile_handles(self):
        a, other = self.adapter(), self.adapter()
        for key, values in dict(principal_handle=(object(), other.principal_handles[0], a.comparison_handles[0]),
                                comparison_handle=(object(), other.comparison_handles[0], a.principal_handles[0]),
                                approver_handle=(object(), other.approver_handles[0], a.approval_handles[0]),
                                approval_handle=(object(), other.approval_handles[0], a.approver_handles[0])).items():
            for value in (*values, fixtures.Hostile(), None, 'forged01'):
                self.denied('INVALID_TRUST_HANDLE', lambda: self.call(a, review=True, **{key: value}))

    def test_duplicate_conflicting_registries(self):
        for key in ('policies', 'humans', 'approvals'):
            records = self.config[key]
            self.denied('DUPLICATE_POLICY_RECORD', lambda: self.adapter(**{key: records * 2}))
        for change in ({'approval_id': 'other01'}, {'approval_id': 'other01', 'decision': 'DENY'},
                       {'approval_version': 2}):
            self.denied('DUPLICATE_POLICY_RECORD', lambda: self.adapter(
                approvals=(self.approval, replace(self.approval, **change))))
        self.denied('DUPLICATE_TRUST_RECORD', lambda: self.adapter(slots=self.sources['slots'] * 2))

    def test_mutable_records_and_hostile_primitives_rejected(self):
        for key in ('policies', 'humans', 'approvals'):
            self.denied('INVALID_POLICY_REGISTRY', lambda: self.adapter(**{key: list(self.config[key])}))
            self.denied('INVALID_POLICY_RECORD', lambda: self.adapter(**{key: ({},)}))
        self.denied('INVALID_POLICY_RECORD', lambda: self.adapter(
            approvals=(replace(self.approval, human_id=fixtures.Hostile()),)))
        self.denied('INVALID_POLICY_REGISTRY', lambda: self.adapter(consumption=ConsumptionSnapshot([])))

    def test_inconsistent_source_registries_rejected_at_construction(self):
        self.denied('SOURCE_SCOPE_MISMATCH', lambda: self.adapter(
            observations=(replace(self.pins.observation, scope=replace(self.scope, tenant_id='tenant02')),)))
        self.denied('MISSING_TRUST_RECORD', lambda: self.adapter(ownership=()))
        self.denied('MISSING_TRUST_RECORD', lambda: self.adapter(manifests=()))
        self.denied('SOURCE_SCOPE_MISMATCH', lambda: self.adapter(
            slots=(replace(self.pins.slot, principal_id='other01'),)))

    def test_altered_request_never_bypasses_policy(self):
        original = self.request.copy()
        for key, value in dict(tenant_id='tenant02', desired_digest=fixtures.C, manifest_version=9,
                               expected_current_version=9, challenge='other01', operation='DEPLOY').items():
            self.request = {**original, key: value}
            self.denied('REQUEST_BINDING_MISMATCH', lambda: self.call(review=True))
        self.request = {**original, 'tenant_id': fixtures.Hostile()}
        self.denied('INVALID_REQUEST', self.call)
        self.request = {**original, 'policy': 'allow'}
        self.denied('INVALID_REQUEST', self.call)

    def test_no_caller_context_injection(self):
        a = self.adapter()
        for key in ('clock', 'policies', 'approvals', 'adapter', 'comparison', 'callback'):
            with self.assertRaises(TypeError):
                a.review_approval(self.request, principal_handle=a.principal_handles[0],
                                  comparison_handle=a.comparison_handles[0],
                                  approver_handle=a.approver_handles[0],
                                  approval_handle=a.approval_handles[0], **{key: object()})

    def test_frozen_slotted_and_no_reinitialization(self):
        a = self.adapter()
        records = (a, self.pins, self.policy, self.human, self.approval,
                   self.config['consumption'], self.call(a))
        for record in records:
            self.assertFalse(hasattr(record, '__dict__'))
            with self.assertRaises(FrozenInstanceError):
                setattr(record, fields(record)[0].name, None)
        self.denied('POLICY_ALREADY_INITIALIZED', lambda: a.__init__(**self.config))
        for handles in (a.principal_handles, a.comparison_handles, a.approver_handles, a.approval_handles):
            self.assertIs(type(handles), tuple)

    def test_no_runtime_registration_or_side_effect_imports(self):
        import avuhz_runtime.local_infrastructure_policy as module
        tree = ast.parse(Path(module.__file__).read_text())
        imports = [n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
        imports += [alias.name for n in ast.walk(tree) if isinstance(n, ast.Import) for alias in n.names]
        self.assertEqual(set(imports), {'dataclasses', 'datetime', 'hashlib', 'json',
                         'avuhz_runtime.local_infrastructure_authority',
                         'avuhz_runtime.local_infrastructure_trust'})
        a = self.adapter()
        self.assertFalse(any(hasattr(a, name) for name in ('register', 'dispatch', 'execute', 'consume', 'recover')))

    def test_source_digest_domain_and_observer_binding(self):
        self.assertNotEqual(self.pins.source_digest, self.pins.operation_digest)
        obs, observer = self.pins.observation, self.sources['grants'][1]
        self.assertNotEqual(source_observation_digest(obs, observer), source_observation_digest(
            obs, replace(observer, status='REVOKED')))

    def test_invalid_scope_and_prestate_fail_closed(self):
        self.denied('INVALID_TRUST_RECORD', lambda: self.adapter(manifests=(replace(
            self.pins.manifest, scope=replace(self.scope, environment='PRODUCTION')),)))
        self.denied('PRECONDITION_MISMATCH', lambda: self.call(self.adapter(
            observations=(replace(self.pins.observation, current_digest=fixtures.D),))))


if __name__ == '__main__':
    unittest.main()
