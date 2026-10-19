"""Adversarial offline composition tests; provisioning never reads the request."""
from dataclasses import FrozenInstanceError, fields, replace
from datetime import datetime, timedelta, timezone
import unittest
from unittest.mock import patch

from avuhz_runtime.local_infrastructure_authority import (
    LocalInfrastructureDenied, ReplayEntry, ResourceScope, TrustedBinding,
    TrustedObservation, TrustedReplaySnapshot, validate_local_resource_contract,
)
from avuhz_runtime.local_infrastructure_trust import (
    ApprovedManifest, ComparisonSlot, IdentityGrant, LocalTrustAdapter,
    ResourceOwnership, SimulatedObservation, TestClock,
)

M = 'sha256:' + '1' * 64
D = 'sha256:' + '2' * 64
C = 'sha256:' + '3' * 64
NOW = datetime(2026, 10, 19, 12, tzinfo=timezone.utc)
START = NOW - timedelta(seconds=30)
END = NOW + timedelta(seconds=120)


class Hostile:
    def __eq__(self, other):
        raise AssertionError('equality invoked')

    def __hash__(self):
        raise AssertionError('hash invoked')


class LocalInfrastructureTrustTests(unittest.TestCase):
    def setUp(self):
        scope = ResourceScope('principal01', 'tenant01', 'TEST', 'fictional.lab',
                              'COMPONENT', 'fictional.component01', 'owner01')
        self.scope = scope
        self.fixture = dict(
            grants=(IdentityGrant(scope, 'PRINCIPAL', 'ACTIVE', START, END),
                    IdentityGrant(replace(scope, identity_id='observer01'),
                                  'OBSERVER', 'ACTIVE', START, END)),
            ownership=(ResourceOwnership(scope),),
            manifests=(ApprovedManifest('manifest01', scope, M, 2, D, 3, C, 2),),
            observations=(SimulatedObservation('observation01', scope, 'observer01', C, 2,
                                               NOW - timedelta(seconds=15),
                                               NOW + timedelta(seconds=60)),),
            slots=(ComparisonSlot('principal01', 'manifest01', 'observation01',
                                  'request01', 'challenge01', START, END),),
            clock=TestClock(NOW, START, END), replay=TrustedReplaySnapshot(()),
        )
        # Independent wire fixture: no derivation from the trusted records.
        self.request = dict(
            schema_version=1, identity_id='principal01', tenant_id='tenant01',
            environment='TEST', namespace='fictional.lab', resource_class='COMPONENT',
            resource_id='fictional.component01', owner_id='owner01',
            manifest_digest='sha256:' + '1' * 64, manifest_version=2,
            desired_digest='sha256:' + '2' * 64, desired_version=3,
            expected_current_digest='sha256:' + '3' * 64, expected_current_version=2,
            request_id='request01', challenge='challenge01', observation_id='observation01',
            issued_at='2026-10-19T11:59:30Z', expires_at='2026-10-19T12:02:00Z',
            operation='COMPARE_FICTIONAL_STATE',
        )

    def adapter(self, **changes):
        return LocalTrustAdapter(**{**self.fixture, **changes})

    def call(self, adapter=None, **handles):
        adapter = self.adapter() if adapter is None else adapter
        return adapter.compare(self.request, **{
            'principal_handle': adapter.identity_handles[0],
            'comparison_handle': adapter.comparison_handles[0], **handles,
        })

    def deny(self, code, action):
        with self.assertRaises(LocalInfrastructureDenied) as caught:
            action()
        self.assertEqual(str(caught.exception), code)

    def change(self, key, **changes):
        values = self.fixture[key]
        return self.adapter(**{key: (replace(values[0], **changes), *values[1:])})

    def test_success_composes_unchanged_validator(self):
        binding = TrustedBinding(self.scope, M, 2, D, 3, C, 2, 'request01',
                                 'challenge01', 'observation01', START, END)
        observation = TrustedObservation(self.scope, 'observation01', C, 2,
                                         NOW - timedelta(seconds=15),
                                         NOW + timedelta(seconds=60))
        expected = validate_local_resource_contract(
            self.request, trusted_binding=binding, trusted_observation=observation,
            trusted_replay_snapshot=TrustedReplaySnapshot(()), now=NOW)
        with patch('avuhz_runtime.local_infrastructure_trust.validate_local_resource_contract',
                   wraps=validate_local_resource_contract) as validator:
            self.assertEqual(self.call(), expected)
            self.assertEqual(validator.call_count, 1)
            kwargs = validator.call_args.kwargs
            self.assertEqual(kwargs['trusted_binding'], binding)
            self.assertEqual(kwargs['trusted_observation'], observation)
        self.assertEqual((expected.outcome, expected.authority_effect), ('CONTRACT_MATCH', 'NONE'))

    def test_repeat_empty_snapshot_does_not_consume(self):
        adapter = self.adapter()
        self.assertEqual(self.call(adapter), self.call(adapter))

    def test_request_scope_forgery(self):
        original = self.request.copy()
        for key, value in dict(identity_id='other01', tenant_id='tenant02', owner_id='owner02',
                               environment='LOCAL', namespace='other.lab', resource_class='SERVICE',
                               resource_id='fictional.component02').items():
            with self.subTest(key=key):
                self.request = {**original, key: value}
                self.deny('REQUEST_BINDING_MISMATCH', self.call)

    def test_forged_manifest_and_prestate_fields(self):
        original = self.request.copy()
        for key, value in dict(manifest_digest=D, manifest_version=9, desired_digest=M,
                               desired_version=9, expected_current_digest=D,
                               expected_current_version=9).items():
            with self.subTest(key=key):
                self.request = {**original, key: value}
                self.deny('REQUEST_BINDING_MISMATCH', self.call)

    def test_forged_provenance_and_trusted_fields(self):
        original = self.request.copy()
        for key in ('provenance', 'approved', 'verified', 'observer_id', 'clock',
                    'trusted_binding', 'trusted_observation', 'replay'):
            self.request = {**original, key: 'forged01'}
            self.deny('INVALID_REQUEST', self.call)

    def test_no_owned_resource(self):
        self.deny('MISSING_TRUST_RECORD', lambda: self.call(self.adapter(ownership=())))

    def test_cross_ownership_membership(self):
        for key, value in (('identity_id', 'other01'), ('tenant_id', 'tenant02'),
                           ('owner_id', 'owner02'), ('environment', 'LOCAL')):
            adapter = self.change('ownership', scope=replace(self.scope, **{key: value}))
            self.deny('MISSING_TRUST_RECORD', lambda: self.call(adapter))

    def test_cross_manifest_and_observation_scope(self):
        for registry in ('manifests', 'observations'):
            for key, value in (('identity_id', 'other01'), ('tenant_id', 'tenant02'),
                               ('owner_id', 'owner02'), ('environment', 'LOCAL')):
                adapter = self.change(registry, scope=replace(self.scope, **{key: value}))
                self.deny('TRUST_SCOPE_MISMATCH', lambda: self.call(adapter))

    def test_nonfictional_scope_rejected_in_all_sources(self):
        for registry in ('grants', 'ownership', 'manifests', 'observations'):
            for key, value in (('namespace', 'other.lab'), ('environment', 'PRODUCTION'),
                               ('resource_class', 'SERVICE'), ('resource_id', 'fictional.component02')):
                self.deny('INVALID_TRUST_RECORD', lambda: self.change(
                    registry, scope=replace(self.scope, **{key: value})))

    def test_principal_observer_swap(self):
        adapter = self.adapter()
        self.deny('PRINCIPAL_MISMATCH', lambda: self.call(
            adapter, principal_handle=adapter.identity_handles[1]))
        self.deny('INVALID_TRUST_HANDLE', lambda: self.call(
            adapter, principal_handle=adapter.comparison_handles[0],
            comparison_handle=adapter.identity_handles[0]))

    def test_same_identity_observer_denied(self):
        self.deny('OBSERVER_MISMATCH', lambda: self.call(
            self.change('observations', observer_id='principal01')))

    def test_unregistered_handles(self):
        for value in (object(), 'principal01', 0, None):
            self.deny('INVALID_TRUST_HANDLE', lambda: self.call(principal_handle=value))
            self.deny('INVALID_TRUST_HANDLE', lambda: self.call(comparison_handle=value))

    def test_cross_adapter_handles(self):
        other = self.adapter()
        self.deny('INVALID_TRUST_HANDLE', lambda: self.call(principal_handle=other.identity_handles[0]))
        self.deny('INVALID_TRUST_HANDLE', lambda: self.call(comparison_handle=other.comparison_handles[0]))

    def test_wrong_roles(self):
        self.deny('PRINCIPAL_MISMATCH', lambda: self.call(self.change('grants', role='OBSERVER')))
        p, o = self.fixture['grants']
        self.deny('OBSERVER_MISMATCH', lambda: self.call(
            self.adapter(grants=(p, replace(o, role='PRINCIPAL')))))

    def test_observer_membership_and_missing_registration(self):
        p, o = self.fixture['grants']
        for key, value in (('tenant_id', 'tenant02'), ('owner_id', 'owner02'), ('environment', 'LOCAL')):
            adapter = self.adapter(grants=(p, replace(o, scope=replace(o.scope, **{key: value}))))
            self.deny('OBSERVER_MISMATCH', lambda: self.call(adapter))
        self.deny('MISSING_TRUST_RECORD', lambda: self.call(self.adapter(grants=(p,))))

    def test_revoked_principal_or_observer(self):
        for index in (0, 1):
            grants = list(self.fixture['grants'])
            grants[index] = replace(grants[index], status='REVOKED')
            self.deny('IDENTITY_REVOKED', lambda: self.call(self.adapter(grants=tuple(grants))))

    def test_duplicate_and_conflicting_registry_entries(self):
        conflicts = dict(grants={'status': 'REVOKED'},
                         ownership={'scope': replace(self.scope, owner_id='owner02')},
                         manifests={'desired_digest': C}, observations={'current_digest': D},
                         slots={'challenge': 'different01'})
        for key, change in conflicts.items():
            records = self.fixture[key]
            for extra in (records[0], replace(records[0], **change)):
                self.deny('DUPLICATE_TRUST_RECORD', lambda: self.adapter(**{key: (*records, extra)}))
        slot = self.fixture['slots'][0]
        self.deny('DUPLICATE_TRUST_RECORD', lambda: self.adapter(
            slots=(slot, replace(slot, request_id='other01'))))

    def test_missing_pinned_manifest_or_observation(self):
        for key in ('manifests', 'observations'):
            self.deny('MISSING_TRUST_RECORD', lambda: self.call(self.adapter(**{key: ()})))
        self.deny('PRINCIPAL_MISMATCH', lambda: self.call(self.change('slots', principal_id='other01')))

    def test_independent_observation_mismatch(self):
        for change in ({'current_digest': D}, {'current_version': 7}):
            self.deny('PRECONDITION_MISMATCH', lambda: self.call(self.change('observations', **change)))
        # Editing request and expected manifest together cannot manufacture observed state.
        self.request['expected_current_digest'] = D
        self.deny('PRECONDITION_MISMATCH', lambda: self.call(
            self.change('manifests', expected_current_digest=D)))

    def test_expired_future_and_overlong_grants(self):
        for index in (0, 1):
            for change in ({'issued_at': NOW + timedelta(seconds=1)}, {'expires_at': NOW},
                           {'issued_at': NOW - timedelta(seconds=301)}):
                grants = list(self.fixture['grants'])
                grants[index] = replace(grants[index], **change)
                self.deny('GRANT_TIME_INVALID', lambda: self.call(self.adapter(grants=tuple(grants))))

    def test_expired_future_observations(self):
        for change in ({'observed_at': NOW + timedelta(seconds=1)}, {'expires_at': NOW},
                       {'observed_at': NOW - timedelta(seconds=301)}):
            self.deny('OBSERVATION_TIME_INVALID', lambda: self.call(self.change('observations', **change)))

    def test_expired_future_clock(self):
        for now in (START - timedelta(seconds=1), END, END + timedelta(seconds=1)):
            self.deny('TRUST_CLOCK_TIME_INVALID', lambda: self.call(self.adapter(
                clock=replace(self.fixture['clock'], now=now))))
        for now in (NOW.replace(tzinfo=None), 'forged01', Hostile()):
            self.deny('INVALID_TRUST_RECORD', lambda: self.adapter(
                clock=replace(self.fixture['clock'], now=now)))

    def test_expired_future_slot(self):
        for change in ({'issued_at': NOW + timedelta(seconds=1)}, {'expires_at': NOW}):
            self.deny('BINDING_TIME_INVALID', lambda: self.call(self.change('slots', **change)))

    def test_replay_consumed_request_or_challenge(self):
        for entry in (ReplayEntry('request01', 'other01', M),
                      ReplayEntry('other01', 'challenge01', M)):
            self.deny('REPLAY_DETECTED', lambda: self.call(self.adapter(
                replay=TrustedReplaySnapshot((entry,)))))

    def test_replay_duplicate_and_mutable_alias(self):
        entry = ReplayEntry('other01', 'otherchallenge01', M)
        self.deny('DUPLICATE_TRUST_RECORD', lambda: self.adapter(
            replay=TrustedReplaySnapshot((entry, entry))))
        self.deny('INVALID_TRUST_REGISTRY', lambda: self.adapter(replay=TrustedReplaySnapshot([entry])))

    def test_frozen_slotted_records_and_adapter(self):
        adapter = self.adapter()
        records = [*self.fixture['grants'], *self.fixture['ownership'], *self.fixture['manifests'],
                   *self.fixture['observations'], *self.fixture['slots'], self.fixture['clock']]
        for record in records:
            self.assertFalse(hasattr(record, '__dict__'))
            with self.assertRaises(FrozenInstanceError):
                setattr(record, fields(record)[0].name, None)
        self.assertFalse(hasattr(adapter, '__dict__'))
        with self.assertRaises(FrozenInstanceError):
            adapter._replay = TrustedReplaySnapshot(())

    def test_reinitialization_cannot_replace_trusted_state(self):
        adapter = self.adapter()
        handle = adapter.identity_handles[0]
        self.deny('TRUST_ALREADY_INITIALIZED', lambda: adapter.__init__(**self.fixture))
        self.assertIs(adapter.identity_handles[0], handle)
        self.assertEqual(self.call(adapter).authority_effect, 'NONE')

    def test_mutable_registry_aliases_and_record_shapes_rejected(self):
        for key in ('grants', 'ownership', 'manifests', 'observations', 'slots'):
            self.deny('INVALID_TRUST_REGISTRY', lambda: self.adapter(**{key: list(self.fixture[key])}))
            self.deny('INVALID_TRUST_RECORD', lambda: self.adapter(**{key: ({},)}))
            self.deny('INVALID_TRUST_REGISTRY', lambda: self.adapter(**{key: self.fixture[key] * 257}))
        self.deny('INVALID_TRUST_RECORD', lambda: self.change('manifests', manifest_version=True))

    def test_request_alias_cannot_mutate_source(self):
        adapter = self.adapter()
        result = self.call(adapter)
        self.request['tenant_id'] = 'tenant02'
        self.deny('REQUEST_BINDING_MISMATCH', lambda: self.call(adapter))
        self.assertEqual(self.fixture['manifests'][0].scope.tenant_id, 'tenant01')
        self.assertEqual(result.authority_effect, 'NONE')

    def test_hostile_equality_never_runs(self):
        hostile = Hostile()
        self.deny('INVALID_TRUST_HANDLE', lambda: self.call(principal_handle=hostile))
        self.deny('INVALID_TRUST_HANDLE', lambda: self.call(comparison_handle=hostile))
        self.deny('INVALID_TRUST_RECORD', lambda: self.change('slots', principal_id=hostile))
        self.deny('INVALID_TRUST_RECORD', lambda: self.change(
            'grants', scope=replace(self.scope, tenant_id=hostile)))
        self.request['tenant_id'] = hostile
        self.deny('INVALID_REQUEST', self.call)

    def test_call_time_context_injection_not_supported(self):
        adapter = self.adapter()
        for key in ('observer', 'manifests', 'clock', 'trusted_binding', 'replay'):
            with self.assertRaises(TypeError):
                self.call(adapter, **{key: self.fixture['clock']})


if __name__ == '__main__':
    unittest.main()
