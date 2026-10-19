"""Offline fictional fixtures; trusted inputs are test-owned, never request-derived."""
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone, tzinfo
import hashlib
import json
from pathlib import Path
import unittest

from avuhz_runtime.local_infrastructure_authority import (
    LocalInfrastructureDenied, ReplayEntry, ResourceScope, TrustedBinding,
    TrustedObservation, TrustedReplaySnapshot, validate_local_resource_contract,
)

D1 = 'sha256:' + '1' * 64
D2 = 'sha256:' + '2' * 64
D3 = 'sha256:' + '3' * 64
NOW = datetime(2026, 10, 19, 12, 0, 0, tzinfo=timezone.utc)


class LocalInfrastructureAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.scope = ResourceScope('identity01', 'tenant01', 'TEST', 'fictional.lab',
                                   'COMPONENT', 'fictional.component01', 'owner01')
        self.binding = TrustedBinding(self.scope, D1, 2, D2, 3, D3, 2,
                                      'request01', 'challenge01', 'observation01',
                                      NOW - timedelta(seconds=30), NOW + timedelta(seconds=120))
        self.observation = TrustedObservation(self.scope, 'observation01', D3, 2,
                                             NOW - timedelta(seconds=15), NOW + timedelta(seconds=60))
        self.snapshot = TrustedReplaySnapshot(())
        # Deliberately independent literal request fixture; no conversion helper.
        self.request = dict(schema_version=1, identity_id='identity01', tenant_id='tenant01',
                            environment='TEST', namespace='fictional.lab', resource_class='COMPONENT',
                            resource_id='fictional.component01', owner_id='owner01',
                            manifest_digest=D1, manifest_version=2, desired_digest=D2, desired_version=3,
                            expected_current_digest=D3, expected_current_version=2,
                            request_id='request01', challenge='challenge01', observation_id='observation01',
                            issued_at='2026-10-19T11:59:30Z', expires_at='2026-10-19T12:02:00Z',
                            operation='COMPARE_FICTIONAL_STATE')

    def call(self, **overrides):
        args = dict(trusted_binding=self.binding, trusted_observation=self.observation,
                    trusted_replay_snapshot=self.snapshot, now=NOW)
        args.update(overrides)
        return validate_local_resource_contract(self.request, **args)

    def denied(self, code, **overrides):
        with self.assertRaises(LocalInfrastructureDenied) as caught:
            self.call(**overrides)
        self.assertEqual(str(caught.exception), code)

    def test_positive_deterministic_digest_and_no_authority(self):
        result = self.call()
        canonical = json.dumps(self.request, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
        expected = 'sha256:' + hashlib.sha256(
            b'avuhz.local-infrastructure-authority.v1\n' + canonical.encode('ascii')).hexdigest()
        self.assertEqual(result.operation_digest, expected)
        self.assertEqual((result.outcome, result.authority_effect), ('CONTRACT_MATCH', 'NONE'))
        self.request = dict(reversed(list(self.request.items())))
        self.assertEqual(self.call(), result)
        self.assertEqual(self.call(), result)  # Pure call does not consume replay state.

    def test_local_environment(self):
        scope = replace(self.scope, environment='LOCAL')
        self.request['environment'] = 'LOCAL'
        self.call(trusted_binding=replace(self.binding, scope=scope),
                  trusted_observation=replace(self.observation, scope=scope))

    def test_scope_and_manifest_mismatches(self):
        changes = dict(identity_id='identity02', tenant_id='tenant02', environment='LOCAL',
                       namespace='other.lab', owner_id='owner02', resource_class='SERVICE',
                       resource_id='fictional.component02', manifest_digest=D2,
                       manifest_version=1, desired_digest=D3, desired_version=2,
                       expected_current_digest=D1, expected_current_version=1,
                       request_id='request02', challenge='challenge02', observation_id='observation02')
        for key, value in changes.items():
            with self.subTest(key=key):
                original = self.request[key]
                self.request[key] = value
                self.denied('REQUEST_BINDING_MISMATCH')
                self.request[key] = original

    def test_missing_manifest_and_other_required_fields(self):
        original = self.request.copy()
        for key in original:
            with self.subTest(key=key):
                self.request = {k:v for k,v in original.items() if k != key}
                self.denied('INVALID_REQUEST')

    def test_hostile_extra_fields(self):
        for key in ('trusted', 'verified', 'signature', 'provenance', 'trusted_binding', 'dispatch'):
            with self.subTest(key=key):
                self.request[key] = 'forged'
                self.denied('INVALID_REQUEST')
                del self.request[key]

    def test_malformed_schema_and_primitives(self):
        for value in (None, [], (), 'request', True, 1):
            with self.subTest(value=value):
                self.request = value
                self.denied('INVALID_REQUEST')

    def test_boolean_integer_and_nonprimitive_fields(self):
        for value in (True, False, 1.0, [], {}, object()):
            with self.subTest(value=type(value)):
                self.request['manifest_version'] = value
                self.denied('INVALID_REQUEST')

    def test_invalid_identifiers_and_digest_shapes(self):
        for value in ('', 'tenant@fictional.invalid', 'tenant01\n', 'x' * 65):
            with self.subTest(value=value):
                self.denied('INVALID_BINDING', trusted_binding=replace(
                    self.binding, scope=replace(self.scope, tenant_id=value)))
        self.denied('INVALID_BINDING', trusted_binding=replace(self.binding, manifest_digest='forged'))

    def test_untrusted_binding_shapes_and_versions(self):
        for value in (None, {}, self.request, {'trusted': True}):
            self.denied('INVALID_BINDING', trusted_binding=value)
        for value in (True, 0, -1, 2147483648, 2.0):
            self.denied('INVALID_BINDING', trusted_binding=replace(self.binding, manifest_version=value))

    def test_trusted_scope_still_restricted_to_fictional_local_test(self):
        for key, value in (('environment','PRODUCTION'), ('namespace','real.lab'),
                           ('resource_class','SERVICE'), ('resource_id','real.component01')):
            self.denied('INVALID_BINDING', trusted_binding=replace(
                self.binding, scope=replace(self.scope, **{key:value})))

    def test_invalid_observation_source_shape(self):
        for value in (None, self.request, {'verified':True}, {'trusted':True}):
            self.denied('INVALID_OBSERVATION', trusted_observation=value)
        self.denied('INVALID_OBSERVATION', trusted_observation=replace(self.observation, current_version=True))

    def test_observation_scope_and_id_mismatch(self):
        for key, value in (('tenant_id','tenant02'), ('identity_id','identity02'),
                           ('owner_id','owner02'), ('environment','LOCAL')):
            self.denied('OBSERVATION_MISMATCH', trusted_observation=replace(
                self.observation, scope=replace(self.scope, **{key:value})))
        self.denied('OBSERVATION_MISMATCH', trusted_observation=replace(self.observation, observation_id='forged01'))

    def test_precondition_wrong(self):
        for change in ({'current_digest':D1}, {'current_version':1}):
            self.denied('PRECONDITION_MISMATCH', trusted_observation=replace(self.observation, **change))

    def test_stale_future_expired_observation(self):
        for change in ({'observed_at': NOW - timedelta(seconds=301)},
                       {'observed_at': NOW + timedelta(seconds=1)},
                       {'expires_at':NOW}, {'expires_at':NOW - timedelta(seconds=1)},
                       {'expires_at':NOW + timedelta(seconds=301)}):
            self.denied('OBSERVATION_TIME_INVALID', trusted_observation=replace(self.observation, **change))

    def test_stale_future_expired_binding(self):
        for change in ({'issued_at':NOW - timedelta(seconds=301)},
                       {'issued_at':NOW + timedelta(seconds=1)}, {'expires_at':NOW}):
            self.denied('BINDING_TIME_INVALID', trusted_binding=replace(self.binding, **change))

    def test_request_time_cannot_override_trusted_time(self):
        self.request['expires_at'] = '2026-10-19T12:03:00Z'
        self.denied('REQUEST_BINDING_MISMATCH')
        self.request['expires_at'] = '2026-10-19T12:02:00+00:00'
        self.denied('INVALID_REQUEST')

    def test_reused_id_challenge_and_conflicting_idempotency(self):
        digest = self.call().operation_digest
        for entry in (ReplayEntry('request01','challenge01',digest),
                      ReplayEntry('request01','different01',D1),
                      ReplayEntry('different01','challenge01',D2)):
            self.denied('REPLAY_DETECTED', trusted_replay_snapshot=TrustedReplaySnapshot((entry,)))

    def test_duplicate_and_malformed_replay_snapshot(self):
        entry = ReplayEntry('other01','otherchallenge01',D1)
        for snapshot in ({}, TrustedReplaySnapshot([entry]), TrustedReplaySnapshot(({},)),
                         TrustedReplaySnapshot((entry, entry)),
                         TrustedReplaySnapshot((entry, replace(entry, operation_digest=D2))),
                         TrustedReplaySnapshot((replace(entry, operation_digest='bad'),))):
            self.denied('INVALID_REPLAY_SNAPSHOT', trusted_replay_snapshot=snapshot)
        self.call(trusted_replay_snapshot=TrustedReplaySnapshot((entry,)))

    def test_untrusted_datetimes_and_timezones(self):
        class HostileTimezone(tzinfo):
            def utcoffset(self, dt):
                raise AssertionError('must not execute untrusted timezone')
        class DerivedDatetime(datetime):
            pass
        values = (NOW.replace(tzinfo=None), NOW.replace(tzinfo=timezone(timedelta(hours=1))),
                  NOW.replace(tzinfo=HostileTimezone()), NOW.isoformat(),
                  DerivedDatetime(2026,10,19,tzinfo=timezone.utc), NOW.replace(fold=1))
        for value in values:
            self.denied('INVALID_CLOCK', now=value)
            self.denied('INVALID_BINDING', trusted_binding=replace(self.binding, issued_at=value))
            self.denied('INVALID_OBSERVATION', trusted_observation=replace(self.observation, observed_at=value))

    def test_mutable_aliasing_and_frozen_inputs(self):
        result = self.call()
        self.request['tenant_id'] = 'tenant02'
        self.assertEqual(self.binding.scope.tenant_id, 'tenant01')
        self.assertEqual(result.authority_effect, 'NONE')
        self.denied('REQUEST_BINDING_MISMATCH')
        with self.assertRaises(FrozenInstanceError):
            self.binding.scope.tenant_id = 'tenant02'
        with self.assertRaises(FrozenInstanceError):
            result.authority_effect = 'APPROVED'
        self.denied('INVALID_BINDING', trusted_binding=replace(self.binding, scope={}))

    def test_hostile_builtin_subclasses(self):
        class HostileStr(str):
            def __eq__(self, other):
                raise AssertionError('must not compare untrusted type')
        class HostileDict(dict):
            def copy(self):
                raise AssertionError('must not call untrusted method')
        self.request['tenant_id'] = HostileStr('tenant01')
        self.denied('INVALID_REQUEST')
        self.request = HostileDict()
        self.denied('INVALID_REQUEST')

    def test_json_schema_offline(self):
        try:
            from jsonschema import Draft202012Validator, FormatChecker
        except ImportError:
            self.skipTest('jsonschema unavailable; runtime validation still tested')
        path = Path(__file__).resolve().parents[2] / 'contracts/proposals/v1/local-infrastructure-authority.schema.json'
        schema = json.loads(path.read_text())
        Draft202012Validator.check_schema(schema)
        checker = FormatChecker()
        # Some offline jsonschema packages omit RFC3339 extras. Supply the
        # contract's narrower UTC-seconds calendar check explicitly.
        @checker.checks('date-time', raises=ValueError)
        def utc_seconds(value):
            if type(value) is not str:
                return True
            return datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').strftime('%Y-%m-%dT%H:%M:%SZ') == value
        validator = Draft202012Validator(schema, format_checker=checker)
        validator.validate(self.request)
        for change in ({'trusted':True}, {'manifest_version':True}, {'environment':'PRODUCTION'},
                       {'tenant_id':'tenant01\n'}, {'issued_at':'2026-02-30T12:00:00Z'},
                       {'resource_id':'other01'}, {'schema_version':2}):
            with self.subTest(change=change):
                self.assertTrue(list(validator.iter_errors({**self.request, **change})))
        for key in self.request:
            self.assertTrue(list(validator.iter_errors({k:v for k,v in self.request.items() if k != key})))


if __name__ == '__main__':
    unittest.main()
