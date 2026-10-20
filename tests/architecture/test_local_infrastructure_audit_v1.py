"""Sole-engineer, disposable SQLite tests; no provider or live execution."""
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from dataclasses import FrozenInstanceError, asdict, replace
from datetime import timedelta
import multiprocessing
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from avuhz_runtime.local_infrastructure_audit import (
    AuditBinding, AuditGrant, LocalTestInfrastructureAudit, MAX_RECORDS,
    _COLUMNS, _SCHEMA, _audit_hash, _write_authorizer,
)
from avuhz_runtime.local_infrastructure_authority import LocalInfrastructureDenied
from avuhz_runtime.local_infrastructure_execution import (
    LocalTestInfrastructureExecution, SimulatedState, TestFailures, _approval_digest,
)
from avuhz_runtime.local_infrastructure_policy import (
    ConsumptionEntry, ConsumptionSnapshot, LocalTestInfrastructurePolicyAdapter, _hash,
    policy_decision_digest, source_observation_digest,
)
from avuhz_runtime.local_infrastructure_trust import LocalTrustAdapter
from avuhz_runtime.local_infrastructure_verification import (
    LocalTestInfrastructureVerification, _evidence_hash as verification_hash,
    _UPDATE as VERIFICATION_UPDATE,
)
from tests.architecture import test_local_infrastructure_execution_v1 as execution
from tests.architecture import test_local_infrastructure_trust_v1 as fixtures
from tests.architecture import test_local_infrastructure_verification_v1 as verification


def provision(path, *, flags=None, state=None):
    executor, base = execution.provision(path, failures=TestFailures(**(flags or {})))
    executor.execute(base.request, principal_handle=executor.principal_handle,
                     execution_handle=executor.execution_handle)
    if state is not None:
        with sqlite3.connect(path) as db:
            db.execute('UPDATE simulated_resource_state SET digest=?,version=?', state)
    options = verification.verifier_options(path)
    verifier = LocalTestInfrastructureVerification(**options)
    result = verifier.verify(verifier_handle=verifier.verifier_handle,
                             binding_handle=verifier.binding_handle)
    if result.reason_code not in ('LOCAL_STATE_MATCH', 'PENDING', 'MISMATCH'):
        raise AssertionError('INVALID_TEST_PROVISIONING')
    return executor, base


def audit_options(path, verification_options=None):
    # Trusted harness registration, independently of any public request/result.
    options = verification.verifier_options(path) if verification_options is None else verification_options
    with sqlite3.connect(path) as db:
        digest = db.execute('SELECT evidence_digest FROM local_verification_evidence').fetchone()[0]
    v = options['verification_binding']
    grant = AuditGrant('auditgrant01', 1, replace(v.scope, identity_id='auditor01'), 'AUDITOR',
                       'APPEND_FICTIONAL_AUDIT', 'ACTIVE', fixtures.START, fixtures.END)
    binding = AuditBinding(v.scope, v.execution_id, v.execution_version, v.execution_digest,
                           _hash(b'avuhz.local-infrastructure-verification.BINDING.v1\n',
                                 {'binding': asdict(v), 'grant': asdict(options['verifier_grant'])}),
                           digest, 'auditor01', 'auditgrant01', 1)
    return dict(**options, audit_grant=grant, audit_binding=binding)


def scoped_database(path, *, tenant='tenant01', environment='LOCAL'):
    """Independent, internally consistent alternative harness registration."""
    options = verification.verifier_options(path)
    approval = options['execution_approval']
    d = approval.diagnostic
    scope = replace(d.pins.manifest.scope, tenant_id=tenant, environment=environment)
    sources = dict(options['policy_sources'])
    for key in ('grants', 'ownership', 'manifests', 'observations'):
        sources[key] = tuple(replace(r, scope=replace(scope, identity_id=r.scope.identity_id)) for r in sources[key])
    # Canonical original comparison operation is recomputed from independent
    # wire fixture fields, then separately pinned in the policy and approval.
    wire = fixtures.LocalInfrastructureTrustTests()
    wire.setUp()
    request = dict(wire.request, tenant_id=tenant, environment=environment)
    pins = replace(d.pins, manifest=sources['manifests'][0], observation=sources['observations'][0],
                   source_digest=source_observation_digest(sources['observations'][0], sources['grants'][1]),
                   operation_digest=_hash(b'avuhz.local-infrastructure-authority.v1\n', request))
    rule = replace(sources['policies'][0], pins=pins)
    d = replace(d, pins=pins, policy_decision_digest=policy_decision_digest(rule))
    sources.update(policies=(rule,), approvals=(d,),
                   humans=(replace(sources['humans'][0], scope=replace(scope, identity_id=d.human_id)),))
    approval = replace(approval, diagnostic=d)
    executor = LocalTestInfrastructureExecution(database_path=path, policy_sources=sources,
                 execution_approval=approval, initial_state=SimulatedState(scope, fixtures.C, 2))
    executor.execute(request, principal_handle=executor.principal_handle, execution_handle=executor.execution_handle)
    options.update(policy_sources=sources, execution_approval=approval,
                   verifier_grant=replace(options['verifier_grant'], scope=replace(scope, identity_id='verifier01')),
                   verification_binding=replace(options['verification_binding'], scope=scope,
                                                execution_digest=_approval_digest(approval)))
    v = LocalTestInfrastructureVerification(**options)
    if v.verify(verifier_handle=v.verifier_handle, binding_handle=v.binding_handle).reason_code != 'LOCAL_STATE_MATCH':
        raise AssertionError('INVALID_SCOPED_FIXTURE')
    return audit_options(path, options)


def append_process(path):
    adapter = LocalTestInfrastructureAudit(**audit_options(path))
    result = adapter.append(auditor_handle=adapter.auditor_handle, binding_handle=adapter.binding_handle)
    return result.reason_code, result.evidence_kind, result.evidence_digest


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='avuhz-3b-', dir='/tmp')
        self.addCleanup(self.tmp.cleanup)
        self.path = str(Path(self.tmp.name) / 'audit.sqlite')
        self.executor, self.base = provision(self.path)
        self.options = audit_options(self.path)

    def adapter(self, **changes):
        return LocalTestInfrastructureAudit(**dict(self.options, **changes))

    def append(self, adapter=None, **handles):
        a = self.adapter() if adapter is None else adapter
        return a.append(**dict({'auditor_handle': a.auditor_handle, 'binding_handle': a.binding_handle}, **handles))

    def sql(self, statement, args=()):
        with sqlite3.connect(self.path) as db:
            return db.execute(statement, args).fetchall()

    def count(self):
        return self.sql('SELECT count(*) FROM local_audit_evidence')[0][0]

    def sources(self):
        return tuple(self.sql(sql) for sql in (
            'SELECT * FROM execution_registry', 'SELECT * FROM local_attempts',
            'SELECT * FROM simulated_resource_state', 'SELECT * FROM local_verification_evidence'))

    def different_fixture(self, **options):
        self.path = str(Path(self.tmp.name) / 'different.sqlite')
        self.executor, self.base = provision(self.path, **options)
        self.options = audit_options(self.path)

    def test_exact_sanitized_immutable_evidence(self):
        before = self.sources()
        result = self.append()
        self.assertEqual((result.reason_code, result.evidence_kind, result.authority_effect),
                         ('AUDIT_RECORDED', 'SYNTHETIC_LOCAL_RECORD', 'NONE'))
        self.assertEqual((result.execution_outcome, result.verification_execution_outcome,
                          result.observation_reason), ('ATTEMPTED', 'ATTEMPTED', 'LOCAL_STATE_MATCH'))
        row = self.sql('SELECT * FROM local_audit_evidence')[0]
        self.assertEqual(len(row), len(_COLUMNS))
        self.assertEqual(row[-1], _audit_hash(row[:-1]))
        self.assertEqual(row[-1], result.evidence_digest)
        self.assertEqual(result.evidence_digest,
                         'sha256:71dafeaadf43959eef9015fb078ab507c984480518813146e7015936dd146b67')
        self.assertEqual(row[15], result.verification_evidence_digest)
        self.assertEqual(row[:2], ('execution01', 1))
        self.assertEqual(row[20:22], (fixtures.D, 3))
        self.assertEqual(row[22:24], ('2026-10-19T12:00:00Z',) * 2)
        self.assertNotIn('request01', repr(row))
        self.assertNotIn('challenge01', repr(row))
        self.assertEqual(before, self.sources())

    def test_uncertain_outcome_and_matching_state_remain_distinct(self):
        self.different_fixture(flags={'lost_ack': True})
        r = self.append()
        self.assertEqual((r.execution_outcome, r.observation_reason), ('UNCERTAIN', 'LOCAL_STATE_MATCH'))
        self.assertEqual(self.sql('SELECT outcome FROM local_attempts'), [('UNCERTAIN',)])

    def test_durable_reservation_does_not_prove_effect(self):
        self.different_fixture(flags={'crash_after_reservation': True})
        r = self.append()
        self.assertEqual((r.execution_outcome, r.observation_reason), ('ATTEMPTED', 'PENDING'))
        self.assertEqual(self.sql('SELECT consumed FROM execution_registry'), [(1,)])
        self.assertEqual(self.sql('SELECT digest,version FROM simulated_resource_state'), [(fixtures.C, 2)])

    def test_effect_failure_is_uncertain_with_pending_observation(self):
        self.different_fixture(flags={'effect_write_failure': True})
        r = self.append()
        self.assertEqual((r.execution_outcome, r.observation_reason), ('UNCERTAIN', 'PENDING'))

    def test_outcome_write_failure_preserves_attempt_ambiguity(self):
        self.different_fixture(flags={'lost_ack': True, 'outcome_write_failure': True})
        r = self.append()
        self.assertEqual((r.execution_outcome, r.observation_reason), ('ATTEMPTED', 'LOCAL_STATE_MATCH'))

    def test_mismatch_is_recorded_without_repair(self):
        self.different_fixture(state=(fixtures.M, 9))
        before = self.sources()
        self.assertEqual(self.append().observation_reason, 'MISMATCH')
        self.assertEqual(before, self.sources())

    def test_version_mismatch_not_digest_only_match(self):
        self.different_fixture(state=(fixtures.D, 9))
        self.assertEqual(self.append().observation_reason, 'MISMATCH')

    def test_retries_return_identical_history(self):
        a = self.adapter()
        first = self.append(a)
        row = self.sql('SELECT * FROM local_audit_evidence')
        for _ in range(4):
            r = self.append(a)
            self.assertEqual(r.evidence_kind, 'HISTORICAL_REPLAY')
            self.assertEqual(replace(first, evidence_kind='HISTORICAL_REPLAY'), r)
        self.assertEqual(self.count(), 1)
        self.assertEqual(row, self.sql('SELECT * FROM local_audit_evidence'))

    def test_restart_new_handles_stable_record(self):
        first = self.append()
        r = append_process(self.path)
        self.assertEqual(r, ('AUDIT_RECORDED', 'HISTORICAL_REPLAY', first.evidence_digest))

    def test_process_restart_stable_record(self):
        first = self.append()
        with ProcessPoolExecutor(max_workers=1, mp_context=multiprocessing.get_context('spawn')) as pool:
            r = pool.submit(append_process, self.path).result(timeout=30)
        self.assertEqual(r, ('AUDIT_RECORDED', 'HISTORICAL_REPLAY', first.evidence_digest))

    def test_concurrent_threads_one_append(self):
        before = self.sources()
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(append_process, [self.path] * 8))
        self.assertEqual({r[0] for r in results}, {'AUDIT_RECORDED'})
        self.assertEqual(sum(r[1] == 'SYNTHETIC_LOCAL_RECORD' for r in results), 1)
        self.assertEqual(len({r[2] for r in results}), 1)
        self.assertEqual(self.count(), 1)
        self.assertEqual(before, self.sources())

    def test_concurrent_processes_one_append(self):
        with ProcessPoolExecutor(max_workers=3, mp_context=multiprocessing.get_context('spawn')) as pool:
            results = list(pool.map(append_process, [self.path] * 6))
        self.assertEqual({r[0] for r in results}, {'AUDIT_RECORDED'})
        self.assertEqual(sum(r[1] == 'SYNTHETIC_LOCAL_RECORD' for r in results), 1)
        self.assertEqual(len({r[2] for r in results}), 1)
        self.assertEqual(self.count(), 1)

    def test_changed_physical_state_does_not_reobserve_or_upgrade(self):
        self.different_fixture(flags={'crash_after_reservation': True})
        a = self.adapter()
        self.sql('UPDATE simulated_resource_state SET digest=?,version=3', (fixtures.D,))
        first = self.append(a)
        self.assertEqual(first.observation_reason, 'PENDING')
        self.sql('DELETE FROM simulated_resource_state')
        self.assertEqual(self.append(a).observation_reason, 'PENDING')

    def test_never_calls_executor_verifier_or_comparison(self):
        with patch.object(LocalTestInfrastructureExecution, 'execute', side_effect=AssertionError), \
                patch.object(LocalTestInfrastructureExecution, '_observe', side_effect=AssertionError), \
                patch.object(LocalTestInfrastructureVerification, 'verify', side_effect=AssertionError), \
                patch.object(LocalTestInfrastructureVerification, '_snapshot', side_effect=AssertionError), \
                patch.object(LocalTestInfrastructurePolicyAdapter, 'review_approval', side_effect=AssertionError), \
                patch.object(LocalTrustAdapter, 'compare', side_effect=AssertionError):
            self.assertEqual(self.append().reason_code, 'AUDIT_RECORDED')

    def test_authorizer_denies_state_reads_and_every_non_audit_write(self):
        a = self.adapter()
        self.append(a)
        before = self.sources()
        with sqlite3.connect(self.path, cached_statements=0) as db:
            db.set_authorizer(_write_authorizer)
            statements = (
                'UPDATE execution_registry SET consumed=0', 'DELETE FROM local_attempts',
                'UPDATE simulated_resource_state SET version=9',
                'SELECT * FROM simulated_resource_state', 'DELETE FROM local_verification_evidence',
                'UPDATE local_audit_evidence SET execution_outcome=\'UNCERTAIN\'',
                'DELETE FROM local_audit_evidence', 'DROP TABLE local_audit_evidence',
                'PRAGMA writable_schema=ON', "ATTACH DATABASE ':memory:' AS other",
                'CREATE TABLE unexpected (id TEXT)', 'SELECT randomblob(100)',
            )
            for sql in statements:
                with self.subTest(sql=sql), self.assertRaises(sqlite3.DatabaseError):
                    db.execute(sql)
        self.assertEqual(before, self.sources())

    def test_invalid_and_hostile_handles(self):
        a = self.adapter()
        for handle in (None, object(), fixtures.Hostile(), 'auditor01', self.executor.execution_handle,
                       self.options['audit_grant'], self.adapter().auditor_handle):
            for name in ('auditor_handle', 'binding_handle'):
                with self.subTest(name=name, handle=type(handle)):
                    self.assertEqual(self.append(a, **{name: handle}).reason_code, 'AUTHORIZATION_DENIED')
        self.assertEqual(self.count(), 0)

    def test_swapped_handles(self):
        a = self.adapter()
        self.assertEqual(self.append(a, auditor_handle=a.binding_handle,
                                     binding_handle=a.auditor_handle).reason_code, 'AUTHORIZATION_DENIED')

    def test_call_time_injection_rejected(self):
        a = self.adapter()
        for key in ('database_path', 'clock', 'observed_digest', 'execution_outcome', 'policy_sources',
                    'callback', 'verification_evidence_digest', 'request'):
            with self.subTest(key=key), self.assertRaises(TypeError):
                a.append(auditor_handle=a.auditor_handle, binding_handle=a.binding_handle, **{key: None})
        self.assertEqual(self.count(), 0)

    def test_frozen_registration_and_no_reinitialization(self):
        a = self.adapter()
        with self.assertRaises(FrozenInstanceError):
            a._path = 'other'
        with self.assertRaises(FrozenInstanceError):
            self.options['audit_grant'].role = 'EXECUTOR'
        with self.assertRaises(LocalInfrastructureDenied):
            a.__init__(**self.options)
        self.assertNotIn(self.path, repr(a))

    def test_closed_auditor_role_capability_and_record_types(self):
        g = self.options['audit_grant']
        for changes in ({'role': 'VERIFIER'}, {'capability': 'APPLY_FICTIONAL_STATE'},
                        {'status': 'UNKNOWN'}, {'grant_version': True}, {'grant_id': fixtures.Hostile()},
                        {'issued_at': fixtures.NOW.replace(tzinfo=None)},
                        {'expires_at': fixtures.END.replace(microsecond=1)}):
            with self.subTest(changes=changes), self.assertRaises(LocalInfrastructureDenied):
                self.adapter(audit_grant=replace(g, **changes))
        for key in ('audit_grant', 'audit_binding', 'clock', 'execution_approval', 'verifier_grant'):
            with self.subTest(key=key), self.assertRaises(LocalInfrastructureDenied):
                self.adapter(**{key: fixtures.Hostile()})

    def test_auditor_distinct_from_all_five_source_identities(self):
        g, b = self.options['audit_grant'], self.options['audit_binding']
        for identity in ('principal01', 'observer01', 'fictional.human01', 'fictional.executor01', 'verifier01'):
            with self.subTest(identity=identity), self.assertRaises(LocalInfrastructureDenied):
                self.adapter(audit_grant=replace(g, scope=replace(g.scope, identity_id=identity)),
                             audit_binding=replace(b, auditor_id=identity))

    def test_all_scope_dimensions_must_match(self):
        b = self.options['audit_binding']
        changes = dict(tenant_id='tenant02', identity_id='principal02', owner_id='owner02',
                       environment='LOCAL', namespace='other.lab', resource_class='SERVICE',
                       resource_id='fictional.component02')
        for key, value in changes.items():
            with self.subTest(key=key), self.assertRaises(LocalInfrastructureDenied):
                self.adapter(audit_binding=replace(b, scope=replace(b.scope, **{key: value})))

    def test_auditor_grant_scope_pinned(self):
        g = self.options['audit_grant']
        for key, value in dict(tenant_id='tenant02', owner_id='owner02', environment='LOCAL').items():
            with self.subTest(key=key), self.assertRaises(LocalInfrastructureDenied):
                self.adapter(audit_grant=replace(g, scope=replace(g.scope, **{key: value})))

    def test_local_environment_positive(self):
        options = scoped_database(str(Path(self.tmp.name) / 'local.sqlite'))
        a = LocalTestInfrastructureAudit(**options)
        self.assertEqual(self.append(a).observation_reason, 'LOCAL_STATE_MATCH')

    def test_fully_consistent_other_tenant_cannot_replay(self):
        first = self.append()
        before = self.sources()
        options = scoped_database(str(Path(self.tmp.name) / 'other.sqlite'), tenant='tenant02', environment='TEST')
        with self.assertRaises(LocalInfrastructureDenied):
            LocalTestInfrastructureAudit(**dict(options, database_path=self.path))
        self.assertEqual(before, self.sources())
        self.assertEqual(self.sql('SELECT evidence_digest FROM local_audit_evidence'), [(first.evidence_digest,)])

    def test_binding_digests_ids_and_versions_pinned(self):
        b = self.options['audit_binding']
        changes = dict(execution_id='execution02', execution_version=2, execution_digest=fixtures.M,
                       verification_binding_digest=fixtures.M, verification_evidence_digest=fixtures.M,
                       auditor_id='auditor02', grant_id='auditgrant02', grant_version=2)
        for key, value in changes.items():
            with self.subTest(key=key), self.assertRaises(LocalInfrastructureDenied):
                self.adapter(audit_binding=replace(b, **{key: value}))

    def test_revoked_expired_future_and_overlong_grants_denied(self):
        for name in ('audit_grant', 'verifier_grant'):
            g = self.options[name]
            for changes in ({'status': 'REVOKED'}, {'expires_at': fixtures.NOW},
                            {'issued_at': fixtures.NOW + timedelta(seconds=1)},
                            {'issued_at': fixtures.NOW - timedelta(seconds=301)}):
                with self.subTest(name=name, changes=changes), self.assertRaises(LocalInfrastructureDenied):
                    self.adapter(**{name: replace(g, **changes)})

    def test_expired_and_inconsistent_clock_denied(self):
        for clock in (replace(self.options['clock'], now=fixtures.END),
                      replace(self.options['clock'], now=fixtures.NOW + timedelta(seconds=1))):
            with self.subTest(clock=clock), self.assertRaises(LocalInfrastructureDenied):
                self.adapter(clock=clock)

    def test_stale_approval_denied_without_replaying_comparison(self):
        now = fixtures.END
        current = replace(self.options['clock'], now=now, issued_at=now, expires_at=now + timedelta(seconds=60))
        sources = dict(self.options['policy_sources'], clock=current)
        with self.assertRaises(LocalInfrastructureDenied):
            self.adapter(clock=current, policy_sources=sources)

    def test_revoked_human_or_principal_denied(self):
        sources = self.options['policy_sources']
        for key in ('humans', 'grants'):
            records = sources[key]
            with self.subTest(key=key), self.assertRaises(LocalInfrastructureDenied):
                self.adapter(policy_sources=dict(sources, **{key: (replace(records[0], status='REVOKED'), *records[1:])}))

    def test_revoked_execution_approval_denied(self):
        with self.assertRaises(LocalInfrastructureDenied):
            self.adapter(execution_approval=replace(self.options['execution_approval'], status='REVOKED'))

    def test_revoked_diagnostic_snapshot_denied(self):
        d = self.options['execution_approval'].diagnostic
        entry = ConsumptionEntry(d.approval_id, d.approval_version, d.pins.slot.request_id,
                                 d.pins.slot.challenge, d.pins.operation_digest, 'REVOKED')
        with self.assertRaises(LocalInfrastructureDenied):
            self.adapter(policy_sources=dict(self.options['policy_sources'], consumption=ConsumptionSnapshot((entry,))))

    def test_exact_consumed_diagnostic_is_only_history(self):
        d = self.options['execution_approval'].diagnostic
        entry = ConsumptionEntry(d.approval_id, d.approval_version, d.pins.slot.request_id,
                                 d.pins.slot.challenge, d.pins.operation_digest, 'CONSUMED')
        a = self.adapter(policy_sources=dict(self.options['policy_sources'], consumption=ConsumptionSnapshot((entry,))))
        self.assertEqual(self.append(a).reason_code, 'AUDIT_RECORDED')
        with self.assertRaises(LocalInfrastructureDenied):
            self.adapter(policy_sources=dict(self.options['policy_sources'],
                         consumption=ConsumptionSnapshot((replace(entry, operation_digest=fixtures.M),))))

    def test_unexpected_source_key_denied(self):
        with self.assertRaises(LocalInfrastructureDenied):
            self.adapter(policy_sources=dict(self.options['policy_sources'], extra='untrusted'))

    def test_changed_manifest_policy_observation_and_approval_denied(self):
        sources = self.options['policy_sources']
        changes = dict(manifests=replace(sources['manifests'][0], manifest_version=9),
                       policies=replace(sources['policies'][0], decision='DENY'),
                       observations=replace(sources['observations'][0], current_digest=fixtures.D),
                       approvals=replace(sources['approvals'][0], decision='DENY'))
        for key, record in changes.items():
            with self.subTest(key=key), self.assertRaises(LocalInfrastructureDenied):
                self.adapter(policy_sources=dict(sources, **{key: (record,)}))

    def test_live_environments_and_unbounded_paths_denied(self):
        for path in (':memory:', 'relative.sqlite', '/var/tmp/other.sqlite', '/tmp/missing-3b.sqlite',
                     'file:/tmp/other.sqlite?mode=rw', '/tmp/../var/other.sqlite', '/tmp/invalid\x00name'):
            with self.subTest(path=path), self.assertRaises(LocalInfrastructureDenied):
                self.adapter(database_path=path)
        for environment in ('DEVELOPMENT', 'STAGING', 'PRODUCTION'):
            b = self.options['audit_binding']
            with self.subTest(environment=environment), self.assertRaises(LocalInfrastructureDenied):
                self.adapter(audit_binding=replace(b, scope=replace(b.scope, environment=environment)))

    def test_symlink_and_directory_denied(self):
        link = Path(self.tmp.name) / 'link.sqlite'
        link.symlink_to(self.path)
        for path in (str(link), self.tmp.name):
            with self.assertRaises(LocalInfrastructureDenied):
                self.adapter(database_path=path)

    def test_runtime_durable_revocation_denies_append_and_replay(self):
        a = self.adapter()
        self.append(a)
        before = self.sql('SELECT * FROM local_audit_evidence')
        self.sql('UPDATE execution_registry SET revoked=1')
        self.assertEqual(self.append(a).reason_code, 'CONFLICT')
        self.assertEqual(before, self.sql('SELECT * FROM local_audit_evidence'))

    def test_runtime_missing_attempt_or_reservation_denied(self):
        a = self.adapter()
        self.sql('DELETE FROM local_attempts')
        self.assertEqual(self.append(a).reason_code, 'CONFLICT')
        self.assertEqual(self.count(), 0)

    def test_unconsumed_reservation_denied(self):
        a = self.adapter()
        self.sql('UPDATE execution_registry SET consumed=0')
        self.assertEqual(self.append(a).reason_code, 'CONFLICT')

    def test_every_reservation_pin_checked(self):
        a = self.adapter()
        columns = ('execution_version', 'approval_id', 'approval_version', 'request_id', 'challenge', 'scope', 'digest')
        original = self.sql('SELECT * FROM execution_registry')[0]
        for index, column in enumerate(columns, 1):
            value = 9 if type(original[index]) is int else 'different01'
            with self.subTest(column=column):
                self.sql('UPDATE execution_registry SET ' + column + '=?', (value,))
                self.assertEqual(self.append(a).reason_code, 'CONFLICT')
                self.sql('UPDATE execution_registry SET ' + column + '=?', (original[index],))
        self.assertEqual(self.count(), 0)

    def test_every_attempt_pin_checked(self):
        a = self.adapter()
        original = self.sql('SELECT * FROM local_attempts')[0]
        for index, column in enumerate(('execution_version', 'approval_id', 'approval_version',
                                        'request_id', 'challenge', 'scope', 'digest'), 1):
            value = 9 if type(original[index]) is int else 'different01'
            with self.subTest(column=column):
                self.sql('UPDATE local_attempts SET ' + column + '=?', (value,))
                self.assertEqual(self.append(a).reason_code, 'CONFLICT')
                self.sql('UPDATE local_attempts SET ' + column + '=?', (original[index],))

    def test_legacy_unknown_outcomes_fail_closed(self):
        a = self.adapter()
        with sqlite3.connect(self.path) as db:
            db.execute('PRAGMA ignore_check_constraints=ON')
            for outcome in ('UNKNOWN', 'VERIFIED', 'SUCCEEDED'):
                db.execute('UPDATE local_attempts SET outcome=?', (outcome,))
                db.commit()
                self.assertEqual(self.append(a).reason_code, 'CONFLICT')
        self.assertEqual(self.count(), 0)

    def test_historical_outcome_advance_retains_original_row(self):
        a = self.adapter()
        first = self.append(a)
        self.sql("UPDATE local_attempts SET outcome='UNCERTAIN'")
        r = self.append(a)
        self.assertEqual(r, replace(first, evidence_kind='HISTORICAL_REPLAY'))
        self.assertEqual(self.sql('SELECT outcome FROM local_attempts'), [('UNCERTAIN',)])

    def test_attempt_advance_before_audit_is_separately_recorded(self):
        a = self.adapter()
        self.sql("UPDATE local_attempts SET outcome='UNCERTAIN'")
        r = self.append(a)
        self.assertEqual((r.execution_outcome, r.verification_execution_outcome), ('UNCERTAIN', 'ATTEMPTED'))

    def test_uncertain_attempt_cannot_regress(self):
        self.different_fixture(flags={'lost_ack': True})
        a = self.adapter()
        self.sql("UPDATE local_attempts SET outcome='ATTEMPTED'")
        self.assertEqual(self.append(a).reason_code, 'CONFLICT')

    def test_missing_verification_denied(self):
        a = self.adapter()
        self.sql('DROP TRIGGER local_verification_no_delete')
        self.sql('DELETE FROM local_verification_evidence')
        # Restore exact schema: missing data must also fail independently of DDL checks.
        from avuhz_runtime.local_infrastructure_verification import _DELETE
        self.sql(_DELETE)
        self.assertEqual(self.append(a).reason_code, 'CONFLICT')

    def test_every_verification_field_tamper_denied(self):
        a = self.adapter()
        self.sql('DROP TRIGGER local_verification_no_update')
        original = self.sql('SELECT * FROM local_verification_evidence')[0]
        names = [r[1] for r in self.sql('PRAGMA table_info(local_verification_evidence)')]
        for index, column in enumerate(names):
            value = 9 if type(original[index]) is int else (
                'UNCERTAIN' if column == 'execution_outcome' else 'MISMATCH' if column == 'reason_code'
                else fixtures.M if column.endswith('digest') else 'different01')
            with self.subTest(column=column):
                self.sql('UPDATE local_verification_evidence SET ' + column + '=?', (value,))
                self.sql(VERIFICATION_UPDATE)
                self.assertEqual(self.append(a).reason_code, 'CONFLICT')
                self.sql('DROP TRIGGER local_verification_no_update')
                self.sql('UPDATE local_verification_evidence SET ' + column + '=?', (original[index],))
        self.sql(VERIFICATION_UPDATE)
        self.assertEqual(self.count(), 0)

    def test_coherent_verification_rehash_still_breaks_independent_pin(self):
        a = self.adapter()
        self.sql('DROP TRIGGER local_verification_no_update')
        self.sql('UPDATE local_verification_evidence SET observed_version=9,reason_code=\'MISMATCH\'')
        row = self.sql('SELECT * FROM local_verification_evidence')[0]
        self.sql('UPDATE local_verification_evidence SET evidence_digest=?', (verification_hash(row[:-1]),))
        self.sql(VERIFICATION_UPDATE)
        self.assertEqual(self.append(a).reason_code, 'CONFLICT')

    def test_noncanonical_binary_verification_fields_fail_closed(self):
        a = self.adapter()
        for column in ('reason_code', 'observed_at', 'evidence_digest'):
            original = self.sql('SELECT ' + column + ' FROM local_verification_evidence')[0][0]
            self.sql('DROP TRIGGER local_verification_no_update')
            with sqlite3.connect(self.path) as db:
                db.execute('PRAGMA ignore_check_constraints=ON')
                db.execute('UPDATE local_verification_evidence SET ' + column + '=?', (b'fictional',))
            self.sql(VERIFICATION_UPDATE)
            with self.subTest(column=column):
                self.assertEqual(self.append(a).reason_code, 'CONFLICT')
            self.sql('DROP TRIGGER local_verification_no_update')
            self.sql('UPDATE local_verification_evidence SET ' + column + '=?', (original,))
            self.sql(VERIFICATION_UPDATE)

    def test_invalid_future_and_outside_window_historical_clock(self):
        original = self.sql('SELECT * FROM local_verification_evidence')[0]
        for stamp in ('2026-02-30T12:00:00Z', '2026-10-19T12:00:01Z', '2026-10-19T11:00:00Z'):
            with self.subTest(stamp=stamp):
                self.sql('DROP TRIGGER local_verification_no_update')
                row = (*original[:15], stamp)
                self.sql('UPDATE local_verification_evidence SET observed_at=?,evidence_digest=?',
                         (stamp, verification_hash(row)))
                self.sql(VERIFICATION_UPDATE)
                options = audit_options(self.path)
                with self.assertRaises(LocalInfrastructureDenied):
                    LocalTestInfrastructureAudit(**options)

    def test_historical_clock_retained_at_later_audit_and_replay(self):
        now = fixtures.NOW + timedelta(seconds=90)
        current = replace(self.options['clock'], now=now)
        a = self.adapter(clock=current, policy_sources=dict(self.options['policy_sources'], clock=current))
        first = self.append(a)
        self.assertEqual((first.observed_at, first.recorded_at),
                         ('2026-10-19T12:00:00Z', '2026-10-19T12:01:30Z'))
        self.assertEqual(self.append(a), replace(first, evidence_kind='HISTORICAL_REPLAY'))

    def test_replay_rejects_clock_before_original_audit(self):
        now = fixtures.NOW + timedelta(seconds=90)
        current = replace(self.options['clock'], now=now)
        a = self.adapter(clock=current, policy_sources=dict(self.options['policy_sources'], clock=current))
        self.assertEqual(self.append(a).reason_code, 'AUDIT_RECORDED')
        self.assertEqual(self.append().reason_code, 'CONFLICT')

    def test_replay_denied_with_current_revoked_auditor(self):
        self.append()
        before = self.sql('SELECT * FROM local_audit_evidence')
        with self.assertRaises(LocalInfrastructureDenied):
            self.adapter(audit_grant=replace(self.options['audit_grant'], status='REVOKED'))
        self.assertEqual(before, self.sql('SELECT * FROM local_audit_evidence'))

    def test_immutable_update_delete_replace_even_with_external_connection(self):
        self.append()
        row = self.sql('SELECT * FROM local_audit_evidence')[0]
        for sql, args in (
                ('UPDATE local_audit_evidence SET recorded_at=recorded_at', ()),
                ('DELETE FROM local_audit_evidence', ()),
                ('INSERT OR REPLACE INTO local_audit_evidence VALUES (' + ','.join('?' for _ in row) + ')', row)):
            with self.subTest(sql=sql), self.assertRaises(sqlite3.IntegrityError):
                self.sql(sql, args)
        self.assertEqual(self.sql('SELECT * FROM local_audit_evidence'), [row])

    def test_every_audit_field_tamper_is_rejected(self):
        a = self.adapter()
        self.append(a)
        row = self.sql('SELECT * FROM local_audit_evidence')[0]
        update = next(sql for name, _, sql in _SCHEMA if name == 'local_audit_no_update')
        for index, column in enumerate(_COLUMNS):
            value = 9 if type(row[index]) is int else (
                'UNCERTAIN' if 'outcome' in column else 'MISMATCH' if column == 'observation_reason'
                else (fixtures.C if row[index] == fixtures.M else fixtures.M) if column.endswith('digest') else '2026-10-19T12:00:01Z'
                if column.endswith('_at') else 'different01')
            with self.subTest(column=column):
                self.sql('DROP TRIGGER local_audit_no_update')
                self.sql('UPDATE local_audit_evidence SET ' + column + '=?', (value,))
                self.sql(update)
                self.assertEqual(self.append(a).reason_code, 'CONFLICT')
                self.sql('DROP TRIGGER local_audit_no_update')
                self.sql('UPDATE local_audit_evidence SET ' + column + '=?', (row[index],))
                self.sql(update)

    def test_rehashed_but_wrong_bound_audit_content_denied(self):
        a = self.adapter()
        self.append(a)
        self.sql('DROP TRIGGER local_audit_no_update')
        self.sql('UPDATE local_audit_evidence SET policy_digest=?', (fixtures.M,))
        row = self.sql('SELECT * FROM local_audit_evidence')[0]
        self.sql('UPDATE local_audit_evidence SET evidence_digest=?', (_audit_hash(row[:-1]),))
        self.sql(next(sql for name, _, sql in _SCHEMA if name == 'local_audit_no_update'))
        self.assertEqual(self.append(a).reason_code, 'CONFLICT')

    def test_wrong_tenant_attempt_cannot_replay_existing_audit(self):
        a = self.adapter()
        first = self.append(a)
        self.sql('UPDATE local_attempts SET scope=replace(scope,\'tenant01\',\'tenant02\')')
        self.assertEqual(self.append(a).reason_code, 'CONFLICT')
        self.assertEqual(self.sql('SELECT evidence_digest FROM local_audit_evidence'), [(first.evidence_digest,)])

    def test_new_auditor_cannot_replace_first_bound_record(self):
        self.append()
        g, b = self.options['audit_grant'], self.options['audit_binding']
        other = self.adapter(audit_grant=replace(g, scope=replace(g.scope, identity_id='auditor02')),
                             audit_binding=replace(b, auditor_id='auditor02'))
        self.assertEqual(self.append(other).reason_code, 'CONFLICT')
        self.assertEqual(self.count(), 1)

    def test_schema_missing_trigger_denied_and_not_repaired(self):
        a = self.adapter()
        self.sql('DROP TRIGGER local_audit_no_delete')
        before = self.sql('SELECT * FROM sqlite_master')
        self.assertEqual(self.append(a).reason_code, 'CONFLICT')
        with self.assertRaises(LocalInfrastructureDenied):
            self.adapter()
        self.assertEqual(before, self.sql('SELECT * FROM sqlite_master'))

    def test_hostile_audit_trigger_cannot_mutate_source(self):
        a = self.adapter()
        before = self.sources()
        self.sql('''CREATE TRIGGER hostile AFTER INSERT ON local_audit_evidence
                    BEGIN UPDATE simulated_resource_state SET version=9; END''')
        self.assertEqual(self.append(a).reason_code, 'CONFLICT')
        self.assertEqual(before, self.sources())
        # Exercise the authorizer separately from schema detection.
        with sqlite3.connect(self.path, cached_statements=0) as db:
            db.set_authorizer(_write_authorizer)
            with self.assertRaises(sqlite3.DatabaseError):
                db.execute('INSERT INTO local_audit_evidence SELECT * FROM local_audit_evidence')
        self.assertEqual(before, self.sources())

    def test_hostile_source_trigger_denied_before_provisioning(self):
        self.sql('''CREATE TRIGGER hostile AFTER UPDATE ON local_attempts
                    BEGIN UPDATE simulated_resource_state SET version=9; END''')
        with self.assertRaises(LocalInfrastructureDenied):
            self.adapter()
        self.assertEqual(self.sql("SELECT name FROM sqlite_master WHERE name='local_audit_evidence'"), [])

    def test_replaced_source_view_and_extra_index_denied(self):
        a = self.adapter()
        self.sql('CREATE INDEX unexpected ON local_attempts(scope)')
        self.assertEqual(self.append(a).reason_code, 'CONFLICT')
        self.sql('DROP INDEX unexpected')
        self.sql('ALTER TABLE local_attempts RENAME TO old_attempts')
        self.sql('CREATE VIEW local_attempts AS SELECT * FROM old_attempts')
        self.assertEqual(self.append(a).reason_code, 'CONFLICT')

    def test_audit_extra_column_schema_denied(self):
        a = self.adapter()
        self.sql('ALTER TABLE local_audit_evidence ADD COLUMN extra TEXT')
        self.assertEqual(self.append(a).reason_code, 'CONFLICT')

    def test_bounded_row_capacity_and_replay_at_capacity(self):
        a = self.adapter()
        first = self.append(a)
        row = self.sql('SELECT * FROM local_audit_evidence')[0]
        # Harness-owned filler is not evidence accepted by the public adapter.
        sql = 'INSERT INTO local_audit_evidence VALUES (' + ','.join('?' for _ in row) + ')'
        with sqlite3.connect(self.path) as db:
            for i in range(MAX_RECORDS - 1):
                filler = list(row[:-1])
                filler[0] = 'capacity' + str(i)
                filler[4] = filler[15] = 'sha256:' + format(i, '064x')
                db.execute(sql, (*filler, _audit_hash(filler)))
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute(sql, ('overflow01', *row[1:]))
        self.assertEqual(self.count(), MAX_RECORDS)
        self.assertEqual(self.append(a), replace(first, evidence_kind='HISTORICAL_REPLAY'))

    def test_full_capacity_refuses_new_append_atomically(self):
        a = self.adapter()
        with a._connect() as db:
            db.execute('BEGIN IMMEDIATE')
            registry, attempt, v = a._sources(db)
            row = a._row(registry, attempt, v, '2026-10-19T12:00:00Z')
            sql = 'INSERT INTO local_audit_evidence VALUES (' + ','.join('?' for _ in _COLUMNS) + ')'
            for i in range(MAX_RECORDS):
                filler = list(row)
                filler[0] = 'capacity' + str(i)
                filler[4] = filler[15] = 'sha256:' + format(i, '064x')
                db.execute(sql, (*filler, _audit_hash(filler)))
        before = self.sources()
        self.assertEqual(self.append(a).reason_code, 'CONFLICT')
        self.assertEqual(self.count(), MAX_RECORDS)
        self.assertEqual(before, self.sources())

    def test_missing_database_never_recreated(self):
        a = self.adapter()
        Path(self.path).unlink()
        self.assertEqual(self.append(a).reason_code, 'CONFLICT')
        self.assertFalse(Path(self.path).exists())

    def test_refused_insert_rolls_back_without_source_changes(self):
        a = self.adapter()
        before = self.sources()
        original = _write_authorizer
        def refuse(action, table, column, database, trigger):
            if action == sqlite3.SQLITE_INSERT:
                return sqlite3.SQLITE_DENY
            return original(action, table, column, database, trigger)
        with patch('avuhz_runtime.local_infrastructure_audit._write_authorizer', refuse):
            self.assertEqual(self.append(a).reason_code, 'CONFLICT')
        self.assertEqual(self.count(), 0)
        self.assertEqual(before, self.sources())
        self.assertEqual(self.append(a).reason_code, 'AUDIT_RECORDED')

    def test_failed_commit_never_returns_recorded_and_retry_is_safe(self):
        a = self.adapter()
        before = self.sources()
        original = _write_authorizer
        def refuse(action, table, column, database, trigger):
            if action == sqlite3.SQLITE_TRANSACTION and table == 'COMMIT':
                return sqlite3.SQLITE_DENY
            return original(action, table, column, database, trigger)
        with patch('avuhz_runtime.local_infrastructure_audit._write_authorizer', refuse):
            self.assertEqual(self.append(a).reason_code, 'CONFLICT')
        self.assertEqual(self.count(), 0)
        self.assertEqual(before, self.sources())
        self.assertEqual(self.append(a).reason_code, 'AUDIT_RECORDED')

    def test_lost_commit_ack_returns_conflict_then_replays_durable_row(self):
        a = self.adapter()
        before = self.sources()
        connect = a._connect
        class LostAck:
            def __init__(self):
                self.db = connect()
            def __getattr__(self, key):
                return getattr(self.db, key)
            def __enter__(self):
                self.db.__enter__()
                return self
            def __exit__(self, kind, value, trace):
                self.db.__exit__(kind, value, trace)
                if kind is None:
                    raise sqlite3.OperationalError('FICTIONAL_COMMIT_ACK_LOST')
        with patch.object(LocalTestInfrastructureAudit, '_connect', side_effect=LostAck):
            self.assertEqual(self.append(a).reason_code, 'CONFLICT')
        self.assertEqual(self.count(), 1)
        self.assertEqual(self.append(a).evidence_kind, 'HISTORICAL_REPLAY')
        self.assertEqual(before, self.sources())

    def test_writer_lock_timeout_is_bounded_and_retry_safe(self):
        a = self.adapter()
        with sqlite3.connect(self.path, isolation_level=None) as db:
            db.execute('BEGIN IMMEDIATE')
            with ThreadPoolExecutor(max_workers=1) as pool:
                r = pool.submit(self.append, a).result(timeout=10)
                self.assertEqual(r.reason_code, 'CONFLICT')
            db.execute('ROLLBACK')
        self.assertEqual(self.count(), 0)
        self.assertEqual(self.append(a).reason_code, 'AUDIT_RECORDED')

    def test_revocation_serialized_before_waiting_append(self):
        a = self.adapter()
        before = self.sources()
        with ThreadPoolExecutor(max_workers=1) as pool:
            with sqlite3.connect(self.path, isolation_level=None) as db:
                db.execute('BEGIN IMMEDIATE')
                future = pool.submit(self.append, a)
                db.execute('UPDATE execution_registry SET revoked=1')
                db.execute('COMMIT')
            self.assertEqual(future.result(timeout=10).reason_code, 'CONFLICT')
        self.assertEqual(self.count(), 0)
        self.assertEqual(before[1:], self.sources()[1:])

    def test_errors_are_bounded_without_exception_payload(self):
        a = self.adapter()
        with patch.object(LocalTestInfrastructureAudit, '_connect', side_effect=sqlite3.OperationalError('FICTIONAL_RAW_ERROR')):
            r = self.append(a)
        self.assertEqual(r.reason_code, 'CONFLICT')
        self.assertNotIn('FICTIONAL_RAW_ERROR', repr(r))

    def test_full_synchronous_on_each_connection(self):
        a = self.adapter()
        with a._connect() as db:
            self.assertEqual(db.execute('PRAGMA synchronous').fetchone(), (2,))
            self.assertEqual(db.execute('PRAGMA trusted_schema').fetchone(), (0,))
        self.assertEqual(self.append(a).reason_code, 'AUDIT_RECORDED')


if __name__ == '__main__':
    unittest.main()
