"""Adversarial disposable LOCAL/TEST reconciliation; no network or providers."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, asdict, fields, replace
from datetime import timedelta
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from avuhz_runtime.local_infrastructure_authority import LocalInfrastructureDenied
from avuhz_runtime.local_infrastructure_recovery import (
    LocalTestInfrastructureRecovery, RecoveryConsent, RecoveryGrant,
    RecoveryObservation, RecoveryResult, recovery_intent_digest, _write_authorizer,
    open_recovery_case, collect_recovery_observation, _observer_authorizer,
    _observation_digest, _OBSERVATION_SCHEMA,
)
from avuhz_runtime.local_infrastructure_audit import LocalTestInfrastructureAudit
from avuhz_runtime.local_infrastructure_execution import (
    LocalTestInfrastructureExecution, SimulatedState, TestFailures, _approval_digest,
)
from avuhz_runtime.local_infrastructure_verification import LocalTestInfrastructureVerification
from tests.architecture import test_local_infrastructure_audit_v1 as audit
from tests.architecture import test_local_infrastructure_verification_v1 as verification
from tests.architecture import test_local_infrastructure_trust_v1 as fixtures


def options(path, *, flags=None, state=None, recovery_at=None):
    # Coherent historical consent follows the original source observation.
    original = verification.verifier_options(path)
    approval = replace(original['execution_approval'], diagnostic=replace(
        original['execution_approval'].diagnostic, issued_at=fixtures.NOW - timedelta(seconds=1)))
    policy_sources = dict(original['policy_sources'], approvals=(approval.diagnostic,))
    executor = LocalTestInfrastructureExecution(database_path=path, policy_sources=policy_sources,
        execution_approval=approval, initial_state=SimulatedState(approval.diagnostic.pins.manifest.scope, fixtures.C, 2),
        failures=TestFailures(**(flags or {})))
    wire = fixtures.LocalInfrastructureTrustTests()
    wire.setUp()
    executor.execute(wire.request, principal_handle=executor.principal_handle, execution_handle=executor.execution_handle)
    if state is not None:
        with sqlite3.connect(path) as db:
            db.execute('UPDATE simulated_resource_state SET digest=?,version=?', state)
    original.update(execution_approval=approval, policy_sources=policy_sources,
        verification_binding=replace(original['verification_binding'], execution_digest=_approval_digest(approval)))
    verifier = LocalTestInfrastructureVerification(**original)
    verifier.verify(verifier_handle=verifier.verifier_handle, binding_handle=verifier.binding_handle)
    sources = audit.audit_options(path, original)
    adapter = LocalTestInfrastructureAudit(**sources)
    result = adapter.append(auditor_handle=adapter.auditor_handle, binding_handle=adapter.binding_handle)
    assert result.reason_code == 'AUDIT_RECORDED'
    now = recovery_at or fixtures.NOW + timedelta(seconds=1)
    clock = replace(sources['clock'], now=now, issued_at=now, expires_at=now + timedelta(seconds=120))
    case = open_recovery_case(audit_sources=sources, audit_digest=result.evidence_digest,
        case_id='recoverycase01', challenge='recoverychallenge01', clock=clock)
    scope = sources['audit_binding'].scope
    with sqlite3.connect(path) as db:
        digest, version = db.execute('SELECT digest,version FROM simulated_resource_state').fetchone()
        outcome = db.execute('SELECT outcome FROM local_attempts').fetchone()[0]
    decision = ('REVIEW_REQUIRED' if outcome == 'UNCERTAIN'
                else 'NO_RETRY_AUTHORIZED' if (digest, version) == (fixtures.D, 3)
                else 'HOLD' if (digest, version) == (fixtures.C, 2) else 'REVIEW_REQUIRED')
    observer = RecoveryGrant(replace(scope, identity_id='recoveryobserver01'), 'OBSERVER',
                             'OBSERVE_FICTIONAL_RECOVERY', 'ACTIVE', now, clock.expires_at)
    human = RecoveryGrant(replace(scope, identity_id='recoveryhuman01'), 'HUMAN',
                          'RECORD_FICTIONAL_RECOVERY', 'ACTIVE', now, clock.expires_at)
    observation = collect_recovery_observation(audit_sources=sources, case=case,
        observer_grant=observer, observation_id='recoveryobservation01',
        clock=replace(clock, now=now + timedelta(seconds=1)))
    intent = recovery_intent_digest(case=case, audit_digest=result.evidence_digest, observation=observation,
                                    observer_grant=observer, human_grant=human, decision=decision)
    consent = RecoveryConsent('recoveryauthorization01', 1, 'recoveryhuman01', intent,
                                          decision, 'ACTIVE', now + timedelta(seconds=2), clock.expires_at)
    return dict(audit_sources=sources, case=case, clock=replace(clock, now=now + timedelta(seconds=3)),
                observation=observation, observer_grant=observer,
                human_grant=human, authorization=consent, audit_digest=result.evidence_digest)


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='avuhz-recovery-', dir='/tmp')
        self.addCleanup(self.tmp.cleanup)
        self.path = str(Path(self.tmp.name) / 'recovery.sqlite')
        self.options = options(self.path)

    def adapter(self, **changes):
        return LocalTestInfrastructureRecovery(**dict(self.options, **changes))

    def reconcile(self, a=None, **handles):
        a = self.adapter() if a is None else a
        return a.reconcile(**dict(observer_handle=a.observer_handle,
                                  authorization_handle=a.authorization_handle, **handles))

    def sql(self, sql, args=()):
        with sqlite3.connect(self.path) as db:
            return db.execute(sql, args).fetchall()

    def sources(self):
        return tuple(self.sql('SELECT * FROM ' + table) for table in (
            'execution_registry', 'local_attempts', 'simulated_resource_state',
            'local_verification_evidence', 'local_audit_evidence',
            'local_recovery_cases', 'local_recovery_observations'))

    def repin(self, **changes):
        result = dict(self.options, **changes)
        a = result['authorization']
        result['authorization'] = replace(a, intent_digest=recovery_intent_digest(
            case=result['case'], audit_digest=result['audit_digest'], observation=result['observation'],
            observer_grant=result['observer_grant'], human_grant=result['human_grant'], decision=a.decision))
        return result

    def test_terminal_replay_restart_and_source_preservation(self):
        before = self.sources()
        a = self.adapter()
        with patch.object(LocalTestInfrastructureExecution, 'execute', side_effect=AssertionError), \
             patch.object(LocalTestInfrastructureVerification, 'verify', side_effect=AssertionError), \
             patch.object(LocalTestInfrastructureAudit, 'append', side_effect=AssertionError):
            first = self.reconcile(a)
            replay = self.reconcile(a)
            reopened = self.reconcile()
        self.assertEqual((first.reason_code, first.decision, first.evidence_kind),
                         ('RECOVERY_RECORDED', 'NO_RETRY_AUTHORIZED', 'SYNTHETIC_LOCAL_RECORD'))
        self.assertEqual(replay.evidence_kind, 'HISTORICAL_REPLAY')
        self.assertEqual(first.evidence_digest, reopened.evidence_digest)
        self.assertEqual(before, self.sources())
        self.assertFalse(first.retry_authorized)
        self.assertEqual(first.authority_effect, 'NONE')
        self.assertEqual(self.sql('SELECT count(*) FROM local_recovery_decisions'), [(1,)])

    def test_dispositions_and_uncertain_matching_state(self):
        for i, flags, state, expected in (
                (1, {'crash_after_reservation': True}, None, 'HOLD'),
                (2, {'lost_ack': True}, None, 'REVIEW_REQUIRED'),
                (3, {}, (fixtures.M, 9), 'REVIEW_REQUIRED')):
            with self.subTest(expected=expected):
                path = str(Path(self.tmp.name) / f'case{i}.sqlite')
                a = LocalTestInfrastructureRecovery(**options(path, flags=flags, state=state))
                r = self.reconcile(a)
                self.assertEqual(r.decision, expected)
                self.assertFalse(r.retry_authorized)

    def test_opaque_handles_and_no_injected_request_interface(self):
        a, b = self.adapter(), self.adapter()
        for observer, human in ((object(), a.authorization_handle),
                                (a.observer_handle, b.authorization_handle),
                                (a.authorization_handle, a.observer_handle)):
            r = a.reconcile(observer_handle=observer, authorization_handle=human)
            self.assertEqual(r.reason_code, 'AUTHORIZATION_DENIED')
            self.assertFalse(r.retry_authorized)
        with self.assertRaises(TypeError):
            a.reconcile(observer_handle=a.observer_handle, authorization_handle=a.authorization_handle, retry=True)

    def test_all_scope_dimensions_bound_even_with_recomputed_intent(self):
        o = self.options['observation']
        for f in fields(o.scope):
            value = 'LOCAL' if f.name == 'environment' else 'other01'
            with self.subTest(field=f.name), self.assertRaises(LocalInfrastructureDenied):
                self.adapter(**self.repin(observation=replace(o, scope=replace(o.scope, **{f.name: value}))))

    def test_separation_from_every_prior_identity(self):
        for identity in ('principal01', 'observer01', 'fictional.human01', 'fictional.executor01', 'verifier01', 'auditor01'):
            o, g = self.options['observation'], self.options['observer_grant']
            with self.subTest(identity=identity), self.assertRaises(LocalInfrastructureDenied):
                self.adapter(**self.repin(observation=replace(o, observer_id=identity),
                    observer_grant=replace(g, scope=replace(g.scope, identity_id=identity))))
        g = self.options['human_grant']
        with self.assertRaises(LocalInfrastructureDenied):
            self.adapter(**self.repin(human_grant=replace(g, scope=self.options['observer_grant'].scope),
                authorization=replace(self.options['authorization'], human_id='recoveryobserver01')))

    def test_stale_future_pre_audit_and_missing_observation(self):
        o = self.options['observation']
        for when in (fixtures.NOW, fixtures.NOW - timedelta(seconds=61), fixtures.NOW + timedelta(seconds=5)):
            with self.subTest(when=when), self.assertRaises(LocalInfrastructureDenied):
                self.adapter(**self.repin(observation=replace(o, observed_at=when)))
        with self.assertRaises(LocalInfrastructureDenied):
            self.adapter(observation=None)

    def test_human_observer_and_authorization_revocation_expiry(self):
        for key in ('observer_grant', 'human_grant', 'authorization'):
            for changes in ({'status': 'REVOKED'}, {'expires_at': fixtures.NOW}):
                with self.subTest(key=key, changes=changes), self.assertRaises(LocalInfrastructureDenied):
                    self.adapter(**self.repin(**{key: replace(self.options[key], **changes)}))

    def test_no_reused_approval_or_forged_pins_or_decision(self):
        a = self.options['authorization']
        for changed in (replace(a, intent_digest=fixtures.M), replace(a, authorization_version=True),
                        replace(a, decision='RETRY'), self.options['audit_sources']['execution_approval']):
            with self.subTest(changed=type(changed)), self.assertRaises(LocalInfrastructureDenied):
                self.adapter(authorization=changed)
        with self.assertRaises(LocalInfrastructureDenied):
            self.adapter(**self.repin(authorization=replace(a, decision='HOLD')))
        with self.assertRaises(LocalInfrastructureDenied):
            self.adapter(**self.repin(audit_digest=fixtures.M))

    def test_delayed_original_effect_after_observation_remains_possible(self):
        a = self.adapter()
        self.sql('UPDATE simulated_resource_state SET version=77')
        before = self.sources()
        self.assertEqual(self.reconcile(a).reason_code, 'RECOVERY_RECORDED')
        self.assertEqual(before, self.sources())
        self.assertEqual(self.sql('SELECT count(*) FROM local_recovery_decisions'), [(1,)])

    def test_missing_or_changed_predecessors_fail_closed(self):
        a = self.adapter()
        self.sql('UPDATE execution_registry SET consumed=0')
        self.assertEqual(self.reconcile(a).reason_code, 'CONFLICT')
        with self.assertRaises(LocalInfrastructureDenied):
            self.adapter()

    def test_terminal_rows_cannot_update_delete_or_replace(self):
        self.reconcile()
        for sql in ('UPDATE local_recovery_decisions SET retry_authorized=1',
                    'DELETE FROM local_recovery_decisions',
                    'INSERT OR REPLACE INTO local_recovery_decisions SELECT * FROM local_recovery_decisions'):
            with self.subTest(sql=sql), self.assertRaises(sqlite3.DatabaseError):
                self.sql(sql)

    def test_new_authorization_cannot_replace_terminal_history(self):
        self.reconcile()
        changed = replace(self.options['authorization'], authorization_id='newauthorization01')
        a = self.adapter(authorization=changed)
        self.assertEqual(self.reconcile(a).reason_code, 'CONFLICT')
        self.assertEqual(self.sql('SELECT count(*) FROM local_recovery_decisions'), [(1,)])

    def test_schema_trigger_and_source_write_defense(self):
        a = self.adapter()
        self.sql("CREATE TRIGGER hostile AFTER INSERT ON local_recovery_decisions BEGIN UPDATE execution_registry SET consumed=0; END")
        before = self.sources()
        self.assertEqual(self.reconcile(a).reason_code, 'CONFLICT')
        self.assertEqual(before, self.sources())
        with sqlite3.connect(self.path) as db:
            db.set_authorizer(_write_authorizer)
            for sql in ('UPDATE execution_registry SET consumed=0', 'DELETE FROM local_attempts',
                        "ATTACH DATABASE ':memory:' AS extra", 'DROP TABLE simulated_resource_state'):
                with self.subTest(sql=sql), self.assertRaises(sqlite3.DatabaseError):
                    db.execute(sql)

    def test_concurrent_calls_have_one_immutable_record(self):
        a = self.adapter()
        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(lambda _: self.reconcile(a), range(12)))
        self.assertEqual({r.reason_code for r in results}, {'RECOVERY_RECORDED'})
        self.assertEqual(len({r.evidence_digest for r in results}), 1)
        self.assertEqual(sum(r.evidence_kind == 'SYNTHETIC_LOCAL_RECORD' for r in results), 1)

    def test_no_success_on_commit_failure(self):
        a = self.adapter()
        class FailedCommit(sqlite3.Connection):
            def __exit__(self, *args):
                self.rollback()
                raise sqlite3.OperationalError('fixture')
        def connect(instance):
            db = sqlite3.connect(instance._path, factory=FailedCommit, isolation_level=None)
            db.execute('PRAGMA synchronous=FULL')
            return db
        with patch.object(LocalTestInfrastructureAudit, '_connect', connect):
            r = self.reconcile(a)
        self.assertEqual(r.reason_code, 'CONFLICT')
        self.assertFalse(r.retry_authorized)
        self.assertEqual(self.sql('SELECT count(*) FROM local_recovery_decisions'), [(0,)])

    def test_insert_failure_does_not_report_success(self):
        a = self.adapter()
        class FailedInsert(sqlite3.Connection):
            def execute(self, statement, *args):
                if statement.startswith('INSERT INTO local_recovery_decisions'):
                    raise sqlite3.OperationalError('fixture')
                return super().execute(statement, *args)
        def connect(instance):
            db = sqlite3.connect(instance._path, factory=FailedInsert, isolation_level=None)
            db.execute('PRAGMA synchronous=FULL')
            return db
        with patch.object(LocalTestInfrastructureAudit, '_connect', connect):
            self.assertEqual(self.reconcile(a).reason_code, 'CONFLICT')
        self.assertEqual(self.sql('SELECT count(*) FROM local_recovery_decisions'), [(0,)])

    def test_replay_requires_fresh_evidence_and_does_not_refresh_history(self):
        first = self.reconcile()
        before = self.sql('SELECT * FROM local_recovery_decisions')
        with self.assertRaises(LocalInfrastructureDenied):
            self.adapter(clock=replace(self.options['clock'], now=fixtures.NOW + timedelta(seconds=80)))
        self.assertEqual(before, self.sql('SELECT * FROM local_recovery_decisions'))
        self.assertFalse(first.retry_authorized)

    def test_authorization_cannot_predate_fresh_observation(self):
        a = replace(self.options['authorization'], issued_at=fixtures.NOW)
        with self.assertRaises(LocalInfrastructureDenied):
            self.adapter(authorization=a)

    def test_missing_audit_and_verification_are_not_recreated(self):
        for i, table, trigger in ((1, 'local_audit_evidence', 'local_audit_no_delete'),
                                  (2, 'local_verification_evidence', 'local_verification_no_delete')):
            with self.subTest(table=table):
                path = str(Path(self.tmp.name) / f'missing{i}.sqlite')
                config = options(path)
                with sqlite3.connect(path) as db:
                    db.execute('DROP TRIGGER ' + trigger)
                    db.execute('DELETE FROM ' + table)
                with self.assertRaises(LocalInfrastructureDenied):
                    LocalTestInfrastructureRecovery(**config)
                with sqlite3.connect(path) as db:
                    self.assertEqual(db.execute('SELECT count(*) FROM ' + table).fetchone(), (0,))
                    self.assertIsNone(db.execute("SELECT 1 FROM sqlite_master WHERE name='local_recovery_decisions'").fetchone())

    def test_original_policy_and_approval_are_bound(self):
        sources = self.options['audit_sources']
        for key in ('policies', 'approvals'):
            original = sources['policy_sources'][key][0]
            for changed in (replace(original, policy_version=2),
                            replace(original, decision='DENY')):
                policy = dict(sources['policy_sources'], **{key: (changed,)})
                with self.subTest(key=key), self.assertRaises(LocalInfrastructureDenied):
                    self.adapter(audit_sources=dict(sources, policy_sources=policy))

    def test_expired_original_authority_does_not_authorize_recovery(self):
        path = str(Path(self.tmp.name) / 'expired.sqlite')
        config = options(path, recovery_at=fixtures.NOW + timedelta(seconds=200))
        self.assertLess(config['audit_sources']['execution_approval'].diagnostic.expires_at,
                        config['clock'].now)
        candidate = LocalTestInfrastructureRecovery(**config)
        self.assertEqual(self.reconcile(candidate).reason_code, 'RECOVERY_RECORDED')
        for key in ('observer_grant', 'human_grant', 'authorization'):
            revoked = dict(config, **{key: replace(config[key], status='REVOKED')})
            with self.subTest(key=key), self.assertRaises(LocalInfrastructureDenied):
                LocalTestInfrastructureRecovery(**revoked)
        with sqlite3.connect(path) as db:
            db.execute('UPDATE execution_registry SET revoked=1')
        self.assertEqual(self.reconcile(candidate).reason_code, 'CONFLICT')

    def test_case_and_fresh_evidence_must_be_durably_registered(self):
        case, o = self.options['case'], self.options['observation']
        for changed in (replace(case, case_id='fabricated01'),
                        replace(case, challenge='fabricated01'),
                        replace(case, opened_at=o.observed_at)):
            with self.subTest(case=changed.case_id), self.assertRaises(LocalInfrastructureDenied):
                self.adapter(**self.repin(case=changed))
        for changed in (replace(o, observation_id='fabricated01'),
                        replace(o, observed_version=99),
                        replace(o, observed_at=case.opened_at)):
            with self.subTest(observation=changed.observation_id), self.assertRaises(LocalInfrastructureDenied):
                self.adapter(**self.repin(observation=changed))
        self.sql('DROP TRIGGER local_recovery_observations_delete')
        self.sql('DELETE FROM local_recovery_observations')
        self.sql(next(sql for name, _, sql in _OBSERVATION_SCHEMA if name.endswith('_delete')))
        with self.assertRaises(LocalInfrastructureDenied):
            self.adapter()
        self.assertEqual(self.sql('SELECT count(*) FROM local_recovery_observations'), [(0,)])

    def test_collection_before_case_and_executor_observer_overlap_denied(self):
        config = self.options
        for clock, grant in (
                (replace(config['clock'], now=config['case'].opened_at), config['observer_grant']),
                (config['clock'], replace(config['observer_grant'], scope=replace(
                    config['case'].scope, identity_id='fictional.executor01')))):
            with self.subTest(grant=grant.scope.identity_id), self.assertRaises(LocalInfrastructureDenied):
                collect_recovery_observation(audit_sources=config['audit_sources'], case=config['case'],
                    observer_grant=grant, observation_id='another01', clock=clock)

    def test_changed_human_digest_and_cross_tenant_case_denied(self):
        with self.assertRaises(LocalInfrastructureDenied):
            self.adapter(authorization=replace(self.options['authorization'], intent_digest=fixtures.M))
        case = self.options['case']
        with self.assertRaises(LocalInfrastructureDenied):
            self.adapter(**self.repin(case=replace(case, scope=replace(case.scope, tenant_id='tenant02'))))

    def test_coherent_observation_rehash_does_not_change_human_pin(self):
        candidate = self.adapter()
        self.sql('DROP TRIGGER local_recovery_observations_update')
        self.sql('UPDATE local_recovery_observations SET observed_version=99')
        row = self.sql('SELECT * FROM local_recovery_observations')[0]
        self.sql('UPDATE local_recovery_observations SET evidence_digest=?', (_observation_digest(row[:-1]),))
        self.sql(next(sql for name, _, sql in _OBSERVATION_SCHEMA if name.endswith('_update')))
        self.assertEqual(self.reconcile(candidate).reason_code, 'CONFLICT')
        with self.assertRaises(LocalInfrastructureDenied):
            self.adapter(observation=replace(self.options['observation'], observed_version=99))

    def test_coherent_original_audit_tamper_still_breaks_case_pin(self):
        candidate = self.adapter()
        self.sql('DROP TRIGGER local_audit_no_update')
        self.sql('UPDATE local_audit_evidence SET policy_digest=?', (fixtures.M,))
        row = self.sql('SELECT * FROM local_audit_evidence')[0]
        self.sql('UPDATE local_audit_evidence SET evidence_digest=?', (audit._audit_hash(row[:-1]),))
        self.sql(next(sql for name, _, sql in audit._SCHEMA if name == 'local_audit_no_update'))
        self.assertEqual(self.reconcile(candidate).reason_code, 'CONFLICT')
        with self.assertRaises(LocalInfrastructureDenied):
            self.adapter(**self.repin(audit_digest=audit._audit_hash(row[:-1])))

    def test_recovery_cannot_read_physical_state_or_write_observer_evidence(self):
        candidate = self.adapter()
        statements = []
        connect = LocalTestInfrastructureAudit._connect
        def traced(instance):
            db = connect(instance)
            db.set_trace_callback(statements.append)
            return db
        with patch.object(LocalTestInfrastructureAudit, '_connect', traced):
            self.assertEqual(self.reconcile(candidate).reason_code, 'RECOVERY_RECORDED')
        self.assertFalse(any('FROM simulated_resource_state' in sql for sql in statements))
        with sqlite3.connect(self.path, cached_statements=0) as db:
            db.set_authorizer(_write_authorizer)
            for statement in ('SELECT * FROM simulated_resource_state',
                              'INSERT INTO local_recovery_observations SELECT * FROM local_recovery_observations',
                              'INSERT INTO local_recovery_cases SELECT * FROM local_recovery_cases'):
                with self.subTest(statement=statement), self.assertRaises(sqlite3.DatabaseError):
                    db.execute(statement)
        with sqlite3.connect(self.path, cached_statements=0) as db:
            db.set_authorizer(_observer_authorizer)
            for statement in ('INSERT INTO local_recovery_decisions SELECT * FROM local_recovery_decisions',
                              'UPDATE simulated_resource_state SET version=9'):
                with self.subTest(statement=statement), self.assertRaises(sqlite3.DatabaseError):
                    db.execute(statement)

    def test_case_and_observation_update_delete_replace_denied(self):
        for table in ('local_recovery_cases', 'local_recovery_observations'):
            for statement in ('UPDATE ' + table + ' SET scope=scope', 'DELETE FROM ' + table,
                              'INSERT OR REPLACE INTO ' + table + ' SELECT * FROM ' + table):
                with self.subTest(statement=statement), self.assertRaises(sqlite3.DatabaseError):
                    self.sql(statement)

    def test_lost_commit_ack_returns_conflict_then_durable_replay(self):
        candidate = self.adapter()
        connect = candidate._audit._connect
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
            self.assertEqual(self.reconcile(candidate).reason_code, 'CONFLICT')
        self.assertEqual(self.sql('SELECT count(*) FROM local_recovery_decisions'), [(1,)])
        self.assertEqual(self.reconcile(candidate).evidence_kind, 'HISTORICAL_REPLAY')

    def test_frozen_results_and_registration(self):
        a = self.adapter()
        with self.assertRaises(FrozenInstanceError):
            a._audit_digest = fixtures.M
        with self.assertRaises(FrozenInstanceError):
            RecoveryResult('CONFLICT').retry_authorized = True
        with self.assertRaises(TypeError):
            RecoveryResult('CONFLICT', retry_authorized=True)
        with self.assertRaises(LocalInfrastructureDenied):
            a.__init__(**self.options)


if __name__ == '__main__':
    unittest.main()
