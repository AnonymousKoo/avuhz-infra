"""Sole-engineer offline tests of independent synthetic poststate observation."""
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from dataclasses import FrozenInstanceError, replace
from datetime import timedelta
import multiprocessing
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from avuhz_runtime.local_infrastructure_authority import LocalInfrastructureDenied
from avuhz_runtime.local_infrastructure_execution import (
    ExecutionApproval, LocalTestInfrastructureExecution, TestFailures, _approval_digest,
)
from avuhz_runtime.local_infrastructure_policy import LocalTestInfrastructurePolicyAdapter
from avuhz_runtime.local_infrastructure_trust import LocalTrustAdapter
from avuhz_runtime.local_infrastructure_verification import (
    LocalTestInfrastructureVerification, VerificationBinding, VerifierGrant,
    _UPDATE, _write_authorizer,
)
from tests.architecture import test_local_infrastructure_execution_v1 as execution
from tests.architecture import test_local_infrastructure_policy_v1 as policy
from tests.architecture import test_local_infrastructure_trust_v1 as fixtures


def verifier_options(path):
    # Independently provisioned fixture, not execution result or executor fields.
    base = policy.PolicyTests()
    base.setUp()
    approval = ExecutionApproval('execution01', 1, base.approval, 'APPLY_FICTIONAL_STATE', 'ACTIVE')
    grant = VerifierGrant('verifiergrant01', 1, replace(base.scope, identity_id='verifier01'),
                          'VERIFIER', 'OBSERVE_FICTIONAL_POSTSTATE', 'ACTIVE', fixtures.START, fixtures.END)
    binding = VerificationBinding(base.scope, 'execution01', 1, _approval_digest(approval),
                                  'verifier01', 'verifiergrant01', 1)
    return dict(database_path=path, policy_sources=base.config, execution_approval=approval,
                verifier_grant=grant, verification_binding=binding, clock=base.sources['clock'])


def observe_process(path):
    v = LocalTestInfrastructureVerification(**verifier_options(path))
    r = v.verify(verifier_handle=v.verifier_handle, binding_handle=v.binding_handle)
    return r.reason_code, r.observation_kind, r.evidence_digest


class VerificationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='avuhz-3a-', dir='/tmp')
        self.addCleanup(self.tmp.cleanup)
        self.path = str(Path(self.tmp.name) / 'fictional.sqlite')
        self.executor, self.base = execution.provision(self.path)
        self.options = verifier_options(self.path)

    def adapter(self, **changes):
        return LocalTestInfrastructureVerification(**{**self.options, **changes})

    def effect(self, **flags):
        a = self.executor if not flags else execution.provision(
            self.path, failures=TestFailures(**flags))[0]
        return a.execute(self.base.request, principal_handle=a.principal_handle,
                         execution_handle=a.execution_handle)

    def observe(self, adapter=None, **changes):
        v = adapter if adapter is not None else self.adapter()
        return v.verify(**dict(verifier_handle=v.verifier_handle,
                               binding_handle=v.binding_handle, **changes))

    def sql(self, statement, args=()):
        with sqlite3.connect(self.path) as db:
            return db.execute(statement, args).fetchall()

    def source_rows(self):
        return tuple(self.sql(s) for s in (
            'SELECT * FROM execution_registry', 'SELECT * FROM local_attempts',
            'SELECT * FROM simulated_resource_state'))

    def count(self):
        return self.sql('SELECT count(*) FROM local_verification_evidence')[0][0]

    def test_desired_match_after_attempted_change(self):
        self.assertEqual(self.effect().reason_code, 'ATTEMPTED')
        r = self.observe()
        self.assertEqual((r.reason_code, r.observed_digest, r.observed_version),
                         ('LOCAL_STATE_MATCH', fixtures.D, 3))
        self.assertEqual((r.observation_kind, r.authority_effect), ('SYNTHETIC_LOCAL_SNAPSHOT', 'NONE'))
        self.assertEqual(self.count(), 1)

    def test_lost_ack_uncertain_can_observe_match(self):
        self.assertEqual(self.effect(lost_ack=True).reason_code, 'UNCERTAIN')
        self.assertEqual(self.observe().reason_code, 'LOCAL_STATE_MATCH')
        self.assertEqual(self.sql('SELECT outcome FROM local_attempts'), [('UNCERTAIN',)])

    def test_crash_pre_effect_pending(self):
        self.effect(crash_after_reservation=True)
        self.assertEqual(self.observe().reason_code, 'PENDING')

    def test_failed_effect_pending(self):
        self.effect(effect_write_failure=True)
        self.assertEqual(self.observe().reason_code, 'PENDING')

    def test_wrong_digest_mismatch(self):
        self.effect()
        self.sql('UPDATE simulated_resource_state SET digest=?', (fixtures.M,))
        self.assertEqual(self.observe().reason_code, 'MISMATCH')

    def test_wrong_version_mismatch(self):
        self.effect()
        self.sql('UPDATE simulated_resource_state SET version=4')
        self.assertEqual(self.observe().reason_code, 'MISMATCH')

    def test_no_attempt_denied_even_if_desired_present(self):
        self.sql('UPDATE simulated_resource_state SET digest=?,version=3', (fixtures.D,))
        self.assertEqual(self.observe().reason_code, 'CONFLICT')
        self.assertEqual(self.count(), 0)

    def test_pending_never_upgraded(self):
        self.effect(crash_after_reservation=True)
        v = self.adapter()
        first = self.observe(v)
        self.sql('UPDATE simulated_resource_state SET digest=?,version=3', (fixtures.D,))
        later = self.observe(v)
        self.assertEqual((later.reason_code, later.observation_kind), ('PENDING', 'HISTORICAL'))
        self.assertEqual(first.evidence_digest, later.evidence_digest)

    def test_mismatch_never_upgraded(self):
        self.effect()
        self.sql('UPDATE simulated_resource_state SET version=4')
        first = self.observe()
        self.sql('UPDATE simulated_resource_state SET version=3')
        later = self.observe()
        self.assertEqual((later.reason_code, later.observation_kind), ('MISMATCH', 'HISTORICAL'))
        self.assertEqual(first.evidence_digest, later.evidence_digest)

    def test_match_replay_is_historical_after_state_changes(self):
        self.effect()
        v = self.adapter()
        first = self.observe(v)
        self.sql('UPDATE simulated_resource_state SET digest=?,version=9', (fixtures.C,))
        for _ in range(3):
            later = self.observe(v)
            self.assertEqual((later.reason_code, later.observation_kind, later.observed_version),
                             ('LOCAL_STATE_MATCH', 'HISTORICAL', 3))
            self.assertEqual(first.evidence_digest, later.evidence_digest)
        self.assertEqual(self.count(), 1)

    def test_restart_retains_evidence(self):
        self.effect()
        first = self.observe()
        second = observe_process(self.path)
        self.assertEqual(second, ('LOCAL_STATE_MATCH', 'HISTORICAL', first.evidence_digest))

    def test_physical_and_ledger_state_untouched(self):
        self.effect()
        before = self.source_rows()
        self.observe()
        self.observe()
        self.assertEqual(self.source_rows(), before)

    def test_no_executor_or_old_prestate_callback(self):
        self.effect()
        with patch.object(LocalTestInfrastructureExecution, '_observe', side_effect=AssertionError), \
                patch.object(LocalTestInfrastructureExecution, 'execute', side_effect=AssertionError), \
                patch.object(LocalTestInfrastructurePolicyAdapter, 'review_approval', side_effect=AssertionError), \
                patch.object(LocalTrustAdapter, 'compare', side_effect=AssertionError):
            self.assertEqual(self.observe().reason_code, 'LOCAL_STATE_MATCH')

    def test_expired_prestate_does_not_require_rerun(self):
        self.effect()
        now = fixtures.NOW + timedelta(seconds=90)  # Original observation expires at +60.
        clock = replace(self.options['clock'], now=now)
        self.assertEqual(self.observe(self.adapter(clock=clock)).reason_code, 'LOCAL_STATE_MATCH')

    def test_revoked_verifier_denied(self):
        self.effect()
        v = self.adapter(verifier_grant=replace(self.options['verifier_grant'], status='REVOKED'))
        self.assertEqual(self.observe(v).reason_code, 'AUTHORIZATION_DENIED')
        self.assertEqual(self.count(), 0)

    def test_expired_future_and_overlong_verifier(self):
        self.effect()
        for change in ({'expires_at': fixtures.NOW}, {'issued_at': fixtures.NOW + timedelta(seconds=1)},
                       {'issued_at': fixtures.NOW - timedelta(seconds=301)}):
            with self.subTest(change=change):
                v = self.adapter(verifier_grant=replace(self.options['verifier_grant'], **change))
                self.assertEqual(self.observe(v).reason_code, 'AUTHORIZATION_DENIED')

    def test_expired_clock_denied(self):
        self.effect()
        v = self.adapter(clock=replace(self.options['clock'], now=fixtures.END))
        self.assertEqual(self.observe(v).reason_code, 'AUTHORIZATION_DENIED')

    def test_replay_still_checks_verifier_authority(self):
        self.effect()
        self.observe()
        v = self.adapter(verifier_grant=replace(self.options['verifier_grant'], status='REVOKED'))
        self.assertEqual(self.observe(v).reason_code, 'AUTHORIZATION_DENIED')

    def test_role_capability_closed(self):
        for change in ({'role': 'PRINCIPAL'}, {'capability': 'APPLY_FICTIONAL_STATE'}, {'status': 'UNKNOWN'}):
            with self.assertRaises(LocalInfrastructureDenied):
                self.adapter(verifier_grant=replace(self.options['verifier_grant'], **change))

    def test_identity_overlap_all_four_roles(self):
        for identity in ('principal01', 'observer01', 'fictional.human01', 'fictional.executor01'):
            g, b = self.options['verifier_grant'], self.options['verification_binding']
            with self.subTest(identity=identity), self.assertRaises(LocalInfrastructureDenied):
                self.adapter(verifier_grant=replace(g, scope=replace(g.scope, identity_id=identity)),
                             verification_binding=replace(b, verifier_id=identity))

    def test_scope_dimensions_and_alternate_tenant(self):
        b = self.options['verification_binding']
        for change in ({'tenant_id': 'tenant02'}, {'owner_id': 'owner02'}, {'identity_id': 'other01'},
                       {'environment': 'LOCAL'}, {'environment': 'PRODUCTION'}, {'namespace': 'other.lab'},
                       {'resource_class': 'SERVICE'}, {'resource_id': 'fictional.component02'}):
            with self.subTest(change=change), self.assertRaises(LocalInfrastructureDenied):
                self.adapter(verification_binding=replace(b, scope=replace(b.scope, **change)))

    def test_verifier_scope_cannot_cross_tenant(self):
        g = self.options['verifier_grant']
        with self.assertRaises(LocalInfrastructureDenied):
            self.adapter(verifier_grant=replace(g, scope=replace(g.scope, tenant_id='tenant02')))

    def test_binding_exact_registration(self):
        b = self.options['verification_binding']
        for change in ({'execution_id': 'execution02'}, {'execution_version': 2},
                       {'execution_digest': fixtures.M}, {'grant_version': 2}, {'grant_id': 'grant02'}):
            with self.subTest(change=change), self.assertRaises(LocalInfrastructureDenied):
                self.adapter(verification_binding=replace(b, **change))

    def test_execution_operation_explicit(self):
        a = self.options['execution_approval']
        for operation in ('COMPARE_FICTIONAL_STATE', 'DEPLOY', fixtures.Hostile()):
            with self.assertRaises(LocalInfrastructureDenied):
                self.adapter(execution_approval=replace(a, operation=operation))

    def test_execution_approval_not_diagnostic(self):
        with self.assertRaises(LocalInfrastructureDenied):
            self.adapter(execution_approval=self.base.approval)

    def test_policy_source_mismatch(self):
        config = self.options['policy_sources']
        for change in ({'policies': (replace(self.base.policy, decision='DENY'),)},
                       {'approvals': ()}, {'observations': (replace(self.base.pins.observation,
                                                                   observed_at=fixtures.START),)}):
            with self.assertRaises(LocalInfrastructureDenied):
                self.adapter(policy_sources={**config, **change})

    def test_registry_each_pin_tamper_detected(self):
        self.effect()
        v = self.adapter()
        for column, value in (('execution_version', 2), ('approval_id', 'other01'), ('approval_version', 2),
                              ('request_id', 'other01'), ('challenge', 'other01'), ('scope', '{}'),
                              ('digest', fixtures.M), ('revoked', 1), ('consumed', 0)):
            # Column names are a fixed closed test list.
            old = self.sql('SELECT ' + column + ' FROM execution_registry')[0][0]
            self.sql('UPDATE execution_registry SET ' + column + '=?', (value,))
            self.assertEqual(self.observe(v).reason_code, 'CONFLICT')
            self.sql('UPDATE execution_registry SET ' + column + '=?', (old,))
        self.assertEqual(self.count(), 0)

    def test_attempt_each_pin_tamper_detected(self):
        self.effect()
        v = self.adapter()
        for column, value in (('execution_version', 2), ('approval_id', 'other01'), ('approval_version', 2),
                              ('request_id', 'other01'), ('challenge', 'other01'), ('scope', '{}'),
                              ('digest', fixtures.M)):
            old = self.sql('SELECT ' + column + ' FROM local_attempts')[0][0]
            self.sql('UPDATE local_attempts SET ' + column + '=?', (value,))
            self.assertEqual(self.observe(v).reason_code, 'CONFLICT')
            self.sql('UPDATE local_attempts SET ' + column + '=?', (old,))

    def test_unknown_and_legacy_outcome_denied(self):
        self.effect()
        v = self.adapter()
        for value in ('VERIFIED', 'UNKNOWN'):
            with sqlite3.connect(self.path) as db:
                db.execute('PRAGMA ignore_check_constraints=ON')
                db.execute('UPDATE local_attempts SET outcome=?', (value,))
            self.assertEqual(self.observe(v).reason_code, 'CONFLICT')
            with self.assertRaises(LocalInfrastructureDenied):
                self.adapter()

    def test_missing_state_denied_without_reseed(self):
        self.effect()
        self.sql('DELETE FROM simulated_resource_state')
        self.assertEqual(self.observe().reason_code, 'CONFLICT')
        self.assertEqual(self.sql('SELECT * FROM simulated_resource_state'), [])

    def test_malformed_state_denied(self):
        self.effect()
        v = self.adapter()
        for digest, version in (('bad', 3), (fixtures.D, 0), (fixtures.D, 2147483648)):
            self.sql('UPDATE simulated_resource_state SET digest=?,version=?', (digest, version))
            self.assertEqual(self.observe(v).reason_code, 'CONFLICT')

    def test_missing_database_not_created(self):
        path = str(Path(self.tmp.name) / 'absent.sqlite')
        with self.assertRaises(LocalInfrastructureDenied):
            self.adapter(database_path=path)
        self.assertFalse(Path(path).exists())

    def test_empty_database_no_auto_source_tables(self):
        path = str(Path(self.tmp.name) / 'empty.sqlite')
        sqlite3.connect(path).close()
        with self.assertRaises(LocalInfrastructureDenied):
            self.adapter(database_path=path)
        with sqlite3.connect(path) as db:
            self.assertEqual(db.execute('SELECT name FROM sqlite_master').fetchall(), [])

    def test_startup_missing_table_and_invalid_schema(self):
        self.sql('DROP TABLE local_attempts')
        with self.assertRaises(LocalInfrastructureDenied):
            self.adapter()
        self.sql('CREATE TABLE local_attempts (wrong TEXT)')
        with self.assertRaises(LocalInfrastructureDenied):
            self.adapter()

    def test_existing_evidence_wrong_schema(self):
        self.sql('CREATE TABLE local_verification_evidence (wrong TEXT)')
        with self.assertRaises(LocalInfrastructureDenied):
            self.adapter()

    def test_database_disappears_after_startup(self):
        v = self.adapter()
        Path(self.path).unlink()
        self.assertEqual(self.observe(v).reason_code, 'CONFLICT')
        self.assertFalse(Path(self.path).exists())

    def test_handle_injection_and_hostile_equality(self):
        self.effect()
        v, other = self.adapter(), self.adapter()
        for handle in (object(), fixtures.Hostile(), {}, None, 'verifier01', other.verifier_handle,
                       self.executor.execution_handle, v.binding_handle):
            self.assertEqual(v.verify(verifier_handle=handle, binding_handle=v.binding_handle).reason_code,
                             'CONFLICT')
        self.assertEqual(v.verify(verifier_handle=v.verifier_handle,
                                  binding_handle=fixtures.Hostile()).reason_code, 'CONFLICT')
        self.assertEqual(self.count(), 0)

    def test_hostile_provisioning_primitives(self):
        g = self.options['verifier_grant']
        b = self.options['verification_binding']
        for change in ({'role': fixtures.Hostile()}, {'grant_id': fixtures.Hostile()}, {'grant_version': True}):
            with self.assertRaises(LocalInfrastructureDenied):
                self.adapter(verifier_grant=replace(g, **change))
        with self.assertRaises(LocalInfrastructureDenied):
            self.adapter(verification_binding=replace(b, execution_digest=fixtures.Hostile()))

    def test_no_calltime_claims_results_clock_path_or_state(self):
        v = self.adapter()
        for name in ('request', 'execution_result', 'observed_digest', 'state', 'clock', 'database_path',
                     'verifier_grant', 'verification_binding'):
            with self.assertRaises(TypeError):
                v.verify(verifier_handle=v.verifier_handle, binding_handle=v.binding_handle,
                         **{name: fixtures.Hostile()})

    def test_evidence_sql_immutability_and_uniqueness(self):
        self.effect()
        self.observe()
        for sql in ('DELETE FROM local_verification_evidence',
                    "UPDATE local_verification_evidence SET reason_code='MISMATCH'",
                    'INSERT INTO local_verification_evidence SELECT * FROM local_verification_evidence',
                    'INSERT OR REPLACE INTO local_verification_evidence SELECT * FROM local_verification_evidence'):
            with self.assertRaises(sqlite3.IntegrityError):
                self.sql(sql)

    def test_evidence_tamper_detected_after_recreated_trigger(self):
        self.effect()
        v = self.adapter()
        self.observe(v)
        self.sql('DROP TRIGGER local_verification_no_update')
        self.sql('UPDATE local_verification_evidence SET observed_version=9')
        self.sql(_UPDATE)
        self.assertEqual(self.observe(v).reason_code, 'CONFLICT')
        self.assertEqual(self.observe().reason_code, 'CONFLICT')

    def test_forged_evidence_hash_and_source_denied(self):
        self.effect()
        v = self.adapter()
        self.observe(v)
        self.sql('DROP TRIGGER local_verification_no_update')
        self.sql('UPDATE local_verification_evidence SET source_digest=?,evidence_digest=?',
                 (fixtures.M, fixtures.M))
        self.sql(_UPDATE)
        self.assertEqual(self.observe(v).reason_code, 'CONFLICT')

    def test_removed_immutability_trigger_conflict(self):
        self.effect()
        v = self.adapter()
        self.sql('DROP TRIGGER local_verification_no_delete')
        self.assertEqual(self.observe(v).reason_code, 'CONFLICT')

    def test_evidence_write_failure_returns_no_match(self):
        self.effect()
        v = self.adapter()
        original = _write_authorizer
        def refuse(action, table, *args):
            if action == sqlite3.SQLITE_INSERT:
                return sqlite3.SQLITE_DENY
            return original(action, table, *args)
        with patch('avuhz_runtime.local_infrastructure_verification._write_authorizer', refuse):
            self.assertEqual(self.observe(v).reason_code, 'CONFLICT')
        self.assertEqual(self.count(), 0)

    def test_malicious_evidence_trigger_cannot_change_physical_state(self):
        self.effect()
        v = self.adapter()
        before = self.source_rows()
        self.sql('CREATE TRIGGER extra AFTER INSERT ON local_verification_evidence '
                 'BEGIN UPDATE simulated_resource_state SET version=99; END')
        self.assertEqual(self.observe(v).reason_code, 'CONFLICT')
        self.assertEqual(self.source_rows(), before)

    def test_readonly_connection_observes_snapshot(self):
        self.effect()
        v = self.adapter()
        original = v._connect
        seen = []
        def connect(instance, mode):
            db = original(mode)
            if mode == 'ro':
                seen.append(mode)
                with self.assertRaises(sqlite3.OperationalError):
                    db.execute('UPDATE simulated_resource_state SET version=99')
            return db
        with patch.object(LocalTestInfrastructureVerification, '_connect', connect):
            self.assertEqual(self.observe(v).reason_code, 'LOCAL_STATE_MATCH')
        self.assertEqual(seen, ['ro'])

    def test_writer_authorizer_only_evidence_insert(self):
        v = self.adapter()
        with sqlite3.connect(self.path) as db:
            db.set_authorizer(_write_authorizer)
            for sql in ('DELETE FROM local_attempts', 'UPDATE simulated_resource_state SET version=99',
                        'UPDATE execution_registry SET consumed=1', 'DROP TABLE local_attempts'):
                with self.assertRaises(sqlite3.DatabaseError):
                    db.execute(sql)
        self.assertIsNotNone(v)

    def test_concurrent_threads_one_record(self):
        self.effect()
        v = self.adapter()
        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(lambda _: self.observe(v), range(12)))
        self.assertEqual({r.reason_code for r in results}, {'LOCAL_STATE_MATCH'})
        self.assertEqual(sum(r.observation_kind == 'SYNTHETIC_LOCAL_SNAPSHOT' for r in results), 1)
        self.assertEqual(len({r.evidence_digest for r in results}), 1)
        self.assertEqual(self.count(), 1)

    def test_concurrent_processes_one_record(self):
        self.effect()
        with ProcessPoolExecutor(max_workers=3, mp_context=multiprocessing.get_context('spawn')) as pool:
            results = list(pool.map(observe_process, [self.path] * 6))
        self.assertEqual({r[0] for r in results}, {'LOCAL_STATE_MATCH'})
        self.assertEqual(sum(r[1] == 'SYNTHETIC_LOCAL_SNAPSHOT' for r in results), 1)
        self.assertEqual(len({r[2] for r in results}), 1)
        self.assertEqual(self.count(), 1)

    def test_different_verifier_has_distinct_evidence_key(self):
        self.effect()
        first = self.observe()
        g, b = self.options['verifier_grant'], self.options['verification_binding']
        v = self.adapter(verifier_grant=replace(g, scope=replace(g.scope, identity_id='verifier02')),
                         verification_binding=replace(b, verifier_id='verifier02'))
        second = self.observe(v)
        self.assertNotEqual(first.evidence_digest, second.evidence_digest)
        self.assertEqual(self.count(), 2)

    def test_conflicting_grant_same_verifier_cannot_overwrite(self):
        self.effect()
        self.observe()
        g = replace(self.options['verifier_grant'], expires_at=fixtures.END - timedelta(seconds=1))
        self.assertEqual(self.observe(self.adapter(verifier_grant=g)).reason_code, 'CONFLICT')
        self.assertEqual(self.count(), 1)

    def test_immutable_registration(self):
        v = self.adapter()
        with self.assertRaises(FrozenInstanceError):
            v._clock = self.options['clock']
        with self.assertRaises(LocalInfrastructureDenied):
            v.__init__(**self.options)
        self.assertFalse(hasattr(v, '__dict__'))

    def test_invalid_paths(self):
        for path in (':memory:', 'file:test.sqlite', '/etc/fictional.sqlite', fixtures.Hostile(),
                     '/tmp/invalid\x00.sqlite', '/tmp/' + 'x' * 4096):
            with self.assertRaises(LocalInfrastructureDenied):
                self.adapter(database_path=path)
        path = Path(self.tmp.name) / 'link.sqlite'
        path.symlink_to(self.path)
        with self.assertRaises(LocalInfrastructureDenied):
            self.adapter(database_path=str(path))


if __name__ == '__main__':
    unittest.main()
