"""Offline, fictional, harness-owned execution and adversarial durability tests."""
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from dataclasses import FrozenInstanceError, replace
import multiprocessing
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from avuhz_runtime.local_infrastructure_authority import LocalInfrastructureDenied
from avuhz_runtime.local_infrastructure_execution import (
    ExecutionApproval, LocalTestInfrastructureExecution, SimulatedState, TestFailures,
)
from avuhz_runtime.local_infrastructure_policy import (
    LocalTestInfrastructurePolicyAdapter, policy_decision_digest,
)
from avuhz_runtime.local_infrastructure_trust import LocalTrustAdapter
from tests.architecture import test_local_infrastructure_policy_v1 as policy_fixtures
from tests.architecture import test_local_infrastructure_trust_v1 as fixtures


def provision(path, **changes):
    base = policy_fixtures.PolicyTests()
    base.setUp()
    options = dict(database_path=path, policy_sources=base.config,
                   execution_approval=ExecutionApproval('execution01', 1, base.approval,
                                                        'APPLY_FICTIONAL_STATE', 'ACTIVE'),
                   initial_state=SimulatedState(base.scope, fixtures.C, 2))
    options.update(changes)
    return LocalTestInfrastructureExecution(**options), base


def process_call(path):
    a, base = provision(path)
    return a.execute(base.request, principal_handle=a.principal_handle,
                     execution_handle=a.execution_handle).reason_code


class ExecutionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='avuhz-2c-', dir='/tmp')
        self.addCleanup(self.tmp.cleanup)
        self.path = str(Path(self.tmp.name) / 'test.sqlite')
        self.a, self.base = provision(self.path)
        # Test-only audit trigger measures effects independently of adapter results.
        with sqlite3.connect(self.path) as db:
            db.executescript('CREATE TABLE effect_audit (marker INTEGER); '
                             'CREATE TRIGGER effect_audit_update AFTER UPDATE ON simulated_resource_state '
                             'BEGIN INSERT INTO effect_audit VALUES (1); END;')

    def call(self, a=None, request=None, **handles):
        a = a or self.a
        return a.execute(self.base.request if request is None else request,
                         **dict(principal_handle=a.principal_handle,
                                execution_handle=a.execution_handle, **handles)).reason_code

    def rows(self, table):
        # Table names are internal closed test literals, never request content.
        with sqlite3.connect(self.path) as db:
            return db.execute({'state': 'SELECT digest,version FROM simulated_resource_state',
                               'attempts': 'SELECT outcome FROM local_attempts',
                               'audit': 'SELECT marker FROM effect_audit',
                               'consumed': 'SELECT consumed FROM execution_registry'}[table]).fetchall()

    def fail(self, **flags):
        return provision(self.path, failures=TestFailures(**flags))[0]

    def untouched(self):
        self.assertEqual(self.rows('audit'), [])
        self.assertEqual(self.rows('attempts'), [])
        self.assertEqual(self.rows('consumed'), [(0,)])

    def test_acknowledged_effect_persists_attempted_only(self):
        self.assertEqual(self.call(), 'ATTEMPTED')
        self.assertEqual(self.rows('state'), [(fixtures.D, 3)])
        self.assertEqual(self.rows('attempts'), [('ATTEMPTED',)])
        self.assertEqual(self.rows('audit'), [(1,)])
        self.assertEqual(self.rows('consumed'), [(1,)])

    def test_no_poststate_self_certification(self):
        original = LocalTestInfrastructureExecution._observe
        seen = []
        def observe(instance):
            seen.append(original(instance))
            self.assertEqual(len(seen), 1, 'Executor must only observe prestate')
            return seen[-1]
        with patch.object(LocalTestInfrastructureExecution, '_observe', observe):
            self.assertEqual(self.call(), 'ATTEMPTED')
        self.assertEqual(seen, [(fixtures.C, 2)])
        self.assertEqual(self.rows('state'), [(fixtures.D, 3)])
        self.assertEqual(self.rows('attempts'), [('ATTEMPTED',)])

    def test_schema_rejects_certified_or_unknown_outcomes(self):
        self.call()
        for outcome in ('VERIFIED', 'UNKNOWN'):
            with self.subTest(outcome=outcome), sqlite3.connect(self.path) as db:
                with self.assertRaises(sqlite3.IntegrityError):
                    db.execute('UPDATE local_attempts SET outcome=?', (outcome,))
        self.assertEqual(self.rows('attempts'), [('ATTEMPTED',)])

    def test_injected_legacy_outcomes_fail_closed_on_restart(self):
        self.call()
        for outcome in ('VERIFIED', 'UNKNOWN'):
            # Simulate an old schema or hostile row in this fresh disposable DB only.
            with self.subTest(outcome=outcome), sqlite3.connect(self.path) as db:
                db.execute('PRAGMA ignore_check_constraints=ON')
                db.execute('UPDATE local_attempts SET outcome=?', (outcome,))
            reopened, _ = provision(self.path)
            self.assertEqual(self.call(reopened), 'UNCERTAIN')
            self.assertEqual(self.call(), 'UNCERTAIN')
            self.assertEqual(self.rows('attempts'), [(outcome,)])
            self.assertEqual(len(self.rows('audit')), 1)

    def test_repeat_returns_recorded_no_dispatch(self):
        self.call()
        for _ in range(3):
            self.assertEqual(self.call(), 'ATTEMPTED')
        self.assertEqual(len(self.rows('audit')), 1)

    def test_restart_no_dispatch(self):
        self.call()
        a, _ = provision(self.path)
        self.assertEqual(self.call(a), 'ATTEMPTED')
        self.assertEqual(len(self.rows('audit')), 1)

    def test_crash_after_reservation_restart_stays_attempted(self):
        self.assertEqual(self.call(self.fail(crash_after_reservation=True)), 'ATTEMPTED')
        self.assertEqual(self.call(), 'ATTEMPTED')
        self.assertEqual(self.rows('audit'), [])
        self.assertEqual(self.rows('consumed'), [(1,)])

    def test_lost_ack_effect_remains_uncertain(self):
        self.assertEqual(self.call(self.fail(lost_ack=True)), 'UNCERTAIN')
        self.assertEqual(self.call(), 'UNCERTAIN')
        self.assertEqual(self.rows('state'), [(fixtures.D, 3)])
        self.assertEqual(len(self.rows('audit')), 1)

    def test_verification_failure_flag_retired(self):
        with self.assertRaises(TypeError):
            TestFailures(verification_unavailable=True)

    def test_effect_write_failure(self):
        self.assertEqual(self.call(self.fail(effect_write_failure=True)), 'UNCERTAIN')
        self.assertEqual(self.rows('audit'), [])
        self.assertEqual(self.call(), 'UNCERTAIN')

    def test_outcome_write_failure_never_verified(self):
        self.assertEqual(self.call(self.fail(outcome_write_failure=True)), 'UNCERTAIN')
        self.assertEqual(self.rows('attempts'), [('ATTEMPTED',)])
        self.assertEqual(self.call(), 'ATTEMPTED')
        self.assertEqual(len(self.rows('audit')), 1)

    def test_reservation_refusal_zero_dispatch(self):
        self.assertEqual(self.call(self.fail(reservation_refusal=True)), 'RESERVATION_UNAVAILABLE')
        self.untouched()

    def test_sqlite_actual_reservation_refusal(self):
        with sqlite3.connect(self.path) as db:
            db.execute("CREATE TRIGGER refuse_attempt BEFORE INSERT ON local_attempts "
                       "BEGIN SELECT RAISE(ABORT, 'TEST_REFUSAL'); END")
        self.assertEqual(self.call(), 'RESERVATION_UNAVAILABLE')
        self.untouched()

    def test_sqlite_actual_outcome_refusal(self):
        with sqlite3.connect(self.path) as db:
            db.execute("CREATE TRIGGER refuse_outcome BEFORE UPDATE ON local_attempts "
                       "BEGIN SELECT RAISE(ABORT, 'TEST_REFUSAL'); END")
        self.assertEqual(self.call(), 'UNCERTAIN')
        self.assertEqual(self.rows('attempts'), [('ATTEMPTED',)])
        self.assertEqual(self.call(), 'ATTEMPTED')

    def test_wrong_disk_state_zero_dispatch(self):
        with sqlite3.connect(self.path) as db:
            db.execute('UPDATE simulated_resource_state SET digest=?', (fixtures.M,))
            db.execute('DELETE FROM effect_audit')
        self.assertEqual(self.call(), 'PRESTATE_DENIED')
        self.untouched()

    def test_stale_disk_version_zero_dispatch(self):
        with sqlite3.connect(self.path) as db:
            db.execute('UPDATE simulated_resource_state SET version=4')
            db.execute('DELETE FROM effect_audit')
        self.assertEqual(self.call(), 'PRESTATE_DENIED')
        self.untouched()

    def test_state_change_before_effect_cas_fails(self):
        self.assertEqual(self.call(self.fail(change_before_effect=True)), 'UNCERTAIN')
        self.assertEqual(self.rows('state'), [(fixtures.C, 3)])
        self.assertEqual(self.call(), 'UNCERTAIN')
        self.assertEqual(len(self.rows('audit')), 1)  # Only the harness perturbation.

    def test_missing_state_not_reseeded(self):
        with sqlite3.connect(self.path) as db:
            db.execute('DELETE FROM simulated_resource_state')
        a, _ = provision(self.path)
        self.assertEqual(self.call(a), 'PRESTATE_DENIED')
        self.assertEqual(self.rows('state'), [])

    def test_independent_initial_state_not_derived_from_request(self):
        other = str(Path(self.tmp.name) / 'wrong.sqlite')
        a, _ = provision(other, initial_state=SimulatedState(self.base.scope, fixtures.M, 9))
        self.assertEqual(self.call(a), 'PRESTATE_DENIED')

    def test_observer_connection_is_read_only(self):
        import avuhz_runtime.local_infrastructure_execution as module
        original = module.sqlite3.connect
        read_connections = []
        def connect(*args, **kwargs):
            db = original(*args, **kwargs)
            if kwargs.get('uri'):
                read_connections.append(args[0])
                with self.assertRaises(sqlite3.OperationalError):
                    db.execute('DELETE FROM simulated_resource_state')
            return db
        with patch.object(module.sqlite3, 'connect', connect):
            self.assertEqual(self.call(), 'ATTEMPTED')
        self.assertEqual(len(read_connections), 1)
        self.assertTrue(all(uri.endswith('?mode=ro') for uri in read_connections))

    def test_diagnostic_recomputed_never_authority(self):
        original = LocalTestInfrastructurePolicyAdapter.review_approval
        seen = []
        def review(instance, *args, **kwargs):
            result = original(instance, *args, **kwargs)
            seen.append((result.reason_code, result.authority_effect))
            return result
        with patch.object(LocalTestInfrastructurePolicyAdapter, 'review_approval', review):
            self.call()
        self.assertEqual(seen, [('APPROVAL_MATCH_DIAGNOSTIC', 'NONE')])

    def test_diagnostic_record_not_execution_approval(self):
        with self.assertRaises(LocalInfrastructureDenied):
            provision(self.path, execution_approval=self.base.approval)
        self.untouched()

    def test_diagnostic_operation_cannot_authorize_apply(self):
        with self.assertRaises(LocalInfrastructureDenied):
            provision(self.path, execution_approval=replace(self.a._approval,
                                                          operation='COMPARE_FICTIONAL_STATE'))
        self.untouched()

    def test_invalid_execution_registration_fields(self):
        for changes in ({'execution_version': True}, {'execution_id': fixtures.Hostile()},
                        {'operation': 'SQL'}, {'status': 'CONSUMED'}):
            with self.subTest(changes=changes), self.assertRaises(LocalInfrastructureDenied):
                provision(self.path, execution_approval=replace(self.a._approval, **changes))
        self.untouched()

    def test_wrong_executor_attempts_recoveries(self):
        for changes in ({'executor_id': 'other01'}, {'max_attempts': 2}, {'max_recoveries': 1}):
            with self.subTest(changes=changes), self.assertRaises(LocalInfrastructureDenied):
                provision(self.path, execution_approval=replace(self.a._approval,
                          diagnostic=replace(self.base.approval, **changes)))
        self.untouched()

    def test_handles_exact_identity_and_registry(self):
        other, _ = provision(self.path)
        for handle in (object(), None, 'execution01', fixtures.Hostile(), other.execution_handle,
                       self.a.principal_handle, self.base.approval):
            with self.assertRaises(LocalInfrastructureDenied):
                self.a.execute(self.base.request, principal_handle=self.a.principal_handle,
                               execution_handle=handle)
        self.untouched()

    def test_wrong_principal_handle(self):
        with self.assertRaises(LocalInfrastructureDenied):
            self.a.execute(self.base.request, principal_handle=object(), execution_handle=self.a.execution_handle)
        self.untouched()

    def test_request_cannot_inject_scope_operation_or_sql(self):
        for changes in ({'tenant_id': 'tenant02'}, {'operation': 'APPLY_FICTIONAL_STATE'},
                        {'sql': 'SELECT 1'}, {'path': '/tmp/other'}, {'desired_version': 4},
                        {'challenge': 'challenge02'}, {'executor_id': 'other01'}):
            with self.subTest(changes=changes), self.assertRaises(LocalInfrastructureDenied):
                self.call(request={**self.base.request, **changes})
        self.untouched()

    def test_no_calltime_injections(self):
        for key in ('database_path', 'failures', 'policy_sources', 'execution_approval', 'executor', 'clock'):
            with self.assertRaises(TypeError):
                self.a.execute(self.base.request, principal_handle=self.a.principal_handle,
                               execution_handle=self.a.execution_handle, **{key: object()})
        self.untouched()

    def test_cross_tenant_replay_does_not_leak_outcome(self):
        self.call()
        with self.assertRaises(LocalInfrastructureDenied):
            self.call(request={**self.base.request, 'tenant_id': 'tenant02'})
        with self.assertRaises(LocalInfrastructureDenied):
            provision(self.path, execution_approval=replace(self.a._approval,
                       diagnostic=replace(self.base.approval, pins=replace(self.base.pins,
                       manifest=replace(self.base.pins.manifest,
                       scope=replace(self.base.scope, tenant_id='tenant02'))))))
        self.assertEqual(len(self.rows('audit')), 1)

    def test_revocation_durable_and_stale_adapter_denied(self):
        provision(self.path, execution_approval=replace(self.a._approval, status='REVOKED'))
        self.assertEqual(self.call(), 'AUTHORIZATION_DENIED')
        reopened, _ = provision(self.path)
        self.assertEqual(self.call(reopened), 'AUTHORIZATION_DENIED')
        self.untouched()

    def test_expired_clock_denies_zero_dispatch(self):
        config = {**self.base.config, 'clock': replace(self.base.sources['clock'], now=fixtures.END)}
        a, _ = provision(self.path, policy_sources=config)
        with self.assertRaises(LocalInfrastructureDenied):
            self.call(a)
        self.untouched()

    def test_revoked_human_denies_zero_dispatch(self):
        config = {**self.base.config, 'humans': (replace(self.base.human, status='REVOKED'),)}
        a, _ = provision(self.path, policy_sources=config)
        self.assertEqual(self.call(a), 'DIAGNOSTIC_DENIED')
        self.untouched()

    def test_policy_denial_not_overridden(self):
        config = {**self.base.config, 'policies': (replace(self.base.policy, decision='DENY'),)}
        a, _ = provision(self.path, policy_sources=config)
        self.assertEqual(self.call(a), 'DIAGNOSTIC_DENIED')
        self.untouched()

    def test_changed_source_digest_denies(self):
        config = {**self.base.config, 'observations': (replace(self.base.pins.observation,
                                                              observed_at=fixtures.START),)}
        a, _ = provision(self.path, policy_sources=config)
        self.assertEqual(self.call(a), 'DIAGNOSTIC_DENIED')
        self.untouched()

    def test_approval_all_versions_unavailable_after_attempt(self):
        self.call()
        for change in ({'execution_version': 2}, {'execution_id': 'execution02'}):
            with self.assertRaises(LocalInfrastructureDenied):
                provision(self.path, execution_approval=replace(self.a._approval, **change))
        self.assertEqual(len(self.rows('audit')), 1)

    def test_concurrent_threads_one_effect(self):
        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(lambda _: self.call(), range(12)))
        self.assertTrue(set(results) <= {'ATTEMPTED'})
        self.assertIn('ATTEMPTED', results)
        self.assertEqual(len(self.rows('audit')), 1)
        self.assertEqual(len(self.rows('attempts')), 1)

    def test_concurrent_processes_one_effect(self):
        with ProcessPoolExecutor(max_workers=3, mp_context=multiprocessing.get_context('spawn')) as pool:
            results = list(pool.map(process_call, [self.path] * 6))
        self.assertTrue(set(results) <= {'ATTEMPTED'})
        self.assertIn('ATTEMPTED', results)
        self.assertEqual(len(self.rows('audit')), 1)

    def test_concurrent_different_request_challenge_approval_identity_conflicts(self):
        # Registration refuses reusing any of the durable identities, even when
        # the other identities and versions differ. This occurs before dispatch.
        def attempt(changes):
            a = replace(self.a._approval, **changes)
            try:
                provision(self.path, execution_approval=a)
            except LocalInfrastructureDenied:
                return 'DENIED'
            return 'UNEXPECTED'
        variants = [{'execution_id': 'execution02'}, {'execution_version': 2}]
        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(list(pool.map(attempt, variants)), ['DENIED', 'DENIED'])
        self.untouched()

    def alternate(self, *, request_id='request02', challenge='challenge02',
                  approval_id='approval02', approval_version=1):
        slot = replace(self.base.pins.slot, request_id=request_id, challenge=challenge)
        sources = {**self.base.sources, 'slots': (slot,)}
        request = {**self.base.request, 'request_id': request_id, 'challenge': challenge}
        trust = LocalTrustAdapter(**sources)
        digest = trust.compare(request, principal_handle=trust.identity_handles[0],
                               comparison_handle=trust.comparison_handles[0]).operation_digest
        pins = replace(self.base.pins, slot=slot, operation_digest=digest)
        policy = replace(self.base.policy, pins=pins)
        approval = replace(self.base.approval, pins=pins, approval_id=approval_id,
                           approval_version=approval_version,
                           policy_decision_digest=policy_decision_digest(policy))
        config = {**self.base.config, **sources, 'policies': (policy,), 'approvals': (approval,)}
        a, _ = provision(self.path, policy_sources=config,
                         execution_approval=ExecutionApproval('execution02', 1, approval,
                                                              'APPLY_FICTIONAL_STATE', 'ACTIVE'))
        return a, request

    def test_distinct_approved_requests_compete_for_one_prestate(self):
        other, request = self.alternate()
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(self.call)
            second = pool.submit(self.call, other, request)
            results = [first.result(), second.result()]
        self.assertEqual(results.count('ATTEMPTED'), 1)
        self.assertTrue(set(results) <= {'ATTEMPTED', 'PRESTATE_DENIED', 'UNCERTAIN'})
        self.assertEqual(len(self.rows('audit')), 1)

    def test_same_request_different_challenge_and_approval_denied(self):
        with self.assertRaises(LocalInfrastructureDenied):
            self.alternate(request_id='request01')
        self.untouched()

    def test_same_challenge_different_request_and_approval_denied(self):
        with self.assertRaises(LocalInfrastructureDenied):
            self.alternate(challenge='challenge01')
        self.untouched()

    def test_same_approval_all_versions_different_request_denied(self):
        for version in (1, 2):
            with self.assertRaises(LocalInfrastructureDenied):
                self.alternate(approval_id='approval01', approval_version=version)
        self.untouched()

    def test_concurrent_distinct_identity_collisions(self):
        variants = ({'request_id': 'request01'}, {'challenge': 'challenge01'},
                    {'approval_id': 'approval01', 'approval_version': 2})
        def rejected(options):
            try:
                self.alternate(**options)
            except LocalInfrastructureDenied:
                return True
            return False
        with ThreadPoolExecutor(max_workers=3) as pool:
            self.assertEqual(list(pool.map(rejected, variants)), [True] * 3)
        self.untouched()

    def test_denied_diagnostic_result_cannot_be_execution_handle(self):
        policy = self.base.adapter()
        diagnostic = self.base.call(policy, review=True)
        with self.assertRaises(LocalInfrastructureDenied):
            self.a.execute(self.base.request, principal_handle=self.a.principal_handle,
                           execution_handle=diagnostic)
        self.untouched()

    def test_expired_explicit_approval_denied(self):
        approval = replace(self.base.approval, expires_at=fixtures.NOW)
        config = {**self.base.config, 'approvals': (approval,)}
        path = str(Path(self.tmp.name) / 'expired.sqlite')
        a, _ = provision(path, policy_sources=config,
                         execution_approval=replace(self.a._approval, diagnostic=approval))
        self.assertEqual(self.call(a), 'DIAGNOSTIC_DENIED')
        with sqlite3.connect(path) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM local_attempts').fetchone(), (0,))

    def test_immutable_and_no_reinitialization(self):
        with self.assertRaises(FrozenInstanceError):
            self.a._path = '/tmp/other'
        with self.assertRaises(LocalInfrastructureDenied):
            self.a.__init__(database_path=self.path, policy_sources=self.base.config,
                            execution_approval=self.a._approval,
                            initial_state=SimulatedState(self.base.scope, fixtures.C, 2))
        self.assertFalse(hasattr(self.a, '__dict__'))

    def test_bad_database_path_and_failure_flags(self):
        for path in (':memory:', 'file:test.sqlite', '/etc/test.sqlite'):
            with self.assertRaises(LocalInfrastructureDenied):
                provision(path)
        with self.assertRaises(LocalInfrastructureDenied):
            provision(self.path, failures=TestFailures(lost_ack=1))


if __name__ == '__main__':
    unittest.main()
