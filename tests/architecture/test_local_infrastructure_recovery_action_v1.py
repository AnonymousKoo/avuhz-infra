"""Fresh fictional action authority, actual state and durable fencing; offline."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import fields, replace
from datetime import timedelta
from pathlib import Path
import sqlite3
import subprocess
import sys
import os
import tempfile
import threading
import unittest
from unittest.mock import patch

from avuhz_runtime.local_infrastructure_authority import LocalInfrastructureDenied
from avuhz_runtime.local_infrastructure_execution import LocalTestInfrastructureExecution
from avuhz_runtime.local_infrastructure_recovery import (
    LocalTestInfrastructureRecovery, RecoveryGrant, open_recovery_case,
    collect_recovery_observation, _case_digest,
)
from avuhz_runtime.local_infrastructure_recovery_action import (
    LocalTestRecoveryAction, RecoveryActionAuthorization, RecoveryActionPolicy,
    RecoveryActionRequest, action_intent_digest, request_digest, _authorizer,
)
from tests.architecture import test_local_infrastructure_recovery_v1 as rec


def options(path, flags=None):
    c = rec.options(path, flags={'crash_after_reservation': True} if flags is None else flags)
    a = LocalTestInfrastructureRecovery(**c)
    result = a.reconcile(observer_handle=a.observer_handle, authorization_handle=a.authorization_handle)
    clock = replace(c['clock'], now=rec.fixtures.NOW + timedelta(seconds=5))
    case = open_recovery_case(audit_sources=c['audit_sources'], audit_digest=c['audit_digest'],
                             case_id='actioncase01', challenge='actioncasechallenge01', clock=clock)
    grants = tuple(RecoveryGrant(replace(case.scope, identity_id='action' + role.lower() + '01'),
        role, role + '_FICTIONAL_RECOVERY_ACTION', 'ACTIVE', c['clock'].issued_at, clock.expires_at)
        for role in ('HUMAN', 'EXECUTOR', 'OBSERVER', 'VERIFIER'))
    clock = replace(clock, now=clock.now + timedelta(seconds=1))
    observation = collect_recovery_observation(audit_sources=c['audit_sources'], case=case,
        observer_grant=replace(grants[2], capability='OBSERVE_FICTIONAL_RECOVERY'),
        observation_id='actionobservation01', clock=clock)
    with sqlite3.connect(path) as db:
        audit = db.execute('SELECT * FROM local_audit_evidence').fetchone()
    r = RecoveryActionRequest('recoveryaction01', 'actionrequest01', 'actionchallenge01', case.scope,
        audit[6], audit[13], _case_digest(c['case']), result.evidence_digest, case,
        observation, rec.fixtures.D, 3)
    policy = RecoveryActionPolicy('actionpolicy01', 1, request_digest(r), 'ALLOW')
    consent = RecoveryActionAuthorization('actionauthorization01', 1,
        grants[0].scope.identity_id, grants[1].scope.identity_id,
        action_intent_digest(r, policy, grants), clock.now + timedelta(seconds=1), clock.expires_at)
    return dict(reconciliation_sources=c, request=r, policy=policy, authorization=consent,
                grants=grants, clock=replace(clock, now=clock.now + timedelta(seconds=2)))


class RecoveryActionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='avuhz-action-', dir='/tmp')
        self.addCleanup(self.tmp.cleanup)
        self.path = str(Path(self.tmp.name) / 'state.sqlite')
        self.c = options(self.path)

    def adapter(self, **changes):
        return LocalTestRecoveryAction(**dict(self.c, **changes))

    def execute(self, a):
        return a.execute(executor_handle=a.executor_handle, authorization_handle=a.authorization_handle)

    def sql(self, sql, args=()):
        with sqlite3.connect(self.path) as db:
            return db.execute(sql, args).fetchall()

    def repin(self, **changes):
        c = dict(self.c, **changes)
        c['policy'] = replace(c['policy'], request_digest=request_digest(c['request']))
        c['authorization'] = replace(c['authorization'], intent_digest=action_intent_digest(
            c['request'], c['policy'], c['grants']))
        return c

    def test_end_to_end_restart_original_failure_preserved(self):
        before = tuple(self.sql('SELECT * FROM ' + t) for t in ('local_attempts', 'local_audit_evidence', 'local_recovery_decisions'))
        a = self.adapter()
        self.assertEqual(self.execute(a).state, 'ATTEMPTED')
        self.assertEqual(a.verify(verifier_handle=a.verifier_handle).state, 'VERIFIED')
        self.assertEqual(self.sql('SELECT digest,version FROM simulated_resource_state'), [(rec.fixtures.D, 3)])
        self.assertEqual(before, tuple(self.sql('SELECT * FROM ' + t) for t in ('local_attempts', 'local_audit_evidence', 'local_recovery_decisions')))
        b = self.adapter()
        self.assertEqual(self.execute(b).state, 'UNCERTAIN')
        self.assertEqual(b.verify(verifier_handle=b.verifier_handle).state, 'VERIFIED')
        self.assertEqual(self.sql('SELECT state FROM local_recovery_action_events ORDER BY rowid'),
            [(s,) for s in ('PROPOSED', 'AUTHORIZED', 'RESERVED', 'ATTEMPTED')])
        self.assertIn(rec.fixtures.D, self.sql("SELECT observation FROM local_recovery_action_verifications WHERE state='VERIFIED'")[0][0])
        self.assertEqual(self.sql('SELECT count(*) FROM local_execution_dispatches'), [(0,)])
        self.assertEqual(self.sql('SELECT count(*) FROM local_execution_fences'), [(1,)])

    def test_all_scope_dimensions_deny_even_rehashed(self):
        for f in fields(self.c['request'].scope):
            r = replace(self.c['request'], scope=replace(self.c['request'].scope, **{f.name: 'LOCAL' if f.name == 'environment' else 'different01'}))
            with self.subTest(field=f.name), self.assertRaises(LocalInfrastructureDenied):
                LocalTestRecoveryAction(**self.repin(request=r))

    def test_every_original_binding_digest_denied(self):
        for name in ('original_execution_digest', 'original_attempt_digest', 'original_case_digest', 'reconciliation_digest', 'desired_digest'):
            with self.subTest(field=name), self.assertRaises(LocalInfrastructureDenied):
                LocalTestRecoveryAction(**self.repin(request=replace(self.c['request'], **{name:rec.fixtures.M})))

    def test_stale_future_revoked_grants_and_authority(self):
        for key in ('authorization', 'clock'):
            changes = ({'status': 'REVOKED'}, {'expires_at': rec.fixtures.NOW}, {'issued_at': self.c['clock'].now + timedelta(seconds=1)}) if key == 'authorization' else ({'now': self.c['clock'].now + timedelta(seconds=70)},)
            for change in changes:
                with self.subTest(key=key, change=change), self.assertRaises(LocalInfrastructureDenied):
                    self.adapter(**{key:replace(self.c[key], **change)})
        for i in range(4):
            for change in ({'status':'REVOKED'}, {'expires_at':rec.fixtures.NOW}, {'issued_at':self.c['clock'].now + timedelta(seconds=1)}):
                g = list(self.c['grants']); g[i] = replace(g[i], **change)
                with self.subTest(grant=i, change=change), self.assertRaises(LocalInfrastructureDenied):
                    LocalTestRecoveryAction(**self.repin(grants=tuple(g)))

    def test_all_prior_role_collisions(self):
        for identity in ('principal01', 'observer01', 'fictional.human01', 'fictional.executor01', 'verifier01', 'auditor01', 'recoveryobserver01', 'recoveryhuman01'):
            for index in range(4):
                grants = list(self.c['grants'])
                grants[index] = replace(grants[index], scope=replace(grants[index].scope, identity_id=identity))
                with self.subTest(identity=identity, role=index), self.assertRaises(LocalInfrastructureDenied):
                    LocalTestRecoveryAction(**self.repin(grants=tuple(grants)))

    def test_forged_handles_policy_and_original_consent(self):
        a, b = self.adapter(), self.adapter()
        self.assertEqual(a.execute(executor_handle=b.executor_handle, authorization_handle=a.authorization_handle).state, 'DENIED')
        self.assertEqual(a.verify(verifier_handle=a.executor_handle).state, 'UNVERIFIED')
        with self.assertRaises(LocalInfrastructureDenied):
            self.adapter(authorization=self.c['reconciliation_sources']['authorization'])
        with self.assertRaises(LocalInfrastructureDenied):
            self.adapter(policy=replace(self.c['policy'], decision='DENY'))
        with self.assertRaises(LocalInfrastructureDenied):
            self.adapter(authorization=replace(self.c['authorization'], intent_digest=rec.fixtures.M))
        for name in ('max_attempts', 'authorization_version'):
            with self.assertRaises(LocalInfrastructureDenied):
                self.adapter(authorization=replace(self.c['authorization'], **{name:True}))

    def test_reused_identity_and_observation(self):
        r = self.c['request']
        for name in ('action_id', 'request_id', 'challenge'):
            with self.subTest(name=name), self.assertRaises(LocalInfrastructureDenied):
                LocalTestRecoveryAction(**self.repin(request=replace(r, **{name:self.c['reconciliation_sources']['case'].challenge})))
        with self.assertRaises(LocalInfrastructureDenied):
            LocalTestRecoveryAction(**self.repin(request=replace(r, observation=replace(r.observation, observed_digest=rec.fixtures.M))))
        with self.assertRaises(LocalInfrastructureDenied):
            LocalTestRecoveryAction(**self.repin(request=replace(r, observation=replace(r.observation, observation_id='inventedobservation01'))))

    def test_prestate_changes_no_reservation_or_fence(self):
        a = self.adapter()
        self.sql('UPDATE simulated_resource_state SET version=9')
        self.assertEqual(self.execute(a).state, 'DENIED')
        self.assertEqual(self.sql('SELECT count(*) FROM local_recovery_action_reservations'), [(0,)])
        self.assertEqual(self.sql('SELECT count(*) FROM local_execution_fences'), [(0,)])

    def test_concurrency_one_effect(self):
        a = self.adapter()
        with ThreadPoolExecutor(max_workers=8) as pool:
            states = list(pool.map(lambda _: self.execute(a).state, range(8)))
        self.assertEqual(states.count('ATTEMPTED'), 1)
        self.assertEqual(self.sql('SELECT count(*) FROM local_recovery_action_reservations'), [(1,)])
        self.assertEqual(self.sql("SELECT count(*) FROM local_recovery_action_events WHERE state='ATTEMPTED'"), [(1,)])

    def test_wrong_actual_poststate_unverified_immutable(self):
        a = self.adapter(); self.execute(a)
        self.sql('UPDATE simulated_resource_state SET digest=?,version=9', (rec.fixtures.M,))
        first = a.verify(verifier_handle=a.verifier_handle)
        self.assertEqual(first.state, 'UNVERIFIED')
        self.sql('UPDATE simulated_resource_state SET digest=?,version=3', (rec.fixtures.D,))
        self.assertEqual(a.verify(verifier_handle=a.verifier_handle), first)
        self.assertIn(rec.fixtures.M, self.sql("SELECT observation FROM local_recovery_action_verifications WHERE state='UNVERIFIED'")[0][0])

    def test_immutable_records_and_schema_substitution(self):
        a = self.adapter(); self.execute(a)
        for table in ('local_recovery_action_registrations','local_recovery_action_reservations','local_recovery_action_events'):
            for query in ('UPDATE '+table+' SET binding=binding', 'DELETE FROM '+table,
                          'INSERT OR REPLACE INTO '+table+' SELECT * FROM '+table):
                with self.subTest(query=query), self.assertRaises(sqlite3.Error): self.sql(query)
        self.sql('DROP TRIGGER local_recovery_action_events_delete')
        self.assertEqual(self.execute(a).state, 'DENIED')

    def test_verifier_writer_cannot_mutate_state_or_original(self):
        a = self.adapter()
        with closing(a._reconciliation._audit._connect()) as db:
            db.set_authorizer(_authorizer('verifier'))
            for query in ('UPDATE simulated_resource_state SET version=9', 'UPDATE local_attempts SET outcome=outcome',
                          'DELETE FROM local_execution_fences', 'CREATE TABLE forbidden(x)', 'SELECT * FROM simulated_resource_state'):
                with self.subTest(query=query), self.assertRaises(sqlite3.Error): db.execute(query)

    def test_original_dispatch_marker_and_missing_protocol_deny(self):
        a = self.adapter()
        self.sql('INSERT INTO local_execution_dispatches SELECT * FROM local_execution_fence_protocol')
        self.assertEqual(self.execute(a).state, 'DENIED')
        self.assertEqual(self.sql('SELECT count(*) FROM local_execution_fences'), [(0,)])

    def test_missing_protocol_denies_legacy(self):
        a = self.adapter()
        self.sql('DROP TRIGGER local_execution_fence_protocol_delete')
        self.sql('DELETE FROM local_execution_fence_protocol')
        self.assertEqual(self.execute(a).state, 'DENIED')

    def test_evidence_write_failure_rolls_back_effect_and_consumes(self):
        a = self.adapter()
        original = LocalTestRecoveryAction._event
        def fail(instance, db, state, observation=''):
            if state == 'ATTEMPTED': raise sqlite3.OperationalError('FICTIONAL_WRITE_FAILURE')
            return original(instance, db, state, observation)
        with patch.object(LocalTestRecoveryAction, '_event', fail):
            self.assertEqual(self.execute(a).state, 'UNCERTAIN')
        self.assertEqual(self.sql('SELECT digest,version FROM simulated_resource_state'), [(rec.fixtures.C, 2)])
        self.assertEqual(self.execute(self.adapter()).state, 'UNCERTAIN')
        self.assertEqual(a.verify(verifier_handle=a.verifier_handle).state, 'UNVERIFIED')

    def test_verifier_unavailable_preserves_attempt(self):
        a = self.adapter(); self.execute(a)
        with patch('sqlite3.connect', side_effect=sqlite3.OperationalError('FICTIONAL_UNAVAILABLE')):
            self.assertEqual(a.verify(verifier_handle=a.verifier_handle).state, 'UNVERIFIED')
        self.assertEqual(a.verify(verifier_handle=a.verifier_handle).state, 'VERIFIED')

    def test_lost_effect_commit_ack_never_redispatches(self):
        a = self.adapter()
        original = type(a._reconciliation._audit)._connect
        class LostAck:
            def __init__(inner, audit): inner.db = original(audit)
            def __getattr__(inner, key): return getattr(inner.db, key)
            def __enter__(inner): inner.db.__enter__(); return inner
            def __exit__(inner, *args):
                attempted = inner.db.execute("SELECT 1 FROM local_recovery_action_events WHERE state='ATTEMPTED'").fetchone()
                inner.db.__exit__(*args)
                if attempted: raise sqlite3.OperationalError('FICTIONAL_LOST_ACK')
        with patch.object(type(a._reconciliation._audit), '_connect', lambda audit: LostAck(audit)):
            self.assertEqual(self.execute(a).state, 'UNCERTAIN')
        self.assertEqual(self.execute(self.adapter()).state, 'UNCERTAIN')
        self.assertEqual(a.verify(verifier_handle=a.verifier_handle).state, 'VERIFIED')
        self.assertEqual(self.sql("SELECT count(*) FROM local_recovery_action_events WHERE state='ATTEMPTED'"), [(1,)])

    def test_durable_revocation_across_restart(self):
        a = self.adapter()
        self.assertTrue(a.revoke(authorization_handle=a.authorization_handle).evidence_digest)
        self.assertEqual(self.execute(a).state, 'DENIED')
        with self.assertRaises(LocalInfrastructureDenied): self.adapter()
        with self.assertRaises(sqlite3.Error): self.sql('DELETE FROM local_recovery_action_revocations')
        self.assertEqual(self.sql('SELECT digest,version FROM simulated_resource_state'), [(rec.fixtures.C, 2)])

    def test_revocation_after_reservation_prevents_effect(self):
        a = self.adapter()
        original = type(a._reconciliation._audit)._connect
        calls = [0]
        def connect(audit):
            calls[0] += 1
            if calls[0] == 2:
                a.revoke(authorization_handle=a.authorization_handle)
            return original(audit)
        with patch.object(type(a._reconciliation._audit), '_connect', connect):
            self.assertEqual(self.execute(a).state, 'UNCERTAIN')
        self.assertEqual(self.sql('SELECT digest,version FROM simulated_resource_state'), [(rec.fixtures.C, 2)])
        self.assertEqual(self.sql('SELECT count(*) FROM local_recovery_action_reservations'), [(1,)])

    def test_reservation_commit_failure_never_dispatches(self):
        a = self.adapter()
        original = type(a._reconciliation._audit)._connect
        class Refusal:
            def __init__(inner, audit): inner.db = original(audit)
            def __getattr__(inner, key): return getattr(inner.db, key)
            def __enter__(inner): inner.db.__enter__(); return inner
            def __exit__(inner, *args):
                inner.db.rollback()
                raise sqlite3.OperationalError('FICTIONAL_RESERVATION_REFUSAL')
        with patch.object(type(a._reconciliation._audit), '_connect', lambda audit: Refusal(audit)):
            self.assertEqual(self.execute(a).state, 'UNCERTAIN')
        self.assertEqual(self.sql('SELECT count(*) FROM local_recovery_action_reservations'), [(0,)])
        self.assertEqual(self.sql('SELECT count(*) FROM local_execution_fences'), [(0,)])
        self.assertEqual(self.sql('SELECT digest,version FROM simulated_resource_state'), [(rec.fixtures.C, 2)])

    def test_full_recovery_blocks_paused_original_after_recovery(self):
        # Pause the actual original executor after durable reservation, before
        # acquiring its effect lock. Build the audit/reconciliation while paused.
        path = str(Path(self.tmp.name) / 'delayed.sqlite')
        paused, resume = threading.Event(), threading.Event()
        original_connect = LocalTestInfrastructureExecution._connect
        calls = [0]
        def connect(instance):
            calls[0] += 1
            if calls[0] == 3:  # provisioning, reservation, effect
                paused.set()
                if not resume.wait(10): raise AssertionError('FICTIONAL_DISPATCH_TIMEOUT')
            return original_connect(instance)
        # options() executes once then builds its historical records. The thread
        # is captured while paused; the harness then observes the consumed row
        # through a second instance whose replay never dispatches.
        with patch.object(LocalTestInfrastructureExecution, '_connect', connect):
            with ThreadPoolExecutor(max_workers=1) as pool:
                delayed = pool.submit(options, path, {})
                try:
                    self.assertTrue(paused.wait(5))
                    c = options(path, {})
                    a = LocalTestRecoveryAction(**c)
                    self.assertEqual(self.execute(a).state, 'ATTEMPTED')
                    self.assertEqual(a.verify(verifier_handle=a.verifier_handle).state, 'VERIFIED')
                finally:
                    resume.set()
                # Late original changes only its safe outcome to UNCERTAIN;
                # options may now reject duplicate immutable audit records.
                try: delayed.result(timeout=5)
                except (sqlite3.Error, LocalInfrastructureDenied, AssertionError): pass
        with sqlite3.connect(path) as db:
            self.assertEqual(db.execute('SELECT digest,version FROM simulated_resource_state').fetchall(), [(rec.fixtures.D, 3)])
            self.assertEqual(db.execute('SELECT count(*) FROM local_execution_dispatches').fetchone(), (0,))
            self.assertEqual(db.execute('SELECT count(*) FROM local_execution_fences').fetchone(), (1,))
            self.assertEqual(db.execute("SELECT count(*) FROM local_recovery_action_events WHERE state='ATTEMPTED'").fetchone(), (1,))

    def test_cross_process_delayed_original_recovery_replay(self):
        path = str(Path(self.tmp.name) / 'process.sqlite')
        root = Path(__file__).resolve().parents[2]
        env = dict(os.environ, PYTHONPATH=str(root / 'src') + os.pathsep + str(root),
                   PYTHONDONTWRITEBYTECODE='1')
        # No semaphores, sockets or timing assumptions: pipes establish ordering.
        child = r"""
import sys
from unittest.mock import patch
from avuhz_runtime.local_infrastructure_execution import LocalTestInfrastructureExecution
from tests.architecture.test_local_infrastructure_recovery_v1 import options
connect = LocalTestInfrastructureExecution._connect
execute = LocalTestInfrastructureExecution.execute
calls = 0
def paused(instance):
    global calls
    calls += 1
    if calls == 3:
        print('RESERVED', flush=True)
        if sys.stdin.readline() != 'RESUME\n': raise RuntimeError('BAD_RESUME')
    return connect(instance)
def checked(instance, *args, **kwargs):
    result = execute(instance, *args, **kwargs)
    if result.reason_code != 'UNCERTAIN': raise RuntimeError('ORIGINAL_NOT_BLOCKED')
    print('BLOCKED', flush=True)
    raise SystemExit(0)
with patch.object(LocalTestInfrastructureExecution, '_connect', paused), patch.object(LocalTestInfrastructureExecution, 'execute', checked):
    options(sys.argv[1], flags={})
"""
        process = subprocess.Popen([sys.executable, '-c', child, path], cwd=root, env=env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            with ThreadPoolExecutor(max_workers=1) as pool:
                ready = pool.submit(process.stdout.readline)
                try:
                    self.assertEqual(ready.result(timeout=20), 'RESERVED\n')
                    c = options(path, {})
                    a = LocalTestRecoveryAction(**c)
                    replay = r"""
import sys
from tests.architecture.test_local_infrastructure_recovery_action_v1 import options
from avuhz_runtime.local_infrastructure_recovery_action import LocalTestRecoveryAction
# Reconstruct deterministic trusted inputs in a private fixture, then bind
# the adapter to the original physical database (no serialized authority).
c = options(sys.argv[1] + '-fixture')
c['reconciliation_sources']['audit_sources']['database_path'] = sys.argv[1]
print('READY', flush=True)
if sys.stdin.readline() != 'REPLAY\n': raise RuntimeError('BAD_REPLAY_SIGNAL')
a = LocalTestRecoveryAction(**c)
outcome = a.execute(executor_handle=a.executor_handle, authorization_handle=a.authorization_handle)
if outcome.state != 'UNCERTAIN': raise RuntimeError('REPLAY_NOT_BLOCKED')
verified = a.verify(verifier_handle=a.verifier_handle)
if verified.state != 'VERIFIED': raise RuntimeError('RECOVERY_NOT_VERIFIED')
print('REPLAY_BLOCKED_VERIFIED')
"""
                    other = subprocess.Popen([sys.executable, '-O', '-c', replay, path], cwd=root, env=env,
                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    try:
                        waiting = pool.submit(other.stdout.readline)
                        signal = waiting.result(timeout=20)
                        self.assertEqual(signal, 'READY\n', other.stderr.read() if not signal else '')
                        self.assertEqual(self.execute(a).state, 'ATTEMPTED')
                        out, err = other.communicate('REPLAY\n', timeout=20)
                        self.assertEqual(other.returncode, 0, err)
                        self.assertEqual(out, 'REPLAY_BLOCKED_VERIFIED\n')
                        self.assertEqual(a.verify(verifier_handle=a.verifier_handle).state, 'VERIFIED')
                    finally:
                        if other.poll() is None:
                            other.kill()
                        other.communicate()
                        for pipe in (other.stdin, other.stdout, other.stderr):
                            pipe.close()
                finally:
                    if not ready.done():
                        process.kill()
            stdout, stderr = process.communicate('RESUME\n', timeout=20)
            self.assertEqual(process.returncode, 0, 'original process failed')
            self.assertEqual(stdout, 'BLOCKED\n')
            self.assertEqual(stderr, '')
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate()
            for pipe in (process.stdin, process.stdout, process.stderr):
                pipe.close()
        # Independent physical read after every child has exited: recovery is
        # the last and only effect, and the original never gained dispatch.
        with sqlite3.connect('file:' + path + '?mode=ro', uri=True) as db:
            self.assertEqual(db.execute('SELECT digest,version FROM simulated_resource_state').fetchall(), [(rec.fixtures.D, 3)])
            self.assertEqual(db.execute('SELECT count(*) FROM local_execution_dispatches').fetchone(), (0,))
            self.assertEqual(db.execute('SELECT count(*) FROM local_execution_fences').fetchone(), (1,))
            self.assertEqual(db.execute('SELECT count(*) FROM local_recovery_action_reservations').fetchone(), (1,))
            self.assertEqual(db.execute("SELECT state FROM local_recovery_action_events WHERE state='ATTEMPTED'").fetchall(), [('ATTEMPTED',)])
            self.assertEqual(db.execute('SELECT state FROM local_recovery_action_verifications').fetchall(), [('VERIFIED',)])

    def test_executor_writer_cannot_forge_verification(self):
        a = self.adapter()
        with closing(a._reconciliation._audit._connect()) as db:
            db.set_authorizer(_authorizer('executor'))
            with self.assertRaises(sqlite3.Error):
                db.execute("INSERT INTO local_recovery_action_verifications VALUES (?,?,?,?,?,?,?,?)",
                           ('fake01','fake01',a._request.action_id,'VERIFIED',a._binding,'[]','2026-10-20T00:00:00Z',rec.fixtures.M))
        self.assertEqual(a.verify(verifier_handle=a.verifier_handle).state, 'UNVERIFIED')

    def test_ambiguous_and_completed_originals_never_recover(self):
        for i, flags in enumerate(({}, {'lost_ack':True}, {'effect_write_failure':True})):
            path = str(Path(self.tmp.name) / ('unresolved' + str(i) + '.sqlite'))
            with self.subTest(flags=flags), self.assertRaises(LocalInfrastructureDenied):
                LocalTestRecoveryAction(**options(path, flags))
            with sqlite3.connect(path) as db:
                self.assertEqual(db.execute('SELECT count(*) FROM local_execution_fences').fetchone(), (0,))

    def test_second_action_cannot_replace_consumed_original(self):
        a = self.adapter(); self.execute(a)
        c = self.repin(request=replace(self.c['request'], action_id='secondaction01',
                      request_id='secondrequest01', challenge='secondchallenge01'))
        c['authorization'] = replace(c['authorization'], authorization_id='secondauthorization01')
        with self.assertRaises(LocalInfrastructureDenied): LocalTestRecoveryAction(**c)
        self.assertEqual(self.sql('SELECT count(*) FROM local_recovery_action_reservations'), [(1,)])
