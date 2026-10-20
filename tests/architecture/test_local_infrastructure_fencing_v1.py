"""Offline checks that original dispatch and pre-dispatch fencing share a lock."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
from threading import Event
import unittest
from unittest.mock import patch

from avuhz_runtime import local_infrastructure_fencing as fencing
from avuhz_runtime.local_infrastructure_authority import LocalInfrastructureDenied
from avuhz_runtime.local_infrastructure_execution import (
    LocalTestInfrastructureExecution, TestFailures, _approval_digest, _scope_key,
)
from tests.architecture.test_local_infrastructure_execution_v1 import provision
from tests.architecture import test_local_infrastructure_trust_v1 as fixtures


class FencingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='avuhz-fence-', dir='/tmp')
        self.addCleanup(self.tmp.cleanup)
        self.path = str(Path(self.tmp.name) / 'state.sqlite')
        self.execution, self.base = provision(self.path)
        self.args = (self.execution._approval.execution_id, _scope_key(self.base.scope),
                     _approval_digest(self.execution._approval))

    def execute(self, execution=None):
        e = execution or self.execution
        return e.execute(self.base.request, principal_handle=e.principal_handle,
                         execution_handle=e.execution_handle)

    def reserve(self):
        e, _ = provision(self.path, failures=TestFailures(crash_after_reservation=True))
        self.assertEqual(self.execute(e).reason_code, 'ATTEMPTED')

    def transaction(self):
        db = sqlite3.connect(self.path, isolation_level=None)
        db.execute('PRAGMA synchronous=FULL')
        db.execute('BEGIN IMMEDIATE')
        return db

    def test_fence_requires_consumed_original_attempt(self):
        with closing(self.transaction()) as db, db:
            with self.assertRaises(LocalInfrastructureDenied):
                fencing.fence(db, *self.args)

    def test_fence_idempotency_and_original_dispatch_denial(self):
        self.reserve()
        with closing(self.transaction()) as db, db:
            self.assertEqual(fencing.fence(db, *self.args), self.args)
            self.assertEqual(fencing.fence(db, *self.args), self.args)
        with closing(self.transaction()) as db, db:
            with self.assertRaises(LocalInfrastructureDenied):
                fencing.dispatch(db, *self.args)
            with self.assertRaises(LocalInfrastructureDenied):
                fencing.fence(db, self.args[0], self.args[1], fixtures.D)

    def test_completed_dispatch_and_lost_ack_always_deny_fence(self):
        for lost_ack in (False, True):
            with self.subTest(lost_ack=lost_ack):
                path = str(Path(self.tmp.name) / f'completed-{lost_ack}.sqlite')
                e, _ = provision(path, failures=TestFailures(lost_ack=lost_ack))
                self.execute(e)
                with sqlite3.connect(path) as db:
                    db.execute('BEGIN IMMEDIATE')
                    self.assertEqual(db.execute('SELECT count(*) FROM local_execution_dispatches').fetchone(), (1,))
                    with self.assertRaises(LocalInfrastructureDenied):
                        fencing.fence(db, *self.args)

    def test_failed_effect_receipt_rolls_back_but_uncertainty_denies(self):
        e, _ = provision(self.path, failures=TestFailures(effect_write_failure=True))
        self.assertEqual(self.execute(e).reason_code, 'UNCERTAIN')
        with closing(self.transaction()) as db, db:
            self.assertEqual(db.execute('SELECT * FROM local_execution_dispatches').fetchall(), [])
            with self.assertRaises(LocalInfrastructureDenied):
                fencing.fence(db, *self.args)

    def test_late_original_dispatch_cannot_mutate_even_failure_fixture(self):
        for change in (False, True):
            with self.subTest(change_before_effect=change):
                path = str(Path(self.tmp.name) / f'late-{change}.sqlite')
                e, _ = provision(path, failures=TestFailures(change_before_effect=change))
                paused, resume = Event(), Event()
                original_connect = LocalTestInfrastructureExecution._connect
                calls = [0]
                def connect(instance):
                    if instance is e:
                        calls[0] += 1
                        if calls[0] == 2:
                            paused.set()
                            if not resume.wait(5):
                                raise AssertionError('dispatcher test timed out')
                    return original_connect(instance)
                with patch.object(LocalTestInfrastructureExecution, '_connect', connect):
                    with ThreadPoolExecutor(max_workers=1) as pool:
                        task = pool.submit(self.execute, e)
                        try:
                            self.assertTrue(paused.wait(5))
                            with sqlite3.connect(path) as db:
                                db.execute('BEGIN IMMEDIATE')
                                fencing.fence(db, *self.args)
                        finally:
                            resume.set()
                        self.assertEqual(task.result(timeout=5).reason_code, 'UNCERTAIN')
                with sqlite3.connect(path) as db:
                    self.assertEqual(db.execute('SELECT digest,version FROM simulated_resource_state').fetchall(), [(fixtures.C, 2)])
                    self.assertEqual(db.execute('SELECT * FROM local_execution_dispatches').fetchall(), [])

    def test_legacy_registration_never_backfilled(self):
        # Simulate the exact pre-protocol database surface, not caller authority.
        with sqlite3.connect(self.path) as db:
            for table in fencing._TABLES:
                db.execute('DROP TABLE ' + table)
        provision(self.path)
        self.reserve()
        with closing(self.transaction()) as db, db:
            self.assertEqual(db.execute('SELECT * FROM local_execution_fence_protocol').fetchall(), [])
            with self.assertRaises(LocalInfrastructureDenied):
                fencing.fence(db, *self.args)

    def test_immutable_rows_and_exact_schema(self):
        self.reserve()
        with closing(self.transaction()) as db, db:
            fencing.fence(db, *self.args)
        for table in ('local_execution_fence_protocol', 'local_execution_fences'):
            for statement in ('UPDATE ' + table + ' SET digest=digest',
                              'DELETE FROM ' + table,
                              'INSERT OR REPLACE INTO ' + table + ' VALUES (?,?,?)'):
                with self.subTest(statement=statement), sqlite3.connect(self.path) as db:
                    with self.assertRaises(sqlite3.IntegrityError):
                        db.execute(statement, self.args if '?' in statement else ())
        with closing(self.transaction()) as db, db:
            db.execute('DROP TRIGGER local_execution_fences_delete')
            with self.assertRaises(LocalInfrastructureDenied):
                fencing.fence(db, *self.args)

    def test_no_transaction_denied(self):
        with sqlite3.connect(self.path) as db:
            with self.assertRaises(LocalInfrastructureDenied):
                fencing.fence(db, *self.args)


if __name__ == '__main__':
    unittest.main()
