"""Offline G3 preflight, no real Supabase or private credential.

Even a successful read-only catalog preflight proves only the acquisition
DATA connection shape, never an owner, live enrollment, AUTH workload,
n8n receiver, or permission to mount a public route.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests" / "service")]

from avuhz_service.development_acquisition_data import (
    probe_development_acquisition_data_readiness,
)
from test_development_acquisition_data import (
    Connection,
    ConnectionFactory,
)


class FailingConnection(Connection):
    def __init__(self, *, fail_rollback=False, fail_close=False):
        super().__init__()
        self.fail_rollback = fail_rollback
        self.fail_close = fail_close

    def rollback(self):
        super().rollback()
        if self.fail_rollback:
            raise RuntimeError("PRIVATE injected rollback error with hidden data")

    def close(self):
        super().close()
        if self.fail_close:
            raise RuntimeError("PRIVATE injected close error with hidden data")


class RawFailureFactory:
    def __init__(self, **kwargs):
        self.options = kwargs
        self.connections = []

    def __call__(self):
        connection = FailingConnection(**self.options)
        self.connections.append(connection)
        return connection


class DataReadinessProbeTests(unittest.TestCase):
    def test_exact_read_only_session_is_preflighted_and_closed(self):
        raw = ConnectionFactory()
        result = probe_development_acquisition_data_readiness(raw)
        self.assertIsNone(result)
        self.assertEqual(len(raw.connections), 1)
        conn = raw.connections[0]
        self.assertFalse(conn.autocommit)
        self.assertEqual(len(conn.calls), 4)
        self.assertEqual(conn.calls[1][0], "set role avuhz_acquisition_service_dev")
        for statement, _ in conn.calls:
            self.assertNotIn("AVUHZ_ACQUISITION_POSTGRES_DSN", statement)
            self.assertNotIn("set_config(", statement)
            self.assertFalse(statement.lower().lstrip().startswith(
                ("insert", "update", "delete", "grant", "alter", "create", "drop")
            ))
        self.assertEqual((conn.rollback_count, conn.close_count), (1, 1))

    def test_missing_or_drifted_private_data_session_fails_closed(self):
        for options in (
            {"host": "db.pwlhruwutoitnieactol.supabase.co"},
            {"host": "db.example.invalid"},
            {"sslmode": "disable"},
            {"preflight": False},
            {"effective": False},
            {"counter_ready": False},
        ):
            with self.subTest(options=options):
                raw = ConnectionFactory(**options)
                with self.assertRaisesRegex(
                    RuntimeError,
                    "^DEVELOPMENT acquisition DATA readiness invalid$",
                ):
                    probe_development_acquisition_data_readiness(raw)
                self.assertEqual(len(raw.connections), 1)
                conn = raw.connections[0]
                self.assertEqual((conn.rollback_count, conn.close_count), (1, 1))

    def test_cleanup_failure_does_not_count_as_ready_or_leak_exception(self):
        for flags in ({"fail_rollback": True}, {"fail_close": True},
                      {"fail_rollback": True, "fail_close": True}):
            with self.subTest(flags=flags):
                raw = RawFailureFactory(**flags)
                with self.assertRaisesRegex(
                    RuntimeError,
                    "^DEVELOPMENT acquisition DATA readiness invalid$",
                ) as error:
                    probe_development_acquisition_data_readiness(raw)
                self.assertNotIn("PRIVATE", str(error.exception))
                self.assertEqual(len(raw.connections), 1)
                connection = raw.connections[0]
                self.assertEqual((connection.rollback_count, connection.close_count), (1, 1))

    def test_raw_driver_error_and_missing_connection_are_sanitized(self):
        def raises_private_error():
            raise RuntimeError("postgresql://user:PRIVATE_PASSWORD@db.invalid")

        for raw in (raises_private_error, lambda: None):
            with self.subTest(raw=raw):
                with self.assertRaisesRegex(
                    RuntimeError, "^DEVELOPMENT acquisition DATA readiness invalid$"
                ) as error:
                    probe_development_acquisition_data_readiness(raw)
                self.assertNotIn("PRIVATE_PASSWORD", str(error.exception))
                self.assertIsNone(error.exception.__cause__)

    def test_non_callable_or_implicit_credentials_are_not_accepted(self):
        for bad in (None, object(), "AVUHZ_ACQUISITION_POSTGRES_DSN"):
            with self.subTest(value_type=type(bad).__name__):
                with self.assertRaisesRegex(
                    ValueError, "^dedicated DEVELOPMENT acquisition factory required$"
                ):
                    probe_development_acquisition_data_readiness(bad)

        source = (ROOT / "src" / "avuhz_service" / "development_acquisition_data.py").read_text()
        self.assertNotIn("create_development_application(", source)
        self.assertNotIn("GRANT ", source)
        self.assertNotIn("create_role(", source)
        # A probe is a preparation tool, not mounted by any hosted app code.
        for name in ("application.py", "development.py", "development_acquisition_composition.py"):
            self.assertNotIn(
                "probe_development_acquisition_data_readiness",
                (ROOT / "src" / "avuhz_service" / name).read_text(),
            )


if __name__ == "__main__":
    unittest.main()
