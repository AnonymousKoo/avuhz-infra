"""Offline fake-connector tests; no hosted TLS, credential or role is contacted.

A fake pg_stat_ssl row and fake libpq parameters verify application-side
enforcement only. Actual server certificate/runner identity remain unproven.
"""
from __future__ import annotations

import dataclasses
import hashlib
import secrets
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests/security"), str(ROOT / "tests/service")]

from avuhz_engineering.development_handoff_runner_connection_candidate import (
    DevelopmentRunnerConnectionFactoryCandidate,
    DevelopmentRunnerConnectionPolicy,
    DevelopmentRunnerTransportStop,
)
from avuhz_engineering.development_handoff_trusted_one_shot_executor import (
    SignedStageProof, TrustedOneShotStop,
    claim_signed_handoff_stages_postgres_candidate,
)
from avuhz_service.development import DEVELOPMENT_DATA_PROJECT_REF
from test_development_handoff_trusted_one_shot_executor import TrustedOneShotExecutorTests
from test_development_handoff_approval_gate import AT

HOST = "db.gnuqaefotwgkwurjpyik.supabase.co"
RUNNER = "avuhz_handoff_claim_runner_dev"
WRITER = "avuhz_handoff_claim_writer"


class FakeResult:
    def __init__(self, row=None, rows=None):
        self.row = row
        self.rows = rows if rows is not None else []

    def fetchone(self):
        return self.row

    def fetchall(self):
        return self.rows


class FakeInfo:
    def __init__(self, kwargs):
        self.host = kwargs["host"]
        self.port = kwargs["port"]
        self.dbname = kwargs["dbname"]
        self.user = kwargs["user"]
        self.params = {
            "sslmode": kwargs["sslmode"],
            "sslrootcert": kwargs["sslrootcert"],
            "gssencmode": kwargs["gssencmode"],
        }

    def get_parameters(self):
        return self.params


class FakeConnection:
    def __init__(self, kwargs):
        self.info = FakeInfo(kwargs)
        self.tls = (True, "TLSv1.3")
        self.identity = (RUNNER, RUNNER, "postgres")
        self.after_role = (RUNNER, WRITER)
        self.role_set = False
        self.closed = False
        self.inserts = []
        self.statements = []

    def execute(self, statement, parameters=None):
        self.statements.append(statement)
        normalized = " ".join(statement.lower().split())
        if "pg_stat_ssl" in normalized:
            return FakeResult(self.tls)
        if normalized == "select session_user, current_user, current_database()":
            return FakeResult(self.identity)
        if normalized == "set role avuhz_handoff_claim_writer":
            self.role_set = True
            return FakeResult()
        if normalized in {"select session_user, current_user", "select session_user,current_user"}:
            return FakeResult(self.after_role if self.role_set else self.identity[:2])
        if "from pg_roles where rolname=%s" in normalized:
            return FakeResult((True, False, False, False, False, False, False))
        if "from pg_auth_members" in normalized:
            return FakeResult(rows=[(False, False, True)])
        if "select pg_has_role" in normalized:
            return FakeResult((False,))
        if "select has_table_privilege" in normalized:
            return FakeResult((False,))
        if "select c.relrowsecurity" in normalized:
            return FakeResult((True, True))
        if "select set_config" in normalized:
            return FakeResult(("",))
        if normalized.startswith("insert into avuhz_handoff_control."):
            self.inserts.append(parameters)
            return FakeResult()
        raise AssertionError("unexpected fake SQL path")

    def transaction(self):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
        return False

    def close(self):
        self.closed = True


class DevelopmentRunnerConnectionOfflineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.ca = Path(self.temp.name) / "fictional-ca.pem"
        # Deliberately NOT a real certificate: test never performs a TLS handshake.
        self.ca.write_bytes(b"fictional-test-root-only-not-a-server-certificate\n")
        self.policy = DevelopmentRunnerConnectionPolicy(
            project_ref=DEVELOPMENT_DATA_PROJECT_REF,
            host=HOST, port=5432, dbname="postgres", user=RUNNER,
            sslmode="verify-full", sslrootcert=str(self.ca),
            expected_ca_sha256="sha256:" + hashlib.sha256(self.ca.read_bytes()).hexdigest(),
        )
        self.calls = []
        self.connections = []
        self.secret = secrets.token_urlsafe(32)

    def supplier(self):
        self.calls.append("supplier")
        return self.secret

    def connector(self, **kwargs):
        self.calls.append("connector")
        self.assertEqual(
            set(kwargs),
            {"host", "port", "dbname", "user", "password", "sslmode",
             "sslrootcert", "gssencmode", "connect_timeout", "options"},
        )
        self.assertEqual(kwargs["password"], self.secret)
        self.assertEqual(kwargs["sslmode"], "verify-full")
        self.assertEqual(kwargs["gssencmode"], "disable")
        self.assertEqual(kwargs["options"], "")
        self.assertEqual(kwargs["connect_timeout"], 5)
        self.assertEqual(kwargs["host"], HOST)
        self.assertEqual(kwargs["user"], RUNNER)
        connection = FakeConnection(kwargs)
        self.connections.append(connection)
        return connection

    def make(self, **overrides):
        args = {"policy": self.policy,
                "secret_supplier": self.supplier,
                "connector": self.connector}
        args.update(overrides)
        return DevelopmentRunnerConnectionFactoryCandidate(**args)

    def test_exact_policy_with_fake_tls_and_role_is_single_attempt(self):
        with patch("socket.create_connection", side_effect=AssertionError("network forbidden")):
            factory = self.make()
            connection = factory()
        self.assertEqual(self.calls, ["supplier", "connector"])
        self.assertTrue(connection.role_set)
        self.assertFalse(connection.closed)
        self.assertIn("set role avuhz_handoff_claim_writer", connection.statements)
        with self.assertRaisesRegex(
            DevelopmentRunnerTransportStop, "HANDOFF_RUNNER_CONNECTION_ATTEMPT_CONSUMED"
        ):
            factory()
        self.assertEqual(self.calls, ["supplier", "connector"])
        self.assertNotIn(self.secret, repr(factory))
        self.assertNotIn(self.secret, repr(connection))
        connection.close()

    def test_policy_rejects_auth_project_wrong_host_and_tls_downgrade(self):
        for field, value in (
            ("project_ref", "pwlhruwutoitnieactol"),
            ("host", "db.pwlhruwutoitnieactol.supabase.co"),
            ("port", 6543),
            ("dbname", "auth"),
            ("user", "postgres"),
            ("sslmode", "require"),
            ("sslmode", "prefer"),
            ("sslrootcert", "relative-ca.pem"),
            ("expected_ca_sha256", "not-a-digest"),
        ):
            with self.subTest(field=field, value=value), self.assertRaisesRegex(
                DevelopmentRunnerTransportStop, "HANDOFF_RUNNER_CONNECTION_POLICY_INVALID"
            ):
                dataclasses.replace(self.policy, **{field: value})
        self.assertEqual(self.calls, [])

    def test_ca_missing_changed_or_symlink_stops_before_credential(self):
        for change in ("changed", "missing", "symlink"):
            with self.subTest(change=change):
                self.ca.write_bytes(b"fictional-test-root-only-not-a-server-certificate\n")
                if change == "changed":
                    self.ca.write_bytes(b"untrusted different certificate material")
                elif change == "missing":
                    self.ca.unlink()
                elif change == "symlink":
                    target = Path(self.temp.name) / "untrusted.pem"
                    target.write_bytes(b"fictional-test-root-only-not-a-server-certificate\n")
                    self.ca.unlink()
                    self.ca.symlink_to(target)
                with self.assertRaisesRegex(
                    DevelopmentRunnerTransportStop, "HANDOFF_RUNNER_CA_UNVERIFIED"
                ):
                    self.make()()
                self.assertEqual(self.calls, [])
                if self.ca.is_symlink():
                    self.ca.unlink()

    def test_effective_libpq_tls_or_host_drift_closes_before_role(self):
        for kind in ("host", "sslmode", "ca", "gssmode"):
            with self.subTest(kind=kind):
                self.calls.clear()
                def connector(**kwargs):
                    connection = self.connector(**kwargs)
                    if kind == "host":
                        connection.info.host = "db.pwlhruwutoitnieactol.supabase.co"
                    elif kind == "sslmode":
                        connection.info.params["sslmode"] = "require"
                    elif kind == "ca":
                        connection.info.params["sslrootcert"] = "/untrusted/ca.pem"
                    else:
                        connection.info.params["gssencmode"] = "prefer"
                    return connection
                with self.assertRaisesRegex(
                    DevelopmentRunnerTransportStop, "HANDOFF_RUNNER_TLS_OR_ENDPOINT_UNVERIFIED"
                ):
                    self.make(connector=connector)()
                self.assertTrue(self.connections[-1].closed)
                self.assertFalse(self.connections[-1].role_set)

    def test_fake_ssl_absent_wrong_runner_or_failed_role_stops_closed(self):
        for kind, code in (
            ("ssl", "HANDOFF_RUNNER_TLS_OR_ENDPOINT_UNVERIFIED"),
            ("identity", "HANDOFF_RUNNER_IDENTITY_UNVERIFIED"),
            ("role", "HANDOFF_RUNNER_ROLE_UNVERIFIED"),
        ):
            with self.subTest(kind=kind):
                def connector(**kwargs):
                    connection = self.connector(**kwargs)
                    if kind == "ssl":
                        connection.tls = (False, None)
                    elif kind == "identity":
                        connection.identity = ("postgres", "postgres", "postgres")
                    else:
                        connection.after_role = (RUNNER, RUNNER)
                    return connection
                with self.assertRaisesRegex(DevelopmentRunnerTransportStop, code):
                    self.make(connector=connector)()
                self.assertTrue(self.connections[-1].closed)

    def test_supplier_or_connector_exception_does_not_expose_material_or_retry(self):
        marker = "fictional-sensitive-driver-error-never-print"
        for where in ("supplier", "connector"):
            with self.subTest(where=where):
                touched = []
                def supplier():
                    touched.append("supplier")
                    if where == "supplier":
                        raise RuntimeError(marker)
                    return self.secret
                def connector(**_):
                    touched.append("connector")
                    raise RuntimeError(marker)
                factory = self.make(secret_supplier=supplier, connector=connector)
                with self.assertRaises(DevelopmentRunnerTransportStop) as context:
                    factory()
                self.assertEqual(str(context.exception), "HANDOFF_RUNNER_CONNECTION_UNVERIFIED")
                self.assertNotIn(marker, repr(context.exception))
                self.assertEqual(touched, ["supplier"] if where == "supplier" else ["supplier", "connector"])
                with self.assertRaisesRegex(
                    DevelopmentRunnerTransportStop, "HANDOFF_RUNNER_CONNECTION_ATTEMPT_CONSUMED"
                ):
                    factory()

    def test_signed_four_stage_bridge_gates_fake_connection_without_live_authority(self):
        fixture = TrustedOneShotExecutorTests(
            methodName="test_four_exact_signed_stage_claims_precede_single_send_and_logout"
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        args = dict(
            request=fixture.f.fixture.command, source=fixture.source,
            github_environment=fixture.env, github_event=fixture.event,
            observed_checkout_sha=fixture.source.canonical_main_sha,
            observed_remote_main_sha=fixture.source.canonical_main_sha,
            observed_git_origin="https://github.com/AnonymousKoo/avuhz-infra",
            at_utc=AT, stages=fixture.f.fixture.stages,
            signed_proofs=fixture.signed_proofs, owner_public_key=fixture.f.public,
            independently_pinned_key_digest=fixture.f.anchor,
            connection_factory=self.make(),
        )
        forged = dict(fixture.signed_proofs)
        proof = forged["DATA_COMMAND"]
        forged["DATA_COMMAND"] = SignedStageProof(
            claims=proof.claims, signature=b"0" * 64,
        )
        with self.assertRaisesRegex(
            TrustedOneShotStop, "HANDOFF_STAGE_OWNER_SIGNATURE_UNVERIFIED"
        ):
            claim_signed_handoff_stages_postgres_candidate(
                **{**args, "signed_proofs": forged}
            )
        self.assertEqual(self.calls, [])
        with self.assertRaisesRegex(
            TrustedOneShotStop, "HANDOFF_TRUSTED_GITHUB_INVOCATION_DENIED"
        ):
            claim_signed_handoff_stages_postgres_candidate(
                **{**args, "observed_remote_main_sha": "f" * 40}
            )
        self.assertEqual(self.calls, [])

        with patch("socket.create_connection", side_effect=AssertionError("network forbidden")):
            receipt = claim_signed_handoff_stages_postgres_candidate(**args)
        self.assertEqual(receipt.claimed_stage_count, 4)
        self.assertFalse(receipt.live_execution_authorized)
        self.assertFalse(receipt.human_owner_binding_verified)
        self.assertFalse(receipt.signed_approval_authority_verified)
        self.assertEqual(len(self.connections[0].inserts), 4)
        self.assertTrue(self.connections[0].closed)
        self.assertEqual(self.calls, ["supplier", "connector"])


if __name__ == "__main__":
    unittest.main()
