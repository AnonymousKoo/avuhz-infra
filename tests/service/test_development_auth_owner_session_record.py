"""Offline-only tests for the dormant DEVELOPMENT AUTH exact-session verifier.

Never connects to hosted AUTH, DATA, or production and uses no credentials.
The in-memory doubles demonstrate fail-closed query/connection behavior only,
not actual Supabase session enforcement or an approved provider grant.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_service.development_auth_owner_session_record import (
    AUTH_DATABASE_PORT, AUTH_DIRECT_DATABASE_HOST, AUTH_OWNER_SESSION_READER_ROLE,
    AUTH_REQUIRED_SSLMODE, DEVELOPMENT_AUTH_PROJECT_REF,
    DEVELOPMENT_DATA_PROJECT_REF, DevelopmentAuthSessionRecordCheck,
    _BIND_OWNER_SUBJECT_SQL, _APPROVED_OWNER_SUBJECT_POLICY_NAME,
    _APPROVED_OWNER_SUBJECT_POLICY_QUAL, _ROLE_PREFLIGHT_SQL,
    _SESSION_PROOF_SQL,
)

SUBJECT = "a4730000-0000-4000-8000-000000000101"
SESSION = "a4730000-0000-4000-8000-000000000102"


class FakeInfo:
    def __init__(self, *, host=AUTH_DIRECT_DATABASE_HOST,
                 port=AUTH_DATABASE_PORT, sslmode=AUTH_REQUIRED_SSLMODE,
                 user=AUTH_OWNER_SESSION_READER_ROLE):
        self.host = host
        self.port = port
        self.user = user
        self.sslmode = sslmode

    def get_parameters(self):
        return {"sslmode": self.sslmode}


class FakeCursor:
    def __init__(self, row):
        self.row = row

    def fetchone(self):
        return self.row


class FakeConnection:
    def __init__(self, *, authorized=True, session_found=True, info=None,
                 autocommit=False, failure=None, scoped_subject=SUBJECT):
        self.autocommit = autocommit
        self.info = FakeInfo() if info is None else info
        self.authorized = authorized
        self.session_found = session_found
        self.scoped_subject = scoped_subject
        self.failure = failure
        self.commands = []
        self.closed = 0
        self.rolled_back = 0

    def execute(self, statement, parameters=()):
        self.commands.append((statement, parameters))
        if self.failure is not None:
            raise self.failure
        if statement == _ROLE_PREFLIGHT_SQL:
            return FakeCursor({"approved_reader": self.authorized})
        if statement == _BIND_OWNER_SUBJECT_SQL:
            return FakeCursor({"owner_subject": self.scoped_subject})
        if statement == _SESSION_PROOF_SQL:
            return FakeCursor({"current_verified_session": self.session_found})
        if statement.startswith("SET TRANSACTION READ ONLY"):
            return FakeCursor(None)
        if statement.startswith("SET LOCAL statement_timeout"):
            return FakeCursor(None)
        raise AssertionError("unreviewed SQL statement")

    def rollback(self):
        self.rolled_back += 1

    def close(self):
        self.closed += 1


class AuthSessionRecordVerificationTests(unittest.TestCase):
    def probe(self, connection):
        calls = []
        def factory():
            calls.append(True)
            return connection
        return DevelopmentAuthSessionRecordCheck(factory), calls

    def test_exact_project_is_auth_not_data_and_no_provider_connection(self):
        self.assertEqual(DEVELOPMENT_AUTH_PROJECT_REF, "pwlhruwutoitnieactol")
        self.assertEqual(DEVELOPMENT_DATA_PROJECT_REF, "gnuqaefotwgkwurjpyik")
        self.assertEqual(AUTH_DIRECT_DATABASE_HOST,
                         "db.pwlhruwutoitnieactol.supabase.co")
        self.assertEqual(AUTH_REQUIRED_SSLMODE, "verify-full")
        self.assertEqual(AUTH_OWNER_SESSION_READER_ROLE,
                         "avuhz_owner_session_reader_dev")
        with self.assertRaises(ValueError):
            DevelopmentAuthSessionRecordCheck(None)

    def test_exact_read_only_session_and_verified_totp_factor(self):
        conn = FakeConnection()
        checker, calls = self.probe(conn)
        self.assertTrue(checker(SUBJECT, SESSION))
        self.assertEqual(len(calls), 1)
        self.assertEqual(conn.commands[0], ("SET TRANSACTION READ ONLY", ()))
        self.assertEqual(conn.commands[1],
                         ("SET LOCAL statement_timeout = '3000ms'", ()))
        self.assertEqual(conn.commands[2],
                         (_ROLE_PREFLIGHT_SQL, (
                             AUTH_OWNER_SESSION_READER_ROLE,
                             AUTH_OWNER_SESSION_READER_ROLE,
                             _APPROVED_OWNER_SUBJECT_POLICY_NAME,
                             _APPROVED_OWNER_SUBJECT_POLICY_QUAL,
                         )))
        self.assertEqual(conn.commands[3],
                         (_BIND_OWNER_SUBJECT_SQL, (SUBJECT,)))
        self.assertEqual(conn.commands[4],
                         (_SESSION_PROOF_SQL, (SESSION, SUBJECT)))
        self.assertIn("session.id=%s::uuid", _SESSION_PROOF_SQL)
        self.assertIn("session.user_id=%s::uuid", _SESSION_PROOF_SQL)
        self.assertIn("session.not_after IS NULL OR session.not_after>now()",
                      _SESSION_PROOF_SQL)
        self.assertIn("session.aal='aal2'", _SESSION_PROOF_SQL)
        self.assertIn("factor.id=session.factor_id", _SESSION_PROOF_SQL)
        self.assertIn("factor.user_id=session.user_id", _SESSION_PROOF_SQL)
        self.assertIn("factor.status='verified'", _SESSION_PROOF_SQL)
        self.assertIn("factor.factor_type='totp'", _SESSION_PROOF_SQL)
        self.assertEqual(conn.rolled_back, 1)
        self.assertEqual(conn.closed, 1)

    def test_invalid_subject_or_session_denied_without_db_call(self):
        checker, calls = self.probe(FakeConnection())
        for sub, session in (
            ("bad", SESSION), (SUBJECT, "bad"),
            (SUBJECT.upper(), SESSION), (SUBJECT, SESSION.upper()),
            (SUBJECT, SESSION + " trailing"), (SUBJECT, None),
            (None, SESSION), ("' OR 1=1--", SESSION), (1, SESSION),
        ):
            self.assertFalse(checker(sub, session))
        self.assertEqual(calls, [])

    def test_subject_binding_must_match_exact_verified_auth_subject(self):
        for scoped in (None, False, 1, "false", SESSION,
                       "a4730000-0000-4000-8000-000000000999"):
            with self.subTest(scoped=repr(scoped)):
                conn = FakeConnection(scoped_subject=scoped)
                checker, _ = self.probe(conn)
                self.assertFalse(checker(SUBJECT, SESSION))
                self.assertEqual(conn.commands[-1],
                                 (_BIND_OWNER_SUBJECT_SQL, (SUBJECT,)))
                self.assertNotIn(_SESSION_PROOF_SQL,
                                 [item[0] for item in conn.commands])
                self.assertEqual(conn.rolled_back, 1)
                self.assertEqual(conn.closed, 1)

    def test_exact_policy_shape_checked_before_scope_binding(self):
        self.assertEqual(_APPROVED_OWNER_SUBJECT_POLICY_NAME,
                         "avuhz_owner_session_reader_dev_scope")
        self.assertEqual(_APPROVED_OWNER_SUBJECT_POLICY_QUAL,
                         "(user_id = (NULLIF(current_setting("
                         "'avuhz.owner_subject'::text, true), ''::text))::uuid)")
        self.assertIn("p.policyname=%s", _ROLE_PREFLIGHT_SQL)
        self.assertIn("p.qual=%s", _ROLE_PREFLIGHT_SQL)
        self.assertIn("p.roles=ARRAY['avuhz_owner_session_reader_dev']::name[]",
                      _ROLE_PREFLIGHT_SQL)
        self.assertIn("p.permissive='PERMISSIVE'", _ROLE_PREFLIGHT_SQL)
        self.assertIn("p.with_check IS NULL", _ROLE_PREFLIGHT_SQL)
        self.assertIn("AND p.tablename IN ('sessions','mfa_factors'))=2",
                      _ROLE_PREFLIGHT_SQL)
        self.assertIn("c.relrowsecurity)=2", _ROLE_PREFLIGHT_SQL)
        self.assertIn("set_config('avuhz.owner_subject', %s, true)",
                      _BIND_OWNER_SUBJECT_SQL)

    def test_missing_revoked_wrong_subject_or_nonboolean_session_denied(self):
        for state in (False, 1, "true", None):
            with self.subTest(found=repr(state)):
                conn = FakeConnection(session_found=state)
                check, _ = self.probe(conn)
                self.assertFalse(check(SUBJECT, SESSION))
                self.assertEqual(conn.rolled_back, 1)
                self.assertEqual(conn.closed, 1)

    def test_role_verification_missing_denies_before_session_sql(self):
        for state in (False, 1, "true", None):
            with self.subTest(approved=repr(state)):
                conn = FakeConnection(authorized=state)
                check, _ = self.probe(conn)
                self.assertFalse(check(SUBJECT, SESSION))
                self.assertEqual(len(conn.commands), 3)
                self.assertEqual(conn.closed, 1)
                self.assertEqual(conn.rolled_back, 1)

    def test_wrong_project_tls_port_role_or_autocommit_denied_before_query(self):
        for kwargs in (
            {"info": FakeInfo(host="db.gnuqaefotwgkwurjpyik.supabase.co")},
            {"info": FakeInfo(host="localhost")},
            {"info": FakeInfo(port=6543)},
            {"info": FakeInfo(sslmode="require")},
            {"info": FakeInfo(sslmode="disable")},
            {"info": FakeInfo(user="postgres")},
            {"info": FakeInfo(user="service_role")},
            {"autocommit": True},
        ):
            with self.subTest(kwargs=repr(kwargs)):
                conn = FakeConnection(**kwargs)
                check, _ = self.probe(conn)
                self.assertFalse(check(SUBJECT, SESSION))
                self.assertEqual(conn.commands, [])
                self.assertEqual(conn.closed, 1)

    def test_no_login_elevation_table_wide_acl_or_write_grants(self):
        self.assertIn("NOT r.rolsuper", _ROLE_PREFLIGHT_SQL)
        self.assertIn("NOT r.rolbypassrls", _ROLE_PREFLIGHT_SQL)
        self.assertIn("NOT r.rolinherit", _ROLE_PREFLIGHT_SQL)
        self.assertIn("r.rolconnlimit=1", _ROLE_PREFLIGHT_SQL)
        self.assertIn("count(*) FROM pg_catalog.pg_auth_members", _ROLE_PREFLIGHT_SQL)
        self.assertIn("NOT has_schema_privilege(current_user,'auth','CREATE')",
                      _ROLE_PREFLIGHT_SQL)
        self.assertIn("NOT has_table_privilege(current_user,'auth.sessions','SELECT')",
                      _ROLE_PREFLIGHT_SQL)
        self.assertIn("NOT has_table_privilege(current_user,'auth.mfa_factors','SELECT')",
                      _ROLE_PREFLIGHT_SQL)
        self.assertIn("'INSERT,UPDATE,DELETE,TRUNCATE'", _ROLE_PREFLIGHT_SQL)
        self.assertIn("c.relrowsecurity)=2", _ROLE_PREFLIGHT_SQL)
        self.assertNotIn("auth.users", _SESSION_PROOF_SQL)
        self.assertNotIn("auth.refresh_tokens", _SESSION_PROOF_SQL)

    def test_bounded_failures_and_close_even_on_exception(self):
        conn = FakeConnection(failure=RuntimeError("private provider connection info"))
        checker, _ = self.probe(conn)
        self.assertFalse(checker(SUBJECT, SESSION))
        self.assertEqual(conn.closed, 1)
        self.assertEqual(conn.rolled_back, 1)

    def test_fails_closed_for_missing_connection(self):
        checker = DevelopmentAuthSessionRecordCheck(lambda: None)
        self.assertFalse(checker(SUBJECT, SESSION))

    def test_server_verified_sub_and_session_parameter_order(self):
        conn = FakeConnection()
        checker, _ = self.probe(conn)
        self.assertTrue(checker(SUBJECT, SESSION))
        sql, params = conn.commands[-1]
        self.assertIs(sql, _SESSION_PROOF_SQL)
        self.assertEqual(params, (SESSION, SUBJECT))
        self.assertEqual(conn.commands[-2],
                         (_BIND_OWNER_SUBJECT_SQL, (SUBJECT,)))
        self.assertNotIn(SUBJECT, sql)
        self.assertNotIn(SESSION, sql)


if __name__ == "__main__":
    unittest.main()
