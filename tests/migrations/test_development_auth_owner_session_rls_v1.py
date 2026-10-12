"""Disposable PostgreSQL 17 AUTH session RLS contract tests.

These tests NEVER contact Supabase and do not authorize AUTH schema changes.
They simulate the *expected* future AUTH reader permission envelope and verify
the exact policy serialization that the dormant shared-core checker requires.
Docker uses trust auth solely inside the disposable database.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from avuhz_service.development_auth_owner_session_record import (
    _APPROVED_OWNER_SUBJECT_POLICY_NAME,
    _APPROVED_OWNER_SUBJECT_POLICY_QUAL,
    _SESSION_PROOF_SQL,
    AUTH_OWNER_SESSION_READER_ROLE,
)

CONTAINER = os.getenv("AVUHZ_LOCAL_POSTGRES_CONTAINER")
DB = "avuhz_auth_owner_scope_candidate_v1"
READER = AUTH_OWNER_SESSION_READER_ROLE
OWNER_A = "b4330000-0000-4000-8000-000000000001"
OWNER_B = "b4330000-0000-4000-8000-000000000002"
SESSION_A = "b4330000-0000-4000-8000-000000000011"
SESSION_B = "b4330000-0000-4000-8000-000000000012"
FACTOR_A = "b4330000-0000-4000-8000-000000000021"
FACTOR_B = "b4330000-0000-4000-8000-000000000022"
PREDICATE = (
    "user_id = NULLIF(current_setting('avuhz.owner_subject',true),'')::uuid"
)


@unittest.skipUnless(CONTAINER, "disposable PostgreSQL 17 container required")
class AuthOwnerSessionScopePg17Tests(unittest.TestCase):
    @classmethod
    def docker(cls, *args, check=True):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", CONTAINER or ""):
            raise AssertionError("UNVERIFIED_DISPOSABLE_CONTAINER")
        p = subprocess.run(
            ["docker", "exec", CONTAINER, *args],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False, timeout=120,
        )
        if check and p.returncode:
            details = [l for l in p.stderr.decode(errors="replace").splitlines()
                       if "ERROR:" in l]
            safe = re.sub(r"[^a-zA-Z0-9_ .:-]", "",
                          details[0] if details else "PG17_SETUP_FAILED")[:150]
            raise AssertionError("AUTH_SCOPE_LOCAL_ONLY_FAILED: " + safe)
        return p

    @classmethod
    def query(cls, sql, *, user="postgres", check=True):
        return cls.docker("psql", "-X", "-q", "-At",
                          "-v", "ON_ERROR_STOP=1", "-U", user, "-d", DB,
                          "-c", sql, check=check)

    def setUp(self):
        self.docker("dropdb", "--if-exists", "-U", "postgres", DB)
        self.docker("psql", "-X", "-q", "-U", "postgres", "-d", "postgres",
                    "-c", f"DROP ROLE IF EXISTS {READER};", check=False)
        self.docker("psql", "-X", "-q", "-U", "postgres", "-d", "postgres",
                    "-c", f"CREATE ROLE {READER} LOGIN PASSWORD NULL "
                          "CONNECTION LIMIT 1 NOINHERIT NOSUPERUSER "
                          "NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;")
        self.docker("createdb", "-U", "postgres", DB)
        # Synthetic AUTH schema: Supabase's real auth schema is owned by
        # supabase_auth_admin and its policies CANNOT be changed by the
        # hosted postgres role without separate owner authority.
        self.query(
            "CREATE SCHEMA auth;"
            "CREATE TABLE auth.sessions ("
            "id uuid PRIMARY KEY,user_id uuid NOT NULL,aal text NOT NULL,"
            "not_after timestamptz,factor_id uuid);"
            "CREATE TABLE auth.mfa_factors ("
            "id uuid PRIMARY KEY,user_id uuid NOT NULL,"
            "status text NOT NULL,factor_type text NOT NULL,secret text);"
            "ALTER TABLE auth.sessions ENABLE ROW LEVEL SECURITY;"
            "ALTER TABLE auth.mfa_factors ENABLE ROW LEVEL SECURITY;"
            f"GRANT USAGE ON SCHEMA auth TO {READER};"
            "GRANT SELECT (id,user_id,aal,not_after,factor_id) "
            f"ON auth.sessions TO {READER};"
            "GRANT SELECT (id,user_id,status,factor_type) "
            f"ON auth.mfa_factors TO {READER};"
        )
        for table in ("sessions", "mfa_factors"):
            self.query(
                f"CREATE POLICY {_APPROVED_OWNER_SUBJECT_POLICY_NAME} "
                f"ON auth.{table} FOR SELECT TO {READER} "
                f"USING ({PREDICATE});"
            )
        self.query(
            "INSERT INTO auth.mfa_factors (id,user_id,status,factor_type) VALUES "
            f"('{FACTOR_A}','{OWNER_A}','verified','totp'),"
            f"('{FACTOR_B}','{OWNER_B}','verified','totp');"
            "INSERT INTO auth.sessions (id,user_id,aal,factor_id) VALUES "
            f"('{SESSION_A}','{OWNER_A}','aal2','{FACTOR_A}'),"
            f"('{SESSION_B}','{OWNER_B}','aal2','{FACTOR_B}');"
        )

    def tearDown(self):
        self.docker("dropdb", "--if-exists", "-U", "postgres", DB)
        self.docker("psql", "-X", "-q", "-U", "postgres", "-d", "postgres",
                    "-c", f"DROP ROLE IF EXISTS {READER};", check=False)

    def test_exact_policies_acl_and_canonical_expression(self):
        actual = self.query(
            "SELECT tablename,qual FROM pg_policies WHERE schemaname='auth' "
            "AND tablename IN ('sessions','mfa_factors') ORDER BY tablename;"
        ).stdout.decode().splitlines()
        self.assertEqual(actual, [
            "mfa_factors|" + _APPROVED_OWNER_SUBJECT_POLICY_QUAL,
            "sessions|" + _APPROVED_OWNER_SUBJECT_POLICY_QUAL,
        ])
        # Column-scoped grants do NOT give table-wide SELECT.
        acl = self.query(
            f"SELECT has_table_privilege('{READER}','auth.sessions','SELECT')::int;"
            f"SELECT has_table_privilege('{READER}','auth.mfa_factors','SELECT')::int;"
            f"SELECT has_column_privilege('{READER}','auth.sessions','user_id','SELECT')::int;"
            f"SELECT has_column_privilege('{READER}','auth.mfa_factors','status','SELECT')::int;"
            f"SELECT has_table_privilege('{READER}','auth.sessions','UPDATE')::int;"
        ).stdout.decode().splitlines()
        self.assertEqual(acl, ["0", "0", "1", "1", "0"])

    def test_scoped_boolean_session_proof_and_missing_guc_denial(self):
        # The SQL is the same constant used by the dormant adapter, with
        # two values substituted ONLY in this synthetic SQL fixture.
        q = _SESSION_PROOF_SQL.replace("%s::uuid", f"'{SESSION_A}'::uuid", 1)
        q = q.replace("%s::uuid", f"'{OWNER_A}'::uuid", 1)
        absent = self.query(q, user=READER)
        self.assertEqual(absent.stdout.decode().strip(), "f")
        scoped = self.query(
            "BEGIN READ ONLY;"
            f"SELECT set_config('avuhz.owner_subject','{OWNER_A}',true);"
            + q + ";ROLLBACK;", user=READER,
        ).stdout.decode().splitlines()
        self.assertEqual(scoped[-1], "t")
        outsider = self.query(
            "BEGIN READ ONLY;"
            f"SELECT set_config('avuhz.owner_subject','{OWNER_B}',true);"
            + q + ";ROLLBACK;", user=READER,
        ).stdout.decode().splitlines()
        self.assertEqual(outsider[-1], "f")

    def test_owner_scoping_is_not_itself_identity_and_write_is_denied(self):
        # Database GUCs can be set by a role that has a SQL connection.
        # This is NOT proof of the bearer or the owner's business. The
        # independently verified signed AUTH token must select the subject.
        read = self.query(
            "BEGIN READ ONLY;"
            f"SELECT set_config('avuhz.owner_subject','{OWNER_B}',true);"
            "SELECT count(*) FROM auth.sessions;"
            "ROLLBACK;", user=READER,
        ).stdout.decode().splitlines()
        self.assertEqual(read[-1], "1")
        for sql in (
            "DELETE FROM auth.sessions;",
            "UPDATE auth.mfa_factors SET status='verified';",
            "SELECT secret FROM auth.mfa_factors;",
        ):
            failed = self.query(sql, user=READER, check=False)
            self.assertNotEqual(failed.returncode, 0)


if __name__ == "__main__":
    unittest.main()
