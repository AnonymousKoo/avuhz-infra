"""Review-only DEVELOPMENT AUTH dormant session-reader LOGIN role verification.

The candidate never contacts Supabase. PostgreSQL 17 integration exercises a
disposable synthetic AUTH schema and simulated non-superuser CREATEROLE
executor, without creating a credential or modifying real AUTH-owned tables.
"""
from __future__ import annotations

import os
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / (
    "supabase/provider-artifacts/development-auth/current/"
    "development_auth_owner_session_reader_login_create_v1.sql"
)
CONTAINER = os.getenv("AVUHZ_LOCAL_POSTGRES_CONTAINER")
DB = "avuhz_auth_reader_login_candidate_v1"
READER = "avuhz_owner_session_reader_dev"
EXECUTOR = "avuhz_test_auth_reader_creator_dev"
SCHEMA_OWNER = "avuhz_test_auth_reader_schemaowner_dev"
TABLE_OWNER = "avuhz_test_auth_reader_tableowner_dev"
MIGRATION = "avuhz_migration_service_dev"


class AuthReaderLoginStaticTests(unittest.TestCase):
    def test_one_dormant_identity_only_and_repo_allowlist(self):
        sql = SOURCE.read_text(encoding="utf-8")
        self.assertIn("REVIEW ONLY. NOT AUTHORIZED FOR PROVIDER EXECUTION", sql)
        self.assertIn("DEVELOPMENT AUTH pwlhruwutoitnieactol", sql)
        self.assertIn("DEVELOPMENT DATA gnuqaefotwgkwurjpyik", sql)
        self.assertIn(f"CREATE ROLE {READER}", sql)
        self.assertIn("LOGIN PASSWORD NULL CONNECTION LIMIT 1", sql)
        self.assertIn("NOINHERIT NOSUPERUSER NOBYPASSRLS", sql)
        self.assertIn("NOCREATEDB NOCREATEROLE NOREPLICATION", sql)
        self.assertIn("AUTH_OWNER_READER_LOGIN_EXECUTOR_OR_PREEXISTENCE_STOP", sql)
        self.assertIn("AUTH_OWNER_READER_LOGIN_AUTH_SCHEMA_DRIFT_STOP", sql)
        self.assertIn("AUTH_OWNER_READER_LOGIN_MIGRATION_BOUNDARY_STOP", sql)
        self.assertIn("AUTH_OWNER_READER_LOGIN_POSTCONDITION_STOP", sql)
        self.assertEqual(len(re.findall(r"(?im)^CREATE ROLE\s+", sql)), 1)
        self.assertNotRegex(
            sql, r"(?im)^\s*(?:GRANT|REVOKE|ALTER|SET\s+ROLE|"
                 r"CREATE\s+(?:TABLE|POLICY|SCHEMA)|INSERT|UPDATE|DELETE|DROP|BEGIN;|COMMIT;)\b"
        )
        self.assertNotIn("GRANT SELECT", sql)
        self.assertNotIn("CREATE POLICY", sql)
        self.assertNotRegex(sql, r"(?i)PASSWORD\s+'[^']+'")
        self.assertNotIn("service_role", sql)
        self.assertNotIn("AVUHZ_OWNER_AUTH_SESSION_POSTGRES_DSN=", sql)
        self.assertFalse(any(
            "development_auth_owner_session_reader_login_create_v1" in p.name
            for p in (ROOT / "supabase/migrations").glob("*.sql")
        ))
        self.assertEqual(
            (ROOT / "scripts/check-baseline.sh").read_text().count(
                "development_auth_owner_session_reader_login_create_v1.sql"
            ), 2
        )

    def test_shared_runtime_is_dormant_and_requires_exact_login(self):
        src = (ROOT / "src/avuhz_service/"
               "development_auth_owner_session_record.py").read_text()
        self.assertIn(f'AUTH_OWNER_SESSION_READER_ROLE = "{READER}"', src)
        self.assertIn("verify-full", src)
        self.assertIn("set_config('avuhz.owner_subject', %s, true)", src)
        self.assertIn("_APPROVED_OWNER_SUBJECT_POLICY_NAME", src)
        self.assertNotIn("connection_factory_from_environment(", src)


@unittest.skipUnless(CONTAINER, "disposable PostgreSQL 17 container required")
class AuthReaderLoginPostgres17Tests(unittest.TestCase):
    @classmethod
    def docker(cls, *args, source=None, check=True):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", CONTAINER or ""):
            raise AssertionError("UNVERIFIED_DISPOSABLE_CONTAINER")
        result = subprocess.run(
            ["docker", "exec", *(["-i"] if source is not None else []),
             CONTAINER, *args],
            input=source.encode() if source is not None else None,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False, timeout=120,
        )
        if check and result.returncode:
            safe = [line for line in result.stderr.decode(errors="replace").splitlines()
                    if "ERROR:" in line]
            raise AssertionError(
                "AUTH_READER_LOGIN_DISPOSABLE_FAILED: "
                + re.sub(r"[^a-zA-Z0-9_ .:-]", "",
                         safe[0] if safe else "PG17_FAILED")[:120]
            )
        return result

    @classmethod
    def query(cls, sql, *, role="postgres", check=True):
        return cls.docker(
            "psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1",
            "-U", role, "-d", DB, "-c", sql, check=check,
        )

    @classmethod
    def apply(cls, sql, *, check=True):
        return cls.docker(
            "psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1",
            "-U", EXECUTOR, "-d", DB, source=sql, check=check,
        )

    @staticmethod
    def simulated_sql():
        # Hosted AUTH's postgres is NOSUPERUSER CREATEROLE. In disposable
        # PostgreSQL, the CREATEROLE executor is separate from superuser
        # postgres, and table/schema owners are separate test roles.
        return (SOURCE.read_text(encoding="utf-8")
                .replace("'postgres'", f"'{EXECUTOR}'")
                .replace("'supabase_admin'", f"'{SCHEMA_OWNER}'")
                .replace("'supabase_auth_admin'", f"'{TABLE_OWNER}'"))

    def setUp(self):
        self.docker("dropdb", "--if-exists", "-U", "postgres", DB)
        for role in (READER, EXECUTOR, SCHEMA_OWNER, TABLE_OWNER, MIGRATION):
            self.docker("psql", "-X", "-q", "-U", "postgres", "-d", "postgres",
                        "-c", f"DROP ROLE IF EXISTS {role};", check=False)
        self.docker(
            "psql", "-X", "-q", "-U", "postgres", "-d", "postgres", "-c",
            f"CREATE ROLE {EXECUTOR} LOGIN NOINHERIT NOSUPERUSER "
            "CREATEROLE NOBYPASSRLS NOCREATEDB NOREPLICATION;"
            f"CREATE ROLE {SCHEMA_OWNER} NOLOGIN;"
            f"CREATE ROLE {TABLE_OWNER} NOLOGIN;"
            f"CREATE ROLE {MIGRATION} NOLOGIN NOINHERIT NOBYPASSRLS;"
        )
        self.docker("createdb", "-U", "postgres", DB)
        self.query(
            "CREATE SCHEMA auth;"
            "CREATE TABLE auth.sessions (id uuid,user_id uuid,aal text);"
            "CREATE TABLE auth.mfa_factors (id uuid,user_id uuid,status text);"
            f"ALTER TABLE auth.sessions OWNER TO {TABLE_OWNER};"
            f"ALTER TABLE auth.mfa_factors OWNER TO {TABLE_OWNER};"
            f"ALTER SCHEMA auth OWNER TO {SCHEMA_OWNER};"
            # Hosted AUTH postgres has schema USAGE, not CREATE. The
            # synthetic NOSUPERUSER executor must match that exact state
            # so catalog privilege introspection can resolve auth tables.
            f"GRANT USAGE ON SCHEMA auth TO {EXECUTOR};"
            "ALTER TABLE auth.sessions ENABLE ROW LEVEL SECURITY;"
            "ALTER TABLE auth.mfa_factors ENABLE ROW LEVEL SECURITY;"
        )
        # Disposable test only. Hosted AUTH owner authorization is distinct.
        self.query(f"GRANT SELECT (oid,rolpassword) ON pg_catalog.pg_authid TO {EXECUTOR};")

    def tearDown(self):
        self.docker("dropdb", "--if-exists", "-U", "postgres", DB)
        self.docker(
            "psql", "-X", "-q", "-U", "postgres", "-d", "postgres",
            "-c", f"REVOKE SELECT (oid,rolpassword) "
                  f"ON pg_catalog.pg_authid FROM {EXECUTOR};",
            check=False,
        )
        for role in (READER, EXECUTOR, SCHEMA_OWNER, TABLE_OWNER, MIGRATION):
            self.docker("psql", "-X", "-q", "-U", "postgres", "-d", "postgres",
                        "-c", f"DROP ROLE IF EXISTS {role};", check=False)

    def test_role_flags_and_postgres17_creator_management_edge(self):
        self.apply("BEGIN;\n" + self.simulated_sql() + "\nCOMMIT;\n")
        state = self.query(
            f"SELECT rolcanlogin::int,rolinherit::int,rolsuper::int,"
            f"rolbypassrls::int,rolcreatedb::int,rolcreaterole::int,"
            f"rolreplication::int,rolconnlimit FROM pg_roles WHERE rolname='{READER}';"
            f"SELECT rolpassword IS NULL FROM pg_authid WHERE rolname='{READER}';"
            f"SELECT count(*) FROM pg_auth_members m JOIN pg_roles grantor"
            f" ON grantor.oid=m.grantor WHERE m.roleid='{READER}'::regrole"
            f" AND m.member='{EXECUTOR}'::regrole AND grantor.rolsuper"
            f" AND m.admin_option AND NOT m.set_option AND NOT m.inherit_option;"
            f"SELECT count(*) FROM pg_auth_members WHERE member='{READER}'::regrole;"
            f"SELECT has_table_privilege('{READER}','auth.sessions','SELECT')::int;"
            f"SELECT has_schema_privilege('{READER}','auth','USAGE')::int;"
        ).stdout.decode().strip().splitlines()
        self.assertEqual(
            state, ["1|0|0|0|0|0|0|1", "t", "1", "0", "0", "0"]
        )

    def test_wrong_auth_table_owner_or_missing_rls_denied_before_change(self):
        self.query("ALTER TABLE auth.sessions DISABLE ROW LEVEL SECURITY;")
        failure = self.apply("BEGIN;\n" + self.simulated_sql() + "\nCOMMIT;\n",
                             check=False)
        self.assertNotEqual(failure.returncode, 0)
        self.assertIn("AUTH_OWNER_READER_LOGIN_AUTH_SCHEMA_DRIFT_STOP",
                      failure.stderr.decode())
        self.assertEqual(self.query(
            f"SELECT count(*) FROM pg_roles WHERE rolname='{READER}';"
        ).stdout.decode().strip(), "0")

    def test_rollback_and_replay_denied(self):
        candidate = self.simulated_sql()
        aborted = self.apply(
            "BEGIN;\n" + candidate + "\nSELECT 1/0;\nCOMMIT;\n",
            check=False,
        )
        self.assertNotEqual(aborted.returncode, 0)
        self.assertEqual(self.query(
            f"SELECT count(*) FROM pg_roles WHERE rolname='{READER}';"
        ).stdout.decode().strip(), "0")
        self.apply("BEGIN;\n" + candidate + "\nCOMMIT;\n")
        replay = self.apply(
            "BEGIN;\n" + candidate + "\nCOMMIT;\n", check=False,
        )
        self.assertNotEqual(replay.returncode, 0)
        self.assertIn("AUTH_OWNER_READER_LOGIN_EXECUTOR_OR_PREEXISTENCE_STOP",
                      replay.stderr.decode())


if __name__ == "__main__":
    unittest.main()
