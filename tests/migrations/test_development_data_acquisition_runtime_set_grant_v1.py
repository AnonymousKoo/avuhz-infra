"""Review-only DEVELOPMENT DATA acquisition login SET-only grant certification.

No hosted SQL, credentials, migrations, Render, AUTH or customer operations.
Disposable PG17 tests simulate the non-superuser hosted role creator and
exercise the exact statement with only the executor/superuser names replaced.
"""
from __future__ import annotations

import os
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / ("supabase/provider-artifacts/development-data/current/"
                 "development_data_acquisition_runtime_set_grant_v1.sql")
LOGIN_SOURCE = ROOT / ("supabase/provider-artifacts/development-data/current/"
                       "development_data_acquisition_runtime_login_create_v1.sql")
CONTAINER = os.getenv("AVUHZ_LOCAL_POSTGRES_CONTAINER")
DB = "avuhz_acquisition_set_grant_candidate_v1"
EXECUTOR = "avuhz_acq_set_grant_executor_dev"
LOGIN = "avuhz_acquisition_runtime_service_dev"
ACQUISITION = "avuhz_acquisition_service_dev"
COMMAND = "avuhz_command_service"
MIGRATION = "avuhz_data_migration_service_dev"
TENANT_A = "aadd0000-0000-4000-8000-000000000001"
TENANT_B = "aadd0000-0000-4000-8000-000000000002"
PREDICATE = (
    "tenant_id = nullif(current_setting('avuhz.tenant_id',true),'')::uuid"
)


class AcquisitionRuntimeSetGrantStaticTests(unittest.TestCase):
    def test_single_set_only_membership_and_artifact_allowlist(self):
        sql = SOURCE.read_text(encoding="utf-8")
        self.assertIn("REVIEW ONLY; NOT AUTHORIZED FOR PROVIDER EXECUTION", sql)
        self.assertIn("gnuqaefotwgkwurjpyik ONLY", sql)
        self.assertIn("pwlhruwutoitnieactol", sql)
        self.assertIn("WITH ADMIN FALSE, INHERIT FALSE, SET TRUE", sql)
        self.assertIn("GRANTED BY CURRENT_USER", sql)
        self.assertIn("ACQ_SET_GRANT_ROLE_OR_MEMBERSHIP_DRIFT_STOP", sql)
        self.assertIn("ACQ_SET_GRANT_RLS_OR_PRIVILEGE_DRIFT_STOP", sql)
        self.assertIn("ACQ_SET_GRANT_POSTCONDITION_STOP", sql)
        self.assertEqual(len(re.findall(r"(?im)^GRANT\s+avuhz_acquisition_service_dev\b", sql)), 1)
        self.assertNotRegex(
            sql,
            r"(?im)^\s*(?:CREATE\s+(?:ROLE|TABLE|POLICY)|ALTER|REVOKE|"
            r"INSERT|UPDATE|DELETE|DROP|TRUNCATE|SET\s+ROLE|BEGIN;|COMMIT;)\b",
        )
        self.assertFalse(any(
            "development_data_acquisition_runtime_set_grant" in p.name
            for p in (ROOT / "supabase/migrations").glob("*.sql")
        ))
        baseline = (ROOT / "scripts/check-baseline.sh").read_text()
        self.assertEqual(
            baseline.count("development_data_acquisition_runtime_set_grant_v1.sql"), 2
        )
        connector = (ROOT / "src/avuhz_service/development_acquisition_data.py").read_text()
        self.assertIn('_ACQUISITION_ROLE_GRANTOR = "postgres"', connector)
        self.assertIn('ACQUISITION_DATABASE_ROLE = "' + ACQUISITION + '"', connector)

    def test_no_credentials_provider_mutations_or_live_binding(self):
        sql = SOURCE.read_text()
        self.assertIn("PASSWORD NULL", sql)
        self.assertIn("An arbitrary avuhz.tenant_id session GUC", sql)
        self.assertNotRegex(sql, r"(?i)PASSWORD\s+'[^']+'")
        self.assertNotIn("AVUHZ_ACQUISITION_POSTGRES_DSN=", sql)
        self.assertNotIn("service_role TO", sql)
        self.assertNotIn("GRANT avuhz_command_service TO", sql)
        self.assertNotIn("GRANT avuhz_data_migration_service_dev TO", sql)


@unittest.skipUnless(CONTAINER, "disposable PostgreSQL 17 container required")
class AcquisitionRuntimeSetGrantPostgresTests(unittest.TestCase):
    @classmethod
    def docker(cls, *args, source=None, check=True):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", CONTAINER or ""):
            raise AssertionError("INVALID_DISPOSABLE_CONTAINER")
        p = subprocess.run(
            ["docker", "exec", *(["-i"] if source is not None else []),
             CONTAINER, *args],
            input=source.encode() if source is not None else None,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=120,
        )
        if check and p.returncode:
            safe = re.sub(r"[^a-zA-Z0-9_ .:-]", "",
                          p.stderr.decode(errors="replace").splitlines()[-1])[:150]
            raise AssertionError("DISPOSABLE_SET_GRANT_TEST_FAILED: " + safe)
        return p

    @classmethod
    def query(cls, sql, *, user=EXECUTOR, check=True):
        return cls.docker(
            "psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1",
            "-U", user, "-d", DB, "-c", sql, check=check,
        )

    @classmethod
    def apply(cls, sql, *, user=EXECUTOR, check=True):
        return cls.docker(
            "psql", "-X", "-q", "-v", "ON_ERROR_STOP=1",
            "-U", user, "-d", DB, source=sql, check=check,
        )

    @staticmethod
    def synthetic_sql():
        # On Supabase, postgres is non-superuser and gets management edges
        # from supabase_admin (superuser). The disposable database gives the
        # same management edges to a local CREATEROLE executor from postgres.
        sql = SOURCE.read_text()
        return (sql.replace("'postgres'", "'" + EXECUTOR + "'")
                   .replace("'supabase_admin'", "'postgres'"))

    def setUp(self):
        self.docker("dropdb", "--if-exists", "-U", "postgres", DB)
        for role in (LOGIN, ACQUISITION, COMMAND, MIGRATION, EXECUTOR):
            self.docker("psql", "-X", "-q", "-U", "postgres", "-d", "postgres",
                        "-c", f"DROP ROLE IF EXISTS {role};", check=False)
        self.docker(
            "psql", "-X", "-q", "-U", "postgres", "-d", "postgres", "-c",
            f"CREATE ROLE {EXECUTOR} LOGIN NOSUPERUSER CREATEROLE "
            "NOINHERIT NOCREATEDB NOREPLICATION NOBYPASSRLS;"
        )
        self.docker("createdb", "-U", "postgres", "-O", EXECUTOR, DB)
        # Local simulator only: Supabase's postgres provider role can read
        # pg_authid; grant those two columns to the disposable test executor.
        self.query(
            f"GRANT SELECT (oid,rolpassword) ON pg_catalog.pg_authid "
            f"TO {EXECUTOR};", user="postgres"
        )
        self.query(
            f"CREATE ROLE {COMMAND} NOLOGIN NOINHERIT NOBYPASSRLS;"
            f"CREATE ROLE {MIGRATION} NOLOGIN NOINHERIT NOBYPASSRLS;",
            user="postgres",
        )
        self.query(
            f"CREATE ROLE {ACQUISITION} NOLOGIN NOINHERIT NOBYPASSRLS "
            "NOCREATEDB NOCREATEROLE NOREPLICATION;"
            f"CREATE ROLE {LOGIN} LOGIN PASSWORD NULL CONNECTION LIMIT 1 "
            "NOINHERIT NOSUPERUSER NOBYPASSRLS "
            "NOCREATEDB NOCREATEROLE NOREPLICATION;"
        )
        self.query(
            "CREATE TABLE public.avuhz_tenant_organizations (tenant_id uuid);"
            "CREATE TABLE public.avuhz_tenant_owner_memberships (tenant_id uuid);"
            "CREATE TABLE public.avuhz_acquisition_intake_requests "
            "(tenant_id uuid,contact_email text);"
            "CREATE TABLE public.avuhz_lifecycle_events (tenant_id uuid);"
            "CREATE TABLE public.avuhz_outbox_deliveries (tenant_id uuid);"
        )
        for table in (
            "avuhz_tenant_organizations",
            "avuhz_tenant_owner_memberships",
            "avuhz_acquisition_intake_requests",
            "avuhz_lifecycle_events",
            "avuhz_outbox_deliveries",
        ):
            self.query("ALTER TABLE public." + table + " ENABLE ROW LEVEL SECURITY;")
            if table not in ("avuhz_lifecycle_events", "avuhz_outbox_deliveries"):
                self.query("ALTER TABLE public." + table + " FORCE ROW LEVEL SECURITY;")
                self.query(
                    f"CREATE POLICY avuhz_acquisition_select ON public.{table} "
                    f"FOR SELECT TO {ACQUISITION} USING ({PREDICATE});"
                )
                self.query(
                    f"CREATE POLICY avuhz_acquisition_lock_only ON public.{table} "
                    f"FOR UPDATE TO {ACQUISITION} USING ({PREDICATE}) "
                    "WITH CHECK (false);"
                )
        self.query(
            "CREATE POLICY avuhz_acquisition_intake_insert "
            f"ON public.avuhz_acquisition_intake_requests FOR INSERT TO {ACQUISITION} "
            f"WITH CHECK ({PREDICATE});"
            "CREATE POLICY avuhz_acquisition_event_read "
            f"ON public.avuhz_lifecycle_events FOR SELECT TO {ACQUISITION} "
            f"USING ({PREDICATE});"
            "CREATE POLICY avuhz_acquisition_event_insert "
            f"ON public.avuhz_lifecycle_events FOR INSERT TO {ACQUISITION} "
            f"WITH CHECK ({PREDICATE});"
            "CREATE POLICY avuhz_acquisition_outbox_insert "
            f"ON public.avuhz_outbox_deliveries FOR INSERT TO {ACQUISITION} "
            f"WITH CHECK ({PREDICATE});"
            f"GRANT SELECT (tenant_id) ON public.avuhz_tenant_organizations "
            f"TO {ACQUISITION};"
            "GRANT INSERT (contact_email) "
            f"ON public.avuhz_acquisition_intake_requests TO {ACQUISITION};"
        )
        self.query(
            f"INSERT INTO public.avuhz_tenant_organizations (tenant_id) "
            f"VALUES ('{TENANT_A}'),('{TENANT_B}');"
        )

    def tearDown(self):
        self.docker("dropdb", "--if-exists", "-U", "postgres", DB)
        for role in (LOGIN, ACQUISITION, COMMAND, MIGRATION, EXECUTOR):
            self.docker("psql", "-X", "-q", "-U", "postgres", "-d", "postgres",
                        "-c", f"DROP ROLE IF EXISTS {role};", check=False)

    def test_set_membership_exact_and_isolation_preserved(self):
        self.apply("BEGIN;\n" + self.synthetic_sql() + "\nCOMMIT;\n")
        roles = self.query(
            f"SELECT pg_has_role('{LOGIN}','{ACQUISITION}','SET')::int;"
            f"SELECT pg_has_role('{LOGIN}','{ACQUISITION}','USAGE')::int;"
            f"SELECT pg_has_role('{LOGIN}','{COMMAND}','MEMBER')::int;"
            f"SELECT has_table_privilege('{LOGIN}',"
            "'public.avuhz_tenant_organizations','SELECT')::int;"
            "SELECT count(*) FROM pg_auth_members "
            f"WHERE member='{LOGIN}'::regrole;"
            "SELECT count(*) FROM pg_auth_members "
            f"WHERE roleid='{ACQUISITION}'::regrole;"
        ).stdout.decode().splitlines()
        self.assertEqual(roles, ["1", "0", "0", "0", "1", "2"])
        # The Docker test container has trust auth; this is NOT hosted auth
        # proof. An explicit SET ROLE must still obey the transaction's RLS.
        scoped = self.query(
            f"BEGIN; SET ROLE {ACQUISITION};"
            f"SET LOCAL avuhz.tenant_id='{TENANT_A}';"
            "SELECT count(*) FROM public.avuhz_tenant_organizations;"
            "ROLLBACK;", user=LOGIN
        ).stdout.decode().splitlines()
        self.assertEqual(scoped, ["1"])
        missing = self.query(
            f"BEGIN; SET ROLE {ACQUISITION};"
            "SELECT count(*) FROM public.avuhz_tenant_organizations;"
            "ROLLBACK;", user=LOGIN
        ).stdout.decode().splitlines()
        self.assertEqual(missing, ["0"])
        denied = self.query(
            f"BEGIN; SET ROLE {COMMAND};", user=LOGIN, check=False
        )
        self.assertNotEqual(denied.returncode, 0)

    def test_rollback_and_replay_fail_closed(self):
        sql = self.synthetic_sql()
        failed = self.apply(
            "BEGIN;\n" + sql + "\nSELECT 1/0;\nCOMMIT;\n", check=False
        )
        self.assertNotEqual(failed.returncode, 0)
        self.assertEqual(self.query(
            f"SELECT pg_has_role('{LOGIN}','{ACQUISITION}','SET')::int;"
        ).stdout.decode().strip(), "0")
        self.apply("BEGIN;\n" + sql + "\nCOMMIT;\n")
        replay = self.apply("BEGIN;\n" + sql + "\nCOMMIT;\n", check=False)
        self.assertNotEqual(replay.returncode, 0)
        self.assertIn("ACQ_SET_GRANT_ROLE_OR_MEMBERSHIP_DRIFT_STOP",
                      replay.stderr.decode())

    def test_rls_drift_and_rogue_membership_stop_before_grant(self):
        sql = self.synthetic_sql()
        self.query(
            "DROP POLICY avuhz_acquisition_intake_insert "
            "ON public.avuhz_acquisition_intake_requests;"
        )
        failed = self.apply("BEGIN;\n" + sql + "\nCOMMIT;\n", check=False)
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn("ACQ_SET_GRANT_RLS_OR_PRIVILEGE_DRIFT_STOP",
                      failed.stderr.decode())
        self.query(
            "CREATE POLICY avuhz_acquisition_intake_insert "
            f"ON public.avuhz_acquisition_intake_requests FOR INSERT TO "
            f"{ACQUISITION} WITH CHECK ({PREDICATE});"
        )
        self.query(f"GRANT {COMMAND} TO {LOGIN};", user="postgres")
        denied = self.apply("BEGIN;\n" + sql + "\nCOMMIT;\n", check=False)
        self.assertNotEqual(denied.returncode, 0)
        self.assertIn("ACQ_SET_GRANT_ROLE_OR_MEMBERSHIP_DRIFT_STOP",
                      denied.stderr.decode())
        self.assertEqual(self.query(
            f"SELECT pg_has_role('{LOGIN}','{ACQUISITION}','SET')::int;"
        ).stdout.decode().strip(), "0")


if __name__ == "__main__":
    unittest.main()
