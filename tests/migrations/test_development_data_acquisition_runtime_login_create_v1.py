"""Offline certification of ONE dormant DEVELOPMENT DATA acquisition login role.

The SQL file is review-only, never submitted to hosted Supabase. The PostgreSQL
tests use a disposable database plus synthetic prior-stage fixtures.
"""
from __future__ import annotations

import os
import re
import runpy
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SQL = ROOT / ("supabase/provider-artifacts/development-data/current/"
              "development_data_acquisition_runtime_login_create_v1.sql")
REGISTRY = ROOT / ("supabase/provider-artifacts/development-data/current/"
                   "development_data_shared_acquisition_registry_role_v1.sql")
BASE = ROOT / "supabase/migrations/20260831120000_rebaseline_provider_neutral_avuhz.sql"
FIXTURES = (
    "tests/integration/test_development_data_tenant_organization_candidate.py",
    "tests/integration/test_development_data_tenant_owner_membership_candidate.py",
    "tests/integration/test_development_data_acquisition_intake_candidate.py",
)
CONTAINER = os.getenv("AVUHZ_LOCAL_POSTGRES_CONTAINER")
DB = "avuhz_acquisition_runtime_login_candidate_v1"
ROLE = "avuhz_acquisition_runtime_service_dev"
DATA_ROLE = "avuhz_acquisition_service_dev"


class AcquisitionRuntimeLoginStaticTests(unittest.TestCase):
    def test_review_only_one_login_no_grants_or_secret_handoff(self):
        sql = SQL.read_text(encoding="utf-8")
        self.assertIn("REVIEW ONLY. NOT AUTHORIZED FOR PROVIDER EXECUTION", sql)
        self.assertIn("DEVELOPMENT DATA gnuqaefotwgkwurjpyik", sql)
        self.assertIn("DEVELOPMENT AUTH pwlhruwutoitnieactol", sql)
        self.assertIn("CREATE ROLE avuhz_acquisition_runtime_service_dev", sql)
        self.assertIn("LOGIN PASSWORD NULL CONNECTION LIMIT 1", sql)
        self.assertIn("NOINHERIT NOSUPERUSER NOBYPASSRLS", sql)
        self.assertIn("NOCREATEDB NOCREATEROLE NOREPLICATION", sql)
        self.assertIn("ACQ_RUNTIME_LOGIN_OWNER_OR_PREEXISTENCE_STOP", sql)
        self.assertIn("ACQ_RUNTIME_LOGIN_STAGE1_ROLE_DRIFT_STOP", sql)
        self.assertIn("ACQ_RUNTIME_LOGIN_UNEXPECTED_AUTHORITY_STOP", sql)
        self.assertIn("ACQ_RUNTIME_LOGIN_CREATOR_EDGE_STOP", sql)
        self.assertNotRegex(sql, r"(?im)^\s*(?:GRANT|REVOKE|ALTER ROLE|SET ROLE|CREATE TABLE)\b")
        self.assertNotRegex(sql, r"(?i)PASSWORD\s+'[^']+'")
        self.assertNotIn("AVUHZ_POSTGRES_DSN", sql)
        self.assertNotIn("AVUHZ_ACQUISITION_POSTGRES_DSN", sql)
        self.assertNotIn("CREATE POLICY", sql)
        self.assertNotIn("BEGIN;", sql)
        self.assertNotIn("COMMIT;", sql)
        self.assertFalse(any(
            p.name.endswith("acquisition_runtime_login_create_v1.sql")
            for p in (ROOT / "supabase/migrations").glob("*.sql")
        ))
        baseline = (ROOT / "scripts/check-baseline.sh").read_text()
        self.assertEqual(
            baseline.count("development_data_acquisition_runtime_login_create_v1.sql"), 2
        )

    def test_connector_requires_future_distinct_set_only_grant(self):
        connector = (ROOT / "src/avuhz_service/development_acquisition_data.py").read_text()
        self.assertIn('ACQUISITION_RUNTIME_LOGIN = "' + ROLE + '"', connector)
        self.assertIn('ACQUISITION_DATABASE_ROLE = "' + DATA_ROLE + '"', connector)
        self.assertIn('"set role avuhz_acquisition_service_dev"', connector)
        sql = SQL.read_text()
        self.assertNotIn("GRANT avuhz_acquisition_service_dev TO", sql)
        self.assertIn("no membership", sql.lower())


@unittest.skipUnless(CONTAINER, "disposable PostgreSQL 17 required")
class AcquisitionRuntimeLoginDisposablePostgresTests(unittest.TestCase):
    @classmethod
    def docker(cls, *args, text=None, check=True):
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", CONTAINER or "") is None:
            raise AssertionError("UNVERIFIED_DISPOSABLE_CONTAINER")
        r = subprocess.run(
            ["docker", "exec", *(["-i"] if text is not None else []),
             CONTAINER, *args],
            input=text.encode() if text is not None else None,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False, timeout=120,
        )
        if check and r.returncode:
            raise AssertionError("ACQUISITION_LOGIN_DISPOSABLE_TEST_FAILED")
        return r

    @classmethod
    def query(cls, sql, check=True):
        return cls.docker(
            "psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1",
            "-U", "postgres", "-d", DB, "-c", sql, check=check
        )

    @classmethod
    def apply(cls, sql, check=True):
        return cls.docker(
            "psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1",
            "-U", "postgres", "-d", DB, text=sql, check=check
        )

    def setUp(self):
        self.docker("dropdb", "--if-exists", "-U", "postgres", DB)
        self.docker("createdb", "-U", "postgres", DB)
        self.apply(BASE.read_text())
        for file in FIXTURES:
            self.apply(runpy.run_path(str(ROOT / file))["INSTALLATION_CANDIDATE_SQL"])
        self.apply(REGISTRY.read_text())

    def tearDown(self):
        self.docker("dropdb", "--if-exists", "-U", "postgres", DB)
        # PostgreSQL roles are cluster-global even in disposable test databases.
        for role in (ROLE, DATA_ROLE):
            self.docker(
                "psql", "-X", "-q", "-v", "ON_ERROR_STOP=1",
                "-U", "postgres", "-d", "postgres",
                "-c", f"DROP ROLE IF EXISTS {role};", check=False,
            )

    def test_exact_login_created_with_zero_runtime_data_privilege(self):
        self.apply("BEGIN;\n" + SQL.read_text() + "\nCOMMIT;\n")
        result = self.query(
            "SELECT rolcanlogin::int,rolinherit::int,rolsuper::int,"
            "rolbypassrls::int,rolcreatedb::int,rolcreaterole::int,"
            "rolreplication::int,rolconnlimit FROM pg_roles "
            f"WHERE rolname='{ROLE}';"
            f"SELECT pg_has_role('{ROLE}','{DATA_ROLE}','SET')::int;"
            f"SELECT pg_has_role('{ROLE}','avuhz_command_service','MEMBER')::int;"
            "SELECT count(*) FROM information_schema.role_table_grants "
            f"WHERE grantee='{ROLE}';"
            "SELECT count(*) FROM pg_auth_members "
            f"WHERE member='{ROLE}'::regrole;"
        ).stdout.decode().strip().splitlines()
        self.assertEqual(result, ["1|0|0|0|0|0|0|1", "0", "0", "0", "0"])

    def test_missing_or_drifted_stage1_fails_before_role_creation(self):
        self.query(f"ALTER ROLE {DATA_ROLE} LOGIN;")
        failure = self.apply("BEGIN;\n" + SQL.read_text() + "\nCOMMIT;\n", check=False)
        self.assertNotEqual(failure.returncode, 0)
        self.assertIn("ACQ_RUNTIME_LOGIN_STAGE1_ROLE_DRIFT_STOP", failure.stderr.decode())
        self.assertEqual(self.query(
            f"SELECT count(*) FROM pg_roles WHERE rolname='{ROLE}';"
        ).stdout.decode().strip(), "0")

    def test_transaction_failure_rolls_back_and_replay_denied(self):
        failed = self.apply(
            "BEGIN;\n" + SQL.read_text() + "\nSELECT 1/0;\nCOMMIT;\n",
            check=False,
        )
        self.assertNotEqual(failed.returncode, 0)
        self.assertEqual(self.query(
            f"SELECT count(*) FROM pg_roles WHERE rolname='{ROLE}';"
        ).stdout.decode().strip(), "0")
        self.apply("BEGIN;\n" + SQL.read_text() + "\nCOMMIT;\n")
        replay = self.apply("BEGIN;\n" + SQL.read_text() + "\nCOMMIT;\n", check=False)
        self.assertNotEqual(replay.returncode, 0)
        self.assertIn("ACQ_RUNTIME_LOGIN_OWNER_OR_PREEXISTENCE_STOP",
                      replay.stderr.decode())
        self.assertEqual(self.query(
            f"SELECT count(*) FROM pg_roles WHERE rolname='{ROLE}';"
        ).stdout.decode().strip(), "1")


if __name__ == "__main__":
    unittest.main()
