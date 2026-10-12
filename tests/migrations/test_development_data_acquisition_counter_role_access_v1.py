"""LOCAL/TEST-only verification of acquisition rate-counter role access.

Runs actual PostgreSQL 17 only against a disposable Docker database.
Does not connect to Supabase AUTH/DATA, Render, n8n, or a real customer.
"""
from __future__ import annotations

import os
import re
import runpy
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from avuhz_service.development_acquisition_rate_limit import _ATOMIC_ADMISSION_SQL

CURRENT = ROOT / "supabase/provider-artifacts/development-data/current"
SOURCE = CURRENT / "development_data_acquisition_counter_role_access_v1.sql"
REGISTRY = CURRENT / "development_data_shared_acquisition_registry_role_v1.sql"
BASE = ROOT / "supabase/migrations/20260831120000_rebaseline_provider_neutral_avuhz.sql"
COUNTER = ROOT / "tests/integration/test_development_data_acquisition_rate_counter_candidate.py"
FIXTURES = (
    "tests/integration/test_development_data_tenant_organization_candidate.py",
    "tests/integration/test_development_data_tenant_owner_membership_candidate.py",
    "tests/integration/test_development_data_acquisition_intake_candidate.py",
)
CONTAINER = os.getenv("AVUHZ_LOCAL_POSTGRES_CONTAINER")
DB = "avuhz_acq_counter_acl_candidate_v1"
ROLE = "avuhz_acquisition_service_dev"
LOGIN = "avuhz_acquisition_runtime_service_dev"
A = "a4730000-0000-4000-8000-000000000001"
B = "a4730000-0000-4000-8000-000000000002"
P = "a" * 64


class AcquisitionCounterAccessStaticTests(unittest.TestCase):
    def test_one_resource_and_no_secret_or_provider_execution(self):
        s = SOURCE.read_text()
        self.assertIn("REVIEW ONLY. NOT AUTHORIZED FOR PROVIDER EXECUTION.", s)
        self.assertIn("DEVELOPMENT DATA gnuqaefotwgkwurjpyik", s)
        self.assertIn("DEVELOPMENT AUTH pwlhruwutoitnieactol", s)
        self.assertIn("ACQ_COUNTER_ACCESS_TABLE_OR_RLS_DRIFT_STOP", s)
        self.assertIn("ACQ_COUNTER_ACCESS_ROLE_DRIFT_STOP", s)
        self.assertIn("ACQ_COUNTER_ACCESS_ACL_DRIFT_STOP", s)
        self.assertIn("ACQ_COUNTER_ACCESS_POSTCONDITION_STOP", s)
        self.assertEqual(s.count("CREATE POLICY avuhz_acquisition_rate_counter_tenant_isolation"), 1)
        self.assertEqual(len(re.findall(r"(?m)^GRANT\s+(?:SELECT|INSERT|UPDATE)\b", s)), 3)
        self.assertIn("FOR ALL TO avuhz_acquisition_service_dev", s)
        self.assertEqual(s.count("current_setting('avuhz.tenant_id', true)"), 2)
        self.assertNotRegex(s, r"(?im)^\s*(?:CREATE ROLE|ALTER ROLE|CREATE TABLE|"
                           r"DROP|REVOKE|DELETE|UPDATE|INSERT|SET ROLE|BEGIN;|COMMIT;)\b")
        self.assertNotRegex(s, r"(?i)PASSWORD\s+'[^']+'")
        self.assertNotIn("TO service_role", s)
        self.assertNotIn("TO avuhz_command_service;", s)
        self.assertNotIn("GRANT DELETE", s)
        self.assertNotIn("GRANT UPDATE (tenant_id", s)
        self.assertNotIn("GRANT UPDATE (principal_digest", s)
        self.assertFalse(any(
            "development_data_acquisition_counter_role_access" in p.name
            for p in (ROOT / "supabase/migrations").glob("*.sql")
        ))
        self.assertEqual((ROOT / "scripts/check-baseline.sh").read_text().count(
            "development_data_acquisition_counter_role_access_v1.sql"), 2)

    def test_shared_limiter_still_uses_same_counter_not_new_billing_auth_path(self):
        source = (ROOT / "src/avuhz_service/development_acquisition_rate_limit.py").read_text()
        self.assertIn("public.avuhz_acquisition_rate_limit_counters", source)
        self.assertIn("on conflict (tenant_id, principal_digest)", source.lower())
        self.assertNotIn("service_role", SOURCE.read_text().split("CREATE POLICY")[1])


@unittest.skipUnless(CONTAINER, "disposable PostgreSQL 17 container required")
class AcquisitionCounterAccessPostgresTests(unittest.TestCase):
    @classmethod
    def docker(cls, *args, data=None, check=True):
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", CONTAINER or "") is None:
            raise AssertionError("UNVERIFIED_DISPOSABLE_CONTAINER")
        x = subprocess.run(
            ["docker", "exec", *(["-i"] if data is not None else []), CONTAINER, *args],
            input=data.encode() if data is not None else None,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=140,
        )
        if check and x.returncode:
            safe = [v for v in x.stderr.decode(errors="replace").splitlines() if "ERROR:" in v]
            msg = re.sub(r"[^a-zA-Z0-9_ .:-]", "", safe[0] if safe else "PG17_FAILED")[:120]
            raise AssertionError("ACQ_COUNTER_DISPOSABLE_FAILED: " + msg)
        return x

    @classmethod
    def sql(cls, query, *, user="postgres", check=True):
        return cls.docker("psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1",
                          "-U", user, "-d", DB, "-c", query, check=check)

    @classmethod
    def apply(cls, source, *, check=True):
        return cls.docker("psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1",
                          "-U", "postgres", "-d", DB, data=source, check=check)

    def setUp(self):
        self.docker("dropdb", "--if-exists", "-U", "postgres", DB)
        self.docker("createdb", "-U", "postgres", DB)
        self.apply(BASE.read_text())
        for path in FIXTURES:
            self.apply(runpy.run_path(str(ROOT / path))["INSTALLATION_CANDIDATE_SQL"])
        self.apply(runpy.run_path(str(COUNTER))["INSTALLATION_CANDIDATE_SQL"])
        self.apply(REGISTRY.read_text())
        # These three already exist in hosted DATA. Only their role/policy
        # count is relevant to this counter-only resource under test.
        self.sql(
            "CREATE POLICY avuhz_acquisition_event_read ON public.avuhz_lifecycle_events "
            f"FOR SELECT TO {ROLE} USING (false);"
            "CREATE POLICY avuhz_acquisition_event_insert ON public.avuhz_lifecycle_events "
            f"FOR INSERT TO {ROLE} WITH CHECK (false);"
            "CREATE POLICY avuhz_acquisition_outbox_insert ON public.avuhz_outbox_deliveries "
            f"FOR INSERT TO {ROLE} WITH CHECK (false);"
        )
        self.sql(
            f"CREATE ROLE {LOGIN} LOGIN PASSWORD NULL CONNECTION LIMIT 1 "
            "NOINHERIT NOSUPERUSER NOBYPASSRLS "
            "NOCREATEDB NOCREATEROLE NOREPLICATION;"
            f"GRANT {ROLE} TO {LOGIN} "
            "WITH ADMIN FALSE, INHERIT FALSE, SET TRUE GRANTED BY CURRENT_USER;"
        )

    def tearDown(self):
        self.docker("dropdb", "--if-exists", "-U", "postgres", DB)
        # Reverse the one SET-only edge before removing disposable roles.
        self.docker("psql", "-X", "-q", "-U", "postgres", "-d", "postgres",
                    "-c", f"REVOKE {ROLE} FROM {LOGIN};", check=False)
        for name in (LOGIN, ROLE):
            self.docker("psql", "-X", "-q", "-U", "postgres", "-d", "postgres",
                        "-c", f"DROP ROLE IF EXISTS {name};", check=False)

    @staticmethod
    def admit(tenant=A, bound=A):
        sql = _ATOMIC_ADMISSION_SQL.replace("%s", f"'{tenant}'", 1).replace(
            "%s", f"'{P}'", 1
        )
        return (f"BEGIN;SET LOCAL ROLE {ROLE};"
                f"SET LOCAL avuhz.tenant_id='{bound}';" + sql + ";COMMIT;")

    def test_exact_acl_and_ten_admissions_but_no_eleventh(self):
        self.apply("BEGIN;\n" + SOURCE.read_text() + "\nCOMMIT;\n")
        state = self.sql(
            "SELECT count(*) FROM pg_policies WHERE schemaname='public' "
            "AND tablename='avuhz_acquisition_rate_limit_counters';"
            f"SELECT pg_has_role('{LOGIN}','{ROLE}','SET')::int;"
            f"SELECT pg_has_role('{LOGIN}','{ROLE}','USAGE')::int;"
            f"SELECT has_table_privilege('{LOGIN}',"
            "'public.avuhz_acquisition_rate_limit_counters','SELECT')::int;"
            f"SELECT has_table_privilege('{ROLE}',"
            "'public.avuhz_acquisition_rate_limit_counters','DELETE')::int;"
            f"SELECT has_column_privilege('{ROLE}',"
            "'public.avuhz_acquisition_rate_limit_counters','tenant_id','UPDATE')::int;"
            f"SELECT has_column_privilege('{ROLE}',"
            "'public.avuhz_acquisition_rate_limit_counters','request_count','UPDATE')::int;"
        ).stdout.decode().splitlines()
        self.assertEqual(state, ["2", "1", "0", "0", "0", "0", "1"])
        for i in range(1, 11):
            self.assertEqual(self.sql(self.admit()).stdout.decode().strip(), str(i))
        self.assertEqual(self.sql(self.admit()).stdout.decode().strip(), "")
        self.assertEqual(self.sql(
            "SELECT request_count FROM public.avuhz_acquisition_rate_limit_counters;"
        ).stdout.decode().strip(), "10")

    def test_missing_scope_cross_tenant_delete_and_broad_role_denied(self):
        self.apply("BEGIN;\n" + SOURCE.read_text() + "\nCOMMIT;\n")
        self.assertEqual(self.sql(self.admit()).stdout.decode().strip(), "1")
        self.assertEqual(self.sql(
            f"BEGIN;SET ROLE {ROLE};SELECT count(*) "
            "FROM public.avuhz_acquisition_rate_limit_counters;ROLLBACK;"
        ).stdout.decode().strip(), "0")
        wrong = self.sql(self.admit(B, A), check=False)
        self.assertNotEqual(wrong.returncode, 0)
        for statement in (
            "DELETE FROM public.avuhz_acquisition_rate_limit_counters;",
            "UPDATE public.avuhz_acquisition_rate_limit_counters "
            "SET tenant_id='a4730000-0000-4000-8000-000000000002';",
            "SELECT * FROM public.avuhz_engagements;",
        ):
            failed = self.sql(f"BEGIN;SET LOCAL ROLE {ROLE};"
                f"SET LOCAL avuhz.tenant_id='{A}';" + statement, check=False)
            self.assertNotEqual(failed.returncode, 0)
        self.assertEqual(self.sql(
            "SELECT count(*) FROM public.avuhz_acquisition_rate_limit_counters"
        ).stdout.decode().strip(), "1")

    def test_transaction_rollback_replay_and_drift_are_fail_closed(self):
        candidate = SOURCE.read_text()
        rollback = self.apply("BEGIN;\n" + candidate + "\nSELECT 1/0;\nCOMMIT;\n",
                              check=False)
        self.assertNotEqual(rollback.returncode, 0)
        self.assertEqual(self.sql(
            "SELECT count(*) FROM pg_policies WHERE schemaname='public' "
            "AND tablename='avuhz_acquisition_rate_limit_counters';"
        ).stdout.decode().strip(), "1")
        self.apply("BEGIN;\n" + candidate + "\nCOMMIT;\n")
        retry = self.apply("BEGIN;\n" + candidate + "\nCOMMIT;\n", check=False)
        self.assertNotEqual(retry.returncode, 0)
        self.assertIn("ACQ_COUNTER_ACCESS_TABLE_OR_RLS_DRIFT_STOP",
                      retry.stderr.decode())

    def test_unexpected_existing_acl_denies_before_change(self):
        self.sql(f"GRANT SELECT (tenant_id) "
                 f"ON public.avuhz_acquisition_rate_limit_counters TO {ROLE};")
        attempted = self.apply("BEGIN;\n" + SOURCE.read_text() + "\nCOMMIT;\n",
                               check=False)
        self.assertNotEqual(attempted.returncode, 0)
        self.assertIn("ACQ_COUNTER_ACCESS_ACL_DRIFT_STOP",
                      attempted.stderr.decode())
        self.assertEqual(self.sql(
            "SELECT count(*) FROM pg_policies WHERE schemaname='public' "
            "AND tablename='avuhz_acquisition_rate_limit_counters';"
        ).stdout.decode().strip(), "1")


if __name__ == "__main__":
    unittest.main()
