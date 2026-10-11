"""Single-resource DEVELOPMENT DATA shared acquisition rate-counter candidate.

This file is executable only against DISPOSABLE local PostgreSQL 17 during
tests. It intentionally lives OUTSIDE supabase/migrations: the automatic
migration chain is not bound to one Supabase project. Never apply it to a
hosted provider without a fresh exact authorization, immutable SQL digest,
project/environment preflight and independent post-apply verification.

Future target only: DEVELOPMENT DATA gnuqaefotwgkwurjpyik.
Distinct AUTH project pwlhruwutoitnieactol must NEVER receive this table.
No real client/company/owner records, credentials or other provider writes.
The shared Avuhz rate limiter is not hosted, and SekInfra public intake
remains disabled. The table counter is deliberately PII-free; one row per
previously authenticated tenant/service-principal hash, not per prospect.
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

from avuhz_service.development_acquisition_rate_limit import (
    _ATOMIC_ADMISSION_SQL,
)

BASELINE = ROOT / "supabase/migrations/20260831120000_rebaseline_provider_neutral_avuhz.sql"
PARENT_FILE = ROOT / "tests/integration/test_development_data_tenant_organization_candidate.py"
INTAKE_FILE = ROOT / "tests/integration/test_development_data_acquisition_intake_candidate.py"
PARENT_SQL = runpy.run_path(str(PARENT_FILE))["INSTALLATION_CANDIDATE_SQL"]
INTAKE_SQL = runpy.run_path(str(INTAKE_FILE))["INSTALLATION_CANDIDATE_SQL"]
CONTAINER = os.getenv("AVUHZ_LOCAL_POSTGRES_CONTAINER")
DATABASE = "avuhz_acquisition_rate_counter_v1"
TENANT_A = "a4730000-0000-4000-8000-000000000001"
TENANT_B = "a4730000-0000-4000-8000-000000000002"
PRINCIPAL_A = "a" * 64
PRINCIPAL_B = "b" * 64

INSTALLATION_CANDIDATE_SQL = r"""
BEGIN;

DO $avuhz_acquisition_rate_counter_preflight$
BEGIN
  IF to_regclass('public.avuhz_acquisition_rate_limit_counters') IS NOT NULL THEN
    RAISE EXCEPTION 'ACQUISITION_COUNTER_PREEXISTING_RESOURCE_STOP';
  END IF;

  IF to_regclass('public.avuhz_acquisition_intake_requests') IS NULL
     OR NOT EXISTS (
       SELECT 1 FROM pg_class
       WHERE oid=to_regclass('public.avuhz_acquisition_intake_requests')
         AND relrowsecurity AND relforcerowsecurity
     )
     OR NOT EXISTS (
       SELECT 1 FROM pg_roles
       WHERE rolname='avuhz_command_service'
         AND NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls
         AND NOT rolcreaterole AND NOT rolcreatedb
     ) THEN
    RAISE EXCEPTION 'ACQUISITION_COUNTER_CANONICAL_DATA_PARENT_MISSING';
  END IF;

  IF NOT has_schema_privilege(current_user, 'public', 'CREATE') THEN
    RAISE EXCEPTION 'ACQUISITION_COUNTER_CREATE_PRIVILEGE_MISSING';
  END IF;
END
$avuhz_acquisition_rate_counter_preflight$;

-- One durable admission record for each independently authenticated
-- tenant/service principal. No names, contact information, IPs, user
-- metadata, payloads, JWTs or submitted request identifiers.
CREATE TABLE public.avuhz_acquisition_rate_limit_counters (
  tenant_id uuid NOT NULL,
  principal_digest text NOT NULL
    CHECK (principal_digest ~ '^[0-9a-f]{64}$'),
  window_started_at timestamptz NOT NULL,
  request_count integer NOT NULL
    CHECK (request_count BETWEEN 1 AND 10),
  PRIMARY KEY (tenant_id, principal_digest)
);

REVOKE ALL ON TABLE public.avuhz_acquisition_rate_limit_counters FROM PUBLIC;
DO $avuhz_acquisition_rate_counter_negative_acl$
DECLARE subject_role text;
BEGIN
  FOREACH subject_role IN ARRAY ARRAY[
    'anon', 'authenticated', 'service_role', 'avuhz_command_service'
  ] LOOP
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname=subject_role) THEN
      EXECUTE format(
        'REVOKE ALL ON TABLE public.avuhz_acquisition_rate_limit_counters FROM %I',
        subject_role
      );
    END IF;
  END LOOP;
END
$avuhz_acquisition_rate_counter_negative_acl$;

ALTER TABLE public.avuhz_acquisition_rate_limit_counters
  ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.avuhz_acquisition_rate_limit_counters
  FORCE ROW LEVEL SECURITY;

-- Only the verified command role plus transaction-local trusted tenant
-- context can read/update this table. Setting a browser-supplied tenant
-- value must never confer authority; the runtime GUC is set by Avuhz.
CREATE POLICY avuhz_command_service_tenant_isolation
  ON public.avuhz_acquisition_rate_limit_counters
  FOR ALL TO avuhz_command_service
  USING (
    tenant_id = NULLIF(current_setting('avuhz.tenant_id', true), '')::uuid
  )
  WITH CHECK (
    tenant_id = NULLIF(current_setting('avuhz.tenant_id', true), '')::uuid
  );

-- Narrow column grants ONLY on the one new table.
-- INSERT ... ON CONFLICT DO UPDATE needs SELECT on the referenced columns.
-- Never grant DELETE, TRUNCATE, REFERENCES or UPDATE on tenant/key columns.
GRANT SELECT (tenant_id, principal_digest, window_started_at, request_count)
  ON public.avuhz_acquisition_rate_limit_counters TO avuhz_command_service;
GRANT INSERT (tenant_id, principal_digest, window_started_at, request_count)
  ON public.avuhz_acquisition_rate_limit_counters TO avuhz_command_service;
GRANT UPDATE (window_started_at, request_count)
  ON public.avuhz_acquisition_rate_limit_counters TO avuhz_command_service;

COMMIT;
"""


class SharedAcquisitionCounterCandidateStaticTests(unittest.TestCase):
    def test_one_new_table_for_data_only_with_exact_scoped_rls(self):
        sql = INSTALLATION_CANDIDATE_SQL
        self.assertEqual(len(re.findall(r"(?m)^BEGIN;$", sql)), 1)
        self.assertEqual(len(re.findall(r"(?m)^COMMIT;$", sql)), 1)
        self.assertEqual(
            sql.count("CREATE TABLE public.avuhz_acquisition_rate_limit_counters"), 1,
        )
        self.assertIn("ACQUISITION_COUNTER_PREEXISTING_RESOURCE_STOP", sql)
        self.assertIn("ACQUISITION_COUNTER_CANONICAL_DATA_PARENT_MISSING", sql)
        self.assertIn("PRIMARY KEY (tenant_id, principal_digest)", sql)
        self.assertIn("request_count BETWEEN 1 AND 10", sql)
        self.assertIn("ENABLE ROW LEVEL SECURITY", sql)
        self.assertIn("FORCE ROW LEVEL SECURITY", sql)
        self.assertEqual(sql.count("current_setting('avuhz.tenant_id', true)"), 2)
        self.assertEqual(len(re.findall(r"(?im)^GRANT\b", sql)), 3)
        self.assertNotIn("CREATE ROLE", sql)
        self.assertNotRegex(sql, r"(?im)^\s*(DROP|ALTER ROLE|CREATE FUNCTION|SECURITY DEFINER)\b")
        self.assertNotIn("GRANT DELETE", sql)
        self.assertNotIn("GRANT TRUNCATE", sql)
        self.assertNotIn("sekinfra", sql.lower())
        self.assertFalse(
            any("acquisition_rate_limit" in p.name
                for p in (ROOT / "supabase/migrations").glob("*.sql"))
        )


@unittest.skipUnless(CONTAINER, "requires disposable PostgreSQL 17 CI container")
class SharedAcquisitionCounterCandidatePostgresTests(unittest.TestCase):
    @classmethod
    def _docker(cls, *args, stdin=None, check=True):
        result = subprocess.run(
            ["docker", "exec", *(["-i"] if stdin is not None else []),
             CONTAINER, *args],
            input=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=90, check=False,
        )
        if check and result.returncode != 0:
            raise AssertionError("DISPOSABLE_COUNTER_POSTGRES_TEST_FAILED")
        return result

    @classmethod
    def _query(cls, sql, *, check=True):
        return cls._docker(
            "psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1",
            "-U", "postgres", "-d", DATABASE, "-c", sql, check=check,
        )

    @classmethod
    def _apply(cls, sql, *, check=True):
        return cls._docker(
            "psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1",
            "-U", "postgres", "-d", DATABASE,
            stdin=sql.encode("utf-8"), check=check,
        )

    def setUp(self):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", CONTAINER or ""):
            raise AssertionError("DISPOSABLE_CONTAINER_NOT_VERIFIED")
        self._docker("dropdb", "--if-exists", "-U", "postgres", DATABASE)
        self._docker("createdb", "-U", "postgres", DATABASE)
        self._apply(BASELINE.read_text(encoding="utf-8"))
        self._apply(PARENT_SQL)
        self._apply(INTAKE_SQL)

    def tearDown(self):
        self._docker("dropdb", "--if-exists", "-U", "postgres", DATABASE)

    @staticmethod
    def _admission_sql(tenant=TENANT_A, digest=PRINCIPAL_A, bound_tenant=TENANT_A):
        # These are fixed synthetic fixture constants only, NEVER user input.
        assert tenant in (TENANT_A, TENANT_B)
        assert bound_tenant in (TENANT_A, TENANT_B)
        assert digest in (PRINCIPAL_A, PRINCIPAL_B)
        sql = _ATOMIC_ADMISSION_SQL
        assert sql.count("%s") == 2
        sql = sql.replace("%s", f"'{tenant}'", 1)
        sql = sql.replace("%s", f"'{digest}'", 1)
        return (
            "begin;"
            "set local role avuhz_command_service;"
            f"set local avuhz.tenant_id='{bound_tenant}';"
            + sql + ";commit;"
        )

    def test_minimal_column_grants_forced_rls_and_no_public_access(self):
        self._apply(INSTALLATION_CANDIDATE_SQL)
        result = self._query(
            "select relrowsecurity::int || ':' || relforcerowsecurity::int "
            "from pg_class where oid='public.avuhz_acquisition_rate_limit_counters'::regclass;"
            "select count(*) from pg_policies where schemaname='public' "
            "and tablename='avuhz_acquisition_rate_limit_counters' "
            "and policyname='avuhz_command_service_tenant_isolation' "
            "and cmd='ALL' and roles=array['avuhz_command_service']::name[] "
            "and qual like '%avuhz.tenant_id%' "
            "and with_check like '%avuhz.tenant_id%';"
            "select count(*) from pg_roles where rolname in "
            "('anon','authenticated','service_role') "
            "and (has_table_privilege(rolname,"
            "'public.avuhz_acquisition_rate_limit_counters','SELECT') "
            "or has_table_privilege(rolname,"
            "'public.avuhz_acquisition_rate_limit_counters','INSERT') "
            "or has_table_privilege(rolname,"
            "'public.avuhz_acquisition_rate_limit_counters','UPDATE'));"
            "select has_table_privilege('avuhz_command_service',"
            "'public.avuhz_acquisition_rate_limit_counters','SELECT,INSERT,UPDATE')::int;"
            "select has_table_privilege('avuhz_command_service',"
            "'public.avuhz_acquisition_rate_limit_counters','DELETE')::int;"
            "select has_column_privilege('avuhz_command_service',"
            "'public.avuhz_acquisition_rate_limit_counters','tenant_id','UPDATE')::int;"
            "select has_column_privilege('avuhz_command_service',"
            "'public.avuhz_acquisition_rate_limit_counters','principal_digest','UPDATE')::int;"
            "select has_column_privilege('avuhz_command_service',"
            "'public.avuhz_acquisition_rate_limit_counters','request_count','UPDATE')::int;"
        )
        self.assertEqual(
            result.stdout.decode().strip().splitlines(),
            ["1:1", "1", "0", "1", "0", "0", "0", "1"],
        )

    def test_real_shared_writer_sql_admits_ten_then_denies_eleventh(self):
        self._apply(INSTALLATION_CANDIDATE_SQL)
        for count in range(1, 11):
            with self.subTest(count=count):
                result = self._query(self._admission_sql())
                self.assertEqual(result.stdout.decode().strip(), str(count))
        denied = self._query(self._admission_sql())
        self.assertEqual(denied.stdout.decode().strip(), "")
        state = self._query(
            "select request_count from public.avuhz_acquisition_rate_limit_counters"
        )
        self.assertEqual(state.stdout.decode().strip(), "10")
        self._query(
            "update public.avuhz_acquisition_rate_limit_counters "
            "set window_started_at=now()-interval '301 seconds'"
        )
        result = self._query(self._admission_sql())
        self.assertEqual(result.stdout.decode().strip(), "1")

    def test_missing_or_foreign_tenant_denied_without_counter_mutation(self):
        self._apply(INSTALLATION_CANDIDATE_SQL)
        first = self._query(self._admission_sql())
        self.assertEqual(first.stdout.decode().strip(), "1")
        other = self._query(self._admission_sql(
            tenant=TENANT_B, bound_tenant=TENANT_B, digest=PRINCIPAL_A,
        ))
        self.assertEqual(other.stdout.decode().strip(), "1")
        principal = self._query(self._admission_sql(
            tenant=TENANT_A, bound_tenant=TENANT_A, digest=PRINCIPAL_B,
        ))
        self.assertEqual(principal.stdout.decode().strip(), "1")
        forbidden = self._query(self._admission_sql(
            tenant=TENANT_B, bound_tenant=TENANT_A,
        ), check=False)
        self.assertNotEqual(forbidden.returncode, 0)
        absent = self._query(
            "begin;set local role avuhz_command_service;"
            + _ATOMIC_ADMISSION_SQL.replace("%s", f"'{TENANT_A}'", 1)
              .replace("%s", f"'{PRINCIPAL_A}'", 1) + ";rollback;",
            check=False,
        )
        self.assertNotEqual(absent.returncode, 0)
        visible = self._query(
            "begin;set local role avuhz_command_service;"
            f"set local avuhz.tenant_id='{TENANT_A}';"
            "select count(*) from public.avuhz_acquisition_rate_limit_counters;"
            "rollback;"
        )
        self.assertEqual(visible.stdout.decode().strip(), "2")
        self.assertEqual(
            self._query(
                "select count(*) from public.avuhz_acquisition_rate_limit_counters"
            ).stdout.decode().strip(), "3",
        )
        disallowed_delete = self._query(
            "begin;set local role avuhz_command_service;"
            f"set local avuhz.tenant_id='{TENANT_A}';"
            "delete from public.avuhz_acquisition_rate_limit_counters;",
            check=False,
        )
        self.assertNotEqual(disallowed_delete.returncode, 0)

    def test_reapply_and_atomic_failure_leave_no_partial_table(self):
        failure = INSTALLATION_CANDIDATE_SQL.replace(
            "\nCOMMIT;", "\nSELECT 1/0;\nCOMMIT;",
        )
        self.assertNotEqual(self._apply(failure, check=False).returncode, 0)
        self.assertEqual(
            self._query(
                "select (to_regclass('public.avuhz_acquisition_rate_limit_counters') "
                "is null)::int"
            ).stdout.decode().strip(), "1",
        )
        self._apply(INSTALLATION_CANDIDATE_SQL)
        second = self._apply(INSTALLATION_CANDIDATE_SQL, check=False)
        self.assertNotEqual(second.returncode, 0)
        self.assertIn(
            "ACQUISITION_COUNTER_PREEXISTING_RESOURCE_STOP",
            second.stderr.decode(),
        )

    def test_requires_existing_forced_rls_intake_table(self):
        self._query("drop table public.avuhz_acquisition_intake_requests")
        failed = self._apply(INSTALLATION_CANDIDATE_SQL, check=False)
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn(
            "ACQUISITION_COUNTER_CANONICAL_DATA_PARENT_MISSING",
            failed.stderr.decode(),
        )
        self.assertEqual(
            self._query(
                "select (to_regclass('public.avuhz_acquisition_rate_limit_counters') "
                "is null)::int"
            ).stdout.decode().strip(), "1",
        )


if __name__ == "__main__":
    unittest.main()
