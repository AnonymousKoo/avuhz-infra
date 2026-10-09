"""DEVELOPMENT DATA tenant/organization registry: disposable PG17 candidate ONLY.

No executable provider deployment path. This single-file migration candidate
is intentionally OUTSIDE supabase/migrations (an automatic chain, not bound to
DATA exclusively) and the immutable provider-artifact allowlist.
Future target: DEVELOPMENT DATA gnuqaefotwgkwurjpyik ONLY.
AUTH pwlhruwutoitnieactol is distinct and is NOT a valid target.
No SekInfra-specific backend, tenant, owner account, AUTH, n8n, or Stripe state.

Successful isolated PostgreSQL tests do not prove the hosted project identity
or grant approval to run SQL. A separately authorized DATA-only artifact,
migration preflight, execution and post-verification are required.
"""
from __future__ import annotations

import os
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BASELINE = ROOT / "supabase/migrations/20260831120000_rebaseline_provider_neutral_avuhz.sql"
CONTAINER = os.getenv("AVUHZ_LOCAL_POSTGRES_CONTAINER")
DATABASE = "avuhz_tenant_org_candidate_v1"
TENANT_A = "a4710000-0000-4000-8000-000000000001"
TENANT_B = "a4710000-0000-4000-8000-000000000002"
ORG_A = "a4710000-0000-4000-8000-000000000011"
ORG_B = "a4710000-0000-4000-8000-000000000012"

INSTALLATION_CANDIDATE_SQL = r"""
BEGIN;

DO $avuhz_tenant_organization_preflight$
BEGIN
  -- Stop; never adopt or replace unknown resource history.
  IF to_regclass('public.avuhz_tenant_organizations') IS NOT NULL THEN
    RAISE EXCEPTION 'TENANT_ORG_PREEXISTING_RESOURCE_STOP';
  END IF;
  -- Coarse canonical DATA-baseline prerequisite; project identity MUST be
  -- proven independently by an authorized provider preflight.
  IF to_regclass('public.avuhz_engagements') IS NULL
     OR to_regclass('public.avuhz_implementation_handoffs') IS NULL
     OR NOT EXISTS (
       SELECT 1 FROM pg_roles
       WHERE rolname = 'avuhz_command_service' AND NOT rolbypassrls
         AND NOT rolsuper AND NOT rolcanlogin
     )
     OR NOT EXISTS (
       SELECT 1 FROM pg_class
       WHERE oid = 'public.avuhz_engagements'::regclass
         AND relrowsecurity
     ) THEN
    RAISE EXCEPTION 'TENANT_ORG_CANONICAL_DATA_BASELINE_MISSING';
  END IF;
  IF NOT has_schema_privilege(current_user, 'public', 'CREATE') THEN
    RAISE EXCEPTION 'TENANT_ORG_SCHEMA_CREATE_PRIVILEGE_MISSING';
  END IF;
END
$avuhz_tenant_organization_preflight$;

CREATE TABLE public.avuhz_tenant_organizations (
  tenant_id uuid NOT NULL PRIMARY KEY,
  organization_id uuid NOT NULL UNIQUE,
  business_reference text NOT NULL UNIQUE
    CHECK (char_length(business_reference) BETWEEN 3 AND 128
      AND business_reference ~ '^[a-z][a-z0-9]*(?:[._:-][a-z0-9]+)*$'),
  lifecycle_state text NOT NULL DEFAULT 'PENDING_VERIFICATION'
    CHECK (lifecycle_state IN (
      'PENDING_VERIFICATION', 'ACTIVE', 'SUSPENDED'
    )),
  record_version integer NOT NULL DEFAULT 1
    CHECK (record_version BETWEEN 1 AND 2147483647),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, organization_id)
);

-- Data API and generic roles must not inherit a new authoritative table.
REVOKE ALL ON TABLE public.avuhz_tenant_organizations FROM PUBLIC;
DO $avuhz_tenant_org_negative_acl$
DECLARE
  subject_role text;
BEGIN
  FOREACH subject_role IN ARRAY ARRAY[
    'anon', 'authenticated', 'service_role', 'avuhz_command_service'
  ] LOOP
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = subject_role) THEN
      EXECUTE format(
        'REVOKE ALL ON TABLE public.avuhz_tenant_organizations FROM %I',
        subject_role
      );
    END IF;
  END LOOP;
END
$avuhz_tenant_org_negative_acl$;

ALTER TABLE public.avuhz_tenant_organizations
  ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.avuhz_tenant_organizations
  FORCE ROW LEVEL SECURITY;

-- Not a membership/owner verifier. GUC alone cannot authenticate a tenant.
-- No runtime access GRANT accompanies this candidate.
CREATE POLICY avuhz_command_service_tenant_isolation
  ON public.avuhz_tenant_organizations
  FOR ALL TO avuhz_command_service
  USING (
    tenant_id = NULLIF(current_setting('avuhz.tenant_id', true), '')::uuid
  )
  WITH CHECK (
    tenant_id = NULLIF(current_setting('avuhz.tenant_id', true), '')::uuid
  );

COMMIT;
"""


class TenantOrganizationCandidateStaticTests(unittest.TestCase):
    def test_one_dormant_transaction_with_fail_closed_policy(self):
        sql = INSTALLATION_CANDIDATE_SQL
        self.assertEqual(len(re.findall(r"(?m)^BEGIN;$", sql)), 1)
        self.assertEqual(len(re.findall(r"(?m)^COMMIT;$", sql)), 1)
        self.assertIn("TENANT_ORG_PREEXISTING_RESOURCE_STOP", sql)
        self.assertIn("TENANT_ORG_CANONICAL_DATA_BASELINE_MISSING", sql)
        self.assertIn("ENABLE ROW LEVEL SECURITY", sql)
        self.assertIn("FORCE ROW LEVEL SECURITY", sql)
        self.assertEqual(sql.count("current_setting('avuhz.tenant_id', true)"), 2)
        self.assertIn("REVOKE ALL ON TABLE", sql)
        self.assertNotRegex(sql, r"(?im)^\s*GRANT\s")
        self.assertNotRegex(sql, r"(?im)^\s*(?:INSERT|UPDATE|DELETE)\s+(?:INTO|FROM|PUBLIC)")
        self.assertFalse(
            any("tenant_organization" in p.name
                for p in (ROOT / "supabase/migrations").glob("*.sql"))
        )
        self.assertNotIn("sekinfra", sql.lower())


@unittest.skipUnless(CONTAINER, "disposable PostgreSQL 17 required")
class TenantOrganizationCandidatePostgresTests(unittest.TestCase):
    @classmethod
    def _docker(cls, *args, input_bytes=None, check=True):
        value = subprocess.run(
            ["docker", "exec", *(["-i"] if input_bytes is not None else []),
             CONTAINER, *args],
            input=input_bytes, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False, timeout=90,
        )
        if check and value.returncode:
            # Sanitized output for a disposable test fixture only.
            raise AssertionError("DISPOSABLE_POSTGRES_CANDIDATE_SETUP_FAILED")
        return value

    @classmethod
    def _sql(cls, statement, *, check=True):
        return cls._docker(
            "psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1",
            "-U", "postgres", "-d", DATABASE, "-c", statement, check=check,
        )

    @classmethod
    def _apply(cls, statement, *, check=True):
        return cls._docker(
            "psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1",
            "-U", "postgres", "-d", DATABASE, input_bytes=statement.encode(),
            check=check,
        )

    def setUp(self):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", CONTAINER or ""):
            raise AssertionError("DISPOSABLE_POSTGRES_CONTAINER_UNVERIFIED")
        self._docker("dropdb", "--if-exists", "-U", "postgres", DATABASE)
        self._docker("createdb", "-U", "postgres", DATABASE)
        self._apply(BASELINE.read_text(encoding="utf-8"))

    def tearDown(self):
        self._docker("dropdb", "--if-exists", "-U", "postgres", DATABASE)
        # Do not touch any provider, shared role or another test's database.

    def test_creates_one_rls_forced_table_without_any_runtime_grants(self):
        self._apply(INSTALLATION_CANDIDATE_SQL)
        result = self._sql(
            "select c.relrowsecurity::int || ':' || c.relforcerowsecurity::int "
            "from pg_class c where c.oid='public.avuhz_tenant_organizations'::regclass;"
            "select count(*) from pg_policies where schemaname='public' "
            "and tablename='avuhz_tenant_organizations' "
            "and policyname='avuhz_command_service_tenant_isolation';"
            "select has_table_privilege('avuhz_command_service', "
            "'public.avuhz_tenant_organizations', 'SELECT')::int;"
            "select has_table_privilege('avuhz_command_service', "
            "'public.avuhz_tenant_organizations', 'INSERT')::int;"
            "select has_table_privilege('public', "
            "'public.avuhz_tenant_organizations', 'SELECT')::int;"
        )
        self.assertEqual(result.stdout.decode().strip().splitlines(),
                         ["1:1", "1", "0", "0", "0"])
        result = self._sql(
            "insert into public.avuhz_tenant_organizations "
            "(tenant_id, organization_id, business_reference) values "
            f"('{TENANT_A}', '{ORG_A}', 'business.fictional-one') "
            "returning lifecycle_state;"
        )
        self.assertEqual(result.stdout.decode().strip(), "PENDING_VERIFICATION")
        bad = self._sql(
            "insert into public.avuhz_tenant_organizations "
            "(tenant_id, organization_id, business_reference, lifecycle_state) values "
            f"('{TENANT_B}', '{ORG_B}', 'business.fictional-two', 'ENABLED')",
            check=False,
        )
        self.assertNotEqual(bad.returncode, 0)

    def test_missing_tenant_and_cross_tenant_denied_under_temporary_read(self):
        self._apply(INSTALLATION_CANDIDATE_SQL)
        self._sql(
            "insert into public.avuhz_tenant_organizations "
            "(tenant_id, organization_id, business_reference) values "
            f"('{TENANT_A}', '{ORG_A}', 'business.fictional-one'), "
            f"('{TENANT_B}', '{ORG_B}', 'business.fictional-two')"
        )
        # A test-only, rolled-back grant makes the RLS predicate observable.
        # Production candidate itself grants no runtime SELECT or INSERT.
        read = self._sql(
            "begin;"
            "grant select on table public.avuhz_tenant_organizations "
            "to avuhz_command_service;"
            "set local role avuhz_command_service;"
            "select count(*) from public.avuhz_tenant_organizations;"
            f"set local avuhz.tenant_id = '{TENANT_A}';"
            "select count(*) from public.avuhz_tenant_organizations;"
            f"select count(*) from public.avuhz_tenant_organizations "
            f"where tenant_id='{TENANT_B}';"
            f"set local avuhz.tenant_id = '{TENANT_B}';"
            "select count(*) from public.avuhz_tenant_organizations;"
            "rollback;"
        )
        self.assertEqual(read.stdout.decode().strip().splitlines(),
                         ["0", "1", "0", "1"])
        permission = self._sql(
            "begin; set local role avuhz_command_service; "
            "select count(*) from public.avuhz_tenant_organizations;",
            check=False,
        )
        self.assertNotEqual(permission.returncode, 0)

    def test_replay_stops_without_repair_or_row_loss(self):
        self._apply(INSTALLATION_CANDIDATE_SQL)
        self._sql(
            "insert into public.avuhz_tenant_organizations "
            "(tenant_id, organization_id, business_reference) values "
            f"('{TENANT_A}', '{ORG_A}', 'business.fictional-one')"
        )
        retry = self._apply(INSTALLATION_CANDIDATE_SQL, check=False)
        self.assertNotEqual(retry.returncode, 0)
        self.assertIn("TENANT_ORG_PREEXISTING_RESOURCE_STOP",
                      retry.stderr.decode())
        remaining = self._sql(
            "select count(*) from public.avuhz_tenant_organizations;"
        )
        self.assertEqual(remaining.stdout.decode().strip(), "1")

    def test_atomic_error_rolls_back_all_table_and_policy_changes(self):
        failed = INSTALLATION_CANDIDATE_SQL.replace(
            "\nCOMMIT;", "\nSELECT 1/0;\nCOMMIT;"
        )
        attempt = self._apply(failed, check=False)
        self.assertNotEqual(attempt.returncode, 0)
        results = self._sql(
            "select (to_regclass('public.avuhz_tenant_organizations') "
            "is null)::int;"
            "select count(*) from pg_policies where schemaname='public' "
            "and tablename='avuhz_tenant_organizations';"
        )
        self.assertEqual(results.stdout.decode().strip().splitlines(),
                         ["1", "0"])

    def test_canonical_baseline_is_required(self):
        self._docker("dropdb", "--if-exists", "-U", "postgres", DATABASE)
        self._docker("createdb", "-U", "postgres", DATABASE)
        failed = self._apply(INSTALLATION_CANDIDATE_SQL, check=False)
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn("TENANT_ORG_CANONICAL_DATA_BASELINE_MISSING",
                      failed.stderr.decode())
        table = self._sql(
            "select (to_regclass('public.avuhz_tenant_organizations') "
            "is null)::int;"
        )
        self.assertEqual(table.stdout.decode().strip(), "1")


if __name__ == "__main__":
    unittest.main()
