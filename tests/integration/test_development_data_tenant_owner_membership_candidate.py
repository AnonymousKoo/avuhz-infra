"""Shared owner-membership table: disposable PostgreSQL candidate, NOT a migration.

Repository-only TEST against disposable PostgreSQL 17. Future project is
DEVELOPMENT DATA gnuqaefotwgkwurjpyik, NEVER AUTH pwlhruwutoitnieactol.
No hosted install, real tenant, owner record, auth change, or permission grant.
The synthetic digests in the tests ARE NOT verified real identity evidence.
"""
from __future__ import annotations

import os
import re
import runpy
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONTAINER = os.environ.get("AVUHZ_LOCAL_POSTGRES_CONTAINER")
DB = "avuhz_owner_membership_candidate_v1"
BASELINE = ROOT / "supabase/migrations/20260831120000_rebaseline_provider_neutral_avuhz.sql"
ORG_CANDIDATE = ROOT / "tests/integration/test_development_data_tenant_organization_candidate.py"
TENANT_A = "a4720000-0000-4000-8000-000000000001"
TENANT_B = "a4720000-0000-4000-8000-000000000002"
ORG_A = "a4720000-0000-4000-8000-000000000011"
ORG_B = "a4720000-0000-4000-8000-000000000012"
SYNTHETIC_DIGEST_A = "sha256:" + "a" * 64
SYNTHETIC_DIGEST_B = "sha256:" + "b" * 64

# Test-only load of the exact PR #603, later-installed DATA table candidate.
# Do not introduce a second, independently drifting tenant/organization DDL.
ORG_INSTALLATION_SQL = runpy.run_path(str(ORG_CANDIDATE))[
    "INSTALLATION_CANDIDATE_SQL"
]

INSTALLATION_CANDIDATE_SQL = r"""
BEGIN;

DO $avuhz_owner_membership_preflight$
BEGIN
  IF to_regclass('public.avuhz_tenant_owner_memberships') IS NOT NULL THEN
    RAISE EXCEPTION 'OWNER_MEMBERSHIP_PREEXISTING_RESOURCE_STOP';
  END IF;
  -- This is only a coarse DATA baseline check, NOT provider identity proof.
  IF to_regclass('public.avuhz_tenant_organizations') IS NULL
     OR NOT EXISTS (
       SELECT 1 FROM pg_class
       WHERE oid=to_regclass('public.avuhz_tenant_organizations')
         AND relrowsecurity AND relforcerowsecurity
     )
     OR NOT EXISTS (
       SELECT 1 FROM pg_roles
       WHERE rolname='avuhz_command_service' AND NOT rolcanlogin
         AND NOT rolsuper AND NOT rolbypassrls
     ) THEN
    RAISE EXCEPTION 'OWNER_MEMBERSHIP_CANONICAL_DATA_PARENT_MISSING';
  END IF;
  IF NOT has_schema_privilege(current_user, 'public', 'CREATE') THEN
    RAISE EXCEPTION 'OWNER_MEMBERSHIP_CREATE_PRIVILEGE_MISSING';
  END IF;
END
$avuhz_owner_membership_preflight$;

CREATE TABLE public.avuhz_tenant_owner_memberships (
  tenant_id uuid NOT NULL,
  organization_id uuid NOT NULL,
  principal_subject_digest text NOT NULL
    CHECK (principal_subject_digest ~ '^sha256:[0-9a-f]{64}$'),
  member_role text NOT NULL DEFAULT 'OWNER'
    CHECK (member_role = 'OWNER'),
  membership_state text NOT NULL DEFAULT 'PENDING_VERIFICATION'
    CHECK (membership_state IN ('PENDING_VERIFICATION','ACTIVE','REVOKED')),
  verified_at timestamptz,
  record_version integer NOT NULL DEFAULT 1
    CHECK (record_version BETWEEN 1 AND 2147483647),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT avuhz_owner_membership_active_verification
    CHECK (membership_state <> 'ACTIVE' OR verified_at IS NOT NULL),
  CONSTRAINT avuhz_owner_membership_exact_tenant_principal
    PRIMARY KEY (tenant_id, principal_subject_digest),
  CONSTRAINT avuhz_owner_membership_exact_organization
    FOREIGN KEY (tenant_id, organization_id)
    REFERENCES public.avuhz_tenant_organizations (tenant_id, organization_id)
    ON UPDATE RESTRICT ON DELETE RESTRICT
);

REVOKE ALL ON TABLE public.avuhz_tenant_owner_memberships FROM PUBLIC;
DO $avuhz_owner_membership_negative_grants$
DECLARE
  subject_role text;
BEGIN
  FOREACH subject_role IN ARRAY ARRAY[
    'anon', 'authenticated', 'service_role', 'avuhz_command_service'
  ] LOOP
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname=subject_role) THEN
      EXECUTE format(
        'REVOKE ALL ON TABLE public.avuhz_tenant_owner_memberships FROM %I',
        subject_role
      );
    END IF;
  END LOOP;
END
$avuhz_owner_membership_negative_grants$;

ALTER TABLE public.avuhz_tenant_owner_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.avuhz_tenant_owner_memberships FORCE ROW LEVEL SECURITY;

-- No membership writer rights, owner authority, or trusted AUTH mapping.
-- A tenant GUC alone is NOT proof of ownership or authentication.
CREATE POLICY avuhz_command_service_tenant_isolation
  ON public.avuhz_tenant_owner_memberships
  FOR ALL TO avuhz_command_service
  USING (
    tenant_id = NULLIF(current_setting('avuhz.tenant_id', true), '')::uuid
  )
  WITH CHECK (
    tenant_id = NULLIF(current_setting('avuhz.tenant_id', true), '')::uuid
  );

COMMIT;
"""


class OwnerMembershipCandidateStaticTests(unittest.TestCase):
    def test_candidate_is_one_unbound_transaction_with_closed_permissions(self):
        sql = INSTALLATION_CANDIDATE_SQL
        self.assertEqual(len(re.findall(r"(?m)^BEGIN;$", sql)), 1)
        self.assertEqual(len(re.findall(r"(?m)^COMMIT;$", sql)), 1)
        self.assertEqual(sql.count("CREATE TABLE public.avuhz_tenant_owner_memberships"), 1)
        self.assertIn("OWNER_MEMBERSHIP_PREEXISTING_RESOURCE_STOP", sql)
        self.assertIn("OWNER_MEMBERSHIP_CANONICAL_DATA_PARENT_MISSING", sql)
        self.assertIn("FOREIGN KEY (tenant_id, organization_id)", sql)
        self.assertIn("ON UPDATE RESTRICT ON DELETE RESTRICT", sql)
        self.assertIn("ENABLE ROW LEVEL SECURITY", sql)
        self.assertIn("FORCE ROW LEVEL SECURITY", sql)
        self.assertEqual(sql.count("current_setting('avuhz.tenant_id', true)"), 2)
        self.assertNotRegex(sql, r"(?im)^\s*GRANT\s")
        self.assertNotRegex(sql, r"(?im)^\s*(INSERT|UPDATE|DELETE)\s+(INTO|FROM|PUBLIC)\b")
        self.assertFalse(any("owner_membership" in p.name
                             for p in (ROOT / "supabase/migrations").glob("*.sql")))
        self.assertNotIn("sekinfra", sql.lower())
        self.assertNotIn("CREATE ROLE", sql)


@unittest.skipUnless(CONTAINER, "requires the exact disposable PostgreSQL 17 CI container")
class OwnerMembershipCandidatePostgresTests(unittest.TestCase):
    @classmethod
    def _docker(cls, *args, input_bytes=None, check=True):
        r = subprocess.run(
            ["docker", "exec", *(["-i"] if input_bytes is not None else []),
             CONTAINER, *args], input=input_bytes,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=90, check=False,
        )
        if check and r.returncode:
            raise AssertionError("DISPOSABLE_OWNER_MEMBERSHIP_SETUP_FAILED")
        return r

    @classmethod
    def _sql(cls, query, *, check=True):
        return cls._docker(
            "psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1",
            "-U", "postgres", "-d", DB, "-c", query, check=check,
        )

    @classmethod
    def _apply(cls, sql, *, check=True):
        return cls._docker(
            "psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1",
            "-U", "postgres", "-d", DB, input_bytes=sql.encode(), check=check,
        )

    def setUp(self):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", CONTAINER or ""):
            raise AssertionError("DISPOSABLE_CONTAINER_NOT_VERIFIED")
        self._docker("dropdb", "--if-exists", "-U", "postgres", DB)
        self._docker("createdb", "-U", "postgres", DB)
        self._apply(BASELINE.read_text(encoding="utf-8"))
        self._apply(ORG_INSTALLATION_SQL)
        self._seed_organizations()

    def tearDown(self):
        self._docker("dropdb", "--if-exists", "-U", "postgres", DB)

    def _seed_organizations(self):
        self._sql(
            "insert into public.avuhz_tenant_organizations "
            "(tenant_id,organization_id,business_reference) values "
            f"('{TENANT_A}','{ORG_A}','business.synthetic-first'),"
            f"('{TENANT_B}','{ORG_B}','business.synthetic-second')"
        )

    def _seed_memberships(self):
        self._sql(
            "insert into public.avuhz_tenant_owner_memberships "
            "(tenant_id,organization_id,principal_subject_digest) values "
            f"('{TENANT_A}','{ORG_A}','{SYNTHETIC_DIGEST_A}'),"
            f"('{TENANT_B}','{ORG_B}','{SYNTHETIC_DIGEST_B}')"
        )

    def test_forced_rls_policy_foreign_key_and_no_public_runtime_grants(self):
        self._apply(INSTALLATION_CANDIDATE_SQL)
        result = self._sql(
            "select c.relrowsecurity::int || ':' || c.relforcerowsecurity::int "
            "from pg_class c where c.oid='public.avuhz_tenant_owner_memberships'::regclass;"
            "select count(*) from pg_policies where schemaname='public' "
            "and tablename='avuhz_tenant_owner_memberships' "
            "and policyname='avuhz_command_service_tenant_isolation' "
            "and cmd='ALL' and roles=array['avuhz_command_service']::name[] "
            "and qual like '%avuhz.tenant_id%' and with_check like '%avuhz.tenant_id%';"
            "select count(*) from pg_constraint where "
            "conrelid='public.avuhz_tenant_owner_memberships'::regclass and contype='f';"
            "select count(*) from information_schema.role_table_grants where "
            "table_schema='public' and table_name='avuhz_tenant_owner_memberships' "
            "and grantee in ('PUBLIC','anon','authenticated','service_role','avuhz_command_service');"
            "select has_table_privilege('avuhz_command_service', "
            "'public.avuhz_tenant_owner_memberships', 'SELECT')::int;"
            "select has_table_privilege('avuhz_command_service', "
            "'public.avuhz_tenant_owner_memberships', 'INSERT')::int;"
        )
        self.assertEqual(result.stdout.decode().strip().splitlines(),
                         ["1:1", "1", "1", "0", "0", "0"])
        self._seed_memberships()
        states = self._sql(
            "select membership_state from public.avuhz_tenant_owner_memberships "
            "order by tenant_id"
        )
        self.assertEqual(states.stdout.decode().strip().splitlines(),
                         ["PENDING_VERIFICATION", "PENDING_VERIFICATION"])

    def test_cross_tenant_organization_and_missing_parent_rejected(self):
        self._apply(INSTALLATION_CANDIDATE_SQL)
        prefix = "insert into public.avuhz_tenant_owner_memberships "
        fields = "(tenant_id,organization_id,principal_subject_digest) values "
        for org in (ORG_B, "a4720000-0000-4000-8000-000000000099"):
            bad = self._sql(
                prefix + fields +
                f"('{TENANT_A}','{org}','{SYNTHETIC_DIGEST_A}')",
                check=False,
            )
            self.assertNotEqual(bad.returncode, 0)
        empty = self._sql("select count(*) from public.avuhz_tenant_owner_memberships")
        self.assertEqual(empty.stdout.decode().strip(), "0")

    def test_reject_bad_digest_role_state_unverified_active_and_duplicate(self):
        self._apply(INSTALLATION_CANDIDATE_SQL)
        prefix = "insert into public.avuhz_tenant_owner_memberships "
        fields = "(tenant_id,organization_id,principal_subject_digest,member_role,membership_state)"
        for digest, role, state in (
            ("plain-subject", "OWNER", "PENDING_VERIFICATION"),
            (SYNTHETIC_DIGEST_A, "ADMIN", "PENDING_VERIFICATION"),
            (SYNTHETIC_DIGEST_A, "OWNER", "ACTIVE"),
            (SYNTHETIC_DIGEST_A, "OWNER", "ENABLED"),
        ):
            sql = prefix + fields + " values " + (
                f"('{TENANT_A}','{ORG_A}','{digest}','{role}','{state}')"
            )
            bad = self._sql(sql, check=False)
            self.assertNotEqual(bad.returncode, 0)
        self._seed_memberships()
        duplicate = self._sql(
            prefix + "(tenant_id,organization_id,principal_subject_digest) "
            f"values ('{TENANT_A}','{ORG_A}','{SYNTHETIC_DIGEST_A}')",
            check=False,
        )
        self.assertNotEqual(duplicate.returncode, 0)
        self.assertEqual(
            self._sql("select count(*) from public.avuhz_tenant_owner_memberships")
            .stdout.decode().strip(), "2"
        )

    def test_missing_tenant_cross_tenant_rls_and_no_real_grants(self):
        self._apply(INSTALLATION_CANDIDATE_SQL)
        self._seed_memberships()
        # Temporary test-only GRANT is rolled back, never in candidate SQL.
        result = self._sql(
            "begin;"
            "grant select on table public.avuhz_tenant_owner_memberships "
            "to avuhz_command_service;"
            "set local role avuhz_command_service;"
            "select count(*) from public.avuhz_tenant_owner_memberships;"
            f"set local avuhz.tenant_id='{TENANT_A}';"
            "select count(*) from public.avuhz_tenant_owner_memberships;"
            "select count(*) from public.avuhz_tenant_owner_memberships "
            f"where tenant_id='{TENANT_B}';"
            f"set local avuhz.tenant_id='{TENANT_B}';"
            "select count(*) from public.avuhz_tenant_owner_memberships;"
            "rollback;"
        )
        self.assertEqual(result.stdout.decode().strip().splitlines(),
                         ["0", "1", "0", "1"])
        forbidden = self._sql(
            "begin; set local role avuhz_command_service;"
            "select count(*) from public.avuhz_tenant_owner_memberships;",
            check=False,
        )
        self.assertNotEqual(forbidden.returncode, 0)
        denied = self._sql(
            "begin; set local role avuhz_command_service;"
            "set local avuhz.tenant_id='" + TENANT_A + "';"
            "insert into public.avuhz_tenant_owner_memberships "
            "(tenant_id,organization_id,principal_subject_digest) values "
            f"('{TENANT_A}','{ORG_A}','{SYNTHETIC_DIGEST_B}');",
            check=False,
        )
        self.assertNotEqual(denied.returncode, 0)

    def test_replay_fails_closed_without_modifying_record(self):
        self._apply(INSTALLATION_CANDIDATE_SQL)
        self._seed_memberships()
        again = self._apply(INSTALLATION_CANDIDATE_SQL, check=False)
        self.assertNotEqual(again.returncode, 0)
        self.assertIn("OWNER_MEMBERSHIP_PREEXISTING_RESOURCE_STOP",
                      again.stderr.decode())
        self.assertEqual(
            self._sql("select count(*) from public.avuhz_tenant_owner_memberships")
            .stdout.decode().strip(), "2"
        )

    def test_failure_rolls_back_membership_table_and_policy(self):
        bad_sql = INSTALLATION_CANDIDATE_SQL.replace(
            "\nCOMMIT;", "\nSELECT 1/0;\nCOMMIT;"
        )
        attempt = self._apply(bad_sql, check=False)
        self.assertNotEqual(attempt.returncode, 0)
        result = self._sql(
            "select (to_regclass('public.avuhz_tenant_owner_memberships') is null)::int;"
            "select count(*) from pg_policies where schemaname='public' "
            "and tablename='avuhz_tenant_owner_memberships';"
            "select (to_regclass('public.avuhz_tenant_organizations') is not null)::int;"
        )
        self.assertEqual(result.stdout.decode().strip().splitlines(),
                         ["1", "0", "1"])

    def test_missing_parent_ends_without_membership_table(self):
        self._sql("drop table public.avuhz_tenant_organizations")
        attempt = self._apply(INSTALLATION_CANDIDATE_SQL, check=False)
        self.assertNotEqual(attempt.returncode, 0)
        self.assertIn("OWNER_MEMBERSHIP_CANONICAL_DATA_PARENT_MISSING",
                      attempt.stderr.decode())
        self.assertEqual(
            self._sql(
                "select (to_regclass('public.avuhz_tenant_owner_memberships') is null)::int"
            ).stdout.decode().strip(), "1"
        )


if __name__ == "__main__":
    unittest.main()
