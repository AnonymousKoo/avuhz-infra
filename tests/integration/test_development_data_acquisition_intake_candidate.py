"""Shared web-acquisition intake persistence: disposable PG17 candidate ONLY.

This is the first *unqualified prospect request*, NOT the existing governed
AcceptAcquisitionHandoff command (which requires a qualified opportunity).
It is a shared Avuhz DATA concept; no vertical-specific authentication, billing,
or automation path is created. Customer PII is confined to the authoritative
tenant-scoped DATA row, never an event, outbox body, diagnostic URL, or log.

No hosted Supabase mutation, API wiring, public POST, credentials, tenant
registration, or live customer submission is authorized by this file.
Future installation target: DEVELOPMENT DATA gnuqaefotwgkwurjpyik, NOT
DEVELOPMENT AUTH pwlhruwutoitnieactol. No existing client owner is registered.

The still-missing hosted ingress must enforce real tenant ACTIVE state,
business owner membership, server authentication, request integrity, rate
limits, idempotency, consent, PII retention/deletion and HTTP error controls.
A client-provided tenant_id or route reference is NEVER trusted authority.
"""
from __future__ import annotations

import os
import re
import runpy
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONTAINER = os.getenv("AVUHZ_LOCAL_POSTGRES_CONTAINER")
DB = "avuhz_acquisition_intake_candidate_v1"
BASELINE = ROOT / "supabase/migrations/20260831120000_rebaseline_provider_neutral_avuhz.sql"
PARENT_FILE = ROOT / "tests/integration/test_development_data_tenant_organization_candidate.py"
PARENT_SQL = runpy.run_path(str(PARENT_FILE))["INSTALLATION_CANDIDATE_SQL"]
TENANT_1 = "a4730000-0000-4000-8000-000000000001"
TENANT_2 = "a4730000-0000-4000-8000-000000000002"
ORG_1 = "a4730000-0000-4000-8000-000000000011"
ORG_2 = "a4730000-0000-4000-8000-000000000012"
REQUEST_1 = "a4730000-0000-4000-8000-000000000021"
REQUEST_2 = "a4730000-0000-4000-8000-000000000022"
INTAKE_1 = "a4730000-0000-4000-8000-000000000031"
INTAKE_2 = "a4730000-0000-4000-8000-000000000032"

INSTALLATION_CANDIDATE_SQL = r"""
BEGIN;

DO $avuhz_acquisition_intake_preflight$
BEGIN
  IF to_regclass('public.avuhz_acquisition_intake_requests') IS NOT NULL THEN
    RAISE EXCEPTION 'ACQUISITION_INTAKE_PREEXISTING_RESOURCE_STOP';
  END IF;
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
    RAISE EXCEPTION 'ACQUISITION_INTAKE_CANONICAL_DATA_PARENT_MISSING';
  END IF;
  IF NOT has_schema_privilege(current_user, 'public', 'CREATE') THEN
    RAISE EXCEPTION 'ACQUISITION_INTAKE_CREATE_PRIVILEGE_MISSING';
  END IF;
END
$avuhz_acquisition_intake_preflight$;

CREATE TABLE public.avuhz_acquisition_intake_requests (
  intake_id uuid NOT NULL PRIMARY KEY,
  tenant_id uuid NOT NULL,
  organization_id uuid NOT NULL,
  external_request_id uuid NOT NULL,
  source_system text NOT NULL
    CHECK (char_length(source_system) BETWEEN 3 AND 128
      AND source_system ~ '^[a-z][a-z0-9]*(?:[._:-][a-z0-9]+)*$'),
  route_reference text NOT NULL
    CHECK (char_length(route_reference) BETWEEN 3 AND 128
      AND route_reference ~ '^[a-z][a-z0-9]*(?:[._:-][a-z0-9]+)*$'),
  business_name text NOT NULL
    CHECK (char_length(business_name) BETWEEN 2 AND 160
      AND business_name !~ '[[:cntrl:]]'),
  contact_name text NOT NULL
    CHECK (char_length(contact_name) BETWEEN 2 AND 120
      AND contact_name !~ '[[:cntrl:]]'),
  contact_email text NOT NULL
    CHECK (char_length(contact_email) BETWEEN 5 AND 254
      AND contact_email ~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$'
      AND contact_email !~ '[[:cntrl:]]'),
  contact_phone text
    CHECK (contact_phone IS NULL OR
      (char_length(contact_phone) BETWEEN 7 AND 30
       AND contact_phone ~ '^[+0-9(). -]+$')),
  preferred_contact_method text NOT NULL
    CHECK (preferred_contact_method IN ('EMAIL','PHONE')),
  contact_requested boolean NOT NULL
    CHECK (contact_requested IS TRUE),
  -- Server-controlled timestamp; raw consent payload is never copied.
  consent_recorded_at timestamptz NOT NULL DEFAULT now(),
  diagnostic_summary text NOT NULL
    CHECK (char_length(diagnostic_summary) BETWEEN 1 AND 500
      AND diagnostic_summary !~ '[[:cntrl:]]'),
  intake_state text NOT NULL DEFAULT 'RECEIVED'
    CHECK (intake_state IN ('RECEIVED','TRIAGED','WITHDRAWN')),
  received_at timestamptz NOT NULL DEFAULT now(),
  record_version integer NOT NULL DEFAULT 1
    CHECK (record_version BETWEEN 1 AND 2147483647),
  CONSTRAINT avuhz_acquisition_intake_phone_preference
    CHECK (preferred_contact_method <> 'PHONE' OR contact_phone IS NOT NULL),
  CONSTRAINT avuhz_acquisition_intake_request_dedupe
    UNIQUE (tenant_id, external_request_id),
  CONSTRAINT avuhz_acquisition_intake_exact_organization
    FOREIGN KEY (tenant_id, organization_id)
    REFERENCES public.avuhz_tenant_organizations (tenant_id, organization_id)
    ON UPDATE RESTRICT ON DELETE RESTRICT
);

-- This table contains operationally necessary PII. Direct client/service
-- access remains closed until a separate reviewed trusted writer/read plan.
REVOKE ALL ON TABLE public.avuhz_acquisition_intake_requests FROM PUBLIC;
DO $avuhz_acquisition_intake_negative_grants$
DECLARE subject_role text;
BEGIN
  FOREACH subject_role IN ARRAY ARRAY[
    'anon', 'authenticated', 'service_role', 'avuhz_command_service'
  ] LOOP
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname=subject_role) THEN
      EXECUTE format(
        'REVOKE ALL ON TABLE public.avuhz_acquisition_intake_requests FROM %I',
        subject_role
      );
    END IF;
  END LOOP;
END
$avuhz_acquisition_intake_negative_grants$;

ALTER TABLE public.avuhz_acquisition_intake_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.avuhz_acquisition_intake_requests FORCE ROW LEVEL SECURITY;

CREATE POLICY avuhz_command_service_tenant_isolation
  ON public.avuhz_acquisition_intake_requests
  FOR ALL TO avuhz_command_service
  USING (
    tenant_id = NULLIF(current_setting('avuhz.tenant_id', true), '')::uuid
  )
  WITH CHECK (
    tenant_id = NULLIF(current_setting('avuhz.tenant_id', true), '')::uuid
  );

COMMIT;
"""


class AcquisitionIntakeCandidateStaticTests(unittest.TestCase):
    def test_exact_one_table_one_transaction_no_live_access(self):
        sql = INSTALLATION_CANDIDATE_SQL
        self.assertEqual(len(re.findall(r"(?m)^BEGIN;$", sql)), 1)
        self.assertEqual(len(re.findall(r"(?m)^COMMIT;$", sql)), 1)
        self.assertEqual(sql.count("CREATE TABLE public.avuhz_acquisition_intake_requests"), 1)
        self.assertIn("ACQUISITION_INTAKE_PREEXISTING_RESOURCE_STOP", sql)
        self.assertIn("ACQUISITION_INTAKE_CANONICAL_DATA_PARENT_MISSING", sql)
        self.assertIn("FOREIGN KEY (tenant_id, organization_id)", sql)
        self.assertIn("UNIQUE (tenant_id, external_request_id)", sql)
        self.assertIn("ENABLE ROW LEVEL SECURITY", sql)
        self.assertIn("FORCE ROW LEVEL SECURITY", sql)
        self.assertEqual(sql.count("current_setting('avuhz.tenant_id', true)"), 2)
        self.assertNotRegex(sql, r"(?im)^\s*GRANT\b")
        self.assertNotIn("CREATE ROLE", sql)
        self.assertNotIn("sekinfra", sql.lower())
        self.assertFalse(any("acquisition_intake" in file.name
                             for file in (ROOT / "supabase/migrations").glob("*.sql")))


@unittest.skipUnless(CONTAINER, "requires disposable PostgreSQL 17 CI container")
class AcquisitionIntakeCandidatePostgresTests(unittest.TestCase):
    @classmethod
    def _docker(cls, *args, stdin=None, check=True):
        r = subprocess.run(
            ["docker", "exec", *(["-i"] if stdin is not None else []),
             CONTAINER, *args],
            input=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=90, check=False,
        )
        if check and r.returncode:
            raise AssertionError("DISPOSABLE_ACQUISITION_INTAKE_TEST_FAILED")
        return r

    @classmethod
    def _query(cls, text, *, check=True):
        return cls._docker("psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1",
                           "-U", "postgres", "-d", DB, "-c", text, check=check)

    @classmethod
    def _apply(cls, text, *, check=True):
        return cls._docker("psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1",
                           "-U", "postgres", "-d", DB, stdin=text.encode(),
                           check=check)

    def setUp(self):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", CONTAINER or ""):
            raise AssertionError("DISPOSABLE_CONTAINER_NOT_VERIFIED")
        self._docker("dropdb", "--if-exists", "-U", "postgres", DB)
        self._docker("createdb", "-U", "postgres", DB)
        self._apply(BASELINE.read_text(encoding="utf-8"))
        self._apply(PARENT_SQL)
        self._query(
            "insert into public.avuhz_tenant_organizations "
            "(tenant_id,organization_id,business_reference,lifecycle_state) values "
            f"('{TENANT_1}','{ORG_1}','business.synthetic-one','ACTIVE'),"
            f"('{TENANT_2}','{ORG_2}','business.synthetic-two','ACTIVE')"
        )

    def tearDown(self):
        self._docker("dropdb", "--if-exists", "-U", "postgres", DB)

    @staticmethod
    def _row(*, intake=INTAKE_1, tenant=TENANT_1, org=ORG_1,
             request=REQUEST_1, consent="true", email="fictional@example.invalid",
             method="EMAIL", phone="NULL", status="RECEIVED"):
        # Test-only fixed synthetic identifiers/values, not user-provided SQL.
        return (
            "insert into public.avuhz_acquisition_intake_requests "
            "(intake_id,tenant_id,organization_id,external_request_id,"
            "source_system,route_reference,business_name,contact_name,"
            "contact_email,contact_phone,preferred_contact_method,"
            "contact_requested,diagnostic_summary,intake_state) values "
            f"('{intake}','{tenant}','{org}','{request}',"
            f"'website.generic','diagnostic.focused','Fictional Test Co',"
            f"'Sample Person','{email}',{phone},'{method}',"
            f"{consent},'Operations need a clearer next step','{status}')"
        )

    def test_forced_rls_exact_tenant_and_closed_role_grants(self):
        self._apply(INSTALLATION_CANDIDATE_SQL)
        result = self._query(
            "select c.relrowsecurity::int || ':' || c.relforcerowsecurity::int "
            "from pg_class c where c.oid='public.avuhz_acquisition_intake_requests'::regclass;"
            "select count(*) from pg_policies where schemaname='public' "
            "and tablename='avuhz_acquisition_intake_requests' "
            "and policyname='avuhz_command_service_tenant_isolation' and cmd='ALL' "
            "and roles=array['avuhz_command_service']::name[] "
            "and qual like '%avuhz.tenant_id%' and with_check like '%avuhz.tenant_id%';"
            "select count(*) from information_schema.role_table_grants "
            "where table_schema='public' and table_name='avuhz_acquisition_intake_requests' "
            "and grantee in ('PUBLIC','anon','authenticated','service_role','avuhz_command_service');"
            "select has_table_privilege('avuhz_command_service',"
            "'public.avuhz_acquisition_intake_requests','SELECT')::int;"
            "select has_table_privilege('avuhz_command_service',"
            "'public.avuhz_acquisition_intake_requests','INSERT')::int;"
        )
        self.assertEqual(result.stdout.decode().strip().splitlines(),
                         ["1:1", "1", "0", "0", "0"])
        self._query(self._row())

    def test_cross_tenant_fk_and_duplicate_submission_denied(self):
        self._apply(INSTALLATION_CANDIDATE_SQL)
        self.assertNotEqual(
            self._query(self._row(org=ORG_2), check=False).returncode, 0
        )
        self._query(self._row())
        self.assertNotEqual(
            self._query(self._row(intake=INTAKE_2), check=False).returncode, 0
        )
        self.assertEqual(
            self._query("select count(*) from public.avuhz_acquisition_intake_requests")
            .stdout.decode().strip(), "1"
        )

    def test_consent_contact_data_and_state_are_constrained(self):
        self._apply(INSTALLATION_CANDIDATE_SQL)
        for label, clause in (
            ("consent_denied", dict(consent="false")),
            ("invalid_email", dict(email="not-an-email")),
            ("phone_required", dict(method="PHONE")),
            ("role_escape", dict(status="IMPLEMENTATION_AUTHORIZED")),
        ):
            with self.subTest(case=label):
                self.assertNotEqual(
                    self._query(self._row(**clause), check=False).returncode, 0
                )
        self._query(self._row())
        result = self._query(
            "select intake_state || ':' || contact_requested::text "
            "from public.avuhz_acquisition_intake_requests"
        )
        self.assertEqual(result.stdout.decode().strip(), "RECEIVED:true")

    def test_no_tenant_cross_tenant_and_direct_writes_denied(self):
        self._apply(INSTALLATION_CANDIDATE_SQL)
        self._query(self._row())
        self._query(self._row(intake=INTAKE_2, tenant=TENANT_2,
                              org=ORG_2, request=REQUEST_2))
        # Test-only grant in a transaction, rolled back.
        response = self._query(
            "begin;"
            "grant select on table public.avuhz_acquisition_intake_requests "
            "to avuhz_command_service;"
            "set local role avuhz_command_service;"
            "select count(*) from public.avuhz_acquisition_intake_requests;"
            f"set local avuhz.tenant_id='{TENANT_1}';"
            "select count(*) from public.avuhz_acquisition_intake_requests;"
            f"set local avuhz.tenant_id='{TENANT_2}';"
            "select count(*) from public.avuhz_acquisition_intake_requests;"
            "rollback;"
        )
        self.assertEqual(response.stdout.decode().strip().splitlines(),
                         ["0", "1", "1"])
        forbidden = self._query(
            "begin; set local role avuhz_command_service;"
            f"set local avuhz.tenant_id='{TENANT_1}';"
            "select count(*) from public.avuhz_acquisition_intake_requests;",
            check=False,
        )
        self.assertNotEqual(forbidden.returncode, 0)
        denied_insert = self._query(
            "begin;set local role avuhz_command_service;"
            f"set local avuhz.tenant_id='{TENANT_1}';"
            + self._row(intake=INTAKE_2, request=REQUEST_2) + ";",
            check=False,
        )
        self.assertNotEqual(denied_insert.returncode, 0)

    def test_atomic_failure_rollback_and_replay_stop(self):
        failure = INSTALLATION_CANDIDATE_SQL.replace(
            "\nCOMMIT;", "\nSELECT 1/0;\nCOMMIT;"
        )
        self.assertNotEqual(self._apply(failure, check=False).returncode, 0)
        self.assertEqual(
            self._query(
                "select (to_regclass('public.avuhz_acquisition_intake_requests') is null)::int;"
                "select count(*) from pg_policies where tablename='avuhz_acquisition_intake_requests';"
            ).stdout.decode().strip().splitlines(), ["1", "0"]
        )
        self._apply(INSTALLATION_CANDIDATE_SQL)
        self._query(self._row())
        again = self._apply(INSTALLATION_CANDIDATE_SQL, check=False)
        self.assertNotEqual(again.returncode, 0)
        self.assertIn("ACQUISITION_INTAKE_PREEXISTING_RESOURCE_STOP",
                      again.stderr.decode())
        self.assertEqual(
            self._query("select count(*) from public.avuhz_acquisition_intake_requests")
            .stdout.decode().strip(), "1"
        )

    def test_parent_missing_rejects_install_before_any_table_creation(self):
        self._query("drop table public.avuhz_tenant_organizations")
        attempt = self._apply(INSTALLATION_CANDIDATE_SQL, check=False)
        self.assertNotEqual(attempt.returncode, 0)
        self.assertIn("ACQUISITION_INTAKE_CANONICAL_DATA_PARENT_MISSING",
                      attempt.stderr.decode())
        self.assertEqual(
            self._query(
                "select (to_regclass('public.avuhz_acquisition_intake_requests') is null)::int"
            ).stdout.decode().strip(), "1"
        )


if __name__ == "__main__":
    unittest.main()
