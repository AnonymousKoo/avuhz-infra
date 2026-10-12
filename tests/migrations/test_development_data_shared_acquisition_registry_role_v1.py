"""LOCAL/TEST certificate of isolated acquisition registry access, no provider writes.

Disposable PG17 exercises the review-only candidate. In particular, PostgreSQL
FOR SHARE/UPDATE needs an UPDATE privilege; an RLS UPDATE policy with
WITH CHECK false must permit locks while forbidding real row mutations.
"""
from __future__ import annotations

import os
import re
import runpy
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SQL = ROOT / "supabase/provider-artifacts/development-data/current/development_data_shared_acquisition_registry_role_v1.sql"
BASE = ROOT / "supabase/migrations/20260831120000_rebaseline_provider_neutral_avuhz.sql"
FIXTURES = (
    ROOT / "tests/integration/test_development_data_tenant_organization_candidate.py",
    ROOT / "tests/integration/test_development_data_tenant_owner_membership_candidate.py",
    ROOT / "tests/integration/test_development_data_acquisition_intake_candidate.py",
)
CONTAINER = os.getenv("AVUHZ_LOCAL_POSTGRES_CONTAINER")
DB = "avuhz_isolated_acquisition_registry_v1"
ROLE = "avuhz_acquisition_service_dev"
TENANT_A = "a4730000-0000-4000-8000-000000000001"
TENANT_B = "a4730000-0000-4000-8000-000000000002"
ORG_A = "a4730000-0000-4000-8000-000000000011"
ORG_B = "a4730000-0000-4000-8000-000000000012"
REQUEST = "a4730000-0000-4000-8000-000000000021"
INTAKE = "a4730000-0000-4000-8000-000000000031"


class IsolatedAcquisitionRoleStaticTests(unittest.TestCase):
    def test_role_and_three_registry_boundaries_no_live_install(self):
        sql = SQL.read_text()
        self.assertEqual(len(re.findall(r"(?m)^BEGIN;$", sql)), 1)
        self.assertEqual(len(re.findall(r"(?m)^COMMIT;$", sql)), 1)
        self.assertIn("REVIEW ONLY. NOT AUTHORIZED FOR PROVIDER EXECUTION", sql)
        self.assertIn("DEVELOPMENT DATA: gnuqaefotwgkwurjpyik", sql)
        self.assertIn("AUTH pwlhruwutoitnieactol", sql)
        self.assertIn("CREATE ROLE avuhz_acquisition_service_dev", sql)
        self.assertIn("NOLOGIN NOINHERIT", sql)
        self.assertIn("NOSUPERUSER NOBYPASSRLS", sql)
        self.assertEqual(sql.count("WITH CHECK (false)"), 1)
        self.assertIn("||'USING (%s) WITH CHECK (false)'", sql)
        self.assertIn("avuhz_acquisition_lock_only", sql)
        self.assertIn("GRANT UPDATE (record_version)", sql)
        self.assertEqual(sql.count("GRANT UPDATE (record_version)"), 3)
        self.assertNotRegex(sql, r"(?im)^\s*GRANT\s+ALL\b")
        self.assertNotRegex(sql, r"(?im)^\s*GRANT\s+(?:DELETE|TRUNCATE|BYPASSRLS)\b")
        self.assertNotIn("GRANT avuhz_command_service TO avuhz_acquisition_service_dev", sql)
        self.assertNotIn("TO avuhz_command_service;", sql)
        self.assertNotIn("CREATE TABLE", sql)
        self.assertNotIn("service_role TO", sql)
        self.assertFalse(any(
            "shared_acquisition_registry_role" in path.name
            for path in (ROOT / "supabase/migrations").glob("*.sql")
        ))


@unittest.skipUnless(CONTAINER, "disposable PostgreSQL 17 container required")
class IsolatedAcquisitionRolePostgresTests(unittest.TestCase):
    @classmethod
    def docker(cls, *args, data=None, check=True):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", CONTAINER or ""):
            raise RuntimeError("untrusted container")
        proc = subprocess.run(
            ["docker", "exec", *(["-i"] if data is not None else []), CONTAINER, *args],
            input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False, timeout=120,
        )
        if check and proc.returncode:
            # Synthetic test database only. Limit error to first fixed, safe
            # PostgreSQL diagnostic code; no input bodies or secret material.
            err = [line.split("ERROR:", 1)[1].strip()
                   for line in proc.stderr.decode(errors="replace").splitlines()
                   if "ERROR:" in line]
            msg = re.sub(r"[^A-Za-z0-9_ .:-]", "", err[0] if err else "UNCLASSIFIED")[:130]
            raise AssertionError("DISPOSABLE_ROLE_TEST_FAILED: " + msg)
        return proc

    def sql(self, text, *, check=True):
        return self.docker(
            "psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1",
            "-U", "postgres", "-d", DB, "-c", text, check=check
        )

    def apply(self, text, *, check=True):
        return self.docker(
            "psql", "-X", "-q", "-v", "ON_ERROR_STOP=1",
            "-U", "postgres", "-d", DB, data=text.encode(), check=check
        )

    def setUp(self):
        self.docker("dropdb", "--if-exists", "-U", "postgres", DB)
        self.docker("createdb", "-U", "postgres", DB)
        self.apply(BASE.read_text())
        for path in FIXTURES:
            self.apply(runpy.run_path(str(path))["INSTALLATION_CANDIDATE_SQL"])

    def tearDown(self):
        self.docker("dropdb", "--if-exists", "-U", "postgres", DB)
        self.docker(
            "psql", "-X", "-q", "-v", "ON_ERROR_STOP=1",
            "-U", "postgres", "-d", "postgres",
            "-c", f"DROP ROLE IF EXISTS {ROLE};",
            check=False,
        )

    def seed(self):
        for tenant, org, suffix, digest in (
            (TENANT_A, ORG_A, "a", "a"*64),
            (TENANT_B, ORG_B, "b", "b"*64),
        ):
            self.sql(
                "INSERT INTO public.avuhz_tenant_organizations "
                "(tenant_id,organization_id,business_reference,lifecycle_state) VALUES "
                f"('{tenant}','{org}','fictional.{suffix}','ACTIVE');"
                "INSERT INTO public.avuhz_tenant_owner_memberships "
                "(tenant_id,organization_id,principal_subject_digest,member_role,membership_state,verified_at) VALUES "
                f"('{tenant}','{org}','sha256:{digest}','OWNER','ACTIVE',now());"
            )

    @staticmethod
    def intake_insert(tenant=TENANT_A, org=ORG_A):
        return (
            "INSERT INTO public.avuhz_acquisition_intake_requests "
            "(intake_id,tenant_id,organization_id,external_request_id,"
            "source_system,route_reference,business_name,contact_name,"
            "contact_email,contact_phone,preferred_contact_method,"
            "contact_requested,diagnostic_summary) VALUES ("
            f"'{INTAKE}','{tenant}','{org}','{REQUEST}',"
            "'sekinfra.website','diagnostic.oia','Fictional Company',"
            "'Example Operator','fictional@example.invalid',null,"
            "'EMAIL',true,'Synthetic demonstration only') "
            "ON CONFLICT (tenant_id,external_request_id) DO NOTHING "
            "RETURNING intake_id;"
        )

    @staticmethod
    def scope(tenant=TENANT_A):
        return (
            f"BEGIN; SET LOCAL ROLE {ROLE}; "
            f"SET LOCAL avuhz.tenant_id='{tenant}';"
        )

    def test_organization_owner_locks_and_exact_replay_succeed(self):
        self.seed()
        self.apply(SQL.read_text())
        query = (
            self.scope() +
            "SELECT 1 FROM public.avuhz_tenant_organizations AS org "
            "JOIN public.avuhz_tenant_owner_memberships AS member "
            "ON member.tenant_id=org.tenant_id AND member.organization_id=org.organization_id "
            f"WHERE org.tenant_id='{TENANT_A}' AND org.organization_id='{ORG_A}' "
            "AND org.lifecycle_state='ACTIVE' AND member.member_role='OWNER' "
            "AND member.membership_state='ACTIVE' AND member.verified_at IS NOT NULL "
            "LIMIT 1 FOR SHARE OF org,member;"
            + self.intake_insert() +
            "SELECT intake_id,contact_email FROM public.avuhz_acquisition_intake_requests "
            f"WHERE tenant_id='{TENANT_A}' AND organization_id='{ORG_A}' "
            f"AND external_request_id='{REQUEST}' FOR UPDATE;"
            + self.intake_insert() + "ROLLBACK;"
        )
        response = self.sql(query)
        output = response.stdout.decode()
        self.assertIn("1", output)
        self.assertIn("fictional@example.invalid", output)
        self.assertEqual(output.count(INTAKE), 2)
        self.assertEqual(
            self.sql("SELECT count(*) FROM public.avuhz_acquisition_intake_requests;")
            .stdout.decode().strip(), "0",
        )

    def test_real_owner_updates_are_denied_even_with_lock_privilege(self):
        self.seed()
        self.apply(SQL.read_text())
        for table, where in (
            ("avuhz_tenant_organizations", f"tenant_id='{TENANT_A}'"),
            ("avuhz_tenant_owner_memberships", f"tenant_id='{TENANT_A}'"),
            ("avuhz_acquisition_intake_requests", f"tenant_id='{TENANT_A}'"),
        ):
            with self.subTest(table=table):
                result = self.sql(
                    self.scope() + f"UPDATE public.{table} "
                    f"SET record_version=record_version+1 WHERE {where};",
                    check=False,
                )
                self.assertNotEqual(result.returncode, 0)
        self.assertEqual(
            self.sql("SELECT record_version FROM public.avuhz_tenant_organizations "
                     f"WHERE tenant_id='{TENANT_A}';").stdout.decode().strip(), "1",
        )

    def test_empty_tenant_cross_tenant_broad_roles_and_hidden_columns_denied(self):
        self.seed()
        self.apply(SQL.read_text())
        empty = self.sql(
            f"BEGIN;SET LOCAL ROLE {ROLE};"
            "SELECT count(*) FROM public.avuhz_tenant_organizations;"
            "SELECT count(*) FROM public.avuhz_tenant_owner_memberships;"
            "ROLLBACK;"
        ).stdout.decode().splitlines()
        self.assertEqual(empty, ["0", "0"])
        scoped = self.sql(
            self.scope() + "SELECT count(*) FROM public.avuhz_tenant_organizations;"
            + "SELECT count(*) FROM public.avuhz_tenant_owner_memberships;"
            + "ROLLBACK;"
        ).stdout.decode().splitlines()
        self.assertEqual(scoped, ["1", "1"])
        for query in (
            "SELECT principal_subject_digest FROM public.avuhz_tenant_owner_memberships;",
            "SELECT intake_state FROM public.avuhz_acquisition_intake_requests;",
            "SELECT * FROM public.avuhz_tenant_organizations;",
            "SELECT * FROM public.avuhz_acquisition_intake_requests;",
            "DELETE FROM public.avuhz_tenant_owner_memberships;",
            "INSERT INTO public.avuhz_lifecycle_events "
            "(lifecycle_event_id,tenant_id,event_type) VALUES "
            f"('{INTAKE}','{TENANT_A}','acquisition.intake.received');",
        ):
            denied = self.sql(self.scope()+query, check=False)
            self.assertNotEqual(denied.returncode, 0)
        crossing = self.sql(self.scope()+self.intake_insert(TENANT_B, ORG_B), check=False)
        self.assertNotEqual(crossing.returncode, 0)
        self.assertEqual(self.sql(
            "SELECT has_table_privilege('avuhz_command_service',"
            "'public.avuhz_acquisition_intake_requests','SELECT')::int;"
        ).stdout.decode().strip(), "0")

    def test_transaction_failure_rolls_back_role_grants_policies_and_replay_denies(self):
        bad=SQL.read_text().replace(
            "\nCOMMIT;", "\nSELECT 1/0; -- synthetic rollback test\nCOMMIT;"
        )
        attempt=self.apply(bad,check=False)
        self.assertNotEqual(attempt.returncode,0)
        self.assertEqual(self.sql(
            "SELECT count(*) FROM pg_roles WHERE rolname='avuhz_acquisition_service_dev';"
        ).stdout.decode().strip(),"0")
        self.apply(SQL.read_text())
        retry=self.apply(SQL.read_text(),check=False)
        self.assertNotEqual(retry.returncode,0)
        self.assertIn("ACQUISITION_ROLE_IDENTITY_OR_PREEXISTENCE_STOP",
                      retry.stderr.decode())
        self.assertEqual(self.sql(
            "SELECT count(*) FROM pg_policies WHERE schemaname='public' "
            "AND policyname LIKE 'avuhz_acquisition_%';"
        ).stdout.decode().strip(),"7")


if __name__=="__main__":
    unittest.main()
