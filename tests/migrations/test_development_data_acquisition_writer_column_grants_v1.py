"""REVIEW-ONLY shared acquisition writer grant tests; disposable PostgreSQL only."""
from __future__ import annotations

import os
import re
import runpy
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ARTIFACT = ROOT / "supabase/provider-artifacts/development-data/current/development_data_acquisition_writer_column_grants_candidate_v1.sql"
BASE = ROOT / "supabase/migrations/20260831120000_rebaseline_provider_neutral_avuhz.sql"
SOURCES = (
    ROOT / "tests/integration/test_development_data_tenant_organization_candidate.py",
    ROOT / "tests/integration/test_development_data_tenant_owner_membership_candidate.py",
    ROOT / "tests/integration/test_development_data_acquisition_intake_candidate.py",
)
CONTAINER = os.getenv("AVUHZ_LOCAL_POSTGRES_CONTAINER")
DATABASE = "avuhz_acquisition_column_grant_candidate"
TENANT_A = "a4730000-0000-4000-8000-000000000001"
TENANT_B = "a4730000-0000-4000-8000-000000000002"
ORG_A = "a4730000-0000-4000-8000-000000000011"
ORG_B = "a4730000-0000-4000-8000-000000000012"
INTAKE_A = "a4730000-0000-4000-8000-000000000031"
REQUEST_A = "a4730000-0000-4000-8000-000000000021"


class SharedAcquisitionColumnGrantStaticTests(unittest.TestCase):
    def test_exact_column_acl_transaction_and_read_only_replay(self):
        sql = ARTIFACT.read_text()
        source = (ROOT / "src/avuhz_service/acquisition_intake_command.py").read_text().lower()
        self.assertEqual(len(re.findall(r"(?m)^BEGIN;$", sql)), 1)
        self.assertEqual(len(re.findall(r"(?m)^COMMIT;$", sql)), 1)
        self.assertIn("REVIEW ONLY", sql)
        self.assertIn("DEVELOPMENT DATA gnuqaefotwgkwurjpyik", sql)
        self.assertIn("AUTH pwlhruwutoitnieactol", sql)
        self.assertIn("ACQUISITION_WRITER_GRANT_PREEXISTING_ACCESS_STOP", sql)
        self.assertIn("ACQUISITION_WRITER_GRANT_POSTCONDITION_STOP", sql)
        self.assertIn("relforcerowsecurity", sql)
        self.assertEqual(sql.count("TO avuhz_command_service;"), 4)
        self.assertEqual(sql.count("GRANT INSERT ("), 1)
        self.assertNotRegex(sql, r"(?im)^\s*GRANT\s+(?:UPDATE|DELETE|ALL)\b")
        self.assertNotRegex(sql, r"(?im)^\s*(?:CREATE|ALTER|REVOKE|INSERT|UPDATE|DELETE)\s")
        self.assertIn("and external_request_id=%s for share", source)
        self.assertNotIn("and external_request_id=%s for update", source)
        self.assertFalse(any("acquisition_writer_column_grants" in p.name
            for p in (ROOT / "supabase/migrations").glob("*.sql")))


@unittest.skipUnless(CONTAINER, "disposable PostgreSQL 17 container required")
class SharedAcquisitionColumnGrantPostgresTests(unittest.TestCase):
    @classmethod
    def docker(cls, *args, input_bytes=None, check=True):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", CONTAINER):
            raise RuntimeError("invalid disposable container name")
        proc = subprocess.run(
            ["docker", "exec", *(["-i"] if input_bytes is not None else []),
             CONTAINER, *args], input=input_bytes, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=110, check=False,
        )
        if check and proc.returncode:
            raise AssertionError("DISPOSABLE_POSTGRES_FAILED")
        return proc

    def query(self, sql, *, check=True):
        return self.docker(
            "psql", "-q", "-X", "-At", "-v", "ON_ERROR_STOP=1",
            "-U", "postgres", "-d", DATABASE, "-c", sql, check=check,
        )

    def apply(self, sql, *, check=True):
        return self.docker(
            "psql", "-q", "-X", "-v", "ON_ERROR_STOP=1", "-U", "postgres",
            "-d", DATABASE, input_bytes=sql.encode("utf-8"), check=check,
        )

    def setUp(self):
        self.docker("dropdb", "--if-exists", "-U", "postgres", DATABASE)
        self.docker("createdb", "-U", "postgres", DATABASE)
        self.apply(BASE.read_text(encoding="utf-8"))
        for source in SOURCES:
            self.apply(runpy.run_path(str(source))["INSTALLATION_CANDIDATE_SQL"])

    def tearDown(self):
        self.docker("dropdb", "--if-exists", "-U", "postgres", DATABASE)
        self.docker("psql", "-q", "-X", "-U", "postgres", "-d", "postgres",
                    "-c", "DROP ROLE IF EXISTS avuhz_command_service", check=False)

    def seed(self):
        for tenant, org, label, digest in (
            (TENANT_A, ORG_A, "alpha", "a"*64),
            (TENANT_B, ORG_B, "bravo", "b"*64),
        ):
            self.query(
                "INSERT INTO public.avuhz_tenant_organizations "
                "(tenant_id,organization_id,business_reference,lifecycle_state)"
                f"VALUES('{tenant}','{org}','test.{label}','ACTIVE');"
                "INSERT INTO public.avuhz_tenant_owner_memberships "
                "(tenant_id,organization_id,principal_subject_digest,member_role,membership_state,verified_at)"
                f"VALUES('{tenant}','{org}','sha256:{digest}','OWNER','ACTIVE',now());"
            )

    def insert(self, tenant=TENANT_A, org=ORG_A):
        return (
            "INSERT INTO public.avuhz_acquisition_intake_requests "
            "(intake_id,tenant_id,organization_id,external_request_id,source_system,"
            "route_reference,business_name,contact_name,contact_email,contact_phone,"
            "preferred_contact_method,contact_requested,diagnostic_summary) VALUES "
            f"('{INTAKE_A}','{tenant}','{org}','{REQUEST_A}',"
            "'website.synthetic','diagnostic.oia','Fictional Example Company',"
            "'Example Operator','example@example.invalid',null,'EMAIL',true,"
            "'Synthetic check only') ON CONFLICT (tenant_id,external_request_id) "
            "DO NOTHING RETURNING intake_id;"
        )

    def test_accepted_writer_sql_and_replay_without_update_permission(self):
        self.seed()
        self.apply(ARTIFACT.read_text())
        response = self.query(
            "BEGIN;SET LOCAL ROLE avuhz_command_service;"
            f"SET LOCAL avuhz.tenant_id='{TENANT_A}';"
            "SELECT org.organization_id FROM public.avuhz_tenant_organizations org "
            "JOIN public.avuhz_tenant_owner_memberships m "
            "ON org.tenant_id=m.tenant_id AND org.organization_id=m.organization_id "
            f"WHERE org.tenant_id='{TENANT_A}' AND org.lifecycle_state='ACTIVE' "
            "AND m.member_role='OWNER' AND m.membership_state='ACTIVE' "
            "AND m.verified_at IS NOT NULL FOR SHARE OF org,m;"
            + self.insert() +
            "SELECT intake_id,contact_email FROM public.avuhz_acquisition_intake_requests "
            f"WHERE tenant_id='{TENANT_A}' AND organization_id='{ORG_A}' "
            f"AND external_request_id='{REQUEST_A}' FOR SHARE;"
            + self.insert() + "ROLLBACK;"
        )
        output = response.stdout.decode()
        self.assertIn(ORG_A, output)
        self.assertEqual(output.count(INTAKE_A), 2)
        self.assertIn("example@example.invalid", output)
        self.assertEqual(
            self.query("SELECT count(*) FROM public.avuhz_acquisition_intake_requests;")
            .stdout.decode().strip(), "0",
        )

    def test_no_tenant_cross_tenant_no_unauthorized_pii_or_mutation(self):
        self.seed()
        self.apply(ARTIFACT.read_text())
        empty = self.query(
            "BEGIN;SET LOCAL ROLE avuhz_command_service;"
            "SELECT count(*) FROM public.avuhz_tenant_organizations;"
            "SELECT count(*) FROM public.avuhz_tenant_owner_memberships;"
            "ROLLBACK;"
        ).stdout.decode().splitlines()
        self.assertEqual(empty, ["0", "0"])
        for denied_sql in (
            "SELECT principal_subject_digest FROM public.avuhz_tenant_owner_memberships;",
            "SELECT intake_state FROM public.avuhz_acquisition_intake_requests;",
            "UPDATE public.avuhz_acquisition_intake_requests SET intake_state='TRIAGED';",
            "DELETE FROM public.avuhz_acquisition_intake_requests;",
            "SELECT * FROM public.avuhz_acquisition_intake_requests;",
        ):
            with self.subTest(operation=denied_sql.split()[0]):
                result = self.query(
                    "BEGIN;SET LOCAL ROLE avuhz_command_service;"
                    f"SET LOCAL avuhz.tenant_id='{TENANT_A}';" + denied_sql,
                    check=False,
                )
                self.assertNotEqual(result.returncode, 0)
        cross = self.query(
            "BEGIN;SET LOCAL ROLE avuhz_command_service;"
            f"SET LOCAL avuhz.tenant_id='{TENANT_A}';"
            + self.insert(TENANT_B, ORG_B),
            check=False,
        )
        self.assertNotEqual(cross.returncode, 0)

    def test_atomic_failure_reverts_grants_and_second_attempt_stops(self):
        sql = ARTIFACT.read_text()
        failed = self.apply(sql.replace(
            "\nCOMMIT;", "\nSELECT 1/0; -- synthetic failure injection\nCOMMIT;"
        ), check=False)
        self.assertNotEqual(failed.returncode, 0)
        before = self.query(
            "SELECT has_column_privilege('avuhz_command_service',"
            "'public.avuhz_acquisition_intake_requests','contact_email','SELECT')::int;"
        ).stdout.decode().strip()
        self.assertEqual(before, "0")
        self.apply(sql)
        replay = self.apply(sql, check=False)
        self.assertNotEqual(replay.returncode, 0)
        self.assertIn("ACQUISITION_WRITER_GRANT_PREEXISTING_ACCESS_STOP",
                      replay.stderr.decode())


if __name__ == "__main__":
    unittest.main()
