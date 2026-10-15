"""System 001 least-privilege acquisition metadata: static and no-network PG."""
from __future__ import annotations
import os
from pathlib import Path
import re
import subprocess
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "supabase/migrations/20261015193000_grant_shared_acquisition_handoff_metadata_read.sql"
CONTAINER = os.getenv("AVUHZ_LOCAL_POSTGRES_CONTAINER")
IMAGE = os.getenv("AVUHZ_POSTGRES_IMAGE")
DATABASE = "avuhz_system001_metadata_forward_v1"
TENANT_A = "a4730000-0000-4000-8000-000000000001"
TENANT_B = "a4730000-0000-4000-8000-000000000002"

POLICY = ("tenant_id = nullif(current_setting('avuhz.tenant_id'::text, true), "
          "''::text)::uuid")
DDL = """
CREATE ROLE avuhz_command_service NOLOGIN NOINHERIT NOBYPASSRLS;
CREATE ROLE avuhz_data_migration_service_dev NOLOGIN NOINHERIT NOBYPASSRLS;
CREATE ROLE avuhz_data_runtime_service_dev LOGIN NOINHERIT NOBYPASSRLS;
GRANT avuhz_command_service TO avuhz_data_migration_service_dev
  WITH ADMIN TRUE, INHERIT FALSE, SET FALSE;
GRANT avuhz_command_service TO avuhz_data_runtime_service_dev
  WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;
GRANT avuhz_data_runtime_service_dev TO postgres
  WITH ADMIN TRUE, INHERIT FALSE, SET FALSE;
GRANT avuhz_data_migration_service_dev TO postgres
  WITH ADMIN TRUE, INHERIT FALSE, SET FALSE;
CREATE ROLE avuhz_acquisition_service_dev NOLOGIN;
CREATE ROLE anon NOLOGIN;
CREATE ROLE authenticated NOLOGIN;
CREATE TABLE public.avuhz_acquisition_intake_requests (
  intake_id uuid NOT NULL PRIMARY KEY, tenant_id uuid NOT NULL,
  organization_id uuid NOT NULL, intake_state text NOT NULL,
  record_version integer NOT NULL, business_name text NOT NULL,
  contact_email text NOT NULL, contact_name text NOT NULL,
  contact_phone text, diagnostic_summary text NOT NULL
);
ALTER TABLE public.avuhz_acquisition_intake_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.avuhz_acquisition_intake_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY avuhz_command_service_tenant_isolation
  ON public.avuhz_acquisition_intake_requests FOR ALL
  TO avuhz_command_service
  USING (tenant_id = nullif(current_setting('avuhz.tenant_id'::text, true),'')::uuid)
  WITH CHECK (tenant_id = nullif(current_setting('avuhz.tenant_id'::text, true),'')::uuid);
CREATE POLICY avuhz_acquisition_select
  ON public.avuhz_acquisition_intake_requests FOR SELECT
  TO avuhz_acquisition_service_dev USING (tenant_id = nullif(current_setting('avuhz.tenant_id',true),'')::uuid);
GRANT USAGE ON SCHEMA public TO avuhz_command_service;
"""

class StaticContract(unittest.TestCase):
    def test_exact_table_and_no_secrets_broad_grants_or_user_creation(self):
        sql = MIGRATION.read_text()
        for required in (
            "Remote execution is unauthorized by default",
            "gnuqaefotwgkwurjpyik",
            "AVUHZ_ACQUISITION_HANDOFF_METADATA_PREFLIGHT_STOP",
            "AVUHZ_ACQUISITION_HANDOFF_METADATA_POSTCONDITION_STOP",
            "relforcerowsecurity", "avuhz_command_service_tenant_isolation",
            "GRANT SELECT (intake_id,tenant_id,organization_id,intake_state,record_version)",
        ):
            self.assertIn(required, sql)
        for forbidden in (
            "GRANT ALL", "GRANT SELECT ON TABLE", "GRANT SELECT ON public.",
            "CREATE TABLE", "CREATE ROLE", "CREATE POLICY", "TO anon",
            "TO authenticated", "TO service_role", "DISABLE ROW LEVEL SECURITY",
            "SECURITY DEFINER", "INSERT INTO", "DELETE FROM",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, sql)
        self.assertTrue(sql.rstrip().endswith("COMMIT;"))

@unittest.skipUnless(CONTAINER, "only isolated disposable PostgreSQL")
class DisposablePostgres(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Roles are cluster-global: the CI migration suite already creates
        # avuhz_command_service in its shared disposable database container.
        # Our destructive role/privilege negatives must run in a separate,
        # isolated, digest-pinned PostgreSQL cluster, never against that peer.
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,99}", CONTAINER or ""):
            raise ValueError("disposable PostgreSQL container identifier unavailable")
        if not re.fullmatch(r"[^\s]+@sha256:[0-9a-f]{64}", IMAGE or ""):
            raise ValueError("digest-pinned PostgreSQL fixture image is required")
        cls.fixture_name = CONTAINER + "-acquisition-metadata"
        if len(cls.fixture_name) > 128:
            raise ValueError("disposable fixture name too long")
        if subprocess.run(
            ["docker", "container", "inspect", cls.fixture_name],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            check=False,
        ).returncode == 0:
            raise RuntimeError("dedicated PostgreSQL fixture name already exists")
        run = subprocess.run(
            ["docker", "run", "--detach", "--rm", "--network", "none",
             "--name", cls.fixture_name, "--env", "POSTGRES_HOST_AUTH_METHOD=trust",
             IMAGE], capture_output=True, text=True, check=False,
        )
        if run.returncode or not re.fullmatch(r"[0-9a-f]{64}", run.stdout.strip()):
            raise RuntimeError("could not start isolated PostgreSQL fixture")
        cls.fixture_id = run.stdout.strip()
        try:
            for _ in range(30):
                ready = subprocess.run(
                    ["docker", "exec", cls.fixture_id, "pg_isready", "-U", "postgres"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    check=False,
                )
                if ready.returncode == 0:
                    version = subprocess.run(
                        ["docker", "exec", cls.fixture_id, "psql", "-X", "-At",
                         "-U", "postgres", "-d", "postgres", "-c", "show server_version_num;"],
                        capture_output=True, text=True, check=False,
                    )
                    if version.returncode or not version.stdout.strip().startswith("17"):
                        raise RuntimeError("fixture must be PostgreSQL 17")
                    return
                time.sleep(1)
            raise RuntimeError("isolated PostgreSQL fixture not ready")
        except BaseException:
            cls.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        fixture_id = getattr(cls, "fixture_id", None)
        if fixture_id:
            subprocess.run(["docker", "rm", "--force", fixture_id],
                           capture_output=True, check=False)
            cls.fixture_id = None

    @classmethod
    def command(cls, sql: str, *, check: bool = True):
        p = subprocess.run([
            "docker","exec","-i",cls.fixture_id,"psql","-X",
            "-v","ON_ERROR_STOP=1","-At","-U","postgres","-d",DATABASE
        ],input=sql.encode(),capture_output=True,check=False)
        if check and p.returncode:
            raise AssertionError(p.stderr.decode()[-1500:])
        return p

    @classmethod
    def docker(cls,*args):
        return subprocess.run(["docker","exec",cls.fixture_id,*args],
                              check=True,capture_output=True)

    def setUp(self):
        self.docker("dropdb","--if-exists","-U","postgres",DATABASE)
        self.docker("createdb","-U","postgres",DATABASE)
        self.command(DDL)

    def tearDown(self):
        self.docker("dropdb","--if-exists","-U","postgres",DATABASE)
        # Roles are cluster-global; clean only own named test roles.
        self.command_global("DROP ROLE IF EXISTS avuhz_command_service,"
                            "avuhz_data_runtime_service_dev,"
                            "avuhz_data_migration_service_dev,"
                            "avuhz_acquisition_service_dev,anon,authenticated,"
                            "avuhz_extra_parent_role;")

    @classmethod
    def command_global(cls,sql):
        p=subprocess.run(
            ["docker","exec",cls.fixture_id,"psql","-X","-v","ON_ERROR_STOP=1",
             "-U","postgres","-d","postgres","-c",sql],
             capture_output=True,check=False
        )
        if p.returncode:
            raise AssertionError(p.stderr.decode()[-1200:])
        return p

    @staticmethod
    def as_role(tenant: str, sql: str):
        return ("BEGIN; SET LOCAL ROLE avuhz_command_service;"
                f"SELECT set_config('avuhz.tenant_id','{tenant}',true);"
                +sql+"COMMIT;")

    def assert_failed_unapplied(self):
        result=self.command(MIGRATION.read_text(),check=False)
        self.assertNotEqual(result.returncode,0)
        self.assertIn("AVUHZ_ACQUISITION_HANDOFF_METADATA_PREFLIGHT_STOP",
                      result.stderr.decode())
        self.assertEqual(
            self.command("SELECT count(*) FROM pg_attribute a "
              "CROSS JOIN LATERAL aclexplode(a.attacl) acl "
              "WHERE a.attrelid='public.avuhz_acquisition_intake_requests'::regclass "
              "AND acl.grantee=(SELECT oid FROM pg_roles "
              "WHERE rolname='avuhz_command_service');").stdout.decode().strip(),"0"
        )

    def test_tenant_scope_and_no_pii_or_mutation(self):
        self.command(MIGRATION.read_text())
        a="a4730000-0000-4000-8000-000000000021"
        b="a4730000-0000-4000-8000-000000000022"
        for tenant,item in ((TENANT_A,a),(TENANT_B,b)):
            self.command("INSERT INTO public.avuhz_acquisition_intake_requests "
              "(intake_id,tenant_id,organization_id,intake_state,record_version,"
              "business_name,contact_email,contact_name,diagnostic_summary) "
              f"VALUES ('{item}','{tenant}','{tenant}','RECEIVED',1,"
              "'Fictional','noone@example.invalid','Fictional','synthetic');")
        rows=self.command(self.as_role(TENANT_A,
            "SELECT intake_id,tenant_id,organization_id,intake_state,record_version "
            "FROM public.avuhz_acquisition_intake_requests ORDER BY intake_id;"))
        self.assertIn(a,rows.stdout.decode())
        self.assertNotIn(b,rows.stdout.decode())
        self.assertEqual(self.command(
            self.as_role(TENANT_A,"SELECT count(*) FROM public.avuhz_acquisition_intake_requests;")
        ).stdout.decode().strip().splitlines()[-2],"1")
        for query in (
            "SELECT contact_email FROM public.avuhz_acquisition_intake_requests;",
            "SELECT * FROM public.avuhz_acquisition_intake_requests;",
            "UPDATE public.avuhz_acquisition_intake_requests SET record_version=2;",
            "DELETE FROM public.avuhz_acquisition_intake_requests;",
        ):
            with self.subTest(query=query):
                self.assertNotEqual(self.command(self.as_role(TENANT_A,query),check=False).returncode,0)
        no_context=self.command("BEGIN; SET LOCAL ROLE avuhz_command_service;"
            "SELECT count(*) FROM public.avuhz_acquisition_intake_requests; COMMIT;")
        self.assertIn("0",no_context.stdout.decode())
        self.assertEqual(self.command(
          "SELECT count(*) FROM pg_attribute a "
          "CROSS JOIN LATERAL aclexplode(a.attacl) acl "
          "WHERE a.attrelid='public.avuhz_acquisition_intake_requests'::regclass "
          "AND acl.grantee=(SELECT oid FROM pg_roles WHERE rolname='avuhz_command_service');"
        ).stdout.decode().strip(),"5")

    def test_replay_denied(self):
        self.command(MIGRATION.read_text())
        second=self.command(MIGRATION.read_text(),check=False)
        self.assertNotEqual(second.returncode,0)
        self.assertIn("AVUHZ_ACQUISITION_HANDOFF_METADATA_PREFLIGHT_STOP",
                      second.stderr.decode())

    def test_true_or_policy_attack_denied(self):
        self.command("DROP POLICY avuhz_command_service_tenant_isolation "
                     "ON public.avuhz_acquisition_intake_requests;")
        self.command("CREATE POLICY avuhz_command_service_tenant_isolation ON "
          "public.avuhz_acquisition_intake_requests FOR ALL TO avuhz_command_service "
          "USING (true OR tenant_id=nullif(current_setting('avuhz.tenant_id',true),'')::uuid)"
          " WITH CHECK (true);")
        self.assert_failed_unapplied()

    def test_browser_role_membership_to_command_is_denied(self):
        self.command("GRANT avuhz_command_service TO authenticated;")
        self.assert_failed_unapplied()

    def test_browser_can_not_be_granted_migration_role(self):
        self.command("GRANT avuhz_data_migration_service_dev TO authenticated WITH SET TRUE;")
        self.assert_failed_unapplied()

    def test_new_migration_or_runtime_parent_role_is_denied(self):
        for target in ("avuhz_data_migration_service_dev","avuhz_data_runtime_service_dev"):
            with self.subTest(target=target):
                self.command("CREATE ROLE avuhz_extra_parent_role NOLOGIN;")
                self.command(f"GRANT avuhz_extra_parent_role TO {target};")
                self.assert_failed_unapplied()
                self.command(f"REVOKE avuhz_extra_parent_role FROM {target};")
                self.command("DROP ROLE avuhz_extra_parent_role;")

    def test_service_role_elevated_attributes_are_denied(self):
        for target in ("avuhz_data_migration_service_dev","avuhz_data_runtime_service_dev"):
            with self.subTest(target=target):
                self.command(f"ALTER ROLE {target} CREATEROLE;")
                self.assert_failed_unapplied()
                self.command(f"ALTER ROLE {target} NOCREATEROLE;")

    def test_extra_browser_member_of_runtime_role_is_denied(self):
        self.command("GRANT avuhz_data_runtime_service_dev TO authenticated;")
        self.assert_failed_unapplied()

    def test_browser_column_select_is_denied(self):
        self.command(
            "GRANT SELECT (intake_state) ON "
            "public.avuhz_acquisition_intake_requests TO anon;"
        )
        self.assert_failed_unapplied()

    def test_ingress_role_state_select_is_denied(self):
        self.command(
            "GRANT SELECT (intake_state) ON "
            "public.avuhz_acquisition_intake_requests TO avuhz_acquisition_service_dev;"
        )
        self.assert_failed_unapplied()

    def test_public_read_denied(self):
        self.command("GRANT SELECT ON public.avuhz_acquisition_intake_requests TO PUBLIC;")
        self.assert_failed_unapplied()

    def test_atomic_rollback_on_post_grant_failure(self):
        sql=MIGRATION.read_text().replace(
          "\nCOMMIT;\n",
          "\nDO $fail$ BEGIN RAISE EXCEPTION 'TEST_ROLLBACK'; END $fail$;\nCOMMIT;\n",
        )
        failed=self.command(sql,check=False)
        self.assertNotEqual(failed.returncode,0)
        self.assertIn("TEST_ROLLBACK",failed.stderr.decode())
        self.assertEqual(self.command(
            "SELECT count(*) FROM pg_attribute a "
            "CROSS JOIN LATERAL aclexplode(a.attacl) acl "
            "WHERE a.attrelid='public.avuhz_acquisition_intake_requests'::regclass "
            "AND acl.grantee=(SELECT oid FROM pg_roles WHERE rolname='avuhz_command_service');"
        ).stdout.decode().strip(),"0")

if __name__=="__main__":
    unittest.main()
