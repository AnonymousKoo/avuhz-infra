"""Local-only PG17 certification of the shared System #001 work-item table.

No hosted provider connection: destructive fixture setup uses a unique
disposable PostgreSQL database within an isolated ephemeral container.
"""
from __future__ import annotations

import os
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MIGRATIONS = ROOT / "supabase" / "migrations"
SOURCES = [
    MIGRATIONS / "20260831120000_rebaseline_provider_neutral_avuhz.sql",
    MIGRATIONS / "20261002213000_enable_implementation_handoff_command_intake.sql",
    MIGRATIONS / "20261012140000_enable_shared_acquisition_intake_received_event.sql",
    MIGRATIONS / "20261014031000_enable_shared_work_intake_lifecycle_events.sql",
]
CANDIDATE = MIGRATIONS / "20261014034000_create_shared_work_items.sql"
CONTAINER = os.getenv("AVUHZ_LOCAL_POSTGRES_CONTAINER")
DB = "avuhz_work_item_table_forward_contract"
TENANT_A = "a4730000-0000-4000-8000-000000000001"
TENANT_B = "a4730000-0000-4000-8000-000000000002"
ITEM = "a4730000-0000-4000-8000-000000000031"


class WorkItemTableStaticTests(unittest.TestCase):
    def test_new_table_is_source_only_no_app_route_and_enforces_rls(self):
        sql = CANDIDATE.read_text()
        for required in (
            "Remote application is unauthorized by default",
            "AVUHZ_SHARED_WORK_ITEMS_PREFLIGHT_STOP",
            "CREATE TABLE public.avuhz_work_items",
            "ENABLE ROW LEVEL SECURITY",
            "FORCE ROW LEVEL SECURITY",
            "REVOKE ALL ON TABLE public.avuhz_work_items FROM PUBLIC",
            "avuhz_command_service_tenant_isolation",
            "current_setting('avuhz.tenant_id',true)",
            "GRANT SELECT ON TABLE public.avuhz_work_items TO avuhz_command_service",
            "GRANT INSERT (", "GRANT UPDATE (",
            "COMMIT;",
        ):
            self.assertIn(required, sql)
        self.assertTrue(sql.strip().endswith("COMMIT;"))
        self.assertEqual(sql.count("CREATE TABLE public.avuhz_work_items"), 1)
        self.assertNotRegex(sql, r"(?im)^\s*(INSERT|DELETE|UPDATE)\s")
        for forbidden in ("BYPASSRLS", "CREATE ROLE", "GRANT ALL", "TO authenticated",
                          "TO anon", "TO service_role", "contact_email", "contact_phone"):
            # NOBYPASSRLS is not DDL in this candidate either; block all.
            self.assertNotIn(forbidden, sql)
        self.assertNotIn("avuhz_work_items", (ROOT / "src/avuhz_service/application.py").read_text())


@unittest.skipUnless(CONTAINER, "disposable local PostgreSQL required")
class WorkItemTablePostgresTests(unittest.TestCase):
    @classmethod
    def docker(cls, *args, source=None, check=True):
        call = subprocess.run(
            ["docker", "exec", *(["-i"] if source is not None else []), CONTAINER, *args],
            input=source.encode() if source is not None else None,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        if check and call.returncode:
            raise AssertionError(call.stderr.decode()[-1500:])
        return call

    @classmethod
    def sql(cls, source, *, check=True):
        return cls.docker(
            "psql", "-v", "ON_ERROR_STOP=1", "-At", "-U", "postgres", "-d", DB,
            source=source, check=check,
        )

    @classmethod
    def setup_db(cls, *, include_event_vocabulary=True):
        cls.docker("dropdb", "--if-exists", "-U", "postgres", DB)
        cls.docker("createdb", "-U", "postgres", DB)
        for migration in SOURCES[:4 if include_event_vocabulary else 3]:
            cls.sql(migration.read_text())

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if CONTAINER and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", CONTAINER):
            raise RuntimeError("invalid disposable container label")

    def setUp(self):
        self.setup_db()

    def tearDown(self):
        self.docker("dropdb", "--if-exists", "-U", "postgres", DB)

    def apply(self, *, check=True):
        return self.sql(CANDIDATE.read_text(), check=check)

    @staticmethod
    def as_command(tenant, statement):
        return (
            "BEGIN; SET LOCAL ROLE avuhz_command_service; "
            f"SELECT set_config('avuhz.tenant_id','{tenant}',true); "
            + statement + " COMMIT;"
        )

    def _create(self, tenant, *, item=ITEM, state="OPEN", source="web",
                classification="service_request", pending="NULL"):
        return (
            "INSERT INTO public.avuhz_work_items "
            "(tenant_id,work_item_id,owner_reference,pending_recipient_reference,"
            "source,classification,state,record_version) "
            f"VALUES ('{tenant}','{item}','worker.sender',{pending},"
            f"'{source}','{classification}','{state}',1);"
        )

    def test_force_rls_only_exact_tenant_policy_and_no_elevated_grants(self):
        self.apply()
        status = self.sql(
            "SELECT relrowsecurity::int||':'||relforcerowsecurity::int "
            "FROM pg_class WHERE oid='public.avuhz_work_items'::regclass;"
            "SELECT count(*) FROM pg_policies WHERE schemaname='public' "
            "AND tablename='avuhz_work_items';"
            "SELECT policyname||':'||array_to_string(roles,',')||':'||cmd "
            "FROM pg_policies WHERE schemaname='public' "
            "AND tablename='avuhz_work_items';"
        ).stdout.decode().strip().splitlines()
        self.assertEqual(status, ["1:1", "1", "avuhz_command_service_tenant_isolation:avuhz_command_service:ALL"])
        acl = self.sql(
            "SELECT has_table_privilege('avuhz_command_service',"
            "'public.avuhz_work_items','SELECT')::int;"
            "SELECT has_table_privilege('avuhz_command_service',"
            "'public.avuhz_work_items','DELETE')::int;"
            "SELECT has_column_privilege('avuhz_command_service',"
            "'public.avuhz_work_items','tenant_id','UPDATE')::int;"
            "SELECT has_column_privilege('avuhz_command_service',"
            "'public.avuhz_work_items','state','UPDATE')::int;"
            "SELECT has_column_privilege('avuhz_command_service',"
            "'public.avuhz_work_items','source','UPDATE')::int;"
            "SELECT EXISTS(SELECT 1 FROM pg_class c, "
            "LATERAL aclexplode(c.relacl) a "
            "WHERE c.oid='public.avuhz_work_items'::regclass "
            "AND a.grantee=0 AND a.privilege_type='SELECT')::int;"
        ).stdout.decode().strip().splitlines()
        self.assertEqual(acl, ["1", "0", "0", "1", "0", "0"])

    def test_tenant_scoped_positive_write_read_and_cross_tenant_denial(self):
        self.apply()
        for tenant in (TENANT_A, TENANT_B):
            self.sql(self.as_command(tenant, self._create(tenant)))
        def read(tenant):
            output = self.sql(self.as_command(
                tenant,
                "SELECT count(*) FROM public.avuhz_work_items "
                f"WHERE tenant_id='{tenant}' AND work_item_id='{ITEM}';",
            )).stdout.decode()
            return re.findall(r"(?m)^\d+$", output)[-1]
        self.assertEqual(read(TENANT_A), "1")
        self.assertEqual(read(TENANT_B), "1")
        unauthorized = self.sql(self.as_command(
            TENANT_A, "SELECT count(*) FROM public.avuhz_work_items "
            f"WHERE tenant_id='{TENANT_B}';"
        )).stdout.decode()
        self.assertEqual(re.findall(r"(?m)^\d+$", unauthorized)[-1], "0")
        cross_write = self.sql(self.as_command(TENANT_A, self._create(
            TENANT_B, item="a4730000-0000-4000-8000-000000000032",
        )), check=False)
        self.assertNotEqual(cross_write.returncode, 0)
        cross_update = self.sql(self.as_command(
            TENANT_A, "UPDATE public.avuhz_work_items SET record_version=2 "
            f"WHERE tenant_id='{TENANT_B}';"
        )).stdout.decode()
        self.assertIn("UPDATE 0", cross_update)
        self.assertEqual(read(TENANT_A), "1")
        self.assertEqual(read(TENANT_B), "1")

    def test_absent_tenant_and_forbidden_classifications_fail_closed(self):
        self.apply()
        no_tenant = self.sql(
            "BEGIN; SET LOCAL ROLE avuhz_command_service; "
            + self._create(TENANT_A) + " COMMIT;", check=False,
        )
        self.assertNotEqual(no_tenant.returncode, 0)
        for source, classification, pending, state in (
            ("john@example.com", "service_request", "NULL", "OPEN"),
            ("web", "John Smith", "NULL", "OPEN"),
            ("web", "service_request", "'worker.receiver'", "BLOCKED"),
            ("web", "service_request", "'worker.sender'", "OPEN"),
        ):
            with self.subTest(source=source, classification=classification, pending=pending):
                denied = self.sql(self.as_command(TENANT_A, self._create(
                    TENANT_A, source=source, classification=classification,
                    state=state, pending=pending,
                )), check=False)
                self.assertNotEqual(denied.returncode, 0)
        self.assertEqual(self.sql(
            "SELECT count(*) FROM public.avuhz_work_items;"
        ).stdout.decode().strip(), "0")

    def test_shared_runtime_cannot_rewrite_tenant_or_delete(self):
        self.apply()
        self.sql(self.as_command(TENANT_A, self._create(TENANT_A)))
        for sql in (
            f"UPDATE public.avuhz_work_items SET tenant_id='{TENANT_B}';",
            "UPDATE public.avuhz_work_items SET source='api';",
            "DELETE FROM public.avuhz_work_items;",
            "TRUNCATE public.avuhz_work_items;",
        ):
            with self.subTest(sql=sql):
                denied = self.sql(self.as_command(TENANT_A, sql), check=False)
                self.assertNotEqual(denied.returncode, 0)
        self.assertEqual(self.sql(
            "SELECT count(*) FROM public.avuhz_work_items;"
        ).stdout.decode().strip(), "1")

    def test_replay_and_preexisting_state_stop_without_changes(self):
        self.apply()
        before = self.sql(
            "SELECT count(*) FROM pg_policies WHERE schemaname='public' "
            "AND tablename='avuhz_work_items';"
        ).stdout.decode().strip()
        replay = self.apply(check=False)
        self.assertNotEqual(replay.returncode, 0)
        self.assertIn("AVUHZ_SHARED_WORK_ITEMS_PREFLIGHT_STOP", replay.stderr.decode())
        self.assertEqual(before, "1")

    def test_missing_shared_event_contract_stops_before_table_creation(self):
        self.setup_db(include_event_vocabulary=False)
        denied = self.apply(check=False)
        self.assertNotEqual(denied.returncode, 0)
        self.assertIn("AVUHZ_SHARED_WORK_ITEMS_PREFLIGHT_STOP", denied.stderr.decode())
        self.assertEqual(self.sql(
            "SELECT to_regclass('public.avuhz_work_items') IS NULL;"
        ).stdout.decode().strip(), "t")

    def test_injected_after_ddl_failure_rolls_back_entire_table(self):
        sql = CANDIDATE.read_text().replace(
            "COMMIT;",
            "DO $injected_stop$ BEGIN RAISE EXCEPTION 'INJECTED_TEST_STOP'; END "
            "$injected_stop$;\nCOMMIT;",
        )
        attempted = self.sql(sql, check=False)
        self.assertNotEqual(attempted.returncode, 0)
        self.assertIn("INJECTED_TEST_STOP", attempted.stderr.decode())
        self.assertEqual(self.sql(
            "SELECT to_regclass('public.avuhz_work_items') IS NULL;"
        ).stdout.decode().strip(), "t")


if __name__ == "__main__":
    unittest.main()
