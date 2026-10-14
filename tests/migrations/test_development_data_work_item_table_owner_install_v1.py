"""Review-only owner-aligned Work Item table migration certification.

Runs against one disposable LOCAL PostgreSQL 17 container/database.
Never contacts Supabase projects, never applies the wrapper to a host.
"""
from __future__ import annotations

import hashlib
import os
import re
import unittest
from pathlib import Path

import test_development_data_work_intake_event_owner_wrapper_v1 as previous

ROOT = Path(__file__).resolve().parents[2]
CURRENT = ROOT / "supabase/provider-artifacts/development-data/current"
WRAPPER = CURRENT / "development_data_work_item_table_owner_install_v1.sql"
ORIGINAL = ROOT / "supabase/migrations/20261014034000_create_shared_work_items.sql"
EXPECTED = "0e78557df12d063d1aad2af7bc267f7be1e89b13e08822746f19ebf76f783f68"
CONTAINER = os.getenv("AVUHZ_LOCAL_POSTGRES_CONTAINER")
PREVIOUS = previous.WorkIntakeOwnerWrapperPostgresTests
SYNTHETIC = previous.synthetic_sql
START = "-- CANONICAL_WORK_ITEM_TABLE_SQL_BODY_BEGIN\n"
END = "-- CANONICAL_WORK_ITEM_TABLE_SQL_BODY_END"
TENANT_A = "a4730000-0000-4000-8000-000000000001"
TENANT_B = "a4730000-0000-4000-8000-000000000002"
ITEM = "a4730000-0000-4000-8000-000000000031"


class WorkItemOwnerInstallStaticTests(unittest.TestCase):
    def test_source_exact_and_one_atomic_transaction(self):
        original = ORIGINAL.read_text()
        wrapped = WRAPPER.read_text()
        self.assertEqual(hashlib.sha256(original.encode()).hexdigest(), EXPECTED)
        match = re.search(r"(?m)^BEGIN;\n([\s\S]*?)^COMMIT;\s*\Z", original)
        self.assertIsNotNone(match)
        self.assertEqual(wrapped.count(START), 1)
        self.assertEqual(wrapped.count(END), 1)
        self.assertEqual(
            wrapped.split(START, 1)[1].split(END, 1)[0].strip(), match.group(1).strip()
        )
        self.assertEqual(len(re.findall(r"(?m)^BEGIN;$", wrapped)), 1)
        self.assertEqual(len(re.findall(r"(?m)^COMMIT;$", wrapped)), 1)
        self.assertIn("REVIEW ONLY; NOT APPROVED FOR HOSTED EXECUTION", wrapped)
        self.assertIn("DEVELOPMENT DATA gnuqaefotwgkwurjpyik", wrapped)
        self.assertIn("DEVELOPMENT AUTH pwlhruwutoitnieactol", wrapped)

    def test_temporary_privilege_grants_are_sealed_before_commit(self):
        sql = WRAPPER.read_text()
        grants = {
            "GRANT avuhz_data_migration_service_dev TO postgres": 1,
            "GRANT CREATE ON SCHEMA public TO avuhz_data_migration_service_dev;": 1,
            "REVOKE CREATE ON SCHEMA public FROM avuhz_data_migration_service_dev;": 1,
            "REVOKE avuhz_data_migration_service_dev FROM postgres GRANTED BY postgres;": 1,
            "ALTER TABLE public.avuhz_work_items OWNER TO avuhz_data_migration_service_dev;": 1,
        }
        for statement, expected in grants.items():
            self.assertEqual(sql.count(statement), expected, statement)
        self.assertLess(sql.index("GRANT CREATE ON SCHEMA"), sql.index(START))
        self.assertLess(sql.index(END), sql.index("ALTER TABLE public.avuhz_work_items OWNER"))
        self.assertLess(sql.index("ALTER TABLE public.avuhz_work_items OWNER"), sql.index("REVOKE CREATE ON SCHEMA"))
        self.assertLess(sql.index("REVOKE CREATE ON SCHEMA"), sql.index("COMMIT;"))
        self.assertNotRegex(sql, r"(?im)^\s*(?:INSERT|DELETE|UPDATE)\s+public\.")
        self.assertNotRegex(sql, r"(?im)^\s*CREATE\s+ROLE")
        self.assertFalse((ROOT / "supabase/migrations/development_data_work_item_table_owner_install_v1.sql").exists())


@unittest.skipUnless(CONTAINER, "disposable offline PostgreSQL 17 required")
class WorkItemOwnerInstallPostgresTests(unittest.TestCase):
    docker = PREVIOUS.__dict__["docker"]
    apply = PREVIOUS.__dict__["apply"]
    query = PREVIOUS.__dict__["query"]
    live_state = PREVIOUS.live_state

    def setUp(self):
        PREVIOUS.setUp(self)
        self._install_policies_and_event()

    def _install_policies_and_event(self):
        PREVIOUS._install_expected_acquisition_event_policies(self)
        self.apply(SYNTHETIC(previous.WRAPPER.read_text()))

    def tearDown(self):
        PREVIOUS.tearDown(self)

    @staticmethod
    def source():
        return SYNTHETIC(WRAPPER.read_text())

    def apply_candidate(self, *, check=True):
        return self.apply(self.source(), check=check)

    def status(self):
        return self.query(
            "SELECT to_regclass('public.avuhz_work_items') IS NOT NULL;"
            "SELECT pg_has_role('avuhz_hosted_data_postgres_sim_v1',"
            "'avuhz_data_migration_service_dev','SET');"
            "SELECT has_schema_privilege('avuhz_data_migration_service_dev',"
            "'public','CREATE');"
            "SELECT count(*) FROM pg_auth_members m "
            "WHERE m.roleid=(SELECT oid FROM pg_roles "
            "WHERE rolname='avuhz_data_migration_service_dev') "
            "AND m.member=(SELECT oid FROM pg_roles "
            "WHERE rolname='avuhz_hosted_data_postgres_sim_v1') "
            "AND m.grantor=m.member;"
        ).splitlines()

    def test_table_installed_as_existing_owner_forced_rls_only_tenant_policy(self):
        self.assertEqual(self.status(), ["f","f","f","0"])
        self.apply_candidate()
        self.assertEqual(self.status(), ["t","f","f","0"])
        status = self.query(
            "SELECT c.relowner::regrole::text||':'||c.relrowsecurity::int||':'||"
            "c.relforcerowsecurity::int FROM pg_class c "
            "WHERE c.oid='public.avuhz_work_items'::regclass;"
            "SELECT count(*) FROM pg_policies "
            "WHERE schemaname='public' AND tablename='avuhz_work_items';"
            "SELECT policyname||':'||array_to_string(roles,',')||':'||cmd "
            "FROM pg_policies WHERE schemaname='public' "
            "AND tablename='avuhz_work_items';"
        ).splitlines()
        self.assertEqual(
            status, ["avuhz_data_migration_service_dev:1:1", "1",
                     "avuhz_command_service_tenant_isolation:avuhz_command_service:ALL"]
        )
        permissions = self.query(
            "SELECT has_table_privilege('avuhz_command_service',"
            "'public.avuhz_work_items','SELECT')::int;"
            "SELECT has_table_privilege('avuhz_command_service',"
            "'public.avuhz_work_items','DELETE')::int;"
            "SELECT has_column_privilege('avuhz_command_service',"
            "'public.avuhz_work_items','tenant_id','UPDATE')::int;"
            "SELECT has_column_privilege('avuhz_command_service',"
            "'public.avuhz_work_items','state','UPDATE')::int;"
        ).splitlines()
        self.assertEqual(permissions, ["1","0","0","1"])

    def test_cross_tenant_write_denied_and_pii_shape_rejected(self):
        self.apply_candidate()
        def command(tenant, statement):
            return (
                "BEGIN; SET LOCAL ROLE avuhz_command_service; "
                f"SELECT set_config('avuhz.tenant_id','{tenant}',true); "
                + statement + " COMMIT;"
            )
        def insert(tenant, item):
            return (
                "INSERT INTO public.avuhz_work_items "
                "(tenant_id,work_item_id,owner_reference,source,classification)"
                f" VALUES ('{tenant}','{item}','worker.sender','web','service_request');"
            )
        self.query(command(TENANT_A, insert(TENANT_A, ITEM)))
        self.assertEqual(self.query("SELECT count(*) FROM public.avuhz_work_items"),"1")
        violation = self.apply(command(
            TENANT_B,
            insert(TENANT_A, "a4730000-0000-4000-8000-000000000099")
        ),user="postgres",check=False)
        self.assertNotEqual(violation.returncode,0)
        invalid = self.apply(command(
            TENANT_A,
            "INSERT INTO public.avuhz_work_items "
            "(tenant_id,work_item_id,owner_reference,source,classification) "
            f"VALUES ('{TENANT_A}','a4730000-0000-4000-8000-000000000098',"
            "'worker.sender','user@example.com','service_request');"
        ),user="postgres",check=False)
        self.assertNotEqual(invalid.returncode,0)
        self.assertEqual(self.query("SELECT count(*) FROM public.avuhz_work_items"),"1")

    def test_replay_denied_without_reopening_owner_or_schema_privileges(self):
        self.apply_candidate()
        before=self.status()
        failed=self.apply_candidate(check=False)
        self.assertNotEqual(failed.returncode,0)
        self.assertIn("AVUHZ_WORK_ITEM_INSTALL_SCHEMA_OR_EVENT_DRIFT_STOP",failed.stderr.decode())
        self.assertEqual(before,self.status())

    def test_failure_after_create_rolls_back_table_and_both_temp_grants(self):
        original=self.status()
        poisoned=self.source().replace(
            "\nALTER TABLE public.avuhz_work_items OWNER TO",
            "\nSELECT 1/0; -- rollback fixture\nALTER TABLE public.avuhz_work_items OWNER TO",
            1,
        )
        rejected=self.apply(poisoned,check=False)
        self.assertNotEqual(rejected.returncode,0)
        self.assertEqual(original,self.status())

    def test_failure_after_owner_transfer_rolls_back_everything(self):
        before=self.status()
        poisoned=self.source().replace(
            "\nREVOKE CREATE ON SCHEMA",
            "\nSELECT 1/0; -- synthetic transfer rollback\nREVOKE CREATE ON SCHEMA",
            1,
        )
        rejected=self.apply(poisoned,check=False)
        self.assertNotEqual(rejected.returncode,0)
        self.assertEqual(before,self.status())

    def test_preexisting_create_privilege_drift_is_denied(self):
        self.query(
            "GRANT CREATE ON SCHEMA public TO avuhz_data_migration_service_dev;"
        )
        before=self.status()
        rejected=self.apply_candidate(check=False)
        self.assertNotEqual(rejected.returncode,0)
        self.assertIn("AVUHZ_WORK_ITEM_INSTALL_SCHEMA_OR_EVENT_DRIFT_STOP",rejected.stderr.decode())
        self.assertEqual(before,self.status())

    def test_event_rls_drift_stops_before_ddl(self):
        self.query("ALTER TABLE public.avuhz_lifecycle_events DISABLE ROW LEVEL SECURITY;")
        before=self.status()
        rejected=self.apply_candidate(check=False)
        self.assertNotEqual(rejected.returncode,0)
        self.assertIn("AVUHZ_WORK_ITEM_INSTALL_SCHEMA_OR_EVENT_DRIFT_STOP",rejected.stderr.decode())
        self.assertEqual(before,self.status())

    def test_unapproved_role_cannot_execute(self):
        before=self.status()
        failed=self.apply(self.source(),user="postgres",check=False)
        self.assertNotEqual(failed.returncode,0)
        self.assertIn("AVUHZ_WORK_ITEM_INSTALL_SESSION_STOP",failed.stderr.decode())
        self.assertEqual(before,self.status())

    def test_unexpected_command_role_member_stops_before_create(self):
        role="avuhz_unreviewed_test_member"
        self.query(f"CREATE ROLE {role} NOLOGIN;")
        try:
            self.query(
                f"GRANT avuhz_command_service TO {role} "
                "WITH ADMIN FALSE, INHERIT TRUE, SET TRUE;"
            )
            before=self.status()
            rejected=self.apply_candidate(check=False)
            self.assertNotEqual(rejected.returncode,0)
            self.assertIn("AVUHZ_WORK_ITEM_INSTALL_OWNER_MEMBERSHIP_DRIFT_STOP",
                          rejected.stderr.decode())
            self.assertEqual(self.status(),before)
        finally:
            self.query(f"REVOKE avuhz_command_service FROM {role}; DROP ROLE {role};")

    def test_unexpected_postgres_default_table_grantee_stops_before_create(self):
        role="avuhz_unreviewed_default_recipient"
        executor="avuhz_hosted_data_postgres_sim_v1"
        self.query(f"CREATE ROLE {role} NOLOGIN;")
        try:
            self.query(
                f"ALTER DEFAULT PRIVILEGES FOR ROLE {executor} IN SCHEMA public "
                f"GRANT SELECT ON TABLES TO {role};"
            )
            before=self.status()
            rejected=self.apply_candidate(check=False)
            self.assertNotEqual(rejected.returncode,0)
            self.assertIn("AVUHZ_WORK_ITEM_INSTALL_SCHEMA_OR_EVENT_DRIFT_STOP",
                          rejected.stderr.decode())
            self.assertEqual(self.status(),before)
        finally:
            self.query(
                f"ALTER DEFAULT PRIVILEGES FOR ROLE {executor} IN SCHEMA public "
                f"REVOKE SELECT ON TABLES FROM {role}; DROP ROLE {role};"
            )

    def test_postcondition_rejects_extra_table_acl_and_rolls_back(self):
        role="avuhz_unreviewed_table_grantee"
        self.query(f"CREATE ROLE {role} NOLOGIN;")
        try:
            injected=self.source().replace(
                "\nREVOKE CREATE ON SCHEMA",
                "\nSET LOCAL ROLE avuhz_data_migration_service_dev; "
                f"GRANT UPDATE ON public.avuhz_work_items TO {role}; "
                "RESET ROLE;\nREVOKE CREATE ON SCHEMA",
                1,
            )
            before=self.status()
            denied=self.apply(injected,check=False)
            self.assertNotEqual(denied.returncode,0)
            self.assertIn("AVUHZ_WORK_ITEM_INSTALL_TABLE_RLS_OR_ACL_STOP",
                          denied.stderr.decode())
            self.assertEqual(before,self.status())
        finally:
            self.query(f"DROP ROLE {role};")

    def test_postcondition_rejects_extra_column_grant_and_rolls_back(self):
        injected=self.source().replace(
            "\nREVOKE CREATE ON SCHEMA",
            "\nSET LOCAL ROLE avuhz_data_migration_service_dev; "
            "GRANT UPDATE (tenant_id) ON public.avuhz_work_items "
            "TO avuhz_command_service; RESET ROLE;\nREVOKE CREATE ON SCHEMA",
            1,
        )
        before=self.status()
        denied=self.apply(injected,check=False)
        self.assertNotEqual(denied.returncode,0)
        self.assertIn("AVUHZ_WORK_ITEM_INSTALL_TABLE_RLS_OR_ACL_STOP",
                      denied.stderr.decode())
        self.assertEqual(before,self.status())

    def test_cross_tenant_read_update_and_unbound_tenant_are_denied(self):
        self.apply_candidate()
        tenant_a=TENANT_A
        tenant_b=TENANT_B
        self.query(
            "BEGIN; SET LOCAL ROLE avuhz_command_service; "
            f"SELECT set_config('avuhz.tenant_id','{tenant_a}',true); "
            "INSERT INTO public.avuhz_work_items "
            "(tenant_id,work_item_id,owner_reference,source,classification) "
            f"VALUES ('{tenant_a}','{ITEM}','worker.sender','web','service_request');"
            "COMMIT;"
        )
        cross=self.query(
            "BEGIN; SET LOCAL ROLE avuhz_command_service; "
            f"SELECT set_config('avuhz.tenant_id','{tenant_b}',true); "
            "SELECT count(*) FROM public.avuhz_work_items;"
            "UPDATE public.avuhz_work_items SET state='BLOCKED'; COMMIT;"
        )
        self.assertIn("UPDATE 0",cross)
        self.assertEqual(re.findall(r"(?m)^\d+$",cross),["0"])
        unbound=self.query(
            "BEGIN; SET LOCAL ROLE avuhz_command_service; "
            "SELECT count(*) FROM public.avuhz_work_items; COMMIT;"
        )
        self.assertEqual(re.findall(r"(?m)^\d+$",unbound),["0"])
        self.assertEqual(self.query(
            "SELECT state FROM public.avuhz_work_items;"
        ),"OPEN")

    def test_new_table_policy_drift_in_transaction_rolls_back_all(self):
        poisoned=self.source().replace(
            "\nREVOKE CREATE ON SCHEMA",
            "\nSET LOCAL ROLE avuhz_data_migration_service_dev; "
            "ALTER POLICY avuhz_command_service_tenant_isolation "
            "ON public.avuhz_work_items USING (true); "
            "RESET ROLE;\nREVOKE CREATE ON SCHEMA",
            1,
        )
        before=self.status()
        failed=self.apply(poisoned,check=False)
        self.assertNotEqual(failed.returncode,0)
        self.assertIn("AVUHZ_WORK_ITEM_INSTALL_TABLE_RLS_OR_ACL_STOP",failed.stderr.decode())
        self.assertEqual(before,self.status())


if __name__ == "__main__":
    unittest.main()
