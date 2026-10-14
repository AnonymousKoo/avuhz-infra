"""Future shared deadline field: source-only static and disposable PG17 contract."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]
MIGRATIONS = ROOT / "supabase" / "migrations"
NEW = MIGRATIONS / "20261014180000_add_shared_work_item_next_action_due_at.sql"
SOURCES = (
    "20260831120000_rebaseline_provider_neutral_avuhz.sql",
    "20261002213000_enable_implementation_handoff_command_intake.sql",
    "20261012140000_enable_shared_acquisition_intake_received_event.sql",
    "20261014031000_enable_shared_work_intake_lifecycle_events.sql",
    "20261014034000_create_shared_work_items.sql",
)
CONTAINER = os.getenv("AVUHZ_LOCAL_POSTGRES_CONTAINER")
DB = "avuhz_shared_deadline_forward_v1"


class WorkItemDeadlineStaticTests(unittest.TestCase):
    def test_exact_one_column_forward_only_and_no_tenant_bypass(self):
        sql = NEW.read_text()
        for marker in (
            "Repository-only candidate", "DEVELOPMENT DATA gnuqaefotwgkwurjpyik",
            "AVUHZ_SHARED_WORK_ITEM_DEADLINE_PREFLIGHT_STOP",
            "ADD COLUMN next_action_due_at timestamptz",
            "GRANT INSERT(next_action_due_at), UPDATE(next_action_due_at)",
            "avuhz_command_service_tenant_isolation", "relforcerowsecurity",
            "AVUHZ_SHARED_WORK_ITEM_DEADLINE_POSTCONDITION_STOP",
        ):
            self.assertIn(marker, sql)
        self.assertEqual(sql.count("ADD COLUMN next_action_due_at"), 1)
        self.assertTrue(sql.strip().endswith("COMMIT;"))
        self.assertEqual(sql.count("BEGIN;"), 1)
        for forbidden in ("CREATE TABLE", "CREATE ROLE", "GRANT ALL", "TO anon",
                          "TO authenticated", "TO service_role", "DISABLE ROW LEVEL",
                          "contact_email", "contact_phone", "INSERT INTO",
                          "BYPASSRLS", "SECURITY DEFINER"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, sql)


@unittest.skipUnless(CONTAINER, "requires a disposable PG17 Docker container")
class WorkItemDeadlinePostgresTests(unittest.TestCase):
    @classmethod
    def run_sql(cls, sql: str, check: bool = True):
        output = subprocess.run(
            ["docker", "exec", "-i", CONTAINER, "psql", "-X", "-v", "ON_ERROR_STOP=1",
             "-At", "-U", "postgres", "-d", DB],
            input=sql.encode(), capture_output=True, check=False,
        )
        if check and output.returncode:
            raise AssertionError(output.stderr.decode()[-1400:])
        return output

    @classmethod
    def setUpClass(cls):
        import re
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", CONTAINER or ""):
            raise ValueError("unsafe disposable container identifier")

    @classmethod
    def reset_disposable_database(cls):
        # PostgreSQL roles/memberships are cluster-global, unlike test tables.
        # Clean adversarial roles after dropping this isolated database.
        subprocess.run(["docker", "exec", CONTAINER, "dropdb", "-U", "postgres",
                        "--if-exists", DB], check=True, capture_output=True)
        cleanup=subprocess.run(
            ["docker", "exec", CONTAINER, "psql", "-X", "-v", "ON_ERROR_STOP=1",
             "-U", "postgres", "-d", "postgres", "-c",
             "DROP ROLE IF EXISTS avuhz_deadline_bypass, avuhz_deadline_bridge, "
             "avuhz_deadline_parent_owner, avuhz_deadline_migration_owner, "
             "anon, authenticated;"],
            capture_output=True, check=False,
        )
        if cleanup.returncode:
            raise AssertionError(cleanup.stderr.decode()[-1200:])

    def setUp(self):
        self.reset_disposable_database()
        subprocess.run(["docker", "exec", CONTAINER, "createdb", "-U", "postgres",
                        DB], check=True, capture_output=True)
        for name in SOURCES:
            self.run_sql((MIGRATIONS/name).read_text())

    def tearDown(self):
        self.reset_disposable_database()

    @staticmethod
    def as_command(tenant: str, statement: str):
        return ("BEGIN; SET LOCAL ROLE avuhz_command_service; "
                f"SELECT set_config('avuhz.tenant_id','{tenant}',true);"
                + statement + " COMMIT;")

    def assert_preflight_denies_without_column(self):
        outcome=self.run_sql(NEW.read_text(),check=False)
        self.assertNotEqual(outcome.returncode,0)
        self.assertIn("AVUHZ_SHARED_WORK_ITEM_DEADLINE_PREFLIGHT_STOP",
                      outcome.stderr.decode())
        self.assertEqual(self.run_sql(
            "SELECT count(*) FROM pg_attribute WHERE attrelid='public.avuhz_work_items'::regclass "
            "AND attname='next_action_due_at' AND NOT attisdropped;"
        ).stdout.decode().strip(),"0")

    def test_same_name_tenant_policy_with_true_or_is_denied(self):
        self.run_sql("""
          DROP POLICY avuhz_command_service_tenant_isolation ON public.avuhz_work_items;
          CREATE POLICY avuhz_command_service_tenant_isolation
            ON public.avuhz_work_items FOR ALL TO avuhz_command_service
            USING (true OR tenant_id=nullif(current_setting('avuhz.tenant_id',true),'')::uuid)
            WITH CHECK (true OR tenant_id=nullif(current_setting('avuhz.tenant_id',true),'')::uuid);
        """)
        self.assert_preflight_denies_without_column()

    def test_public_acl_privilege_even_without_anon_role_is_denied(self):
        self.run_sql("GRANT SELECT ON public.avuhz_work_items TO PUBLIC;")
        self.assert_preflight_denies_without_column()

    def test_named_anon_trigger_acl_is_denied(self):
        # Less common privileges must not slip through an allowlist of verbs.
        self.run_sql("CREATE ROLE anon NOLOGIN; "
                     "GRANT TRIGGER ON public.avuhz_work_items TO anon;")
        self.assert_preflight_denies_without_column()

    def test_named_authenticated_column_references_acl_is_denied(self):
        self.run_sql("CREATE ROLE authenticated NOLOGIN; "
                     "GRANT REFERENCES (source) ON public.avuhz_work_items TO authenticated;")
        self.assert_preflight_denies_without_column()

    def test_existing_tablewide_insert_is_denied(self):
        self.run_sql("GRANT INSERT ON public.avuhz_work_items TO avuhz_command_service;")
        self.assert_preflight_denies_without_column()

    def test_transitive_role_membership_to_bypassrls_is_denied(self):
        self.run_sql("""
          CREATE ROLE avuhz_deadline_bypass NOLOGIN BYPASSRLS;
          CREATE ROLE avuhz_deadline_bridge NOLOGIN;
          GRANT avuhz_deadline_bypass TO avuhz_deadline_bridge;
          GRANT avuhz_deadline_bridge TO avuhz_command_service;
        """)
        self.assert_preflight_denies_without_column()

    def test_owner_role_membership_is_denied(self):
        self.run_sql("""
          CREATE ROLE avuhz_deadline_parent_owner NOLOGIN;
          GRANT avuhz_deadline_parent_owner TO avuhz_command_service;
        """)
        self.assert_preflight_denies_without_column()

    def test_missing_table_uses_safe_preflight_error(self):
        self.run_sql("DROP TABLE public.avuhz_work_items;")
        outcome=self.run_sql(NEW.read_text(),check=False)
        self.assertNotEqual(outcome.returncode,0)
        self.assertIn("AVUHZ_SHARED_WORK_ITEM_DEADLINE_PREFLIGHT_STOP",
                      outcome.stderr.decode())
        self.assertNotIn('does not exist',outcome.stderr.decode())

    def test_owner_session_role_selection_before_begin_supported(self):
        self.run_sql("""
          CREATE ROLE avuhz_deadline_migration_owner NOLOGIN;
          ALTER TABLE public.avuhz_work_items OWNER TO avuhz_deadline_migration_owner;
          GRANT avuhz_deadline_migration_owner TO postgres;
        """)
        self.assert_preflight_denies_without_column()
        outcome=self.run_sql(
            "SET ROLE avuhz_deadline_migration_owner;\n"
            +NEW.read_text()
            +"\nRESET ROLE;")
        self.assertEqual(outcome.returncode,0)
        self.assertEqual(self.run_sql(
            "SELECT count(*) FROM pg_attribute WHERE attrelid='public.avuhz_work_items'::regclass "
            "AND attname='next_action_due_at' AND NOT attisdropped;"
        ).stdout.decode().strip(),"1")

    def test_nullable_field_and_no_new_policy_or_anon_grant(self):
        self.run_sql(NEW.read_text())
        sql = """SELECT atttypid='timestamptz'::regtype,
                     NOT attnotnull,NOT atthasdef
                   FROM pg_attribute WHERE attrelid='public.avuhz_work_items'::regclass
                   AND attname='next_action_due_at';
                   SELECT relrowsecurity,relforcerowsecurity FROM pg_class
                   WHERE oid='public.avuhz_work_items'::regclass;
                   SELECT count(*) FROM pg_policies
                   WHERE schemaname='public' and tablename='avuhz_work_items';
                   SELECT has_column_privilege('avuhz_command_service',
                     'public.avuhz_work_items','next_action_due_at','UPDATE');
                   SELECT count(*) FROM pg_roles r
                     WHERE r.rolname IN ('anon','authenticated','service_role')
                       AND (has_table_privilege(r.oid,'public.avuhz_work_items','SELECT')
                         OR has_table_privilege(r.oid,'public.avuhz_work_items','UPDATE')
                         OR has_table_privilege(r.oid,'public.avuhz_work_items','INSERT'));
                   SELECT has_column_privilege('avuhz_command_service',
                     'public.avuhz_work_items','tenant_id','UPDATE');"""
        self.assertEqual(self.run_sql(sql).stdout.decode().strip().splitlines(),
                         ["t|t|t", "t|t", "1", "t", "0", "f"])

    def test_tenant_scoped_due_write_and_other_tenant_denial(self):
        self.run_sql(NEW.read_text())
        a="a4730000-0000-4000-8000-000000000001"
        b="a4730000-0000-4000-8000-000000000002"
        item="a4730000-0000-4000-8000-000000000031"
        insert=("INSERT INTO public.avuhz_work_items "
                "(tenant_id,work_item_id,owner_reference,source,classification,state,record_version) "
                "VALUES ('{t}','{item}','worker.owner','web','service_request','OPEN',1);")
        for tenant in (a,b):
            self.run_sql(self.as_command(tenant,insert.format(t=tenant,item=item)))
        self.run_sql(self.as_command(a,
            f"UPDATE public.avuhz_work_items SET next_action_due_at='2030-01-15T16:00:00Z' "
            f"WHERE work_item_id='{item}' AND tenant_id='{a}';"))
        result=self.run_sql(self.as_command(a,
            "SELECT count(*) FROM public.avuhz_work_items WHERE next_action_due_at IS NOT NULL;")).stdout.decode()
        self.assertIn("\n1\n",result)
        result=self.run_sql(self.as_command(b,
            "SELECT count(*) FROM public.avuhz_work_items WHERE next_action_due_at IS NOT NULL;")).stdout.decode()
        self.assertIn("\n0\n",result)
        cross=self.run_sql(self.as_command(a,
            f"UPDATE public.avuhz_work_items SET next_action_due_at='2030-01-16T16:00:00Z' WHERE tenant_id='{b}';"))
        self.assertIn("UPDATE 0",cross.stdout.decode())
        no_tenant=self.run_sql(
            "BEGIN; SET LOCAL ROLE avuhz_command_service; "
            "UPDATE public.avuhz_work_items SET next_action_due_at=now(); COMMIT;", check=False,
        )
        # An absent tenant scope must not affect rows, whether UPDATE 0 or denied.
        self.assertTrue(no_tenant.returncode != 0 or b"UPDATE 0" in no_tenant.stdout)

    def test_repeat_migration_and_injected_failure_rollback(self):
        self.run_sql(NEW.read_text())
        again=self.run_sql(NEW.read_text(),check=False)
        self.assertNotEqual(again.returncode,0)
        self.assertIn("AVUHZ_SHARED_WORK_ITEM_DEADLINE_PREFLIGHT_STOP",
                      again.stderr.decode())
        self.assertEqual(self.run_sql(
            "SELECT COUNT(*) FROM pg_attribute WHERE attrelid='public.avuhz_work_items'::regclass "
            "AND attname='next_action_due_at' AND NOT attisdropped;"
        ).stdout.decode().strip(),"1")

    def test_rollback_on_injected_post_ddl_failure(self):
        source=NEW.read_text()
        injection="DO $inject$ BEGIN RAISE EXCEPTION 'INJECTED_STOP'; END $inject$;\nCOMMIT;"
        bad=source.replace("COMMIT;",injection)
        attempted=self.run_sql(bad,check=False)
        self.assertNotEqual(attempted.returncode,0)
        self.assertIn("INJECTED_STOP",attempted.stderr.decode())
        self.assertEqual(self.run_sql(
            "SELECT COUNT(*) FROM pg_attribute WHERE attrelid='public.avuhz_work_items'::regclass "
            "AND attname='next_action_due_at' AND NOT attisdropped;"
        ).stdout.decode().strip(),"0")


if __name__ == "__main__":
    unittest.main()
