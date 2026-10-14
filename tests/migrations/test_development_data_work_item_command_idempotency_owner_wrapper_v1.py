"""Source-only PG17 certification of the DEVELOPMENT DATA shared ledger wrapper.

Provider SQL is never called. Integration tests use one disposable Docker
PostgreSQL database whose host port is not published.
"""
from __future__ import annotations

import hashlib
import os
import re
import unittest
from pathlib import Path

import test_development_data_work_item_table_owner_install_v1 as previous

ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "supabase/migrations/20261014041000_enable_shared_work_item_command_idempotency.sql"
WRAPPER = ROOT / "supabase/provider-artifacts/development-data/current/development_data_work_item_command_idempotency_owner_wrapper_v1.sql"
SOURCE_SHA = "e3b4fc664b95fe4395b1b885a727f25a92cd4d941492bd324c51d54939b77d33"
START = "-- CANONICAL_WORK_ITEM_IDEMPOTENCY_SQL_BODY_BEGIN\n"
END = "\n-- CANONICAL_WORK_ITEM_IDEMPOTENCY_SQL_BODY_END"
CONTAINER = os.getenv("AVUHZ_LOCAL_POSTGRES_CONTAINER")
BASE = previous.WorkItemOwnerInstallPostgresTests
SYNTHETIC = previous.SYNTHETIC


def original_body():
    source = MIGRATION.read_text()
    assert hashlib.sha256(source.encode()).hexdigest() == SOURCE_SHA
    found = re.search(r"(?m)^BEGIN;\n([\s\S]*?)^COMMIT;\s*\Z", source)
    if found is None or len(re.findall(r"(?m)^BEGIN;$", source)) != 1:
        raise AssertionError("canonical SQL transaction drift")
    return found.group(1).strip()


class WorkItemCommandIdempotencyOwnerStaticTests(unittest.TestCase):
    def test_single_transaction_exact_canonical_body(self):
        s = WRAPPER.read_text()
        self.assertEqual(s.count(START), 1)
        self.assertEqual(s.count(END), 1)
        self.assertEqual(s.split(START, 1)[1].split(END, 1)[0].strip(), original_body())
        self.assertEqual(len(re.findall(r"(?m)^BEGIN;$", s)), 1)
        self.assertEqual(len(re.findall(r"(?m)^COMMIT;$", s)), 1)
        self.assertIn("NOT APPROVED FOR REMOTE EXECUTION", s)
        self.assertIn("DEVELOPMENT DATA gnuqaefotwgkwurjpyik", s)
        self.assertIn("DEVELOPMENT AUTH pwlhruwutoitnieactol", s)
        self.assertIn(SOURCE_SHA, s)

    def test_only_one_temporary_set_grant_and_revoke_with_exact_pins(self):
        s = WRAPPER.read_text()
        for expr in (
            "GRANT avuhz_data_migration_service_dev TO postgres",
            "REVOKE avuhz_data_migration_service_dev FROM postgres GRANTED BY postgres;",
            "SET LOCAL ROLE avuhz_data_migration_service_dev;",
            "\nRESET ROLE;\n",
            "SET LOCAL search_path = pg_catalog, pg_temp;",
        ):
            self.assertEqual(s.count(expr), 1, expr)
        for digest in (
            "ffe09fa849ce1bc165c7565e24be9dc14b96b33752a79276264181b378ecaa58",
            "5fe8ad76352fc2f3a43b698f37097df4e647b6a353022c99f96eaff4dc24f268",
            "1742b76d0dd8d99c26eafc15fe3c8f705a6fa58341b43a7c6fab669091df9e88",
        ):
            self.assertIn(digest, s)
        self.assertLess(s.index("GRANT avuhz_data_migration_service_dev"),
                        s.index("SET LOCAL ROLE"))
        self.assertLess(s.index("SET LOCAL ROLE"), s.index(START))
        self.assertLess(s.index(END), s.index("RESET ROLE;"))
        self.assertLess(s.index("RESET ROLE;"),
                        s.index("REVOKE avuhz_data_migration_service_dev"))
        self.assertNotRegex(s, r"(?im)^\s*(?:INSERT|DELETE|UPDATE|CREATE\s+ROLE)\s")
        self.assertNotIn("GRANT CREATE ON SCHEMA", s)
        self.assertFalse((ROOT / "supabase/migrations/development_data_work_item_command_idempotency_owner_wrapper_v1.sql").exists())


@unittest.skipUnless(CONTAINER, "disposable LOCAL PostgreSQL 17 required")
class WorkItemCommandIdempotencyOwnerPostgresTests(unittest.TestCase):
    docker = BASE.__dict__["docker"]
    apply = BASE.__dict__["apply"]
    query = BASE.__dict__["query"]
    _install_policies_and_event = BASE._install_policies_and_event

    def setUp(self):
        BASE.setUp(self)
        self.apply(BASE.source())
        # Host Supabase has a distinct restricted runtime LOGIN role with
        # exactly two provider-approved membership edges. Recreate those
        # edges only in the disposable PostgreSQL fixture.
        self.query(
            "CREATE ROLE avuhz_data_runtime_service_dev LOGIN "
            "NOINHERIT NOBYPASSRLS;"
        )
        self.query(
            "GRANT avuhz_command_service TO avuhz_data_runtime_service_dev "
            "WITH ADMIN FALSE, INHERIT FALSE, SET TRUE "
            "GRANTED BY avuhz_data_migration_service_dev;"
        )
        self.query(
            "GRANT avuhz_data_runtime_service_dev "
            "TO avuhz_hosted_data_postgres_sim_v1 "
            "WITH ADMIN TRUE, INHERIT FALSE, SET FALSE "
            "GRANTED BY postgres;"
        )

    def tearDown(self):
        try:
            self.query(
                "REVOKE avuhz_command_service FROM "
                "avuhz_data_runtime_service_dev "
                "GRANTED BY avuhz_data_migration_service_dev;"
            )
            self.query(
                "REVOKE avuhz_data_runtime_service_dev "
                "FROM avuhz_hosted_data_postgres_sim_v1 "
                "GRANTED BY postgres;"
            )
            self.query("DROP ROLE avuhz_data_runtime_service_dev;")
        finally:
            BASE.tearDown(self)

    @staticmethod
    def source():
        # Local cluster grants provider edges from superuser postgres instead
        # of hosted Supabase's supabase_admin. All other source remains exact.
        return SYNTHETIC(WRAPPER.read_text()).replace(
            "g.rolname='supabase_admin'", "g.rolname='postgres'"
        )

    def constraint_status(self):
        return self.query(
            "SELECT conname||':'||pg_get_constraintdef(oid) "
            "FROM pg_constraint WHERE conrelid="
            "'public.avuhz_idempotency_records'::regclass "
            "AND conname IN ("
            "'avuhz_idempotency_records_command_type_check',"
            "'avuhz_idempotency_records_subject_type_check') ORDER BY conname;"
        )

    def temp_grant_count(self):
        return self.query(
            "SELECT count(*) FROM pg_auth_members m "
            "WHERE m.roleid='avuhz_data_migration_service_dev'::regrole "
            "AND m.member='avuhz_hosted_data_postgres_sim_v1'::regrole "
            "AND m.grantor=m.member;"
        )

    def test_forward_reuses_same_ledger_and_seals_role_grant(self):
        before = self.constraint_status()
        self.assertNotIn("TransitionWorkItem", before)
        self.assertNotIn("WORK_ITEM", before)
        self.assertEqual(self.temp_grant_count(), "0")
        self.apply(self.source())
        after = self.constraint_status()
        self.assertIn("TransitionWorkItem", after)
        self.assertIn("WORK_ITEM", after)
        self.assertEqual(self.temp_grant_count(), "0")
        self.assertEqual(self.query(
            "SELECT pg_get_userbyid(relowner) FROM pg_class "
            "WHERE oid='public.avuhz_idempotency_records'::regclass;"
        ), "avuhz_data_migration_service_dev")
        self.assertEqual(self.query(
            "SELECT relrowsecurity FROM pg_class "
            "WHERE oid='public.avuhz_idempotency_records'::regclass;"
        ), "t")
        self.assertEqual(self.query(
            "SELECT count(*) FROM public.avuhz_idempotency_records;"
        ), "0")

    def test_preflight_denies_changed_original_check_and_rolls_back(self):
        self.query(
            "ALTER TABLE public.avuhz_idempotency_records "
            "DROP CONSTRAINT avuhz_idempotency_records_subject_type_check;"
            "ALTER TABLE public.avuhz_idempotency_records "
            "ADD CONSTRAINT avuhz_idempotency_records_subject_type_check "
            "CHECK (subject_type IN ('IMPLEMENTATION_HANDOFF'));"
        )
        before = self.constraint_status()
        failure = self.apply(self.source(), check=False)
        self.assertNotEqual(failure.returncode, 0)
        self.assertIn(b"AVUHZ_WORK_ITEM_IDEMPOTENCY_SCHEMA_DRIFT_STOP",
                      failure.stderr)
        self.assertEqual(before, self.constraint_status())
        self.assertEqual(self.temp_grant_count(), "0")

    def test_unexpected_grantee_blocks_before_temporary_role_grant(self):
        rogue = "avuhz_work_item_acl_rogue_local"
        self.query(f"CREATE ROLE {rogue} NOLOGIN;")
        try:
            self.query(
                "GRANT SELECT ON TABLE public.avuhz_idempotency_records "
                f"TO {rogue};"
            )
            before = self.constraint_status()
            fail = self.apply(self.source(), check=False)
            self.assertNotEqual(fail.returncode, 0)
            self.assertIn(b"AVUHZ_WORK_ITEM_IDEMPOTENCY_SCHEMA_DRIFT_STOP",
                          fail.stderr)
            self.assertEqual(before, self.constraint_status())
            self.assertEqual(self.temp_grant_count(), "0")
        finally:
            self.query(
                "REVOKE SELECT ON TABLE public.avuhz_idempotency_records "
                f"FROM {rogue}; DROP ROLE {rogue};"
            )

    def test_command_role_createdb_attribute_blocks_preflight(self):
        self.query("ALTER ROLE avuhz_command_service CREATEDB;")
        try:
            before = self.constraint_status()
            fail = self.apply(self.source(), check=False)
            self.assertNotEqual(fail.returncode, 0)
            self.assertEqual(before, self.constraint_status())
            self.assertEqual(self.temp_grant_count(), "0")
        finally:
            self.query("ALTER ROLE avuhz_command_service NOCREATEDB;")

    def test_unexpected_command_role_member_denied(self):
        rogue = "avuhz_local_unexpected_command_member"
        self.query(f"CREATE ROLE {rogue} NOLOGIN;")
        try:
            self.query(
                f"GRANT avuhz_command_service TO {rogue} "
                "WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;"
            )
            before = self.constraint_status()
            fail = self.apply(self.source(), check=False)
            self.assertNotEqual(fail.returncode, 0)
            self.assertIn(b"AVUHZ_WORK_ITEM_IDEMPOTENCY_MEMBERSHIP_DRIFT_STOP",
                          fail.stderr)
            self.assertEqual(before, self.constraint_status())
            self.assertEqual(self.temp_grant_count(), "0")
        finally:
            self.query(f"REVOKE avuhz_command_service FROM {rogue};")
            self.query(f"DROP ROLE {rogue};")

    def test_extra_runtime_role_member_denied(self):
        rogue = "avuhz_local_unexpected_runtime_member"
        self.query(f"CREATE ROLE {rogue} NOLOGIN;")
        try:
            self.query(
                "GRANT avuhz_data_runtime_service_dev "
                f"TO {rogue} WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;"
            )
            before = self.constraint_status()
            fail = self.apply(self.source(), check=False)
            self.assertNotEqual(fail.returncode, 0)
            self.assertIn(b"AVUHZ_WORK_ITEM_IDEMPOTENCY_MEMBERSHIP_DRIFT_STOP",
                          fail.stderr)
            self.assertEqual(before, self.constraint_status())
            self.assertEqual(self.temp_grant_count(), "0")
        finally:
            self.query(f"REVOKE avuhz_data_runtime_service_dev FROM {rogue};")
            self.query(f"DROP ROLE {rogue};")

    def test_command_role_with_unexpected_parent_denied(self):
        rogue = "avuhz_local_unexpected_parent_role"
        self.query(f"CREATE ROLE {rogue} NOLOGIN;")
        try:
            self.query(
                f"GRANT {rogue} TO avuhz_command_service "
                "WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;"
            )
            before = self.constraint_status()
            fail = self.apply(self.source(), check=False)
            self.assertNotEqual(fail.returncode, 0)
            self.assertIn(b"AVUHZ_WORK_ITEM_IDEMPOTENCY_MEMBERSHIP_DRIFT_STOP",
                          fail.stderr)
            self.assertEqual(before, self.constraint_status())
            self.assertEqual(self.temp_grant_count(), "0")
        finally:
            self.query(f"REVOKE {rogue} FROM avuhz_command_service;")
            self.query(f"DROP ROLE {rogue};")

    def test_unexpected_work_item_policy_denied(self):
        self.query(
            "CREATE POLICY avuhz_unexpected_local_read "
            "ON public.avuhz_work_items FOR SELECT TO PUBLIC USING (true);"
        )
        before = self.constraint_status()
        fail = self.apply(self.source(), check=False)
        self.assertNotEqual(fail.returncode, 0)
        self.assertIn(b"AVUHZ_WORK_ITEM_IDEMPOTENCY_SCHEMA_DRIFT_STOP",
                      fail.stderr)
        self.assertEqual(before, self.constraint_status())
        self.assertEqual(self.temp_grant_count(), "0")

    def test_failure_after_temporary_grant_rolls_back(self):
        source = self.source().replace(
            "SET LOCAL ROLE avuhz_data_migration_service_dev;",
            "DO $injected$ BEGIN RAISE EXCEPTION 'LOCAL_INJECTED_STOP'; "
            "END $injected$;\n"
            "SET LOCAL ROLE avuhz_data_migration_service_dev;",
        )
        before = self.constraint_status()
        fail = self.apply(source, check=False)
        self.assertNotEqual(fail.returncode, 0)
        self.assertIn(b"LOCAL_INJECTED_STOP", fail.stderr)
        self.assertEqual(before, self.constraint_status())
        self.assertEqual(self.temp_grant_count(), "0")

    def test_postcondition_rejects_acl_widening_and_rolls_back(self):
        # Inject only in a throwaway LOCAL transaction while the table-owner
        # role is active. Do not change the canonical or approved wrapper.
        marker = "-- CANONICAL_WORK_ITEM_IDEMPOTENCY_SQL_BODY_END"
        source = self.source().replace(
            marker,
            marker + "\nGRANT DELETE ON TABLE "
            "public.avuhz_idempotency_records TO avuhz_command_service;",
        )
        before = self.constraint_status()
        fail = self.apply(source, check=False)
        self.assertNotEqual(fail.returncode, 0)
        self.assertIn(b"AVUHZ_WORK_ITEM_IDEMPOTENCY_POSTCONDITION_STOP",
                      fail.stderr)
        self.assertEqual(before, self.constraint_status())
        self.assertEqual(self.temp_grant_count(), "0")
        self.assertEqual(self.query(
            "SELECT has_table_privilege("
            "'avuhz_command_service','public.avuhz_idempotency_records',"
            "'DELETE');"
        ), "f")

    def test_no_retry_after_success(self):
        self.apply(self.source())
        after = self.constraint_status()
        failure = self.apply(self.source(), check=False)
        self.assertNotEqual(failure.returncode, 0)
        self.assertEqual(after, self.constraint_status())
        self.assertEqual(self.temp_grant_count(), "0")


if __name__ == "__main__":
    unittest.main()
