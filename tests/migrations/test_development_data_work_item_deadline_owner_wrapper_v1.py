"""Review-only, single-transaction owner wrapper for Work Item deadline.

Hosted provider execution is NEVER performed by these tests. Docker must be
an explicitly isolated PostgreSQL 17 fixture with no published host port.
"""
from __future__ import annotations

import hashlib
import os
import re
import unittest
from pathlib import Path

import test_development_data_work_item_command_idempotency_owner_wrapper_v1 as previous

ROOT=Path(__file__).resolve().parents[2]
MIGRATION=ROOT/"supabase/migrations/20261014180000_add_shared_work_item_next_action_due_at.sql"
WRAPPER=ROOT/"supabase/provider-artifacts/development-data/current/development_data_work_item_deadline_owner_wrapper_v1.sql"
SOURCE_SHA="8511708bce3e2236772d41775ab5fd1fd255cf4097141f621cb604b203bbc9d2"
START="-- CANONICAL_WORK_ITEM_DEADLINE_SQL_BODY_BEGIN\n"
END="\n-- CANONICAL_WORK_ITEM_DEADLINE_SQL_BODY_END"
CONTAINER=os.getenv("AVUHZ_LOCAL_POSTGRES_CONTAINER")
PREV=previous.WorkItemCommandIdempotencyOwnerPostgresTests
SYNTHETIC=previous.SYNTHETIC


def canonical_body():
    src=MIGRATION.read_text()
    if hashlib.sha256(src.encode()).hexdigest()!=SOURCE_SHA:
        raise AssertionError("unexpected canonical deadline source digest")
    match=re.search(r"(?m)^BEGIN;\n([\s\S]*?)^COMMIT;\s*\Z",src)
    if match is None or len(re.findall(r"(?m)^BEGIN;$",src))!=1:
        raise AssertionError("noncanonical transaction shape")
    return match.group(1).strip()


class WorkItemDeadlineOwnerStaticTests(unittest.TestCase):
    def test_exact_source_single_transaction_review_only(self):
        source=WRAPPER.read_text()
        self.assertEqual(source.count(START),1)
        self.assertEqual(source.count(END),1)
        self.assertEqual(source.split(START,1)[1].split(END,1)[0].strip(),canonical_body())
        self.assertEqual(len(re.findall(r"(?m)^BEGIN;$",source)),1)
        self.assertEqual(len(re.findall(r"(?m)^COMMIT;$",source)),1)
        for required in (SOURCE_SHA,"NOT APPROVED FOR REMOTE EXECUTION",
                         "DEVELOPMENT DATA gnuqaefotwgkwurjpyik",
                         "DEVELOPMENT AUTH pwlhruwutoitnieactol",
                         "ae3f54bdf5768e8f4ce9473272ff965bdcdcfdea807c2eeb04f44aed40c31fbe",
                         "2ff513bf4ad6cb9ad181a9c8693d57a27aa0b1c8ec17eca8747ce0aec01d3b50",
                         "AVUHZ_SHARED_WORK_ITEM_DEADLINE_OWNER_SCHEMA_DRIFT_STOP"):
            self.assertIn(required,source)

    def test_temporary_role_edge_is_sealed_and_only_one_column_grant(self):
        text=WRAPPER.read_text()
        for marker in ("GRANT avuhz_data_migration_service_dev TO postgres",
                       "REVOKE avuhz_data_migration_service_dev FROM postgres GRANTED BY postgres;",
                       "SET LOCAL ROLE avuhz_data_migration_service_dev;",
                       "RESET ROLE;", "SET LOCAL search_path = pg_catalog, pg_temp;",
                       "ADD COLUMN next_action_due_at timestamptz",
                       "GRANT INSERT(next_action_due_at), UPDATE(next_action_due_at)"):
            self.assertEqual(text.count(marker),1,marker)
        self.assertLess(text.index("SET LOCAL ROLE"),text.index(START))
        self.assertLess(text.index(END),text.index("RESET ROLE;"))
        self.assertLess(text.index("RESET ROLE;"),text.index("REVOKE avuhz_data_migration_service_dev"))
        self.assertNotRegex(text,r"(?im)^\s*(?:CREATE ROLE|CREATE TABLE|GRANT ALL|INSERT INTO|DELETE FROM)\s")
        self.assertEqual(text.count("avuhz_command_service_tenant_isolation"),4)


@unittest.skipUnless(CONTAINER,"requires isolated no-network PostgreSQL17 fixture")
class WorkItemDeadlineOwnerPostgresTests(unittest.TestCase):
    docker=PREV.__dict__["docker"]
    apply=PREV.__dict__["apply"]
    query=PREV.__dict__["query"]
    _install_policies_and_event=PREV._install_policies_and_event

    def setUp(self):
        PREV.setUp(self)
        self.apply(PREV.source())

    @staticmethod
    def source():
        return SYNTHETIC(WRAPPER.read_text()).replace(
            "g.rolname='supabase_admin'","g.rolname='postgres'")

    def column_status(self):
        return self.query(
            "SELECT count(*) FROM pg_attribute WHERE "
            "attrelid='public.avuhz_work_items'::regclass AND "
            "attname='next_action_due_at' AND NOT attisdropped;")

    def temp_edge(self):
        return self.query(
            "SELECT count(*) FROM pg_auth_members m WHERE "
            "m.roleid='avuhz_data_migration_service_dev'::regrole "
            "AND m.member='avuhz_hosted_data_postgres_sim_v1'::regrole "
            "AND m.grantor=m.member;")

    def test_forward_exact_schema_and_revoked_owner_grant(self):
        self.assertEqual(self.column_status(),"0")
        self.assertEqual(self.temp_edge(),"0")
        self.apply(self.source())
        self.assertEqual(self.column_status(),"1")
        self.assertEqual(self.temp_edge(),"0")
        self.assertEqual(self.query(
            "SELECT atttypid='timestamptz'::regtype AND NOT attnotnull AND NOT atthasdef "
            "FROM pg_attribute WHERE attrelid='public.avuhz_work_items'::regclass "
            "AND attname='next_action_due_at';"),"t")
        self.assertEqual(self.query(
            "SELECT count(*) FROM pg_attribute a CROSS JOIN LATERAL aclexplode(a.attacl) x "
            "WHERE a.attrelid='public.avuhz_work_items'::regclass AND "
            "a.attname='next_action_due_at' AND NOT a.attisdropped;"),"2")
        self.assertEqual(self.query(
            "SELECT relrowsecurity::text||':'||relforcerowsecurity::text "
            "FROM pg_class WHERE oid='public.avuhz_work_items'::regclass;"),"true:true")

    def test_replay_denied_no_role_leak(self):
        self.apply(self.source())
        result=self.apply(self.source(),check=False)
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(self.column_status(),"1")
        self.assertEqual(self.temp_edge(),"0")

    def test_changed_tenant_policy_denied_before_grant(self):
        self.query("DROP POLICY avuhz_command_service_tenant_isolation ON public.avuhz_work_items;"
                   "CREATE POLICY avuhz_command_service_tenant_isolation ON public.avuhz_work_items "
                   "FOR ALL TO avuhz_command_service USING (true) WITH CHECK (true);")
        failed=self.apply(self.source(),check=False)
        self.assertNotEqual(failed.returncode,0)
        self.assertEqual(self.column_status(),"0")
        self.assertEqual(self.temp_edge(),"0")

    def test_extra_acl_denied_before_grant(self):
        self.query("GRANT SELECT ON public.avuhz_work_items TO PUBLIC;")
        failed=self.apply(self.source(),check=False)
        self.assertNotEqual(failed.returncode,0)
        self.assertEqual(self.column_status(),"0")
        self.assertEqual(self.temp_edge(),"0")

    def test_post_ddl_forced_failure_is_atomic(self):
        candidate=self.source().replace(
            "-- CANONICAL_WORK_ITEM_DEADLINE_SQL_BODY_END",
            "-- CANONICAL_WORK_ITEM_DEADLINE_SQL_BODY_END\n"
            "DO $deadline_local_injected_stop$ BEGIN "
            "RAISE EXCEPTION 'LOCAL_INJECTED_STOP'; END "
            "$deadline_local_injected_stop$;",1)
        failed=self.apply(candidate,check=False)
        self.assertNotEqual(failed.returncode,0)
        self.assertIn(b"LOCAL_INJECTED_STOP",failed.stderr)
        self.assertEqual(self.column_status(),"0")
        self.assertEqual(self.temp_edge(),"0")
