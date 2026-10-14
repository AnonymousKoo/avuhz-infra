"""Certify forward-only System #001 event vocabulary on disposable PostgreSQL.

No hosted Supabase access, no real clients, no credentials or DML migration.
"""
from __future__ import annotations

import os
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MIGRATIONS = ROOT / "supabase/migrations"
INITIAL = MIGRATIONS / "20260831120000_rebaseline_provider_neutral_avuhz.sql"
HANDOFF = MIGRATIONS / "20261002213000_enable_implementation_handoff_command_intake.sql"
ACQUISITION = MIGRATIONS / "20261012140000_enable_shared_acquisition_intake_received_event.sql"
CANDIDATE = MIGRATIONS / "20261014031000_enable_shared_work_intake_lifecycle_events.sql"
CONTAINER = os.getenv("AVUHZ_LOCAL_POSTGRES_CONTAINER")
DB = "avuhz_work_intake_event_forward_contract"
TENANT = "e1000000-0000-4000-8000-000000000082"
ITEM = "e1000000-0000-4000-8000-000000000083"
CORRELATION = "e1000000-0000-4000-8000-000000000084"

EVENT_TYPES = {
    "work_intake.opened": "OPEN",
    "work_intake.handoff_offered": "OPEN",
    "work_intake.handoff_accepted": "OPEN",
    "work_intake.handoff_cancelled": "OPEN",
    "work_intake.blocked": "BLOCKED",
    "work_intake.resumed": "OPEN",
    "work_intake.resolved": "RESOLVED",
}


class WorkIntakeEventStaticTests(unittest.TestCase):
    def test_forward_only_sql_preserves_existing_table_and_permissions(self):
        sql = CANDIDATE.read_text()
        self.assertIn("Remote application is unauthorized by default", sql)
        self.assertIn("WORK_INTAKE_EVENT_VOCABULARY_DRIFT_STOP", sql)
        self.assertIn("avuhz_command_service_tenant_isolation", sql)
        self.assertIn("BEGIN;", sql)
        self.assertTrue(sql.rstrip().endswith("COMMIT;"))
        self.assertEqual(sql.count("DROP CONSTRAINT"), 2)
        self.assertEqual(sql.count("ADD CONSTRAINT"), 2)
        self.assertIn("'WORK_ITEM'", sql)
        for event_type in EVENT_TYPES:
            self.assertIn("'" + event_type + "'", sql)
        for prohibited in (
            "GRANT ", "REVOKE ", "CREATE ROLE", "CREATE TABLE", "DROP TABLE",
            "UPDATE public.", "INSERT INTO", "DELETE FROM", "BYPASSRLS",
        ):
            self.assertNotIn(prohibited, sql.upper() if prohibited.isupper() else sql)
        self.assertNotIn("pwlhruwutoitnieactol", sql)
        self.assertFalse(CANDIDATE.name.startswith("development_data_"))


@unittest.skipUnless(CONTAINER, "disposable PostgreSQL required")
class WorkIntakeEventPostgresTests(unittest.TestCase):
    @classmethod
    def docker(cls, *args, input_bytes=None, check=True):
        call = subprocess.run(
            ["docker", "exec", *(["-i"] if input_bytes is not None else []),
             CONTAINER, *args], input=input_bytes, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=False,
        )
        if check and call.returncode:
            raise AssertionError(call.stderr.decode().strip())
        return call

    @classmethod
    def sql(cls, query, check=True):
        return cls.docker(
            "psql", "-v", "ON_ERROR_STOP=1", "-At", "-U", "postgres",
            "-d", DB, "-c", query, check=check,
        )

    @classmethod
    def apply(cls, source, check=True):
        return cls.docker(
            "psql", "-v", "ON_ERROR_STOP=1", "-U", "postgres",
            "-d", DB, input_bytes=source.encode(), check=check,
        )

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if CONTAINER and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", CONTAINER):
            raise RuntimeError("invalid disposable container label")

    def setUp(self):
        self.docker("dropdb", "--if-exists", "-U", "postgres", DB)
        self.docker("createdb", "-U", "postgres", DB)
        for source in (INITIAL, HANDOFF, ACQUISITION):
            self.apply(source.read_text())

    def tearDown(self):
        self.docker("dropdb", "--if-exists", "-U", "postgres", DB)

    def _constraint(self, name):
        return self.sql(
            "select pg_get_constraintdef(oid) from pg_constraint where "
            "conrelid='public.avuhz_lifecycle_events'::regclass "
            "and conname='" + name + "';"
        ).stdout.decode().strip()

    def _insert(self, event_type, subject_type, event_id, *, state="OPEN"):
        return (
            "insert into public.avuhz_lifecycle_events "
            "(lifecycle_event_id,tenant_id,event_type,event_schema_version,"
            "authoritative_subject_type,authoritative_subject_id,"
            "authoritative_subject_version,occurred_at,producer_reference,"
            "correlation_id,idempotency_key,visibility,sanitized_metadata) values ("
            "'" + event_id + "','" + TENANT + "','" + event_type + "',1,'"
            + subject_type + "','" + ITEM + "',1,"
            "'2030-01-15T15:00:00Z','command.service-01','" + CORRELATION
            + "','work-test-" + event_id[-4:]
            + "','TENANT_OPERATIONAL','{\"work_item_id\":\"" + ITEM
            + "\",\"state\":\"" + state + "\"}'::jsonb)"
        )

    def test_all_seven_work_events_allowed_and_prior_security_preserved(self):
        old = self._constraint("avuhz_lifecycle_events_event_type_check")
        self.assertIn("acquisition.intake.received", old)
        self.assertNotIn("work_intake.opened", old)
        self.apply(CANDIDATE.read_text())
        rls = self.sql(
            "select relrowsecurity::int||':'||relforcerowsecurity::int "
            "from pg_class where oid='public.avuhz_lifecycle_events'::regclass;"
            "select count(*) from pg_policies where schemaname='public' "
            "and tablename='avuhz_lifecycle_events';"
        ).stdout.decode().splitlines()
        self.assertEqual(rls, ["1:0", "1"])
        self.assertIn("acquisition.intake.received", self._constraint("avuhz_lifecycle_events_event_type_check"))
        self.assertIn("IMPLEMENTATION_HANDOFF", self._constraint("avuhz_lifecycle_events_authoritative_subject_type_check"))
        self.assertIn("WORK_ITEM", self._constraint("avuhz_lifecycle_events_authoritative_subject_type_check"))
        for i, (kind, state) in enumerate(EVENT_TYPES.items(), 1):
            self.sql(self._insert(
                kind, "WORK_ITEM", f"e1000000-0000-4000-8000-0000000001{i:02d}", state=state,
            ))
        self.assertEqual(self.sql(
            "select count(*) from public.avuhz_lifecycle_events;"
        ).stdout.decode().strip(), "7")
        for kind, subject in (
            ("work_intake.unapproved", "WORK_ITEM"),
            ("work_intake.opened", "UNAPPROVED"),
        ):
            denied = self.sql(self._insert(
                kind, subject, "e1000000-0000-4000-8000-000000000199",
            ), check=False)
            self.assertNotEqual(denied.returncode, 0)
        self.assertEqual(self.sql(
            "select count(*) from public.avuhz_lifecycle_events;"
        ).stdout.decode().strip(), "7")

    def test_replay_stops_without_losing_constraint_or_rows(self):
        self.apply(CANDIDATE.read_text())
        self.sql(self._insert("work_intake.opened", "WORK_ITEM",
                              "e1000000-0000-4000-8000-000000000191"))
        before = self._constraint("avuhz_lifecycle_events_event_type_check")
        again = self.apply(CANDIDATE.read_text(), check=False)
        self.assertNotEqual(again.returncode, 0)
        self.assertIn("WORK_INTAKE_EVENT_VOCABULARY_DRIFT_STOP",
                      again.stderr.decode())
        self.assertEqual(before, self._constraint("avuhz_lifecycle_events_event_type_check"))
        self.assertEqual(self.sql(
            "select count(*) from public.avuhz_lifecycle_events;"
        ).stdout.decode().strip(), "1")

    def test_missing_rls_policy_stops_before_any_constraint_replacement(self):
        before = self._constraint("avuhz_lifecycle_events_event_type_check")
        self.sql("ALTER TABLE public.avuhz_lifecycle_events DISABLE ROW LEVEL SECURITY;")
        blocked = self.apply(CANDIDATE.read_text(), check=False)
        self.assertNotEqual(blocked.returncode, 0)
        self.assertIn("WORK_INTAKE_EVENT_RLS_NOT_SCOPED_STOP",
                      blocked.stderr.decode())
        self.assertEqual(before, self._constraint("avuhz_lifecycle_events_event_type_check"))


if __name__ == "__main__":
    unittest.main()
