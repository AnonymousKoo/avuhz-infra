"""Disposable PostgreSQL certification of the forward-only intake-event vocabulary.

No hosted provider access; all mutations occur in a uniquely named disposable
test database inside the GitHub Actions PostgreSQL container.
"""
from __future__ import annotations

import os
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MIGRATIONS = ROOT / "supabase/migrations"
BASELINE = MIGRATIONS / "20260831120000_rebaseline_provider_neutral_avuhz.sql"
PRIOR = MIGRATIONS / "20261002213000_enable_implementation_handoff_command_intake.sql"
CANDIDATE = MIGRATIONS / "20261012140000_enable_shared_acquisition_intake_received_event.sql"
CONTAINER = os.getenv("AVUHZ_LOCAL_POSTGRES_CONTAINER")
DATABASE = "avuhz_intake_event_forward_contract"
EVENT = "e1000000-0000-4000-8000-000000000081"
TENANT = "e1000000-0000-4000-8000-000000000082"
INTAKE = "e1000000-0000-4000-8000-000000000083"
CORRELATION = "e1000000-0000-4000-8000-000000000084"


@unittest.skipUnless(CONTAINER, "disposable local PostgreSQL container required")
class AcquisitionIntakeEventForwardMigrationTests(unittest.TestCase):
    @classmethod
    def docker(cls, *args, input_bytes=None, check=True):
        result = subprocess.run(
            ["docker", "exec", *(["-i"] if input_bytes is not None else []),
             CONTAINER, *args], input=input_bytes,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        if check and result.returncode:
            raise AssertionError(result.stderr.decode().strip())
        return result

    @classmethod
    def sql(cls, query, check=True):
        return cls.docker(
            "psql", "-v", "ON_ERROR_STOP=1", "-At", "-U", "postgres", "-d", DATABASE,
            "-c", query, check=check,
        )

    @classmethod
    def apply(cls, source, *, check=True):
        return cls.docker(
            "psql", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", DATABASE,
            input_bytes=source.encode(), check=check,
        )

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if not CONTAINER:
            return
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", CONTAINER):
            raise RuntimeError("untrusted disposable container label")
        cls.docker("dropdb", "--if-exists", "-U", "postgres", DATABASE)
        cls.docker("createdb", "-U", "postgres", DATABASE)
        cls.apply(BASELINE.read_text())
        cls.apply(PRIOR.read_text())

    @classmethod
    def tearDownClass(cls):
        if CONTAINER:
            cls.docker("dropdb", "--if-exists", "-U", "postgres", DATABASE)
        super().tearDownClass()

    def test_extension_preserves_existing_event_types_and_forced_rls(self):
        self.apply(CANDIDATE.read_text())
        result = self.sql(
            "select relrowsecurity::int||':'||relforcerowsecurity::int "
            "from pg_class where oid='public.avuhz_lifecycle_events'::regclass;"
            "select count(*) from pg_policies where schemaname='public' "
            "and tablename='avuhz_lifecycle_events';"
            "select pg_get_constraintdef(oid) from pg_constraint where "
            "conrelid='public.avuhz_lifecycle_events'::regclass and "
            "conname='avuhz_lifecycle_events_event_type_check';"
            "select pg_get_constraintdef(oid) from pg_constraint where "
            "conrelid='public.avuhz_lifecycle_events'::regclass and "
            "conname='avuhz_lifecycle_events_authoritative_subject_type_check';"
        )
        lines = result.stdout.decode().splitlines()
        # The canonical initial migration enables tenant RLS without FORCE.
        # This forward migration must preserve that existing mode and policy.
        self.assertEqual(lines[:2], ["1:0", "1"])
        self.assertIn("acquisition.intake.received", lines[2])
        self.assertIn("implementation_handoff.accepted", lines[2])
        self.assertIn("engagement.opened", lines[2])
        self.assertIn("ACQUISITION_INTAKE", lines[3])
        self.assertIn("IMPLEMENTATION_HANDOFF", lines[3])

    def test_received_event_allowed_and_unsupported_values_rejected(self):
        # The candidate is idempotently installed by the preceding test, but
        # tests must not depend on method ordering.
        current = self.sql(
            "select pg_get_constraintdef(oid) from pg_constraint where "
            "conrelid='public.avuhz_lifecycle_events'::regclass and "
            "conname='avuhz_lifecycle_events_event_type_check';"
        ).stdout.decode()
        if "acquisition.intake.received" not in current:
            self.apply(CANDIDATE.read_text())
        columns = (
            "(lifecycle_event_id,tenant_id,event_type,event_schema_version,"
            "authoritative_subject_type,authoritative_subject_id,"
            "authoritative_subject_version,occurred_at,producer_reference,"
            "correlation_id,idempotency_key,visibility,sanitized_metadata)"
        )
        def insert(event_type, subject_type, event_id):
            return (
                "insert into public.avuhz_lifecycle_events " + columns +
                " values ('" + event_id + "','" + TENANT + "','" + event_type +
                "',1,'" + subject_type + "','" + INTAKE +
                "',1,'2030-01-15T15:00:00Z','command.service-01','" + CORRELATION +
                "','intake-test-" + event_id[-4:] +
                "','INTEGRATION_INTERNAL',"
                "'{\"intake_id\":\"" + INTAKE +
                "\",\"intake_state\":\"RECEIVED\"}'::jsonb)"
            )
        self.sql(insert("acquisition.intake.received", "ACQUISITION_INTAKE", EVENT))
        stored = self.sql("select count(*) from public.avuhz_lifecycle_events "
                          "where lifecycle_event_id='" + EVENT + "'").stdout.decode().strip()
        self.assertEqual(stored, "1")
        for name, kind, event_id in (
            ("acquisition.intake.qualified", "ACQUISITION_INTAKE",
             "e1000000-0000-4000-8000-000000000085"),
            ("acquisition.intake.received", "UNAPPROVED_SUBJECT",
             "e1000000-0000-4000-8000-000000000086"),
        ):
            with self.subTest(type=name, subject=kind):
                result = self.sql(insert(name, kind, event_id), check=False)
                self.assertNotEqual(result.returncode, 0)
        self.assertEqual(
            self.sql("select count(*) from public.avuhz_lifecycle_events").stdout.decode().strip(),
            "1",
        )

    def test_reapplying_migration_stops_without_changing_constraints(self):
        current = self.sql(
            "select pg_get_constraintdef(oid) from pg_constraint where "
            "conrelid='public.avuhz_lifecycle_events'::regclass and "
            "conname='avuhz_lifecycle_events_event_type_check';"
        ).stdout.decode()
        if "acquisition.intake.received" not in current:
            self.apply(CANDIDATE.read_text())
        denied = self.apply(CANDIDATE.read_text(), check=False)
        self.assertNotEqual(denied.returncode, 0)
        self.assertIn("ACQUISITION_INTAKE_EVENT_VOCABULARY_DRIFT_STOP",
                      denied.stderr.decode())
        observed = self.sql(
            "select pg_get_constraintdef(oid) from pg_constraint where "
            "conrelid='public.avuhz_lifecycle_events'::regclass and "
            "conname='avuhz_lifecycle_events_event_type_check';"
        ).stdout.decode()
        self.assertEqual(observed, current)


if __name__ == "__main__":
    unittest.main()
