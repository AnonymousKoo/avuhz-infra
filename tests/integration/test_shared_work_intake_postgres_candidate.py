"""Synthetic end-to-end PostgreSQL certification for shared Work Intake #001.

Opt-in disposable PostgreSQL 17 only. No hosted AUTH/DATA, client tenant,
n8n, credentials or customer data. Requires an explicitly local Docker container
and ephemeral localhost DSN plus pinned isolated psycopg.
"""
from __future__ import annotations

import dataclasses
import importlib.util
import json
import os
import re
import subprocess
import sys
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
DRIVER = importlib.util.find_spec("psycopg") is not None
CONTAINER = os.environ.get("AVUHZ_LOCAL_POSTGRES_CONTAINER")
DATABASE = "avuhz_system001_durable_writer_test"
DSN = os.environ.get("AVUHZ_WORK_ITEM_TEST_LOCAL_DSN")
# Reuse the existing CI disposable Postgres connection rather than relying
# on a separate secret/DSN or skipping the strict PG integration gate.
# The test creates its own synthetic DB inside that exact disposable container.
if DRIVER and not DSN and CONTAINER and os.environ.get("AVUHZ_POSTGRES_DSN"):
    from psycopg.conninfo import conninfo_to_dict, make_conninfo
    source = conninfo_to_dict(os.environ["AVUHZ_POSTGRES_DSN"])
    if (
        source.get("host") == "127.0.0.1"
        and source.get("user") == "postgres"
        and "password" not in source
        and str(source.get("port", "")).isdigit()
    ):
        DSN = make_conninfo(os.environ["AVUHZ_POSTGRES_DSN"], dbname=DATABASE)
MIGRATION_DIR = ROOT / "supabase" / "migrations"
MIGRATION_NAMES = (
    "20260831120000_rebaseline_provider_neutral_avuhz.sql",
    "20261002213000_enable_implementation_handoff_command_intake.sql",
    "20261012140000_enable_shared_acquisition_intake_received_event.sql",
    "20261014031000_enable_shared_work_intake_lifecycle_events.sql",
    "20261014034000_create_shared_work_items.sql",
    "20261014041000_enable_shared_work_item_command_idempotency.sql",
    "20261014180000_add_shared_work_item_next_action_due_at.sql",
)
if DRIVER:
    import psycopg
    from psycopg.rows import dict_row
    from avuhz_runtime.guards import TrustedExecutionContext
    from avuhz_runtime.postgres import PostgresStore
    from avuhz_service.shared_work_intake_candidate import (
        WorkIntakeCommand, WorkIntakeDenied, WorkIntakeConflict,
    )
    from avuhz_service.shared_work_intake_postgres_candidate import (
        SharedWorkIntakePostgresCandidate, WorkIntakePersistenceUnavailable,
    )

TENANT_A = "a4730000-0000-4000-8000-000000000001"
TENANT_B = "a4730000-0000-4000-8000-000000000002"
ITEM = "a4730000-0000-4000-8000-000000000031"
ITEM_B = "a4730000-0000-4000-8000-000000000032"
ALL = frozenset({
    "work_intake:create", "work_intake:manage", "work_intake:accept",
    "work_intake:read",
})


@unittest.skipUnless(DRIVER and DSN and CONTAINER, "disposable PG17, isolated psycopg and local DSN required")
class SharedDurableWorkIntakePostgresTests(unittest.TestCase):
    @classmethod
    def docker(cls, *args, source=None, check=True):
        r = subprocess.run(
            ["docker", "exec", *(["-i"] if source is not None else []),
             CONTAINER, *args],
            input=source.encode() if source is not None else None,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        if check and r.returncode:
            raise AssertionError(r.stderr.decode()[-1200:])
        return r

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", CONTAINER):
            raise RuntimeError("not an allowed disposable container label")
        # Never connect to a hostname or database supplied by a provider.
        from psycopg.conninfo import conninfo_to_dict
        params = conninfo_to_dict(DSN)
        if (
            params.get("host") != "127.0.0.1"
            or params.get("user") != "postgres"
            or params.get("dbname") != DATABASE
            or "password" in params
            or not str(params.get("port", "")).isdigit()
        ):
            raise RuntimeError("disposable LOCAL-only PostgreSQL boundary required")

    def setUp(self):
        self.docker("dropdb", "--if-exists", "-U", "postgres", DATABASE)
        self.docker("createdb", "-U", "postgres", DATABASE)
        for name in MIGRATION_NAMES:
            self.docker(
                "psql", "-v", "ON_ERROR_STOP=1", "-At",
                "-U", "postgres", "-d", DATABASE,
                source=(MIGRATION_DIR / name).read_text(),
            )
        self.evidence = {
            "sender": self.context("worker.sender", TENANT_A),
            "receiver": self.context("worker.receiver", TENANT_A),
            "other": self.context("worker.other", TENANT_A),
            "outside": self.context("worker.outside", TENANT_B),
        }
        self.members = {
            TENANT_A: {"worker.sender", "worker.receiver", "worker.other"},
            TENANT_B: {"worker.outside"},
        }
        self.store = PostgresStore(self.service_factory)
        self.writer = SharedWorkIntakePostgresCandidate(
            self.store,
            resolve_identity=self.resolve_identity,
            resolve_tenant_member=self.resolve_tenant_member,
        )

    def tearDown(self):
        self.docker("dropdb", "--if-exists", "-U", "postgres", DATABASE)

    @classmethod
    def context(cls, actor, tenant, caps=ALL):
        return TrustedExecutionContext(
            True, actor, "HUMAN", tenant, None, caps, frozenset(),
            "DEVELOPMENT", "avuhz-command-api", "STRONG", False,
            "2026-10-13T00:00:00Z", "2099-01-01T00:00:00Z",
        )

    def resolve_identity(self, bearer):
        # Synthetic credential string is an in-memory test alias, NOT an auth
        # provider key, password, JWT, API token or usable hosted credential.
        if type(bearer) is not str or bearer not in self.evidence:
            raise ValueError("local identity unavailable")
        return self.evidence[bearer]

    def resolve_tenant_member(self, conn, tenant, principal):
        # Synthetic directory: real provider must independently verify tenant
        # membership from authoritative DATA within this exact UoW.
        return principal if principal in self.members.get(tenant, ()) else None

    @classmethod
    def owner(cls):
        return psycopg.connect(DSN, row_factory=dict_row, autocommit=True)

    @classmethod
    def service_factory(cls):
        conn = cls.owner()
        conn.execute("SET ROLE avuhz_command_service")
        conn.autocommit = False
        return conn

    def table(self, table, fields="*"):
        with self.owner() as con:
            return con.execute(f"select {fields} from public.{table}").fetchall()

    @staticmethod
    def command(kind, version=None, *, key, item=ITEM, recipient=None):
        return WorkIntakeCommand(
            kind, item, key, expected_record_version=version,
            source="web" if kind == "OPEN" else None,
            classification="service_request" if kind == "OPEN" else None,
            recipient=recipient,
        )

    def full_journey(self):
        transitions = [
            ("sender", self.command("OPEN", key="opened0001")),
            ("sender", self.command("OFFER_HANDOFF", 1, key="offered001", recipient="worker.receiver")),
            ("receiver", self.command("ACCEPT_HANDOFF", 2, key="accept0001")),
            ("receiver", self.command("BLOCK", 3, key="blocked001")),
            ("receiver", self.command("RESUME", 4, key="resumed001")),
            ("receiver", self.command("RESOLVE", 5, key="resolved001")),
        ]
        return [self.writer.execute(actor, cmd) for actor, cmd in transitions]

    def test_legacy_fingerprints_replay_for_open_and_nonopen(self):
        import hashlib
        # The predecessor hash omitted the optional deadline field entirely.
        # Simulate legacy rows by seeding that exact hash before replay.
        cases=(
            ("OPEN",None,"legacyop01"),
            ("BLOCK",1,"legacybl01"),
        )
        self.writer.execute("sender",self.command("OPEN",key="opened001"))
        for kind,version,key in cases:
            cmd=self.command(kind,version,key=key)
            if kind=="OPEN":
                # OPEN replay uses the original persisted OPEN receipt.
                cmd=self.command("OPEN",key="opened001")
            else:
                self.writer.execute("sender",cmd)
            prior_payload={
                "tenant":TENANT_A,"principal":"worker.sender",
                "kind":cmd.kind,"item":cmd.work_item_id,
                "expected":cmd.expected_record_version,
                "source":cmd.source,"classification":cmd.classification,
                "recipient":cmd.recipient,
            }
            digest="fpv1:"+hashlib.sha256(
                json.dumps(prior_payload,separators=(",",":"),sort_keys=True).encode("ascii")
            ).hexdigest()
            # The ledger correctly FORBIDS rewriting completed receipts.
            # Byte-for-byte equality to the independently computed pre-change
            # fingerprint proves persisted legacy receipts will replay.
            with self.owner() as con:
                row=con.execute(
                    "SELECT semantic_request_fingerprint FROM "
                    "public.avuhz_idempotency_records WHERE tenant_id=%s "
                    "AND idempotency_key=%s",
                    (TENANT_A,cmd.idempotency_key),
                ).fetchone()
                self.assertIsNotNone(row)
                self.assertEqual(row["semantic_request_fingerprint"],digest)
            replay=self.writer.execute("sender",cmd)
            self.assertTrue(replay.replayed)
        self.assertEqual(len(self.table("avuhz_lifecycle_events")),2)
        self.assertEqual(len(self.table("avuhz_outbox_deliveries")),2)
        self.assertEqual(len(self.table("avuhz_idempotency_records")),2)

    def test_deadline_exact_sixty_seconds_and_thirty_days_allowed(self):
        from datetime import datetime, timezone
        self.writer._clock=lambda:datetime(2030,1,15,16,0,0,tzinfo=timezone.utc)
        for i,due in enumerate(("2030-01-15T16:01:00Z", "2030-02-14T16:00:00Z")):
            item=f"a4730000-0000-4000-8000-{i+51:012d}"
            cmd=dataclasses.replace(self.command("OPEN",key=f"exact{i:04d}",item=item),
                                    next_action_due_at=due)
            receipt=self.writer.execute("sender",cmd)
            self.assertEqual((receipt.accepted_version,receipt.replayed),(1,False))
        self.assertEqual(len(self.table("avuhz_work_items")),2)
        self.assertEqual(len(self.table("avuhz_lifecycle_events")),2)

    def test_deadline_subsecond_boundary_uses_full_trusted_clock(self):
        from datetime import datetime,timezone
        cases=(
            ("2030-01-15T16:01:00Z",False),
            ("2030-01-15T16:01:01Z",True),
            ("2030-02-14T16:00:00Z",True),
            ("2030-02-14T16:00:01Z",False),
        )
        self.writer._clock=lambda:datetime(2030,1,15,16,0,0,500000,tzinfo=timezone.utc)
        for i,(due,valid) in enumerate(cases):
            item=f"a4730000-0000-4000-8000-{i+41:012d}"
            cmd=dataclasses.replace(
                self.command("OPEN",key=f"fraction{i:02d}",item=item),
                next_action_due_at=due,
            )
            if valid:
                receipt=self.writer.execute("sender",cmd)
                self.assertEqual(receipt.accepted_version,1)
            else:
                with self.assertRaises(WorkIntakeDenied):
                    self.writer.execute("sender",cmd)
        self.assertEqual(len(self.table("avuhz_work_items")),2)
        self.assertEqual(len(self.table("avuhz_lifecycle_events")),2)
        self.assertEqual(len(self.table("avuhz_outbox_deliveries")),2)

    def test_deadline_open_is_atomic_and_replay_safe_in_existing_uow(self):
        from datetime import datetime, timezone
        # Fixed trusted server time. No real tenant or hosted DATA.
        fixed=datetime(2030,1,15,16,0,0,tzinfo=timezone.utc)
        self.writer._clock=lambda:fixed
        original=dataclasses.replace(
            self.command("OPEN",key="dueopen001"),
            next_action_due_at="2030-01-15T17:00:00Z",
        )
        first=self.writer.execute("sender",original)
        self.assertEqual((first.accepted_version,first.replayed),(1,False))
        rows=self.table("avuhz_work_items")
        self.assertEqual(len(rows),1)
        self.assertEqual(
            rows[0]["next_action_due_at"].isoformat(),"2030-01-15T17:00:00+00:00",
        )
        self.assertEqual(len(self.table("avuhz_lifecycle_events")),1)
        self.assertEqual(len(self.table("avuhz_idempotency_records")),1)
        self.assertEqual(len(self.table("avuhz_outbox_deliveries")),1)
        self.writer._clock=lambda:datetime(2031,1,15,16,0,0,tzinfo=timezone.utc)
        replay=self.writer.execute("sender",original)
        self.assertTrue(replay.replayed)
        self.assertIsNone(replay.event_id)
        with self.assertRaises(WorkIntakeConflict):
            self.writer.execute("sender",dataclasses.replace(
                original,next_action_due_at="2030-01-15T18:00:00Z",
            ))
        self.assertEqual(len(self.table("avuhz_lifecycle_events")),1)
        self.assertEqual(len(self.table("avuhz_idempotency_records")),1)
        self.assertEqual(len(self.table("avuhz_outbox_deliveries")),1)

    def test_deadline_bounds_denied_without_any_receipt_or_event(self):
        from datetime import datetime,timezone
        self.writer._clock=lambda:datetime(2030,1,15,16,0,0,tzinfo=timezone.utc)
        for i, due in enumerate((
            "2030-01-15T16:00:59Z",
            "2030-02-15T16:00:01Z",
            "2030-01-15T15:59:00Z",
        )):
            with self.subTest(i=i),self.assertRaises(WorkIntakeDenied):
                self.writer.execute("sender",dataclasses.replace(
                    self.command("OPEN",key=f"limit{i:04d}"),next_action_due_at=due,
                ))
        for table in ("avuhz_work_items","avuhz_lifecycle_events",
                      "avuhz_idempotency_records","avuhz_outbox_deliveries"):
            self.assertEqual(len(self.table(table)),0)

    def test_complete_six_transition_database_event_outbox_and_idempotency_journey(self):
        receipts = self.full_journey()
        self.assertEqual([r.accepted_version for r in receipts], list(range(1, 7)))
        self.assertTrue(all(not r.replayed and r.event_id for r in receipts))
        work = self.table("avuhz_work_items")
        self.assertEqual(len(work), 1)
        self.assertEqual(str(work[0]["tenant_id"]), TENANT_A)
        self.assertEqual(work[0]["state"], "RESOLVED")
        self.assertEqual(work[0]["owner_reference"], "worker.receiver")
        self.assertEqual(work[0]["record_version"], 6)
        self.assertIsNone(work[0]["pending_recipient_reference"])
        events = self.table("avuhz_lifecycle_events", "event_type,tenant_id,authoritative_subject_type,authoritative_subject_version,sanitized_metadata")
        self.assertEqual(len(events), 6)
        self.assertEqual(
            sorted(x["authoritative_subject_version"] for x in events),
            list(range(1, 7)),
        )
        self.assertTrue(all(str(x["tenant_id"]) == TENANT_A for x in events))
        self.assertTrue(all(x["authoritative_subject_type"] == "WORK_ITEM" for x in events))
        self.assertEqual(
            {x["event_type"] for x in events},
            {"work_intake.opened", "work_intake.handoff_offered",
             "work_intake.handoff_accepted", "work_intake.blocked",
             "work_intake.resumed", "work_intake.resolved"},
        )
        self.assertTrue(all(
            set(x["sanitized_metadata"]) == {"work_item_id", "state"} for x in events
        ))
        self.assertNotIn("worker.sender", json.dumps([x["sanitized_metadata"] for x in events]))
        self.assertNotIn("worker.receiver", json.dumps([x["sanitized_metadata"] for x in events]))
        self.assertEqual(len(self.table("avuhz_outbox_deliveries")), 6)
        self.assertEqual(
            {row["status"] for row in self.table("avuhz_outbox_deliveries")},
            {"PENDING"},
        )
        self.assertEqual(len(self.table("avuhz_idempotency_records")), 6)
        self.assertTrue(all(row["processing_status"]=="COMPLETED" for row in self.table("avuhz_idempotency_records")))

    def test_identical_replay_returns_original_receipt_and_no_second_event(self):
        original = self.command("OPEN", key="opened0001")
        first = self.writer.execute("sender", original)
        replay = self.writer.execute("sender", original)
        self.assertEqual((first.work_item_id, first.accepted_version),
                         (replay.work_item_id, replay.accepted_version))
        self.assertTrue(replay.replayed)
        self.assertIsNone(replay.event_id)
        self.assertEqual(len(self.table("avuhz_lifecycle_events")), 1)
        self.assertEqual(len(self.table("avuhz_outbox_deliveries")), 1)
        self.assertEqual(len(self.table("avuhz_idempotency_records")), 1)
        with self.assertRaises(WorkIntakeConflict):
            self.writer.execute("sender", WorkIntakeCommand(
                "OPEN", ITEM, "opened0001", source="api",
                classification="internal_task",
            ))
        self.assertEqual(len(self.table("avuhz_lifecycle_events")), 1)

    def test_former_owner_cannot_replay_after_accepted_handoff(self):
        self.writer.execute("sender", self.command("OPEN", key="opened0001"))
        self.writer.execute("sender", self.command(
            "OFFER_HANDOFF", 1, key="offered001", recipient="worker.receiver",
        ))
        self.writer.execute("receiver", self.command("ACCEPT_HANDOFF", 2, key="accept0001"))
        for cmd in (
            self.command("OPEN", key="opened0001"),
            self.command("OFFER_HANDOFF", 1, key="offered001", recipient="worker.receiver"),
            self.command("BLOCK", 99, key="guess0001"),
        ):
            with self.subTest(kind=cmd.kind):
                with self.assertRaises(WorkIntakeDenied):
                    self.writer.execute("sender", cmd)
        self.assertEqual(len(self.table("avuhz_lifecycle_events")), 3)

    def test_unauthorized_member_cross_tenant_and_stale_version_denied(self):
        self.writer.execute("sender", self.command("OPEN", key="opened0001"))
        for actor in ("other", "outside"):
            for version in (1, 99):
                with self.subTest(actor=actor, version=version):
                    with self.assertRaises(WorkIntakeDenied):
                        self.writer.execute(actor, self.command(
                            "BLOCK", version, key=f"denied{version:05d}",
                        ))
        with self.assertRaises(WorkIntakeConflict):
            self.writer.execute("sender", self.command("BLOCK", 2, key="stale0001"))
        self.members[TENANT_A].remove("worker.sender")
        with self.assertRaises(WorkIntakeDenied):
            self.writer.execute("sender", self.command("BLOCK", 1, key="revoked001"))
        self.assertEqual(len(self.table("avuhz_lifecycle_events")), 1)

    def test_outbox_append_failure_rolls_back_authoritative_row_event_and_receipt(self):
        self.store.fail_stage = "OUTBOX_APPEND"
        with self.assertRaisesRegex(WorkIntakePersistenceUnavailable, "work_intake_persistence_unavailable"):
            self.writer.execute("sender", self.command("OPEN", key="opened0001"))
        for table in ("avuhz_work_items", "avuhz_lifecycle_events",
                      "avuhz_outbox_deliveries", "avuhz_idempotency_records"):
            with self.subTest(table=table):
                self.assertEqual(len(self.table(table)), 0)
        self.store.fail_stage = None
        result = self.writer.execute("sender", self.command("OPEN", key="opened0001"))
        self.assertEqual(result.accepted_version, 1)
        self.assertEqual(len(self.table("avuhz_lifecycle_events")), 1)

    def test_invalid_recipient_and_source_never_write_partial_state(self):
        self.writer.execute("sender", self.command("OPEN", key="opened0001"))
        for recipient in ("worker.outside", "worker.unverified"):
            with self.subTest(recipient=recipient):
                with self.assertRaises(WorkIntakeDenied):
                    self.writer.execute("sender", self.command(
                        "OFFER_HANDOFF", 1, key="offered001", recipient=recipient,
                    ))
        with self.assertRaises(WorkIntakeDenied):
            self.writer.execute("untrusted", self.command("BLOCK", 1, key="unknown001"))
        self.assertEqual(len(self.table("avuhz_lifecycle_events")), 1)
        self.assertEqual(len(self.table("avuhz_idempotency_records")), 1)

    def test_two_tenants_can_use_same_id_without_reading_or_updating_each_other(self):
        self.writer.execute("sender", self.command("OPEN", key="opened0001"))
        other = self.writer.execute("outside", self.command("OPEN", key="opened0001"))
        self.assertEqual(other.accepted_version, 1)
        self.assertEqual(len(self.table("avuhz_work_items")), 2)
        self.assertEqual(len(self.table("avuhz_lifecycle_events")), 2)
        with self.assertRaises(WorkIntakeConflict):
            self.writer.execute("outside", self.command("BLOCK", 2, key="badver0001"))
        self.writer.execute("outside", self.command("BLOCK", 1, key="ownblock01"))
        # The B-only transition must leave A's identical item identifier alone.
        with self.owner() as con:
            records=con.execute(
                "select tenant_id,record_version,state "
                "from public.avuhz_work_items order by tenant_id"
            ).fetchall()
        self.assertEqual(
            [(str(x["tenant_id"]),x["record_version"],x["state"]) for x in records],
            [(TENANT_A,1,"OPEN"),(TENANT_B,2,"BLOCKED")],
        )

    def test_simultaneous_initial_open_dedupes_to_one_event_and_receipt(self):
        cmd = self.command("OPEN", key="sameopen001")
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(
                lambda _: self.writer.execute("sender", cmd), range(2)
            ))
        self.assertEqual(sum(not x.replayed for x in results), 1)
        self.assertEqual(sum(x.replayed for x in results), 1)
        self.assertEqual({x.accepted_version for x in results}, {1})
        self.assertEqual(len(self.table("avuhz_work_items")), 1)
        self.assertEqual(len(self.table("avuhz_idempotency_records")), 1)
        self.assertEqual(len(self.table("avuhz_lifecycle_events")), 1)
        self.assertEqual(len(self.table("avuhz_outbox_deliveries")), 1)

    def test_preflight_refuses_owner_role_and_migration_replay(self):
        owner_writer = SharedWorkIntakePostgresCandidate(
            PostgresStore(self.owner),
            resolve_identity=self.resolve_identity,
            resolve_tenant_member=self.resolve_tenant_member,
        )
        with self.assertRaises(WorkIntakeDenied):
            owner_writer.execute("sender", self.command(
                "OPEN", key="ownerrole01",
            ))
        replay = self.docker(
            "psql", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", DATABASE,
            source=(MIGRATION_DIR / "20261014041000_enable_shared_work_item_command_idempotency.sql").read_text(), check=False,
        )
        self.assertNotEqual(replay.returncode, 0)
        self.assertIn("AVUHZ_WORK_ITEM_COMMAND_PREFLIGHT_STOP", replay.stderr.decode())
        self.assertEqual(len(self.table("avuhz_work_items")), 0)

    def test_competing_open_with_distinct_keys_uses_one_authoritative_winner(self):
        commands = [
            self.command("OPEN", key="different001"),
            self.command("OPEN", key="different002"),
        ]
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(self.writer.execute, "sender", c) for c in commands]
            accepted, conflicts = [], []
            for future in futures:
                try:
                    accepted.append(future.result())
                except WorkIntakeConflict as exc:
                    conflicts.append(str(exc))
        self.assertEqual(len(accepted), 1)
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(len(self.table("avuhz_work_items")), 1)
        self.assertEqual(len(self.table("avuhz_idempotency_records")), 1)
        self.assertEqual(len(self.table("avuhz_lifecycle_events")), 1)
        self.assertEqual(len(self.table("avuhz_outbox_deliveries")), 1)

    def test_competing_transitions_with_same_version_only_one_commits(self):
        self.writer.execute("sender", self.command("OPEN", key="opened0001"))
        commands = [
            self.command("BLOCK", 1, key="blockrace1"),
            self.command("RESOLVE", 1, key="endrace001"),
        ]
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(self.writer.execute, "sender", c) for c in commands]
            accepted, failures = [], []
            for future in futures:
                try:
                    accepted.append(future.result())
                except WorkIntakeConflict:
                    failures.append("CONFLICT")
        self.assertEqual((len(accepted),len(failures)),(1,1))
        self.assertEqual(self.table("avuhz_work_items")[0]["record_version"], 2)
        self.assertEqual(len(self.table("avuhz_lifecycle_events")), 2)

    def test_competing_same_key_different_payload_fails_without_second_event(self):
        self.writer.execute("sender", self.command("OPEN", key="opened0001"))
        commands = [
            self.command("BLOCK", 1, key="samekey100"),
            self.command("RESOLVE", 1, key="samekey100"),
        ]
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(self.writer.execute, "sender", c) for c in commands]
            successes, failures = [], []
            for future in futures:
                try:
                    successes.append(future.result())
                except WorkIntakeConflict:
                    failures.append("CONFLICT")
        self.assertEqual((len(successes),len(failures)),(1,1))
        self.assertEqual(len(self.table("avuhz_idempotency_records")), 2)
        self.assertEqual(len(self.table("avuhz_outbox_deliveries")), 2)

    def test_each_transactional_failure_boundary_rolls_back_all_four_tables(self):
        for stage in ("LIFECYCLE_EVENT_APPEND","IDEMPOTENCY_COMPLETE","COMMIT"):
            with self.subTest(stage=stage):
                self.store.fail_stage = stage
                with self.assertRaises(WorkIntakePersistenceUnavailable):
                    self.writer.execute("sender", self.command("OPEN", key="opened0001"))
                for table in ("avuhz_work_items","avuhz_idempotency_records",
                              "avuhz_lifecycle_events","avuhz_outbox_deliveries"):
                    self.assertEqual(len(self.table(table)), 0, (stage,table))
                self.store.fail_stage = None

    def test_all_four_rls_policies_checked_and_disabled_row_security_denied(self):
        def unsafe_factory():
            conn = self.service_factory()
            conn.execute("SET row_security TO off")
            return conn
        unsafe = SharedWorkIntakePostgresCandidate(
            PostgresStore(unsafe_factory),
            resolve_identity=self.resolve_identity,
            resolve_tenant_member=self.resolve_tenant_member,
        )
        with self.assertRaises(WorkIntakeDenied):
            unsafe.execute("sender", self.command("OPEN", key="unsafe0001"))

        with self.owner() as conn:
            conn.execute("ALTER TABLE public.avuhz_lifecycle_events DISABLE ROW LEVEL SECURITY")
            conn.execute("COMMIT")
        with self.assertRaises(WorkIntakeDenied):
            self.writer.execute("sender", self.command("OPEN", key="rlsdrift01"))
        self.assertEqual(len(self.table("avuhz_work_items")),0)

    def test_weak_or_future_authentication_context_denied(self):
        original = self.evidence["sender"]
        for invalid in (
            dataclasses.replace(original,authentication_strength="WEAK"),
            dataclasses.replace(original,authenticated_at="2099-01-01T00:00:00Z"),
            dataclasses.replace(original,step_up_satisfied="yes"),
        ):
            with self.subTest(invalid=invalid.authentication_strength):
                self.evidence["sender"]=invalid
                with self.assertRaises(WorkIntakeDenied):
                    self.writer.execute("sender", self.command("OPEN", key="denied0001"))
        self.evidence["sender"]=original
        self.assertEqual(len(self.table("avuhz_lifecycle_events")),0)

    def test_concurrent_same_versus_different_idempotency_commands_single_winner(self):
        self.writer.execute("sender", self.command("OPEN", key="opened0001"))
        cmd=self.command("BLOCK", 1, key="repeat0001")
        with ThreadPoolExecutor(max_workers=2) as pool:
            results=list(pool.map(lambda _: self.writer.execute("sender",cmd),range(2)))
        self.assertEqual(sum(not x.replayed for x in results),1)
        self.assertEqual(sum(x.replayed for x in results),1)
        self.assertEqual(len(self.table("avuhz_lifecycle_events")),2)
        self.assertEqual(self.table("avuhz_work_items")[0]["record_version"],2)


    def test_due_reader_uses_actual_tenant_rls_and_owner_membership(self):
        from datetime import datetime,timezone
        from avuhz_service.shared_due_work_reader_candidate import SharedDueWorkReadCandidate
        from avuhz_service.shared_revenue_followup_review import FollowupReviewPolicy
        fixed=datetime(2030,1,15,16,0,0,tzinfo=timezone.utc)
        self.writer._clock=lambda: fixed
        due="2030-01-15T16:05:00Z"
        for actor in ("sender","outside"):
            self.writer.execute(actor,dataclasses.replace(
                self.command("OPEN",key="shared001",item=ITEM),
                next_action_due_at=due,
            ))
        reader=SharedDueWorkReadCandidate(
            self.store,resolve_identity=self.resolve_identity,
            resolve_tenant_member=self.resolve_tenant_member,
        )
        result=reader.review_owned_due(
            "sender", policy=FollowupReviewPolicy(escalation_after_minutes=15),
            now=datetime(2030,1,15,16,30,0,tzinfo=timezone.utc),
        )
        self.assertEqual(len(result),1)
        self.assertEqual(result[0].work_item_id,ITEM)
        self.assertEqual(result[0].owner_reference,"worker.sender")
        self.assertEqual(result[0].kind,"FOLLOWUP_ESCALATION_REVIEW_REQUIRED")
        other=reader.review_owned_due(
            "outside",policy=FollowupReviewPolicy(escalation_after_minutes=15),
            now=datetime(2030,1,15,16,30,0,tzinfo=timezone.utc),
        )
        self.assertEqual(len(other),1)
        self.assertEqual(other[0].owner_reference,"worker.outside")
        self.assertEqual(len(self.table("avuhz_lifecycle_events")),2)
        self.assertEqual(len(self.table("avuhz_outbox_deliveries")),2)

    def test_due_reader_revoked_member_and_former_owner_denied(self):
        from datetime import datetime, timezone
        from avuhz_service.shared_due_work_reader_candidate import SharedDueWorkReadCandidate
        from avuhz_service.shared_revenue_followup_review import FollowupReviewPolicy
        from avuhz_service.shared_work_intake_candidate import WorkIntakeDenied
        self.writer._clock=lambda:datetime(2030,1,15,16,0,0,tzinfo=timezone.utc)
        self.writer.execute("sender",dataclasses.replace(
            self.command("OPEN",key="dueread01"),
            next_action_due_at="2030-01-15T16:05:00Z",
        ))
        self.writer.execute("sender",self.command(
            "OFFER_HANDOFF",1,key="dueoffer1",recipient="worker.receiver",
        ))
        self.writer.execute("receiver",self.command("ACCEPT_HANDOFF",2,key="dueaccept"))
        reader=SharedDueWorkReadCandidate(
            self.store,resolve_identity=self.resolve_identity,
            resolve_tenant_member=self.resolve_tenant_member,
        )
        policy=FollowupReviewPolicy(escalation_after_minutes=15)
        now=datetime(2030,1,15,16,30,0,tzinfo=timezone.utc)
        self.assertEqual(reader.review_owned_due("sender",policy=policy,now=now),())
        self.assertEqual(len(reader.review_owned_due("receiver",policy=policy,now=now)),1)
        self.members[TENANT_A].remove("worker.receiver")
        with self.assertRaises(WorkIntakeDenied):
            reader.review_owned_due("receiver",policy=policy,now=now)
        self.assertEqual(len(self.table("avuhz_lifecycle_events")),3)

    def test_due_reader_rejects_database_rls_drift(self):
        from datetime import datetime, timezone
        from avuhz_service.shared_due_work_reader_candidate import (
            SharedDueWorkReadCandidate,SharedFollowupReadUnavailable,
        )
        from avuhz_service.shared_revenue_followup_review import FollowupReviewPolicy
        reader=SharedDueWorkReadCandidate(
            self.store,resolve_identity=self.resolve_identity,
            resolve_tenant_member=self.resolve_tenant_member,
        )
        with self.owner() as con:
            con.execute("ALTER TABLE public.avuhz_work_items DISABLE ROW LEVEL SECURITY")
        with self.assertRaises(SharedFollowupReadUnavailable):
            reader.review_owned_due(
                "sender",policy=FollowupReviewPolicy(escalation_after_minutes=15),
                now=datetime(2030,1,15,16,30,0,tzinfo=timezone.utc),
            )


    def test_synthetic_authenticated_open_deadline_due_review_with_handoff(self):
        """One bounded proof of the shared writer/read path; LOCAL PG only.

        A server-injected synthetic strong HUMAN context is NOT hosted auth.
        The four shared stores must remain atomic and reads must cause no
        new lifecycle events, receipts, outbox deliveries or messages.
        """
        from datetime import datetime, timezone, timedelta
        from avuhz_service.shared_due_work_reader_candidate import SharedDueWorkReadCandidate
        from avuhz_service.shared_revenue_followup_review import FollowupReviewPolicy
        from avuhz_service.shared_work_intake_candidate import WorkIntakeDenied

        start = datetime(2030, 1, 15, 16, 0, 0, tzinfo=timezone.utc)
        self.writer._clock = lambda: start
        policy = FollowupReviewPolicy(escalation_after_minutes=15)
        reader = SharedDueWorkReadCandidate(
            self.store,
            resolve_identity=self.resolve_identity,
            resolve_tenant_member=self.resolve_tenant_member,
        )

        # A forged/unauthenticated context cannot create a work item.
        genuine_context = self.evidence["sender"]
        self.evidence["sender"] = dataclasses.replace(genuine_context, authenticated=False)
        initial = dataclasses.replace(
            self.command("OPEN", key="proof_due_open_01"),
            next_action_due_at="2030-01-15T16:05:00Z",
        )
        try:
            with self.assertRaises(WorkIntakeDenied):
                self.writer.execute("sender", initial)
        finally:
            self.evidence["sender"] = genuine_context
        self.assertEqual(len(self.table("avuhz_work_items")), 0)

        # The trusted test-only resolver grants the existing shared capability.
        created = self.writer.execute("sender", initial)
        self.assertEqual((created.accepted_version, created.replayed), (1, False))
        self.assertIsNotNone(created.event_id)
        persisted = self.table("avuhz_work_items")
        self.assertEqual(len(persisted), 1)
        self.assertEqual(str(persisted[0]["tenant_id"]), TENANT_A)
        self.assertEqual(persisted[0]["owner_reference"], "worker.sender")
        self.assertEqual(persisted[0]["state"], "OPEN")
        self.assertEqual(persisted[0]["next_action_due_at"], start + timedelta(minutes=5))

        # Idempotency does not create duplicate events/receipts/outbox rows.
        replay = self.writer.execute("sender", initial)
        self.assertTrue(replay.replayed)
        self.assertIsNone(replay.event_id)
        for table in ("avuhz_work_items", "avuhz_idempotency_records",
                      "avuhz_lifecycle_events", "avuhz_outbox_deliveries"):
            self.assertEqual(len(self.table(table)), 1, table)

        self.assertEqual(reader.review_owned_due(
            "sender", policy=policy, now=start + timedelta(minutes=4, seconds=59)), ())
        due = reader.review_owned_due(
            "sender", policy=policy, now=start + timedelta(minutes=5))
        self.assertEqual(len(due), 1)
        self.assertEqual((due[0].kind, due[0].record_version,
                          due[0].owner_reference),
                         ("FOLLOWUP_DUE", 1, "worker.sender"))
        escalated = reader.review_owned_due(
            "sender", policy=policy, now=start + timedelta(minutes=20))
        self.assertEqual(len(escalated), 1)
        self.assertEqual(escalated[0].kind, "FOLLOWUP_ESCALATION_REVIEW_REQUIRED")
        # Both a different owner in the same tenant and a different tenant
        # must see no due candidate, even with the same synthetic item ID.
        for actor in ("other", "outside"):
            self.assertEqual(reader.review_owned_due(
                actor, policy=policy, now=start + timedelta(minutes=20)), ())

        # Existing shared handoff transfers due-work visibility exactly once.
        self.writer.execute("sender", self.command(
            "OFFER_HANDOFF", 1, key="proof_due_offer_01",
            recipient="worker.receiver"))
        self.writer.execute("receiver", self.command(
            "ACCEPT_HANDOFF", 2, key="proof_due_accept_01"))
        self.assertEqual(reader.review_owned_due(
            "sender", policy=policy, now=start + timedelta(minutes=20)), ())
        receiver = reader.review_owned_due(
            "receiver", policy=policy, now=start + timedelta(minutes=20))
        self.assertEqual(len(receiver), 1)
        self.assertEqual((receiver[0].owner_reference,
                          receiver[0].record_version, receiver[0].kind),
                         ("worker.receiver", 3, "FOLLOWUP_ESCALATION_REVIEW_REQUIRED"))

        # Revocation is honored; no informational row escapes.
        self.members[TENANT_A].remove("worker.receiver")
        with self.assertRaises(WorkIntakeDenied):
            reader.review_owned_due(
                "receiver", policy=policy, now=start + timedelta(minutes=20))
        for table, expected in (("avuhz_work_items", 1),
                                ("avuhz_idempotency_records", 3),
                                ("avuhz_lifecycle_events", 3),
                                ("avuhz_outbox_deliveries", 3)):
            self.assertEqual(len(self.table(table)), expected, table)


if __name__ == "__main__":
    unittest.main()
