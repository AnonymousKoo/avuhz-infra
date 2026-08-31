"""Local-only PostgreSQL certification for Phase 5D-B1 ImplementationBrief."""
from __future__ import annotations

import copy
import os
import sys
import threading
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "src")]
DSN = os.environ.get("AVUHZ_POSTGRES_DSN")

from avuhz_runtime.in_memory import UnitOfWork
from avuhz_runtime.phase5d_brief import ImplementationBriefReadService, implementation_brief_digest
from avuhz_runtime.schema_registry import SchemaRegistry
from tests.runtime import test_phase5d_implementation_brief_runtime as brief_runtime


if DSN:
    from psycopg.errors import InsufficientPrivilege
    from avuhz_runtime.postgres import PostgresStore, PostgresUnitOfWork
    from tests.integration.provider_neutral_postgres_harness import ProviderNeutralPostgresHarness
    PostgresHarness = ProviderNeutralPostgresHarness
else:
    InsufficientPrivilege = Exception
    PostgresStore = PostgresUnitOfWork = None
    PostgresHarness = unittest.TestCase


@unittest.skipUnless(DSN, "local Phase 5D-B1 PostgreSQL DSN is required")
class Phase5DImplementationBriefPostgresTests(PostgresHarness):
    """Use the provider-neutral current-tree seed, migration, and RLS harness."""

    def brief_helper(self):
        helper = brief_runtime.ImplementationBriefRuntimeTests()
        helper.setUp()
        helper.h = self.harness.h
        helper.handoff = self.harness.handoff
        helper._tenant = self.harness.tenant
        helper._engagement_id = self.harness.engagement_id
        helper.store = self.harness.store  # Deterministic source fixture used only to compose payloads.
        helper._number = 800
        helper.executor = self.harness.executor
        return helper

    def phase5d_uow(self, tenant=None):
        helper = self.brief_helper()
        return PostgresUnitOfWork(
            PostgresStore(self.service_factory),
            helper.context("DraftImplementationBrief", tenant=tenant or self.harness.tenant),
        )

    def test_brief_restart_durability_rls_schema_events_and_zero_authority(self):
        self.build_active()
        helper = self.brief_helper()
        payload = helper.payload()
        helper.draft(payload)
        helper.approve(payload)

        fresh = self.phase5d_uow()
        try:
            record = fresh.implementation_briefs.get_version(
                self.harness.tenant, brief_runtime.BRIEF_ID, 1
            )
            readiness = ImplementationBriefReadService(fresh).readiness(
                self.harness.tenant, brief_runtime.BRIEF_ID, 1, self.harness.now
            )
        finally:
            fresh.rollback()
            fresh.close()
        self.assertEqual((record["state"], record["record_version"]), ("APPROVED", 2))
        validator = Draft202012Validator(
            SchemaRegistry(ROOT / "contracts/schemas/v1").expanded(
                "urn:avuhz:schema:contracts:domain:implementation-brief:v1"
            ), format_checker=FormatChecker(),
        )
        self.assertEqual(list(validator.iter_errors(record)), [])
        self.assertTrue(readiness["implementation_brief_ready"])
        self.assertEqual(
            (readiness["implementation_authorized"], readiness["deployment_authorized"],
             readiness["production_change_authorized"]),
            (False, False, False),
        )

        with self.owner() as connection:
            counts = tuple(connection.execute(f"select count(*) from public.{table}").fetchone()["count"]
                           for table in (
                               "avuhz_implementation_briefs", "avuhz_implementation_handoffs",
                               "avuhz_idempotency_records", "avuhz_lifecycle_events",
                               "avuhz_outbox_deliveries",
                           ))
            deployment_tables = connection.execute(
                "select count(*) from information_schema.tables where table_schema='public' "
                "and table_name='avuhz_deployment_verifications'"
            ).fetchone()["count"]
        self.assertEqual(counts, (1, 1, 4, 4, 4))
        self.assertEqual(deployment_tables, 0)

        other = self.phase5d_uow(self.OTHER_TENANT)
        try:
            self.assertIsNone(other.implementation_briefs.get_version(
                self.harness.tenant, brief_runtime.BRIEF_ID, 1
            ))
            self.assertEqual(other.implementation_briefs.list_versions(
                self.harness.tenant, brief_runtime.BRIEF_ID
            ), ())
        finally:
            other.rollback()
            other.close()
        raw = self.service_factory()
        try:
            self.assertEqual(raw.execute(
                "select count(*) from public.avuhz_implementation_briefs"
            ).fetchone()["count"], 0)
            raw.execute("select set_config('avuhz.tenant_id',%s,false)", (self.harness.tenant,))
            with self.assertRaises(InsufficientPrivilege):
                raw.execute(
                    "delete from public.avuhz_implementation_briefs "
                    "where tenant_id=%s and implementation_brief_id=%s",
                    (self.harness.tenant, brief_runtime.BRIEF_ID),
                )
        finally:
            raw.rollback()
            raw.close()

    def test_brief_revision_history_exact_round_trip_and_stale_concurrency(self):
        self.build_active()
        helper = self.brief_helper()
        first = helper.payload()
        helper.draft(first)
        second = helper.payload(version=2)
        second["current_state_context"][0]["statement"] = (
            "The exact approved source confirms inconsistent required-field coverage."
        )
        second["implementation_brief_digest"] = implementation_brief_digest(second)
        helper.approve(first)
        helper.execute("ReviseImplementationBrief", second, expected=2)

        fresh = self.phase5d_uow()
        try:
            history = fresh.implementation_briefs.list_versions(
                self.harness.tenant, brief_runtime.BRIEF_ID
            )
        finally:
            fresh.rollback()
            fresh.close()
        self.assertEqual(
            [(item["implementation_brief_version"], item["state"], item["record_version"])
             for item in history],
            [(1, "SUPERSEDED", 3), (2, "DRAFT", 1)],
        )
        self.assertEqual(history[0]["implementation_brief_digest"], first["implementation_brief_digest"])
        self.assertEqual(history[1]["source_implementation_handoff_reference"], second["source_implementation_handoff_reference"])

        helper.approve(second)

        third = helper.payload(version=3)
        third["supersedes_implementation_brief_reference"]["reference_version"] = 2
        third["implementation_brief_digest"] = implementation_brief_digest(third)
        barrier = threading.Barrier(2)
        outcomes = []

        def worker():
            uow = self.phase5d_uow()
            try:
                current = uow.implementation_briefs.get_current(
                    self.harness.tenant, brief_runtime.BRIEF_ID
                )
                replacement = copy.deepcopy(current)
                replacement.update(copy.deepcopy(third))
                replacement.update(state="DRAFT", record_version=1,
                                   created_at=self.harness.now, updated_at=self.harness.now)
                replacement.pop("client_approval_reference", None)
                replacement.pop("provider_approval_reference", None)
                replacement.pop("approved_at", None)
                barrier.wait()
                uow.implementation_briefs.revise(current, replacement, self.harness.now)
                uow.commit()
                outcomes.append("ACCEPTED")
            except ValueError:
                uow.rollback()
                outcomes.append("STALE")
            finally:
                uow.close()

        threads = [threading.Thread(target=worker), threading.Thread(target=worker)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(sorted(outcomes), ["ACCEPTED", "STALE"])

    def test_brief_idempotency_across_restart_and_atomic_failpoint(self):
        self.build_active()
        helper = self.brief_helper()
        payload = helper.payload()
        raw = helper.raw(
            "DraftImplementationBrief", payload, key="phase5d-postgres-replay-0001"
        )
        context = helper.context("DraftImplementationBrief")
        self.assertEqual(self.harness.executor.execute(copy.deepcopy(raw), context)["result"], "ACCEPTED")
        self.assertEqual(self.executor().execute(copy.deepcopy(raw), context)["result"], "DUPLICATE")
        changed = copy.deepcopy(raw)
        changed["payload"]["risks"] = ["Changed semantic request must conflict."]
        self.assertEqual(self.executor().execute(changed, context)["result"], "CONFLICT")

        self.tearDown()
        self.setUp()
        self.build_active()
        helper = self.brief_helper()
        raw = helper.raw(
            "DraftImplementationBrief", helper.payload(), key="phase5d-postgres-atomic-0001"
        )
        store = PostgresStore(self.service_factory)
        store.fail_stage = "OUTBOX_APPEND"
        result = self.executor(store).execute(raw, helper.context("DraftImplementationBrief"))
        self.assertEqual(result["result"], "REJECTED")
        with self.owner() as connection:
            counts = tuple(connection.execute(f"select count(*) from public.{table}").fetchone()["count"]
                           for table in (
                               "avuhz_implementation_briefs", "avuhz_implementation_handoffs",
                               "avuhz_idempotency_records", "avuhz_lifecycle_events",
                               "avuhz_outbox_deliveries",
                           ))
        self.assertEqual(counts, (0, 1, 0, 0, 0))


if __name__ == "__main__":
    unittest.main()
