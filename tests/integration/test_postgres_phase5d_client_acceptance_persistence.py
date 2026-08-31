"""Local-only PostgreSQL certification for Phase 5D-D3 ClientAcceptance."""
from __future__ import annotations

import copy
import os
import sys
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "src")]
DSN = os.environ.get("AVUHZ_POSTGRES_DSN")

from avuhz_runtime.phase5d_client_acceptance import (
    ClientAcceptanceReadService,
    client_acceptance_digest,
)
from avuhz_runtime.schema_registry import SchemaRegistry
from tests.runtime import test_phase5d_client_acceptance_runtime as acceptance_runtime
from tests.runtime import test_phase5d_qa_result_runtime as qa_runtime
from tests.integration import test_postgres_phase5d_qa_result_persistence as qa_postgres

if DSN:
    from psycopg.errors import InsufficientPrivilege
    from avuhz_runtime.in_memory import Executor
    from avuhz_runtime.postgres import PostgresStore, PostgresUnitOfWork
    PostgresHarness = qa_postgres.Phase5DQAResultPostgresTests
else:
    InsufficientPrivilege = Exception
    Executor = PostgresStore = PostgresUnitOfWork = None
    PostgresHarness = unittest.TestCase


@unittest.skipUnless(DSN, "local Phase 5D-D3 PostgreSQL DSN is required")
class Phase5DClientAcceptancePostgresTests(PostgresHarness):
    def acceptance_helper(self):
        qa = self.qa_helper()
        qa.record()
        fresh = PostgresUnitOfWork(
            PostgresStore(self.service_factory), qa.context()
        )
        try:
            qa_record = fresh.qa_results.get(self.harness.tenant, qa_runtime.QA_ID)
            build = fresh.build_execution_results.get(
                self.harness.tenant,
                qa_record["build_execution_reference"]["reference_id"],
            )
        finally:
            fresh.rollback()
            fresh.close()
        helper = acceptance_runtime.ClientAcceptanceRuntimeTests()
        helper.q = qa
        helper.store = PostgresStore(self.service_factory)
        helper._number = 1280
        helper.source_qa = qa_record
        helper.source_builds = {
            build["build_execution_result_id"]: build,
        }
        helper.executor = self.harness.executor
        return helper

    def acceptance_uow(self, helper, tenant=None):
        return PostgresUnitOfWork(
            PostgresStore(self.service_factory),
            helper.context(tenant=tenant or self.harness.tenant),
        )

    def test_restart_durability_rls_exact_round_trip_and_no_deployment_authority(self):
        helper = self.acceptance_helper()
        payload = helper.payload()
        helper.record(payload)
        fresh = self.acceptance_uow(helper)
        try:
            record = fresh.client_acceptances.get_version(
                self.harness.tenant, acceptance_runtime.ACCEPTANCE_ID, 1
            )
            view = ClientAcceptanceReadService(fresh).status(
                self.harness.tenant, acceptance_runtime.ACCEPTANCE_ID, 1, self.harness.now
            )
        finally:
            fresh.rollback()
            fresh.close()
        self.assertEqual(record["client_acceptance_digest"], payload["client_acceptance_digest"])
        self.assertEqual(record["qa_result_digest"], payload["qa_result_digest"])
        validator = Draft202012Validator(
            SchemaRegistry(ROOT / "contracts/schemas/v1").expanded(
                "urn:avuhz:schema:contracts:domain:client-acceptance:v1"
            ),
            format_checker=FormatChecker(),
        )
        self.assertEqual(list(validator.iter_errors(record)), [])
        self.assertEqual(
            (view["sources_exact"], view["client_accepted"], view["deployment_authorized"]),
            (True, True, False),
        )
        with self.owner() as connection:
            counts = tuple(connection.execute(query).fetchone()["count"] for query in (
                "select count(*) from public.avuhz_client_acceptances",
                "select count(*) from public.avuhz_lifecycle_events where event_type='client_acceptance.recorded'",
                "select count(*) from public.avuhz_outbox_deliveries o join public.avuhz_lifecycle_events e on e.lifecycle_event_id=o.lifecycle_event_id where e.event_type='client_acceptance.recorded' and o.status='PENDING'",
            ))
            deployment = connection.execute(
                "select count(*) from information_schema.tables where table_schema='public' "
                "and table_name='avuhz_deployment_verifications'"
            ).fetchone()["count"]
        self.assertEqual(counts, (1, 1, 1))
        self.assertEqual(deployment, 0)

        other = self.acceptance_uow(helper, self.OTHER_TENANT)
        try:
            self.assertIsNone(other.client_acceptances.get_version(
                self.harness.tenant, acceptance_runtime.ACCEPTANCE_ID, 1
            ))
            self.assertEqual(other.client_acceptances.list_by_package(
                self.harness.tenant, helper.package_payload["codex_build_package_id"], 1
            ), ())
        finally:
            other.rollback()
            other.close()
        raw = self.service_factory()
        try:
            self.assertEqual(
                raw.execute("select count(*) from public.avuhz_client_acceptances").fetchone()["count"],
                0,
            )
            raw.execute(
                "select set_config('avuhz.tenant_id',%s,false)", (self.harness.tenant,)
            )
            with self.assertRaises(InsufficientPrivilege):
                raw.execute(
                    "delete from public.avuhz_client_acceptances "
                    "where tenant_id=%s and client_acceptance_id=%s",
                    (self.harness.tenant, acceptance_runtime.ACCEPTANCE_ID),
                )
        finally:
            raw.rollback()
            raw.close()

    def test_immutable_version_history_stale_predecessor_and_atomic_rollback(self):
        helper = self.acceptance_helper()
        helper.record()
        replacement = helper.payload(version=2, decision="REJECTED")
        helper.record(replacement, key="phase5d-postgres-client-reject-v2")
        fresh = self.acceptance_uow(helper)
        try:
            history = fresh.client_acceptances.list_by_package(
                self.harness.tenant, helper.package_payload["codex_build_package_id"], 1
            )
        finally:
            fresh.rollback()
            fresh.close()
        self.assertEqual(
            [(item["acceptance_version"], item["decision"]) for item in history],
            [(1, "ACCEPTED"), (2, "REJECTED")],
        )
        stale = helper.payload(version=3)
        stale["supersedes_client_acceptance_reference"]["reference_version"] = 1
        stale["client_acceptance_digest"] = client_acceptance_digest(
            helper.tenant, helper.engagement_id, stale,
            {
                "principal_reference": "human.client-acceptance",
                "organization_reference": "organization.client",
                "authority_role": "CLIENT_ACCEPTANCE_AUTHORITY",
            },
        )
        self.assertEqual(
            helper.execute(helper.raw(
                stale, key="phase5d-postgres-client-stale-predecessor"
            ))["result"],
            "REJECTED",
        )
        with self.owner() as connection:
            before = tuple(connection.execute(query).fetchone()["count"] for query in (
                "select count(*) from public.avuhz_client_acceptances",
                "select count(*) from public.avuhz_lifecycle_events where event_type='client_acceptance.recorded'",
                "select count(*) from public.avuhz_outbox_deliveries o join public.avuhz_lifecycle_events e on e.lifecycle_event_id=o.lifecycle_event_id where e.event_type='client_acceptance.recorded'",
            ))
        failing = PostgresStore(self.service_factory)
        failing.fail_stage = "OUTBOX_APPEND"
        rollback = acceptance_runtime.ClientAcceptanceRuntimeTests()
        rollback.q = helper.q
        rollback.store = failing
        rollback._number = 1380
        rollback.source_qa = copy.deepcopy(helper.source_qa)
        rollback.source_builds = copy.deepcopy(helper.source_builds)
        rollback.executor = Executor(
            self.harness.executor.validator, self.harness.executor.pipeline, failing,
            clock=lambda: self.harness.now, ids=rollback.next_id,
            uow_factory=PostgresUnitOfWork,
        )
        payload = rollback.payload(version=3)
        result = rollback.execute(rollback.raw(
            payload, key="phase5d-postgres-client-rollback-v3"
        ))
        self.assertEqual(result["result"], "REJECTED")
        with self.owner() as connection:
            after = tuple(connection.execute(query).fetchone()["count"] for query in (
                "select count(*) from public.avuhz_client_acceptances",
                "select count(*) from public.avuhz_lifecycle_events where event_type='client_acceptance.recorded'",
                "select count(*) from public.avuhz_outbox_deliveries o join public.avuhz_lifecycle_events e on e.lifecycle_event_id=o.lifecycle_event_id where e.event_type='client_acceptance.recorded'",
            ))
        self.assertEqual(after, before)


if __name__ == "__main__":
    unittest.main()
