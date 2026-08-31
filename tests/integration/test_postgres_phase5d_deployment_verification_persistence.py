"""Local-only PostgreSQL certification for Phase 5D-D5b DeploymentVerification."""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "src")]
DSN = os.environ.get("AVUHZ_POSTGRES_DSN")

from avuhz_runtime.phase5d_deployment_verification import DeploymentVerificationReadService
from avuhz_runtime.schema_registry import SchemaRegistry
from tests.runtime import test_phase5d_deployment_execution_runtime as execution_runtime
from tests.runtime import test_phase5d_deployment_verification_runtime as verification_runtime
from tests.integration import test_postgres_phase5d_deployment_execution_persistence as execution_postgres

if DSN:
    from psycopg.errors import InsufficientPrivilege
    from avuhz_runtime.postgres import PostgresStore, PostgresUnitOfWork
    PostgresHarness = execution_postgres.Phase5DDeploymentExecutionPostgresTests
else:
    InsufficientPrivilege = Exception
    PostgresStore = PostgresUnitOfWork = None
    PostgresHarness = unittest.TestCase


@unittest.skipUnless(DSN, "local Phase 5D-D5b PostgreSQL DSN is required")
class Phase5DDeploymentVerificationPostgresTests(PostgresHarness):
    def verification_helper(self):
        execution = self.execution_helper()
        start, context = execution.raw("StartDeploymentExecution", execution.start_payload())
        self.assertEqual(execution.execute(start, context)["result"], "ACCEPTED")
        complete, context = execution.raw("CompleteDeploymentExecution", execution.completion_payload(), expected=1)
        self.assertEqual(execution.execute(complete, context)["result"], "ACCEPTED")
        uow = PostgresUnitOfWork(
            PostgresStore(self.service_factory), execution.context("CompleteDeploymentExecution")
        )
        try:
            source_execution = uow.deployment_executions.get(
                self.harness.tenant, execution_runtime.EXECUTION_ID
            )
        finally:
            uow.rollback(); uow.close()
        helper = verification_runtime.DeploymentVerificationRuntimeTests()
        helper.e = execution; helper.store = PostgresStore(self.service_factory)
        helper.source_execution = source_execution; helper._number = 1900
        helper.executor = self.harness.executor
        return helper

    def verification_uow(self, helper, tenant=None):
        return PostgresUnitOfWork(
            PostgresStore(self.service_factory),
            helper.context(tenant=tenant or self.harness.tenant),
        )

    def test_restart_durability_exact_round_trip_rls_event_outbox_and_immutability(self):
        helper = self.verification_helper()
        raw, context = helper.raw(helper.payload())
        self.assertEqual(helper.execute(raw, context)["result"], "ACCEPTED")
        fresh = self.verification_uow(helper)
        try:
            record = fresh.deployment_verifications.get(
                self.harness.tenant, verification_runtime.VERIFICATION_ID
            )
            view = DeploymentVerificationReadService(fresh).status(
                self.harness.tenant, verification_runtime.VERIFICATION_ID, self.harness.now
            )
        finally:
            fresh.rollback(); fresh.close()
        validator = Draft202012Validator(
            SchemaRegistry(ROOT / "contracts/schemas/v1").expanded(
                "urn:avuhz:schema:contracts:domain:deployment-verification:v1"
            ), format_checker=FormatChecker(),
        )
        self.assertEqual(list(validator.iter_errors(record)), [])
        self.assertEqual((record["overall_status"], view["deployment_verified"]), ("VERIFIED", True))
        with self.owner() as connection:
            self.assertEqual(connection.execute("select count(*) from public.avuhz_deployment_verifications").fetchone()["count"], 1)
            self.assertEqual(connection.execute("select count(*) from public.avuhz_lifecycle_events where event_type='deployment_verification.recorded'").fetchone()["count"], 1)
            self.assertEqual(connection.execute("select count(*) from public.avuhz_outbox_deliveries o join public.avuhz_lifecycle_events e on e.lifecycle_event_id=o.lifecycle_event_id where e.event_type='deployment_verification.recorded' and o.status='PENDING'").fetchone()["count"], 1)
        other = self.verification_uow(helper, self.OTHER_TENANT)
        try:
            self.assertIsNone(other.deployment_verifications.get(
                self.harness.tenant, verification_runtime.VERIFICATION_ID
            ))
        finally:
            other.rollback(); other.close()
        raw_connection = self.service_factory()
        try:
            self.assertEqual(raw_connection.execute("select count(*) from public.avuhz_deployment_verifications").fetchone()["count"], 0)
            raw_connection.execute("select set_config('avuhz.tenant_id',%s,false)", (self.harness.tenant,))
            with self.assertRaises(InsufficientPrivilege):
                raw_connection.execute("update public.avuhz_deployment_verifications set overall_status='FAILED' where tenant_id=%s", (self.harness.tenant,))
        finally:
            raw_connection.rollback(); raw_connection.close()

    def test_idempotency_stale_supersedes_and_atomic_rollback(self):
        helper = self.verification_helper()
        first, context = helper.raw(helper.payload(result="BLOCKED"), key="d5b-postgres-initial-blocked")
        self.assertEqual(helper.execute(first, context)["result"], "ACCEPTED")
        self.assertEqual(helper.execute(first, context)["result"], "DUPLICATE")
        helper.store.fail_stage = "OUTBOX_APPEND"
        helper.executor.store = helper.store
        retry = helper.payload(attempt=2)
        retry["supersedes_deployment_verification_reference"] = {
            "reference_type": "DEPLOYMENT_VERIFICATION",
            "reference_id": verification_runtime.VERIFICATION_ID,
            "reference_version": 1,
        }
        raw, context = helper.raw(
            retry, verification_id="d5d60000-0000-4000-8000-000000000002",
            key="d5b-postgres-atomic-rollback",
        )
        self.assertEqual(helper.execute(raw, context)["result"], "REJECTED")
        with self.owner() as connection:
            self.assertEqual(connection.execute("select count(*) from public.avuhz_deployment_verifications").fetchone()["count"], 1)
            self.assertEqual(connection.execute("select count(*) from public.avuhz_lifecycle_events where event_type='deployment_verification.recorded'").fetchone()["count"], 1)


if __name__ == "__main__": unittest.main()
