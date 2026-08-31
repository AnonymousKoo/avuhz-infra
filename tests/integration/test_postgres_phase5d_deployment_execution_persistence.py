"""Local-only PostgreSQL certification for Phase 5D-D5a DeploymentExecution."""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "src")]
DSN = os.environ.get("AVUHZ_POSTGRES_DSN")

from avuhz_runtime.phase5d_deployment_execution import DeploymentExecutionReadService
from avuhz_runtime.schema_registry import SchemaRegistry
from tests.runtime import test_phase5d_deployment_authorization_runtime as authorization_runtime
from tests.runtime import test_phase5d_deployment_execution_runtime as execution_runtime
from tests.integration import test_postgres_phase5d_deployment_authorization_persistence as authorization_postgres

if DSN:
    from psycopg.errors import InsufficientPrivilege
    from avuhz_runtime.postgres import PostgresStore, PostgresUnitOfWork
    PostgresHarness = authorization_postgres.Phase5DDeploymentAuthorizationPostgresTests
else:
    InsufficientPrivilege = Exception
    PostgresStore = PostgresUnitOfWork = None
    PostgresHarness = unittest.TestCase


@unittest.skipUnless(DSN, "local Phase 5D-D5a PostgreSQL DSN is required")
class Phase5DDeploymentExecutionPostgresTests(PostgresHarness):
    def execution_helper(self):
        deployment = self.deployment_helper()
        deployment.make_active()
        uow = PostgresUnitOfWork(PostgresStore(self.service_factory), deployment.context("ActivateDeploymentAuthorization"))
        try:
            authority = uow.deployment_authorizations.get_version(
                self.harness.tenant, authorization_runtime.AUTHORIZATION_ID, 1
            )
        finally:
            uow.rollback(); uow.close()
        helper = execution_runtime.DeploymentExecutionRuntimeTests()
        helper.d = deployment; helper.store = PostgresStore(self.service_factory)
        helper.source_authority = authority; helper._number = 1700
        helper.executor = self.harness.executor
        return helper

    def execution_uow(self, helper, tenant=None):
        return PostgresUnitOfWork(
            PostgresStore(self.service_factory),
            helper.context("CompleteDeploymentExecution", tenant=tenant or self.harness.tenant),
        )

    def test_restart_durability_exact_round_trip_rls_event_outbox_and_verification_stop(self):
        helper = self.execution_helper()
        start, context = helper.raw("StartDeploymentExecution", helper.start_payload())
        self.assertEqual(helper.execute(start, context)["result"], "ACCEPTED")
        complete, context = helper.raw("CompleteDeploymentExecution", helper.completion_payload(), expected=1)
        self.assertEqual(helper.execute(complete, context)["result"], "ACCEPTED")
        fresh = self.execution_uow(helper)
        try:
            record = fresh.deployment_executions.get(self.harness.tenant, execution_runtime.EXECUTION_ID)
            view = DeploymentExecutionReadService(fresh).status(
                self.harness.tenant, execution_runtime.EXECUTION_ID, self.harness.now
            )
        finally:
            fresh.rollback(); fresh.close()
        validator = Draft202012Validator(
            SchemaRegistry(ROOT / "contracts/schemas/v1").expanded(
                "urn:avuhz:schema:contracts:domain:deployment-execution:v1"
            ), format_checker=FormatChecker(),
        )
        self.assertEqual(list(validator.iter_errors(record)), [])
        self.assertEqual((record["status"], view["deployment_verified"]), ("SUCCEEDED", False))
        with self.owner() as connection:
            self.assertEqual(connection.execute("select count(*) from public.avuhz_deployment_executions").fetchone()["count"], 1)
            self.assertEqual(connection.execute("select count(*) from public.avuhz_lifecycle_events where event_type like 'deployment_execution.%'").fetchone()["count"], 2)
            self.assertEqual(connection.execute("select count(*) from public.avuhz_outbox_deliveries o join public.avuhz_lifecycle_events e on e.lifecycle_event_id=o.lifecycle_event_id where e.event_type like 'deployment_execution.%' and o.status='PENDING'").fetchone()["count"], 2)
        other = self.execution_uow(helper, self.OTHER_TENANT)
        try:
            self.assertIsNone(other.deployment_executions.get(self.harness.tenant, execution_runtime.EXECUTION_ID))
        finally:
            other.rollback(); other.close()
        raw = self.service_factory()
        try:
            self.assertEqual(raw.execute("select count(*) from public.avuhz_deployment_executions").fetchone()["count"], 0)
            raw.execute("select set_config('avuhz.tenant_id',%s,false)", (self.harness.tenant,))
            with self.assertRaises(InsufficientPrivilege):
                raw.execute("delete from public.avuhz_deployment_executions where tenant_id=%s", (self.harness.tenant,))
        finally:
            raw.rollback(); raw.close()

    def test_atomic_rollback_and_stale_write_denial(self):
        helper = self.execution_helper()
        start, context = helper.raw("StartDeploymentExecution", helper.start_payload())
        self.assertEqual(helper.execute(start, context)["result"], "ACCEPTED")
        stale, context = helper.raw("CompleteDeploymentExecution", helper.completion_payload(), expected=2)
        self.assertEqual(helper.execute(stale, context)["reason_code"], "VERSION_STALE")
        helper.store.fail_stage = "OUTBOX_APPEND"
        helper.executor.store = helper.store
        failed, context = helper.raw("CompleteDeploymentExecution", helper.completion_payload(), expected=1, key="d5a-postgres-atomic-rollback")
        self.assertEqual(helper.execute(failed, context)["result"], "REJECTED")
        with self.owner() as connection:
            row = connection.execute("select status,record_version from public.avuhz_deployment_executions").fetchone()
            self.assertEqual((row["status"], row["record_version"]), ("IN_PROGRESS", 1))
            self.assertEqual(connection.execute("select count(*) from public.avuhz_lifecycle_events where event_type='deployment_execution.completed'").fetchone()["count"], 0)


if __name__ == "__main__": unittest.main()
