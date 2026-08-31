"""Local-only PostgreSQL certification for Phase 5D-D4 DeploymentAuthorization."""
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

from avuhz_runtime.phase5d_deployment_authorization import (
    DeploymentAuthorizationReadService,
)
from avuhz_runtime.schema_registry import SchemaRegistry
from tests.runtime import test_phase5d_client_acceptance_runtime as acceptance_runtime
from tests.runtime import test_phase5d_deployment_authorization_runtime as deployment_runtime
from tests.integration import test_postgres_phase5d_client_acceptance_persistence as acceptance_postgres

if DSN:
    from psycopg.errors import InsufficientPrivilege
    from avuhz_runtime.in_memory import Executor
    from avuhz_runtime.postgres import PostgresStore, PostgresUnitOfWork
    PostgresHarness = acceptance_postgres.Phase5DClientAcceptancePostgresTests
else:
    InsufficientPrivilege = Exception
    Executor = PostgresStore = PostgresUnitOfWork = None
    PostgresHarness = unittest.TestCase


@unittest.skipUnless(DSN, "local Phase 5D-D4 PostgreSQL DSN is required")
class Phase5DDeploymentAuthorizationPostgresTests(PostgresHarness):
    def deployment_helper(self):
        acceptance_helper = self.acceptance_helper()
        acceptance_helper.record()
        fresh = PostgresUnitOfWork(
            PostgresStore(self.service_factory), acceptance_helper.context()
        )
        try:
            acceptance = fresh.client_acceptances.get_version(
                self.harness.tenant, acceptance_runtime.ACCEPTANCE_ID, 1
            )
            build = fresh.build_execution_results.get(
                self.harness.tenant,
                acceptance["build_execution_reference"]["reference_id"],
            )
            package_ref = acceptance["codex_build_package_reference"]
            package = fresh.codex_build_packages.get_version(
                self.harness.tenant,
                package_ref["reference_id"],
                package_ref["reference_version"],
            )
        finally:
            fresh.rollback()
            fresh.close()
        helper = deployment_runtime.DeploymentAuthorizationRuntimeTests()
        helper.a = acceptance_helper
        helper.store = PostgresStore(self.service_factory)
        helper._number = 1480
        helper.executor = self.harness.executor
        helper.source_acceptance = acceptance
        helper.source_build = build
        helper.source_package = package
        return helper

    def deployment_uow(self, helper, tenant=None):
        return PostgresUnitOfWork(
            PostgresStore(self.service_factory),
            helper.context(
                "ActivateDeploymentAuthorization",
                tenant=tenant or self.harness.tenant,
            ),
        )

    def test_restart_durability_dual_approval_rls_and_no_execution(self):
        helper = self.deployment_helper()
        helper.make_active()
        fresh = self.deployment_uow(helper)
        try:
            record = fresh.deployment_authorizations.get_version(
                self.harness.tenant, deployment_runtime.AUTHORIZATION_ID, 1
            )
            view = DeploymentAuthorizationReadService(fresh).status(
                self.harness.tenant,
                deployment_runtime.AUTHORIZATION_ID,
                1,
                self.harness.now,
            )
        finally:
            fresh.rollback()
            fresh.close()
        validator = Draft202012Validator(
            SchemaRegistry(ROOT / "contracts/schemas/v1").expanded(
                "urn:avuhz:schema:contracts:domain:deployment-authorization:v1"
            ),
            format_checker=FormatChecker(),
        )
        self.assertEqual(list(validator.iter_errors(record)), [])
        self.assertEqual(
            (record["state"], view["approvals_active"], view["deployment_authorized"],
             view["deployment_completed"]),
            ("ACTIVE", True, True, False),
        )
        with self.owner() as connection:
            counts = tuple(connection.execute(query).fetchone()["count"] for query in (
                "select count(*) from public.avuhz_deployment_authorizations",
                "select count(*) from public.avuhz_human_approvals where subject_type='DEPLOYMENT_AUTHORIZATION'",
                "select count(*) from public.avuhz_lifecycle_events where event_type like 'deployment_authorization.%'",
                "select count(*) from public.avuhz_outbox_deliveries o join public.avuhz_lifecycle_events e on e.lifecycle_event_id=o.lifecycle_event_id where e.event_type like 'deployment_authorization.%' and o.status='PENDING'",
            ))
        self.assertEqual(counts, (1, 2, 4, 4))

        other = self.deployment_uow(helper, self.OTHER_TENANT)
        try:
            self.assertIsNone(other.deployment_authorizations.get_version(
                self.harness.tenant, deployment_runtime.AUTHORIZATION_ID, 1
            ))
        finally:
            other.rollback()
            other.close()
        raw = self.service_factory()
        try:
            self.assertEqual(
                raw.execute(
                    "select count(*) from public.avuhz_deployment_authorizations"
                ).fetchone()["count"],
                0,
            )
            raw.execute(
                "select set_config('avuhz.tenant_id',%s,false)", (self.harness.tenant,)
            )
            with self.assertRaises(InsufficientPrivilege):
                raw.execute(
                    "delete from public.avuhz_deployment_authorizations "
                    "where tenant_id=%s and deployment_authorization_id=%s",
                    (self.harness.tenant, deployment_runtime.AUTHORIZATION_ID),
                )
        finally:
            raw.rollback()
            raw.close()

    def test_version_history_stale_write_and_atomic_rollback(self):
        helper = self.deployment_helper()
        helper.make_active()
        replacement = helper.payload(version=2)
        helper.propose(
            replacement,
            command="ReviseDeploymentAuthorization",
            expected=2,
            key="phase5d-postgres-deployment-revise-v2",
        )
        fresh = self.deployment_uow(helper)
        try:
            history = fresh.deployment_authorizations.list_versions(
                self.harness.tenant, deployment_runtime.AUTHORIZATION_ID
            )
        finally:
            fresh.rollback()
            fresh.close()
        self.assertEqual(
            [(item["authorization_version"], item["state"]) for item in history],
            [(1, "SUPERSEDED"), (2, "PROPOSED")],
        )
        self.assertEqual(
            helper.execute(helper.raw(
                "ReviseDeploymentAuthorization", copy.deepcopy(replacement),
                expected=2, key="phase5d-postgres-deployment-stale-write",
            ))["result"],
            "REJECTED",
        )
        with self.owner() as connection:
            before = tuple(connection.execute(query).fetchone()["count"] for query in (
                "select count(*) from public.avuhz_deployment_authorizations",
                "select count(*) from public.avuhz_lifecycle_events where event_type like 'deployment_authorization.%'",
                "select count(*) from public.avuhz_outbox_deliveries o join public.avuhz_lifecycle_events e on e.lifecycle_event_id=o.lifecycle_event_id where e.event_type like 'deployment_authorization.%'",
            ))
        failing = PostgresStore(self.service_factory)
        failing.fail_stage = "OUTBOX_APPEND"
        helper.store = failing
        helper.executor = Executor(
            self.harness.executor.validator,
            self.harness.executor.pipeline,
            failing,
            clock=lambda: self.harness.now,
            ids=helper.next_id,
            uow_factory=PostgresUnitOfWork,
        )
        rollback_payload = {
            "deployment_authorization_id": deployment_runtime.AUTHORIZATION_ID,
            "authorization_version": 2,
            "revocation_reason": "SECURITY_CONCERN",
            "deployment_authority_digest": replacement["deployment_authority_digest"],
        }
        result = helper.execute(helper.raw(
            "RevokeDeploymentAuthorization",
            rollback_payload,
            expected=1,
            key="phase5d-postgres-deployment-rollback-v2",
        ), role="PROVIDER_DEPLOYMENT_AUTHORITY")
        self.assertEqual(result["result"], "REJECTED")
        with self.owner() as connection:
            after = tuple(connection.execute(query).fetchone()["count"] for query in (
                "select count(*) from public.avuhz_deployment_authorizations",
                "select count(*) from public.avuhz_lifecycle_events where event_type like 'deployment_authorization.%'",
                "select count(*) from public.avuhz_outbox_deliveries o join public.avuhz_lifecycle_events e on e.lifecycle_event_id=o.lifecycle_event_id where e.event_type like 'deployment_authorization.%'",
            ))
        self.assertEqual(after, before)


if __name__ == "__main__":
    unittest.main()
