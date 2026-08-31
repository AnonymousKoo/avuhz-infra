"""Local-only PostgreSQL certification for Phase 5D-B3 CodexBuildPackage."""
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

from avuhz_runtime.phase5d_package import CodexBuildPackageReadService, codex_build_package_digest
from avuhz_runtime.schema_registry import SchemaRegistry
from tests.runtime import test_phase5d_codex_build_package_runtime as package_runtime
from tests.runtime import test_phase5d_implementation_authorization_runtime as auth_runtime
from tests.runtime import test_phase5d_implementation_brief_runtime as brief_runtime


if DSN:
    from psycopg.errors import InsufficientPrivilege
    from avuhz_runtime.postgres import PostgresStore, PostgresUnitOfWork
    from tests.integration import test_postgres_phase5d_implementation_authorization_persistence as auth_postgres
    PostgresHarness = auth_postgres.PostgresHarness
else:
    InsufficientPrivilege = Exception
    PostgresStore = PostgresUnitOfWork = None
    PostgresHarness = unittest.TestCase


@unittest.skipUnless(DSN, "local Phase 5D-B3 PostgreSQL DSN is required")
class Phase5DCodexBuildPackagePostgresTests(PostgresHarness):
    def brief_helper(self):
        helper = brief_runtime.ImplementationBriefRuntimeTests()
        helper.setUp()
        helper.h = self.harness.h
        helper.handoff = self.harness.handoff
        helper._tenant = self.harness.tenant
        helper._engagement_id = self.harness.engagement_id
        helper.store = self.harness.store
        helper._number = 940
        helper.executor = self.harness.executor
        return helper

    def authorization_helper(self, brief_helper):
        helper = auth_runtime.ImplementationAuthorizationRuntimeTests()
        helper.setUp()
        helper.b = brief_helper
        helper._number = 950
        helper.executor = self.harness.executor
        return helper

    def package_helper(self, authorization_helper, authorization_payload):
        helper = package_runtime.CodexBuildPackageRuntimeTests()
        helper.setUp()
        helper.a = authorization_helper
        helper.authorization_payload = authorization_payload
        helper._number = 960
        helper.executor = self.harness.executor
        return helper

    def package_uow(self, helper, tenant=None):
        return PostgresUnitOfWork(
            PostgresStore(self.service_factory),
            helper.context(
                "DraftCodexBuildPackage",
                tenant=tenant or self.harness.tenant,
            ),
        )

    def active_authorization(self):
        self.build_active()
        brief_helper = self.brief_helper()
        brief_payload = brief_helper.payload()
        brief_helper.draft(brief_payload)
        brief_helper.approve(brief_payload)
        authorization_helper = self.authorization_helper(brief_helper)
        authorization_payload = authorization_helper.payload()
        authorization_helper.execute(
            "ProposeImplementationAuthorization", authorization_payload
        )
        authorization_helper.activate(
            authorization_payload, authorization_helper.approve(authorization_payload)
        )
        return authorization_helper, authorization_payload

    def released_package(self):
        authorization_helper, authorization_payload = self.active_authorization()
        helper = self.package_helper(authorization_helper, authorization_payload)
        payload = helper.payload()
        helper.draft(payload)
        helper.release(payload, helper.approve(payload))
        return helper, payload

    def test_restart_durability_rls_exact_round_trip_and_deployment_hard_stop(self):
        helper, payload = self.released_package()
        fresh = self.package_uow(helper)
        try:
            record = fresh.codex_build_packages.get_version(
                self.harness.tenant, package_runtime.PACKAGE_ID, 1
            )
            readiness = CodexBuildPackageReadService(fresh).readiness(
                self.harness.tenant,
                package_runtime.PACKAGE_ID,
                1,
                self.harness.now,
            )
        finally:
            fresh.rollback()
            fresh.close()
        self.assertEqual((record["state"], record["record_version"]), ("RELEASED", 2))
        self.assertEqual(record["package_digest"], payload["package_digest"])
        self.assertEqual(
            record["implementation_brief_reference"],
            payload["implementation_brief_reference"],
        )
        self.assertEqual(
            record["implementation_authorization_reference"],
            payload["implementation_authorization_reference"],
        )
        validator = Draft202012Validator(
            SchemaRegistry(ROOT / "contracts/schemas/v1").expanded(
                "urn:avuhz:schema:contracts:domain:codex-build-package:v1"
            ),
            format_checker=FormatChecker(),
        )
        self.assertEqual(list(validator.iter_errors(record)), [])
        self.assertTrue(readiness["codex_build_package_ready"])
        self.assertEqual(
            (
                readiness["package_grants_authority"],
                readiness["deployment_authorized"],
                readiness["production_change_authorized"],
            ),
            (False, False, False),
        )

        with self.owner() as connection:
            counts = tuple(
                connection.execute(query).fetchone()["count"]
                for query in (
                    "select count(*) from public.avuhz_codex_build_packages",
                    "select count(*) from public.avuhz_human_approvals where subject_type='CODEX_BUILD_PACKAGE'",
                    "select count(*) from public.avuhz_lifecycle_events where event_type like 'codex_build_package.%'",
                    "select count(*) from public.avuhz_outbox_deliveries o join public.avuhz_lifecycle_events e on e.lifecycle_event_id=o.lifecycle_event_id where e.event_type like 'codex_build_package.%' and o.status='PENDING'",
                )
            )
        self.assertEqual(counts, (1, 2, 4, 4))

        other = self.package_uow(helper, self.OTHER_TENANT)
        try:
            self.assertIsNone(other.codex_build_packages.get_version(
                self.harness.tenant, package_runtime.PACKAGE_ID, 1
            ))
            self.assertEqual(
                other.codex_build_packages.list_versions(
                    self.harness.tenant, package_runtime.PACKAGE_ID
                ),
                (),
            )
        finally:
            other.rollback()
            other.close()

        raw = self.service_factory()
        try:
            self.assertEqual(
                raw.execute(
                    "select count(*) from public.avuhz_codex_build_packages"
                ).fetchone()["count"],
                0,
            )
            raw.execute(
                "select set_config('avuhz.tenant_id',%s,false)",
                (self.harness.tenant,),
            )
            with self.assertRaises(InsufficientPrivilege):
                raw.execute(
                    "delete from public.avuhz_codex_build_packages "
                    "where tenant_id=%s and codex_build_package_id=%s",
                    (self.harness.tenant, package_runtime.PACKAGE_ID),
                )
        finally:
            raw.rollback()
            raw.close()

    def test_immutable_history_stale_write_and_no_source_rebinding(self):
        helper, first = self.released_package()
        fresh = self.package_uow(helper)
        try:
            brief_before = fresh.implementation_briefs.get_version(
                self.harness.tenant,
                first["implementation_brief_reference"]["reference_id"],
                first["implementation_brief_reference"]["reference_version"],
            )
            authorization_before = fresh.implementation_authorizations.get_version(
                self.harness.tenant,
                first["implementation_authorization_reference"]["reference_id"],
                first["implementation_authorization_reference"]["reference_version"],
            )
        finally:
            fresh.rollback()
            fresh.close()

        second = helper.payload(version=2)
        second["test_obligations"].append("Run PostgreSQL immutable-history checks.")
        second["package_digest"] = codex_build_package_digest(second)
        raw = helper.raw("ReviseCodexBuildPackage", second, expected=2)
        context = helper.context("ReviseCodexBuildPackage")
        self.assertEqual(
            self.harness.executor.execute(copy.deepcopy(raw), context)["result"],
            "ACCEPTED",
        )
        stale = copy.deepcopy(raw)
        stale["command_id"] = helper.next_id()
        stale["idempotency_key"] = "phase5d-postgres-package-stale-0001"
        self.assertEqual(
            self.harness.executor.execute(stale, context)["reason_code"],
            "VERSION_STALE",
        )

        fresh = self.package_uow(helper)
        try:
            history = fresh.codex_build_packages.list_versions(
                self.harness.tenant, package_runtime.PACKAGE_ID
            )
            brief_after = fresh.implementation_briefs.get_version(
                self.harness.tenant,
                first["implementation_brief_reference"]["reference_id"],
                first["implementation_brief_reference"]["reference_version"],
            )
            authorization_after = fresh.implementation_authorizations.get_version(
                self.harness.tenant,
                first["implementation_authorization_reference"]["reference_id"],
                first["implementation_authorization_reference"]["reference_version"],
            )
        finally:
            fresh.rollback()
            fresh.close()
        self.assertEqual(
            [(row["package_version"], row["state"], row["record_version"]) for row in history],
            [(1, "SUPERSEDED", 3), (2, "DRAFT", 1)],
        )
        self.assertEqual(history[0]["package_digest"], first["package_digest"])
        self.assertEqual(history[1]["package_digest"], second["package_digest"])
        self.assertEqual(brief_after, brief_before)
        self.assertEqual(authorization_after, authorization_before)

    def test_idempotency_across_restart_and_atomic_outbox_rollback(self):
        authorization_helper, authorization_payload = self.active_authorization()
        helper = self.package_helper(authorization_helper, authorization_payload)
        payload = helper.payload()
        raw = helper.raw(
            "DraftCodexBuildPackage",
            payload,
            key="phase5d-postgres-package-replay-0001",
        )
        context = helper.context("DraftCodexBuildPackage")
        self.assertEqual(
            self.harness.executor.execute(copy.deepcopy(raw), context)["result"],
            "ACCEPTED",
        )
        self.assertEqual(
            self.executor().execute(copy.deepcopy(raw), context)["result"],
            "DUPLICATE",
        )
        changed = copy.deepcopy(raw)
        changed["payload"]["test_obligations"].append("Changed semantic request.")
        changed["payload"]["package_digest"] = codex_build_package_digest(
            changed["payload"]
        )
        self.assertEqual(self.executor().execute(changed, context)["result"], "CONFLICT")

        self.tearDown()
        self.setUp()
        authorization_helper, authorization_payload = self.active_authorization()
        helper = self.package_helper(authorization_helper, authorization_payload)
        payload = helper.payload()
        raw = helper.raw(
            "DraftCodexBuildPackage",
            payload,
            key="phase5d-postgres-package-atomic-0001",
        )
        store = PostgresStore(self.service_factory)
        store.fail_stage = "OUTBOX_APPEND"
        result = self.executor(store).execute(
            raw, helper.context("DraftCodexBuildPackage")
        )
        self.assertEqual(result["result"], "REJECTED")
        with self.owner() as connection:
            counts = tuple(
                connection.execute(query).fetchone()["count"]
                for query in (
                    "select count(*) from public.avuhz_codex_build_packages",
                    "select count(*) from public.avuhz_idempotency_records where command_type='DraftCodexBuildPackage'",
                    "select count(*) from public.avuhz_lifecycle_events where event_type='codex_build_package.drafted'",
                    "select count(*) from public.avuhz_outbox_deliveries o join public.avuhz_lifecycle_events e on e.lifecycle_event_id=o.lifecycle_event_id where e.event_type='codex_build_package.drafted'",
                )
            )
        self.assertEqual(counts, (0, 0, 0, 0))


if __name__ == "__main__":
    unittest.main()
