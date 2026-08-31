"""Local-only PostgreSQL certification for Phase 5D-B2 ImplementationAuthorization."""
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

from avuhz_runtime.phase5d_authorization import (
    ImplementationAuthorizationReadService,
    implementation_authority_digest,
    implementation_authorization_scope_digest,
)
from avuhz_runtime.schema_registry import SchemaRegistry
from tests.runtime import test_phase5d_implementation_authorization_runtime as auth_runtime
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


@unittest.skipUnless(DSN, "local Phase 5D-B2 PostgreSQL DSN is required")
class Phase5DImplementationAuthorizationPostgresTests(PostgresHarness):
    """Use the provider-neutral current-tree seed and transactional harness."""

    def brief_helper(self):
        helper = brief_runtime.ImplementationBriefRuntimeTests()
        helper.setUp()
        helper.h = self.harness.h
        helper.handoff = self.harness.handoff
        helper._tenant = self.harness.tenant
        helper._engagement_id = self.harness.engagement_id
        helper.store = self.harness.store
        helper._number = 850
        helper.executor = self.harness.executor
        return helper

    def authorization_helper(self, brief_helper):
        helper = auth_runtime.ImplementationAuthorizationRuntimeTests()
        helper.setUp()
        helper.b = brief_helper
        helper._number = 900
        helper.executor = self.harness.executor
        return helper

    def phase5d_uow(self, helper, tenant=None):
        return PostgresUnitOfWork(
            PostgresStore(self.service_factory),
            helper.context(
                "ProposeImplementationAuthorization",
                tenant=tenant or self.harness.tenant,
            ),
        )

    def approved_brief(self):
        self.build_active()
        brief_helper = self.brief_helper()
        payload = brief_helper.payload()
        brief_helper.draft(payload)
        brief_helper.approve(payload)
        uow = self.phase5d_uow(self.authorization_helper(brief_helper))
        try:
            record = uow.implementation_briefs.get_version(
                self.harness.tenant, brief_runtime.BRIEF_ID, 1
            )
        finally:
            uow.rollback()
            uow.close()
        return brief_helper, record

    def authorization_payload(
        self,
        brief,
        *,
        authorization_id=auth_runtime.AUTHORIZATION_ID,
        version=1,
    ):
        payload = {
            "implementation_authorization_id": authorization_id,
            "authorization_version": version,
            "implementation_brief_reference": {
                "reference_type": "IMPLEMENTATION_BRIEF",
                "reference_id": brief["implementation_brief_id"],
                "reference_version": brief["implementation_brief_version"],
            },
            "implementation_brief_digest": brief["implementation_brief_digest"],
            "authorized_scope_digest": implementation_authorization_scope_digest(brief),
            "target_references": [
                {"target_reference_id": "scope.intake", "target_class": "COMPONENT"},
                {
                    "target_reference_id": "integration.fictional.sandbox",
                    "target_class": "NON_PRODUCTION_SYSTEM",
                },
            ],
            "permitted_action_classes": [
                "READ_REPOSITORY", "CREATE_CODE", "MODIFY_CODE", "CREATE_TEST",
                "MODIFY_TEST", "RUN_TEST", "CREATE_DOCUMENTATION",
                "MODIFY_DOCUMENTATION", "BUILD_NON_PRODUCTION_ARTIFACT",
            ],
            "prohibited_action_classes": copy.deepcopy(brief["prohibited_changes"]),
            "effective_at": self.harness.now,
            "expires_at": "2030-02-15T14:59:59Z",
            "implementation_authority_digest": "sha256:" + "0" * 64,
        }
        if version > 1:
            payload["supersedes_implementation_authorization_reference"] = {
                "reference_type": "IMPLEMENTATION_AUTHORIZATION",
                "reference_id": authorization_id,
                "reference_version": version - 1,
            }
        payload["implementation_authority_digest"] = implementation_authority_digest(payload)
        return payload

    def activate_authorization(self):
        brief_helper, brief = self.approved_brief()
        helper = self.authorization_helper(brief_helper)
        payload = self.authorization_payload(brief)
        helper.execute("ProposeImplementationAuthorization", payload)
        helper.activate(payload, helper.approve(payload))
        return helper, payload

    def test_restart_durability_rls_schema_events_and_deployment_hard_stop(self):
        helper, payload = self.activate_authorization()
        fresh = self.phase5d_uow(helper)
        try:
            record = fresh.implementation_authorizations.get_version(
                self.harness.tenant, auth_runtime.AUTHORIZATION_ID, 1
            )
            status = ImplementationAuthorizationReadService(fresh).status(
                self.harness.tenant,
                auth_runtime.AUTHORIZATION_ID,
                1,
                self.harness.now,
            )
        finally:
            fresh.rollback()
            fresh.close()
        self.assertEqual((record["state"], record["record_version"]), ("ACTIVE", 2))
        self.assertEqual(record["implementation_authority_digest"], payload["implementation_authority_digest"])
        validator = Draft202012Validator(
            SchemaRegistry(ROOT / "contracts/schemas/v1").expanded(
                "urn:avuhz:schema:contracts:domain:implementation-authorization:v1"
            ),
            format_checker=FormatChecker(),
        )
        self.assertEqual(list(validator.iter_errors(record)), [])
        self.assertTrue(status["implementation_authorization_usable"])
        self.assertEqual(
            (status["deployment_authorized"], status["production_change_authorized"]),
            (False, False),
        )

        with self.owner() as connection:
            counts = tuple(
                connection.execute(query).fetchone()["count"]
                for query in (
                    "select count(*) from public.avuhz_implementation_authorizations",
                    "select count(*) from public.avuhz_human_approvals where subject_type='IMPLEMENTATION_AUTHORIZATION'",
                    "select count(*) from public.avuhz_lifecycle_events where event_type like 'implementation_authorization.%'",
                    "select count(*) from public.avuhz_outbox_deliveries o join public.avuhz_lifecycle_events e on e.lifecycle_event_id=o.lifecycle_event_id where e.event_type like 'implementation_authorization.%' and o.status='PENDING'",
                )
            )
            forbidden_tables = connection.execute(
                "select count(*) from information_schema.tables where table_schema='public' "
                "and table_name='avuhz_deployment_executions'"
            ).fetchone()["count"]
        self.assertEqual(counts, (1, 2, 4, 4))
        self.assertEqual(forbidden_tables, 0)

        other = self.phase5d_uow(helper, self.OTHER_TENANT)
        try:
            self.assertIsNone(other.implementation_authorizations.get_version(
                self.harness.tenant, auth_runtime.AUTHORIZATION_ID, 1
            ))
            self.assertEqual(other.implementation_authorizations.list_versions(
                self.harness.tenant, auth_runtime.AUTHORIZATION_ID
            ), ())
        finally:
            other.rollback()
            other.close()
        raw = self.service_factory()
        try:
            self.assertEqual(raw.execute(
                "select count(*) from public.avuhz_implementation_authorizations"
            ).fetchone()["count"], 0)
            raw.execute(
                "select set_config('avuhz.tenant_id',%s,false)",
                (self.harness.tenant,),
            )
            with self.assertRaises(InsufficientPrivilege):
                raw.execute(
                    "delete from public.avuhz_implementation_authorizations "
                    "where tenant_id=%s and implementation_authorization_id=%s",
                    (self.harness.tenant, auth_runtime.AUTHORIZATION_ID),
                )
        finally:
            raw.rollback()
            raw.close()

    def test_history_exact_round_trip_stale_write_and_brief_immutability(self):
        helper, first = self.activate_authorization()
        fresh = self.phase5d_uow(helper)
        try:
            brief_before = fresh.implementation_briefs.get_version(
                self.harness.tenant, brief_runtime.BRIEF_ID, 1
            )
        finally:
            fresh.rollback()
            fresh.close()
        second = self.authorization_payload(brief_before, version=2)
        second["permitted_action_classes"] = ["READ_REPOSITORY", "CREATE_TEST", "RUN_TEST"]
        second["implementation_authority_digest"] = implementation_authority_digest(second)
        raw = helper.raw("ReviseImplementationAuthorization", second, expected=2)
        context = helper.context("ReviseImplementationAuthorization")
        self.assertEqual(self.harness.executor.execute(copy.deepcopy(raw), context)["result"], "ACCEPTED")
        stale = copy.deepcopy(raw)
        stale["command_id"] = helper.next_id()
        stale["idempotency_key"] = "phase5d-postgres-auth-stale-0001"
        stale_result = self.harness.executor.execute(stale, context)
        self.assertEqual(stale_result["reason_code"], "VERSION_STALE")

        fresh = self.phase5d_uow(helper)
        try:
            history = fresh.implementation_authorizations.list_versions(
                self.harness.tenant, auth_runtime.AUTHORIZATION_ID
            )
            brief_after = fresh.implementation_briefs.get_version(
                self.harness.tenant, brief_runtime.BRIEF_ID, 1
            )
        finally:
            fresh.rollback()
            fresh.close()
        self.assertEqual(
            [(item["authorization_version"], item["state"], item["record_version"]) for item in history],
            [(1, "SUPERSEDED", 3), (2, "PROPOSED", 1)],
        )
        self.assertEqual(history[0]["implementation_authority_digest"], first["implementation_authority_digest"])
        self.assertEqual(history[1]["implementation_authority_digest"], second["implementation_authority_digest"])
        self.assertEqual(brief_after, brief_before)

    def test_idempotency_across_restart_and_atomic_outbox_rollback(self):
        brief_helper, brief = self.approved_brief()
        helper = self.authorization_helper(brief_helper)
        payload = self.authorization_payload(brief)
        raw = helper.raw(
            "ProposeImplementationAuthorization",
            payload,
            key="phase5d-postgres-auth-replay-0001",
        )
        context = helper.context("ProposeImplementationAuthorization")
        self.assertEqual(self.harness.executor.execute(copy.deepcopy(raw), context)["result"], "ACCEPTED")
        self.assertEqual(self.executor().execute(copy.deepcopy(raw), context)["result"], "DUPLICATE")
        changed = copy.deepcopy(raw)
        changed["payload"]["expires_at"] = "2030-02-14T14:59:59Z"
        changed["payload"]["implementation_authority_digest"] = implementation_authority_digest(
            changed["payload"]
        )
        self.assertEqual(self.executor().execute(changed, context)["result"], "CONFLICT")

        self.tearDown()
        self.setUp()
        brief_helper, brief = self.approved_brief()
        helper = self.authorization_helper(brief_helper)
        payload = self.authorization_payload(brief)
        raw = helper.raw(
            "ProposeImplementationAuthorization",
            payload,
            key="phase5d-postgres-auth-atomic-0001",
        )
        store = PostgresStore(self.service_factory)
        store.fail_stage = "OUTBOX_APPEND"
        result = self.executor(store).execute(
            raw, helper.context("ProposeImplementationAuthorization")
        )
        self.assertEqual(result["result"], "REJECTED")
        with self.owner() as connection:
            counts = tuple(
                connection.execute(query).fetchone()["count"]
                for query in (
                    "select count(*) from public.avuhz_implementation_authorizations",
                    "select count(*) from public.avuhz_idempotency_records where command_type='ProposeImplementationAuthorization'",
                    "select count(*) from public.avuhz_lifecycle_events where event_type='implementation_authorization.proposed'",
                    "select count(*) from public.avuhz_outbox_deliveries o join public.avuhz_lifecycle_events e on e.lifecycle_event_id=o.lifecycle_event_id where e.event_type='implementation_authorization.proposed'",
                )
            )
        self.assertEqual(counts, (0, 0, 0, 0))


if __name__ == "__main__":
    unittest.main()
