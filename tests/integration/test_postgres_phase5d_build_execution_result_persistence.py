"""Local-only PostgreSQL certification for Phase 5D-D1 BuildExecutionResult."""
from __future__ import annotations

import copy
import os
import sys
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/"src")]
DSN=os.environ.get("AVUHZ_POSTGRES_DSN")

from avuhz_runtime.phase5d_build_execution import BuildExecutionResultReadService
from avuhz_runtime.schema_registry import SchemaRegistry
from tests.runtime import test_phase5d_build_execution_result_runtime as build_runtime
from tests.integration import test_postgres_phase5d_codex_build_package_persistence as package_postgres

if DSN:
    from psycopg.errors import InsufficientPrivilege
    from avuhz_runtime.postgres import PostgresStore,PostgresUnitOfWork
    PostgresHarness=package_postgres.Phase5DCodexBuildPackagePostgresTests
else:
    InsufficientPrivilege=Exception
    PostgresStore=PostgresUnitOfWork=None
    PostgresHarness=unittest.TestCase


@unittest.skipUnless(DSN,"local Phase 5D-D1 PostgreSQL DSN is required")
class Phase5DBuildExecutionResultPostgresTests(PostgresHarness):
    def build_helper(self):
        package_helper,package_payload=self.released_package()
        helper=build_runtime.BuildExecutionResultRuntimeTests()
        helper.setUp()
        helper.p=package_helper;helper.package_payload=package_payload
        helper._number=980
        helper.executor=self.harness.executor
        original_start=helper.start
        def start_and_sync(payload=None,**kwargs):
            raw=original_start(payload,**kwargs)
            fresh=self.build_uow(helper)
            try:
                current=fresh.build_execution_results.get(helper.tenant,raw["subject_id"])
            finally:
                fresh.rollback();fresh.close()
            helper.store.build_execution_results[(helper.tenant,raw["subject_id"])]=current
            return raw
        helper.start=start_and_sync
        return helper

    def build_uow(self,helper,tenant=None):
        return PostgresUnitOfWork(
            PostgresStore(self.service_factory),
            helper.context("StartBuildExecution",tenant=tenant or self.harness.tenant),
        )

    def test_restart_durability_rls_exact_round_trip_and_non_authority(self):
        helper=self.build_helper()
        helper.start();helper.complete()
        fresh=self.build_uow(helper)
        try:
            record=fresh.build_execution_results.get(self.harness.tenant,build_runtime.RESULT_ID)
            view=BuildExecutionResultReadService(fresh).status(self.harness.tenant,build_runtime.RESULT_ID,self.harness.now)
        finally:
            fresh.rollback();fresh.close()
        self.assertEqual((record["status"],record["record_version"]),("SUCCEEDED",2))
        self.assertEqual(record["package_digest"],helper.package_payload["package_digest"])
        self.assertEqual(record["implementation_authorization_reference"],helper.package_payload["implementation_authorization_reference"])
        validator=Draft202012Validator(SchemaRegistry(ROOT/"contracts/schemas/v1").expanded("urn:avuhz:schema:contracts:domain:build-execution-result:v1"),format_checker=FormatChecker())
        self.assertEqual(list(validator.iter_errors(record)),[])
        self.assertEqual((view["build_succeeded"],view["qa_passed"],view["client_accepted"],view["deployment_authorized"]),(True,False,False,False))
        with self.owner() as connection:
            counts=tuple(connection.execute(query).fetchone()["count"] for query in (
                "select count(*) from public.avuhz_build_execution_results",
                "select count(*) from public.avuhz_lifecycle_events where event_type like 'build_execution.%'",
                "select count(*) from public.avuhz_outbox_deliveries o join public.avuhz_lifecycle_events e on e.lifecycle_event_id=o.lifecycle_event_id where e.event_type like 'build_execution.%' and o.status='PENDING'",
            ))
            later=connection.execute("select count(*) from information_schema.tables where table_schema='public' and table_name in ('avuhz_client_acceptances','avuhz_deployment_authorizations')").fetchone()["count"]
        self.assertEqual(counts,(1,2,2));self.assertEqual(later,0)
        other=self.build_uow(helper,self.OTHER_TENANT)
        try:
            self.assertIsNone(other.build_execution_results.get(self.harness.tenant,build_runtime.RESULT_ID))
            self.assertEqual(other.build_execution_results.list_by_package(self.harness.tenant,helper.package_payload["codex_build_package_id"],1),())
        finally:
            other.rollback();other.close()
        raw=self.service_factory()
        try:
            self.assertEqual(raw.execute("select count(*) from public.avuhz_build_execution_results").fetchone()["count"],0)
            raw.execute("select set_config('avuhz.tenant_id',%s,false)",(self.harness.tenant,))
            with self.assertRaises(InsufficientPrivilege):
                raw.execute("delete from public.avuhz_build_execution_results where tenant_id=%s and build_execution_result_id=%s",(self.harness.tenant,build_runtime.RESULT_ID))
        finally:
            raw.rollback();raw.close()

    def test_failure_correction_history_stale_write_and_atomic_rollback(self):
        helper=self.build_helper()
        helper.start();helper.complete(helper.completion_payload(status="FAILED"))
        correction=helper.start_payload(result_id=build_runtime.CORRECTION_ID,attempt=2)
        helper.start(correction,result_id=build_runtime.CORRECTION_ID)
        helper.complete(helper.completion_payload(build_runtime.CORRECTION_ID,2),result_id=build_runtime.CORRECTION_ID)
        fresh=self.build_uow(helper)
        try:
            history=fresh.build_execution_results.list_by_package(self.harness.tenant,helper.package_payload["codex_build_package_id"],1)
        finally:
            fresh.rollback();fresh.close()
        self.assertEqual([(x["execution_attempt"],x["status"]) for x in history],[(1,"FAILED"),(2,"SUCCEEDED")])
        stale=helper.raw("CompleteBuildExecution",helper.completion_payload(build_runtime.CORRECTION_ID,2),result_id=build_runtime.CORRECTION_ID,expected=1,key="phase5d-postgres-build-stale-0001")
        self.assertEqual(self.harness.executor.execute(stale,helper.context("CompleteBuildExecution"))["reason_code"],"VERSION_STALE")
        with self.owner() as connection:
            before=tuple(connection.execute(q).fetchone()["count"] for q in (
                "select count(*) from public.avuhz_build_execution_results",
                "select count(*) from public.avuhz_lifecycle_events where event_type like 'build_execution.%'",
                "select count(*) from public.avuhz_outbox_deliveries o join public.avuhz_lifecycle_events e on e.lifecycle_event_id=o.lifecycle_event_id where e.event_type like 'build_execution.%'",
            ))
        failing=PostgresStore(self.service_factory);failing.fail_stage="OUTBOX_APPEND"
        raw=helper.raw("StartBuildExecution",helper.start_payload(result_id=helper.next_id()),key="phase5d-postgres-build-rollback-0001")
        result=self.harness.executor.__class__(self.harness.executor.validator,self.harness.executor.pipeline,failing,clock=lambda:self.harness.now,ids=helper.next_id,uow_factory=PostgresUnitOfWork).execute(raw,helper.context("StartBuildExecution"))
        self.assertEqual(result["result"],"REJECTED")
        with self.owner() as connection:
            after=tuple(connection.execute(q).fetchone()["count"] for q in (
                "select count(*) from public.avuhz_build_execution_results",
                "select count(*) from public.avuhz_lifecycle_events where event_type like 'build_execution.%'",
                "select count(*) from public.avuhz_outbox_deliveries o join public.avuhz_lifecycle_events e on e.lifecycle_event_id=o.lifecycle_event_id where e.event_type like 'build_execution.%'",
            ))
        self.assertEqual(after,before)


if __name__=="__main__":unittest.main()
