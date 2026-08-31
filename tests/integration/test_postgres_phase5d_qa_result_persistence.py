"""Local-only PostgreSQL certification for Phase 5D-D2 QAResult."""
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

from avuhz_runtime.phase5d_build_execution import build_execution_digest
from avuhz_runtime.phase5d_qa_result import QAResultReadService, qa_result_digest
from avuhz_runtime.schema_registry import SchemaRegistry
from tests.runtime import test_phase5d_build_execution_result_runtime as build_runtime
from tests.runtime import test_phase5d_qa_result_runtime as qa_runtime
from tests.integration import test_postgres_phase5d_build_execution_result_persistence as build_postgres

if DSN:
    from psycopg.errors import InsufficientPrivilege
    from avuhz_runtime.postgres import PostgresStore,PostgresUnitOfWork
    PostgresHarness=build_postgres.Phase5DBuildExecutionResultPostgresTests
else:
    InsufficientPrivilege=Exception
    PostgresStore=PostgresUnitOfWork=None
    PostgresHarness=unittest.TestCase


@unittest.skipUnless(DSN,"local Phase 5D-D2 PostgreSQL DSN is required")
class Phase5DQAResultPostgresTests(PostgresHarness):
    def qa_helper(self):
        build=self.build_helper();build.start()
        fresh=self.build_uow(build)
        try:
            current=fresh.build_execution_results.get(self.harness.tenant,build_runtime.RESULT_ID)
        finally:
            fresh.rollback();fresh.close()
        completion={
            "build_execution_result_id":build_runtime.RESULT_ID,"execution_attempt":1,
            "status":"SUCCEEDED","changed_targets":[copy.deepcopy(build.package_payload["allowed_targets"][0])],
            "artifact_references":[{"artifact_reference_id":"artifact.build.1","artifact_class":"BUILD_ARTIFACT","artifact_version":"1.0.1","artifact_digest":"sha256:"+"a"*64}],
            "test_result_references":[{"test_result_reference_id":"test.build.1","test_class":"CONTRACT","result_digest":"sha256:"+"b"*64}],
            "execution_digest":"sha256:"+"0"*64,
        }
        completion["execution_digest"]=build_execution_digest(current,completion)
        build.complete(completion)
        fresh=self.build_uow(build)
        try:
            terminal=fresh.build_execution_results.get(self.harness.tenant,build_runtime.RESULT_ID)
        finally:
            fresh.rollback();fresh.close()
        helper=qa_runtime.QAResultRuntimeTests()
        helper.setUp()
        helper.b=build;helper._number=1080
        helper.source_builds={build_runtime.RESULT_ID:terminal}
        helper.executor=self.harness.executor
        return helper

    def qa_uow(self,helper,tenant=None):
        return PostgresUnitOfWork(
            PostgresStore(self.service_factory),
            helper.context(tenant=tenant or self.harness.tenant),
        )

    def test_restart_durability_rls_exact_round_trip_and_non_authority(self):
        helper=self.qa_helper();helper.record()
        fresh=self.qa_uow(helper)
        try:
            record=fresh.qa_results.get(self.harness.tenant,qa_runtime.QA_ID)
            view=QAResultReadService(fresh).status(self.harness.tenant,qa_runtime.QA_ID,self.harness.now)
        finally:
            fresh.rollback();fresh.close()
        self.assertEqual((record["overall_status"],record["record_version"]),("PASSED",1))
        self.assertEqual(record["build_execution_digest"],helper.payload()["build_execution_digest"])
        validator=Draft202012Validator(SchemaRegistry(ROOT/"contracts/schemas/v1").expanded("urn:avuhz:schema:contracts:domain:qa-result:v1"),format_checker=FormatChecker())
        self.assertEqual(list(validator.iter_errors(record)),[])
        self.assertEqual((view["qa_passed"],view["client_accepted"],view["deployment_authorized"]),(True,False,False))
        with self.owner() as connection:
            counts=tuple(connection.execute(query).fetchone()["count"] for query in (
                "select count(*) from public.avuhz_qa_results",
                "select count(*) from public.avuhz_lifecycle_events where event_type='qa_result.recorded'",
                "select count(*) from public.avuhz_outbox_deliveries o join public.avuhz_lifecycle_events e on e.lifecycle_event_id=o.lifecycle_event_id where e.event_type='qa_result.recorded' and o.status='PENDING'",
            ))
            later=connection.execute("select count(*) from information_schema.tables where table_schema='public' and table_name='avuhz_deployment_verifications'").fetchone()["count"]
        self.assertEqual(counts,(1,1,1));self.assertEqual(later,0)
        other=self.qa_uow(helper,self.OTHER_TENANT)
        try:
            self.assertIsNone(other.qa_results.get(self.harness.tenant,qa_runtime.QA_ID))
            self.assertEqual(other.qa_results.list_by_package(self.harness.tenant,helper.package_payload["codex_build_package_id"],1),())
        finally:
            other.rollback();other.close()
        raw=self.service_factory()
        try:
            self.assertEqual(raw.execute("select count(*) from public.avuhz_qa_results").fetchone()["count"],0)
            raw.execute("select set_config('avuhz.tenant_id',%s,false)",(self.harness.tenant,))
            with self.assertRaises(InsufficientPrivilege):
                raw.execute("delete from public.avuhz_qa_results where tenant_id=%s and qa_result_id=%s",(self.harness.tenant,qa_runtime.QA_ID))
        finally:
            raw.rollback();raw.close()

    def test_failure_retest_history_stale_predecessor_and_atomic_rollback(self):
        helper=self.qa_helper()
        failed=helper.payload();failed["criterion_results"][0]["result"]="FAIL";failed["overall_status"]="FAILED"
        failed["qa_digest"]=qa_result_digest(helper.tenant,helper.engagement_id,failed,{"principal_reference":"service.phase5d-qa","caller_type":"INTERNAL_SERVICE","recorded_by":"service.phase5d-qa"})
        helper.record(failed)
        retest=helper.payload(qa_id=qa_runtime.RETEST_ID,attempt=2)
        helper.record(retest,qa_id=qa_runtime.RETEST_ID)
        fresh=self.qa_uow(helper)
        try:
            history=fresh.qa_results.list_by_package(self.harness.tenant,helper.package_payload["codex_build_package_id"],1)
        finally:
            fresh.rollback();fresh.close()
        self.assertEqual([(x["qa_attempt"],x["overall_status"]) for x in history],[(1,"FAILED"),(2,"PASSED")])
        stale=helper.payload(qa_id=helper.next_id(),attempt=3);stale["supersedes_qa_result_reference"]={"reference_type":"QA_RESULT","reference_id":qa_runtime.RETEST_ID,"reference_version":2}
        stale["qa_digest"]=qa_result_digest(helper.tenant,helper.engagement_id,stale,{"principal_reference":"service.phase5d-qa","caller_type":"INTERNAL_SERVICE","recorded_by":"service.phase5d-qa"})
        self.assertEqual(helper.execute(helper.raw(stale,key="phase5d-postgres-qa-stale-0001"))["result"],"REJECTED")
        with self.owner() as connection:
            before=tuple(connection.execute(q).fetchone()["count"] for q in (
                "select count(*) from public.avuhz_qa_results",
                "select count(*) from public.avuhz_lifecycle_events where event_type='qa_result.recorded'",
                "select count(*) from public.avuhz_outbox_deliveries o join public.avuhz_lifecycle_events e on e.lifecycle_event_id=o.lifecycle_event_id where e.event_type='qa_result.recorded'",
            ))
        failing=PostgresStore(self.service_factory);failing.fail_stage="OUTBOX_APPEND"
        fresh_helper=qa_runtime.QAResultRuntimeTests();fresh_helper.b=helper.b;fresh_helper.store=failing;fresh_helper._number=1180
        fresh_helper.source_builds=copy.deepcopy(helper.source_builds)
        fresh_helper.executor=self.harness.executor.__class__(self.harness.executor.validator,self.harness.executor.pipeline,failing,clock=lambda:self.harness.now,ids=fresh_helper.next_id,uow_factory=PostgresUnitOfWork)
        payload=fresh_helper.payload(qa_id=fresh_helper.next_id(),attempt=3);payload["supersedes_qa_result_reference"]={"reference_type":"QA_RESULT","reference_id":qa_runtime.RETEST_ID,"reference_version":1}
        payload["qa_digest"]=qa_result_digest(fresh_helper.tenant,fresh_helper.engagement_id,payload,{"principal_reference":"service.phase5d-qa","caller_type":"INTERNAL_SERVICE","recorded_by":"service.phase5d-qa"})
        result=fresh_helper.execute(fresh_helper.raw(payload,key="phase5d-postgres-qa-rollback-0001"))
        self.assertEqual(result["result"],"REJECTED")
        with self.owner() as connection:
            after=tuple(connection.execute(q).fetchone()["count"] for q in (
                "select count(*) from public.avuhz_qa_results",
                "select count(*) from public.avuhz_lifecycle_events where event_type='qa_result.recorded'",
                "select count(*) from public.avuhz_outbox_deliveries o join public.avuhz_lifecycle_events e on e.lifecycle_event_id=o.lifecycle_event_id where e.event_type='qa_result.recorded'",
            ))
        self.assertEqual(after,before)


if __name__=="__main__":unittest.main()
