"""Phase 5D-D1 BuildExecutionResult runtime, boundary, history, and atomicity coverage."""
from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"src"))

from avuhz_runtime.guards import GuardPipeline, TrustedExecutionContext
from avuhz_runtime.in_memory import Executor, UnitOfWork
from avuhz_runtime.phase5d_build_execution import (
    BUILD_EXECUTION_CAPABILITIES,
    BuildExecutionResultReadService,
    build_execution_digest,
)
from avuhz_runtime.schema_registry import SchemaRegistry
from avuhz_runtime.validation import CommandValidator
from tests.runtime import test_phase5d_codex_build_package_runtime as package_runtime


RESULT_ID="d5d10000-0000-4000-8000-000000000001"
CORRECTION_ID="d5d10000-0000-4000-8000-000000000002"
FOREIGN_TENANT="d5d10000-0000-4000-8000-000000000099"


def schema_validator(schema_id):
    registry=SchemaRegistry(ROOT/"contracts/schemas/v1")
    return Draft202012Validator(registry.expanded(schema_id),format_checker=FormatChecker())


class BuildExecutionResultRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.p=package_runtime.CodexBuildPackageRuntimeTests()
        self.p.setUp()
        package=self.p.payload()
        self.p.draft(package)
        self.p.release(package,self.p.approve(package))
        self.package_payload=package
        self.store=self.p.store
        self.store.events.clear();self.store.outbox.clear();self.store.idempotency.clear()
        self._number=980
        self.executor=Executor(CommandValidator(ROOT/"contracts/schemas/v1"),GuardPipeline(),self.store,clock=lambda:self.now,ids=self.next_id)

    @property
    def tenant(self):return self.p.tenant
    @property
    def engagement_id(self):return self.p.engagement_id
    @property
    def now(self):return self.p.now
    def next_id(self):
        self._number+=1
        return f"d5d19000-0000-4000-8000-{self._number:012d}"

    def context(self,command,*,caller_type="INTERNAL_SERVICE",tenant=None,principal=None):
        principal=principal or ("human.builder" if caller_type=="HUMAN" else "service.phase5d-builder")
        human=caller_type=="HUMAN"
        return TrustedExecutionContext(
            True,principal,caller_type,tenant or self.tenant,None,
            frozenset({BUILD_EXECUTION_CAPABILITIES[command]}),frozenset(),"TEST",
            "avuhz-command-api","STRONG",False,"2030-01-15T14:00:00Z",
            "2030-03-15T16:00:00Z",principal if human else None,
            "organization.builder" if human else None,None,
        )

    def raw(self,command,payload,*,result_id=None,expected=None,key=None,command_id=None,tenant=None,engagement=None,caller_type="INTERNAL_SERVICE"):
        slug={"StartBuildExecution":"start-build-execution","CompleteBuildExecution":"complete-build-execution"}[command]
        value={
            "command_id":command_id or self.next_id(),"command_type":command,
            "command_schema_version":1,"tenant_id":tenant or self.tenant,
            "engagement_id":engagement or self.engagement_id,
            "subject_type":"BUILD_EXECUTION_RESULT",
            "subject_id":result_id or payload["build_execution_result_id"],
            "requested_by":"trusted.phase5d","caller_type":caller_type,
            "caller_identity":{"subject":"trusted.phase5d","audience":"avuhz-command-api","caller_type":caller_type,"tenant_ids":[tenant or self.tenant],"capabilities":[BUILD_EXECUTION_CAPABILITIES[command]],"environment":"TEST","authentication_strength":"STRONG","step_up_performed":False,"authenticated_at":"2030-01-15T14:00:00Z","expires_at":"2030-03-15T16:00:00Z"},
            "correlation_id":"d5d10000-0000-4000-8000-000000000090",
            "idempotency_key":key or f"phase5d-build-{command.lower()}-{self._number}",
            "requested_at":self.now,"environment":"TEST",
            "payload_schema":f"urn:avuhz:schema:contracts:commands:{slug}-payload:v1",
            "payload_version":1,"payload":copy.deepcopy(payload),
        }
        if expected is not None:value["expected_record_version"]=expected
        return value

    def start_payload(self,*,result_id=RESULT_ID,attempt=1):
        value={
            "build_execution_result_id":result_id,
            "execution_attempt":attempt,
            "codex_build_package_reference":{"reference_type":"CODEX_BUILD_PACKAGE","reference_id":self.package_payload["codex_build_package_id"],"reference_version":self.package_payload["package_version"]},
            "package_digest":self.package_payload["package_digest"],
            "implementation_authorization_reference":copy.deepcopy(self.package_payload["implementation_authorization_reference"]),
            "implementation_authority_digest":self.package_payload["implementation_authority_digest"],
            "execution_fingerprint":f"fpv1:build-execution-attempt-{attempt:04d}",
        }
        if attempt>1:
            value["supersedes_build_execution_reference"]={"reference_type":"BUILD_EXECUTION_RESULT","reference_id":RESULT_ID,"reference_version":2}
        return value

    def completion_payload(self,result_id=RESULT_ID,attempt=1,status="SUCCEEDED"):
        target=copy.deepcopy(self.package_payload["allowed_targets"][0])
        value={
            "build_execution_result_id":result_id,"execution_attempt":attempt,
            "status":status,"changed_targets":[target],
            "artifact_references":[{"artifact_reference_id":f"artifact.build.{attempt}","artifact_class":"BUILD_ARTIFACT","artifact_version":f"1.0.{attempt}","artifact_digest":"sha256:"+"a"*64}],
            "test_result_references":[{"test_result_reference_id":f"test.build.{attempt}","test_class":"CONTRACT","result_digest":"sha256:"+"b"*64}],
            "execution_digest":"sha256:"+"0"*64,
        }
        if status=="FAILED":value["failure_summary"]="A bounded build step failed; correction requires a new attempt."
        uow=UnitOfWork(self.store)
        current=uow.build_execution_results.get(self.tenant,result_id)
        value["execution_digest"]=build_execution_digest(current,value)
        return value

    def execute(self,raw,*,caller_type="INTERNAL_SERVICE",tenant=None,principal=None):
        return self.executor.execute(raw,self.context(raw["command_type"],caller_type=caller_type,tenant=tenant,principal=principal))

    def start(self,payload=None,**kwargs):
        payload=payload or self.start_payload()
        raw=self.raw("StartBuildExecution",payload,**kwargs)
        result=self.execute(raw,caller_type=raw["caller_type"])
        self.assertEqual(result["result"],"ACCEPTED",result)
        return raw

    def complete(self,payload=None,**kwargs):
        payload=payload or self.completion_payload()
        raw=self.raw("CompleteBuildExecution",payload,expected=kwargs.pop("expected",1),**kwargs)
        result=self.execute(raw,caller_type=raw["caller_type"])
        self.assertEqual(result["result"],"ACCEPTED",result)
        return raw

    def test_start_complete_exact_bindings_events_outbox_and_non_authority(self):
        self.start();self.complete()
        uow=UnitOfWork(self.store)
        record=uow.build_execution_results.get(self.tenant,RESULT_ID)
        view=BuildExecutionResultReadService(uow).status(self.tenant,RESULT_ID,self.now)
        self.assertEqual((record["status"],record["record_version"]),("SUCCEEDED",2))
        self.assertEqual(record["package_digest"],self.package_payload["package_digest"])
        self.assertEqual(record["implementation_authorization_reference"],self.package_payload["implementation_authorization_reference"])
        self.assertEqual(list(schema_validator("urn:avuhz:schema:contracts:domain:build-execution-result:v1").iter_errors(record)),[])
        self.assertEqual(list(schema_validator("urn:avuhz:schema:contracts:read-models:build-execution-status-view:v1").iter_errors(view)),[])
        self.assertEqual((view["build_succeeded"],view["qa_passed"],view["client_accepted"],view["deployment_authorized"]),(True,False,False,False))
        self.assertEqual([e["event_type"] for e in self.store.events],["build_execution.started","build_execution.completed"])
        self.assertTrue(all(e["authoritative_subject_reference"]["reference_type"]=="BUILD_EXECUTION_RESULT" for e in self.store.events))
        self.assertEqual([o["status"] for o in self.store.outbox],["PENDING","PENDING"])
        event_validator=schema_validator("urn:avuhz:schema:contracts:orchestration:lifecycle-event:v1")
        self.assertTrue(all(event_validator.is_valid(e) for e in self.store.events))

    def test_failure_and_correction_are_distinct_immutable_history(self):
        self.start();self.complete(self.completion_payload(status="FAILED"))
        correction=self.start_payload(result_id=CORRECTION_ID,attempt=2)
        self.start(correction,result_id=CORRECTION_ID)
        self.complete(self.completion_payload(CORRECTION_ID,2),result_id=CORRECTION_ID)
        history=UnitOfWork(self.store).build_execution_results.list_by_package(self.tenant,self.package_payload["codex_build_package_id"],1)
        self.assertEqual([(x["execution_attempt"],x["status"]) for x in history],[(1,"FAILED"),(2,"SUCCEEDED")])
        self.assertIn("failure_summary",history[0])
        self.assertEqual(history[1]["supersedes_build_execution_reference"]["reference_id"],RESULT_ID)
        self.assertNotEqual(history[0]["execution_digest"],history[1]["execution_digest"])

    def test_source_authority_scope_and_spoofing_negatives_have_no_side_effects(self):
        cases=[]
        for label,mutation in (
            ("wrong package digest",lambda p:p.update(package_digest="sha256:"+"9"*64)),
            ("wrong package version",lambda p:p["codex_build_package_reference"].update(reference_version=2)),
            ("wrong authorization digest",lambda p:p.update(implementation_authority_digest="sha256:"+"9"*64)),
            ("wrong authorization version",lambda p:p["implementation_authorization_reference"].update(reference_version=2)),
        ):
            payload=self.start_payload(result_id=self.next_id());mutation(payload);cases.append((label,self.raw("StartBuildExecution",payload)))
        for label,raw in cases:
            before=(len(self.store.build_execution_results),len(self.store.events),len(self.store.outbox),len(self.store.idempotency))
            result=self.execute(raw)
            self.assertEqual(result["result"],"REJECTED",label)
            self.assertEqual((len(self.store.build_execution_results),len(self.store.events),len(self.store.outbox),len(self.store.idempotency)),before,label)
        payload=self.start_payload();self.start(payload)
        for field,value in (("success",True),("qa_passed",True),("client_accepted",True),("deployment_allowed",True),("production_authorized",True),("actor","spoofed"),("role","DEPLOYMENT_AUTHORITY"),("deployment_instruction","Deploy to production.")):
            bad=self.completion_payload();bad[field]=value
            result=self.execute(self.raw("CompleteBuildExecution",bad,expected=1,key=f"phase5d-build-forbidden-{field}"))
            self.assertEqual(result["result"],"VALIDATION_FAILED",field)
        bad=self.completion_payload();bad["changed_targets"]=[{"target_reference_id":"repository.unauthorized","target_class":"REPOSITORY"}];bad["execution_digest"]=build_execution_digest(UnitOfWork(self.store).build_execution_results.get(self.tenant,RESULT_ID),bad)
        self.assertEqual(self.execute(self.raw("CompleteBuildExecution",bad,expected=1,key="phase5d-build-unauthorized-target"))["result"],"REJECTED")
        self.assertEqual(UnitOfWork(self.store).build_execution_results.get(self.tenant,RESULT_ID)["status"],"IN_PROGRESS")

    def test_unreleased_revoked_cross_tenant_and_executor_spoof_rejected(self):
        package_key=(self.tenant,self.package_payload["codex_build_package_id"],1)
        self.store.codex_build_packages[package_key]["state"]="DRAFT"
        self.assertEqual(self.execute(self.raw("StartBuildExecution",self.start_payload()))["result"],"REJECTED")
        self.store.codex_build_packages[package_key]["state"]="RELEASED"
        authorization_id=self.package_payload["implementation_authorization_reference"]["reference_id"]
        auth_key=(self.tenant,authorization_id,1)
        self.store.implementation_authorizations[auth_key]["state"]="REVOKED"
        self.assertEqual(self.execute(self.raw("StartBuildExecution",self.start_payload(),key="phase5d-build-revoked"))["result"],"REJECTED")
        self.store.implementation_authorizations[auth_key]["state"]="ACTIVE"
        foreign=self.start_payload(result_id=self.next_id())
        raw=self.raw("StartBuildExecution",foreign,tenant=FOREIGN_TENANT,key="phase5d-build-cross-tenant")
        self.assertEqual(self.execute(raw,tenant=FOREIGN_TENANT)["result"],"REJECTED")
        self.start()
        payload=self.completion_payload()
        raw=self.raw("CompleteBuildExecution",payload,expected=1,key="phase5d-build-principal-spoof")
        self.assertEqual(self.execute(raw,principal="service.other-builder")["result"],"REJECTED")

    def test_stale_duplicate_idempotency_conflict_and_atomic_rollback(self):
        raw=self.start()
        replay=self.execute(copy.deepcopy(raw))
        self.assertEqual(replay["result"],"DUPLICATE")
        changed=copy.deepcopy(raw);changed["payload"]["execution_fingerprint"]="fpv1:semantically-changed-0001"
        self.assertEqual(self.execute(changed)["result"],"CONFLICT")
        duplicate=self.start_payload();duplicate["execution_fingerprint"]="fpv1:duplicate-identity-0001"
        self.assertEqual(self.execute(self.raw("StartBuildExecution",duplicate,key="phase5d-build-duplicate-identity"))["result"],"REJECTED")
        payload=self.completion_payload()
        stale=self.raw("CompleteBuildExecution",payload,expected=2,key="phase5d-build-stale-version")
        self.assertEqual(self.execute(stale)["reason_code"],"VERSION_STALE")
        for stage in ("AUTHORITATIVE_WRITE","LIFECYCLE_EVENT_APPEND","OUTBOX_APPEND","IDEMPOTENCY_COMPLETE","COMMIT"):
            fresh=BuildExecutionResultRuntimeTests();fresh.setUp();fresh.store.fail_stage=stage
            before=copy.deepcopy(fresh.store)
            result=fresh.execute(fresh.raw("StartBuildExecution",fresh.start_payload(),key=f"phase5d-build-fail-{stage.lower()}"))
            self.assertEqual(result["result"],"REJECTED",stage)
            fresh.store.fail_stage=None
            self.assertEqual(fresh.store.build_execution_results,before.build_execution_results,stage)
            self.assertEqual(fresh.store.events,before.events,stage)
            self.assertEqual(fresh.store.outbox,before.outbox,stage)
            self.assertEqual(fresh.store.idempotency,before.idempotency,stage)


if __name__=="__main__":unittest.main()
