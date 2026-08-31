"""Phase 5D-D2 QAResult runtime, truth, history, boundary, and atomicity coverage."""
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
from avuhz_runtime.phase5d_build_execution import BuildExecutionResultReadService
from avuhz_runtime.phase5d_qa_result import (
    QA_RESULT_CAPABILITIES,
    QAResultReadService,
    derive_overall_status,
    qa_result_digest,
)
from avuhz_runtime.schema_registry import SchemaRegistry
from avuhz_runtime.validation import CommandValidator
from tests.runtime import test_phase5d_build_execution_result_runtime as build_runtime


QA_ID="d5d20000-0000-4000-8000-000000000001"
RETEST_ID="d5d20000-0000-4000-8000-000000000002"
FOREIGN_TENANT="d5d20000-0000-4000-8000-000000000099"


def schema_validator(schema_id):
    registry=SchemaRegistry(ROOT/"contracts/schemas/v1")
    return Draft202012Validator(registry.expanded(schema_id),format_checker=FormatChecker())


class QAResultRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.b=build_runtime.BuildExecutionResultRuntimeTests();self.b.setUp()
        self.b.start();self.b.complete()
        self.store=self.b.store
        self.store.events.clear();self.store.outbox.clear();self.store.idempotency.clear()
        self._number=1080
        self.executor=Executor(CommandValidator(ROOT/"contracts/schemas/v1"),GuardPipeline(),self.store,clock=lambda:self.now,ids=self.next_id)

    @property
    def tenant(self):return self.b.tenant
    @property
    def engagement_id(self):return self.b.engagement_id
    @property
    def now(self):return self.b.now
    @property
    def package_payload(self):return self.b.package_payload
    def next_id(self):
        self._number+=1
        return f"d5d29000-0000-4000-8000-{self._number:012d}"

    def context(self,*,caller_type="INTERNAL_SERVICE",tenant=None,principal=None):
        principal=principal or ("human.qa-reviewer" if caller_type=="HUMAN" else "service.phase5d-qa")
        human=caller_type=="HUMAN"
        return TrustedExecutionContext(
            True,principal,caller_type,tenant or self.tenant,None,
            frozenset({QA_RESULT_CAPABILITIES["RecordQAResult"]}),frozenset(),"TEST",
            "avuhz-command-api","STRONG",False,"2030-01-15T14:00:00Z",
            "2030-03-15T16:00:00Z",principal if human else None,
            "organization.qa" if human else None,None,
        )

    def raw(self,payload,*,qa_id=None,key=None,command_id=None,tenant=None,engagement=None,caller_type="INTERNAL_SERVICE",expected=None):
        value={
            "command_id":command_id or self.next_id(),"command_type":"RecordQAResult",
            "command_schema_version":1,"tenant_id":tenant or self.tenant,
            "engagement_id":engagement or self.engagement_id,"subject_type":"QA_RESULT",
            "subject_id":qa_id or payload["qa_result_id"],"requested_by":"trusted.phase5d",
            "caller_type":caller_type,
            "caller_identity":{"subject":"trusted.phase5d","audience":"avuhz-command-api","caller_type":caller_type,"tenant_ids":[tenant or self.tenant],"capabilities":[QA_RESULT_CAPABILITIES["RecordQAResult"]],"environment":"TEST","authentication_strength":"STRONG","step_up_performed":False,"authenticated_at":"2030-01-15T14:00:00Z","expires_at":"2030-03-15T16:00:00Z"},
            "correlation_id":"d5d20000-0000-4000-8000-000000000090",
            "idempotency_key":key or f"phase5d-qa-record-{self._number}",
            "requested_at":self.now,"environment":"TEST",
            "payload_schema":"urn:avuhz:schema:contracts:commands:record-qa-result-payload:v1",
            "payload_version":1,"payload":copy.deepcopy(payload),
        }
        if expected is not None:value["expected_record_version"]=expected
        return value

    def payload(self,*,qa_id=QA_ID,attempt=1,build_id=build_runtime.RESULT_ID,results=None,caller_type="INTERNAL_SERVICE"):
        build=getattr(self,"source_builds",{}).get(build_id)
        if build is None:
            build=UnitOfWork(self.store).build_execution_results.get(self.tenant,build_id)
        test=build["test_result_references"][0]
        criterion_results=results or [
            {"criterion_id":criterion["criterion_id"],"criterion_package_version":self.package_payload["package_version"],"result":"PASS","evidence_references":[{"evidence_reference_id":test["test_result_reference_id"],"evidence_class":"TEST_RESULT","evidence_digest":test["result_digest"]}],"summary":"Exact bounded evidence satisfies this criterion."}
            for criterion in self.package_payload["acceptance_criteria"]
        ]
        value={
            "qa_result_id":qa_id,"qa_attempt":attempt,
            "build_execution_reference":{"reference_type":"BUILD_EXECUTION_RESULT","reference_id":build_id,"reference_version":build["record_version"]},
            "build_execution_digest":build["execution_digest"],
            "codex_build_package_reference":copy.deepcopy(build["codex_build_package_reference"]),
            "package_digest":build["package_digest"],"criterion_results":criterion_results,
            "overall_status":derive_overall_status(criterion_results),"qa_digest":"sha256:"+"0"*64,
        }
        if attempt>1:value["supersedes_qa_result_reference"]={"reference_type":"QA_RESULT","reference_id":QA_ID,"reference_version":1}
        principal="human.qa-reviewer" if caller_type=="HUMAN" else "service.phase5d-qa"
        attribution={"principal_reference":principal,"caller_type":caller_type,"recorded_by":principal}
        value["qa_digest"]=qa_result_digest(self.tenant,self.engagement_id,value,attribution)
        return value

    def execute(self,raw,*,caller_type="INTERNAL_SERVICE",tenant=None,principal=None):
        return self.executor.execute(raw,self.context(caller_type=caller_type,tenant=tenant,principal=principal))

    def record(self,payload=None,**kwargs):
        payload=payload or self.payload(caller_type=kwargs.get("caller_type","INTERNAL_SERVICE"))
        raw=self.raw(payload,**kwargs);result=self.execute(raw,caller_type=raw["caller_type"])
        self.assertEqual(result["result"],"ACCEPTED",result);return raw

    def test_exact_criterion_truth_event_outbox_and_non_authority(self):
        build_view=BuildExecutionResultReadService(UnitOfWork(self.store)).status(self.tenant,build_runtime.RESULT_ID,self.now)
        self.assertFalse(build_view["qa_passed"])
        self.record()
        uow=UnitOfWork(self.store);record=uow.qa_results.get(self.tenant,QA_ID)
        view=QAResultReadService(uow).status(self.tenant,QA_ID,self.now)
        self.assertEqual((record["overall_status"],record["record_version"]),("PASSED",1))
        self.assertEqual(len(record["criterion_results"]),len(self.package_payload["acceptance_criteria"]))
        self.assertEqual(list(schema_validator("urn:avuhz:schema:contracts:domain:qa-result:v1").iter_errors(record)),[])
        self.assertEqual(list(schema_validator("urn:avuhz:schema:contracts:read-models:qa-result-status-view:v1").iter_errors(view)),[])
        self.assertEqual((view["qa_passed"],view["client_accepted"],view["deployment_authorized"]),(True,False,False))
        self.assertEqual([e["event_type"] for e in self.store.events],["qa_result.recorded"])
        self.assertEqual(self.store.events[0]["authoritative_subject_reference"]["reference_type"],"QA_RESULT")
        self.assertEqual([o["status"] for o in self.store.outbox],["PENDING"])
        self.assertTrue(schema_validator("urn:avuhz:schema:contracts:orchestration:lifecycle-event:v1").is_valid(self.store.events[0]))

    def test_failure_blocked_rebuild_retest_and_history_are_immutable(self):
        failed=self.payload();failed["criterion_results"][0]["result"]="FAIL";failed["overall_status"]="FAILED"
        failed["qa_digest"]=qa_result_digest(self.tenant,self.engagement_id,failed,{"principal_reference":"service.phase5d-qa","caller_type":"INTERNAL_SERVICE","recorded_by":"service.phase5d-qa"})
        self.record(failed)
        correction=self.b.start_payload(result_id=build_runtime.CORRECTION_ID,attempt=2)
        self.b.executor=self.executor;self.b.start(correction,result_id=build_runtime.CORRECTION_ID)
        self.b.complete(self.b.completion_payload(build_runtime.CORRECTION_ID,2),result_id=build_runtime.CORRECTION_ID)
        blocked=self.payload(qa_id=RETEST_ID,attempt=2,build_id=build_runtime.CORRECTION_ID)
        blocked["criterion_results"][0]["result"]="BLOCKED";blocked["overall_status"]="BLOCKED"
        blocked["qa_digest"]=qa_result_digest(self.tenant,self.engagement_id,blocked,{"principal_reference":"service.phase5d-qa","caller_type":"INTERNAL_SERVICE","recorded_by":"service.phase5d-qa"})
        self.record(blocked,qa_id=RETEST_ID)
        history=UnitOfWork(self.store).qa_results.list_by_package(self.tenant,self.package_payload["codex_build_package_id"],1)
        self.assertEqual([(x["qa_attempt"],x["overall_status"]) for x in history],[(1,"FAILED"),(2,"BLOCKED")])
        self.assertEqual(history[1]["supersedes_qa_result_reference"]["reference_id"],QA_ID)
        self.assertNotEqual(history[0]["build_execution_digest"],history[1]["build_execution_digest"])
        old_view=QAResultReadService(UnitOfWork(self.store)).status(self.tenant,QA_ID,self.now)
        self.assertIn("QA_SUPERSEDED",old_view["reasons"]);self.assertFalse(old_view["qa_passed"])

    def test_source_criteria_evidence_and_staleness_negatives_have_no_side_effects(self):
        cases=[]
        for label,mutation in (
            ("wrong build digest",lambda p:p.update(build_execution_digest="sha256:"+"9"*64)),
            ("wrong build version",lambda p:p["build_execution_reference"].update(reference_version=1)),
            ("wrong package digest",lambda p:p.update(package_digest="sha256:"+"9"*64)),
            ("wrong package version",lambda p:p["codex_build_package_reference"].update(reference_version=2)),
            ("missing criterion",lambda p:p["criterion_results"].pop()),
            ("criterion not in package",lambda p:p["criterion_results"][0].update(criterion_id="criterion.not-in-package")),
            ("stale criterion version",lambda p:p["criterion_results"][0].update(criterion_package_version=2)),
            ("invented test evidence",lambda p:p["criterion_results"][0]["evidence_references"][0].update(evidence_reference_id="test.invented")),
            ("fake overall pass",lambda p:p.update(overall_status="FAILED")),
        ):
            payload=self.payload(qa_id=self.next_id());mutation(payload)
            if label not in {"missing criterion","fake overall pass"}:
                payload["qa_digest"]=qa_result_digest(self.tenant,self.engagement_id,payload,{"principal_reference":"service.phase5d-qa","caller_type":"INTERNAL_SERVICE","recorded_by":"service.phase5d-qa"})
            cases.append((label,self.raw(payload)))
        schema_failures={"fake overall pass"}
        for label,raw in cases:
            before=(len(self.store.qa_results),len(self.store.events),len(self.store.outbox),len(self.store.idempotency))
            result=self.execute(raw)
            self.assertEqual(result["result"],"VALIDATION_FAILED" if label in schema_failures else "REJECTED",label)
            self.assertEqual((len(self.store.qa_results),len(self.store.events),len(self.store.outbox),len(self.store.idempotency)),before,label)
        build_key=(self.tenant,build_runtime.RESULT_ID);self.store.build_execution_results[build_key]["status"]="FAILED"
        self.assertEqual(self.execute(self.raw(self.payload(qa_id=self.next_id()),key="phase5d-qa-failed-build"))["result"],"REJECTED")
        self.store.build_execution_results[build_key]["status"]="SUCCEEDED"
        package_key=(self.tenant,self.package_payload["codex_build_package_id"],1);self.store.codex_build_packages[package_key]["state"]="SUPERSEDED"
        self.assertEqual(self.execute(self.raw(self.payload(qa_id=self.next_id()),key="phase5d-qa-stale-package"))["result"],"REJECTED")
        self.store.codex_build_packages[package_key]["state"]="RELEASED"
        foreign=self.payload(qa_id=self.next_id());raw=self.raw(foreign,tenant=FOREIGN_TENANT,key="phase5d-qa-cross-tenant")
        self.assertEqual(self.execute(raw,tenant=FOREIGN_TENANT)["result"],"REJECTED")
        correction=self.b.start_payload(result_id=build_runtime.CORRECTION_ID,attempt=2)
        self.b.executor=self.executor;self.b.start(correction,result_id=build_runtime.CORRECTION_ID)
        self.assertEqual(self.execute(self.raw(self.payload(qa_id=self.next_id()),key="phase5d-qa-stale-build"))["result"],"REJECTED")
        incomplete=self.payload(qa_id=self.next_id())
        incomplete["build_execution_reference"]={"reference_type":"BUILD_EXECUTION_RESULT","reference_id":build_runtime.CORRECTION_ID,"reference_version":1}
        incomplete["build_execution_digest"]="sha256:"+"8"*64
        incomplete["qa_digest"]=qa_result_digest(self.tenant,self.engagement_id,incomplete,{"principal_reference":"service.phase5d-qa","caller_type":"INTERNAL_SERVICE","recorded_by":"service.phase5d-qa"})
        self.assertEqual(self.execute(self.raw(incomplete,key="phase5d-qa-incomplete-build"))["result"],"REJECTED")

    def test_workload_human_spoof_and_authority_claims_rejected(self):
        human=self.payload(caller_type="HUMAN");self.record(human,caller_type="HUMAN")
        fresh=QAResultRuntimeTests();fresh.setUp()
        for field,value in (("qa_passed",True),("overall_success",True),("approved",True),("client_accepted",True),("deployment_allowed",True),("production_authorized",True),("role","CLIENT_ACCEPTANCE_AUTHORITY")):
            bad=fresh.payload();bad[field]=value
            result=fresh.execute(fresh.raw(bad,key=f"phase5d-qa-forbidden-{field}"))
            self.assertEqual(result["result"],"VALIDATION_FAILED",field)
        bad=fresh.payload();bad["criterion_results"][0]["summary"]="Deployment authorized for production."
        bad["qa_digest"]=qa_result_digest(fresh.tenant,fresh.engagement_id,bad,{"principal_reference":"service.phase5d-qa","caller_type":"INTERNAL_SERVICE","recorded_by":"service.phase5d-qa"})
        self.assertEqual(fresh.execute(fresh.raw(bad,key="phase5d-qa-authority-text"))["result"],"REJECTED")
        self.assertEqual(len(fresh.store.qa_results),0)

    def test_idempotency_duplicate_identity_stale_retest_and_atomic_rollback(self):
        raw=self.record();self.assertEqual(self.execute(copy.deepcopy(raw))["result"],"DUPLICATE")
        changed=copy.deepcopy(raw);changed["payload"]["criterion_results"][0]["summary"]="Semantically changed bounded evidence summary."
        self.assertEqual(self.execute(changed)["result"],"CONFLICT")
        duplicate=self.payload(qa_id=QA_ID);self.assertEqual(self.execute(self.raw(duplicate,key="phase5d-qa-duplicate-identity"))["result"],"REJECTED")
        concurrent=self.payload(qa_id=self.next_id());self.assertEqual(self.execute(self.raw(concurrent,key="phase5d-qa-duplicate-attempt"))["result"],"REJECTED")
        stale=self.payload(qa_id=RETEST_ID,attempt=2);stale["supersedes_qa_result_reference"]["reference_version"]=2
        stale["qa_digest"]=qa_result_digest(self.tenant,self.engagement_id,stale,{"principal_reference":"service.phase5d-qa","caller_type":"INTERNAL_SERVICE","recorded_by":"service.phase5d-qa"})
        self.assertEqual(self.execute(self.raw(stale,qa_id=RETEST_ID,key="phase5d-qa-stale-predecessor"))["result"],"REJECTED")
        for stage in ("AUTHORITATIVE_WRITE","LIFECYCLE_EVENT_APPEND","OUTBOX_APPEND","IDEMPOTENCY_COMPLETE","COMMIT"):
            fresh=QAResultRuntimeTests();fresh.setUp();fresh.store.fail_stage=stage;before=copy.deepcopy(fresh.store)
            result=fresh.execute(fresh.raw(fresh.payload(),key=f"phase5d-qa-fail-{stage.lower()}"))
            self.assertEqual(result["result"],"REJECTED",stage);fresh.store.fail_stage=None
            self.assertEqual(fresh.store.qa_results,before.qa_results,stage)
            self.assertEqual(fresh.store.events,before.events,stage);self.assertEqual(fresh.store.outbox,before.outbox,stage);self.assertEqual(fresh.store.idempotency,before.idempotency,stage)


if __name__=="__main__":unittest.main()
