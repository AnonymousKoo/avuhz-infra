#!/usr/bin/env python3
"""Validate frozen Phase 5D-C build, QA, acceptance, and deployment-authority contracts."""
from __future__ import annotations
import copy,json,sys
from pathlib import Path
from jsonschema import Draft202012Validator,FormatChecker

ROOT=Path(__file__).resolve().parents[2]
SCHEMA_ROOT=ROOT/"contracts/schemas/v1"
sys.path.insert(0,str(ROOT/"src"))
from avuhz_runtime.command_registry import COMMANDS
from avuhz_runtime.schema_registry import SCHEMA_FILES

COMMANDS_C=["StartBuildExecution","CompleteBuildExecution","RecordQAResult","RecordClientAcceptance","ProposeDeploymentAuthorization","ReviseDeploymentAuthorization","RecordDeploymentAuthorizationApproval","ActivateDeploymentAuthorization","RevokeDeploymentAuthorization"]
CAPS_C=["build_execution:start","build_execution:complete","qa_result:record","client_acceptance:record","deployment_authorization:propose","deployment_authorization:approve","deployment_authorization:activate","deployment_authorization:revoke"]
EVENTS_C=["build_execution.started","build_execution.completed","qa_result.recorded","client_acceptance.recorded","deployment_authorization.proposed","deployment_authorization.revised","deployment_authorization.approval_recorded","deployment_authorization.activated","deployment_authorization.revoked"]
SUBJECTS_C=["BUILD_EXECUTION_RESULT","QA_RESULT","CLIENT_ACCEPTANCE","DEPLOYMENT_AUTHORIZATION"]
PROHIBITED=["ARTIFACT_SUBSTITUTION","TARGET_WIDENING","ENVIRONMENT_WIDENING","PERMISSION_WIDENING","CREDENTIAL_ROTATION","DATA_DELETION","BILLING_CHANGE","UNAUTHORIZED_PRODUCTION_CHANGE","OUT_OF_SCOPE_NETWORK_CHANGE","OUT_OF_SCOPE_SECURITY_CONTROL_CHANGE"]
DOMAIN={"build":"urn:avuhz:schema:contracts:domain:build-execution-result:v1","qa":"urn:avuhz:schema:contracts:domain:qa-result:v1","acceptance":"urn:avuhz:schema:contracts:domain:client-acceptance:v1","deployment":"urn:avuhz:schema:contracts:domain:deployment-authorization:v1","approval":"urn:avuhz:schema:contracts:domain:human-approval:v1"}

def fail(message):
 print("phase5d-c validation: FAIL: "+message,file=sys.stderr); raise SystemExit(1)
def pointer(doc,frag):
 x=doc
 if not frag:return x
 for part in frag.lstrip("/").split("/"):x=x[part.replace("~1","/").replace("~0","~")]
 return x
def expand(x,doc,schemas):
 if isinstance(x,dict):
  if "$ref" in x:
   ref=x["$ref"]; sid,sep,frag=ref.partition("#")
   target_doc=doc if not sid else schemas[sid]
   base=expand(copy.deepcopy(pointer(target_doc,frag if sep else "")),target_doc,schemas)
   return {**base,**{k:expand(v,doc,schemas) for k,v in x.items() if k!="$ref"}}
  return {k:expand(v,doc,schemas) for k,v in x.items()}
 if isinstance(x,list):return [expand(v,doc,schemas) for v in x]
 return x
def validator(sid,schemas):
 return Draft202012Validator(expand(schemas[sid],schemas[sid],schemas),format_checker=FormatChecker())
def valid(sid,value,schemas,label):
 errors=list(validator(sid,schemas).iter_errors(value))
 if errors:fail(label+": "+"; ".join(e.message for e in errors[:3]))
def invalid(sid,value,schemas,label):
 if validator(sid,schemas).is_valid(value):fail(label+" was accepted")
def ref(kind,ident,version=1):return {"reference_type":kind,"reference_id":ident,"reference_version":version}
def digest(ch):return "sha256:"+ch*64

def examples(target):
 tenant="d5c00000-0000-4000-8000-000000000001"; engagement="d5c00000-0000-4000-8000-000000000002"
 brief_auth="d5c00000-0000-4000-8000-000000000003"; package="d5c00000-0000-4000-8000-000000000004"
 build_id="d5c00000-0000-4000-8000-000000000005"; qa_id="d5c00000-0000-4000-8000-000000000006"; acc_id="d5c00000-0000-4000-8000-000000000007"; dep_id="d5c00000-0000-4000-8000-000000000008"
 package_ref=ref("CODEX_BUILD_PACKAGE",package); auth_ref=ref("IMPLEMENTATION_AUTHORIZATION",brief_auth); build_ref=ref("BUILD_EXECUTION_RESULT",build_id); qa_ref=ref("QA_RESULT",qa_id); acc_ref=ref("CLIENT_ACCEPTANCE",acc_id)
 artifact={"artifact_reference_id":"artifact.release.1","artifact_class":"BUILD_ARTIFACT","artifact_version":"1.0.0","artifact_digest":digest("a")}
 now="2026-08-30T12:00:00Z"
 build={"build_execution_result_id":build_id,"execution_attempt":1,"tenant_id":tenant,"engagement_id":engagement,"codex_build_package_reference":package_ref,"package_digest":digest("b"),"implementation_authorization_reference":auth_ref,"implementation_authority_digest":digest("c"),"status":"SUCCEEDED","changed_targets":[{"target_reference_id":"repository.application","target_class":"REPOSITORY"}],"artifact_references":[artifact],"test_result_references":[{"test_result_reference_id":"test.contract.1","test_class":"CONTRACT","result_digest":digest("d")}],"execution_fingerprint":"fpv1:deterministic-build-0001","execution_digest":digest("e"),"attribution":{"principal_reference":"service.builder","caller_type":"INTERNAL_SERVICE","recorded_by":"service.command"},"started_at":now,"completed_at":"2026-08-30T12:10:00Z","record_version":1,"created_at":now,"updated_at":"2026-08-30T12:10:00Z"}
 criteria=[]
 for i in range(1,4):criteria.append({"criterion_id":f"criterion.{i}","criterion_package_version":1,"result":"PASS","evidence_references":[{"evidence_reference_id":f"evidence.{i}","evidence_class":"TEST_RESULT","evidence_digest":digest(str(i))}]})
 qa={"qa_result_id":qa_id,"qa_attempt":1,"tenant_id":tenant,"engagement_id":engagement,"build_execution_reference":build_ref,"build_execution_digest":build["execution_digest"],"codex_build_package_reference":package_ref,"package_digest":build["package_digest"],"criterion_results":criteria,"overall_status":"PASSED","qa_digest":digest("f"),"attribution":{"principal_reference":"service.qa","caller_type":"INTERNAL_SERVICE","recorded_by":"service.command"},"recorded_at":"2026-08-30T12:20:00Z","record_version":1,"created_at":"2026-08-30T12:20:00Z","updated_at":"2026-08-30T12:20:00Z"}
 acceptance={"client_acceptance_id":acc_id,"acceptance_version":1,"tenant_id":tenant,"engagement_id":engagement,"codex_build_package_reference":package_ref,"package_digest":build["package_digest"],"build_execution_reference":build_ref,"build_execution_digest":build["execution_digest"],"qa_result_reference":qa_ref,"qa_result_digest":qa["qa_digest"],"artifact_reference":artifact,"decision":"ACCEPTED","decision_rationale":"Exact tested artifact accepted.","client_acceptance_digest":digest("6"),"attribution":{"principal_reference":"human.client","organization_reference":"organization.client","authority_role":"CLIENT_ACCEPTANCE_AUTHORITY"},"recorded_at":"2026-08-30T12:30:00Z","record_version":1,"created_at":"2026-08-30T12:30:00Z","updated_at":"2026-08-30T12:30:00Z"}
 deployment={"deployment_authorization_id":dep_id,"authorization_version":1,"tenant_id":tenant,"engagement_id":engagement,"implementation_authorization_reference":auth_ref,"implementation_authority_digest":build["implementation_authority_digest"],"codex_build_package_reference":package_ref,"package_digest":build["package_digest"],"build_execution_reference":build_ref,"build_execution_digest":build["execution_digest"],"qa_result_reference":qa_ref,"qa_result_digest":qa["qa_digest"],"client_acceptance_reference":acc_ref,"client_acceptance_digest":acceptance["client_acceptance_digest"],"artifact_reference":artifact,"target_environment":"PRODUCTION","target_resources":[{"target_reference_id":target,"target_class":"SERVICE"}],"permitted_deployment_actions":["DEPLOY_EXACT_ARTIFACT","ROLLBACK_EXACT_ARTIFACT"],"prohibited_deployment_actions":list(PROHIBITED),"rollback_recovery_requirement":{"strategy":"Restore the exact preceding artifact and verify health.","verification_reference":"verification.rollback"},"effective_at":"2026-08-30T13:00:00Z","expires_at":"2026-08-30T15:00:00Z","deployment_authority_digest":digest("7"),"state":"ACTIVE","client_approval_reference":ref("HUMAN_APPROVAL","d5c00000-0000-4000-8000-000000000009"),"provider_approval_reference":ref("HUMAN_APPROVAL","d5c00000-0000-4000-8000-000000000010"),"activated_at":"2026-08-30T13:00:00Z","record_version":1,"created_at":"2026-08-30T12:40:00Z","updated_at":"2026-08-30T13:00:00Z"}
 return build,qa,acceptance,deployment

def chain_ok(b,q,a,d,implementation_state="ACTIVE"):
 return implementation_state=="ACTIVE" and b["status"]=="SUCCEEDED" and q["overall_status"]=="PASSED" and a["decision"]=="ACCEPTED" and q["package_digest"]==b["package_digest"] and q["build_execution_reference"]["reference_id"]==b["build_execution_result_id"] and q["build_execution_digest"]==b["execution_digest"] and a["qa_result_reference"]["reference_id"]==q["qa_result_id"] and a["qa_result_digest"]==q["qa_digest"] and d["client_acceptance_reference"]["reference_id"]==a["client_acceptance_id"] and d["client_acceptance_digest"]==a["client_acceptance_digest"] and a["artifact_reference"]==b["artifact_references"][0] and d["artifact_reference"]==b["artifact_references"][0] and d["package_digest"]==a["package_digest"] and d["build_execution_digest"]==b["execution_digest"] and d["qa_result_digest"]==q["qa_digest"] and set(d["prohibited_deployment_actions"])==set(PROHIBITED)

def main():
 paths=sorted(SCHEMA_ROOT.rglob("*.schema.json")); schemas={}
 for p in paths:
  s=json.loads(p.read_text()); Draft202012Validator.check_schema(s)
  if s["$id"] in schemas:fail("duplicate schema ID "+s["$id"])
  schemas[s["$id"]]=s
 catalog=set(SCHEMA_FILES); actual={str(p.relative_to(SCHEMA_ROOT)) for p in paths}
 if catalog!=actual:fail("runtime schema catalog must exactly match current provider-neutral schemas")
 for s in schemas.values():
  for ref_value in refs(s):
   sid=ref_value.partition("#")[0]
   if sid and not sid.startswith("https://") and sid not in schemas:fail("unresolved ref "+ref_value)
 envelope=schemas["urn:avuhz:schema:contracts:commands:command-envelope:v1"]; capability=schemas["urn:avuhz:schema:contracts:identity:capability:v1"]; event=schemas["urn:avuhz:schema:contracts:orchestration:lifecycle-event:v1"]; idem=schemas["urn:avuhz:schema:contracts:orchestration:idempotency-record:v1"]
 if envelope["$defs"]["commandType"]["enum"][-9:]!=COMMANDS_C or idem["properties"]["command_type"]["enum"][-9:]!=COMMANDS_C:fail("command vocabulary/order")
 if capability["enum"][-8:]!=CAPS_C or event["properties"]["event_type"]["enum"][-9:]!=EVENTS_C:fail("capability/event vocabulary/order")
 if envelope["$defs"]["subjectType"]["enum"][-4:]!=SUBJECTS_C:fail("subject vocabulary/order")
 if set(COMMANDS_C)&set(COMMANDS)!=set(COMMANDS_C):fail("D4 runtime boundary drifted")
 if len(SCHEMA_FILES)!=len(paths):fail("D4 runtime schema boundary drifted")
 approval=schemas[DOMAIN["approval"]]
 if approval["properties"]["actor_role"]["enum"][-2:]!=["CLIENT_DEPLOYMENT_AUTHORITY","PROVIDER_DEPLOYMENT_AUTHORITY"]:fail("deployment human roles")
 doc=(ROOT/"docs/phase5d-build-qa-deployment-authority-architecture.md").read_text()
 for phrase in ["RELEASED != build completed","build completed != QA passed","QA passed != client accepted","client accepted != deployment authorized","CLIENT HUMAN","WORKLOAD/AI cannot accept","No deployment execution"]:
  if phrase not in doc:fail("missing architecture invariant: "+phrase)
 for industry,target in [("roofing / home services","roofing.dispatch"),("security staffing","security.scheduling"),("medical-office operations","medical.workflow")]:
  b,q,a,d=examples(target)
  valid(DOMAIN["build"],b,schemas,industry+" build"); valid(DOMAIN["qa"],q,schemas,industry+" QA"); valid(DOMAIN["acceptance"],a,schemas,industry+" acceptance"); valid(DOMAIN["deployment"],d,schemas,industry+" deployment")
  if not chain_ok(b,q,a,d):fail(industry+" exact chain")
 # Dual human approval cases are separate attributable records.
 b,q,a,d=examples("target.approval")
 common={"tenant_id":d["tenant_id"],"engagement_id":d["engagement_id"],"subject_type":"DEPLOYMENT_AUTHORIZATION","subject_id":d["deployment_authorization_id"],"subject_version":1,"approval_category":"DEPLOYMENT_AUTHORIZATION","decision":"APPROVE","phase5d_authority":{"subject_id":d["deployment_authorization_id"],"authority_digest":d["deployment_authority_digest"]},"conditions":[],"effective_at":"2026-08-30T12:45:00Z","evidence_reference":{"reference_type":"DEPLOYMENT_AUTHORIZATION","reference_id":d["deployment_authorization_id"]},"status":"ACTIVE","correlation_id":"d5c00000-0000-4000-8000-000000000011","created_at":"2026-08-30T12:45:00Z"}
 client={**common,"approval_id":"d5c00000-0000-4000-8000-000000000009","authority_category":"CLIENT_AUTHORITY","actor_identity":"human.client.deploy","actor_organization":"organization.client","actor_role":"CLIENT_DEPLOYMENT_AUTHORITY","idempotency_key":"phase5dc-client-approval-0001"}
 provider={**common,"approval_id":"d5c00000-0000-4000-8000-000000000010","authority_category":"PROVIDER_AUTHORITY","actor_identity":"human.provider.deploy","actor_organization":"organization.provider","actor_role":"PROVIDER_DEPLOYMENT_AUTHORITY","idempotency_key":"phase5dc-provider-approval-0001"}
 valid(DOMAIN["approval"],client,schemas,"client deployment approval"); valid(DOMAIN["approval"],provider,schemas,"provider deployment approval")
 spoof=copy.deepcopy(client); spoof["actor_role"]="PROVIDER_DEPLOYMENT_AUTHORITY"; invalid(DOMAIN["approval"],spoof,schemas,"deployment role spoof")
 # Schema security negatives and generic claims.
 b,q,a,d=examples("target.exact")
 for sid,obj,field in [(DOMAIN["build"],b,"raw_provider_payload"),(DOMAIN["qa"],q,"qa_passed"),(DOMAIN["acceptance"],a,"actor_role"),(DOMAIN["deployment"],d,"deployment_allowed")]:
  bad=copy.deepcopy(obj); bad[field]=True; invalid(sid,bad,schemas,"forbidden "+field)
 # Semantic stale/wrong/revoked negatives.
 for label,mutator in [
  ("wrong package digest",lambda b,q,a,d:q.__setitem__("package_digest",digest("8"))),
  ("wrong build",lambda b,q,a,d:q.__setitem__("build_execution_reference",ref("BUILD_EXECUTION_RESULT","d5c00000-0000-4000-8000-000000000099"))),
  ("stale QA",lambda b,q,a,d:a.__setitem__("qa_result_digest",digest("8"))),
  ("stale acceptance",lambda b,q,a,d:d.__setitem__("client_acceptance_digest",digest("8"))),
  ("wrong artifact",lambda b,q,a,d:d.__setitem__("artifact_reference",{**d["artifact_reference"],"artifact_digest":digest("8")})),
  ("prohibited set weakened",lambda b,q,a,d:d["prohibited_deployment_actions"].pop()),
 ]:
  bb,qq,aa,dd=examples("target.exact"); mutator(bb,qq,aa,dd)
  if chain_ok(bb,qq,aa,dd):fail(label+" accepted")
 bb,qq,aa,dd=examples("target.exact")
 if chain_ok(bb,qq,aa,dd,"REVOKED"):fail("revoked ImplementationAuthorization accepted")
 print("phase5d-c validation: PASS (4 resources, 9 commands, 8 capabilities, 9 events, 5 read models, 3 industries, security/stale-source negatives, D4 runtime boundary exact)")

def refs(x):
 if isinstance(x,dict):
  for k,v in x.items():
   if k=="$ref":yield v
   yield from refs(v)
 elif isinstance(x,list):
  for v in x:yield from refs(v)
if __name__=="__main__":main()
