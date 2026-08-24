#!/usr/bin/env python3
"""Validate HumanApproval's AssessmentAccessGrant subject branch."""
import copy,json,sys
from pathlib import Path
from jsonschema import Draft202012Validator,FormatChecker
ROOT=Path(__file__).resolve().parents[2];SC=ROOT/"contracts/schemas/v1";SID="urn:avuhz:schema:contracts:domain:human-approval:v1";FIX=ROOT/"contracts/fixtures/v1/assessment-access-human-approval.cases.json";OLD=ROOT/"contracts/fixtures/v1/approval-diagnostic-scope.cases.json"
def load(p):
 with p.open(encoding="utf-8") as h:return json.load(h)
def fail(m):print(f"assessment-access-human-approval validation: FAIL: {m}",file=sys.stderr);raise SystemExit(1)
def resolve(r,d,ss):
 t,f=(d,r[1:]) if r.startswith("#") else (ss[r.partition("#")[0]],r.partition("#")[2])
 for p in ([] if not f else f[1:].split("/")):t=t[p]
 return t
def expand(v,d,ss):
 if isinstance(v,dict):
  if "$ref" in v:
   td=d if v["$ref"].startswith("#") else ss[v["$ref"].partition("#")[0]]
   return {**expand(copy.deepcopy(resolve(v["$ref"],d,ss)),td,ss),**{k:expand(x,d,ss) for k,x in v.items() if k!="$ref"}}
  return {k:expand(x,d,ss) for k,x in v.items()}
 if isinstance(v,list):return [expand(x,d,ss) for x in v]
 return v
def mutate(v,c):
 v=copy.deepcopy(v)
 for k,x in c.items():
  t=v;ps=k.split(".")
  for p in ps[:-1]:t=t[p]
  t[ps[-1]]=x
 return v
def remove(v,k):
 t=v;ps=k.split(".")
 for p in ps[:-1]:t=t[p]
 t.pop(ps[-1])
def semantic(v):return v["subject_type"]!="ASSESSMENT_ACCESS_PROPOSAL" or v["subject_id"]==v["assessment_access"]["assessment_access_proposal_id"]
def main():
 ss={load(p)["$id"]:load(p) for p in sorted(SC.rglob("*.schema.json"))};s=ss[SID]
 for x in ss.values():Draft202012Validator.check_schema(x)
 if s["properties"]["subject_type"]["enum"]!=["DIAGNOSTIC_SCOPE","ASSESSMENT_ACCESS_PROPOSAL"]:fail("closed subject vocabulary drifted")
 val=Draft202012Validator(expand(s,s,ss),format_checker=FormatChecker());old=load(OLD)["human_approval"]["positive"][:2]
 for c in old:
  if list(val.iter_errors(c["value"])) or not semantic(c["value"]):fail(f"scope compatibility failed: {c['name']}")
 fx=load(FIX);base=fx["base"]
 for c in fx["positive"]:
  v=mutate(base,c.get("mutate",{}))
  if list(val.iter_errors(v)) or not semantic(v):fail(f"positive failed: {c['name']}")
 for c in fx["negative"]:
  v=mutate(base,c.get("mutate",{}))
  if c.get("operation")=="remove":remove(v,c["field"])
  if c.get("operation")=="scope_with_assessment":v={**old[0]["value"],"assessment_access":copy.deepcopy(base["assessment_access"])}
  if c.get("semantic_failure"):
   if semantic(v):fail(f"semantic negative passed: {c['name']}")
  elif not list(val.iter_errors(v)):fail(f"negative passed: {c['name']}")
 print(f"assessment-access-human-approval validation: PASS ({len(old)+len(fx['positive'])} positive, {len(fx['negative'])} negative, scope compatibility preserved)")
if __name__=="__main__":main()
