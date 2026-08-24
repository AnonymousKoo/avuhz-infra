#!/usr/bin/env python3
"""Validate AssessmentAccessGrant's closed authority boundary."""
import copy, json, sys
from pathlib import Path
from jsonschema import Draft202012Validator, FormatChecker
ROOT=Path(__file__).resolve().parents[2]; SCHEMAS=ROOT/"contracts/schemas/v1"; SID="urn:avuhz:schema:contracts:domain:assessment-access-grant:v1"; FIX=ROOT/"contracts/fixtures/v1/assessment-access-grant.cases.json"
def load(p):
 with p.open(encoding="utf-8") as h:return json.load(h)
def fail(m):print(f"assessment-access-grant validation: FAIL: {m}",file=sys.stderr);raise SystemExit(1)
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
 for key,x in c.items():
  t=v;ps=key.split(".")
  for p in ps[:-1]:t=t[p]
  t[ps[-1]]=x
 return v
def semantic(v):return v.get("status")!="ACTIVE" or v["active_from"]==v["verified_at"]
def main():
 ps=sorted(SCHEMAS.rglob("*.schema.json"));ss={load(p)["$id"]:load(p) for p in ps}
 for s in ss.values():Draft202012Validator.check_schema(s)
 s=ss[SID];p=s["properties"]
 if p["status"]["enum"]!=["APPROVED","ACTIVE","EXPIRED","REVOKED","CLOSED"]:fail("status vocabulary drifted")
 actions=s["$defs"]["permittedDiagnosticAction"]["enum"]
 if len(actions)!=10 or set(actions)&{"CREATE","MODIFY","DELETE","DEPLOY","RESTART","ROTATE","GRANT","REVOKE","CHANGE_CONFIGURATION","PRODUCTION_CHANGE"}:fail("action boundary widened")
 forbidden={"credential_reference","credentials","password","api_key","provider_data","metadata","access_payload","ongoing_access","deployment_authority"}
 if forbidden&set(p):fail("authority or credential boundary leaked")
 val=Draft202012Validator(expand(s,s,ss),format_checker=FormatChecker());fx=load(FIX);base=fx["base"]
 for c in fx["positive"]:
  v=mutate(base,c.get("mutate",{}))
  if list(val.iter_errors(v)) or not semantic(v):fail(f"positive failed: {c['name']}")
 for c in fx["negative"]:
  v=mutate(base,c.get("mutate",{}))
  if "remove" in c:v.pop(c["remove"])
  if c.get("semantic_failure"):
   if semantic(v):fail(f"semantic negative passed: {c['name']}")
  elif not list(val.iter_errors(v)):fail(f"negative passed: {c['name']}")
 print(f"assessment-access-grant validation: PASS ({len(fx['positive'])} positive, {len(fx['negative'])} negative, no credential or authority leakage)")
if __name__=="__main__":main()
