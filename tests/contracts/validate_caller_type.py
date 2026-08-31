#!/usr/bin/env python3
import json,sys
from pathlib import Path
from jsonschema import Draft202012Validator
ROOT=Path(__file__).resolve().parents[2]
def main():
 schema=json.load(open(ROOT/"contracts/schemas/v1/identity/caller-type.schema.json"));fixtures=json.load(open(ROOT/"contracts/fixtures/v1/caller-type.cases.json"));expected=["HUMAN","WORKLOAD","INTERNAL_SERVICE","PROVIDER_ADAPTER","SCHEDULED_AUTOMATION","SECURITY_AUTOMATION"]
 Draft202012Validator.check_schema(schema)
 if schema["enum"]!=expected:raise SystemExit("caller-type validation: FAIL: vocabulary drift")
 v=Draft202012Validator(schema)
 if any(list(v.iter_errors(x["value"])) for x in fixtures["positive"]):raise SystemExit("caller-type validation: FAIL: positive")
 if any(not list(v.iter_errors(x["value"])) for x in fixtures["negative"]):raise SystemExit("caller-type validation: FAIL: negative")
 print(f"caller-type validation: PASS ({len(expected)} provider-neutral types)")
if __name__=="__main__":main()
