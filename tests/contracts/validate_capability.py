#!/usr/bin/env python3
import json
from pathlib import Path
from jsonschema import Draft202012Validator
ROOT=Path(__file__).resolve().parents[2]
def main():
 schema=json.load(open(ROOT/"contracts/schemas/v1/identity/capability.schema.json"));fixtures=json.load(open(ROOT/"contracts/fixtures/v1/capability.cases.json"));Draft202012Validator.check_schema(schema);v=Draft202012Validator(schema)
 if any(list(v.iter_errors(x["value"])) for x in fixtures["positive"]):raise SystemExit("capability validation: FAIL: positive")
 if any(not list(v.iter_errors(x["value"])) for x in fixtures["negative"]):raise SystemExit("capability validation: FAIL: negative")
 forbidden=("company","assessment","finding","conversion","payment")
 if any(any(word in value.lower() for word in forbidden) for value in schema["enum"]):raise SystemExit("capability validation: FAIL: domain vocabulary")
 print(f"capability validation: PASS ({len(schema['enum'])} provider-neutral capabilities)")
if __name__=="__main__":main()
