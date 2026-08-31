#!/usr/bin/env python3
import json,sys
from pathlib import Path
from jsonschema import Draft202012Validator
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/"src"))
from avuhz_runtime.command_registry import COMMANDS
def main():
 paths=sorted((ROOT/"contracts/schemas/v1").rglob("*.schema.json"));schemas=[]
 for path in paths: value=json.load(open(path));Draft202012Validator.check_schema(value);schemas.append(value)
 if len({x["$id"] for x in schemas})!=len(schemas):raise SystemExit("command-protocol validation: FAIL: duplicate schema ID")
 envelope=next(x for x in schemas if x["$id"].endswith("command-envelope:v1"));idem=next(x for x in schemas if x["$id"].endswith("idempotency-record:v1"))
 commands=envelope["$defs"]["commandType"]["enum"]
 if commands!=idem["properties"]["command_type"]["enum"]:raise SystemExit("command-protocol validation: FAIL: idempotency parity")
 if not set(COMMANDS)<=set(commands):raise SystemExit("command-protocol validation: FAIL: active command missing")
 text=json.dumps(envelope).lower()
 if any(word in text for word in ("sekinfra","oia_","oiaassessment")):raise SystemExit("command-protocol validation: FAIL: company/domain dependency")
 print(f"command-protocol validation: PASS ({len(COMMANDS)} active, {len(commands)} contracted commands)")
if __name__=="__main__":main()
