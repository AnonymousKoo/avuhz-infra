#!/usr/bin/env python3
import json,sys
from pathlib import Path
from jsonschema import Draft202012Validator
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/"src"))
from avuhz_runtime.schema_registry import SchemaRegistry
def main():
 registry=SchemaRegistry(ROOT/"contracts/schemas/v1")
 for schema_id in registry.schema_ids:Draft202012Validator.check_schema(registry.resolve(schema_id));registry.expanded(schema_id)
 lifecycle=registry.resolve("urn:avuhz:schema:contracts:orchestration:lifecycle-event:v1")["properties"]["event_type"]["enum"]
 required={"engagement.handoff.accepted","engagement.opened","implementation_brief.approved","implementation_authorization.activated","codex_build_package.released","build_execution.completed","qa_result.recorded"}
 if not required<=set(lifecycle):raise SystemExit("orchestration-foundation validation: FAIL: lifecycle vocabulary")
 if any("oia" in value.lower() or "sekinfra" in value.lower() for value in lifecycle):raise SystemExit("orchestration-foundation validation: FAIL: domain event")
 print(f"orchestration-foundation validation: PASS ({len(registry.schema_ids)} local schemas, {len(lifecycle)} events)")
if __name__=="__main__":main()
