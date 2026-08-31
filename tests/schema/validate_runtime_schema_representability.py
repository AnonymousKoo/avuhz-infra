#!/usr/bin/env python3
import json,sys
from pathlib import Path
from jsonschema import Draft202012Validator,FormatChecker
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/"src"))
from avuhz_runtime.schema_registry import SchemaRegistry
from avuhz_runtime.in_memory import MemoryStore,UnitOfWork
IDS={"implementation_handoff":"urn:avuhz:public-contract:implementation-handoff:v1","implementation_brief":"urn:avuhz:schema:contracts:domain:implementation-brief:v1","implementation_authorization":"urn:avuhz:schema:contracts:domain:implementation-authorization:v1","codex_build_package":"urn:avuhz:schema:contracts:domain:codex-build-package:v1"}
def main():
 registry=SchemaRegistry(ROOT/"contracts/schemas/v1");fixture=json.load(open(ROOT/"contracts/fixtures/v1/phase5d-implementation-package.cases.json"))["positive"];checker=FormatChecker();checker.checks("date-time")(lambda x:isinstance(x,str) and x.endswith("Z"))
 for name,schema_id in IDS.items():
  errors=list(Draft202012Validator(registry.expanded(schema_id),format_checker=checker).iter_errors(fixture[name]))
  if errors:raise SystemExit(f"runtime-schema representability: FAIL: {name}")
 uow=UnitOfWork(MemoryStore());required=("implementation_handoffs","implementation_briefs","implementation_authorizations","codex_build_packages","build_execution_results","qa_results","client_acceptances","human_approvals","idempotency","lifecycle_events","outbox")
 if not all(hasattr(uow,name) for name in required):raise SystemExit("runtime-schema representability: FAIL: UoW surface")
 json.dumps(fixture,sort_keys=True)
 print(f"runtime-schema representability: PASS ({len(IDS)} exact handoff/Phase 5D records)")
if __name__=="__main__":main()
