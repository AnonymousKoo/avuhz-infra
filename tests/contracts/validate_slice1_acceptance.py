#!/usr/bin/env python3
import copy,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path[:0]=[str(ROOT/"src"),str(ROOT/"tests/contracts")]
from avuhz_runtime.guards import GuardPipeline,TrustedExecutionContext,COMMAND_CAPABILITIES
from avuhz_runtime.in_memory import Executor,MemoryStore
from avuhz_runtime.validation import CommandValidator
from validate_command_payloads import envelope,payloads,handoff
T="a3000000-0000-4000-8000-000000000002"
def context(command,tenant=T):return TrustedExecutionContext(True,"fictional-service","INTERNAL_SERVICE",tenant,None,frozenset({COMMAND_CAPABILITIES[command]}),frozenset(),"TEST","avuhz-command-api","STRONG",False,"2030-01-15T15:00:00Z","2030-01-15T16:00:00Z")
def main():
 store=MemoryStore();source=handoff();store.handoffs[source["handoff_id"]]=source;executor=Executor(CommandValidator(ROOT/"contracts/schemas/v1"),GuardPipeline(),store,ids=iter(["c5000000-0000-4000-8000-000000000001","c5000000-0000-4000-8000-000000000002"]).__next__)
 for command in ("AcceptAcquisitionHandoff","OpenEngagement"):
  result=executor.execute(envelope(command,copy.deepcopy(payloads()[command])),context(command))
  if result["result"]!="ACCEPTED":raise SystemExit(f"active-foundation acceptance: FAIL: {command}")
 if len(store.events)!=2 or len(store.outbox)!=2 or any(x["status"]!="PENDING" for x in store.outbox):raise SystemExit("active-foundation acceptance: FAIL: atomic lifecycle")
 cross=envelope("OpenEngagement",copy.deepcopy(payloads()["OpenEngagement"]));cross["tenant_id"]="a3000000-0000-4000-8000-000000000099"
 if executor.execute(cross,context("OpenEngagement"))["result"]!="REJECTED":raise SystemExit("active-foundation acceptance: FAIL: tenant isolation")
 print("active-foundation acceptance: PASS (handoff -> engagement, events/outbox, tenant denial)")
if __name__=="__main__":main()
