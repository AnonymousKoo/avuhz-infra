"""No-network regression for non-authoritative System #001 n8n child candidate."""
from __future__ import annotations
import json
from pathlib import Path
import shutil
import subprocess
import unittest

FILE = Path(__file__).resolve().parents[2] / "contracts/templates/n8n/avuhz-system-001-revenue-intake-inactive-v1.json"

class RevenueWorkflowSourceTests(unittest.TestCase):
    def setUp(self):
        self.w = json.loads(FILE.read_text())

    def test_inactive_child_has_only_two_safe_nodes(self):
        self.assertIs(self.w["active"], False)
        self.assertEqual([n["type"] for n in self.w["nodes"]],[
            "n8n-nodes-base.executeWorkflowTrigger", "n8n-nodes-base.code"])
        self.assertEqual(self.w["nodes"][0]["parameters"]["inputSource"],"passthrough")
        self.assertTrue(all("credentials" not in n for n in self.w["nodes"]))
        self.assertNotIn("pinData",self.w)
        self.assertNotIn("staticData",self.w)
        self.assertEqual(self.w["settings"]["saveDataSuccessExecution"],"none")
        self.assertEqual(self.w["settings"]["saveDataErrorExecution"],"none")
        self.assertIs(self.w["settings"]["saveManualExecutions"],False)

    def test_no_outbound_pii_or_authority(self):
        s=self.w["nodes"][1]["parameters"]["jsCode"].lower()
        for marker in ("fetch(", "httprequest","axios","require(", "console.log",
                      "process.env", "service_role","sendemail(", "sendsms(",
                      "insert into","https://"):
            with self.subTest(marker=marker):self.assertNotIn(marker,s)
        self.assertIn("revenue_event_rejected",s)
        self.assertIn("owner_lookup_required",s)
        self.assertIn("acquisition.intake.received",s)

    def test_synthetic_js_decision_without_side_effects(self):
        if not shutil.which("node"):
            self.skipTest("Node unavailable; static tests still protect source")
        event={
          "event_id":"f1000000-0000-4000-8000-000000000001",
          "event_type":"acquisition.intake.received",
          "tenant_id":"f1000000-0000-4000-8000-000000000002",
          "correlation_id":"f1000000-0000-4000-8000-000000000003",
          "occurred_at":"2030-01-01T00:00:00Z",
          "authoritative_subject_reference":{"reference_type":"ACQUISITION_INTAKE",
           "reference_id":"f1000000-0000-4000-8000-000000000004"},
          "authoritative_subject_version":1,
          "delivery_idempotency_key":"synthetic-delivery-key-001",
        }
        cases=[[event],
           [{**event,"contact_email":"synthetic@example.invalid"}],
           [{**event,"event_type":"billing.payment.confirmed"}],
           [{**event,"authoritative_subject_version":2}],
           [{**event,"tenant_id":"bogus"}],
           [{**event,"occurred_at":"2030-02-30T00:00:00Z"}],
           [{**event,"authoritative_subject_reference":{"reference_type":"ENGAGEMENT","reference_id":event["authoritative_subject_reference"]["reference_id"]}}],
           [],[event,event]]
        runner="""
const vm=require('node:vm');
const obj=JSON.parse(process.argv[1]);
for (const sample of obj.cases) {
 const ctx={$input:{all:()=>sample.map(j=>({json:j}))}};
 const out=vm.runInNewContext('(function(){'+String.fromCharCode(10)+obj.code+String.fromCharCode(10)+'})()',ctx,{timeout:1000});
 process.stdout.write(JSON.stringify(out)+'\\n');
}"""
        done=subprocess.run(["node","-e",runner,json.dumps({"code":self.w["nodes"][1]["parameters"]["jsCode"],"cases":cases})],
                             capture_output=True,text=True,check=True,timeout=10)
        result=[json.loads(line)[0]["json"] for line in done.stdout.splitlines()]
        self.assertEqual(len(result),len(cases))
        self.assertEqual(result[0]["code"],"OWNER_LOOKUP_REQUIRED")
        self.assertIs(result[0]["requires_authoritative_lookup"],True)
        self.assertEqual(result[0]["event_id"],event["event_id"])
        self.assertNotIn("tenant_id",result[0])
        for rejected in result[1:]:
            self.assertEqual(rejected,{"code":"REVENUE_EVENT_REJECTED","requires_authoritative_lookup":False})
        self.assertNotIn("synthetic@example.invalid",done.stdout)

if __name__=="__main__":unittest.main()
