"""LOCAL/TEST-only proof of System #001 receipt-gated n8n workflow source.

No live n8n instance, provider credentials, customer data, hosted service,
Supabase AUTH/DATA access, sender or business authority.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FILE = ROOT / "contracts/templates/n8n/avuhz-system-001-revenue-receipt-gated-inactive-v2.json"
SHARED = ROOT / "contracts/templates/n8n/avuhz-shared-local-receipt-bridge-child-inactive-v1.json"

EVENT = {
    "event_id": "f1000000-0000-4000-8000-000000000001",
    "event_type": "acquisition.intake.received",
    "tenant_id": "f1000000-0000-4000-8000-000000000002",
    "correlation_id": "f1000000-0000-4000-8000-000000000003",
    "occurred_at": "2030-01-01T00:00:00Z",
    "authoritative_subject_reference": {
        "reference_type": "ACQUISITION_INTAKE",
        "reference_id": "f1000000-0000-4000-8000-000000000004",
    },
    "authoritative_subject_version": 1,
    "delivery_idempotency_key": "synthetic-delivery-key-001",
}

# Execute the actual n8n Code contents in a CPU-limited, no-network VM.
# Only $input.all is exposed. Errors carry no input to stdout.
RUNNER = r"""
const vm=require('node:vm');
const fixture=JSON.parse(process.argv[1]);
for(const entry of fixture.cases) {
  const ctx={$input:{all:()=>entry.input.map(json=>({json}))}};
  try {
    const out=vm.runInNewContext(
      '(function(){'+String.fromCharCode(10)+fixture.code+String.fromCharCode(10)+'})()',
      ctx,{timeout:300});
    process.stdout.write(JSON.stringify({ok:true,data:out})+'\n');
  } catch(_error) {
    process.stdout.write(JSON.stringify({ok:false,error:'SAFE_DENIAL'})+'\n');
  }
}
"""


@unittest.skipUnless(shutil.which("node"), "Node required for full workflow certificate")
class RevenueIntakeV2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = json.loads(FILE.read_text())
        cls.shared = json.loads(SHARED.read_text())
        cls.nodes = cls.workflow["nodes"]

    @classmethod
    def js(cls, node, samples):
        command = [
            "node", "-e", RUNNER,
            json.dumps({"code": cls.nodes[node]["parameters"]["jsCode"],
                        "cases": [{"input": sample} for sample in samples]}),
        ]
        run = subprocess.run(command, capture_output=True, text=True, check=True, timeout=12)
        outputs = [json.loads(line) for line in run.stdout.splitlines()]
        assert len(outputs) == len(samples), (len(outputs), len(samples))
        return outputs

    def test_exact_five_node_sequential_receipt_gated_topology(self):
        wf = self.workflow
        self.assertIs(wf["active"], False)
        self.assertEqual(len(self.nodes), 5)
        self.assertEqual([n["type"] for n in self.nodes], [
            "n8n-nodes-base.executeWorkflowTrigger",
            "n8n-nodes-base.code",
            "n8n-nodes-base.httpRequest",
            "n8n-nodes-base.code",
            "n8n-nodes-base.code",
        ])
        self.assertEqual(self.nodes[0]["parameters"]["inputSource"], "passthrough")
        self.assertEqual(len({n["id"] for n in self.nodes}), len(self.nodes))
        self.assertEqual(len({n["name"] for n in self.nodes}), len(self.nodes))
        self.assertEqual(list(wf["connections"]), [n["name"] for n in self.nodes[:-1]])
        for before, after in zip(self.nodes, self.nodes[1:]):
            self.assertEqual(wf["connections"][before["name"]],
                             {"main": [[{"node": after["name"], "type": "main", "index": 0}]]})
        self.assertNotIn("pinData", wf)
        self.assertNotIn("staticData", wf)
        self.assertFalse(any("credentials" in node for node in self.nodes))
        self.assertEqual(wf["settings"], {
            "executionOrder": "v1",
            "saveDataErrorExecution": "none",
            "saveDataSuccessExecution": "none",
            "saveManualExecutions": False,
        })
        self.assertEqual(wf["tags"], [])

    def test_reuses_shared_validators_and_exact_receipt_gate_unchanged(self):
        for stage in (1, 3):
            self.assertEqual(self.nodes[stage]["parameters"]["jsCode"],
                             self.shared["nodes"][stage]["parameters"]["jsCode"])
        self.assertEqual(self.nodes[2]["parameters"], self.shared["nodes"][2]["parameters"])
        req = self.nodes[2]["parameters"]
        self.assertEqual(req["method"], "POST")
        self.assertEqual(req["url"],
                         "http://127.0.0.1:1/v1/avuhz/local-n8n-receipts")
        self.assertEqual(req["authentication"], "genericCredentialType")
        self.assertEqual(req["genericAuthType"], "httpHeaderAuth")
        self.assertFalse(req["options"]["redirect"]["redirect"]["followRedirects"])
        self.assertEqual(req["options"]["timeout"], 1000)
        self.assertTrue(req["options"]["response"]["response"]["neverError"])
        self.assertEqual(req["headerParameters"]["parameters"],
                         [{"name": "X-Avuhz-Delivery-Key",
                           "value": "={{$json.delivery_idempotency_key}}"}])

    def test_first_durable_receipt_and_duplicate_are_distinct_safe_paths(self):
        valid = self.js(1, [[EVENT]])[0]
        self.assertTrue(valid["ok"], valid)
        self.assertEqual(valid["data"], [{"json": EVENT}])

        receipts = self.js(3, [
            [{"statusCode": 202, "body": {"accepted": True, "duplicate": False}}],
            [{"statusCode": 202, "body": {"accepted": True, "duplicate": True}}],
        ])
        self.assertTrue(all(r["ok"] for r in receipts), receipts)
        self.assertEqual(receipts[0]["data"][0]["json"], {
            "code": "NEW_DURABLE_RECEIPT", "durable": True, "first_delivery": True})
        self.assertEqual(receipts[1]["data"][0]["json"], {
            "code": "DUPLICATE_RECEIPT_NO_EFFECT", "durable": True, "first_delivery": False})

        final = self.js(4, [[receipts[0]["data"][0]["json"]],
                            [receipts[1]["data"][0]["json"]]])
        self.assertTrue(final[0]["ok"])
        self.assertEqual(final[0]["data"], [{"json": {
            "code": "OWNER_LOOKUP_REQUIRED",
            "requires_authoritative_lookup": True,
            "work_item_committed": False,
            "followup_scheduled": False,
            "notification_sent": False,
        }}])
        self.assertEqual(final[1], {"ok": True, "data": []})
        output = json.dumps(final)
        for private in (EVENT["tenant_id"], EVENT["correlation_id"],
                        EVENT["authoritative_subject_reference"]["reference_id"]):
            self.assertNotIn(private, output)

    def test_event_shape_denied_for_contact_metadata_or_foreign_types(self):
        invalid_events = [
            {**EVENT, "contact_email": "synthetic@example.invalid"},
            {**EVENT, "phone": "555-111-2222"},
            {**EVENT, "event_type": "billing.payment.confirmed"},
            {**EVENT, "tenant_id": "not-a-uuid"},
            {**EVENT, "authoritative_subject_version": 2},
            {**EVENT, "occurred_at": "2030-02-30T00:00:00Z"},
            {**EVENT, "authoritative_subject_reference":
             {**EVENT["authoritative_subject_reference"], "reference_type": "ENGAGEMENT"}},
            {**EVENT, "delivery_idempotency_key": ""},
        ]
        results = self.js(1, [[sample] for sample in invalid_events] + [[], [EVENT, EVENT]])
        self.assertTrue(all(not r["ok"] for r in results), results)
        self.assertNotIn("synthetic@example.invalid", json.dumps(results))

    def test_receipt_not_confirmed_fail_closed(self):
        responses = [
            {"statusCode": 200, "body": {"accepted": True, "duplicate": False}},
            {"statusCode": 204, "body": {"accepted": True, "duplicate": False}},
            {"statusCode": 302, "body": {"accepted": True, "duplicate": False}},
            {"statusCode": 503, "body": {"error": "storage_unavailable"}},
            {"statusCode": 202, "body": {"accepted": True}},
            {"statusCode": 202, "body": {"accepted": True, "duplicate": "false"}},
            {"statusCode": 202, "body": {"accepted": True, "duplicate": False,
                                        "contact": "synthetic@example.invalid"}},
            {"statusCode": 202, "body": {"accepted": False, "duplicate": False}},
            {"statusCode": 202, "body": {"accepted": True, "duplicate": False},
             "extra": "not-authority"},
        ]
        outcomes = self.js(3, [[x] for x in responses] + [[]])
        # The shared response gate is intentionally strict about the body.
        # Full-response metadata may exist, but must not enter the next output.
        self.assertTrue(all(not r["ok"] for r in outcomes[:8]), outcomes)
        self.assertTrue(outcomes[8]["ok"])
        self.assertEqual(outcomes[8]["data"][0]["json"]["code"], "NEW_DURABLE_RECEIPT")
        self.assertFalse(outcomes[9]["ok"])
        self.assertNotIn("synthetic@example.invalid", json.dumps(outcomes))

    def test_no_forged_receipt_may_create_an_owner_lookup(self):
        cases = [
            [],
            [{"code": "NEW_DURABLE_RECEIPT", "durable": False, "first_delivery": True}],
            [{"code": "NEW_DURABLE_RECEIPT", "durable": True, "first_delivery": False}],
            [{"code": "DUPLICATE_RECEIPT_NO_EFFECT", "durable": True,
              "first_delivery": True}],
            [{"code": "NEW_DURABLE_RECEIPT", "durable": True,
              "first_delivery": True, "tenant_id": EVENT["tenant_id"]}],
            [{"code": "OWNER_LOOKUP_REQUIRED", "durable": True, "first_delivery": True}],
            [{"code": "NEW_DURABLE_RECEIPT", "durable": True, "first_delivery": True}] * 2,
        ]
        results = self.js(4, cases)
        self.assertTrue(all(not x["ok"] for x in results), results)

    def test_no_unapproved_side_effects_in_source(self):
        serialized = json.dumps(self.workflow).lower()
        assert "executecommand" not in serialized
        self.assertNotIn("n8n-nodes-base.webhook", serialized)
        self.assertNotIn("service_role", serialized)
        self.assertNotIn("smtp", serialized)
        self.assertNotIn("twilio", serialized)
        self.assertNotIn("sendemail", serialized)
        self.assertNotIn("sendsms", serialized)
        for node in self.nodes:
            if node["type"] != "n8n-nodes-base.code":
                continue
            code = node["parameters"]["jsCode"].lower()
            for marker in ("fetch(", "axios", "require(", "console.log",
                           "process.env", "insert into", "update public.", "secret"):
                with self.subTest(node=node["name"], marker=marker):
                    self.assertNotIn(marker, code)


if __name__ == "__main__":
    unittest.main()
