"""Source-only shared v2 n8n durable receiver, no workflow import or network.

The current installed local n8n receiver is inactive and the v1 source
returns 503 intentionally. This v2 is an unbound candidate, not activated
or permission for real customer traffic.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
SOURCE=ROOT/"contracts/templates/n8n/avuhz-shared-event-receiver-durable-inactive-v2.json"
ORIGINAL=ROOT/"contracts/templates/n8n/avuhz-shared-event-receiver-inactive-v1.json"
BRIDGE=ROOT/"contracts/templates/n8n/avuhz-shared-local-receipt-bridge-child-inactive-v1.json"

TENANT="a4730000-0000-4000-8000-000000000001"
EVENT="a4730000-0000-4000-8000-000000000041"
SUBJECT="a4730000-0000-4000-8000-000000000021"
KEY="outbox-delivery:"+EVENT


def envelope():
    return {
        "event_id":EVENT,
        "event_type":"acquisition.intake.received",
        "tenant_id":TENANT,
        "correlation_id":"a4730000-0000-4000-8000-000000000042",
        "occurred_at":"2030-01-15T16:00:00Z",
        "authoritative_subject_reference":{
            "reference_type":"ACQUISITION_INTAKE",
            "reference_id":SUBJECT,
        },
        "authoritative_subject_version":1,
        "delivery_idempotency_key":KEY,
    }


def node_output(code, items):
    """Evaluate only the extracted n8n Code-node text inside a sterile Node VM.

    No scripts or functions from untrusted network input are executed; the
    JS comes solely from this repository's reviewed source template.
    """
    request=json.dumps({"script":code,"items":items},separators=(",",":"))
    runner="""
const fs=require('node:fs');
const vm=require('node:vm');
const data=JSON.parse(fs.readFileSync(0,'utf8'));
const $input={all:()=>data.items};
try{
  const result=new vm.Script('(function($input){'+data.script+'})').runInNewContext({})($input);
  process.stdout.write(JSON.stringify({ok:true,value:result}));
}catch(e){
  process.stdout.write(JSON.stringify({ok:false,error:String(e.message)}));
}
"""
    out=subprocess.run(["node","-e",runner],input=request,
                       text=True,capture_output=True,timeout=4,check=True)
    return json.loads(out.stdout)


@unittest.skipUnless(shutil.which("node"),"Node runtime needed for n8n Code regression")
class SharedDurableN8nReceiverV2Tests(unittest.TestCase):
    def setUp(self):
        self.workflow=json.loads(SOURCE.read_text())
        self.nodes=self.workflow["nodes"]

    def test_source_inactive_and_no_credential_or_runtime_mutation_authority(self):
        self.assertFalse(self.workflow["active"])
        self.assertEqual(self.workflow["settings"]["saveDataSuccessExecution"],"none")
        self.assertEqual(self.workflow["settings"]["saveDataErrorExecution"],"none")
        self.assertFalse(self.workflow["settings"]["saveManualExecutions"])
        self.assertNotIn("credentials",self.workflow)
        self.assertNotIn("staticData",self.workflow)
        self.assertNotIn("pinData",self.workflow)
        self.assertNotIn("executeOnce",self.workflow)
        for n in self.nodes:
            self.assertNotIn("credentials",n)
            self.assertNotIn("continueOnFail",n)
            self.assertNotIn("alwaysOutputData",n)

    def test_exact_five_node_sequential_durable_receipt_before_202(self):
        self.assertEqual(len(self.nodes),5)
        self.assertEqual([n["type"] for n in self.nodes],[
            "n8n-nodes-base.webhook","n8n-nodes-base.code",
            "n8n-nodes-base.httpRequest","n8n-nodes-base.code",
            "n8n-nodes-base.respondToWebhook",
        ])
        names=[n["name"] for n in self.nodes]
        self.assertEqual(len(set(names)),5)
        self.assertEqual(len({n["id"] for n in self.nodes}),5)
        self.assertEqual(set(self.workflow["connections"]),set(names[:-1]))
        for i in range(4):
            self.assertEqual(self.workflow["connections"][names[i]],{
                "main":[[{"node":names[i+1],"type":"main","index":0}]],
            })
        self.assertNotIn(names[-1],self.workflow["connections"])

    def test_webhook_native_header_auth_and_existing_shared_event_route(self):
        webhook=self.nodes[0]["parameters"]
        self.assertEqual(webhook["httpMethod"],"POST")
        self.assertEqual(webhook["authentication"],"headerAuth")
        self.assertEqual(webhook["responseMode"],"responseNode")
        self.assertEqual(webhook["path"],"avuhz-events")
        self.assertTrue(self.nodes[0]["webhookId"])
        self.assertNotEqual(self.nodes[0]["webhookId"],
                            json.loads(ORIGINAL.read_text())["nodes"][0]["webhookId"])

    def test_private_receipt_request_is_unbound_authenticated_and_non_redirecting(self):
        params=self.nodes[2]["parameters"]
        legacy=json.loads(BRIDGE.read_text())["nodes"][2]["parameters"]
        self.assertEqual(params,legacy)
        self.assertEqual(params["method"],"POST")
        self.assertEqual(params["url"],"http://127.0.0.1:1/v1/avuhz/local-n8n-receipts")
        self.assertEqual(params["authentication"],"genericCredentialType")
        self.assertEqual(params["genericAuthType"],"httpHeaderAuth")
        self.assertEqual(params["headerParameters"]["parameters"],[
            {"name":"X-Avuhz-Delivery-Key",
             "value":"={{$json.delivery_idempotency_key}}"},
        ])
        self.assertEqual(params["jsonBody"],"={{JSON.stringify($json)}}")
        self.assertEqual(params["options"]["response"]["response"]["neverError"],True)
        self.assertFalse(params["options"]["redirect"]["redirect"]["followRedirects"])

    def test_response_is_always_fixed_202_but_only_downstream_of_durable_gate(self):
        params=self.nodes[-1]["parameters"]
        self.assertEqual(params["respondWith"],"json")
        self.assertEqual(json.loads(params["responseBody"]),{"accepted":True})
        self.assertEqual(params["options"]["responseCode"],202)
        self.assertNotIn("{{$json",json.dumps(params))
        code=self.nodes[-2]["parameters"]["jsCode"]
        self.assertIn("reply.statusCode===202",code)
        self.assertIn("body.accepted===true",code)
        self.assertIn("typeof body.duplicate==='boolean'",code)
        self.assertIn("DURABLE_RECEIPT_NOT_CONFIRMED",code)

    def test_only_sanitized_eight_field_event_is_forwarded(self):
        item={"json":{"body":envelope(),
                      "headers":{"x-avuhz-delivery-key":KEY,
                                 "x-avuhz-webhook-token":"fake-never-authority"},
                      "contact_email":"never-persist@example.invalid"}}
        data=node_output(self.nodes[1]["parameters"]["jsCode"],[item])
        self.assertTrue(data["ok"],data)
        self.assertEqual(data["value"],[{"json":envelope()}])
        raw=json.dumps(data["value"])
        for leak in ("contact_email","fake-never-authority",
                     "never-persist@example.invalid","metadata","headers"):
            self.assertNotIn(leak,raw)

    def test_wrong_tenant_shape_bad_ids_unexpected_fields_and_headers_are_denied(self):
        safe=envelope()
        examples=[
            {"body":safe,"headers":{}},
            {"body":safe,"headers":{"x-avuhz-delivery-key":"wrong"}},
            {"body":{**safe,"contact_email":"person@example.invalid"},
             "headers":{"x-avuhz-delivery-key":KEY}},
            {"body":{**safe,"event_type":"engagement.opened"},
             "headers":{"x-avuhz-delivery-key":KEY}},
            {"body":{**safe,"authoritative_subject_version":2},
             "headers":{"x-avuhz-delivery-key":KEY}},
            {"body":{**safe,"tenant_id":"not-a-uuid"},
             "headers":{"x-avuhz-delivery-key":KEY}},
            {"body":{**safe,"occurred_at":"2030-02-30T16:00:00Z"},
             "headers":{"x-avuhz-delivery-key":KEY}},
            {"body":{**safe,"authoritative_subject_reference":{
                        "reference_type":"WORK_ITEM","reference_id":SUBJECT}},
             "headers":{"x-avuhz-delivery-key":KEY}},
            {"body":{**safe,"delivery_idempotency_key":"bad key"},
             "headers":{"x-avuhz-delivery-key":"bad key"}},
            {"body":{**safe,"authoritative_subject_reference":{
                        "reference_type":"ACQUISITION_INTAKE","reference_id":SUBJECT,
                        "owner_verified":True}},
             "headers":{"x-avuhz-delivery-key":KEY}},
        ]
        for example in examples:
            with self.subTest(example=str(example)[:100]):
                data=node_output(self.nodes[1]["parameters"]["jsCode"],
                                 [{"json":example}])
                self.assertFalse(data["ok"],data)
                self.assertIn(data["error"],{
                    "RECEIVER_DELIVERY_KEY_DENIED","RECEIPT_ENVELOPE_DENIED",
                })

    def test_no_or_multiple_n8n_events_fail_closed(self):
        valid={"json":{"body":envelope(),
                       "headers":{"x-avuhz-delivery-key":KEY}}}
        for items in ([],[valid,valid],[{"json":{}}]):
            with self.subTest(length=len(items)):
                data=node_output(self.nodes[1]["parameters"]["jsCode"],items)
                self.assertFalse(data["ok"],data)

    def test_exact_202_durable_response_only_no_failure_ack(self):
        code=self.nodes[3]["parameters"]["jsCode"]
        for duplicate in (False,True):
            ok=node_output(code,[{"json":{
                "statusCode":202,"body":{"accepted":True,"duplicate":duplicate},
            }}])
            self.assertTrue(ok["ok"],ok)
            self.assertEqual(ok["value"][0]["json"]["durable"],True)
            self.assertEqual(ok["value"][0]["json"]["first_delivery"],not duplicate)
        examples=[
            {"statusCode":200,"body":{"accepted":True,"duplicate":False}},
            {"statusCode":201,"body":{"accepted":True,"duplicate":False}},
            {"statusCode":503,"body":{"accepted":True,"duplicate":False}},
            {"statusCode":202,"body":{"accepted":False,"duplicate":False}},
            {"statusCode":202,"body":{"accepted":True}},
            {"statusCode":202,"body":{"accepted":True,"duplicate":False,
                                      "owner_verified":True}},
        ]
        for value in examples:
            with self.subTest(value=value):
                refused=node_output(code,[{"json":value}])
                self.assertFalse(refused["ok"],refused)
                self.assertEqual(refused["error"],"DURABLE_RECEIPT_NOT_CONFIRMED")

    def test_no_secrets_external_calls_or_direct_data_access_in_source(self):
        raw=SOURCE.read_text()
        for pattern in (
            r"(?i)sb_secret_[a-z0-9_-]{8,}",
            r"(?i)sk_live_[a-z0-9_-]+",
            r"(?i)bearer\s+[a-z0-9_.-]{20,}",
            r"(?i)https?://(?!127\.0\.0\.1:1/)",
            r"(?i)service_role|supabase\.co|twilio\.com|stripe\.com",
            r"(?i)insert\s+into|update\s+public\.|/rest/v1/",
        ):
            with self.subTest(pattern=pattern):
                self.assertIsNone(re.search(pattern,raw))


if __name__=="__main__":
    unittest.main()
