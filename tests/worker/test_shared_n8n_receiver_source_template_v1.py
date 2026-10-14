"""Source-only n8n v1.103.2 template security regression; never import to live."""
from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

WORKFLOW = (
    Path(__file__).resolve().parents[2] /
    "contracts/templates/n8n/avuhz-shared-event-receiver-inactive-v1.json"
)


class SharedN8nReceiverTemplateTests(unittest.TestCase):
    def setUp(self):
        self.template = json.loads(WORKFLOW.read_text())

    def test_template_is_inactive_and_has_no_provider_credential_binding(self):
        self.assertIs(self.template["active"], False)
        self.assertNotIn("credentials", self.template)
        for node in self.template["nodes"]:
            self.assertNotIn("credentials", node)
        self.assertNotIn("staticData", self.template)
        self.assertNotIn("pinData", self.template)
        for key in ("saveDataSuccessExecution", "saveDataErrorExecution"):
            self.assertEqual(self.template["settings"][key], "none")
        self.assertIs(self.template["settings"]["saveManualExecutions"], False)

    def test_receiver_native_auth_and_no_exposed_anonymous_listener(self):
        trigger, code, response = self.template["nodes"]
        self.assertEqual(trigger["type"], "n8n-nodes-base.webhook")
        params = trigger["parameters"]
        self.assertEqual(params["httpMethod"], "POST")
        self.assertEqual(params["authentication"], "headerAuth")
        self.assertEqual(params["responseMode"], "responseNode")
        self.assertEqual(params["path"], "avuhz-events")
        self.assertEqual(code["type"], "n8n-nodes-base.code")
        self.assertEqual(response["type"], "n8n-nodes-base.respondToWebhook")

    def test_response_is_always_fail_closed_without_persistent_store(self):
        params = self.template["nodes"][2]["parameters"]
        self.assertEqual(params["respondWith"], "json")
        self.assertEqual(params["options"]["responseCode"], 503)
        self.assertEqual(json.loads(params["responseBody"]), {
            "code": "RECEIVER_NOT_READY",
        })
        self.assertEqual(set(self.template["connections"]), {
            "Authenticated Avuhz Event Webhook",
            "Validate Non-Authoritative Shape Only",
        })

    def test_no_outbound_side_effect_nodes_or_event_pii(self):
        allowed_types = {
            "n8n-nodes-base.webhook", "n8n-nodes-base.code",
            "n8n-nodes-base.respondToWebhook",
        }
        self.assertEqual({n["type"] for n in self.template["nodes"]}, allowed_types)
        code = self.template["nodes"][1]["parameters"]["jsCode"]
        self.assertNotIn("fetch(", code)
        self.assertNotIn("console.log", code)
        self.assertNotIn("process.env", code)
        self.assertNotIn("this.helpers.httpRequest", code)
        self.assertIn("RECEIVER_NOT_READY", code)
        self.assertIn("acquisition.intake.received", code)
        self.assertIn("engagement.opened", code)

    def test_no_hardcoded_secret_bearer_provider_address_or_data_table(self):
        raw = WORKFLOW.read_text()
        for pattern in (
            r"sb_secret_[A-Za-z0-9._-]{8,}",
            r"(?i)sk_live_[A-Za-z0-9]+",
            r"(?i)bearer\s+[A-Za-z0-9._-]{20,}",
            r"(?i)https?://",
            r"(?i)(insert\s+into|update\s+public\.|/rest/v1/)",
        ):
            with self.subTest(pattern=pattern):
                self.assertIsNone(re.search(pattern, raw))


if __name__ == "__main__":
    unittest.main()
