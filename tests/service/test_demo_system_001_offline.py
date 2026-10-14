"""LOCAL/TEST-only regression of the one-command System #001 walkthrough."""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "demo_system_001_offline.py"


class OfflineSystem001DemoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("system001_demo", SCRIPT)
        cls.demo = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.demo)

    def test_full_synthetic_journey_reuses_existing_shared_services(self):
        result = self.demo.run_demo()
        self.assertEqual(result["mode"], "OFFLINE_SYNTHETIC_ONLY")
        self.assertEqual(
            [row["action"] for row in result["history"]],
            ["OPEN", "OFFER_HANDOFF", "ACCEPT_HANDOFF", "BLOCK", "RESUME", "RESOLVE"],
        )
        self.assertEqual([row["version"] for row in result["history"]], list(range(1, 7)))
        self.assertEqual(result["history"][-1]["state"], "RESOLVED")
        self.assertTrue(all(result["security"].values()))
        self.assertEqual(result["local_outbox"], {
            "events_projected": 6, "stub_deliveries": 6, "second_run_published": 0,
        })
        self.assertFalse(result["customer_data_used"])
        self.assertFalse(result["hosted_database_used"])
        self.assertFalse(result["live_n8n_used"])

    def test_default_cli_is_safe_and_disclaims_delivery_guarantees(self):
        run = subprocess.run(
            [sys.executable, str(SCRIPT)], cwd=ROOT,
            text=True, capture_output=True, check=True,
        )
        output = run.stdout
        self.assertIn("OFFLINE SYNTHETIC WALKTHROUGH", output)
        self.assertIn("6/6 published to LOCAL stub", output)
        self.assertIn("idle second run published 0", output)
        self.assertIn("NOT PROVEN | Consumer-side deduplication", output)
        self.assertIn("No hosted work-item persistence", output)
        for disallowed in (
            "worker.sender", "worker.receiver", self.demo.TENANT,
            self.demo.OTHER_TENANT, "X-Avuhz-Webhook-Token",
            "Live customer", "PRODUCTION READY", "exactly-once delivery verified",
        ):
            self.assertNotIn(disallowed, output)

    def test_cli_json_is_safe_and_explicit_about_limitations(self):
        run = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"], cwd=ROOT,
            text=True, capture_output=True, check=True,
        )
        body = json.loads(run.stdout)
        self.assertEqual(body["mode"], "OFFLINE_SYNTHETIC_ONLY")
        self.assertEqual(len(body["history"]), 6)
        self.assertNotIn("worker.sender", run.stdout)
        self.assertNotIn("worker.receiver", run.stdout)
        self.assertNotIn("X-Avuhz-Webhook-Token", run.stdout)
        self.assertNotIn("tenant_id", run.stdout)
        self.assertIn("no hosted transactional", body["limitations"].lower())


if __name__ == "__main__":
    unittest.main()
