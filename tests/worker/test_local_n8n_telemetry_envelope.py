"""LOCAL ONLY synthetic, negative and tamper evidence for signed n8n aggregates."""
from __future__ import annotations

import copy
import json
import unittest

from src.avuhz_worker.local_n8n_telemetry_envelope import (
    create_envelope, verify_envelope, MAX_AGE_SECONDS, VERSION
)
from scripts.local_n8n_activity_snapshot import KNOWN_EXECUTION_STATES, EXPECTED_SOURCE


def sample() -> dict:
    return {
        "schema_version": 1, "source": EXPECTED_SOURCE, "read_only": True,
        "connection_to_command_center": False,
        "workflows": {"stored": 3, "active": 0, "inactive": 3},
        "executions": {"total": 0, "statuses": dict.fromkeys(KNOWN_EXECUTION_STATES, 0),
                       "other": 0},
        "system_001": {"matching_candidate_workflows": 1, "active_candidates": 0,
                       "runtime_certified": False},
    }


KEY = b"local-test-only-not-for-hosted-use-" + b"x" * 32
T = 1792050000
NONCE = "0123456789abcdef" * 2


class LocalN8nSignedTelemetryTests(unittest.TestCase):
    def test_contract_roundtrip_without_identity_or_workflow_claims(self):
        e = create_envelope(sample(), KEY, now=T, nonce=NONCE)
        self.assertTrue(verify_envelope(e, KEY, now=T, replay_seen=lambda _: False))
        self.assertEqual(e["version"], VERSION)
        self.assertEqual(e["nonce"], NONCE)
        self.assertEqual(e["observed_at"], T)
        self.assertEqual(set(e), {"version", "observed_at", "nonce", "evidence", "mac"})
        self.assertNotIn("tenant_id", json.dumps(e))
        self.assertNotIn("credentials", json.dumps(e))
        self.assertNotIn("private-workflow-id", json.dumps(e))
        self.assertFalse(e["evidence"]["connection_to_command_center"])
        self.assertFalse(e["evidence"]["system_001"]["runtime_certified"])

    def test_tamper_payload_signature_and_source_all_rejected(self):
        base = create_envelope(sample(), KEY, now=T, nonce=NONCE)
        for key, value in [
            ("observed_at", T + 1), ("version", "not-the-version"),
            ("nonce", "a" * 32), ("mac", "b" * 64),
        ]:
            changed = copy.deepcopy(base)
            changed[key] = value
            self.assertFalse(verify_envelope(changed, KEY, now=T, replay_seen=lambda _: False),
                             f"tamper allowed: {key}")
        changed = copy.deepcopy(base)
        changed["evidence"]["workflows"]["active"] = 1
        self.assertFalse(verify_envelope(changed, KEY, now=T, replay_seen=lambda _: False))
        changed = copy.deepcopy(base)
        changed["evidence"]["source"] = "PRODUCTION_N8N"
        self.assertFalse(verify_envelope(changed, KEY, now=T, replay_seen=lambda _: False))

    def test_expired_future_and_replayed_nonce_are_denied(self):
        packet = create_envelope(sample(), KEY, now=T, nonce=NONCE)
        self.assertFalse(verify_envelope(packet, KEY, now=T + MAX_AGE_SECONDS + 1,
                                         replay_seen=lambda _: False))
        self.assertFalse(verify_envelope(packet, KEY, now=T - MAX_AGE_SECONDS - 1,
                                         replay_seen=lambda _: False))
        self.assertFalse(verify_envelope(packet, KEY, now=T,
                                         replay_seen=lambda nonce: nonce == NONCE))
        self.assertFalse(verify_envelope(packet, KEY, now=T, replay_seen=None))
        self.assertFalse(verify_envelope(packet, KEY + b"wrong", now=T,
                                         replay_seen=lambda _: False))

    def test_disallow_secret_pii_unexpected_fields_and_inconsistent_count(self):
        invalid = []
        changed = sample()
        changed["phone"] = "555-123-4567"
        invalid.append(changed)
        changed = sample()
        changed["source"] = "another host"
        invalid.append(changed)
        changed = sample()
        changed["workflows"]["inactive"] = 2
        invalid.append(changed)
        changed = sample()
        changed["executions"]["statuses"]["attack"] = 10
        invalid.append(changed)
        changed = sample()
        changed["system_001"]["runtime_certified"] = True
        invalid.append(changed)
        changed = sample()
        changed["executions"]["total"] = 1
        invalid.append(changed)
        changed = sample()
        changed["workflows"]["stored"] = True
        invalid.append(changed)
        for bad in invalid:
            with self.assertRaises(ValueError):
                create_envelope(bad, KEY, now=T, nonce=NONCE)
        with self.assertRaises(ValueError):
            create_envelope(sample(), b"short", now=T)
        with self.assertRaises(ValueError):
            create_envelope(sample(), KEY, now=T, nonce="zz")

    def test_verify_malformed_input_does_not_crash_or_expose_secrets(self):
        for packet in [None, "{}", [], {}, {"mac": KEY.hex()},
                       {"version": VERSION, "observed_at": 0, "nonce": NONCE,
                        "evidence": sample(), "mac": KEY.hex(), "extra": "PII"}]:
            self.assertFalse(verify_envelope(packet, KEY, now=T,
                                             replay_seen=lambda _: False))


if __name__ == "__main__":
    unittest.main()
