"""Shared unqualified acquisition-intake notification contract tests.

LOCAL/TEST only. No customer data, database changes, workflow activation,
n8n connection, AUTH/DATA enrollment, billing, or provider network operations.
"""
from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_runtime.schema_registry import SchemaRegistry
from avuhz_worker.n8n_event_sink import N8nOutboxSink
from avuhz_worker.outbox import DeliveryRejected


TENANT = "f1000000-0000-4000-8000-000000000001"
INTAKE = "f2000000-0000-4000-8000-000000000003"
EVENT_ID = "f2000000-0000-4000-8000-000000000001"
CORRELATION = "f2000000-0000-4000-8000-000000000002"
ENDPOINT = "https://n8n.example.invalid/webhook/avuhz-events"


def received_event():
    """An internal, non-authoritative record of intake receipt, not qualification."""
    return {
        "event_id": EVENT_ID,
        "event_type": "acquisition.intake.received",
        "event_schema_version": 1,
        "tenant_id": TENANT,
        "authoritative_subject_reference": {
            "reference_type": "ACQUISITION_INTAKE",
            "reference_id": INTAKE,
        },
        "authoritative_subject_version": 1,
        "occurred_at": "2030-01-15T15:00:00Z",
        "producer_reference": "command.service-01",
        "correlation_id": CORRELATION,
        "idempotency_key": "worker-fixture-idempotency-0001",
        "visibility": "INTEGRATION_INTERNAL",
        "sanitized_metadata": {
            "intake_id": INTAKE,
            "intake_state": "RECEIVED",
        },
    }


class AcquisitionIntakeEventContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        registry = SchemaRegistry(ROOT / "contracts/schemas/v1")
        cls.validator = Draft202012Validator(
            registry.expanded("urn:avuhz:schema:contracts:orchestration:lifecycle-event:v1"),
            format_checker=FormatChecker(),
        )
        cls.reference_schema = registry.resolve(
            "urn:avuhz:schema:contracts:common:references:v1"
        )

    def assert_rejected(self, candidate):
        self.assertFalse(self.validator.is_valid(candidate))

    def test_event_is_valid_and_uses_canonical_internal_reference(self):
        value = received_event()
        self.assertTrue(self.validator.is_valid(value),
                        [error.message for error in self.validator.iter_errors(value)])
        allowed = self.reference_schema["$defs"]["internalReferenceType"]["enum"]
        self.assertIn("ACQUISITION_INTAKE", allowed)
        self.assertNotIn("customer_email", value["sanitized_metadata"])
        self.assertNotIn("organization_id", value["sanitized_metadata"])

    def test_intake_receipt_cannot_be_forged_into_qualified_or_engagement(self):
        base = received_event()
        variations = (
            {"event_type": "acquisition.intake.qualified"},
            {"engagement_id": "f2000000-0000-4000-8000-000000000009"},
            {"authoritative_subject_version": 2},
            {"visibility": "TENANT_OPERATIONAL"},
            {"authoritative_subject_reference": {
                "reference_type": "ENGAGEMENT", "reference_id": INTAKE
            }},
        )
        for change in variations:
            with self.subTest(changed=list(change)):
                self.assert_rejected({**base, **change})

    def test_state_and_metadata_reject_pii_raw_data_and_extra_authority(self):
        for metadata in (
            {},
            {"intake_id": INTAKE},
            {"intake_id": INTAKE, "intake_state": "QUALIFIED"},
            {"intake_id": INTAKE, "intake_state": "RECEIVED", "contact_email": "someone@example.invalid"},
            {"intake_id": INTAKE, "intake_state": "RECEIVED", "contact_phone": "+1-555-0100"},
            {"intake_id": INTAKE, "intake_state": "RECEIVED", "tenant_id": TENANT},
            {"intake_id": INTAKE, "intake_state": "RECEIVED", "authorized": True},
            {"intake_id": "not-uuid", "intake_state": "RECEIVED"},
        ):
            with self.subTest(keys=list(metadata)):
                value = received_event()
                value["sanitized_metadata"] = metadata
                self.assert_rejected(value)

    def test_no_client_pii_or_credentials_reach_n8n_notification(self):
        calls = []
        def fake_post(url, headers, body):
            calls.append((url, dict(headers), json.loads(body)))
            return 202
        sink = N8nOutboxSink(
            environment="TEST",
            tenant_id=TENANT,
            endpoint=ENDPOINT,
            expected_host="n8n.example.invalid",
            credential_provider=lambda: "synthetic-test-not-a-credential",
            post=fake_post,
        )
        self.assertEqual(
            sink.deliver("synthetic-intake-delivery-v1", received_event(),
                         "2030-01-15T15:01:00Z")["result"], "PUBLISHED"
        )
        self.assertEqual(len(calls), 1)
        _, headers, body = calls[0]
        self.assertEqual(body["event_type"], "acquisition.intake.received")
        self.assertEqual(body["tenant_id"], TENANT)
        self.assertNotIn("sanitized_metadata", body)
        self.assertNotIn("contact_email", body)
        self.assertNotIn("business_name", body)
        self.assertNotIn("token", json.dumps(body).lower())
        self.assertIn("X-Avuhz-Webhook-Token", headers)

    def test_cross_tenant_is_rejected_before_transport(self):
        calls = []
        sink = N8nOutboxSink(
            environment="TEST",
            tenant_id=TENANT,
            endpoint=ENDPOINT,
            expected_host="n8n.example.invalid",
            credential_provider=lambda: "synthetic-test-not-a-credential",
            post=lambda *args: calls.append(args) or 202,
        )
        foreign = received_event()
        foreign["tenant_id"] = "f1000000-0000-4000-8000-000000000002"
        with self.assertRaises(DeliveryRejected):
            sink.deliver("synthetic-intake-delivery-v1", foreign,
                         "2030-01-15T15:01:00Z")
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
