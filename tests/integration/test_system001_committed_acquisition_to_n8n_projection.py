"""No-provider LOCAL/TEST certification of contiguous shared acquisition event.

The existing QA script now constructs its n8n input from the actual committed
fictional HTTP acquisition and the shared OutboxWorker + N8nOutboxSink; it no
longer fabricates an event in the n8n manual QA parent. This test never
imports/activates n8n workflows, provisions credentials or writes hosted DATA.
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from scripts.certify_system001_live_local_n8n_to_work import (
    ROOT, build_committed_local_acquisition_envelope,
)

QA = ROOT / "tests" / "fixtures" / "system001_qa_tenant_local_v1.json"


def fixture():
    return json.loads(QA.read_text())


class LocalCommittedAcquisitionToN8nProjectionTests(TestCase):
    def test_shared_http_intake_to_real_outbox_emits_actual_committed_subject(self):
        qa = fixture()
        envelope, authority = build_committed_local_acquisition_envelope(qa)
        self.assertEqual(set(envelope), {
            "event_id", "event_type", "tenant_id", "correlation_id",
            "occurred_at", "authoritative_subject_reference",
            "authoritative_subject_version", "delivery_idempotency_key",
        })
        self.assertEqual(envelope["event_type"], "acquisition.intake.received")
        self.assertEqual(envelope["tenant_id"], qa["tenant_id"])
        self.assertEqual(envelope["authoritative_subject_reference"], {
            "reference_type": "ACQUISITION_INTAKE", "reference_id": authority,
        })
        self.assertNotEqual(authority, qa["request"]["external_request_id"])
        self.assertEqual(envelope["authoritative_subject_version"], 1)
        self.assertGreaterEqual(len(envelope["delivery_idempotency_key"]), 8)
        render = json.dumps(envelope)
        for forbidden in (
            qa["request"]["contact_name"],
            qa["request"]["contact_email"],
            qa["request"]["business_name"],
            qa["request"]["diagnostic_summary"],
            qa["request"]["external_request_id"],
            "fictional.test.only.identity.token.1234567",
            "sanitized_metadata",
            "principal_subject_digest",
        ):
            self.assertNotIn(forbidden, render)
        self.assertNotIn("password", render.lower())

    def test_client_business_or_owner_is_not_promoted_to_authority(self):
        qa = fixture()
        for attrs in (
            {"owner_is_real_or_verified": True},
            {"hosted_data_insert_authorized": True},
            {"production_allowed": True},
            {"fixture_type": "REAL_CLIENT"},
            {"tenant_id": "a4730000-0000-4000-8000-000000000002"},
        ):
            with self.subTest(attrs=attrs):
                copy = {**qa, **attrs}
                with self.assertRaisesRegex(RuntimeError,"^fictional_acquisition_fixture_invalid$"):
                    build_committed_local_acquisition_envelope(copy)

    def test_real_contact_or_wrong_source_denied_before_any_work(self):
        qa = fixture()
        for update in (
            {"contact_email": "customer@example.com"},
            {"external_request_id": "a4730000-0000-4000-8000-000000000099"},
            {"source_system": "unapproved.external"},
        ):
            with self.subTest(update=update):
                copy={**qa,"request":{**qa["request"], **update}}
                with self.assertRaisesRegex(RuntimeError,"^fictional_acquisition_fixture_invalid$"):
                    build_committed_local_acquisition_envelope(copy)

    def test_nonactive_company_fails_before_projecting_any_event(self):
        qa=fixture()
        from test_development_acquisition_http import application as original
        from test_development_acquisition_ingress import Store
        def inactive():
            return original(store=Store(rows=[]))
        with patch("test_development_acquisition_http.application", side_effect=inactive):
            with self.assertRaisesRegex(RuntimeError,"^fictional_acquisition_not_committed$"):
                build_committed_local_acquisition_envelope(qa)

    def test_forged_http_receipt_does_not_match_committed_event(self):
        qa=fixture()
        from test_development_acquisition_http import request as original
        def fake_response(*args,**kwargs):
            status,receipt,headers=original(*args,**kwargs)
            assert status == 202
            return status,{**receipt,
                "intake_id":"a4730000-0000-4000-8000-000000000099"},headers
        with patch("test_development_acquisition_http.request",side_effect=fake_response):
            with self.assertRaisesRegex(RuntimeError,"^fictional_acquisition_event_invalid$"):
                build_committed_local_acquisition_envelope(qa)

    def test_projected_event_must_match_intake_tenant(self):
        qa=fixture()
        from tests.integration.test_acquisition_http_to_n8n_synthetic_journey import (
            event_and_outbox_from_committed_intake as original,
        )
        def wrong_tenant(*args,**kwargs):
            memory=original(*args,**kwargs)
            memory.events[0]["tenant_id"]="a4730000-0000-4000-8000-000000000002"
            return memory
        with patch("tests.integration.test_acquisition_http_to_n8n_synthetic_journey."
                   "event_and_outbox_from_committed_intake",
                   side_effect=wrong_tenant):
            with self.assertRaisesRegex(RuntimeError,"^fictional_acquisition_event_invalid$"):
                build_committed_local_acquisition_envelope(qa)


if __name__ == "__main__":
    import unittest
    unittest.main()
