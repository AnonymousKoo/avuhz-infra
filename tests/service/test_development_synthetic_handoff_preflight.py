"""Portable no-network certification of a synthetic handoff candidate and result."""
from __future__ import annotations

import copy
import json
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from test_development_synthetic_handoff_offline_certification import (
    CANONICAL_DEVELOPMENT_TENANT,
    NOW,
    SAMPLE_HANDOFF_ID,
    fictional_envelope,
)

from avuhz_engineering.development_synthetic_handoff_preflight import (
    SyntheticCommandPreflightStop,
    certify_accepted_response,
    certify_synthetic_command,
)
from avuhz_runtime.implementation_handoff import canonical_digest

CLOCK = datetime.fromisoformat(NOW.replace("Z", "+00:00"))


class DevelopmentSyntheticCommandPreflightTests(unittest.TestCase):
    def test_exact_fictional_candidate_is_certified_without_any_network(self):
        request = fictional_envelope()
        with patch("urllib.request.urlopen", side_effect=AssertionError("network forbidden")):
            candidate = certify_synthetic_command(request, at_utc=CLOCK)
        self.assertEqual(candidate.tenant_id, CANONICAL_DEVELOPMENT_TENANT)
        self.assertEqual(candidate.handoff_id, SAMPLE_HANDOFF_ID)
        self.assertEqual(candidate.handoff_digest, request["payload"]["handoff_digest"])
        self.assertTrue(candidate.command_digest.startswith("sha256:"))
        self.assertEqual(len(candidate.command_digest), 71)
        self.assertFalse(hasattr(candidate, "bearer_token"))
        self.assertFalse(hasattr(candidate, "refresh_token"))

    def test_exact_accepted_response_is_only_pending_independent_data_readback(self):
        candidate = certify_synthetic_command(fictional_envelope(), at_utc=CLOCK)
        body = json.dumps({
            "result": "ACCEPTED",
            "reason_code": "COMMAND_ACCEPTED",
            "authoritative_record_reference": SAMPLE_HANDOFF_ID,
        }).encode()
        self.assertEqual(
            certify_accepted_response(
                http_status=202, response_bytes=body, candidate=candidate
            ),
            "SYNTHETIC_COMMAND_ACCEPTED_PENDING_DATA_VERIFICATION",
        )
        for status in (200, 401, 403, 409, 422, 500):
            with self.subTest(status=status), self.assertRaises(SyntheticCommandPreflightStop):
                certify_accepted_response(
                    http_status=status, response_bytes=body, candidate=candidate
                )
        for bad_body in (
            b"{}",
            b"not-json",
            b"",
            b"{" + b"x" * 1500 + b"}",
            json.dumps({
                "result": "ACCEPTED",
                "reason_code": "COMMAND_ACCEPTED",
                "authoritative_record_reference": "a6b00000-0000-4000-8000-000000000099",
            }).encode(),
        ):
            with self.subTest(body_length=len(bad_body)), self.assertRaises(SyntheticCommandPreflightStop):
                certify_accepted_response(
                    http_status=202, response_bytes=bad_body, candidate=candidate
                )

    def test_development_tenant_identity_and_scope_are_exact(self):
        scenarios = [
            ("wrong-tenant", lambda r: r.update(tenant_id="a6b00000-0000-4000-8000-000000000099")),
            ("wrong-identity", lambda r: r["caller_identity"].update(subject="service.other")),
            ("wrong-capability", lambda r: r["caller_identity"].update(capabilities=["engagement:read"])),
            ("wrong-env", lambda r: r.update(environment="PRODUCTION")),
            ("nonfictional-source", lambda r: r["payload"].update(client_reference="client.real")),
            ("overscoped-access", lambda r: r["payload"].update(allowed_access_level="FULL_ACCESS")),
            ("unbounded-production-change", lambda r: r["payload"]["prohibited_changes"].remove("PRODUCTION_CHANGE")),
        ]
        for name, change in scenarios:
            with self.subTest(name=name):
                request = fictional_envelope()
                change(request)
                if name in {"nonfictional-source", "overscoped-access", "unbounded-production-change"}:
                    request["payload"].pop("handoff_digest")
                    request["payload"]["handoff_digest"] = canonical_digest(request["payload"])
                with self.assertRaises(SyntheticCommandPreflightStop):
                    certify_synthetic_command(request, at_utc=CLOCK)

    def test_digests_fictional_approvals_and_time_gates_fail_closed(self):
        scenarios = [
            ("bad-handoff-digest", lambda r: r["payload"].update(handoff_digest="sha256:" + "0" * 64)),
            ("real-client-approval", lambda r: r["payload"]["upstream_approval_references"][0].update(approved_by="human.real-client")),
            ("future-request", lambda r: r.update(requested_at="2026-10-08T20:00:00Z")),
            ("expired-identity", lambda r: r["caller_identity"].update(expires_at="2026-10-08T19:10:00Z")),
            ("stale-request", lambda r: r.update(requested_at="2026-10-08T18:00:00Z")),
            ("secret-in-constraints", lambda r: r["payload"]["constraints"].append("api_" + "key=not-an-allowed-input")),
        ]
        for name, change in scenarios:
            with self.subTest(name=name):
                request = fictional_envelope()
                change(request)
                if name in {"real-client-approval", "secret-in-constraints"}:
                    request["payload"].pop("handoff_digest")
                    request["payload"]["handoff_digest"] = canonical_digest(request["payload"])
                with self.assertRaises(SyntheticCommandPreflightStop):
                    certify_synthetic_command(request, at_utc=CLOCK)
        with self.assertRaises(SyntheticCommandPreflightStop):
            certify_synthetic_command(fictional_envelope(), at_utc=CLOCK + timedelta(minutes=20))
        with self.assertRaises(SyntheticCommandPreflightStop):
            certify_synthetic_command(fictional_envelope(), at_utc=datetime.now().replace(tzinfo=None))


if __name__ == "__main__":
    unittest.main()
