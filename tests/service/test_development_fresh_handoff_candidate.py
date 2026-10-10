"""Offline certification of one fresh fictional handoff approval candidate.

Does not import an HTTP transport, fetch a JWT, query a hosted provider, or
generate real owner/client consent. Synthetic approval labels are never an
authorization to run the command.
"""
from __future__ import annotations

import json
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.development_fresh_handoff_candidate import (
    FreshHandoffCandidateStop, prepare_fictional_development_handoff,
)
from avuhz_engineering.development_synthetic_handoff_preflight import (
    SyntheticCommandPreflightStop, certify_synthetic_command,
)
from avuhz_engineering.development_source_bound_handoff_lifecycle import (
    COMMAND_URL,
)
from avuhz_runtime.implementation_handoff import canonical_digest
from avuhz_service.development import (
    DEVELOPMENT_AUTH_PROJECT_REF, DEVELOPMENT_DATA_PROJECT_REF,
)
from avuhz_service.development_supabase_identity import (
    DEVELOPMENT_PROVIDER_ADAPTER_IMPLEMENTATION_HANDOFF_ENTRY,
)

CLOCK = datetime(2026, 10, 10, 21, 16, 0, tzinfo=timezone.utc)
SHA = "38dc26e584d9b4edf1e4a8940b21022dd49d3c82"


class FreshSyntheticHandoffTests(unittest.TestCase):
    def prepare(self, *, now=CLOCK, source=SHA):
        return prepare_fictional_development_handoff(
            at_utc=now, claimed_main_sha=source,
        )

    def test_fresh_request_passes_existing_exact_preflight(self):
        result = self.prepare()
        command = result.command_copy()
        receipt = result.receipt
        entry = DEVELOPMENT_PROVIDER_ADAPTER_IMPLEMENTATION_HANDOFF_ENTRY
        cert = certify_synthetic_command(command, at_utc=CLOCK)
        self.assertEqual(cert.command_digest, receipt.command_digest)
        self.assertEqual(cert.handoff_digest, receipt.handoff_digest)
        self.assertEqual(receipt.command_id, command["command_id"])
        self.assertEqual(receipt.handoff_id, command["subject_id"])
        self.assertEqual(receipt.tenant_id, entry.tenant_id)
        self.assertEqual(command["tenant_id"], entry.tenant_id)
        self.assertEqual(command["payload"]["tenant_id"], entry.tenant_id)
        self.assertEqual(receipt.repository, "AnonymousKoo/avuhz-infra")
        self.assertEqual(receipt.canonical_main_sha_claimed, SHA)
        self.assertEqual(receipt.environment, "DEVELOPMENT")
        self.assertEqual(receipt.command_type, "AcceptImplementationHandoff")
        self.assertEqual(receipt.auth_project, DEVELOPMENT_AUTH_PROJECT_REF)
        self.assertEqual(receipt.data_project, DEVELOPMENT_DATA_PROJECT_REF)
        self.assertNotEqual(receipt.auth_project, receipt.data_project)
        self.assertEqual(receipt.authorized_http_target, COMMAND_URL)
        self.assertTrue(receipt.request_expires_at.endswith("Z"))
        self.assertEqual(command["requested_at"], "2026-10-10T21:16:00Z")
        self.assertFalse(receipt.authorization_verified)
        self.assertFalse(receipt.live_handoff_authorized)
        self.assertFalse(receipt.provider_contact_attempted)
        self.assertFalse(receipt.data_readback_verified)
        self.assertFalse(receipt.retry_authorized)

    def test_payload_contains_only_fictional_bounded_sandbox_truth(self):
        command = self.prepare().command_copy()
        payload = command["payload"]
        self.assertEqual(payload["state"], "APPROVED")
        self.assertEqual(payload["handoff_version"], 1)
        self.assertEqual(payload["allowed_access_level"], "SANDBOX_ONLY")
        self.assertEqual(payload["source_provider_reference"], "provider.fictional.sekinfra")
        self.assertTrue(payload["client_reference"].startswith("client.fictional."))
        self.assertEqual({a["approval_role"] for a in payload["upstream_approval_references"]}, {
            "CLIENT_APPROVER", "PROVIDER_APPROVER",
        })
        self.assertTrue(all(
            a["approved_by"].startswith("human.synthetic.")
            and a["approval_reference"].startswith("approval.synthetic.")
            for a in payload["upstream_approval_references"]
        ))
        self.assertTrue(payload["source_artifact_references"][0][
            "reference_id"
        ].startswith("provider.artifact.synthetic."))
        self.assertIn("PRODUCTION_CHANGE", payload["prohibited_changes"])
        self.assertIn("BILLING_CHANGE", payload["prohibited_changes"])
        self.assertIn("CREDENTIAL_ROTATION", payload["prohibited_changes"])
        self.assertEqual(payload["handoff_digest"], canonical_digest(
            {key: value for key, value in payload.items() if key != "handoff_digest"}
        ))
        self.assertEqual(
            command["caller_identity"]["capabilities"], ["implementation_handoff:accept"]
        )
        self.assertEqual(command["caller_identity"]["tenant_ids"], [command["tenant_id"]])
        self.assertEqual(command["environment"], "DEVELOPMENT")

    def test_two_issuances_never_reuse_command_handoff_or_idempotency(self):
        first, second = self.prepare(), self.prepare()
        a, b = first.command_copy(), second.command_copy()
        for path in ("command_id", "subject_id", "correlation_id", "idempotency_key"):
            self.assertNotEqual(a[path], b[path])
        self.assertNotEqual(first.receipt.command_digest, second.receipt.command_digest)
        self.assertNotEqual(a["payload"]["source_engagement_reference"],
                            b["payload"]["source_engagement_reference"])
        self.assertNotEqual(a["payload"]["upstream_approval_references"][0][
            "approval_reference"
        ], b["payload"]["upstream_approval_references"][0][
            "approval_reference"
        ])

    def test_command_copy_is_not_mutable_backdoor_into_digest_receipt(self):
        prepared = self.prepare()
        altered = prepared.command_copy()
        altered["payload"]["constraints"].append("Changed after digest.")
        with self.assertRaises(SyntheticCommandPreflightStop):
            certify_synthetic_command(altered, at_utc=CLOCK)
        self.assertEqual(
            certify_synthetic_command(prepared.command_copy(), at_utc=CLOCK).command_digest,
            prepared.receipt.command_digest,
        )
        text = repr(prepared)
        self.assertNotIn('"payload":', text)
        self.assertNotIn("approved_scope", text)
        self.assertNotIn("upstream_approval_references", text)

    def test_request_expires_without_extending_old_approvals(self):
        prepared = self.prepare()
        after = CLOCK + timedelta(minutes=16)
        self.assertLess(
            datetime.fromisoformat(
                prepared.receipt.request_expires_at.replace("Z", "+00:00")
            ), after,
        )
        with self.assertRaises(SyntheticCommandPreflightStop):
            certify_synthetic_command(prepared.command_copy(), at_utc=after)

    def test_fail_closed_on_unbound_invalid_environment_or_sha(self):
        for moment, sha in (
            (CLOCK, "x" * 40),
            (CLOCK, "A" * 40),
            (CLOCK, SHA[:39]),
            (CLOCK, None),
            (CLOCK.replace(tzinfo=None), SHA),
            (CLOCK.replace(tzinfo=timezone(timedelta(hours=-4))), SHA),
            (CLOCK.replace(microsecond=1), SHA),
            ("2026-10-10T21:16:00Z", SHA),
        ):
            with self.subTest(moment=str(moment), sha=sha):
                with self.assertRaisesRegex(
                    FreshHandoffCandidateStop, "^HANDOFF_FRESH_CANDIDATE_INVALID$"
                ):
                    self.prepare(now=moment, source=sha)

    def test_no_network_provider_db_write_or_approval_signing_during_preparation(self):
        with (
            patch("urllib.request.urlopen", side_effect=AssertionError("no HTTP")),
            patch("urllib.request.build_opener", side_effect=AssertionError("no HTTP")),
        ):
            receipt = self.prepare().receipt
        self.assertFalse(receipt.authorization_verified)
        self.assertFalse(receipt.live_handoff_authorized)
        self.assertFalse(receipt.provider_contact_attempted)


if __name__ == "__main__":
    unittest.main()
