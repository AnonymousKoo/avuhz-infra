"""Pure offline checks of the one-attempt dispatch core. No real network."""
from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from test_development_synthetic_handoff_offline_certification import (
    SAMPLE_HANDOFF_ID,
    fictional_envelope,
)
from test_development_synthetic_handoff_preflight import CLOCK

from avuhz_engineering.development_one_shot_handoff_dispatch import (
    dispatch_one_synthetic_handoff,
)
from avuhz_engineering.development_synthetic_handoff_preflight import (
    SyntheticCommandPreflightStop,
    certify_synthetic_command,
)

# A non-functional stand-in for an opaque in-memory credential, not a JWT.
SAMPLE_OPAQUE_INPUT = "not-a-real-session-" + ("x" * 40)


def make_request_and_digest():
    request = fictional_envelope()
    return request, certify_synthetic_command(request, at_utc=CLOCK).command_digest


def invoke(request, digest, authorization_check, send_once, token=SAMPLE_OPAQUE_INPUT):
    return dispatch_one_synthetic_handoff(
        request,
        at_utc=CLOCK,
        approved_command_digest=digest,
        authorization_check=authorization_check,
        access_token=token,
        send_once=send_once,
    )


class DevelopmentOneShotHandoffDispatchTests(unittest.TestCase):
    def test_single_accepted_delivery_is_pending_independent_readback(self):
        request, digest = make_request_and_digest()
        calls = []
        checks = []

        def check(candidate):
            checks.append(candidate.command_digest)
            return candidate.command_digest == digest

        def send_once(envelope, access_token):
            calls.append((envelope["subject_id"], len(access_token)))
            envelope["subject_id"] = "a6b00000-0000-4000-8000-000000000099"
            return 202, json.dumps({
                "result": "ACCEPTED",
                "reason_code": "COMMAND_ACCEPTED",
                "authoritative_record_reference": SAMPLE_HANDOFF_ID,
            }).encode()

        with patch("urllib.request.urlopen", side_effect=AssertionError("network forbidden")):
            outcome = invoke(request, digest, check, send_once)

        self.assertEqual(checks, [digest])
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], SAMPLE_HANDOFF_ID)
        self.assertEqual(request["subject_id"], SAMPLE_HANDOFF_ID)
        self.assertEqual(
            outcome.classification,
            "SYNTHETIC_COMMAND_ACCEPTED_PENDING_DATA_VERIFICATION",
        )
        self.assertTrue(outcome.send_attempted)
        self.assertTrue(outcome.data_readback_required)
        self.assertTrue(outcome.session_cleanup_readback_required)
        self.assertTrue(outcome.credential_retirement_required)
        self.assertFalse(outcome.retry_authorized)
        self.assertFalse(outcome.token_material_retained)
        self.assertFalse(outcome.pii_retained)
        self.assertIsNone(outcome.safe_error_code)

    def test_wrong_source_missing_approval_and_session_stop_before_send(self):
        request, digest = make_request_and_digest()
        scenarios = (
            ("digest-mismatch", "sha256:" + "0" * 64, lambda _: True, SAMPLE_OPAQUE_INPUT),
            ("missing-approval", digest, lambda _: False, SAMPLE_OPAQUE_INPUT),
            ("approval-exception", digest, lambda _: (_ for _ in ()).throw(RuntimeError("sensitive")), SAMPLE_OPAQUE_INPUT),
            ("invalid-session", digest, lambda _: True, "too-short"),
        )
        for name, approved_digest, check, token in scenarios:
            with self.subTest(name=name):
                calls = []
                with self.assertRaises(SyntheticCommandPreflightStop):
                    invoke(request, approved_digest, check, lambda *_: calls.append(1), token=token)
                self.assertEqual(calls, [])

    def test_unverified_network_and_rejected_responses_require_readback_no_retry(self):
        request, digest = make_request_and_digest()
        outcomes = [
            ("transport", lambda *_: (_ for _ in ()).throw(RuntimeError("untrusted-provider-payload"))),
            ("authorization", lambda *_: (401, b'{"error":"denied"}')),
            ("invalid-response", lambda *_: (202, b'{"result":"ACCEPTED"}')),
            ("server-error", lambda *_: (500, b'{"error":"unexpected"}')),
        ]
        for name, fake in outcomes:
            with self.subTest(name=name):
                calls = []

                def send_once(*args):
                    calls.append(1)
                    return fake(*args)

                outcome = invoke(request, digest, lambda _: True, send_once)
                self.assertEqual(len(calls), 1)
                self.assertEqual(outcome.classification, "SYNTHETIC_COMMAND_OUTCOME_UNVERIFIED")
                self.assertTrue(outcome.send_attempted)
                self.assertTrue(outcome.data_readback_required)
                self.assertFalse(outcome.retry_authorized)
                self.assertIsNotNone(outcome.safe_error_code)
                self.assertNotIn("untrusted-provider-payload", repr(outcome))

    def test_mutated_candidate_is_rejected_before_approval_or_dispatch(self):
        request, digest = make_request_and_digest()
        mutated = copy.deepcopy(request)
        mutated["tenant_id"] = "a6b00000-0000-4000-8000-000000000099"
        calls = []
        with self.assertRaises(SyntheticCommandPreflightStop):
            invoke(mutated, digest, lambda *_: calls.append(1), lambda *_: calls.append(2))
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
