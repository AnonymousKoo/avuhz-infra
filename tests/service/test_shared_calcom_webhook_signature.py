"""No-network, no-provider shared Cal.com signature security tests."""
from __future__ import annotations

import hashlib
import hmac
import secrets
import unittest

from avuhz_service.shared_calcom_webhook_signature import (
    CalcomSignatureDenied, verify_calcom_signature,
)


_DEFAULT = object()


class CalcomWebhookSignatureTests(unittest.TestCase):
    def setUp(self):
        # Never persist an actual or synthetic fixed credential in the repo.
        self.key = secrets.token_bytes(48)
        self.body = b'{"triggerEvent":"BOOKING_CREATED","payload":{"uid":"synthetic"}}'
        self.sig = hmac.new(self.key, self.body, hashlib.sha256).hexdigest()

    def verify(self, body=_DEFAULT, header=_DEFAULT, *, key=_DEFAULT):
        return verify_calcom_signature(
            self.body if body is _DEFAULT else body,
            self.sig if header is _DEFAULT else header,
            secret=self.key if key is _DEFAULT else key,
        )

    def test_exact_raw_body_hmac_is_accepted(self):
        self.assertIsNone(self.verify())
        self.assertIsNone(self.verify(header="sha256=" + self.sig))

    def test_bytewise_payload_tamper_denied(self):
        for body in (
            self.body + b" ",
            self.body + b"\n",
            self.body.replace(b"CREATED", b"CANCELLED"),
            self.body.replace(b'"uid"', b'"id"'),
        ):
            with self.subTest(body=repr(body[:12])), self.assertRaises(CalcomSignatureDenied):
                self.verify(body=body)

    def test_wrong_key_denied(self):
        with self.assertRaises(CalcomSignatureDenied):
            self.verify(key=secrets.token_bytes(48))

    def test_no_secret_or_inadequate_secret_denied(self):
        for key in (b"", None, "fake", b"short", b"x" * 4097):
            with self.subTest(kind=type(key).__name__), self.assertRaises(CalcomSignatureDenied):
                self.verify(key=key)

    def test_invalid_headers_fail_closed(self):
        for header in (
            "", None, " sha256=" + self.sig, self.sig + " ",
            self.sig.upper(), "SHA256=" + self.sig, "sha256=" + self.sig + ",sha256=" + self.sig,
            ["sha256=" + self.sig], self.sig[:32], "sha1=" + self.sig,
            "sha256=" + self.sig + "\n", "sha256=" + self.sig + "x",
        ):
            with self.subTest(header_type=type(header).__name__), self.assertRaises(CalcomSignatureDenied):
                self.verify(header=header)

    def test_raw_body_must_be_original_bytes(self):
        for body in (None, "", {}, bytearray(self.body), memoryview(self.body), b"", b"X" * 65_537):
            with self.subTest(kind=type(body).__name__), self.assertRaises(CalcomSignatureDenied):
                self.verify(body=body)

    def test_boundary_payload_can_be_verified_without_parsing(self):
        body = b"X" * 65_536
        signature = hmac.new(self.key, body, hashlib.sha256).hexdigest()
        self.assertIsNone(self.verify(body=body, header=signature))

    def test_generic_error_does_not_contain_signature_or_payload(self):
        try:
            self.verify(body=self.body + b"unsafe")
        except CalcomSignatureDenied as exc:
            self.assertEqual(str(exc), "calcom_signature_unverified")
            self.assertNotIn(self.sig, str(exc))
            self.assertNotIn("BOOKING_CREATED", str(exc))
        else:
            self.fail("expected a signature denial")

    def test_valid_signature_is_not_a_booking_or_replay_protection(self):
        # Two valid messages can be replayed. No durable ledger is present.
        self.assertIsNone(self.verify())
        self.assertIsNone(self.verify())
        from avuhz_service import shared_calcom_webhook_signature as module
        for forbidden in ("create_work_item", "receive_booking",
                          "replay_guard", "send_to_n8n", "parse_booking"):
            self.assertFalse(hasattr(module, forbidden))


if __name__ == "__main__":
    unittest.main()
