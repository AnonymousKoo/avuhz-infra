"""No-network tests for the bounded DEVELOPMENT live-probe classifier."""
from __future__ import annotations

import io
import socket
import ssl
import unittest
import urllib.error

from scripts.development_live_probe_classifier_v1 import (
    MAX_RESPONSE_BYTES,
    PROBE_ACCEPTED,
    classify_http_response,
    classify_transport_error,
)


class LiveProbeClassifierTests(unittest.TestCase):
    def test_exact_invalid_query_after_auth_is_only_pass(self) -> None:
        self.assertEqual(
            classify_http_response(400, b'{"error":"invalid_query"}'),
            PROBE_ACCEPTED,
        )
        self.assertEqual(
            classify_http_response(400, b'{"error": "invalid_query"}'),
            PROBE_ACCEPTED,
        )
        for body in (
            b'{"error":"trusted_identity_required"}',
            b'{"error":"invalid_query","more":"unapproved"}',
            b'{}',
            b'bad json',
            b"",
            b"x" * (MAX_RESPONSE_BYTES + 1),
        ):
            with self.subTest(body=body[:20]):
                self.assertEqual(
                    classify_http_response(400, body),
                    "LIVE_PROBE_RESPONSE_SHAPE_INVALID",
                )

    def test_http_status_classifications_fail_closed(self) -> None:
        cases = {
            200: "LIVE_PROBE_UNEXPECTED_HTTP_STATUS",
            301: "LIVE_PROBE_REDIRECT_REJECTED",
            307: "LIVE_PROBE_REDIRECT_REJECTED",
            401: "LIVE_PROBE_IDENTITY_REJECTED",
            403: "LIVE_PROBE_AUTHORIZATION_DENIED",
            408: "LIVE_PROBE_HTTP_TIMEOUT",
            429: "LIVE_PROBE_RATE_LIMITED",
            502: "LIVE_PROBE_SERVICE_UNAVAILABLE",
            503: "LIVE_PROBE_SERVICE_UNAVAILABLE",
            504: "LIVE_PROBE_HTTP_TIMEOUT",
        }
        for status, expected in cases.items():
            with self.subTest(status=status):
                self.assertEqual(classify_http_response(status), expected)
        self.assertEqual(
            classify_http_response(True, b'{"error":"invalid_query"}'),
            "LIVE_PROBE_HTTP_STATUS_INVALID",
        )
        self.assertEqual(classify_http_response(0), "LIVE_PROBE_HTTP_STATUS_INVALID")

    def test_http_error_uses_only_bounded_body_and_status(self) -> None:
        error = urllib.error.HTTPError(
            "https://example.invalid/private",
            400,
            "sensitive marker",
            {},
            io.BytesIO(b'{"error":"invalid_query"}'),
        )
        self.assertEqual(classify_transport_error(error), PROBE_ACCEPTED)

    def test_network_error_classification_does_not_echo_exception_content(self) -> None:
        marker = "PRIVATE_TOKEN_AND_CUSTOMER_PII_NEVER_ECHO"
        cases = [
            (urllib.error.URLError(socket.timeout(marker)), "LIVE_PROBE_NETWORK_TIMEOUT"),
            (urllib.error.URLError(ssl.SSLError(marker)), "LIVE_PROBE_TLS_FAILURE"),
            (urllib.error.URLError(socket.gaierror(marker)), "LIVE_PROBE_DNS_FAILURE"),
            (urllib.error.URLError(ConnectionRefusedError(marker)), "LIVE_PROBE_CONNECTION_FAILURE"),
            (urllib.error.URLError(marker), "LIVE_PROBE_NETWORK_FAILURE"),
        ]
        for error, expected in cases:
            with self.subTest(expected=expected):
                result = classify_transport_error(error)
                self.assertEqual(result, expected)
                self.assertNotIn(marker, result)

    def test_http_error_response_is_not_echoed(self) -> None:
        marker = b"PRIVATE_RESPONSE_BODY_DO_NOT_ECHO"
        error = urllib.error.HTTPError(
            "https://example.invalid",
            500,
            "internal details must not escape",
            {},
            io.BytesIO(marker),
        )
        result = classify_transport_error(error)
        self.assertEqual(result, "LIVE_PROBE_SERVICE_UNAVAILABLE")
        self.assertNotIn(marker.decode(), result)


if __name__ == "__main__":
    unittest.main()
