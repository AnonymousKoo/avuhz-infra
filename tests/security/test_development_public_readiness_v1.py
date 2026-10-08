"""Offline security tests for the DEVELOPMENT public health probe."""
from __future__ import annotations

import io
import json
import socket
import unittest
import urllib.error

from scripts import development_public_readiness_v1 as probe


class FakeResponse:
    def __init__(self, code: int, body: bytes):
        self.code = code
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def getcode(self):
        return self.code

    def read(self, limit: int):
        return self.body[:limit]


def good_response(name: str):
    return FakeResponse(200, json.dumps(probe.EXPECTED_HEALTH[name]).encode())


class ReadinessProbeTests(unittest.TestCase):
    def test_success_uses_three_fixed_public_gets_and_no_auth(self):
        calls = []

        def opener(request, *, timeout):
            calls.append((request, timeout))
            name = request.full_url.rsplit("/", 1)[1]
            return good_response(name)

        result = probe.run_probe(opener=opener)
        self.assertEqual(result["classification"], "DEVELOPMENT_PUBLIC_READINESS_PASS")
        self.assertEqual(result["passed_checks"], ["startup", "live", "ready"])
        self.assertFalse(result["credential_used"])
        self.assertFalse(result["provider_mutation_attempted"])
        self.assertEqual(len(calls), 3)
        for request, timeout in calls:
            self.assertEqual(timeout, probe.TIMEOUT_SECONDS)
            self.assertEqual(request.get_method(), "GET")
            self.assertTrue(request.full_url.startswith(probe.SERVICE_ORIGIN + "/health/"))
            self.assertIsNone(request.get_header("Authorization"))

    def test_readiness_failure_stops_once_and_does_not_retry(self):
        calls = []

        def opener(request, *, timeout):
            name = request.full_url.rsplit("/", 1)[1]
            calls.append(name)
            if name == "ready":
                return FakeResponse(
                    503,
                    b'{"status":"not_ready","checks":{"identity":"unavailable"}}',
                )
            return good_response(name)

        result = probe.run_probe(opener=opener)
        self.assertEqual(calls, ["startup", "live", "ready"])
        self.assertEqual(result["classification"], "DEVELOPMENT_PUBLIC_READINESS_FAILED")
        self.assertEqual(result["failure_code"], "HTTP_STATUS_UNEXPECTED")
        self.assertEqual(result["failed_check"], "ready")
        self.assertEqual(result["passed_checks"], ["startup", "live"])
        self.assertFalse(result["credential_used"])

    def test_token_and_provider_payload_are_never_logged(self):
        sensitive = "DO_NOT_LOG_AUTH_TOKEN_AND_PERSONAL_DATA"

        def opener(request, *, timeout):
            raise urllib.error.URLError(socket.timeout(sensitive))

        result = probe.run_probe(opener=opener)
        self.assertEqual(result["failure_code"], "NETWORK_TIMEOUT")
        self.assertNotIn(sensitive, json.dumps(result))
        self.assertEqual(result["passed_checks"], [])

    def test_redirect_and_wrong_body_fail_closed(self):
        def redirected(request, *, timeout):
            raise urllib.error.HTTPError(
                "https://other.example.invalid", 302, "sensitive", {},
                io.BytesIO(b"private data"),
            )

        self.assertEqual(
            probe.run_probe(opener=redirected)["failure_code"],
            "HTTP_STATUS_UNEXPECTED",
        )

        def wrong_body(request, *, timeout):
            return FakeResponse(200, b'{"status":"ready"}')

        self.assertEqual(
            probe.run_probe(opener=wrong_body)["failure_code"],
            "HTTP_BODY_INVALID",
        )

    def test_oversize_and_invalid_json_fail_closed(self):
        def oversized(request, *, timeout):
            return FakeResponse(200, b"x" * (probe.MAX_BYTES + 50))

        self.assertEqual(
            probe.run_probe(opener=oversized)["failure_code"],
            "HTTP_BODY_OVERSIZED",
        )

        def invalid_json(request, *, timeout):
            return FakeResponse(200, b"invalid json")

        self.assertEqual(
            probe.run_probe(opener=invalid_json)["failure_code"],
            "HTTP_BODY_INVALID",
        )

    def test_invalid_invocation_never_opens_network(self):
        required = {
            "GITHUB_REPOSITORY": "AnonymousKoo/avuhz-infra",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_RUN_ATTEMPT": "1",
            "AVUHZ_CONFIRMATION": probe.CONFIRMATION,
        }
        probe.verify_invocation(required)
        for key in required:
            wrong = dict(required)
            wrong[key] = "not_authorized"
            with self.subTest(key=key), self.assertRaises(probe.PublicReadinessStop):
                probe.verify_invocation(wrong)

    def test_unhandled_error_classification_is_safe(self):
        def failing(request, *, timeout):
            raise RuntimeError("sensitive provider payload")

        result = probe.run_probe(opener=failing)
        self.assertEqual(result["failure_code"], "NETWORK_FAILED")
        self.assertNotIn("sensitive", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
