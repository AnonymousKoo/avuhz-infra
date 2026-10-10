"""No-provider tests for the pinned one-attempt DEVELOPMENT command HTTPS sender.

All transport responses and tokens are fabricated. No Render, Supabase,
n8n, GitHub workflow, customer, credential or production contact occurs.
"""
from __future__ import annotations

import io
import json
import sys
import unittest
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.development_handoff_command_https import (
    DevelopmentOneShotCommandHttps, HandoffCommandTransportStop,
    _NeverRedirectBearer,
)
from avuhz_engineering.development_source_bound_handoff_lifecycle import COMMAND_URL
from avuhz_engineering.development_synthetic_handoff_preflight import (
    MAX_COMMAND_RESPONSE_BYTES,
)

_HANDOFF_ID = "70000000-0000-4000-8000-000000000001"
_ACCEPTED = json.dumps({
    "result": "ACCEPTED", "reason_code": "COMMAND_ACCEPTED",
    "authoritative_record_reference": _HANDOFF_ID,
}).encode()
_TOKEN = "synthetic." + ("x" * 62) + ".signature"


def command():
    # Transport is downstream from the independently authenticated
    # preflight/approval/claim layers. This payload is intentionally fictitious.
    return {
        "command_type": "AcceptImplementationHandoff",
        "subject_id": _HANDOFF_ID,
        "source": "fictional.only",
    }


class FakeResponse:
    def __init__(self, status=202, data=_ACCEPTED, url=COMMAND_URL):
        self.status = status
        self.data = data
        self.url = url
        self.reads = 0

    def geturl(self):
        return self.url

    def read(self, n):
        self.reads += 1
        return self.data[:n]

    def __enter__(self):
        return self

    def __exit__(self, kind, exc, traceback):
        return False


class FakeOpener:
    def __init__(self, response=None, error=None):
        self.response = response if response is not None else FakeResponse()
        self.error = error
        self.requests = []

    def open(self, req, *, timeout):
        self.requests.append((req, timeout))
        if self.error is not None:
            raise self.error
        return self.response


class SpyBody(io.BytesIO):
    def __init__(self, value):
        super().__init__(value)
        self.reads = 0

    def read(self, *args, **kwargs):
        self.reads += 1
        return super().read(*args, **kwargs)


class HandoffHttpsTests(unittest.TestCase):
    def fake_transport(self, response=None, error=None):
        opener = FakeOpener(response, error=error)
        with patch("urllib.request.build_opener", return_value=opener):
            # The real method builds the opener on send, so patch must stay
            # active for the whole simulated send. Tests use helper below.
            pass
        return opener

    def send(self, transport, *, response=None, error=None, payload=None, token=_TOKEN):
        opener = FakeOpener(response, error=error)
        with patch("urllib.request.build_opener", return_value=opener):
            result = transport(command() if payload is None else payload, token)
        return result, opener

    def test_exact_https_origin_method_headers_body_and_no_live_secrets(self):
        sender = DevelopmentOneShotCommandHttps()
        (status, body), opener = self.send(sender)
        self.assertEqual((status, body), (202, _ACCEPTED))
        self.assertEqual(len(opener.requests), 1)
        req, timeout = opener.requests[0]
        self.assertEqual(req.full_url, "https://avuhz-command-dev.onrender.com/v1/commands")
        self.assertEqual(req.get_method(), "POST")
        self.assertEqual(req.get_header("Authorization"), "Bearer " + _TOKEN)
        self.assertEqual(req.get_header("Content-type"), "application/json")
        self.assertEqual(req.data, json.dumps(
            command(), sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False,
        ).encode())
        self.assertEqual(timeout, 10)
        self.assertNotIn(_TOKEN, repr(sender))
        self.assertNotIn("service_role", repr(sender))
        with self.assertRaisesRegex(
            HandoffCommandTransportStop, "^HANDOFF_TRANSPORT_ATTEMPT_ALREADY_CONSUMED$"
        ):
            self.send(sender)
        self.assertEqual(len(opener.requests), 1)

    def test_exact_error_status_does_not_read_provider_body_or_retry(self):
        for status in (200, 302, 401, 403, 409, 422, 429, 500, 503):
            with self.subTest(status=status):
                sender = DevelopmentOneShotCommandHttps()
                response = FakeResponse(status=status, data=b"private-provider-body")
                (code, body), opener = self.send(sender, response=response)
                self.assertEqual((code, body), (status, b""))
                self.assertEqual(response.reads, 0)
                self.assertEqual(len(opener.requests), 1)

    def test_httperror_status_classification_without_error_body(self):
        body = SpyBody(b"private-diagnostic-do-not-read")
        error = urllib.error.HTTPError(COMMAND_URL, 403, "deny", {}, body)
        (status, response), opener = self.send(
            DevelopmentOneShotCommandHttps(), error=error
        )
        self.assertEqual((status, response), (403, b""))
        self.assertEqual(body.reads, 0)
        self.assertEqual(len(opener.requests), 1)

    def test_transport_failure_is_sanitized_and_consumes_attempt(self):
        sender = DevelopmentOneShotCommandHttps()
        with self.assertRaisesRegex(
            HandoffCommandTransportStop, "^HANDOFF_TRANSPORT_OUTCOME_UNVERIFIED$"
        ) as failure:
            self.send(sender, error=RuntimeError("private provider diagnostic"))
        self.assertNotIn("private provider diagnostic", str(failure.exception))
        with self.assertRaisesRegex(
            HandoffCommandTransportStop, "^HANDOFF_TRANSPORT_ATTEMPT_ALREADY_CONSUMED$"
        ):
            self.send(sender)

    def test_redirected_success_and_large_result_are_denied_without_retry(self):
        for response in (
            FakeResponse(url="https://different.invalid/redirect"),
            FakeResponse(data=b"X" * (MAX_COMMAND_RESPONSE_BYTES + 4)),
        ):
            sender = DevelopmentOneShotCommandHttps()
            with self.assertRaisesRegex(
                HandoffCommandTransportStop, "^HANDOFF_TRANSPORT_OUTCOME_UNVERIFIED$"
            ):
                self.send(sender, response=response)
            with self.assertRaisesRegex(
                HandoffCommandTransportStop, "^HANDOFF_TRANSPORT_ATTEMPT_ALREADY_CONSUMED$"
            ):
                self.send(sender)

    def test_invalid_credentials_command_or_size_denied_before_network(self):
        for payload, token in (
            ([], _TOKEN),
            (command(), ""),
            (command(), _TOKEN + " "),
            (command(), _TOKEN + "\n"),
            (command(), _TOKEN + "\r"),
            (command(), _TOKEN + "\x00"),
            ({"unserializable": object()}, _TOKEN),
            ({"too_large": "x" * 70000}, _TOKEN),
        ):
            with self.subTest(input_type=type(payload).__name__):
                sender = DevelopmentOneShotCommandHttps()
                with self.assertRaisesRegex(
                    HandoffCommandTransportStop, "^HANDOFF_TRANSPORT_INPUT_INVALID$"
                ):
                    self.send(sender, payload=payload, token=token)
                self.assertFalse(sender._attempted)

    def test_redirect_handler_never_reuses_bearer(self):
        handler = _NeverRedirectBearer()
        redirected = handler.redirect_request(
            urllib.request.Request(
                COMMAND_URL, headers={"Authorization": "Bearer " + _TOKEN}
            ),
            None, 302, "Found", {},
            "https://attacker.invalid/collect",
        )
        self.assertIsNone(redirected)

    def test_concurrent_same_instance_can_only_transmit_once(self):
        sender = DevelopmentOneShotCommandHttps()
        opener = FakeOpener()
        with patch("urllib.request.build_opener", return_value=opener):
            def invoke(_):
                try:
                    return sender(command(), _TOKEN)[0]
                except HandoffCommandTransportStop as error:
                    return str(error)
            with ThreadPoolExecutor(max_workers=8) as pool:
                results = list(pool.map(invoke, range(16)))
        self.assertEqual(results.count(202), 1)
        self.assertEqual(
            results.count("HANDOFF_TRANSPORT_ATTEMPT_ALREADY_CONSUMED"), 15
        )
        self.assertEqual(len(opener.requests), 1)

    def test_real_transport_opener_disables_proxies_and_redirects(self):
        built = []
        def capture(*handlers):
            built.extend(handlers)
            return FakeOpener()
        sender = DevelopmentOneShotCommandHttps()
        with patch("urllib.request.build_opener", side_effect=capture):
            self.assertEqual(sender(command(), _TOKEN)[0], 202)
        self.assertTrue(any(
            type(handler) is urllib.request.ProxyHandler and not handler.proxies
            for handler in built
        ))
        self.assertTrue(any(isinstance(handler, _NeverRedirectBearer) for handler in built))


if __name__ == "__main__":
    unittest.main()
