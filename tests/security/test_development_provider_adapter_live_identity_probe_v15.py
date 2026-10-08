"""Credential-free offline coverage of the proposed DEVELOPMENT live identity probe."""
from __future__ import annotations

import io
import json
import socket
import unittest
import urllib.error
from unittest.mock import patch

from avuhz_engineering.development_auth_token_lifecycle import (
    IssuedSession,
    JwtValidationResult,
    RecoveryVerificationCredential,
    SafeLifecycleStop,
)
from avuhz_service.development import DEVELOPMENT_AUTH_ISSUER, DEVELOPMENT_SERVICE_AUDIENCE
from avuhz_service.development_supabase_identity import (
    DEVELOPMENT_PROVIDER_ADAPTER_IMPLEMENTATION_HANDOFF_ENTRY,
)
from scripts import development_provider_adapter_live_identity_probe_v15 as probe
from scripts import development_provider_adapter_positive_auth_v4 as lifecycle

FAKE_TOKEN = "fixture-not-an-actual-jwt-" + ("x" * 70)


class _Response:
    def __init__(self, status: int, body: bytes):
        self.status = status
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def getcode(self):
        return self.status

    def read(self, limit: int):
        return self.body[:limit]


def _http_error(status: int, body: bytes) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        probe.DEVELOPMENT_QUERY_URL,
        status,
        "DO_NOT_EMIT_PROVIDER_RESPONSE",
        {},
        io.BytesIO(body),
    )


class ProviderAdapterLiveIdentityProbeV15Tests(unittest.TestCase):
    def test_exact_400_invalid_query_passes_with_one_post_and_no_retry(self) -> None:
        requests = []

        def opener(request, *, timeout):
            requests.append((request, timeout))
            raise _http_error(400, b'{"error":"invalid_query"}')

        probe.authenticated_live_identity_probe(FAKE_TOKEN, opener=opener)
        self.assertEqual(len(requests), 1)
        request, timeout = requests[0]
        self.assertEqual(request.full_url, probe.DEVELOPMENT_QUERY_URL)
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(request.data, b"{}")
        self.assertEqual(request.get_header("Authorization"), "Bearer " + FAKE_TOKEN)
        self.assertEqual(request.get_header("Content-type"), "application/json")
        self.assertEqual(timeout, probe.PROBE_TIMEOUT_SECONDS)

    def test_fails_closed_with_safe_specific_codes(self) -> None:
        cases = (
            (_http_error(401, b"PRIVATE_JWT_OR_SUBJECT"), "LIVE_PROBE_IDENTITY_REJECTED"),
            (_http_error(403, b"PRIVATE_JWT_OR_SUBJECT"), "LIVE_PROBE_AUTHORIZATION_DENIED"),
            (_http_error(302, b"PRIVATE_JWT_OR_SUBJECT"), "LIVE_PROBE_REDIRECT_REJECTED"),
            (_http_error(503, b"PRIVATE_JWT_OR_SUBJECT"), "LIVE_PROBE_SERVICE_UNAVAILABLE"),
            (_http_error(400, b'{"error":"trusted_identity_required"}'), "LIVE_PROBE_RESPONSE_SHAPE_INVALID"),
            (_http_error(400, b'{"error":"invalid_query","leak":"private"}'), "LIVE_PROBE_RESPONSE_SHAPE_INVALID"),
            (_http_error(400, b"x" * 4097), "LIVE_PROBE_RESPONSE_SHAPE_INVALID"),
        )
        for error, expected in cases:
            with self.subTest(code=expected):
                with self.assertRaises(SafeLifecycleStop) as caught:
                    probe.authenticated_live_identity_probe(
                        FAKE_TOKEN, opener=lambda *_args, **_kwargs: (_ for _ in ()).throw(error)
                    )
                self.assertEqual(caught.exception.code, expected)
                self.assertNotIn("PRIVATE", str(caught.exception))
                self.assertNotIn(FAKE_TOKEN, repr(caught.exception))

    def test_200_is_not_false_positive(self):
        with self.assertRaises(SafeLifecycleStop) as caught:
            probe.authenticated_live_identity_probe(
                FAKE_TOKEN, opener=lambda *_args, **_kwargs: _Response(200, b'{"error":"invalid_query"}')
            )
        self.assertEqual(caught.exception.code, "LIVE_PROBE_UNEXPECTED_HTTP_STATUS")

    def test_timeout_dns_and_tls_are_sanitized(self):
        for exception, expected in (
            (socket.timeout("PRIVATE_TOKEN"), "LIVE_PROBE_NETWORK_TIMEOUT"),
            (urllib.error.URLError(socket.gaierror("PRIVATE_TOKEN")), "LIVE_PROBE_DNS_FAILURE"),
            (urllib.error.URLError("PRIVATE_TOKEN"), "LIVE_PROBE_NETWORK_FAILURE"),
        ):
            with self.subTest(code=expected):
                with self.assertRaises(SafeLifecycleStop) as caught:
                    probe.authenticated_live_identity_probe(
                        FAKE_TOKEN,
                        opener=lambda *_args, **_kwargs: (_ for _ in ()).throw(exception),
                    )
                self.assertEqual(caught.exception.code, expected)
                self.assertNotIn("PRIVATE_TOKEN", str(caught.exception))

    def test_missing_or_bad_token_prevents_request(self):
        for invalid in (None, "", "short", " " * 60, "x" * 80 + "\n"):
            with self.subTest(value_type=type(invalid).__name__):
                def unexpected_opener(*args, **kwargs):
                    self.fail("no network request permitted for invalid token")
                with self.assertRaises(SafeLifecycleStop) as caught:
                    probe.authenticated_live_identity_probe(invalid, opener=unexpected_opener)
                self.assertEqual(caught.exception.code, "LIVE_PROBE_CREDENTIAL_UNAVAILABLE")

    def test_redirect_handler_never_follows(self):
        handler = probe._RejectRedirects()
        self.assertIsNone(handler.redirect_request(None, None, 302, "redirect", {}, "https://other.invalid"))

    def test_existing_lifecycle_still_logs_out_and_clears_session_on_probe_failure(self):
        entry = DEVELOPMENT_PROVIDER_ADAPTER_IMPLEMENTATION_HANDOFF_ENTRY
        credential = RecoveryVerificationCredential(
            "fixture-recovery-material-value",
            user_id="33333333-3333-4333-8333-333333333333",
        )
        session = IssuedSession(
            access_token=FAKE_TOKEN,
            refresh_token="fixture-refresh-material-long-enough",
            expires_in=3600,
            expires_at=1800000000,
            token_type="bearer",
            user_id="33333333-3333-4333-8333-333333333333",
        )
        validated = JwtValidationResult(
            algorithm="ES256",
            issuer=DEVELOPMENT_AUTH_ISSUER,
            audience=DEVELOPMENT_SERVICE_AUDIENCE,
            subject_digest=entry.subject_digest,
            tenant_id=entry.tenant_id,
            role="authenticated",
            aal="aal1",
            is_anonymous=False,
            caller_type="PROVIDER_ADAPTER",
            capabilities=("implementation_handoff:accept",),
            authority_roles=(),
        )
        events = []

        def reject_probe(_token):
            events.append("probe")
            raise SafeLifecycleStop("LIVE_PROBE_NETWORK_TIMEOUT")

        with self.assertRaises(SafeLifecycleStop) as caught:
            lifecycle.execute_positive_auth(
                admin_secret="fixture-admin",
                publishable_key="fixture-publishable",
                generate=lambda **_: (events.append("generate") or credential),
                verify=lambda **_: (events.append("verify") or session),
                validate_jwt=lambda _: (events.append("validate") or validated),
                live_probe=reject_probe,
                logout_global=lambda **_: events.append("logout"),
            )
        self.assertEqual(caught.exception.code, "LIVE_PROBE_NETWORK_TIMEOUT")
        self.assertEqual(events, ["generate", "verify", "validate", "probe", "logout"])
        self.assertTrue(credential.is_cleared)
        self.assertTrue(session.is_cleared)


if __name__ == "__main__":
    unittest.main()
