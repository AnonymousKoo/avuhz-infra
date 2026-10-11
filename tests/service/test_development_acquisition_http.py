"""TEST-only WSGI certification for unmounted shared acquisition HTTP ingress.

All identities and payloads below are synthetic. A test-only token verifier
does not prove production cryptography or authorize any provider mutation.
"""
from __future__ import annotations

import io
import json
import sys
import unittest
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests" / "service")]

from avuhz_service.development_acquisition_http import DevelopmentAcquisitionHttpAdapter
from avuhz_service.development_acquisition_ingress import DevelopmentAuthenticatedAcquisitionIngress
from avuhz_service.development_identity import DevelopmentTrustedIdentityResolver
from test_development_acquisition_ingress import (
    NOW, ORG_A, ORG_B, TENANT_A, Store, evidence, sample,
)

TOKEN = "fictional.test.only.identity.token.1234567"
PATH = "/v1/acquisition/intakes"


class FakeTokenVerifier:
    def __init__(self, proof):
        self.proof = proof

    def verify(self, opaque):
        if opaque != TOKEN:
            raise PermissionError("invalid fictional bearer")
        return self.proof


def application(*, store=None, proof=None, limiter=None, clock=None):
    store = Store() if store is None else store
    resolver = DevelopmentTrustedIdentityResolver(
        FakeTokenVerifier(evidence() if proof is None else proof),
        clock=lambda: NOW,
    )
    receive = DevelopmentAuthenticatedAcquisitionIngress(
        resolver,
        store,
        rate_limit_admit=(lambda tenant, principal: True) if limiter is None else limiter,
    )
    return DevelopmentAcquisitionHttpAdapter(
        receive, clock=(lambda: NOW) if clock is None else clock,
    ), store


def request(
    app,
    *,
    method="POST",
    path=PATH,
    headers=None,
    obj=None,
    raw=None,
    content_length=None,
    scheme="https",
):
    if raw is None:
        raw = json.dumps(sample() if obj is None else obj).encode("utf-8")
    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "CONTENT_TYPE": "application/json",
        "CONTENT_LENGTH": str(len(raw)) if content_length is None else content_length,
        "wsgi.input": io.BytesIO(raw),
        "wsgi.url_scheme": scheme,
        "HTTP_AUTHORIZATION": "Bearer " + TOKEN,
    }
    if headers:
        environ.update(headers)
    capture = {}

    def start_response(status, response_headers):
        capture["status"] = int(status.split()[0])
        capture["headers"] = dict(response_headers)

    rendered = b"".join(app(environ, start_response))
    return capture["status"], json.loads(rendered), capture["headers"]


class SharedDevelopmentAcquisitionHttpTests(unittest.TestCase):
    def test_real_shared_validator_and_writer_are_exercised_by_http_request(self):
        app, store = application()
        status, result, headers = request(app)
        self.assertEqual(status, 202)
        self.assertEqual(result, {
            "intake_id": "a4730000-0000-4000-8000-000000000031",
            "duplicate": False,
        })
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertNotIn("alpha@example.invalid", json.dumps(result))
        self.assertEqual(len(store.connections), 2)
        self.assertEqual(store.connections[0].calls[0][1], (TENANT_A,))
        self.assertEqual(store.connections[0].calls[1][1], (TENANT_A,))
        self.assertEqual(store.connections[1].calls[2][1][1:3], (TENANT_A, ORG_A))
        self.assertEqual(store.connections[1].commits, 1)

    def test_no_token_bad_token_or_unsupported_auth_scheme_never_opens_data(self):
        for headers in (
            {"HTTP_AUTHORIZATION": ""},
            {"HTTP_AUTHORIZATION": None},
            {"HTTP_AUTHORIZATION": "Basic "+TOKEN},
            {"HTTP_AUTHORIZATION": "Bearer x"},
            {"HTTP_AUTHORIZATION": "Bearer "+TOKEN+" extra"},
            {"HTTP_AUTHORIZATION": "Bearer "+TOKEN+"\n"},
        ):
            with self.subTest(headers=headers):
                app, store = application()
                status, result, _ = request(app, headers=headers)
                self.assertEqual(status, 401)
                self.assertEqual(result, {"error": "bearer_authentication_required"})
                self.assertEqual(store.connections, [])

        app, store = application()
        status, result, _ = request(
            app, headers={"HTTP_AUTHORIZATION": "Bearer " + "x" * 40},
        )
        self.assertEqual(status, 403)
        self.assertEqual(result, {"error": "acquisition_intake_not_authorized"})
        self.assertEqual(store.connections, [])

    def test_environment_and_untrusted_headers_never_confer_authority(self):
        for payload in (
            {**sample(), "tenant_id": TENANT_A},
            {**sample(), "organization_id": ORG_A},
            {**sample(), "authority": {"accepted": True}},
        ):
            with self.subTest(field=list(payload)[-1]):
                app, store = application()
                status, result, _ = request(
                    app, obj=payload,
                    headers={
                        "HTTP_X_AVUHZ_TENANT_ID": TENANT_A,
                        "HTTP_X_AVUHZ_ORGANIZATION_ID": ORG_A,
                        "avuhz.trusted_identity": object(),
                    },
                )
                self.assertEqual(status, 403)
                self.assertEqual(result, {"error": "acquisition_intake_not_authorized"})
                self.assertEqual(store.connections, [])

    def test_transport_enforces_trusted_wsgi_scheme_not_forwarded_headers(self):
        app, store = application()
        status, result, _ = request(
            app, scheme="http", headers={"HTTP_X_FORWARDED_PROTO": "https"},
        )
        self.assertEqual(status, 403)
        self.assertEqual(result, {"error": "secure_transport_required"})
        self.assertEqual(store.connections, [])

    def test_only_exact_post_route_allowed(self):
        for method, path, expected in (
            ("GET", PATH, 405),
            ("PUT", PATH, 405),
            ("POST", "/v1/commands", 404),
            ("POST", PATH+"/", 404),
        ):
            with self.subTest(method=method, path=path):
                app, store = application()
                status, _, _ = request(app, method=method, path=path)
                self.assertEqual(status, expected)
                self.assertEqual(store.connections, [])

    def test_content_length_size_and_type_enforced_without_database_access(self):
        for kwargs, code in (
            ({"headers": {"CONTENT_TYPE": "text/plain"}}, 415),
            ({"headers": {"CONTENT_TYPE": "application/json; charset=utf-8"}}, 415),
            ({"content_length": ""}, 411),
            ({"content_length": "two"}, 411),
            ({"content_length": "99999999"}, 413),
            ({"raw": b""}, 400),
            ({"raw": b"{}", "content_length": "100"}, 400),
            ({"raw": b"{" + b"x" * 8192 + b"}"}, 413),
            ({"raw": b"not json"}, 400),
            ({"raw": b"[]"}, 400),
            ({"raw": b'{"one":1,"one":2}'}, 400),
            ({"raw": b'{"value":NaN}'}, 400),
            ({"raw": b"\xff"}, 400),
        ):
            with self.subTest(kwargs=kwargs):
                app, store = application()
                status, result, _ = request(app, **kwargs)
                self.assertEqual(status, code)
                self.assertIn("error", result)
                self.assertEqual(store.connections, [])

    def test_nonactive_or_ambiguous_company_stops_before_insert(self):
        for rows in ([], [{"organization_id": ORG_A}, {"organization_id": ORG_B}]):
            with self.subTest(rows=rows):
                app, store = application(store=Store(rows=rows))
                status, result, _ = request(app)
                self.assertEqual(status, 403)
                self.assertEqual(result, {"error": "acquisition_intake_not_authorized"})
                self.assertEqual(len(store.connections), 1)
                self.assertEqual(store.connections[0].commits, 0)

    def test_rate_limit_failure_and_data_failure_never_leak_input(self):
        app, store = application(limiter=lambda tenant, principal: False)
        status, result, _ = request(app)
        self.assertEqual(status, 403)
        self.assertEqual(result, {"error": "acquisition_intake_not_authorized"})
        self.assertEqual(len(store.connections), 1)

        app, store = application(store=Store(fail_lookup=True))
        status, result, _ = request(app)
        self.assertEqual(status, 503)
        self.assertEqual(result, {"error": "acquisition_intake_unavailable"})
        self.assertEqual(len(store.connections), 1)
        self.assertNotIn("alpha@example.invalid", str(result))
        self.assertNotIn(TOKEN, str(result))

    def test_identity_issuer_and_expiry_are_checked_before_any_data_access(self):
        for proof in (
            evidence(issuer="https://invalid.example"),
            evidence(expires_at="2030-01-15T14:59:59Z"),
            evidence(capabilities=frozenset({"engagement:read"})),
            evidence(caller_type="HUMAN"),
        ):
            app, store = application(proof=proof)
            status, result, _ = request(app)
            self.assertEqual(status, 403)
            self.assertEqual(result, {"error": "acquisition_intake_not_authorized"})
            self.assertEqual(store.connections, [])

    def test_default_hosted_composition_never_registers_http_intake_route(self):
        text = (ROOT / "src" / "avuhz_service" / "development.py").read_text()
        self.assertNotIn("DevelopmentAcquisitionHttpAdapter", text)
        application_source = (ROOT / "src" / "avuhz_service" / "application.py").read_text()
        self.assertNotIn(PATH, application_source)
        from avuhz_service.development_supabase_identity import DEVELOPMENT_IDENTITY_ALLOWLIST
        for entry in DEVELOPMENT_IDENTITY_ALLOWLIST:
            self.assertNotIn("acquisition_intake:receive", entry.capabilities)


if __name__ == "__main__":
    unittest.main()
