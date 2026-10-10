"""Offline tests for the dormant signed owner MFA freshness boundary.

No hosted Supabase calls. Ephemeral ES256 keys are created in memory only.
No real AUTH session, tenant, owner, or production record is used.
"""
from __future__ import annotations

import hashlib
import json
import sys
import time
import unittest
from unittest.mock import patch
from urllib import request as url_request
from pathlib import Path
from types import SimpleNamespace

import jwt
from cryptography.hazmat.primitives.asymmetric import ec

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_service.development import (
    DEVELOPMENT_AUTH_ISSUER, DEVELOPMENT_SERVICE_AUDIENCE,
)
from avuhz_service.development_owner_mfa_freshness import (
    DevelopmentOwnerMfaFreshnessCheck,
    DevelopmentAuthUserSessionCheck,
)
from avuhz_service.development_supabase_jwt import (
    DevelopmentSupabaseEs256JwtVerifier,
)
from avuhz_service.development_owner_authentication import (
    DevelopmentOwnerAuthenticationCheckpoint,
)
from avuhz_service.development_tenant_registration import (
    DevelopmentTenantRegistrationCandidate,
)

_SUBJECT = "33333333-3333-4333-8333-333333333333"
_SESSION = "44444444-4444-4444-8444-444444444444"


class TestJwks:
    def __init__(self, public_key):
        self.public_key = public_key

    def get_signing_key_from_jwt(self, _token):
        return SimpleNamespace(key=self.public_key)


class DummyCursor:
    def __init__(self, row):
        self.row = row

    def fetchone(self):
        return self.row


class FakeConnection:
    autocommit = False

    def __init__(self):
        self.queries = []
        self.commits = 0
        self.rollbacks = 0
        self.closes = 0

    def execute(self, sql, values=()):
        self.queries.append((sql, values))
        if "set_config('avuhz.tenant_id'" in sql:
            return DummyCursor({"set": True})
        if "insert into public.avuhz_tenant_organizations" in sql:
            return DummyCursor({"tenant_id": values[0]})
        if "insert into public.avuhz_tenant_owner_memberships" in sql:
            return DummyCursor({"tenant_id": values[0]})
        raise AssertionError("unexpected SQL")

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1

    def close(self):
        self.closes += 1


class FakeStore:
    def __init__(self):
        self.connection = FakeConnection()

    def connection_factory(self):
        return self.connection


class OwnerMfaFreshnessTests(unittest.TestCase):
    def setUp(self):
        self.private = ec.generate_private_key(ec.SECP256R1())
        self.verifier = DevelopmentSupabaseEs256JwtVerifier(
            TestJwks(self.private.public_key())
        )
        self.now = int(time.time())
        self.claims = {
            "iss": DEVELOPMENT_AUTH_ISSUER,
            "aud": DEVELOPMENT_SERVICE_AUDIENCE,
            "sub": _SUBJECT,
            "session_id": _SESSION,
            "role": "authenticated",
            "is_anonymous": False,
            "aal": "aal2",
            "iat": self.now - 1,
            "exp": self.now + 240,
            "amr": [
                {"method": "password", "timestamp": self.now - 100},
                {"method": "totp", "timestamp": self.now - 3},
            ],
        }
        self.digest = "sha256:" + hashlib.sha256(_SUBJECT.encode()).hexdigest()
        self.checked = []
        self.seen_bearers = []

    def token(self, **changes):
        return jwt.encode({**self.claims, **changes}, self.private, algorithm="ES256")

    def gate(self, admitted=True):
        def live_session(subject, session, bearer):
            self.checked.append((subject, session))
            self.seen_bearers.append(bearer)
            return admitted
        return DevelopmentOwnerMfaFreshnessCheck(
            self.verifier, confirm_live_session=live_session
        )

    def test_signed_recent_totp_and_live_subject_session_match(self):
        bearer = self.token()
        self.assertTrue(self.gate()(bearer, self.digest))
        self.assertEqual(self.checked, [(_SUBJECT, _SESSION)])
        self.assertEqual(self.seen_bearers, [bearer])

    def test_aal2_and_recent_iat_do_not_substitute_for_mfa(self):
        variations = [
            {"amr": [{"method": "password", "timestamp": self.now - 3}]},
            {"amr": [{"method": "otp", "timestamp": self.now - 3}]},
            {"amr": [{"method": "totp", "timestamp": self.now - 400}]},
            {"amr": [{"method": "totp", "timestamp": self.now + 20}]},
            {"amr": [{"method": "totp", "timestamp": True}]},
            {"amr": [{"method": "totp", "timestamp": "2026-10-10"}]},
            {"amr": [{"method": "totp", "timestamp": self.now}]},
            {"amr": []},
            {"amr": None},
            {"amr": {"method": "totp", "timestamp": self.now - 3}},
        ]
        for patch in variations:
            with self.subTest(patch=repr(patch)):
                self.checked.clear()
                self.assertFalse(self.gate()(self.token(**patch), self.digest))
                self.assertEqual(self.checked, [])

    def test_session_and_claim_mismatch_denied_before_live_check(self):
        variations = [
            {"session_id": "not-a-uuid"},
            {"session_id": None},
            {"role": "anon"},
            {"aal": "aal1"},
            {"is_anonymous": True},
            {"iss": "https://different-project.example/auth/v1"},
            {"aud": "browser"},
            {"sub": "not-a-uuid"},
            {"avuhz_tenant_id": "55555555-5555-4555-8555-555555555555"},
        ]
        for patch in variations:
            with self.subTest(patch=repr(patch)):
                self.checked.clear()
                self.assertFalse(self.gate()(self.token(**patch), self.digest))
                self.assertEqual(self.checked, [])
        self.assertFalse(self.gate()(self.token(), "sha256:" + "0" * 64))
        self.assertFalse(self.gate()(self.token(), "malformed"))
        self.assertFalse(self.gate()(None, self.digest))

    def test_live_session_false_non_boolean_or_error_fails_closed(self):
        for state in (False, None, 1, "true"):
            with self.subTest(state=repr(state)):
                self.checked.clear()
                self.assertFalse(self.gate(admitted=state)(
                    self.token(), self.digest
                ))
                self.assertEqual(self.checked, [(_SUBJECT, _SESSION)])
        def provider_error(_sub, _session, _bearer):
            raise RuntimeError("private mock AUTH provider diagnostics")
        self.assertFalse(DevelopmentOwnerMfaFreshnessCheck(
            self.verifier, confirm_live_session=provider_error
        )(self.token(), self.digest))

    def test_invalid_signature_is_never_replaced_with_decoded_jwt(self):
        outsider = ec.generate_private_key(ec.SECP256R1())
        forged = jwt.encode(self.claims, outsider, algorithm="ES256")
        self.assertFalse(self.gate()(forged, self.digest))
        self.assertEqual(self.checked, [])

    def test_gate_does_not_expose_bearer_or_session_in_repr(self):
        gate = self.gate()
        self.assertNotIn(_SESSION, repr(gate))
        self.assertNotIn(self.token(), repr(gate))

    def test_registration_candidate_uses_existing_proof_port_without_new_auth(self):
        auth_checkpoint = DevelopmentOwnerAuthenticationCheckpoint(self.verifier)
        store = FakeStore()
        mfa = self.gate()
        register = DevelopmentTenantRegistrationCandidate(
            store, auth_checkpoint,
            check_fresh_auth_mfa=mfa,
            # Local synthetic owner proof. Never a hosted implementation.
            check_business_owner=lambda _digest, _business, _env: True,
        )
        receipt = register.propose(
            untrusted_bearer=self.token(),
            business_reference="business.fictional",
        )
        self.assertEqual(receipt.state, "PENDING_VERIFICATION")
        self.assertEqual(store.connection.commits, 1)
        self.assertEqual(self.checked, [(_SUBJECT, _SESSION)])
        self.assertEqual(len(store.connection.queries), 3)

    def test_denied_session_prevents_all_registration_writes(self):
        store = FakeStore()
        register = DevelopmentTenantRegistrationCandidate(
            store, DevelopmentOwnerAuthenticationCheckpoint(self.verifier),
            check_fresh_auth_mfa=self.gate(admitted=False),
            check_business_owner=lambda _digest, _business, _env: True,
        )
        with self.assertRaisesRegex(
            PermissionError, "^tenant_registration_not_authorized$"
        ):
            register.propose(
                untrusted_bearer=self.token(),
                business_reference="business.fictional",
            )
        self.assertEqual(store.connection.queries, [])
        self.assertEqual(store.connection.commits, 0)


class FakeAuthUserResponse:
    def __init__(self, body, *, status=200, url=None):
        self.status = status
        self.url = url or "https://pwlhruwutoitnieactol.supabase.co/auth/v1/user"
        self.body = body if isinstance(body, bytes) else json.dumps(body).encode()

    def geturl(self):
        return self.url

    def read(self, limit):
        return self.body[:limit]

    def __enter__(self):
        return self

    def __exit__(self, kind, value, trace):
        return False


class FakeAuthOpener:
    def __init__(self, response=None, failure=None):
        self.response = response
        self.failure = failure
        self.requests = []

    def open(self, request, *, timeout):
        self.requests.append((request, timeout))
        if self.failure:
            raise self.failure
        return self.response


class DevelopmentAuthUserSessionCheckTests(unittest.TestCase):
    def setUp(self):
        # Clearly synthetic publishable-key-shaped value, never a usable key.
        self.key = "sb_" + "publishable_" + ("x" * 32)
        self.bearer = ("a" * 48) + "." + ("b" * 48) + "." + ("c" * 48)

    def build(self, response=None, failure=None):
        opener = FakeAuthOpener(
            response or FakeAuthUserResponse({"id": _SUBJECT}), failure=failure
        )
        with patch.object(url_request, "build_opener", return_value=opener):
            checker = DevelopmentAuthUserSessionCheck(self.key)
        return checker, opener

    def test_fixed_development_auth_user_request_and_no_elevated_key(self):
        checker, opener = self.build()
        self.assertTrue(checker(_SUBJECT, _SESSION, self.bearer))
        self.assertEqual(len(opener.requests), 1)
        req, timeout = opener.requests[0]
        self.assertEqual(req.full_url, "https://pwlhruwutoitnieactol.supabase.co/auth/v1/user")
        self.assertEqual(req.get_method(), "GET")
        self.assertEqual(req.get_header("Authorization"), "Bearer " + self.bearer)
        self.assertEqual(req.get_header("Apikey"), self.key)
        self.assertEqual(timeout, 5)
        self.assertNotIn("service_role", repr(checker))
        self.assertNotIn(self.bearer, repr(checker))
        self.assertNotIn(self.key, repr(checker))

    def test_denies_nonmatching_or_bad_auth_user_responses(self):
        for response in (
            FakeAuthUserResponse({"id": "44444444-4444-4444-8444-444444444444"}),
            FakeAuthUserResponse({"error": "invalid_token"}),
            FakeAuthUserResponse({"id": _SUBJECT}, status=401),
            FakeAuthUserResponse({"id": _SUBJECT}, status=302),
            FakeAuthUserResponse(
                {"id": _SUBJECT},
                url="https://gnuqaefotwgkwurjpyik.supabase.co/auth/v1/user",
            ),
            FakeAuthUserResponse(b"not json"),
            FakeAuthUserResponse(b"{" + b"x" * 9000),
            FakeAuthUserResponse([{"id": _SUBJECT}]),
        ):
            with self.subTest(status=response.status, url=response.url):
                checker, _ = self.build(response)
                self.assertFalse(checker(_SUBJECT, _SESSION, self.bearer))

    def test_denies_network_failures_and_never_exposes_diagnostics(self):
        checker, _ = self.build(
            failure=RuntimeError("private synthetic AUTH diagnostic")
        )
        self.assertFalse(checker(_SUBJECT, _SESSION, self.bearer))

    def test_denies_untrusted_inputs_before_network(self):
        for subject, session, bearer in (
            (_SUBJECT, "invalid", self.bearer),
            ("invalid", _SESSION, self.bearer),
            (_SUBJECT, _SESSION, "x"),
            (_SUBJECT, _SESSION, self.bearer + "\n"),
            (_SUBJECT, _SESSION, self.bearer + "\r"),
            (_SUBJECT, _SESSION, self.bearer + " "),
            (_SUBJECT, _SESSION, self.bearer + "\\n"),
        ):
            checker, opener = self.build()
            self.assertFalse(checker(subject, session, bearer))
            self.assertEqual(opener.requests, [])

    def test_rejects_missing_or_non_publishable_configuration(self):
        for value in (None, "", "synthetic", "sb_secret_synthetic", "sb_publishable_x"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    DevelopmentAuthUserSessionCheck(value)

    def test_mfa_gate_invokes_live_provider_with_exact_verified_bearer(self):
        original = OwnerMfaFreshnessTests("test_signed_recent_totp_and_live_subject_session_match")
        original.setUp()
        token = original.token()
        checker, opener = self.build(FakeAuthUserResponse({"id": _SUBJECT}))
        gate = DevelopmentOwnerMfaFreshnessCheck(
            original.verifier, confirm_live_session=checker
        )
        self.assertTrue(gate(token, original.digest))
        self.assertEqual(len(opener.requests), 1)
        self.assertEqual(
            opener.requests[0][0].get_header("Authorization"), "Bearer " + token
        )


if __name__ == "__main__":
    unittest.main()
