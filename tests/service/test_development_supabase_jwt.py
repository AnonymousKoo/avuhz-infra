"""Focused tests for the concrete DEVELOPMENT Supabase ES256/JWKS verifier."""
from __future__ import annotations

import sys
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

import jwt
from cryptography.hazmat.primitives.asymmetric import ec

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_service.development import (
    DEVELOPMENT_AUTH_ISSUER,
    DEVELOPMENT_SERVICE_AUDIENCE,
)
from avuhz_service.development_supabase_jwt import (
    DEVELOPMENT_AUTH_JWKS_URL,
    DevelopmentSupabaseEs256JwtVerifier,
)


SUBJECT = "11111111-1111-4111-8111-111111111111"
TENANT = "22222222-2222-4222-8222-222222222222"


def claims(**changes):
    now = int(time.time())
    values = {
        "iss": DEVELOPMENT_AUTH_ISSUER,
        "aud": DEVELOPMENT_SERVICE_AUDIENCE,
        "sub": SUBJECT,
        "iat": now - 5,
        "exp": now + 300,
        "role": "authenticated",
        "aal": "aal1",
        "is_anonymous": False,
        "avuhz_tenant_id": TENANT,
    }
    values.update(changes)
    return values


class StaticJwkClient:
    def __init__(self, public_key):
        self.public_key = public_key
        self.calls = []

    def get_signing_key_from_jwt(self, token):
        self.calls.append(token)
        return SimpleNamespace(key=self.public_key)


class DevelopmentSupabaseEs256JwtVerifierTests(unittest.TestCase):
    def setUp(self):
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()
        self.client = StaticJwkClient(self.public_key)
        self.verifier = DevelopmentSupabaseEs256JwtVerifier(self.client)

    def token(self, payload=None, *, key=None, algorithm="ES256"):
        signing_key = self.private_key if key is None else key
        return jwt.encode(payload or claims(), signing_key, algorithm=algorithm, headers={"kid": "local-test-key"})

    def test_exact_jwks_url_is_derived_from_approved_auth_issuer(self):
        self.assertEqual(
            DEVELOPMENT_AUTH_JWKS_URL,
            DEVELOPMENT_AUTH_ISSUER + "/.well-known/jwks.json",
        )

    def test_valid_es256_token_returns_verified_immutable_claims(self):
        token = self.token()
        verified = self.verifier.verify(token)

        self.assertEqual(self.client.calls, [token])
        self.assertEqual(verified["iss"], DEVELOPMENT_AUTH_ISSUER)
        self.assertEqual(verified["aud"], DEVELOPMENT_SERVICE_AUDIENCE)
        self.assertEqual(verified["sub"], SUBJECT)
        self.assertEqual(verified["avuhz_tenant_id"], TENANT)
        with self.assertRaises(TypeError):
            verified["sub"] = "changed"

    def test_invalid_signature_fails_closed(self):
        other_private_key = ec.generate_private_key(ec.SECP256R1())
        token = self.token(key=other_private_key)
        with self.assertRaises(PermissionError):
            self.verifier.verify(token)

    def test_algorithm_is_pinned_to_es256(self):
        token = jwt.encode(
            claims(),
            "local-hs256-test-secret-that-is-never-a-runtime-secret",
            algorithm="HS256",
            headers={"kid": "local-test-key"},
        )
        with self.assertRaises(PermissionError):
            self.verifier.verify(token)

    def test_registered_claim_mismatches_fail_closed(self):
        invalid_payloads = {
            "issuer": claims(iss="https://issuer.invalid/auth/v1"),
            "audience": claims(aud="authenticated"),
            "expired": claims(exp=int(time.time()) - 1),
            "not_before": claims(nbf=int(time.time()) + 300),
        }
        for name, payload in invalid_payloads.items():
            with self.subTest(name=name), self.assertRaises(PermissionError):
                self.verifier.verify(self.token(payload))

    def test_required_registered_claims_must_exist(self):
        for required in ("exp", "iat", "sub", "iss", "aud"):
            payload = claims()
            del payload[required]
            with self.subTest(required=required), self.assertRaises(PermissionError):
                self.verifier.verify(self.token(payload))

    def test_malformed_input_and_invalid_client_fail_closed(self):
        for invalid in (None, object(), "", "short", "x" * 16385):
            with self.subTest(type=type(invalid).__name__), self.assertRaises(PermissionError):
                self.verifier.verify(invalid)

        with self.assertRaises(ValueError):
            DevelopmentSupabaseEs256JwtVerifier(object())


if __name__ == "__main__":
    unittest.main()
