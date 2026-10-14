"""Offline signed-JWT to shared HTTP intake composition certification.

Uses a fresh in-memory ES256 keypair and a TEST JWKS lookup, never live
Supabase AUTH, DATA, hosted n8n, or a customer. Positive DATA and limiter
are existing synthetic doubles; this certifies the real signature and
identity boundary in front of the existing shared HTTP writer contract.
It does not mount an ingress or enroll a trusted service subject.
"""
from __future__ import annotations

import hashlib
import json
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import jwt
from cryptography.hazmat.primitives.asymmetric import ec

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests" / "service")]

from avuhz_service.development import DEVELOPMENT_AUTH_ISSUER, DEVELOPMENT_SERVICE_AUDIENCE
from avuhz_service.development_acquisition_composition import (
    create_unmounted_development_acquisition_http_candidate,
)
from avuhz_service.development_acquisition_service_identity_candidate import (
    DevelopmentAcquisitionServicePolicy,
)
from avuhz_service.development_supabase_jwt import DevelopmentSupabaseEs256JwtVerifier
from test_development_acquisition_http import request
from test_development_acquisition_ingress import TENANT_A, Store
from test_development_acquisition_service_identity_candidate import SUBJECT


class LocalJwkClient:
    def __init__(self, public_key):
        self.public_key = public_key
        self.seen = []

    def get_signing_key_from_jwt(self, token):
        self.seen.append(token)
        return SimpleNamespace(key=self.public_key)


class SignedAcquisitionHttpTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.client = LocalJwkClient(self.key.public_key())
        self.store = Store()
        self.admissions = []
        self.jwt_constructor = patch(
            "avuhz_service.development_acquisition_composition."
            "DevelopmentSupabaseEs256JwtVerifier",
            return_value=DevelopmentSupabaseEs256JwtVerifier(self.client),
        )
        self.data_constructor = patch(
            "avuhz_service.development_acquisition_composition."
            "create_hosted_development_acquisition_store",
            return_value=self.store,
        )
        self.limiter_constructor = patch(
            "avuhz_service.development_acquisition_composition."
            "DevelopmentPostgresAcquisitionRateLimiter",
            return_value=lambda tenant, principal: self.admissions.append(
                (tenant, principal),
            ) or True,
        )
        with self.jwt_constructor as crypto, self.data_constructor as data, self.limiter_constructor as limiter:
            self.app = create_unmounted_development_acquisition_http_candidate(
                service_policy=DevelopmentAcquisitionServicePolicy(
                    subject_digest="sha256:" + hashlib.sha256(SUBJECT.encode("ascii")).hexdigest(),
                    principal_reference="service.acquisition-development",
                    tenant_id=TENANT_A,
                ),
                acquisition_connection_factory=self._never_open_real_database,
                clock=lambda: self.now,
            )
            crypto.assert_called_once_with()
            data.assert_called_once()
            limiter.assert_called_once_with(self.store)
        self.assertEqual(self.store.connections, [])

    @staticmethod
    def _never_open_real_database():
        raise AssertionError("candidate cannot contact a hosted database")

    def payload(self, **changes):
        issued = int((self.now - timedelta(seconds=25)).timestamp())
        expiry = int((self.now + timedelta(minutes=5)).timestamp())
        result = {
            "iss": DEVELOPMENT_AUTH_ISSUER,
            "aud": DEVELOPMENT_SERVICE_AUDIENCE,
            "sub": SUBJECT,
            "iat": issued,
            "exp": expiry,
            "role": "authenticated",
            "aal": "aal1",
            "is_anonymous": False,
            "avuhz_tenant_id": TENANT_A,
            "app_metadata": {
                "avuhz_workload": "acquisition_intake",
                "avuhz_tenant_id": TENANT_A,
            },
        }
        result.update(changes)
        return result

    def sign(self, payload=None, *, key=None, algorithm="ES256"):
        if key is None:
            key = self.key
        return jwt.encode(
            self.payload() if payload is None else payload,
            key,
            algorithm=algorithm,
            headers={"kid": "ephemeral-offline-test-only"},
        )

    def send(self, token, **kwargs):
        return request(
            self.app,
            headers={"HTTP_AUTHORIZATION": "Bearer " + token, **kwargs.pop("headers", {})},
            **kwargs,
        )

    def test_real_es256_signature_enters_shared_writer_without_activating_route(self):
        token = self.sign()
        status, result, headers = self.send(token)
        self.assertEqual((status, result["duplicate"]), (202, False))
        self.assertEqual(result["intake_id"], "a4730000-0000-4000-8000-000000000031")
        self.assertEqual(self.client.seen, [token])
        self.assertEqual(self.admissions, [(TENANT_A, "service.acquisition-development")])
        self.assertEqual(len(self.store.connections), 2)
        self.assertEqual(self.store.connections[1].commits, 1)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertNotIn("alpha@example.invalid", json.dumps(result))
        self.assertNotIn(token, json.dumps(result))

    def test_valid_es256_signature_with_excess_workload_lifetime_is_denied(self):
        for lifetime in (3601, 24 * 60 * 60):
            with self.subTest(lifetime=lifetime):
                issued = int((self.now - timedelta(seconds=25)).timestamp())
                token = self.sign(self.payload(
                    iat=issued,
                    exp=issued + lifetime,
                ))
                status, body, _ = self.send(token)
                self.assertEqual(
                    (status, body),
                    (403, {"error": "acquisition_intake_not_authorized"}),
                )
                self.assertEqual(self.store.connections, [])
                self.assertEqual(self.admissions, [])

    def test_signature_forgery_and_algorithm_confusion_denied_before_data(self):
        bad_private = ec.generate_private_key(ec.SECP256R1())
        forged = self.sign(key=bad_private)
        hs256 = jwt.encode(
            self.payload(),
            "local-ephemeral-test-only-not-a-credential",
            algorithm="HS256",
            headers={"kid": "ephemeral-offline-test-only"},
        )
        for token in (forged, hs256, "x" * 48):
            with self.subTest(kind=token[:10]):
                status, body, _ = self.send(token)
                self.assertEqual((status, body), (
                    403, {"error": "acquisition_intake_not_authorized"},
                ))
                self.assertEqual(self.store.connections, [])
                self.assertEqual(self.admissions, [])

    def test_cross_tenant_and_invalid_claims_denied_despite_valid_signature(self):
        variants = (
            {"iss": "https://issuer.invalid"},
            {"aud": "authenticated"},
            {"role": "service_role"},
            {"aal": "aal2"},
            {"is_anonymous": True},
            {"sub": "55555555-5555-4555-8555-555555555555"},
            {"avuhz_tenant_id": "a4730000-0000-4000-8000-000000000002"},
            {"app_metadata": {"avuhz_workload": "acquisition_intake",
                              "avuhz_tenant_id": "a4730000-0000-4000-8000-000000000002"}},
            {"app_metadata": {"avuhz_workload": "implementation_handoff",
                              "avuhz_tenant_id": TENANT_A}},
            {"exp": int((self.now - timedelta(minutes=1)).timestamp())},
            {"iat": int((self.now + timedelta(minutes=2)).timestamp())},
        )
        for changes in variants:
            with self.subTest(changed=list(changes)):
                token = self.sign(self.payload(**changes))
                status, body, _ = self.send(
                    token,
                    headers={
                        "HTTP_X_AVUHZ_TENANT_ID": TENANT_A,
                        "HTTP_X_FORWARDED_PROTO": "https",
                    },
                )
                self.assertEqual((status, body), (
                    403, {"error": "acquisition_intake_not_authorized"},
                ))
                self.assertEqual(self.store.connections, [])
                self.assertEqual(self.admissions, [])

    def test_client_tenant_field_rejected_after_valid_signature_without_data(self):
        from test_development_acquisition_ingress import sample
        token = self.sign()
        status, body, _ = self.send(token, obj={**sample(), "tenant_id": TENANT_A})
        self.assertEqual((status, body), (403, {"error": "acquisition_intake_not_authorized"}))
        self.assertEqual(self.store.connections, [])
        self.assertEqual(self.admissions, [])

    def test_https_required_before_signature_verification_or_data(self):
        token = self.sign()
        status, body, _ = self.send(
            token, scheme="http", headers={"HTTP_X_FORWARDED_PROTO": "https"},
        )
        self.assertEqual((status, body), (403, {"error": "secure_transport_required"}))
        self.assertEqual(self.client.seen, [])
        self.assertEqual(self.store.connections, [])


if __name__ == "__main__":
    unittest.main()
