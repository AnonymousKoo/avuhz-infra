"""Offline-only tests for the shared Avuhz acquisition service identity candidate.

Synthetic AUTH claims, subjects and tokens only. Nothing touches hosted AUTH,
DATA, credentials, website intake, billing, Render, n8n, or customer records.
"""
from __future__ import annotations

import hashlib
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_service.development import DEVELOPMENT_AUTH_ISSUER, DEVELOPMENT_SERVICE_AUDIENCE
from avuhz_service.development_acquisition_service_identity_candidate import (
    MAX_ACQUISITION_TOKEN_LIFETIME_SECONDS,
    DevelopmentAcquisitionServiceIdentityCandidate, DevelopmentAcquisitionServicePolicy,
)
from avuhz_service.development_identity import DevelopmentTrustedIdentityResolver
from avuhz_service.development_supabase_identity import DEVELOPMENT_IDENTITY_ALLOWLIST


SUBJECT = "44444444-4444-4444-8444-444444444444"
TENANT = "22222222-2222-4222-8222-222222222222"
TOKEN = "fictional.jwt.not.a.real.identity.token.1234567"
NOW = datetime(2030, 1, 15, 15, 0, tzinfo=timezone.utc)
ISSUED = int(datetime(2030, 1, 15, 14, 55, tzinfo=timezone.utc).timestamp())
EXPIRES = int(datetime(2030, 1, 15, 15, 5, tzinfo=timezone.utc).timestamp())


def policy(**changes):
    values = {
        "subject_digest": "sha256:" + hashlib.sha256(SUBJECT.encode("ascii")).hexdigest(),
        "principal_reference": "service.acquisition-development",
        "tenant_id": TENANT,
    }
    values.update(changes)
    return DevelopmentAcquisitionServicePolicy(**values)


def claims(**changes):
    value = {
        "iss": DEVELOPMENT_AUTH_ISSUER,
        "aud": DEVELOPMENT_SERVICE_AUDIENCE,
        "sub": SUBJECT,
        "avuhz_tenant_id": TENANT,
        "role": "authenticated",
        "aal": "aal1",
        "is_anonymous": False,
        "iat": ISSUED,
        "exp": EXPIRES,
        "app_metadata": {
            "avuhz_workload": "acquisition_intake",
            "avuhz_tenant_id": TENANT,
        },
    }
    value.update(changes)
    return value


class FakeSignedJwtVerifier:
    def __init__(self, verified_claims):
        self.verified_claims = verified_claims
        self.calls = []

    def verify(self, token):
        self.calls.append(token)
        if token != TOKEN:
            raise PermissionError("fictional JWT invalid")
        return self.verified_claims


class AcquisitionServiceIdentityCandidateTests(unittest.TestCase):
    def test_synthetic_signed_workload_is_single_capability_and_trusted_context(self):
        fake = FakeSignedJwtVerifier(claims())
        verifier = DevelopmentAcquisitionServiceIdentityCandidate(fake, policy())
        evidence = verifier.verify(TOKEN)
        self.assertEqual(fake.calls, [TOKEN])
        self.assertEqual(evidence.subject, "service.acquisition-development")
        self.assertEqual(evidence.tenant_id, TENANT)
        self.assertEqual(evidence.caller_type, "INTERNAL_SERVICE")
        self.assertEqual(evidence.capabilities, frozenset({"acquisition_intake:receive"}))
        self.assertEqual(evidence.authority_roles, frozenset())
        self.assertNotIn("engagement:read", evidence.capabilities)
        self.assertNotIn("implementation_handoff:accept", evidence.capabilities)
        resolver = DevelopmentTrustedIdentityResolver(verifier, clock=lambda: NOW)
        bound = resolver.resolve(TOKEN)
        self.assertTrue(bound.authenticated)
        self.assertEqual(bound.tenant_id, TENANT)
        self.assertIsNone(bound.organization_id)
        self.assertEqual(bound.caller_type, "INTERNAL_SERVICE")
        self.assertEqual(bound.capabilities, frozenset({"acquisition_intake:receive"}))

    def test_untrusted_or_human_jwt_never_becomes_internal_service(self):
        cases = (
            claims(app_metadata=None),
            claims(app_metadata={}),
            claims(app_metadata={"avuhz_workload": "acquisition_intake"}),
            claims(app_metadata={"avuhz_workload": "implementation_handoff", "avuhz_tenant_id": TENANT}),
            claims(app_metadata={"avuhz_workload": "acquisition_intake", "avuhz_tenant_id": SUBJECT}),
            claims(app_metadata="acquisition_intake"),
            claims(app_metadata=None, user_metadata={"avuhz_workload": "acquisition_intake", "avuhz_tenant_id": TENANT}),
            claims(sub="55555555-5555-4555-8555-555555555555"),
            claims(avuhz_tenant_id=SUBJECT),
            claims(iss="https://wrong.invalid"),
            claims(aud="authenticated"),
            claims(role="service_role"),
            claims(aal="aal2"),
            claims(is_anonymous=True),
            claims(iat="invalid"),
            claims(exp=ISSUED),
            claims(exp=ISSUED - 1),
            claims(exp=True),
        )
        for candidate in cases:
            with self.subTest(fields=sorted(candidate)):
                verifier = DevelopmentAcquisitionServiceIdentityCandidate(
                    FakeSignedJwtVerifier(candidate), policy(),
                )
                with self.assertRaisesRegex(PermissionError, "^acquisition_service_identity_invalid$"):
                    verifier.verify(TOKEN)

    def test_signed_claims_must_have_bounded_workload_lifetime(self):
        self.assertEqual(MAX_ACQUISITION_TOKEN_LIFETIME_SECONDS, 3600)
        accepted = DevelopmentAcquisitionServiceIdentityCandidate(
            FakeSignedJwtVerifier(
                claims(exp=ISSUED + MAX_ACQUISITION_TOKEN_LIFETIME_SECONDS),
            ), policy(),
        )
        result = DevelopmentTrustedIdentityResolver(
            accepted, clock=lambda: NOW,
        ).resolve(TOKEN)
        self.assertEqual(result.capabilities, frozenset({"acquisition_intake:receive"}))
        self.assertEqual(result.caller_type, "INTERNAL_SERVICE")
        for expiry in (
            ISSUED + MAX_ACQUISITION_TOKEN_LIFETIME_SECONDS + 1,
            ISSUED + 24 * 60 * 60,
            ISSUED + 30 * 24 * 60 * 60,
        ):
            with self.subTest(lifetime_seconds=expiry - ISSUED):
                candidate = DevelopmentAcquisitionServiceIdentityCandidate(
                    FakeSignedJwtVerifier(claims(exp=expiry)), policy(),
                )
                with self.assertRaisesRegex(
                    PermissionError, "^acquisition_service_identity_invalid$",
                ):
                    candidate.verify(TOKEN)

    def test_subject_credential_and_policy_confusion_fail_closed(self):
        verifier = DevelopmentAcquisitionServiceIdentityCandidate(
            FakeSignedJwtVerifier(claims()), policy(),
        )
        for token in (None, "", "short", "x" * 16385, TOKEN + "not-valid"):
            with self.subTest(credential_type=type(token).__name__):
                with self.assertRaisesRegex(PermissionError, "^acquisition_service_identity_invalid$"):
                    verifier.verify(token)

        for invalid in (
            {"subject_digest": "not-a-digest"},
            {"subject_digest": DEVELOPMENT_IDENTITY_ALLOWLIST[0].subject_digest},
            {"subject_digest": DEVELOPMENT_IDENTITY_ALLOWLIST[1].subject_digest},
            {"principal_reference": "provider-adapter.shared"},
            {"principal_reference": "INVALID PRINCIPAL"},
            {"tenant_id": "wrong-tenant"},
        ):
            with self.subTest(invalid=sorted(invalid)):
                with self.assertRaises(ValueError):
                    policy(**invalid)

        for invalid in (None, object(), "not-policy"):
            with self.assertRaises(ValueError):
                DevelopmentAcquisitionServiceIdentityCandidate(
                    FakeSignedJwtVerifier(claims()), invalid,
                )

    def test_existing_hosted_policy_stays_unmodified_and_service_unenrolled(self):
        self.assertEqual(len(DEVELOPMENT_IDENTITY_ALLOWLIST), 2)
        self.assertEqual(
            {x.caller_type for x in DEVELOPMENT_IDENTITY_ALLOWLIST},
            {"HUMAN", "PROVIDER_ADAPTER"},
        )
        self.assertTrue(all(
            "acquisition_intake:receive" not in x.capabilities
            for x in DEVELOPMENT_IDENTITY_ALLOWLIST
        ))
        source = (ROOT / "src" / "avuhz_service" / "development.py").read_text()
        self.assertNotIn("DevelopmentAcquisitionServiceIdentityCandidate", source)
        source = (ROOT / "src" / "avuhz_service" / "application.py").read_text()
        self.assertNotIn("/v1/acquisition/intakes", source)


if __name__ == "__main__":
    unittest.main()
