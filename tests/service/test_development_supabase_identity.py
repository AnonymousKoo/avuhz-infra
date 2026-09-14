"""Focused tests for the DEVELOPMENT Supabase identity policy boundary."""
from __future__ import annotations

import hashlib
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_service.development import (
    DEVELOPMENT_AUTH_ISSUER,
    DEVELOPMENT_SERVICE_AUDIENCE,
)
from avuhz_service.development_supabase_identity import (
    DevelopmentIdentityAllowlistEntry,
    DevelopmentSupabaseIdentityVerifier,
)


PROVIDER_SUBJECT = "11111111-1111-4111-8111-111111111111"
TENANT = "22222222-2222-4222-8222-222222222222"
TOKEN = "synthetic.jwt." + ("x" * 64)


def digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def entry(**changes):
    values = dict(
        subject_digest=digest(PROVIDER_SUBJECT),
        principal_reference="subject.development-synthetic-user",
        tenant_id=TENANT,
    )
    values.update(changes)
    return DevelopmentIdentityAllowlistEntry(**values)


def claims(**changes):
    values = dict(
        iss=DEVELOPMENT_AUTH_ISSUER,
        aud=DEVELOPMENT_SERVICE_AUDIENCE,
        sub=PROVIDER_SUBJECT,
        avuhz_tenant_id=TENANT,
        role="authenticated",
        aal="aal1",
        is_anonymous=False,
        iat=1894716000,
        exp=1894723200,
    )
    values.update(changes)
    return values


class FakeCryptographicVerifier:
    def __init__(self, verified_claims):
        self.verified_claims = verified_claims
        self.calls = []

    def verify(self, token):
        self.calls.append(token)
        if token != TOKEN:
            raise PermissionError("unverified token")
        return self.verified_claims


class DevelopmentSupabaseIdentityVerifierTests(unittest.TestCase):
    def test_verified_token_maps_to_exact_read_only_provider_neutral_evidence(self):
        cryptographic = FakeCryptographicVerifier(claims())
        verifier = DevelopmentSupabaseIdentityVerifier(
            cryptographic,
            allowlist=(entry(),),
        )

        evidence = verifier.verify(TOKEN)

        self.assertEqual(cryptographic.calls, [TOKEN])
        self.assertEqual(evidence.issuer, DEVELOPMENT_AUTH_ISSUER)
        self.assertEqual(evidence.audience, DEVELOPMENT_SERVICE_AUDIENCE)
        self.assertEqual(evidence.subject, "subject.development-synthetic-user")
        self.assertNotEqual(evidence.subject, PROVIDER_SUBJECT)
        self.assertEqual(evidence.tenant_id, TENANT)
        self.assertEqual(evidence.caller_type, "HUMAN")
        self.assertEqual(evidence.capabilities, frozenset({"engagement:read"}))
        self.assertEqual(evidence.authority_roles, frozenset())
        self.assertEqual(evidence.environment, "DEVELOPMENT")
        self.assertEqual(evidence.authentication_strength, "STANDARD")
        self.assertFalse(evidence.step_up_performed)
        self.assertEqual(evidence.authenticated_at, "2030-01-15T14:00:00Z")
        self.assertEqual(evidence.expires_at, "2030-01-15T16:00:00Z")

    def test_provider_subject_and_tenant_must_match_server_allowlist(self):
        for invalid_claims in (
            claims(sub="33333333-3333-4333-8333-333333333333"),
            claims(avuhz_tenant_id="44444444-4444-4444-8444-444444444444"),
        ):
            with self.subTest(invalid_claims=invalid_claims), self.assertRaises(PermissionError):
                DevelopmentSupabaseIdentityVerifier(
                    FakeCryptographicVerifier(invalid_claims),
                    allowlist=(entry(),),
                ).verify(TOKEN)

    def test_provider_and_authentication_claims_fail_closed(self):
        cases = {
            "issuer": claims(iss="https://issuer.invalid"),
            "audience": claims(aud="authenticated"),
            "subject_shape": claims(sub="not-a-uuid"),
            "tenant_shape": claims(avuhz_tenant_id="not-a-tenant"),
            "role": claims(role="service_role"),
            "aal": claims(aal="aal2"),
            "anonymous": claims(is_anonymous=True),
            "iat": claims(iat="1894716000"),
            "exp": claims(exp=True),
        }
        for name, invalid_claims in cases.items():
            with self.subTest(name=name), self.assertRaises(PermissionError):
                DevelopmentSupabaseIdentityVerifier(
                    FakeCryptographicVerifier(invalid_claims),
                    allowlist=(entry(),),
                ).verify(TOKEN)

    def test_unverified_or_malformed_identity_never_reaches_policy_as_trusted(self):
        verifier = DevelopmentSupabaseIdentityVerifier(
            FakeCryptographicVerifier(claims()),
            allowlist=(entry(),),
        )
        for invalid in (None, object(), "", "too-short", "y" * 16385):
            with self.subTest(type=type(invalid).__name__), self.assertRaises(PermissionError):
                verifier.verify(invalid)

        with self.assertRaises(PermissionError):
            verifier.verify("wrong.jwt." + ("z" * 64))

    def test_allowlist_shape_is_exact_and_single_entry(self):
        with self.assertRaises(ValueError):
            DevelopmentSupabaseIdentityVerifier(
                FakeCryptographicVerifier(claims()),
                allowlist=(),
            )
        with self.assertRaises(ValueError):
            DevelopmentSupabaseIdentityVerifier(
                FakeCryptographicVerifier(claims()),
                allowlist=(entry(), entry()),
            )
        for changes in (
            {"subject_digest": "sha256:not-a-digest"},
            {"principal_reference": "INVALID SUBJECT"},
            {"tenant_id": "not-a-tenant"},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                entry(**changes)


if __name__ == "__main__":
    unittest.main()
