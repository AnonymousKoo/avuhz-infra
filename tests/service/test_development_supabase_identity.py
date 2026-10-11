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
    DEVELOPMENT_IDENTITY_ALLOWLIST,
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

    def test_provider_adapter_policy_maps_to_exact_single_handoff_capability(self):
        provider_subject = "33333333-3333-4333-8333-333333333333"
        provider_entry = DevelopmentIdentityAllowlistEntry(
            subject_digest=digest(provider_subject),
            principal_reference="provider-adapter.sekinfra-development",
            tenant_id=TENANT,
            caller_type="PROVIDER_ADAPTER",
            capabilities=frozenset({"implementation_handoff:accept"}),
        )
        verifier = DevelopmentSupabaseIdentityVerifier(
            FakeCryptographicVerifier(claims(sub=provider_subject)),
            allowlist=(entry(), provider_entry),
        )

        evidence = verifier.verify(TOKEN)

        self.assertEqual(evidence.subject, "provider-adapter.sekinfra-development")
        self.assertEqual(evidence.tenant_id, TENANT)
        self.assertEqual(evidence.caller_type, "PROVIDER_ADAPTER")
        self.assertEqual(evidence.capabilities, frozenset({"implementation_handoff:accept"}))
        self.assertNotIn("engagement:read", evidence.capabilities)
        self.assertEqual(evidence.authority_roles, frozenset())
        self.assertEqual(evidence.authentication_strength, "STANDARD")

    def test_offline_acquisition_service_identity_requires_pinned_signed_workload(self):
        # This is an injection-only candidate: no AUTH subject is enrolled,
        # no credential issued and no live allowlist entry activated.
        provider_subject = "33333333-3333-4333-8333-333333333333"
        service_subject = "44444444-4444-4444-8444-444444444444"
        provider = DevelopmentIdentityAllowlistEntry(
            subject_digest=digest(provider_subject),
            principal_reference="provider-adapter.sekinfra-development",
            tenant_id=TENANT,
            caller_type="PROVIDER_ADAPTER",
            capabilities=frozenset({"implementation_handoff:accept"}),
        )
        service = DevelopmentIdentityAllowlistEntry(
            subject_digest=digest(service_subject),
            principal_reference="service.acquisition-development",
            tenant_id=TENANT,
            caller_type="INTERNAL_SERVICE",
            capabilities=frozenset({"acquisition_intake:receive"}),
        )
        allowlist = (entry(), provider, service)
        approved_metadata = {
            "avuhz_workload": "acquisition_intake",
            "avuhz_tenant_id": TENANT,
        }
        assert len(DEVELOPMENT_IDENTITY_ALLOWLIST) == 2
        assert all(e.caller_type != "INTERNAL_SERVICE" for e in DEVELOPMENT_IDENTITY_ALLOWLIST)
        actual = DevelopmentSupabaseIdentityVerifier(
            FakeCryptographicVerifier(claims(
                sub=service_subject, app_metadata=approved_metadata,
            )),
            allowlist=allowlist,
        ).verify(TOKEN)
        self.assertEqual(actual.subject, "service.acquisition-development")
        self.assertEqual(actual.tenant_id, TENANT)
        self.assertEqual(actual.caller_type, "INTERNAL_SERVICE")
        self.assertEqual(actual.capabilities, frozenset({"acquisition_intake:receive"}))
        self.assertEqual(actual.authority_roles, frozenset())
        self.assertNotIn("engagement:read", actual.capabilities)
        self.assertNotIn("implementation_handoff:accept", actual.capabilities)

        for untrusted in (
            claims(sub=service_subject),
            claims(sub=service_subject, user_metadata=approved_metadata),
            claims(sub=service_subject, app_metadata={"avuhz_workload": "acquisition_intake"}),
            claims(sub=service_subject, app_metadata={
                "avuhz_workload": "acquisition_intake",
                "avuhz_tenant_id": "55555555-5555-4555-8555-555555555555",
            }),
            claims(sub=service_subject, app_metadata={
                "avuhz_workload": "implementation_handoff",
                "avuhz_tenant_id": TENANT,
            }),
            claims(sub=service_subject, app_metadata="acquisition_intake"),
            claims(sub="66666666-6666-4666-8666-666666666666",
                   app_metadata=approved_metadata),
            claims(sub=service_subject, role="service_role",
                   app_metadata=approved_metadata),
            claims(sub=service_subject, avuhz_tenant_id="77777777-7777-4777-8777-777777777777",
                   app_metadata=approved_metadata),
        ):
            with self.subTest(untrusted=sorted(untrusted)), self.assertRaises(PermissionError):
                DevelopmentSupabaseIdentityVerifier(
                    FakeCryptographicVerifier(untrusted), allowlist=allowlist,
                ).verify(TOKEN)

        for invalid in (
            {"capabilities": frozenset({"engagement:read"})},
            {"capabilities": frozenset({"implementation_handoff:accept"})},
            {"capabilities": frozenset({"acquisition_intake:receive", "engagement:read"})},
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                DevelopmentIdentityAllowlistEntry(
                    subject_digest=digest(service_subject),
                    principal_reference="service.acquisition-development",
                    tenant_id=TENANT, caller_type="INTERNAL_SERVICE", **invalid,
                )

        # An unactivated service policy cannot reclassify the existing
        # provider-adapter identity or confer rights to the hosted allowlist.
        with self.assertRaises(PermissionError):
            DevelopmentSupabaseIdentityVerifier(
                FakeCryptographicVerifier(claims(
                    sub=service_subject, app_metadata=approved_metadata,
                )),
                allowlist=DEVELOPMENT_IDENTITY_ALLOWLIST,
            ).verify(TOKEN)

    def test_allowlist_shape_is_bounded_unique_and_caller_capabilities_are_exact(self):
        provider_subject = "33333333-3333-4333-8333-333333333333"
        provider_entry = DevelopmentIdentityAllowlistEntry(
            subject_digest=digest(provider_subject),
            principal_reference="provider-adapter.sekinfra-development",
            tenant_id=TENANT,
            caller_type="PROVIDER_ADAPTER",
            capabilities=frozenset({"implementation_handoff:accept"}),
        )
        with self.assertRaises(ValueError):
            DevelopmentSupabaseIdentityVerifier(FakeCryptographicVerifier(claims()), allowlist=())
        with self.assertRaises(ValueError):
            DevelopmentSupabaseIdentityVerifier(
                FakeCryptographicVerifier(claims(sub=provider_subject)),
                allowlist=(provider_entry,),
            )
        with self.assertRaises(ValueError):
            DevelopmentSupabaseIdentityVerifier(
                FakeCryptographicVerifier(claims()),
                allowlist=(entry(), provider_entry, DevelopmentIdentityAllowlistEntry(
                    subject_digest=digest("44444444-4444-4444-8444-444444444444"),
                    principal_reference="provider-adapter.second-development",
                    tenant_id="55555555-5555-4555-8555-555555555555",
                    caller_type="PROVIDER_ADAPTER",
                    capabilities=frozenset({"implementation_handoff:accept"}),
                )),
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
            {"caller_type": "INTERNAL_SERVICE"},
            {"capabilities": frozenset({"implementation_handoff:accept"})},
            {"caller_type": "PROVIDER_ADAPTER", "capabilities": frozenset({"engagement:read"})},
            {"caller_type": "PROVIDER_ADAPTER", "capabilities": frozenset({"implementation_handoff:accept", "engagement:read"})},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                entry(**changes)


if __name__ == "__main__":
    unittest.main()
