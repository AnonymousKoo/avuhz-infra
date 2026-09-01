"""Deterministic local tests for the DEVELOPMENT trusted-identity boundary."""
from __future__ import annotations

import sys
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_service.development import DevelopmentServiceSettings, create_development_application
from avuhz_service.development_identity import (
    DevelopmentTrustedIdentityResolver,
    VerifiedDevelopmentIdentityEvidence,
)


NOW = datetime(2030, 1, 15, 15, 0, tzinfo=timezone.utc)
TENANT = "00000000-0000-4000-8000-000000000021"
HANDLE = object()
DEFAULT_EVIDENCE = object()


def evidence(**changes):
    value = VerifiedDevelopmentIdentityEvidence(
        issuer="https://pwlhruwutoitnieactol.supabase.co/auth/v1",
        audience="audience.avuhz.command-service.development",
        subject="subject.development-user-1",
        tenant_id=TENANT,
        caller_type="WORKLOAD",
        capabilities=frozenset({"engagement:read", "implementation_brief:draft"}),
        authority_roles=frozenset(),
        environment="DEVELOPMENT",
        authentication_strength="STRONG",
        step_up_performed=False,
        authenticated_at="2030-01-15T14:00:00Z",
        expires_at="2030-01-15T16:00:00Z",
    )
    return replace(value, **changes)


class DeterministicFakeVerifier:
    """Test-only verifier that recognizes one in-memory opaque handle."""

    def __init__(self, result):
        self.result = result

    def verify(self, untrusted_identity):
        if untrusted_identity is not HANDLE:
            raise PermissionError("untrusted fake identity")
        return self.result


def resolver(result=DEFAULT_EVIDENCE):
    return DevelopmentTrustedIdentityResolver(
        DeterministicFakeVerifier(evidence() if result is DEFAULT_EVIDENCE else result),
        clock=lambda: NOW,
    )


class DevelopmentTrustedIdentityResolverTests(unittest.TestCase):
    def test_exact_verified_evidence_maps_to_bounded_trusted_context(self):
        context = resolver().resolve(HANDLE)
        self.assertTrue(context.authenticated)
        self.assertEqual(context.principal_id, "subject.development-user-1")
        self.assertEqual(context.caller_type, "WORKLOAD")
        self.assertEqual(context.tenant_id, TENANT)
        self.assertEqual(context.environment, "DEVELOPMENT")
        self.assertEqual(context.audience, "avuhz-command-api")
        self.assertEqual(
            context.capabilities,
            frozenset({"engagement:read", "implementation_brief:draft"}),
        )
        self.assertEqual(context.authority_roles, frozenset())
        self.assertIsNone(context.human_authority_role)
        self.assertIsNone(context.human_principal_reference)
        self.assertIsNone(context.human_organization_reference)

    def test_identity_and_authority_negatives_fail_closed(self):
        cases = {
            "issuer": evidence(issuer="https://issuer.invalid"),
            "audience": evidence(audience="audience.avuhz.command-service.staging"),
            "tenant": evidence(tenant_id="not-a-tenant"),
            "subject": evidence(subject="INVALID SUBJECT"),
            "caller_type": evidence(caller_type="SUPERUSER"),
            "capability": evidence(capabilities=frozenset({"deployment:unbounded"})),
            "capability_shape": evidence(capabilities=["engagement:read"]),
            "authority": evidence(authority_roles=frozenset({"CLIENT_DEPLOYMENT_AUTHORITY"})),
            "environment": evidence(environment="STAGING"),
            "strength": evidence(authentication_strength="UNBOUNDED"),
            "step_up": evidence(authentication_strength="STEP_UP", step_up_performed=False),
            "expired": evidence(expires_at="2030-01-15T15:00:00Z"),
            "future": evidence(authenticated_at="2030-01-15T15:00:01Z"),
            "timestamp": evidence(authenticated_at="not-a-timestamp"),
        }
        for name, invalid in cases.items():
            with self.subTest(name=name), self.assertRaises(PermissionError):
                resolver(invalid).resolve(HANDLE)

    def test_malformed_or_unverified_evidence_fails_closed(self):
        for invalid in ({"subject": "spoofed"}, object(), None):
            with self.subTest(type=type(invalid).__name__), self.assertRaises(PermissionError):
                resolver(invalid).resolve(HANDLE)
        with self.assertRaises(PermissionError):
            resolver().resolve(object())

    def test_live_development_composition_remains_unavailable_and_not_ready(self):
        source = (ROOT / "src/avuhz_service/development.py").read_text()
        self.assertNotIn("DevelopmentTrustedIdentityResolver", source)
        settings = DevelopmentServiceSettings.from_environment({
            "AVUHZ_SERVICE_ENVIRONMENT": "DEVELOPMENT",
            "AVUHZ_DATA_PROJECT_REF": "pwlhruwutoitnieactol",
            "AVUHZ_DATA_PROJECT_URL": "https://pwlhruwutoitnieactol.supabase.co",
            "AVUHZ_AUTH_PROJECT_REF": "pwlhruwutoitnieactol",
            "AVUHZ_AUTH_ISSUER": "https://pwlhruwutoitnieactol.supabase.co/auth/v1",
            "AVUHZ_SERVICE_AUDIENCE": "audience.avuhz.command-service.development",
            "AVUHZ_TENANT_BRIDGE": "TrustedExecutionContext.tenant_id -> avuhz.tenant_id",
            "AVUHZ_RLS_POLICY_REFERENCE": "policy.avuhz.tenant-rls.development.v1",
            "AVUHZ_COMMAND_SERVICE_IDENTITY": "avuhz_command_service_dev",
            "PORT": "10000",
        })
        application = create_development_application(settings)
        self.assertFalse(application.readiness_probes["identity"].ready())
        self.assertFalse(application.readiness_probes["data"].ready())
        with self.assertRaises(PermissionError):
            application.identity_resolver.resolve(HANDLE)


if __name__ == "__main__":
    unittest.main()
