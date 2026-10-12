"""Offline TEST certification for dormant shared DEVELOPMENT authenticated intake.

Every identity and acquisition payload in this file is fictional. An in-memory
verifier demonstrates only the interface contract, not real AUTH access or
permission to turn on a hosted intake endpoint.
"""
from __future__ import annotations

import sys
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_service.acquisition_intake_command import AcquisitionIntakeUnavailable
from avuhz_service.development import (
    DEVELOPMENT_AUTH_ISSUER,
    DEVELOPMENT_SERVICE_AUDIENCE,
)
from avuhz_service.development_acquisition_ingress import (
    DevelopmentAuthenticatedAcquisitionIngress,
)
from avuhz_service.development_identity import (
    DevelopmentTrustedIdentityResolver,
    VerifiedDevelopmentIdentityEvidence,
)


TENANT_A = "a4730000-0000-4000-8000-000000000001"
TENANT_B = "a4730000-0000-4000-8000-000000000002"
ORG_A = "a4730000-0000-4000-8000-000000000011"
ORG_B = "a4730000-0000-4000-8000-000000000012"
NOW = datetime(2030, 1, 15, 15, 0, tzinfo=timezone.utc)
TEST_HANDLE = object()


def evidence(tenant=TENANT_A, **changes):
    result = VerifiedDevelopmentIdentityEvidence(
        issuer=DEVELOPMENT_AUTH_ISSUER,
        audience=DEVELOPMENT_SERVICE_AUDIENCE,
        subject="service.shared-acquisition-test",
        tenant_id=tenant,
        caller_type="INTERNAL_SERVICE",
        capabilities=frozenset({"acquisition_intake:receive"}),
        authority_roles=frozenset(),
        environment="DEVELOPMENT",
        authentication_strength="STRONG",
        step_up_performed=False,
        authenticated_at="2030-01-15T14:59:00Z",
        expires_at="2030-01-15T15:10:00Z",
    )
    return replace(result, **changes)


class SyntheticTestVerifier:
    def __init__(self, proof):
        self.proof = proof

    def verify(self, candidate):
        if candidate is not TEST_HANDLE:
            raise PermissionError("synthetic untrusted identity")
        return self.proof


def sample(company="Fictional Alpha Services", email="alpha@example.invalid"):
    return {
        "external_request_id": "a4730000-0000-4000-8000-000000000021",
        "source_system": "sekinfra.website",
        "route_reference": "diagnostic.oia",
        "business_name": company,
        "contact_name": "Example Operator",
        "contact_email": email,
        "contact_phone": None,
        "preferred_contact_method": "EMAIL",
        "contact_requested": True,
        "diagnostic_summary": "Sekinfra website problem check; path=OPERATIONAL_INFRASTRUCTURE_ASSESSMENT",
    }


class Cursor:
    def __init__(self, row=None, rows=(), rowcount=1):
        self.row = row
        self.rows = list(rows)
        self.rowcount = rowcount

    def fetchone(self):
        return self.row

    def fetchall(self):
        return self.rows


class LookupConnection:
    autocommit = False

    def __init__(self, rows=(), fail=False):
        self.rows = rows
        self.fail = fail
        self.calls = []
        self.rollbacks = 0
        self.commits = 0
        self.closed = False

    def execute(self, sql, args=()):
        self.calls.append((sql, args))
        if "set_config('avuhz.tenant_id'" in sql:
            return Cursor()
        if "select distinct org.organization_id" in sql:
            if self.fail:
                raise RuntimeError("private database diagnostics")
            return Cursor(rows=self.rows)
        raise AssertionError("unexpected lookup statement")

    def rollback(self):
        self.rollbacks += 1

    def commit(self):
        self.commits += 1

    def close(self):
        self.closed = True


class WriterConnection:
    autocommit = False

    def __init__(self, authorized=True):
        self.authorized = authorized
        self.calls = []
        self.rollbacks = 0
        self.commits = 0
        self.closed = False

    def execute(self, sql, args=()):
        self.calls.append((sql, args))
        if "set_config('avuhz.tenant_id'" in sql:
            return Cursor()
        if "from public.avuhz_tenant_organizations" in sql:
            return Cursor({"authorized": 1} if self.authorized else None)
        if "insert into public.avuhz_acquisition_intake_requests" in sql:
            return Cursor({"intake_id": "a4730000-0000-4000-8000-000000000031"})
        if "insert into public.avuhz_lifecycle_events" in sql:
            return Cursor()
        if "insert into public.avuhz_outbox_deliveries" in sql:
            return Cursor(rowcount=1)
        raise AssertionError("unexpected writer statement")

    def rollback(self):
        self.rollbacks += 1

    def commit(self):
        self.commits += 1

    def close(self):
        self.closed = True


class Store:
    def __init__(self, org=ORG_A, *, rows=None, authorized=True, fail_lookup=False):
        self.rows = ([{"organization_id": org}] if rows is None else rows)
        self.authorized = authorized
        self.fail_lookup = fail_lookup
        self.connections = []

    def connection_factory(self):
        if not self.connections:
            result = LookupConnection(self.rows, self.fail_lookup)
        else:
            result = WriterConnection(self.authorized)
        self.connections.append(result)
        return result


def service(store=None, proof=None, limiter=None):
    store = Store() if store is None else store
    resolver = DevelopmentTrustedIdentityResolver(
        SyntheticTestVerifier(evidence() if proof is None else proof),
        clock=lambda: NOW,
    )
    limiter = (lambda tenant, principal: True) if limiter is None else limiter
    return DevelopmentAuthenticatedAcquisitionIngress(
        resolver, store, rate_limit_admit=limiter,
    ), store


class SharedAuthenticatedAcquisitionIngressTests(unittest.TestCase):
    def test_two_independent_fictional_tenants_use_one_shared_ingress(self):
        for tenant, org, company, email in (
            (TENANT_A, ORG_A, "Fictional Alpha Services", "alpha@example.invalid"),
            (TENANT_B, ORG_B, "Fictional Beta Logistics", "beta@example.invalid"),
        ):
            with self.subTest(tenant=tenant):
                admission = []
                ingress, store = service(
                    Store(org),
                    evidence(tenant),
                    lambda t, principal: admission.append((t, principal)) or True,
                )
                receipt = ingress.receive(
                    untrusted_identity=TEST_HANDLE,
                    untrusted_payload=sample(company, email),
                    evaluated_at=NOW,
                )
                self.assertFalse(receipt.duplicate)
                self.assertEqual(admission, [(tenant, "service.shared-acquisition-test")])
                self.assertEqual(len(store.connections), 2)
                lookup, write = store.connections
                self.assertEqual(lookup.calls[0][1], (tenant,))
                self.assertEqual(lookup.calls[1][1], (tenant,))
                self.assertIn("member.verified_at is not null", lookup.calls[1][0])
                self.assertIn("limit 2", lookup.calls[1][0])
                self.assertEqual(lookup.commits, 0)
                self.assertEqual(lookup.rollbacks, 1)
                self.assertTrue(lookup.closed)
                self.assertEqual(write.calls[0][1], (tenant,))
                self.assertEqual(write.calls[1][1], (tenant, org))
                self.assertEqual(write.calls[2][1][1:3], (tenant, org))
                self.assertEqual(len(write.calls), 5)
                self.assertIn("insert into public.avuhz_lifecycle_events", write.calls[3][0])
                self.assertEqual(write.calls[3][1][1], tenant)
                self.assertEqual(write.calls[3][1][3], "acquisition.intake.received")
                self.assertNotIn(email, str(write.calls[3][1]))
                self.assertIn("insert into public.avuhz_outbox_deliveries", write.calls[4][0])
                self.assertEqual(write.calls[4][1][1], "PENDING")
                self.assertEqual(write.commits, 1)
                self.assertTrue(write.closed)
                self.assertNotIn("tenant_id", sample())
                self.assertNotIn("organization_id", sample())

    def test_untrusted_identity_or_client_authority_denied_before_database(self):
        for payload, identity in (
            (sample(), object()),
            ({**sample(), "tenant_id": TENANT_B}, TEST_HANDLE),
            ({**sample(), "organization_id": ORG_B}, TEST_HANDLE),
            ({**sample(), "authority": {"admin": True}}, TEST_HANDLE),
            ({**sample(), "contact_requested": False}, TEST_HANDLE),
        ):
            with self.subTest(case=list(payload)):
                ingress, store = service()
                with self.assertRaisesRegex(
                    PermissionError, "^acquisition_intake_not_authorized$"
                ):
                    ingress.receive(
                        untrusted_identity=identity,
                        untrusted_payload=payload,
                        evaluated_at=NOW,
                    )
                self.assertEqual(store.connections, [])

    def test_unapproved_caller_capabilities_and_provider_evidence_are_denied(self):
        cases = (
            {"caller_type": "HUMAN"},
            {"caller_type": "PROVIDER_ADAPTER"},
            {"capabilities": frozenset({"engagement:read"})},
            {"capabilities": frozenset({"acquisition_intake:receive", "engagement:read"})},
            {"environment": "PRODUCTION"},
            {"issuer": "https://example.invalid/auth"},
            {"audience": "browser"},
            {"authenticated_at": "2030-01-15T14:30:00Z"},
            {"expires_at": "2030-01-15T15:00:00Z"},
            {"tenant_id": "not-a-tenant"},
        )
        for change in cases:
            with self.subTest(change=change):
                ingress, store = service(proof=evidence(**change))
                with self.assertRaisesRegex(
                    PermissionError, "^acquisition_intake_not_authorized$"
                ):
                    ingress.receive(
                        untrusted_identity=TEST_HANDLE,
                        untrusted_payload=sample(),
                        evaluated_at=NOW,
                    )
                self.assertEqual(store.connections, [])

    def test_absent_ambiguous_or_invalid_company_denies_before_writer(self):
        for rows in (
            [],
            [{"organization_id": ORG_A}, {"organization_id": ORG_B}],
            [{"organization_id": "not-a-uuid"}],
            [{"organization_id": None}],
            [{"wrong_field": ORG_A}],
        ):
            with self.subTest(rows=rows):
                ingress, store = service(Store(rows=rows))
                with self.assertRaisesRegex(
                    PermissionError, "^acquisition_intake_not_authorized$"
                ):
                    ingress.receive(
                        untrusted_identity=TEST_HANDLE,
                        untrusted_payload=sample(),
                        evaluated_at=NOW,
                    )
                self.assertEqual(len(store.connections), 1)
                lookup = store.connections[0]
                self.assertTrue(lookup.closed)
                self.assertEqual(lookup.rollbacks, 1)

    def test_inactive_owner_recheck_is_fail_closed_after_readonly_lookup(self):
        ingress, store = service(Store(authorized=False))
        with self.assertRaisesRegex(
            PermissionError, "^acquisition_intake_not_authorized$"
        ):
            ingress.receive(
                untrusted_identity=TEST_HANDLE,
                untrusted_payload=sample(),
                evaluated_at=NOW,
            )
        self.assertEqual(len(store.connections), 2)
        write = store.connections[1]
        self.assertFalse(any("insert into" in sql for sql, _ in write.calls))
        self.assertEqual(write.commits, 0)
        self.assertEqual(write.rollbacks, 1)

    def test_database_failure_is_sanitized_and_no_payload_is_logged(self):
        ingress, store = service(Store(fail_lookup=True))
        with self.assertRaises(AcquisitionIntakeUnavailable) as caught:
            ingress.receive(
                untrusted_identity=TEST_HANDLE,
                untrusted_payload=sample(),
                evaluated_at=NOW,
            )
        self.assertEqual(str(caught.exception), "acquisition_intake_unavailable")
        self.assertNotIn("private database diagnostics", str(caught.exception))
        self.assertNotIn("alpha@example.invalid", str(caught.exception))
        self.assertEqual(len(store.connections), 1)
        self.assertTrue(store.connections[0].closed)

    def test_rate_limit_denial_causes_no_write(self):
        admissions = []
        ingress, store = service(
            limiter=lambda t, p: admissions.append((t, p)) or False
        )
        with self.assertRaisesRegex(
            PermissionError, "^acquisition_intake_not_authorized$"
        ):
            ingress.receive(
                untrusted_identity=TEST_HANDLE,
                untrusted_payload=sample(),
                evaluated_at=NOW,
            )
        self.assertEqual(admissions, [(TENANT_A, "service.shared-acquisition-test")])
        self.assertEqual(len(store.connections), 1)

    def test_requires_actual_shared_identity_resolver_not_static_context(self):
        with self.assertRaisesRegex(ValueError, "approved DEVELOPMENT identity"):
            DevelopmentAuthenticatedAcquisitionIngress(
                lambda identity: evidence(), Store(), rate_limit_admit=lambda t, p: True,
            )

    def test_hosted_identity_remains_ungranted_and_public_intake_not_connected(self):
        from avuhz_service.development_supabase_identity import DEVELOPMENT_IDENTITY_ALLOWLIST
        for entry in DEVELOPMENT_IDENTITY_ALLOWLIST:
            self.assertNotIn("acquisition_intake:receive", entry.capabilities)
        source = (ROOT / "src" / "avuhz_service" / "development.py").read_text()
        self.assertNotIn("DevelopmentAuthenticatedAcquisitionIngress(", source)
        application = (ROOT / "src" / "avuhz_service" / "application.py").read_text()
        self.assertNotIn("/v1/acquisition", application)
        self.assertNotIn("/v1/intake", application)


if __name__ == "__main__":
    unittest.main()
