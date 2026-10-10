"""Repository-only verification of dormant DEVELOPMENT owner registration.

These tests use synthetic ES256 signatures and fake transaction connections.
They never call AUTH, DATA, Render, n8n, Stripe or the SekInfra website.
"""
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
from avuhz_service.development_owner_authentication import (
    DevelopmentOwnerAuthenticationCheckpoint,
)
from avuhz_service.development_supabase_jwt import DevelopmentSupabaseEs256JwtVerifier
from avuhz_service.development_tenant_registration import (
    DevelopmentTenantRegistrationCandidate,
    TenantRegistrationConflict,
    TenantRegistrationUnavailable,
)


class KeySet:
    def __init__(self, public):
        self.public = public

    def get_signing_key_from_jwt(self, _token):
        return SimpleNamespace(key=self.public)


class Connection:
    autocommit = False

    def __init__(self, *, org_conflict=False, owner_conflict=False, fail=False):
        self.calls = []
        self.org_conflict = org_conflict
        self.owner_conflict = owner_conflict
        self.fail = fail
        self.commits = 0
        self.rollbacks = 0
        self.closes = 0

    def execute(self, sql, params=()):
        self.calls.append((sql, params))
        if "set_config('avuhz.tenant_id'" in sql:
            return self
        if self.fail:
            raise RuntimeError("private fake database credentials")
        if "insert into public.avuhz_tenant_organizations" in sql:
            return Cursor(None if self.org_conflict else {"tenant_id": params[0]})
        if "insert into public.avuhz_tenant_owner_memberships" in sql:
            return Cursor(None if self.owner_conflict else {"tenant_id": params[0]})
        raise AssertionError("Unexpected SQL")

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1

    def close(self):
        self.closes += 1


class Cursor:
    def __init__(self, value):
        self.value = value

    def fetchone(self):
        return self.value


class Store:
    def __init__(self, connection):
        self.connection = connection

    def connection_factory(self):
        return self.connection


class RegistrationCandidateTests(unittest.TestCase):
    def setUp(self):
        self.private = ec.generate_private_key(ec.SECP256R1())
        verifier = DevelopmentSupabaseEs256JwtVerifier(
            KeySet(self.private.public_key())
        )
        self.checkpoint = DevelopmentOwnerAuthenticationCheckpoint(verifier)
        now = int(time.time())
        self.claims = {
            "iss": DEVELOPMENT_AUTH_ISSUER,
            "aud": "authenticated",
            "sub": "33333333-3333-4333-8333-333333333333",
            "role": "authenticated", "is_anonymous": False,
            "aal": "aal2", "iat": now - 5, "exp": now + 300,
        }
        self.token = jwt.encode(self.claims, self.private, algorithm="ES256")
        self.db = Connection()
        self.mfa_calls = []
        self.owner_calls = []

    def candidate(self, *, mfa=True, owner=True, connection=None):
        def check_fresh_auth_mfa(token, digest):
            self.mfa_calls.append((token, digest))
            return mfa

        def check_business_owner(digest, business, environment):
            self.owner_calls.append((digest, business, environment))
            return owner

        return DevelopmentTenantRegistrationCandidate(
            Store(connection or self.db), self.checkpoint,
            check_fresh_auth_mfa=check_fresh_auth_mfa,
            check_business_owner=check_business_owner,
        )

    def test_verified_callbacks_create_exactly_two_pending_rows_atomically(self):
        receipt = self.candidate().propose(
            untrusted_bearer=self.token,
            business_reference="business.fictional",
        )
        self.assertEqual(receipt.state, "PENDING_VERIFICATION")
        self.assertEqual(self.db.commits, 1)
        self.assertEqual(self.db.rollbacks, 0)
        self.assertEqual(self.db.closes, 1)
        self.assertEqual(len(self.db.calls), 3)
        self.assertIn("set_config('avuhz.tenant_id'", self.db.calls[0][0])
        tenant, org, business = self.db.calls[1][1]
        self.assertEqual((tenant, org, business),
                         (receipt.tenant_id, receipt.organization_id, "business.fictional"))
        self.assertEqual(self.db.calls[0][1], (tenant,))
        self.assertEqual(self.db.calls[2][1][0:2], (tenant, org))
        self.assertEqual(self.db.calls[2][1][2], self.mfa_calls[0][1])
        self.assertEqual(self.owner_calls[0],
                         (self.mfa_calls[0][1], "business.fictional", "DEVELOPMENT"))
        self.assertNotIn(self.mfa_calls[0][1], repr(receipt))
        self.assertNotIn(self.token, repr(receipt))
        self.assertFalse(any(
            "ACTIVE" in statement or "GRANT " in statement
            for statement, _ in self.db.calls
        ))

    def test_aal2_jwt_alone_never_proves_recent_mfa_or_business_ownership(self):
        for mfa, owner in ((False, True), (True, False), (False, False)):
            with self.subTest(mfa=mfa, owner=owner):
                c = Connection()
                with self.assertRaisesRegex(PermissionError,
                                            "^tenant_registration_not_authorized$"):
                    self.candidate(mfa=mfa, owner=owner, connection=c).propose(
                        untrusted_bearer=self.token,
                        business_reference="business.fictional",
                    )
                self.assertEqual(c.calls, [])

    def test_invalid_source_or_business_is_denied_before_db(self):
        for business in ("", "SEKINFRA", "x", "business with spaces"):
            with self.subTest(business=business):
                c = Connection()
                with self.assertRaisesRegex(PermissionError,
                                            "^tenant_registration_not_authorized$"):
                    self.candidate(connection=c).propose(
                        untrusted_bearer=self.token,
                        business_reference=business,
                    )
                self.assertEqual(c.calls, [])

        changed = dict(self.claims, iss="https://invalid.example/auth/v1")
        forged = jwt.encode(changed, self.private, algorithm="ES256")
        c = Connection()
        with self.assertRaisesRegex(PermissionError,
                                    "^tenant_registration_not_authorized$"):
            self.candidate(connection=c).propose(
                untrusted_bearer=forged, business_reference="business.fictional",
            )
        self.assertEqual(c.calls, [])

    def test_pretenant_owner_rejects_command_audience_and_metadata_tenant(self):
        for overrides in (
            {"aud": DEVELOPMENT_SERVICE_AUDIENCE},
            {"app_metadata": {"avuhz_tenant_id": "55555555-5555-4555-8555-555555555555"}},
        ):
            with self.subTest(overrides=overrides):
                candidate = jwt.encode(
                    {**self.claims, **overrides},
                    self.private, algorithm="ES256",
                )
                connection = Connection()
                with self.assertRaisesRegex(
                    PermissionError, "^tenant_registration_not_authorized$"
                ):
                    self.candidate(connection=connection).propose(
                        untrusted_bearer=candidate,
                        business_reference="business.fictional",
                    )
                self.assertEqual(connection.calls, [])

    def test_org_collision_never_creates_owner_or_commits(self):
        c = Connection(org_conflict=True)
        with self.assertRaisesRegex(TenantRegistrationConflict,
                                    "^tenant_registration_conflict$"):
            self.candidate(connection=c).propose(
                untrusted_bearer=self.token, business_reference="business.fictional",
            )
        self.assertEqual(c.commits, 0)
        self.assertEqual(c.rollbacks, 1)
        self.assertEqual(c.closes, 1)
        self.assertEqual(len(c.calls), 2)

    def test_membership_conflict_rolls_back_organization_in_same_transaction(self):
        c = Connection(owner_conflict=True)
        with self.assertRaisesRegex(TenantRegistrationConflict,
                                    "^tenant_registration_conflict$"):
            self.candidate(connection=c).propose(
                untrusted_bearer=self.token, business_reference="business.fictional",
            )
        self.assertEqual(c.commits, 0)
        self.assertEqual(c.rollbacks, 1)
        self.assertEqual(c.closes, 1)

    def test_db_errors_redacted_and_transaction_rolled_back(self):
        c = Connection(fail=True)
        with self.assertRaisesRegex(TenantRegistrationUnavailable,
                                    "^tenant_registration_unavailable$") as exc:
            self.candidate(connection=c).propose(
                untrusted_bearer=self.token, business_reference="business.fictional",
            )
        self.assertNotIn("private fake database credentials", str(exc.exception))
        self.assertNotIn(self.token, str(exc.exception))
        self.assertEqual(c.commits, 0)
        self.assertEqual(c.rollbacks, 1)
        self.assertEqual(c.closes, 1)

    def test_no_hosted_provider_credentials_or_active_registry_behavior(self):
        source = (ROOT / "src/avuhz_service/development_tenant_registration.py").read_text()
        self.assertNotIn("service_role", source)
        self.assertNotIn("CREATE ROLE", source)
        self.assertNotIn("GRANT ", source)
        self.assertNotIn("UPDATE public.avuhz_tenant_organizations", source)
        self.assertNotIn("UPDATE public.avuhz_tenant_owner_memberships", source)
        self.assertNotIn("SEKINFRA", source)


if __name__ == "__main__":
    unittest.main()
