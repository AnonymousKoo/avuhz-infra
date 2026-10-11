"""Shared Avuhz company activation: synthetic two-company/negative transaction tests.

TEST/DEVELOPMENT ONLY. All JWT signatures and Auth/session/owner adapters are
synthetic in-memory fixtures; these tests certify NO hosted activation or grant.
"""
from __future__ import annotations

import copy
import hashlib
import sys
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import jwt
from cryptography.hazmat.primitives.asymmetric import ec

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_service.development import DEVELOPMENT_AUTH_ISSUER
from avuhz_service.development_pretenant_supabase_jwt import (
    DevelopmentPreTenantEs256JwtVerifier,
)
from avuhz_service.development_owner_authentication import (
    DevelopmentOwnerAuthenticationCheckpoint,
)
from avuhz_service.development_owner_mfa_freshness import (
    DevelopmentOwnerMfaFreshnessCheck,
)
from avuhz_service.development_company_activation import (
    CompanyActivationConflict,
    CompanyActivationUnavailable,
    DevelopmentCompanyActivationCandidate,
)

TENANT_A = "a4760000-0000-4000-8000-000000000001"
TENANT_B = "a4760000-0000-4000-8000-000000000002"
ORG_A = "a4760000-0000-4000-8000-000000000011"
ORG_B = "a4760000-0000-4000-8000-000000000012"
SUBJECT_A = "a4760000-0000-4000-8000-000000000021"
SUBJECT_B = "a4760000-0000-4000-8000-000000000022"
SESSION_A = "a4760000-0000-4000-8000-000000000031"
SESSION_B = "a4760000-0000-4000-8000-000000000032"
BUSINESS_A = "business.fictional-alpha"
BUSINESS_B = "business.fictional-beta"


def digest(subject):
    return "sha256:" + hashlib.sha256(subject.encode("ascii")).hexdigest()


def row(tenant, organization, business, subject):
    return dict(
        tenant_id=tenant,
        organization_id=organization,
        business_reference=business,
        principal_subject_digest=digest(subject),
        lifecycle_state="PENDING_VERIFICATION",
        membership_state="PENDING_VERIFICATION",
        verified_at=None,
        org_version=1,
        membership_version=1,
    )


class Cursor:
    def __init__(self, value):
        self.value = value

    def fetchone(self):
        return copy.deepcopy(self.value)


class InMemoryConnection:
    autocommit = False

    def __init__(self, store):
        self.store = store
        self.working = copy.deepcopy(store.rows)
        self.calls = []
        self.commits = 0
        self.rollbacks = 0
        self.closes = 0

    def execute(self, statement, params=()):
        self.calls.append((statement, params))
        if "set_config('avuhz.tenant_id'" in statement:
            return Cursor({"configured": True})
        if self.store.fail_sql and self.store.fail_sql in statement:
            raise RuntimeError("private fake database diagnostics")
        if statement.startswith("select org.lifecycle_state"):
            tenant, org, business, owner_digest = params
            match = self.working.get(tenant)
            if not match or (
                match["organization_id"] != org
                or match["business_reference"] != business
                or match["principal_subject_digest"] != owner_digest
            ):
                return Cursor(None)
            return Cursor({
                "lifecycle_state": match["lifecycle_state"],
                "membership_state": match["membership_state"],
                "org_version": match["org_version"],
                "membership_version": match["membership_version"],
                "verified_at": match["verified_at"],
            })
        if statement.startswith("update public.avuhz_tenant_owner_memberships"):
            tenant, org, owner_digest, version = params
            match = self.working.get(tenant)
            if not match or (
                match["organization_id"] != org
                or match["principal_subject_digest"] != owner_digest
                or match["membership_state"] != "PENDING_VERIFICATION"
                or match["verified_at"] is not None
                or match["membership_version"] != version
                or self.store.force_member_conflict
            ):
                return Cursor(None)
            match["membership_state"] = "ACTIVE"
            match["membership_version"] += 1
            match["verified_at"] = datetime.now(timezone.utc)
            return Cursor({"tenant_id": tenant})
        if statement.startswith("update public.avuhz_tenant_organizations"):
            tenant, org, business, version = params
            match = self.working.get(tenant)
            if not match or (
                match["organization_id"] != org
                or match["business_reference"] != business
                or match["lifecycle_state"] != "PENDING_VERIFICATION"
                or match["org_version"] != version
                or self.store.force_org_conflict
            ):
                return Cursor(None)
            match["lifecycle_state"] = "ACTIVE"
            match["org_version"] += 1
            return Cursor({"tenant_id": tenant})
        raise AssertionError("unexpected SQL")

    def commit(self):
        self.store.rows = copy.deepcopy(self.working)
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1

    def close(self):
        self.closes += 1


class FakeStore:
    def __init__(self):
        self.rows = {
            TENANT_A: row(TENANT_A, ORG_A, BUSINESS_A, SUBJECT_A),
            TENANT_B: row(TENANT_B, ORG_B, BUSINESS_B, SUBJECT_B),
        }
        self.connections = []
        self.fail_sql = ""
        self.force_member_conflict = False
        self.force_org_conflict = False

    def connection_factory(self):
        db = InMemoryConnection(self)
        self.connections.append(db)
        return db


class PublicKeySet:
    def __init__(self, public):
        self.public = public

    def get_signing_key_from_jwt(self, _token):
        return SimpleNamespace(key=self.public)


class CompanyActivationTests(unittest.TestCase):
    def setUp(self):
        self.private = ec.generate_private_key(ec.SECP256R1())
        self.verifier = DevelopmentPreTenantEs256JwtVerifier(
            PublicKeySet(self.private.public_key())
        )
        self.checkpoint = DevelopmentOwnerAuthenticationCheckpoint(self.verifier)
        self.store = FakeStore()
        self.checked_sessions = []
        self.ownership_calls = []
        self.subject_business = {
            (digest(SUBJECT_A), BUSINESS_A): True,
            (digest(SUBJECT_B), BUSINESS_B): True,
        }
        self.session_active = True
        self.owner_active = True

    def token(self, subject, session, *, totp=True, **changes):
        now = int(time.time())
        claims = {
            "iss": DEVELOPMENT_AUTH_ISSUER,
            "aud": "authenticated",
            "sub": subject,
            "session_id": session,
            "role": "authenticated",
            "is_anonymous": False,
            "aal": "aal2",
            "iat": now - 1,
            "exp": now + 300,
            "amr": [
                {"method": "password", "timestamp": now - 120},
                *([{"method": "totp", "timestamp": now - 2}] if totp else []),
            ],
        }
        return jwt.encode({**claims, **changes}, self.private, algorithm="ES256")

    def candidate(self):
        def live_session(subject, session, bearer):
            self.checked_sessions.append((subject, session))
            return self.session_active

        mfa = DevelopmentOwnerMfaFreshnessCheck(
            self.verifier, confirm_live_session=live_session,
        )

        def verify_business(owner_digest, business, environment):
            self.ownership_calls.append((owner_digest, business, environment))
            return (
                self.owner_active and environment == "DEVELOPMENT"
                and self.subject_business.get((owner_digest, business)) is True
            )

        return DevelopmentCompanyActivationCandidate(
            self.store, self.checkpoint,
            check_fresh_auth_mfa=mfa,
            check_business_owner=verify_business,
        )

    def activate(self, tenant=TENANT_A, org=ORG_A, business=BUSINESS_A,
                 subject=SUBJECT_A, session=SESSION_A, bearer=None):
        return self.candidate().activate(
            untrusted_bearer=bearer if bearer is not None
            else self.token(subject, session),
            tenant_id=tenant, organization_id=org, business_reference=business,
        )

    def test_two_independent_businesses_use_identical_activation_path(self):
        first = self.activate()
        second = self.activate(
            TENANT_B, ORG_B, BUSINESS_B, SUBJECT_B, SESSION_B,
        )
        self.assertEqual(first.state, "ACTIVE")
        self.assertEqual(second.state, "ACTIVE")
        self.assertFalse(first.duplicate)
        self.assertFalse(second.duplicate)
        self.assertNotEqual(first.tenant_id, second.tenant_id)
        self.assertEqual(len(self.store.connections), 2)
        for db in self.store.connections:
            self.assertEqual(db.commits, 1)
            self.assertEqual(db.rollbacks, 0)
            self.assertEqual(db.closes, 1)
            self.assertEqual(len(db.calls), 4)
            self.assertIn("set_config('avuhz.tenant_id'", db.calls[0][0])
            self.assertIn("principal_subject_digest=%s", db.calls[1][0])
            self.assertIn("for update of org, member", db.calls[1][0])
            self.assertIn("returning tenant_id", db.calls[2][0])
            self.assertIn("returning tenant_id", db.calls[3][0])
        self.assertEqual(
            self.store.rows[TENANT_A]["membership_version"], 2,
        )
        self.assertEqual(
            self.store.rows[TENANT_B]["org_version"], 2,
        )
        self.assertEqual(
            self.ownership_calls,
            [
                (digest(SUBJECT_A), BUSINESS_A, "DEVELOPMENT"),
                (digest(SUBJECT_B), BUSINESS_B, "DEVELOPMENT"),
            ],
        )

    def test_exact_replay_is_read_only_after_fresh_owner_reauthentication(self):
        first = self.activate()
        replay = self.activate()
        self.assertEqual(first.tenant_id, replay.tenant_id)
        self.assertTrue(replay.duplicate)
        db = self.store.connections[-1]
        self.assertEqual(db.commits, 0)
        self.assertEqual(db.rollbacks, 1)
        self.assertFalse(any(sql.startswith("update ") for sql, _ in db.calls))
        self.assertEqual(self.store.rows[TENANT_A]["org_version"], 2)

    def test_other_company_owner_or_tenant_selector_never_activates(self):
        for tenant, org, business, subject, session in (
            (TENANT_B, ORG_B, BUSINESS_B, SUBJECT_A, SESSION_A),
            (TENANT_A, ORG_A, BUSINESS_A, SUBJECT_B, SESSION_B),
            (TENANT_B, ORG_A, BUSINESS_A, SUBJECT_A, SESSION_A),
            (TENANT_A, ORG_B, BUSINESS_A, SUBJECT_A, SESSION_A),
            (TENANT_A, ORG_A, BUSINESS_B, SUBJECT_A, SESSION_A),
        ):
            with self.subTest(tenant=tenant, org=org, business=business):
                with self.assertRaisesRegex(
                    PermissionError, "^company_activation_not_authorized$"
                ):
                    self.activate(tenant, org, business, subject, session)
                self.assertEqual(
                    self.store.rows[TENANT_A]["lifecycle_state"],
                    "PENDING_VERIFICATION",
                )
                self.assertEqual(
                    self.store.rows[TENANT_B]["membership_state"],
                    "PENDING_VERIFICATION",
                )

    def test_invalid_authorization_fails_before_sql(self):
        for changed in (
            dict(totp=False),
            dict(aud="audience.avuhz.command-service.development"),
            dict(app_metadata={"avuhz_tenant_id": TENANT_A}),
            dict(is_anonymous=True),
            dict(role="service_role"),
        ):
            with self.subTest(changed=changed):
                options = dict(changed)
                totp = options.pop("totp", True)
                bearer = self.token(SUBJECT_A, SESSION_A, totp=totp, **options)
                with self.assertRaisesRegex(
                    PermissionError, "^company_activation_not_authorized$"
                ):
                    self.activate(bearer=bearer)
                self.assertEqual(self.store.connections, [])

        for state in ("session", "owner"):
            with self.subTest(state=state):
                setattr(self, "session_active" if state == "session"
                        else "owner_active", False)
                with self.assertRaisesRegex(
                    PermissionError, "^company_activation_not_authorized$"
                ):
                    self.activate()
                self.assertEqual(self.store.connections, [])
                setattr(self, "session_active" if state == "session"
                        else "owner_active", True)

    def test_invalid_selectors_rejected_before_provider_or_db(self):
        for tenant, org, business in (
            ("not-a-uuid", ORG_A, BUSINESS_A),
            (TENANT_A, ORG_A.upper(), BUSINESS_A),
            (TENANT_A, None, BUSINESS_A),
            (TENANT_A, ORG_A, "SEKINFRA"),
            (TENANT_A, ORG_A, "business with spaces"),
            (TENANT_A, ORG_A, "secret:credential"),
        ):
            with self.subTest(tenant=tenant, business=business):
                with self.assertRaisesRegex(
                    PermissionError, "^company_activation_not_authorized$"
                ):
                    self.activate(tenant, org, business)
                self.assertEqual(self.store.connections, [])

    def test_mismatched_or_partially_active_state_blocks_activation(self):
        variants = [
            {"lifecycle_state": "SUSPENDED"},
            {"membership_state": "REVOKED"},
            {"lifecycle_state": "ACTIVE"},
            {"membership_state": "ACTIVE"},
            {"verified_at": datetime.now(timezone.utc)},
            {"org_version": 2147483647},
        ]
        for changes in variants:
            with self.subTest(changes=changes):
                self.store = FakeStore()
                self.store.rows[TENANT_A].update(changes)
                with self.assertRaisesRegex(
                    CompanyActivationConflict, "^company_activation_state_conflict$"
                ):
                    self.activate()
                self.assertEqual(self.store.connections[-1].commits, 0)
                self.assertEqual(self.store.connections[-1].rollbacks, 1)

    def test_update_conflicts_and_sql_error_rollback_both_rows(self):
        for fail in ("force_member_conflict", "force_org_conflict", "fail_sql"):
            self.store = FakeStore()
            if fail == "fail_sql":
                self.store.fail_sql = "update public.avuhz_tenant_organizations"
            else:
                setattr(self.store, fail, True)
            with self.subTest(fail=fail):
                with self.assertRaisesRegex(
                    ValueError if fail != "fail_sql" else CompanyActivationUnavailable,
                    "^company_activation_(state_conflict|unavailable)$",
                ) as error:
                    self.activate()
                db = self.store.connections[-1]
                self.assertEqual(db.commits, 0)
                self.assertEqual(db.rollbacks, 1)
                self.assertEqual(db.closes, 1)
                self.assertEqual(
                    self.store.rows[TENANT_A]["membership_state"],
                    "PENDING_VERIFICATION",
                )
                self.assertEqual(
                    self.store.rows[TENANT_A]["lifecycle_state"],
                    "PENDING_VERIFICATION",
                )
                self.assertNotIn("private fake database diagnostics", str(error.exception))

    def test_no_vertical_infrastructure_or_hosted_authority_was_added(self):
        source = (ROOT / "src/avuhz_service/development_company_activation.py").read_text()
        self.assertNotIn("sekinfra", source.lower())
        self.assertNotIn("service_role", source)
        self.assertNotIn("CREATE ROLE", source)
        self.assertNotIn("GRANT ", source)
        self.assertNotIn("n8n.", source)
        self.assertNotIn("stripe.", source)
        self.assertNotIn("HTTP_AUTHORIZATION", source)


if __name__ == "__main__":
    unittest.main()
