"""Fictional LOCAL/TEST proof of the shared onboarding composition.

All JWT and directory/principal keys are ephemeral in-memory test material.
No network, provider, credential, live identity, or external system is used.
"""
from __future__ import annotations

import copy
import hashlib
import json
import time
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from avuhz_runtime.guards import TrustedExecutionContext
from avuhz_service.development import (
    DEVELOPMENT_AUTH_ISSUER,
    DEVELOPMENT_AUTH_PROJECT_REF,
    DEVELOPMENT_DATA_PROJECT_REF,
)
from avuhz_service.development_active_owner_membership import (
    DevelopmentActiveOwnerMembershipCheck,
)
from avuhz_service.development_business_owner_directory import (
    DevelopmentBusinessOwnerDirectoryCheck,
    ISSUER as OWNER_ISSUER,
    PURPOSE as OWNER_PURPOSE,
    SignedBusinessOwnerDecision,
)
from avuhz_service.development_company_activation import (
    DevelopmentCompanyActivationCandidate,
)
from avuhz_service.development_owner_authentication import (
    DevelopmentOwnerAuthenticationCheckpoint,
)
from avuhz_service.development_owner_mfa_freshness import (
    DevelopmentOwnerMfaFreshnessCheck,
)
from avuhz_service.development_pretenant_supabase_jwt import (
    DevelopmentPreTenantEs256JwtVerifier,
)
from avuhz_service.development_signed_work_owner_identity import (
    DevelopmentSignedWorkOwnerIdentityResolver,
    ISSUER as PRINCIPAL_ISSUER,
    PURPOSE as PRINCIPAL_PURPOSE,
    SignedWorkOwnerPrincipalBinding,
)
from avuhz_service.development_tenant_registration import (
    DevelopmentTenantRegistrationCandidate,
    PendingTenantRegistration,
    TenantRegistrationConflict,
)
from avuhz_service.shared_client_onboarding_local_proof import (
    SharedClientOnboardingLocalProofHarness,
)

SUBJECT = "b6010000-0000-4000-8000-000000000001"
SESSION = "b6010000-0000-4000-8000-000000000002"
BUSINESS = "company.fictional-local"
PRINCIPAL = "owner.fictional-local-001"


def utc(value: datetime) -> str:
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def fingerprint(key) -> str:
    raw = key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def digest(subject: str) -> str:
    return "sha256:" + hashlib.sha256(subject.encode("ascii")).hexdigest()


class KeySet:
    def __init__(self, public):
        self.public = public

    def get_signing_key_from_jwt(self, _token):
        return SimpleNamespace(key=self.public)


class Cursor:
    def __init__(self, row):
        self.row = copy.deepcopy(row)

    def fetchone(self):
        return copy.deepcopy(self.row)


class LocalConnection:
    autocommit = False

    def __init__(self, store):
        self.store = store
        self.rows = copy.deepcopy(store.rows)
        self.calls = []
        self.commits = 0
        self.rollbacks = 0
        self.closes = 0

    def execute(self, sql, params=()):
        self.calls.append((sql, params))
        if "set_config('avuhz.tenant_id'" in sql:
            return Cursor({"configured": True})
        if "insert into public.avuhz_tenant_organizations" in sql:
            tenant, organization, business = params
            if any(r["business_reference"] == business for r in self.rows.values()):
                return Cursor(None)
            self.rows[tenant] = {
                "tenant_id": tenant,
                "organization_id": organization,
                "business_reference": business,
                "principal_subject_digest": None,
                "lifecycle_state": "PENDING_VERIFICATION",
                "membership_state": None,
                "verified_at": None,
                "org_version": 1,
                "membership_version": 1,
            }
            return Cursor({"tenant_id": tenant})
        if "insert into public.avuhz_tenant_owner_memberships" in sql:
            tenant, organization, owner_digest = params
            row = self.rows.get(tenant)
            if row is None or row["organization_id"] != organization:
                return Cursor(None)
            row["principal_subject_digest"] = owner_digest
            row["membership_state"] = "PENDING_VERIFICATION"
            return Cursor({"tenant_id": tenant})
        if sql.startswith("select org.lifecycle_state"):
            tenant, organization, business, owner_digest = params
            row = self.rows.get(tenant)
            if row is None or (
                row["organization_id"] != organization
                or row["business_reference"] != business
                or row["principal_subject_digest"] != owner_digest
            ):
                return Cursor(None)
            return Cursor({
                "lifecycle_state": row["lifecycle_state"],
                "org_version": row["org_version"],
                "membership_state": row["membership_state"],
                "membership_version": row["membership_version"],
                "verified_at": row["verified_at"],
            })
        if sql.startswith("update public.avuhz_tenant_owner_memberships"):
            tenant, organization, owner_digest, version = params
            row = self.rows.get(tenant)
            if row is None or (
                row["organization_id"] != organization
                or row["principal_subject_digest"] != owner_digest
                or row["membership_state"] != "PENDING_VERIFICATION"
                or row["verified_at"] is not None
                or row["membership_version"] != version
            ):
                return Cursor(None)
            row["membership_state"] = "ACTIVE"
            row["membership_version"] += 1
            row["verified_at"] = datetime.now(timezone.utc)
            return Cursor({"tenant_id": tenant})
        if sql.startswith("update public.avuhz_tenant_organizations"):
            tenant, organization, business, version = params
            row = self.rows.get(tenant)
            if row is None or (
                row["organization_id"] != organization
                or row["business_reference"] != business
                or row["lifecycle_state"] != "PENDING_VERIFICATION"
                or row["org_version"] != version
            ):
                return Cursor(None)
            row["lifecycle_state"] = "ACTIVE"
            row["org_version"] += 1
            return Cursor({"tenant_id": tenant})
        if "AS bounded" in sql and "pg_roles" in sql:
            return Cursor({"bounded": self.store.membership_boundary_ok})
        if "SELECT true AS member_verified" in sql:
            tenant, organization, owner_digest = params
            row = self.rows.get(tenant)
            valid = row is not None and (
                row["organization_id"] == organization
                and row["principal_subject_digest"] == owner_digest
                and row["lifecycle_state"] == "ACTIVE"
                and row["membership_state"] == "ACTIVE"
                and row["verified_at"] is not None
            )
            return Cursor({"member_verified": True} if valid else None)
        raise AssertionError("unexpected local proof SQL")

    def commit(self):
        self.store.rows = copy.deepcopy(self.rows)
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1

    def close(self):
        self.closes += 1


class LocalStore:
    def __init__(self):
        self.rows = {}
        self.connections = []
        self.membership_boundary_ok = True

    def connection_factory(self):
        connection = LocalConnection(self)
        self.connections.append(connection)
        return connection


class SharedClientOnboardingLocalProofTests(unittest.TestCase):
    def setUp(self):
        self.auth_key = ec.generate_private_key(ec.SECP256R1())
        self.verifier = DevelopmentPreTenantEs256JwtVerifier(
            KeySet(self.auth_key.public_key())
        )
        self.checkpoint = DevelopmentOwnerAuthenticationCheckpoint(self.verifier)
        self.session_active = True
        self.mfa = DevelopmentOwnerMfaFreshnessCheck(
            self.verifier,
            confirm_live_session=lambda subject, session, _bearer: (
                self.session_active and subject == SUBJECT and session == SESSION
            ),
        )
        self.owner_key = Ed25519PrivateKey.generate()
        self.owner_status = "VERIFIED"
        self.owner_signature_valid = True
        self.owner_directory = DevelopmentBusinessOwnerDirectoryCheck(
            directory_public_key=self.owner_key.public_key(),
            pinned_fingerprint=fingerprint(self.owner_key.public_key()),
            fetch_signed_decision=self.owner_decision,
        )
        self.principal_key = Ed25519PrivateKey.generate()
        self.principal_subject = digest(SUBJECT)
        self.store = LocalStore()
        self.registration = DevelopmentTenantRegistrationCandidate(
            self.store,
            self.checkpoint,
            check_fresh_auth_mfa=self.mfa,
            check_business_owner=self.owner_directory,
        )
        self.activation = DevelopmentCompanyActivationCandidate(
            self.store,
            self.checkpoint,
            check_fresh_auth_mfa=self.mfa,
            check_business_owner=self.owner_directory,
        )
        self.harness = SharedClientOnboardingLocalProofHarness(
            self.registration,
            self.activation,
            identity_resolver_factory=lambda tenant, organization: self.resolver(
                PendingTenantRegistration(tenant, organization)
            ),
        )

    def token(self, *, totp_age=2, subject=SUBJECT):
        now = int(time.time())
        return jwt.encode({
            "iss": DEVELOPMENT_AUTH_ISSUER,
            "aud": "authenticated",
            "sub": subject,
            "session_id": SESSION,
            "role": "authenticated",
            "is_anonymous": False,
            "aal": "aal2",
            "iat": now - 1,
            "exp": now + 300,
            "amr": [{"method": "totp", "timestamp": now - totp_age}],
        }, self.auth_key, algorithm="ES256")

    def owner_decision(self, owner_digest, business):
        now = datetime.now(timezone.utc).replace(microsecond=0)
        statement = {
            "purpose": OWNER_PURPOSE,
            "issuer": OWNER_ISSUER,
            "environment": "DEVELOPMENT",
            "auth_project_ref": DEVELOPMENT_AUTH_PROJECT_REF,
            "data_project_ref": DEVELOPMENT_DATA_PROJECT_REF,
            "business_reference": business,
            "subject_digest": owner_digest,
            "ownership_status": self.owner_status,
            "issued_at": utc(now - timedelta(seconds=2)),
            "expires_at": utc(now + timedelta(seconds=60)),
        }
        canonical = json.dumps(
            statement, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False,
        ).encode()
        signature = self.owner_key.sign(canonical)
        if not self.owner_signature_valid:
            signature = bytes(64)
        return SignedBusinessOwnerDecision(statement, signature)

    def resolver(self, pending):
        membership = DevelopmentActiveOwnerMembershipCheck(
            self.store, self.checkpoint, self.mfa,
        )

        def fetch(owner_digest, tenant, organization):
            now = datetime.now(timezone.utc).replace(microsecond=0)
            statement = {
                "purpose": PRINCIPAL_PURPOSE,
                "issuer": PRINCIPAL_ISSUER,
                "environment": "DEVELOPMENT",
                "auth_project_ref": DEVELOPMENT_AUTH_PROJECT_REF,
                "data_project_ref": DEVELOPMENT_DATA_PROJECT_REF,
                "tenant_id": tenant,
                "organization_id": organization,
                "subject_digest": self.principal_subject,
                "principal_reference": PRINCIPAL,
                "issued_at": utc(now - timedelta(seconds=2)),
                "expires_at": utc(now + timedelta(seconds=60)),
            }
            canonical = json.dumps(
                statement, sort_keys=True, separators=(",", ":"),
                ensure_ascii=True, allow_nan=False,
            ).encode()
            return SignedWorkOwnerPrincipalBinding(
                statement, self.principal_key.sign(canonical),
            )

        return DevelopmentSignedWorkOwnerIdentityResolver(
            tenant_id=pending.tenant_id,
            organization_id=pending.organization_id,
            auth_checkpoint=self.checkpoint,
            mfa_check=self.mfa,
            active_owner_membership=membership,
            principal_public_key=self.principal_key.public_key(),
            pinned_fingerprint=fingerprint(self.principal_key.public_key()),
            fetch_signed_binding=fetch,
        )

    def register(self, bearer):
        return self.harness.register_pending(
            untrusted_bearer=bearer, business_reference=BUSINESS,
        )

    def activate(self, pending, bearer):
        return self.harness.activate_and_bind(
            pending=pending,
            untrusted_bearer=bearer,
            business_reference=BUSINESS,
        )

    def test_verified_owner_pending_then_separate_active_and_bound_proof(self):
        bearer = self.token()
        pending = self.register(bearer)
        self.assertEqual(pending.state, "PENDING_VERIFICATION")
        self.assertEqual(self.store.rows[pending.tenant_id]["lifecycle_state"],
                         "PENDING_VERIFICATION")

        proof = self.activate(pending, bearer)
        self.assertEqual(proof.state, "ACTIVE")
        self.assertEqual(proof.principal_reference, PRINCIPAL)
        self.assertEqual(proof.evidence_class, "LOCAL_TEST_ONLY")
        self.assertFalse(proof.live_identity_authorized)
        self.assertFalse(proof.provider_change_authorized)
        self.assertFalse(hasattr(proof, "trusted_context"))
        row = self.store.rows[pending.tenant_id]
        self.assertEqual((row["lifecycle_state"], row["membership_state"]),
                         ("ACTIVE", "ACTIVE"))

    def test_duplicate_registration_denied_and_exact_activation_replay_is_read_only(self):
        bearer = self.token()
        pending = self.register(bearer)
        with self.assertRaisesRegex(TenantRegistrationConflict,
                                    "^tenant_registration_conflict$"):
            self.register(bearer)
        first = self.activate(pending, bearer)
        versions = copy.deepcopy(self.store.rows[pending.tenant_id])
        replay = self.activate(pending, bearer)
        self.assertFalse(first.activation_duplicate)
        self.assertTrue(replay.activation_duplicate)
        self.assertEqual(self.store.rows[pending.tenant_id], versions)

    def test_forged_or_self_verified_owner_never_creates_pending_rows(self):
        for status, signature_valid in (("SELF_ASSERTED", True), ("VERIFIED", False)):
            with self.subTest(status=status, signature_valid=signature_valid):
                self.owner_status = status
                self.owner_signature_valid = signature_valid
                with self.assertRaisesRegex(
                    PermissionError, "^tenant_registration_not_authorized$"
                ):
                    self.register(self.token())
                self.assertEqual(self.store.rows, {})

    def test_stale_mfa_and_revoked_session_fail_before_registration_write(self):
        with self.assertRaisesRegex(PermissionError,
                                    "^tenant_registration_not_authorized$"):
            self.register(self.token(totp_age=301))
        self.session_active = False
        with self.assertRaisesRegex(PermissionError,
                                    "^tenant_registration_not_authorized$"):
            self.register(self.token())
        self.assertEqual(self.store.rows, {})

    def test_forged_pending_scope_and_caller_supplied_authority_cannot_activate(self):
        bearer = self.token()
        pending = self.register(bearer)
        forged = PendingTenantRegistration(
            pending.tenant_id, "b6010000-0000-4000-8000-000000000099",
        )
        caller_context = TrustedExecutionContext(
            authenticated=True,
            principal_id="caller.supplied",
            caller_type="HUMAN",
            tenant_id=pending.tenant_id,
            organization_id=pending.organization_id,
            capabilities=frozenset({"work_intake:create"}),
            authority_roles=frozenset({"OWNER"}),
            environment="DEVELOPMENT",
            audience="avuhz-command-api",
            authentication_strength="STRONG",
            step_up_satisfied=True,
            authenticated_at=utc(datetime.now(timezone.utc)),
        )
        with self.assertRaisesRegex(
            PermissionError, "^local_client_onboarding_proof_denied$"
        ):
            self.activate(forged, bearer)
        attacker_resolver = self.resolver(pending)
        with self.assertRaises(TypeError):
            self.harness.activate_and_bind(
                pending=pending,
                untrusted_bearer=bearer,
                business_reference=BUSINESS,
                identity_resolver=attacker_resolver,
            )
        with self.assertRaises(TypeError):
            self.harness.activate_and_bind(
                pending=pending,
                untrusted_bearer=bearer,
                business_reference=BUSINESS,
                identity_resolver=caller_context,
            )
        self.assertEqual(self.store.rows[pending.tenant_id]["lifecycle_state"],
                         "PENDING_VERIFICATION")

    def test_revoked_or_wrong_member_returns_no_proof_after_separate_activation(self):
        for failure in ("membership_boundary", "wrong_principal_subject"):
            with self.subTest(failure=failure):
                self.setUp()
                bearer = self.token()
                pending = self.register(bearer)
                if failure == "membership_boundary":
                    self.store.membership_boundary_ok = False
                else:
                    self.principal_subject = "sha256:" + "f" * 64
                with self.assertRaisesRegex(
                    PermissionError, "^work owner identity unavailable$"
                ):
                    self.activate(pending, bearer)
                # Activation and binding are intentionally separate boundaries:
                # failure returns no proof even though ACTIVE already committed.
                self.assertEqual(
                    self.store.rows[pending.tenant_id]["lifecycle_state"], "ACTIVE"
                )

    def test_premature_binding_without_harness_pending_is_denied(self):
        pending = PendingTenantRegistration(
            "b6010000-0000-4000-8000-000000000010",
            "b6010000-0000-4000-8000-000000000011",
        )
        with self.assertRaisesRegex(
            PermissionError, "^local_client_onboarding_proof_denied$"
        ):
            self.activate(pending, self.token())
        self.assertEqual(self.store.rows, {})


if __name__ == "__main__":
    unittest.main()
