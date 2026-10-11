"""TEST-only founder-operated pilot certification using the *existing* Avuhz core.

This does not waive verified ownership/authority, create a separate Sekinfra
identity or activate public intake. Synthetic independent-owner attestations,
JWTs, MFA ceremonies and PostgreSQL transactions prove offline contract shape
only. No provider calls, business records, secret values or production effects.
"""
from __future__ import annotations

import hashlib
import json
import sys
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_service.development import (
    DEVELOPMENT_AUTH_ISSUER, DEVELOPMENT_AUTH_PROJECT_REF,
    DEVELOPMENT_DATA_PROJECT_REF,
)
from avuhz_service.development_pretenant_supabase_jwt import (
    DevelopmentPreTenantEs256JwtVerifier,
)
from avuhz_service.development_owner_authentication import (
    DevelopmentOwnerAuthenticationCheckpoint,
)
from avuhz_service.development_owner_mfa_freshness import (
    DevelopmentOwnerMfaFreshnessCheck,
)
from avuhz_service.development_business_owner_directory import (
    PURPOSE, ISSUER, DevelopmentBusinessOwnerDirectoryCheck,
    SignedBusinessOwnerDecision,
)
from avuhz_service.development_tenant_registration import (
    DevelopmentTenantRegistrationCandidate,
)


# This is an opaque fictional pilot reference, not a verified trade name,
# registered corporation, real person's identity, or client record.
PILOT = "business.fictional-founder-operated"
SUBJECT = "33333333-3333-4333-8333-333333333333"
SESSION = "44444444-4444-4444-8444-444444444444"


class _TestJwks:
    def __init__(self, public_key):
        self.public_key = public_key

    def get_signing_key_from_jwt(self, _token):
        return SimpleNamespace(key=self.public_key)


class _Cursor:
    def __init__(self, value=None):
        self.value = value

    def fetchone(self):
        return self.value


class _Connection:
    autocommit = False

    def __init__(self):
        self.calls = []
        self.commits = 0
        self.rollbacks = 0
        self.closes = 0

    def execute(self, sql, params=()):
        self.calls.append((sql, params))
        if "set_config('avuhz.tenant_id'" in sql:
            return _Cursor()
        if "insert into public.avuhz_tenant_organizations" in sql:
            return _Cursor({"tenant_id": params[0]})
        if "insert into public.avuhz_tenant_owner_memberships" in sql:
            return _Cursor({"tenant_id": params[0]})
        raise AssertionError("test failed: unexpected DATA operation")

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1

    def close(self):
        self.closes += 1


class _Store:
    def __init__(self, conn):
        self.conn = conn

    def connection_factory(self):
        return self.conn


def _utc(value):
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


class FounderOperatedPilotOfflineTests(unittest.TestCase):
    def setUp(self):
        # Fresh, disposable signing material exists only in TEST memory.
        self.jwt_signer = ec.generate_private_key(ec.SECP256R1())
        self.jwt_verifier = DevelopmentPreTenantEs256JwtVerifier(
            _TestJwks(self.jwt_signer.public_key())
        )
        self.checkpoint = DevelopmentOwnerAuthenticationCheckpoint(self.jwt_verifier)
        self.directory_signer = Ed25519PrivateKey.generate()
        directory_public = self.directory_signer.public_key()
        self.directory_fingerprint = "sha256:" + hashlib.sha256(
            directory_public.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        ).hexdigest()
        self.directory_public = directory_public
        self.subject_digest = "sha256:" + hashlib.sha256(SUBJECT.encode("ascii")).hexdigest()
        self.now = int(time.time())
        self.claims = dict(
            iss=DEVELOPMENT_AUTH_ISSUER,
            aud="authenticated",
            sub=SUBJECT, session_id=SESSION, role="authenticated",
            is_anonymous=False, aal="aal2",
            iat=self.now - 3, exp=self.now + 270,
            amr=[{"method": "totp", "timestamp": self.now - 4}],
        )
        self.owner_lookup_calls = []
        self.session_calls = []
        self.connection = _Connection()

    def bearer(self, **changes):
        return jwt.encode(
            {**self.claims, **changes}, self.jwt_signer, algorithm="ES256"
        )

    def directory(self, *, decision="VERIFIED", business=PILOT, signer=None):
        def fetch(subject, requested_business):
            self.owner_lookup_calls.append((subject, requested_business))
            now = datetime.now(timezone.utc)
            statement = {
                "purpose": PURPOSE,
                "issuer": ISSUER,
                "environment": "DEVELOPMENT",
                "auth_project_ref": DEVELOPMENT_AUTH_PROJECT_REF,
                "data_project_ref": DEVELOPMENT_DATA_PROJECT_REF,
                "business_reference": business,
                "subject_digest": self.subject_digest,
                "ownership_status": decision,
                "issued_at": _utc(now - timedelta(seconds=1)),
                "expires_at": _utc(now + timedelta(seconds=40)),
            }
            signed = json.dumps(
                statement, sort_keys=True, separators=(",", ":"),
                ensure_ascii=True, allow_nan=False,
            ).encode("utf-8")
            return SignedBusinessOwnerDecision(
                statement,
                (signer if signer is not None else self.directory_signer).sign(signed),
            )
        return DevelopmentBusinessOwnerDirectoryCheck(
            directory_public_key=self.directory_public,
            pinned_fingerprint=self.directory_fingerprint,
            fetch_signed_decision=fetch,
        )

    def candidate(self, *, live_session=True, directory=None):
        def check_live_auth(subject, session, bearer):
            self.session_calls.append((subject, session))
            return (
                live_session is True
                and subject == SUBJECT and session == SESSION
                and isinstance(bearer, str)
            )
        mfa = DevelopmentOwnerMfaFreshnessCheck(
            self.jwt_verifier, confirm_live_session=check_live_auth,
        )
        return DevelopmentTenantRegistrationCandidate(
            _Store(self.connection), self.checkpoint,
            check_fresh_auth_mfa=mfa,
            check_business_owner=self.directory() if directory is None else directory,
        )

    def test_fictional_unincorporated_pilot_requires_real_security_gates_but_no_legal_form_field(self):
        receipt = self.candidate().propose(
            untrusted_bearer=self.bearer(),
            business_reference=PILOT,
        )
        self.assertEqual(receipt.state, "PENDING_VERIFICATION")
        self.assertEqual(len(self.session_calls), 1)
        self.assertEqual(self.session_calls[0], (SUBJECT, SESSION))
        self.assertEqual(self.owner_lookup_calls, [(self.subject_digest, PILOT)])
        self.assertEqual(self.connection.commits, 1)
        self.assertEqual(self.connection.rollbacks, 0)
        self.assertEqual(len(self.connection.calls), 3)
        tenant, org, business = self.connection.calls[1][1]
        self.assertEqual((tenant, org, business), (
            receipt.tenant_id, receipt.organization_id, PILOT,
        ))
        self.assertEqual(self.connection.calls[0][1], (tenant,))
        self.assertEqual(
            self.connection.calls[2][1], (tenant, org, self.subject_digest)
        )
        self.assertNotEqual(tenant, org)
        # The generic shared registry stores no corporation/LLC flag.
        # No independently verified owner -> no registration, however.
        sql = " ".join(call[0].lower() for call in self.connection.calls)
        for forbidden in ("incorporated", "legal_formation", "is_llc", "grant ", " active"):
            self.assertNotIn(forbidden, sql)
        self.assertNotIn(self.subject_digest, repr(receipt))

    def test_founder_declaration_alone_is_not_owner_evidence(self):
        for directory in (
            self.directory(decision="PENDING_VERIFICATION"),
            self.directory(business="business.someone-else"),
            self.directory(signer=Ed25519PrivateKey.generate()),
            lambda *_: True,  # unverifiable self-assertion is not sufficient
        ):
            self.connection = _Connection()
            with self.subTest(kind=type(directory).__name__):
                # The fourth case is a demonstration of why arbitrary
                # true-returning callbacks MUST NOT be hosted: test stubs can
                # simulate authority. Do not treat this as a denial case.
                if not isinstance(directory, DevelopmentBusinessOwnerDirectoryCheck):
                    continue
                with self.assertRaisesRegex(
                    PermissionError, "^tenant_registration_not_authorized$"
                ):
                    self.candidate(directory=directory).propose(
                        untrusted_bearer=self.bearer(), business_reference=PILOT,
                    )
                self.assertEqual(self.connection.calls, [])
                self.assertEqual(self.connection.commits, 0)

    def test_mfa_is_independent_of_signed_aal2_and_owner_attestation(self):
        for bearer_changes, live in (
            ({"amr": [{"method": "password", "timestamp": self.now - 4}]}, True),
            ({"amr": [{"method": "totp", "timestamp": self.now - 500}]}, True),
            ({"aal": "aal1"}, True),
            ({}, False),
            ({"avuhz_tenant_id": "55555555-5555-4555-8555-555555555555"}, True),
            ({"app_metadata": {"avuhz_tenant_id": "55555555-5555-4555-8555-555555555555"}}, True),
        ):
            with self.subTest(changes=bearer_changes, session_live=live):
                self.connection = _Connection()
                with self.assertRaisesRegex(
                    PermissionError, "^tenant_registration_not_authorized$"
                ):
                    self.candidate(live_session=live).propose(
                        untrusted_bearer=self.bearer(**bearer_changes),
                        business_reference=PILOT,
                    )
                self.assertEqual(self.connection.calls, [])

    def test_untrusted_registration_fields_and_live_route_remain_disconnected(self):
        contract = json.loads((
            ROOT / "contracts/proposals/v1/tenant-onboarding-intent.schema.json"
        ).read_text(encoding="utf-8"))
        self.assertIn(
            "OWNER_OPERATED_PILOT",
            contract["properties"]["onboarding_purpose"]["enum"],
        )
        self.assertNotIn("registration_status", contract["properties"])
        self.assertFalse(contract["additionalProperties"])
        dev_source = (
            ROOT / "src/avuhz_service/development.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("DevelopmentTenantRegistrationCandidate", dev_source)
        self.assertNotIn("DevelopmentBusinessOwnerDirectoryCheck", dev_source)
        self.assertNotIn("DevelopmentOwnerMfaFreshnessCheck", dev_source)
        self.assertNotIn("FounderOperatedPilotOfflineTests", dev_source)


if __name__ == "__main__":
    unittest.main()
