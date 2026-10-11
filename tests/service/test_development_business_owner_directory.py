"""Repository-only tests for the shared signed business-ownership trust boundary.

Synthetic Ed25519 keys prove only the offline verifier. They do NOT establish
an independently vetted owner, an authorized directory trust anchor, a live
Supabase integration or authority to register/activate a company.
"""
from __future__ import annotations

import hashlib
import json
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_service.development import (
    DEVELOPMENT_AUTH_PROJECT_REF, DEVELOPMENT_DATA_PROJECT_REF,
)
from avuhz_service.development_business_owner_directory import (
    PURPOSE, ISSUER, DevelopmentBusinessOwnerDirectoryCheck,
    SignedBusinessOwnerDecision,
)

SUBJECT_ONE = "sha256:" + hashlib.sha256(
    b"fictional-development-subject-one"
).hexdigest()
SUBJECT_TWO = "sha256:" + hashlib.sha256(
    b"fictional-development-subject-two"
).hexdigest()
BUSINESS_ONE = "business.fictional-first"
BUSINESS_TWO = "business.fictional-second"


def _utc(value):
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


class SignedBusinessOwnerDirectoryTests(unittest.TestCase):
    def setUp(self):
        self.private = Ed25519PrivateKey.generate()
        self.public = self.private.public_key()
        self.fingerprint = "sha256:" + hashlib.sha256(
            self.public.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        ).hexdigest()
        self.requests = []
        self.statement = self._statement(SUBJECT_ONE, BUSINESS_ONE)
        self.resolved = None

    def _statement(self, subject, business):
        now = datetime.now(timezone.utc)
        return {
            "purpose": PURPOSE,
            "issuer": ISSUER,
            "environment": "DEVELOPMENT",
            "auth_project_ref": DEVELOPMENT_AUTH_PROJECT_REF,
            "data_project_ref": DEVELOPMENT_DATA_PROJECT_REF,
            "business_reference": business,
            "subject_digest": subject,
            "ownership_status": "VERIFIED",
            "issued_at": _utc(now - timedelta(seconds=1)),
            "expires_at": _utc(now + timedelta(seconds=40)),
        }

    @staticmethod
    def _canonical(statement):
        return json.dumps(
            statement, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False,
        ).encode("utf-8")

    def _sign(self, statement, signer=None):
        return SignedBusinessOwnerDecision(
            statement,
            (signer if signer is not None else self.private).sign(
                self._canonical(statement)
            ),
        )

    def checker(self):
        def provider(subject, business):
            self.requests.append((subject, business))
            if self.resolved is not None:
                return self.resolved
            return self._sign(self.statement)
        return DevelopmentBusinessOwnerDirectoryCheck(
            directory_public_key=self.public,
            pinned_fingerprint=self.fingerprint,
            fetch_signed_decision=provider,
        )

    def test_two_independent_businesses_use_one_verifier(self):
        checker = self.checker()
        self.assertTrue(checker(SUBJECT_ONE, BUSINESS_ONE, "DEVELOPMENT"))
        self.statement = self._statement(SUBJECT_TWO, BUSINESS_TWO)
        self.assertTrue(checker(SUBJECT_TWO, BUSINESS_TWO, "DEVELOPMENT"))
        self.assertEqual(self.requests, [
            (SUBJECT_ONE, BUSINESS_ONE),
            (SUBJECT_TWO, BUSINESS_TWO),
        ])
        self.assertFalse(checker(SUBJECT_ONE, BUSINESS_TWO, "DEVELOPMENT"))

    def test_rejects_changed_or_claimed_owner_and_business_after_signature(self):
        checker = self.checker()
        self.assertFalse(checker(SUBJECT_TWO, BUSINESS_ONE, "DEVELOPMENT"))
        self.assertFalse(checker(SUBJECT_ONE, BUSINESS_TWO, "DEVELOPMENT"))
        self.assertFalse(checker(SUBJECT_ONE, BUSINESS_ONE, "PRODUCTION"))
        self.assertEqual(self.requests, [
            (SUBJECT_TWO, BUSINESS_ONE),
            (SUBJECT_ONE, BUSINESS_TWO),
        ])
        with self.subTest("signed payload tamper"):
            original = self._sign(self.statement)
            changed = dict(self.statement, business_reference=BUSINESS_TWO)
            self.resolved = SignedBusinessOwnerDecision(changed, original.signature)
            self.assertFalse(checker(SUBJECT_ONE, BUSINESS_TWO, "DEVELOPMENT"))

    def test_rejects_unsigned_fake_signer_and_missing_attestation(self):
        checker = self.checker()
        other = Ed25519PrivateKey.generate()
        for value in (
            self._sign(self.statement, signer=other),
            SignedBusinessOwnerDecision(self.statement, b""),
            SignedBusinessOwnerDecision(self.statement, bytes(64)),
            {"ownership_status": "VERIFIED"},
            None,
        ):
            with self.subTest(kind=type(value).__name__):
                self.resolved = value if value is not None else False
                self.assertFalse(checker(SUBJECT_ONE, BUSINESS_ONE, "DEVELOPMENT"))
        self.resolved = SignedBusinessOwnerDecision(
            dict(self.statement, extra_claim="admin"),
            self._sign(self.statement).signature,
        )
        self.assertFalse(checker(SUBJECT_ONE, BUSINESS_ONE, "DEVELOPMENT"))

    def test_signed_but_invalid_scope_status_or_times_is_denied(self):
        now = datetime.now(timezone.utc)
        changes = (
            {"purpose": "AVUHZ_OTHER_ASSERTION"},
            {"issuer": "GITHUB_OWNER"},
            {"environment": "PRODUCTION"},
            {"auth_project_ref": DEVELOPMENT_DATA_PROJECT_REF},
            {"data_project_ref": DEVELOPMENT_AUTH_PROJECT_REF},
            {"auth_project_ref": DEVELOPMENT_DATA_PROJECT_REF,
             "data_project_ref": DEVELOPMENT_DATA_PROJECT_REF},
            {"ownership_status": "PENDING"},
            {"ownership_status": "REVOKED"},
            {"issued_at": _utc(now - timedelta(seconds=90))},
            {"issued_at": _utc(now + timedelta(seconds=45))},
            {"expires_at": _utc(now - timedelta(seconds=1))},
            {"expires_at": _utc(now + timedelta(seconds=300))},
            {"expires_at": "invalid"},
            {"issued_at": "invalid"},
            {"issued_at": _utc(now + timedelta(seconds=20)),
             "expires_at": _utc(now + timedelta(seconds=30))},
        )
        checker = self.checker()
        for changed in changes:
            with self.subTest(changed=changed):
                s = dict(self.statement, **changed)
                self.resolved = self._sign(s)
                self.assertFalse(checker(SUBJECT_ONE, BUSINESS_ONE, "DEVELOPMENT"))

    def test_bogus_or_absent_inputs_deny_without_fetch(self):
        checker = self.checker()
        for subject, business, env in (
            ("not-a-digest", BUSINESS_ONE, "DEVELOPMENT"),
            (SUBJECT_ONE, "x", "DEVELOPMENT"),
            (SUBJECT_ONE, "Fictional Company", "DEVELOPMENT"),
            (SUBJECT_ONE, BUSINESS_ONE, "STAGING"),
            (SUBJECT_ONE, BUSINESS_ONE, None),
            (None, BUSINESS_ONE, "DEVELOPMENT"),
            (SUBJECT_ONE, None, "DEVELOPMENT"),
            (SUBJECT_ONE, BUSINESS_ONE, {"environment": "DEVELOPMENT"}),
        ):
            with self.subTest(subject=subject, business=business):
                self.assertFalse(checker(subject, business, env))
        self.assertEqual(self.requests, [])

    def test_key_pin_and_reader_are_independently_required(self):
        for changes in (
            {"pinned_fingerprint": "sha256:" + "0" * 64},
            {"directory_public_key": "caller-key"},
            {"fetch_signed_decision": None},
        ):
            args = dict(
                directory_public_key=self.public,
                pinned_fingerprint=self.fingerprint,
                fetch_signed_decision=lambda *_: self._sign(self.statement),
            )
            args.update(changes)
            with self.subTest(changes=tuple(changes)):
                with self.assertRaises(ValueError):
                    DevelopmentBusinessOwnerDirectoryCheck(**args)

    def test_directory_failure_does_not_disclose_provider_details(self):
        def failing_provider(_subject, _business):
            raise RuntimeError("private test directory response")

        checker = DevelopmentBusinessOwnerDirectoryCheck(
            directory_public_key=self.public,
            pinned_fingerprint=self.fingerprint,
            fetch_signed_decision=failing_provider,
        )
        self.assertFalse(checker(SUBJECT_ONE, BUSINESS_ONE, "DEVELOPMENT"))

    def test_adapter_has_no_enrollment_authority_or_vertical_dependency(self):
        source = (ROOT / "src/avuhz_service/development_business_owner_directory.py").read_text()
        for forbidden in (
            "service_role", "CREATE ROLE", "GRANT ", "sekinfra",
            "stripe.", "n8n.", "requests.post", "INSERT INTO",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn("CANNOT attest their", source)


if __name__ == "__main__":
    unittest.main()
