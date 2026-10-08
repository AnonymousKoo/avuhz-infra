"""Pure offline proof-of-possession tests, never an owner-approval test."""
from __future__ import annotations

import hashlib
import json
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "src")]

from avuhz_engineering.development_handoff_owner_key_enrollment import (
    PURPOSE, OwnerKeyEnrollmentStop, verify_owner_key_enrollment_candidate,
)
from avuhz_engineering.development_handoff_approval_gate import EXPECTED_OWNER
from avuhz_engineering.development_source_bound_handoff_lifecycle import REPOSITORY
from avuhz_service.development import (
    DEVELOPMENT_AUTH_PROJECT_REF, DEVELOPMENT_DATA_PROJECT_REF,
)
from avuhz_service.development_supabase_identity import (
    DEVELOPMENT_PROVIDER_ADAPTER_IMPLEMENTATION_HANDOFF_ENTRY,
)

AT = datetime(2026, 10, 8, 22, 30, tzinfo=timezone.utc)


class DevelopmentOwnerKeyEnrollmentCandidateTests(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()  # ephemeral test only
        self.public = self.key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        self.fingerprint = "sha256:" + hashlib.sha256(self.public).hexdigest()
        self.statement = {
            "purpose": PURPOSE,
            "owner_identity": EXPECTED_OWNER,
            "repository": REPOSITORY,
            "environment": "DEVELOPMENT",
            "tenant_id": DEVELOPMENT_PROVIDER_ADAPTER_IMPLEMENTATION_HANDOFF_ENTRY.tenant_id,
            "auth_project_ref": DEVELOPMENT_AUTH_PROJECT_REF,
            "data_project_ref": DEVELOPMENT_DATA_PROJECT_REF,
            "public_key_sha256": self.fingerprint,
            "issued_at": "2026-10-08T22:25:00Z",
            "expires_at": "2026-10-08T22:40:00Z",
            "nonce": "fresh_owner_enrollment_nonce_0123456789",
        }

    def prove(self, statement=None, *, public=None, signature=None, at=AT):
        statement = self.statement if statement is None else statement
        encoded = json.dumps(
            statement, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode()
        signature = self.key.sign(encoded) if signature is None else signature
        return verify_owner_key_enrollment_candidate(
            statement, signature, self.public if public is None else public,
            at_utc=at,
        )

    def test_signed_candidate_proves_possession_not_owner_or_live_authority(self):
        result = self.prove()
        self.assertEqual(result.public_key_sha256, self.fingerprint)
        self.assertTrue(result.candidate_signature_verified)
        self.assertTrue(result.candidate_scope_verified)
        self.assertFalse(result.human_owner_binding_verified)
        self.assertFalse(result.owner_fingerprint_independently_pinned)
        self.assertFalse(result.signed_stage_approvals_verified)
        self.assertFalse(result.provider_or_credential_authority)
        self.assertFalse(result.live_execution_authorized)

    def test_wrong_signer_or_key_fails_closed(self):
        other = Ed25519PrivateKey.generate()
        with self.assertRaisesRegex(
            OwnerKeyEnrollmentStop, "HANDOFF_ENROLLMENT_SIGNATURE_INVALID"
        ):
            encoded = json.dumps(
                self.statement, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ).encode()
            self.prove(signature=other.sign(encoded))
        wrong_public = other.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        with self.assertRaisesRegex(
            OwnerKeyEnrollmentStop, "HANDOFF_ENROLLMENT_BINDING_INVALID"
        ):
            self.prove(public=wrong_public)

    def test_auth_and_data_cannot_be_exchanged(self):
        swapped = {
            **self.statement,
            "auth_project_ref": DEVELOPMENT_DATA_PROJECT_REF,
            "data_project_ref": DEVELOPMENT_AUTH_PROJECT_REF,
        }
        with self.assertRaisesRegex(
            OwnerKeyEnrollmentStop, "HANDOFF_ENROLLMENT_BINDING_INVALID"
        ):
            self.prove(swapped)

    def test_owner_repository_tenant_production_and_fingerprint_drift_denied(self):
        alterations = (
            {"owner_identity": "github:untrusted"},
            {"repository": "AnonymousKoo/other"},
            {"tenant_id": "d5000000-0000-4000-8000-000000000001"},
            {"environment": "production"},
            {"public_key_sha256": "sha256:" + "0" * 64},
        )
        for change in alterations:
            with self.subTest(change=change), self.assertRaisesRegex(
                OwnerKeyEnrollmentStop, "HANDOFF_ENROLLMENT_BINDING_INVALID"
            ):
                self.prove({**self.statement, **change})

    def test_expired_future_or_oversized_windows_denied(self):
        statements = (
            {**self.statement, "expires_at": "2026-10-08T22:30:00Z"},
            {**self.statement, "issued_at": "2026-10-08T22:31:00Z"},
            {**self.statement, "expires_at": "2026-10-08T22:41:00Z"},
        )
        for statement in statements:
            with self.subTest(statement=statement["issued_at"]+statement["expires_at"]):
                with self.assertRaisesRegex(
                    OwnerKeyEnrollmentStop, "HANDOFF_ENROLLMENT_WINDOW_INVALID"
                ):
                    self.prove(statement)

    def test_malformed_statement_and_signature_denied(self):
        for bad in (
            {**self.statement, "nonce": "short"},
            {**self.statement, "unknown_field": "untrusted"},
            {k: v for k, v in self.statement.items() if k != "purpose"},
        ):
            with self.subTest(bad=tuple(sorted(bad))):
                with self.assertRaises(OwnerKeyEnrollmentStop):
                    self.prove(bad)
        with self.assertRaisesRegex(
            OwnerKeyEnrollmentStop, "HANDOFF_ENROLLMENT_SHAPE_INVALID"
        ):
            self.prove(signature=b"invalid")

    def test_no_private_key_or_owner_attribution_artifact_created(self):
        self.assertFalse(hasattr(self.prove(), "private_key"))
        self.assertFalse(hasattr(self.prove(), "trusted_owner_identity"))
        self.assertFalse(hasattr(self.prove(), "authorization_granted"))


if __name__ == "__main__":
    unittest.main()
