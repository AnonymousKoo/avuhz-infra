"""Offline DEVELOPMENT DATA TLS-preflight tests, with generated public test CAs.

No Supabase connection, database operation, credential, GitHub environment
secret, network socket or production resource is used. Generated test private
keys live only in memory and are never committed or printed.
"""
from __future__ import annotations

import dataclasses
import hashlib
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.development_handoff_runner_connection_candidate import (
    DevelopmentRunnerTransportStop,
)
from avuhz_engineering.development_handoff_runner_tls_preflight import (
    prepare_development_runner_tls_policy_v1,
)

NOW = datetime(2026, 10, 11, tzinfo=timezone.utc)
DATA_REF = "gnuqaefotwgkwurjpyik"
AUTH_REF = "pwlhruwutoitnieactol"


def make_fake_ca(*, cn="Supabase Root 2021 CA", org="Supabase Inc",
                 is_ca=True, not_after=None, sign_with_other=False):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signer = rsa.generate_private_key(public_exponent=65537, key_size=2048) if sign_with_other else key
    name = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=30))
        .not_valid_after(not_after or NOW + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=is_ca, crl_sign=is_ca,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(signer, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


class RunnerCaPreflightOfflineTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.file = self.root / "fake-public-ca.crt"
        self.set_ca(make_fake_ca())

    def set_ca(self, data):
        self.file.write_bytes(data)
        self.pin = "sha256:" + hashlib.sha256(data).hexdigest()

    def invoke(self, **changes):
        params = dict(
            environment="DEVELOPMENT",
            data_project_ref=DATA_REF,
            mode="session_pooler",
            ca_path=str(self.file),
            independently_enrolled_ca_sha256=self.pin,
            as_of_utc=NOW,
        )
        params.update(changes)
        return prepare_development_runner_tls_policy_v1(**params)

    def test_offline_pinned_certificate_prepares_exact_session_pooler_profile(self):
        with patch("socket.create_connection", side_effect=AssertionError("network forbidden")):
            receipt = self.invoke()
        p = receipt.policy
        self.assertEqual(p.host, "aws-1-us-west-2.pooler.supabase.com")
        self.assertEqual(p.user, "avuhz_handoff_claim_runner_dev." + DATA_REF)
        self.assertEqual(p.port, 5432)
        self.assertEqual(p.sslmode, "verify-full")
        self.assertEqual(p.expected_ca_sha256, self.pin)
        self.assertTrue(receipt.certificate_parsed)
        self.assertTrue(receipt.certificate_is_current_ca)
        self.assertTrue(receipt.supplied_digest_matches_file)
        self.assertFalse(receipt.independent_ca_origin_verified)
        self.assertFalse(receipt.client_to_provider_tls_handshake_verified)
        self.assertFalse(receipt.connection_or_credential_authorized)

    def test_direct_connection_is_still_constrained_to_development_data(self):
        p = self.invoke(mode="direct").policy
        self.assertEqual(p.host, "db." + DATA_REF + ".supabase.co")
        self.assertEqual(p.user, "avuhz_handoff_claim_runner_dev")
        self.assertEqual(p.port, 5432)
        self.assertEqual(p.sslmode, "verify-full")

    def test_auth_or_non_development_or_unapproved_modes_fail_closed(self):
        for changes in (
            {"data_project_ref": AUTH_REF},
            {"environment": "PRODUCTION"},
            {"environment": "STAGING"},
            {"mode": "transaction_pooler"},
            {"mode": "session-pooler"},
            {"mode": "auto"},
            {"as_of_utc": NOW.replace(tzinfo=None)},
            {"independently_enrolled_ca_sha256": "not-a-pin"},
        ):
            with self.subTest(changes=changes), self.assertRaisesRegex(
                DevelopmentRunnerTransportStop,
                "HANDOFF_RUNNER_TLS_PREFLIGHT_SCOPE_INVALID",
            ):
                self.invoke(**changes)

    def test_wrong_digest_or_changed_file_rejected(self):
        changed = "sha256:" + "0" * 64
        with self.assertRaisesRegex(
            DevelopmentRunnerTransportStop, "HANDOFF_RUNNER_CA_UNVERIFIED"
        ):
            self.invoke(independently_enrolled_ca_sha256=changed)
        self.file.write_bytes(self.file.read_bytes() + b"unexpected changes")
        with self.assertRaisesRegex(
            DevelopmentRunnerTransportStop, "HANDOFF_RUNNER_CA_UNVERIFIED"
        ):
            self.invoke()

    def test_symlink_missing_extra_pem_or_oversized_rejected(self):
        original = self.file.read_bytes()
        self.file.unlink()
        with self.assertRaisesRegex(
            DevelopmentRunnerTransportStop, "HANDOFF_RUNNER_CA_UNVERIFIED"
        ):
            self.invoke()
        target = self.root / "other.crt"
        target.write_bytes(original)
        self.file.symlink_to(target)
        with self.assertRaisesRegex(
            DevelopmentRunnerTransportStop, "HANDOFF_RUNNER_CA_UNVERIFIED"
        ):
            self.invoke()
        self.file.unlink()
        for data in (original + original, original + b"UNTRUSTED", b"X" * 65537):
            self.set_ca(data)
            with self.assertRaisesRegex(
                DevelopmentRunnerTransportStop, "HANDOFF_RUNNER_CA_UNVERIFIED"
            ):
                self.invoke()

    def test_wrong_ca_identity_or_invalid_root_signature_rejected(self):
        candidates = (
            make_fake_ca(cn="Unrelated CA"),
            make_fake_ca(org="Unrelated Organization"),
            make_fake_ca(is_ca=False),
            make_fake_ca(sign_with_other=True),
        )
        for candidate in candidates:
            with self.subTest(digest=hashlib.sha256(candidate).hexdigest()[:10]):
                self.set_ca(candidate)
                with self.assertRaisesRegex(
                    DevelopmentRunnerTransportStop, "HANDOFF_RUNNER_CA_UNVERIFIED"
                ):
                    self.invoke()

    def test_expired_ca_rejected_even_if_hash_matches(self):
        self.set_ca(make_fake_ca(not_after=NOW - timedelta(days=1)))
        with self.assertRaisesRegex(
            DevelopmentRunnerTransportStop, "HANDOFF_RUNNER_CA_UNVERIFIED"
        ):
            self.invoke()

    def test_matching_self_signed_ca_alone_never_asserts_origin(self):
        # A separate fabricated self-signed root with the same CA *name*
        # and a matching locally calculated digest still cannot prove issuer.
        receipt = self.invoke()
        self.set_ca(make_fake_ca())
        next_receipt = self.invoke()
        self.assertNotEqual(
            receipt.policy.expected_ca_sha256,
            next_receipt.policy.expected_ca_sha256,
        )
        self.assertFalse(next_receipt.independent_ca_origin_verified)
        self.assertFalse(next_receipt.connection_or_credential_authorized)


if __name__ == "__main__":
    unittest.main()
