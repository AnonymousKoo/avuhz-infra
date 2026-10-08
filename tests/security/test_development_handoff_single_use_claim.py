"""No-network tests for signed DEVELOPMENT owner proof and single-host claim."""
from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests/security"), str(ROOT / "tests/service")]
from test_development_handoff_approval_gate import (
    AT, DevelopmentHandoffApprovalGateTests,
)
from avuhz_engineering.development_handoff_single_use_claim import (
    SingleUseClaimStop, verify_and_claim_single_stage_offline,
)


class SignedSingleUseClaimTests(unittest.TestCase):
    def setUp(self):
        fixture = DevelopmentHandoffApprovalGateTests(
            methodName="test_real_engine_proposes_each_stage_individually_without_execution"
        )
        fixture.setUp()
        self.fixture = fixture
        self.private = Ed25519PrivateKey.generate()
        self.public = self.private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        self.anchor = "sha256:" + sha256(self.public).hexdigest()
        self.tempdir = tempfile.TemporaryDirectory(prefix="avuhz-offline-stage-")
        self.addCleanup(self.tempdir.cleanup)
        self.ledger = Path(self.tempdir.name) / "once.sqlite3"
        fd = os.open(str(self.ledger), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)

    def claims(self, stage="DATA_COMMAND"):
        doc = self.fixture.stages[stage]
        return {
            "purpose": "AVUHZ_DEVELOPMENT_HANDOFF_STAGE_OWNER_APPROVAL_V1",
            "owner_identity": "github:AnonymousKoo",
            "repository": self.fixture.source.repository,
            "source_sha": self.fixture.source.canonical_main_sha,
            "command_digest": self.fixture.source.command_digest,
            "authorization_set_digest": self.fixture.source.authorization_plan_digest,
            "stage": stage,
            "plan_digest": doc.plan["plan_digest"],
            "approval_digest": doc.approval["approval_digest"],
            "tenant_id": self.fixture.source.tenant_id,
            "project_reference": doc.plan["target"]["project_reference"],
            "not_before": doc.approval["effective_at"],
            "expires_at": doc.approval["expires_at"],
            "nonce": "owner_signed_nonce_0123456789",
        }

    def invoke(self, stage="DATA_COMMAND", *, claims=None, signature=None, **changes):
        claims = self.claims(stage) if claims is None else claims
        serialized = json.dumps(
            claims, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode()
        signature = self.private.sign(serialized) if signature is None else signature
        args = dict(
            request=self.fixture.command,
            source=self.fixture.source,
            observed_main_sha=self.fixture.source.canonical_main_sha,
            at_utc=AT,
            stage=stage,
            stages=self.fixture.stages,
            owner_claims=claims,
            owner_signature=signature,
            pinned_owner_public_key=self.public,
            pinned_owner_key_digest=self.anchor,
            ledger_path=self.ledger,
        )
        args.update(changes)
        return verify_and_claim_single_stage_offline(**args)

    def test_signed_claim_once_then_replay_denied(self):
        with patch("urllib.request.urlopen", side_effect=AssertionError("network prohibited")):
            receipt = self.invoke()
        self.assertTrue(receipt.durable_local_claim_recorded)
        self.assertFalse(receipt.remote_execution_authorized)
        self.assertFalse(receipt.retry_authorized)
        self.assertFalse(receipt.distributed_consumption_verified)
        self.assertFalse(receipt.owner_signing_key_binding_verified_externally)
        with self.assertRaisesRegex(SingleUseClaimStop, "HANDOFF_STAGE_ALREADY_CLAIMED"):
            self.invoke()
        with sqlite3.connect(self.ledger) as db:
            rows = db.execute(
                "SELECT stage, count(*) FROM avuhz_offline_handoff_stage_claim GROUP BY stage"
            ).fetchall()
        self.assertEqual(rows, [("DATA_COMMAND", 1)])

    def test_concurrent_attempts_exactly_one_claim(self):
        with ThreadPoolExecutor(max_workers=8) as workers:
            futures = [workers.submit(self.invoke) for _ in range(8)]
            successful, stopped = 0, []
            for future in futures:
                try:
                    result = future.result()
                except SingleUseClaimStop as exc:
                    stopped.append(str(exc))
                else:
                    self.assertFalse(result.remote_execution_authorized)
                    successful += 1
        self.assertEqual(successful, 1)
        self.assertEqual(stopped, ["HANDOFF_STAGE_ALREADY_CLAIMED"] * 7)

    def test_forged_signature_or_unsigned_mutation_rejected_before_claim(self):
        claims = self.claims()
        encoded = json.dumps(
            claims, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode()
        valid_sig = self.private.sign(encoded)
        tampered = {**claims, "command_digest": "sha256:" + "f" * 64}
        with self.assertRaisesRegex(SingleUseClaimStop, "HANDOFF_OWNER_PROOF_BINDING_MISMATCH"):
            self.invoke(claims=tampered, signature=valid_sig)
        other = Ed25519PrivateKey.generate()
        bad_sig = other.sign(encoded)
        with self.assertRaisesRegex(SingleUseClaimStop, "HANDOFF_OWNER_SIGNATURE_INVALID"):
            self.invoke(signature=bad_sig)
        with sqlite3.connect(self.ledger) as db:
            rows = db.execute(
                "SELECT name FROM sqlite_master WHERE name='avuhz_offline_handoff_stage_claim'"
            ).fetchall()
        self.assertEqual(rows, [])

    def test_unpinned_or_substituted_key_rejected(self):
        with self.assertRaisesRegex(SingleUseClaimStop, "HANDOFF_OWNER_TRUST_ANCHOR_UNVERIFIED"):
            self.invoke(pinned_owner_key_digest="sha256:" + "0" * 64)
        with self.assertRaisesRegex(SingleUseClaimStop, "HANDOFF_OWNER_TRUST_ANCHOR_UNVERIFIED"):
            self.invoke(pinned_owner_public_key=b"0" * 32)

    def test_wrong_project_scope_and_expiry_stop_before_claim(self):
        claims = self.claims()
        claims["project_reference"] = self.fixture.source.auth_project_ref
        with self.assertRaisesRegex(SingleUseClaimStop, "HANDOFF_OWNER_PROOF_BINDING_MISMATCH"):
            self.invoke(claims=claims)
        with self.assertRaisesRegex(SingleUseClaimStop, "HANDOFF_OWNER_PROOF_EXPIRED"):
            self.invoke(at_utc=datetime(2026, 10, 8, 19, 21, tzinfo=timezone.utc))

    def test_private_preprovisioned_ledger_required(self):
        missing = Path(self.tempdir.name) / "missing.sqlite3"
        with self.assertRaisesRegex(SingleUseClaimStop, "HANDOFF_CLAIM_LEDGER_UNAVAILABLE"):
            self.invoke(ledger_path=missing)
        os.chmod(self.ledger, 0o644)
        with self.assertRaisesRegex(SingleUseClaimStop, "HANDOFF_CLAIM_LEDGER_UNTRUSTED"):
            self.invoke()

    def test_distinct_stage_claims_are_independent(self):
        first = self.invoke("AUTH_GENERATE")
        second = self.invoke("DATA_COMMAND")
        self.assertEqual((first.stage, second.stage), ("AUTH_GENERATE", "DATA_COMMAND"))
        with sqlite3.connect(self.ledger) as db:
            count = db.execute(
                "SELECT COUNT(*) FROM avuhz_offline_handoff_stage_claim"
            ).fetchone()[0]
        self.assertEqual(count, 2)


if __name__ == "__main__":
    unittest.main()
