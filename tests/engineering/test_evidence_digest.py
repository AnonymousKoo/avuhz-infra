"""Regression tests for canonical evidence digests with embedded self-digests."""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.authorization_plan import AuthorizationPlanError
from avuhz_engineering.evidence_digest import evidence_digest
from avuhz_runtime.implementation_handoff import canonical_digest


V7_LATE_REJECTION = (
    ROOT
    / "contracts/plans/v1/"
    / "development-implementation-handoff-provider-adapter-positive-auth-v7-late-window-rejection.evidence.json"
)
V7_DIGEST = "sha256:5ea9bd9fade9a6b5674f190bc133a7aa70233e06c50193e7125f26303d8eca5b"


class EvidenceDigestTests(unittest.TestCase):
    def test_embedded_digest_is_excluded_from_its_own_body_digest(self) -> None:
        evidence = json.loads(V7_LATE_REJECTION.read_text())

        self.assertEqual(evidence["evidence_digest"], V7_DIGEST)
        self.assertEqual(evidence_digest(evidence), V7_DIGEST)
        self.assertNotEqual(canonical_digest(evidence), V7_DIGEST)

    def test_invalid_embedded_digest_fails_closed(self) -> None:
        evidence = json.loads(V7_LATE_REJECTION.read_text())
        evidence["evidence_digest"] = "sha256:" + "0" * 64

        with self.assertRaisesRegex(AuthorizationPlanError, "EVIDENCE_DIGEST_INVALID"):
            evidence_digest(evidence)

    def test_evidence_without_embedded_digest_uses_whole_body(self) -> None:
        evidence = {
            "evidence_type": "fictional.validation",
            "environment": "DEVELOPMENT",
            "outcome": "PASS",
        }

        self.assertEqual(evidence_digest(evidence), canonical_digest(evidence))


if __name__ == "__main__":
    unittest.main()
