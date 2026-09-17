from __future__ import annotations

import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class DevelopmentAuthV32SessionInspectionPlanTests(unittest.TestCase):
    def test_preparation_is_canonical_and_pristine(self) -> None:
        result = subprocess.run(
            [
                "python3",
                "tests/contracts/validate_development_auth_v32_session_inspection_v1.py",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=True,
        )
        self.assertIn("DEVELOPMENT_AUTH_V32_SESSION_INSPECTION_V1_PREPARED=PASS", result.stdout)


if __name__ == "__main__":
    unittest.main()
