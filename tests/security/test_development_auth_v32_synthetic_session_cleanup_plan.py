from __future__ import annotations

import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class DevelopmentAuthV32SyntheticSessionCleanupPlanTests(unittest.TestCase):
    def test_preparation_is_pristine_and_fail_closed(self) -> None:
        result = subprocess.run(
            [
                "python3",
                "tests/contracts/validate_development_auth_v32_synthetic_session_cleanup_v1.py",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=True,
        )
        self.assertIn(
            "DEVELOPMENT AUTH v32 synthetic-session cleanup v1 preparation: VALID",
            result.stdout,
        )


if __name__ == "__main__":
    unittest.main()
