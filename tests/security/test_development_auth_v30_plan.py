from __future__ import annotations

import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class DevelopmentAuthV30PlanTests(unittest.TestCase):
    def test_v30_synthetic_token_preparation_is_certified(self) -> None:
        result = subprocess.run(
            ["python3", "tests/contracts/validate_development_auth_plan_v30.py"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=True,
        )
        self.assertIn("DEVELOPMENT_AUTH_V30_PREPARED=PASS", result.stdout)


if __name__ == "__main__":
    unittest.main()
