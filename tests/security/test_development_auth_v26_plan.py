from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = ROOT / "tests/contracts/validate_development_auth_plan_v26.py"


class DevelopmentAuthV26PlanTests(unittest.TestCase):
    def test_v26_local_allowlist_outcome_is_certified(self):
        result = subprocess.run(
            [sys.executable, str(VALIDATOR)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("DEVELOPMENT_AUTH_V26_OUTCOME=PASS", result.stdout)


if __name__ == "__main__":
    unittest.main()
