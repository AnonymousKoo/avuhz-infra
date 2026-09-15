from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = ROOT / "tests/contracts/validate_development_auth_admin_retirement.py"


class DevelopmentAuthAdminRetirementTests(unittest.TestCase):
    def test_bootstrap_credential_retirement_is_certified(self):
        result = subprocess.run(
            [sys.executable, str(VALIDATOR)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("DEVELOPMENT_AUTH_ADMIN_RETIREMENT=PASS", result.stdout)


if __name__ == "__main__":
    unittest.main()
