from __future__ import annotations

import os
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class DevelopmentAuthV32PlanTests(unittest.TestCase):
    def test_v32_synthetic_token_failure_is_recorded_consumed(self) -> None:
        env = dict(os.environ)
        env["PYTHONPATH"] = "src:."
        result = subprocess.run(
            ["python3", "tests/contracts/validate_development_auth_plan_v32.py"],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)
        self.assertIn("DEVELOPMENT_AUTH_V32_FAILED_CONSUMED=PASS", result.stdout)


if __name__ == "__main__":
    unittest.main()
