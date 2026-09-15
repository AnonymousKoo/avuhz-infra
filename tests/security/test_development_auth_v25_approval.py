from __future__ import annotations

import runpy
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = ROOT / "tests/contracts/validate_development_auth_plan_v25.py"


class DevelopmentAuthV25ApprovalTests(unittest.TestCase):
    def test_exact_v25_owner_approval_is_certified(self):
        namespace = runpy.run_path(str(VALIDATOR))
        self.assertEqual(namespace["main"](), 0)


if __name__ == "__main__":
    unittest.main()
