#!/usr/bin/env python3
"""Ensure the DEVELOPMENT DATA v3 continuation validator runs in Main PR Gate."""
from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = ROOT / "tests/contracts/validate_development_data_plan_v3.py"


class DevelopmentDataV3ContinuationGateTest(unittest.TestCase):
    def test_continuation_contract(self) -> None:
        subprocess.run(
            [sys.executable, str(VALIDATOR)],
            cwd=ROOT,
            check=True,
        )


if __name__ == "__main__":
    unittest.main()
