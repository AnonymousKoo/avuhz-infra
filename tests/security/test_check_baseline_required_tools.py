#!/usr/bin/env python3
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "check-baseline.sh"
EXPECTED_ERROR = "error: required command unavailable: rg"


class BaselineRequiredToolsTests(unittest.TestCase):
    def test_missing_rg_fails_closed_before_baseline_pass(self) -> None:
        bash = shutil.which("bash")
        self.assertIsNotNone(bash)

        with tempfile.TemporaryDirectory() as temporary_path:
            environment = os.environ.copy()
            environment["PATH"] = temporary_path
            result = subprocess.run(
                [bash, str(SCRIPT)],
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

        combined_output = result.stdout + result.stderr
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(EXPECTED_ERROR, result.stderr)
        self.assertNotIn("baseline checks: PASS", combined_output)


if __name__ == "__main__":
    unittest.main()
