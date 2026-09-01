"""Installed-wheel proof for the canonical schema resource catalog."""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
import venv
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class InstalledWheelSchemaCatalogTests(unittest.TestCase):
    def test_schema_root_resolves_from_isolated_installed_wheel(self):
        with tempfile.TemporaryDirectory() as temporary:
            isolated = Path(temporary)
            wheels = isolated / "wheels"
            wheels.mkdir()
            environment = {**os.environ, "PIP_NO_INDEX": "1"}
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pip",
                    "wheel",
                    ".",
                    "--no-deps",
                    "--no-build-isolation",
                    "--disable-pip-version-check",
                    "-w",
                    str(wheels),
                ],
                cwd=ROOT,
                env=environment,
                check=True,
                capture_output=True,
                text=True,
            )
            wheel = next(wheels.glob("avuhz_service-*.whl"))
            installation = isolated / "installation"
            venv.EnvBuilder(with_pip=True, system_site_packages=True).create(installation)
            python = installation / "bin" / "python"
            subprocess.run(
                [str(python), "-m", "pip", "install", "--no-deps", "--no-index", str(wheel)],
                cwd=isolated,
                env=environment,
                check=True,
                capture_output=True,
                text=True,
            )
            proof = subprocess.run(
                [
                    str(python),
                    "-I",
                    "-c",
                    (
                        "import sys; from pathlib import Path; "
                        "from avuhz_service.composition import schema_root; "
                        "from avuhz_runtime.schema_registry import SCHEMA_FILES, SchemaRegistry; "
                        "root = schema_root(); registry = SchemaRegistry(root); "
                        "assert len(registry.schema_ids) == len(SCHEMA_FILES); "
                        "assert Path(sys.argv[1]) in root.parents; "
                        "assert Path(sys.argv[2]) not in map(Path, sys.path)"
                    ),
                    str(installation),
                    str(ROOT),
                ],
                cwd=isolated,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(proof.returncode, 0, proof.stderr)


if __name__ == "__main__":
    unittest.main()
