"""Offline wheel proof for the canonical catalog and LOCAL/TEST workers."""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class InstalledWheelSchemaCatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.isolated = Path(cls.temporary.name)
        project = cls.isolated / "project"
        project.mkdir()
        for name in ("pyproject.toml", "README.md"):
            shutil.copy2(ROOT / name, project / name)
        for name in ("src", "contracts"):
            shutil.copytree(ROOT / name, project / name, ignore=shutil.ignore_patterns("__pycache__"))
        wheels = cls.isolated / "wheels"
        wheels.mkdir()
        # Invoke the already-installed backend directly: no pip, installs,
        # dependency resolution, build isolation, or downloads.
        build = subprocess.run(
            [sys.executable, "-I", "-c",
             "import sys; from setuptools.build_meta import build_wheel; build_wheel(sys.argv[1])",
             str(wheels)],
            cwd=project, capture_output=True, text=True,
        )
        if build.returncode:
            raise AssertionError(build.stdout + build.stderr)
        cls.wheel = next(wheels.glob("avuhz_service-*.whl"))

    def setUp(self):
        self.installation = self.isolated / self.id().split(".")[-1]
        with zipfile.ZipFile(self.wheel) as archive:
            archive.extractall(self.installation)

    def proof(self, body):
        script = '''
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
installation = Path(sys.argv[1])
assert Path(sys.argv[2]) not in map(Path, sys.path)
assert Path(sys.argv[2]) / "src" not in map(Path, sys.path)
from datetime import datetime, timedelta, timezone
from avuhz_runtime.guards import TrustedExecutionContext
from avuhz_runtime.schema_registry import SCHEMA_FILES, SchemaRegistry, schema_root
from avuhz_service.composition import schema_root as service_schema_root
from avuhz_worker.shared_communications_local import DeterministicLocalCommunicationsFake
from avuhz_worker.shared_usage_billing_local import DeterministicLocalUsageBillingFake
for module in ("avuhz_runtime", "avuhz_service", "avuhz_worker"):
    assert installation in Path(sys.modules[module].__file__).parents
now = datetime.now(timezone.utc)
tenant = "f1000000-0000-4000-8000-000000000001"
context = TrustedExecutionContext(
    True, "service.wheel-test", "INTERNAL_SERVICE", tenant, None,
    frozenset({"event:publish_internal"}), frozenset(), "TEST",
    "avuhz-command-api", "STRONG", False, now.isoformat(),
    (now + timedelta(hours=1)).isoformat(), human_authority_role=None,
)
fakes = (DeterministicLocalCommunicationsFake, DeterministicLocalUsageBillingFake)
def construct(fake):
    return fake(tenant_id=tenant, environment="TEST", trusted_context=context)
'''
        result = subprocess.run(
            [sys.executable, "-I", "-c", textwrap.dedent(script) + textwrap.dedent(body),
             str(self.installation), str(ROOT)],
            cwd=self.isolated, capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_schema_catalog_and_workers_resolve_from_extracted_wheel(self):
        # The wheel must carry the exact canonical files, not a partial or stale copy.
        source = ROOT / "contracts/schemas/v1"
        packaged = self.installation / "avuhz_contracts/schemas/v1"
        self.assertEqual(
            {p.relative_to(source) for p in source.rglob("*.json")},
            {p.relative_to(packaged) for p in packaged.rglob("*.json")},
        )
        for path in source.rglob("*.json"):
            self.assertEqual(path.read_bytes(), (packaged / path.relative_to(source)).read_bytes())
        self.proof('''
root = schema_root()
assert root == installation / "avuhz_contracts/schemas/v1"
assert service_schema_root() == root
assert len(SchemaRegistry(root).schema_ids) == len(SCHEMA_FILES) == 76
for fake in fakes:
    construct(fake)
''')

    def assert_catalog_fails_closed(self, message):
        self.proof(f'''
for fake in fakes:
    try:
        construct(fake)
    except RuntimeError as error:
        assert str(error) == {message!r}
    else:
        raise AssertionError("worker accepted a missing canonical catalog")
''')

    def test_incomplete_catalog_fails_closed(self):
        (self.installation / "avuhz_contracts/schemas/v1/common/identifiers.schema.json").unlink()
        self.assert_catalog_fails_closed("approved local schema catalog is incomplete")

    def test_missing_catalog_directory_fails_closed(self):
        shutil.rmtree(self.installation / "avuhz_contracts/schemas/v1")
        self.assert_catalog_fails_closed("canonical schema catalog is unavailable")

    def test_missing_catalog_package_fails_closed(self):
        shutil.rmtree(self.installation / "avuhz_contracts")
        self.assert_catalog_fails_closed("canonical schema catalog is unavailable")


if __name__ == "__main__":
    unittest.main()
