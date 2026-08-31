import importlib
import re
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from avuhz_runtime.command_registry import COMMANDS

FORBIDDEN = re.compile(
    r"sekinfra|oiaassessment|oia[_-](?:assessment|evidence|observation|root[_-]cause|finding|findings)|"
    r"findingrevision|findingsdelivery|diagnostic[_-]scope|assessment[_-]access|"
    r"conversion[_-]decision|ongoing[_-](?:agreement|payment)|offboarding",
    re.IGNORECASE,
)
ACTIVE_ROOTS = (ROOT / "src/avuhz_runtime", ROOT / "contracts")
REMOVED_RUNTIME = (
    "oia_assessment.py", "oia_evidence.py", "oia_observation.py", "oia_root_cause.py",
    "oia_finding.py", "oia_findings_delivery.py", "postgres_oia.py", "phase5c.py",
    "postgres_phase5c.py", "assessment_access_authority.py", "commercial_ingress.py",
)

class AvuhzSeparationTests(unittest.TestCase):
    def test_active_tree_has_no_company_or_consulting_runtime_dependency(self):
        hits = []
        for root in ACTIVE_ROOTS:
            for path in root.rglob("*"):
                if path.is_file() and path.suffix in {".py", ".json"}:
                    for number, line in enumerate(path.read_text().splitlines(), 1):
                        if FORBIDDEN.search(line): hits.append(f"{path.relative_to(ROOT)}:{number}")
        self.assertEqual(hits, [])

    def test_domain_runtime_modules_are_removed(self):
        for name in REMOVED_RUNTIME:
            self.assertFalse((ROOT / "src/avuhz_runtime" / name).exists(), name)

    def test_all_active_runtime_modules_import_without_company_code(self):
        for path in sorted((ROOT / "src/avuhz_runtime").glob("*.py")):
            try:
                importlib.import_module(f"avuhz_runtime.{path.stem}")
            except ModuleNotFoundError as error:
                if error.name != "psycopg":
                    raise

    def test_command_surface_is_shared_system_and_phase5d_only(self):
        for command in COMMANDS:
            self.assertIsNone(FORBIDDEN.search(command), command)
        self.assertIn("AcceptAcquisitionHandoff", COMMANDS)
        self.assertIn("OpenEngagement", COMMANDS)
        self.assertIn("DraftImplementationBrief", COMMANDS)
        self.assertIn("RecordQAResult", COMMANDS)

    def test_public_handoff_contract_is_identical_without_circular_import(self):
        avuhz = ROOT / "contracts/schemas/v1/public/implementation-handoff.schema.json"
        provider = Path("/home/network-p/sekinfra/consulting/contracts/public/implementation-handoff.schema.json")
        self.assertEqual(avuhz.read_bytes(), provider.read_bytes())
        source = "\n".join(path.read_text() for path in (ROOT / "src/avuhz_runtime").glob("*.py"))
        self.assertNotIn("sekinfra_consulting", source)

if __name__ == "__main__": unittest.main()
