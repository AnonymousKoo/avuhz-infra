import sys
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/"src"))
from avuhz_runtime.command_registry import COMMANDS,resolve_command
from avuhz_runtime.schema_registry import SchemaRegistry
from avuhz_runtime.phase5d_brief import IMPLEMENTATION_BRIEF_COMMANDS
from avuhz_runtime.phase5d_authorization import IMPLEMENTATION_AUTHORIZATION_COMMANDS
from avuhz_runtime.phase5d_package import CODEX_BUILD_PACKAGE_COMMANDS
from avuhz_runtime.phase5d_build_execution import BUILD_EXECUTION_COMMANDS
from avuhz_runtime.phase5d_qa_result import QA_RESULT_COMMANDS
class Tests(unittest.TestCase):
 def test_registry_is_exactly_active_surface(self):
  expected={"AcceptAcquisitionHandoff","OpenEngagement"}|set(IMPLEMENTATION_BRIEF_COMMANDS)|set(IMPLEMENTATION_AUTHORIZATION_COMMANDS)|set(CODEX_BUILD_PACKAGE_COMMANDS)|set(BUILD_EXECUTION_COMMANDS)|set(QA_RESULT_COMMANDS)
  self.assertEqual(set(COMMANDS),expected);self.assertTrue(all(x.executable and x.validatable for x in COMMANDS.values()));self.assertIsNone(resolve_command("CompanySpecificCommand"))
 def test_schema_catalog_is_fixed_and_local(self):
  r=SchemaRegistry(ROOT/"contracts/schemas/v1");self.assertGreaterEqual(len(r.schema_ids),50)
  with self.assertRaises(KeyError):r.resolve("https://example.invalid/schema")
if __name__=="__main__":unittest.main()
