"""Static authority and subprocess boundaries for the LOCAL observer."""
from __future__ import annotations

import ast
import inspect
import json
import sys
import unittest
from dataclasses import fields
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.local_worktree_observer import (
    LocalWorktreeObservation,
    observe_local_worktree,
)


class LocalWorktreeObserverBoundaryTests(unittest.TestCase):
    def test_public_api_has_no_command_environment_key_or_authority_input(self):
        parameters = set(inspect.signature(observe_local_worktree).parameters)
        prohibited = {
            "argv", "command", "environment", "env", "executable", "git_flags",
            "issuer", "private_key", "approval", "network", "provider_authority",
        }
        self.assertTrue(parameters.isdisjoint(prohibited))

    def test_result_cannot_claim_execution_or_os_isolation(self):
        result_fields = {field.name: field.default for field in fields(LocalWorktreeObservation)}
        self.assertIs(result_fields["execution_authorized"], False)
        self.assertIs(result_fields["os_isolation_certified"], False)
        self.assertEqual(result_fields["provider_authority"], "NONE")
        self.assertIs(result_fields["exclusive_lease_required"], True)
        self.assertIs(result_fields["repeat_at_execution_required"], True)

    def test_subprocess_surface_is_fixed_non_shell_and_has_no_network_import(self):
        source_path = ROOT / "src/avuhz_engineering/local_worktree_observer.py"
        source = source_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        imports: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.add(node.module or "")
        self.assertTrue(
            imports.isdisjoint({"socket", "urllib", "urllib.request", "http.client", "requests", "httpx"})
        )
        self.assertIn('shell=False', source)
        self.assertNotIn('shell=True', source)
        self.assertNotIn('os.environ.copy', source)
        self.assertNotIn('subprocess.run', source)
        self.assertNotIn('subprocess.call', source)
        self.assertNotIn('subprocess.check_output', source)

    def test_git_command_catalog_contains_reads_only(self):
        source = (ROOT / "src/avuhz_engineering/local_worktree_observer.py").read_text(
            encoding="utf-8"
        )
        for prohibited in (
            '"fetch"', '"push"', '"pull"', '"clone"', '"checkout"', '"reset"',
            '"clean"', '"add"', '"commit"', '"update-index"', '"gc"', '"maintenance"',
        ):
            self.assertNotIn(prohibited, source)
        for required in ('"rev-parse"', '"symbolic-ref"', '"status"', '"ls-files"'):
            self.assertIn(required, source)

    def test_schema_is_strict_and_denies_authority_claims(self):
        schema = json.loads(
            (ROOT / "docs/schemas/local-worktree-observation-v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertFalse(schema["additionalProperties"])
        properties = schema["properties"]
        self.assertEqual(properties["execution_authorized"]["const"], False)
        self.assertEqual(properties["os_isolation_certified"]["const"], False)
        self.assertEqual(properties["provider_authority"]["const"], "NONE")
        self.assertNotIn("issuer", properties)
        self.assertNotIn("approval", properties)
        self.assertNotIn("private_key", properties)

    def test_documentation_preserves_toctou_and_credential_boundary(self):
        document = (ROOT / "docs/local-worktree-observer-v1.md").read_text(encoding="utf-8")
        self.assertIn("time-of-check/time-of-use", document)
        self.assertIn("exclusive lease", document)
        self.assertIn("repeat this complete observation", document)
        self.assertIn("`os_isolation_certified` is always false", document)
        self.assertIn("not permission for unattended execution", document)
        self.assertIn("Gitlinks/submodules are denied", document)


if __name__ == "__main__":
    unittest.main()
