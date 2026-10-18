"""Static and negative security boundary tests for LOCAL admission."""
from __future__ import annotations

import ast
import json
import sys
import unittest
from dataclasses import fields
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.local_codex_admission import (
    AdmissionCandidate,
    AdmissionResult,
    COMMAND_PROFILE_IDS,
)


class LocalCodexAdmissionBoundaryTests(unittest.TestCase):
    def test_module_has_no_execution_network_thread_or_process_import(self):
        source_path = ROOT / "src/avuhz_engineering/local_codex_admission.py"
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        forbidden_roots = {
            "subprocess", "socket", "threading", "multiprocessing", "asyncio",
            "urllib.request", "http.client", "requests", "httpx", "git",
        }
        imported: set[str] = set()
        calls: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.add(node.module or "")
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    calls.add(node.func.id)
                elif isinstance(node.func, ast.Attribute):
                    calls.add(node.func.attr)
        self.assertFalse(imported & forbidden_roots)
        self.assertTrue({"run", "Popen", "system", "fork", "exec", "eval"}.isdisjoint(calls))

    def test_no_execution_capability_is_returned(self):
        candidate_fields = {field.name for field in fields(AdmissionCandidate)}
        result_fields = {field.name for field in fields(AdmissionResult)}
        prohibited = {"command", "argv", "callable", "callback", "runner", "worker", "retry"}
        self.assertTrue(candidate_fields.isdisjoint(prohibited))
        self.assertTrue(result_fields.isdisjoint(prohibited))
        self.assertIn("execution_authorized", candidate_fields)
        self.assertIn("execution_authorized", result_fields)

    def test_command_catalog_contains_identifiers_not_shell_strings(self):
        self.assertEqual(len(COMMAND_PROFILE_IDS), 5)
        for profile in COMMAND_PROFILE_IDS:
            self.assertRegex(profile, r"^[a-z][a-z0-9.-]+\.v1$")
            self.assertNotRegex(profile, r"[\s;&|`$()<>\\]")

    def test_schema_has_no_manifest_trust_key_or_execution_fields(self):
        schema = json.loads(
            (ROOT / "docs/schemas/local-codex-admission-v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        payload = schema["$defs"]["payload"]
        signature = schema["$defs"]["signature"]
        self.assertFalse({"public_key", "command", "argv", "shell"} & set(payload["properties"]))
        self.assertFalse({"public_key", "certificate", "jwk"} & set(signature["properties"]))
        self.assertEqual(payload["properties"]["mode"]["const"], "PREFLIGHT_ONLY")
        self.assertEqual(payload["properties"]["network"]["const"], False)
        self.assertEqual(payload["properties"]["provider_authority"]["const"], "NONE")
        self.assertEqual(payload["properties"]["github_mutation"]["const"], False)


if __name__ == "__main__":
    unittest.main()
