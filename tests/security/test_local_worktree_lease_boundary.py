"""Static authority and capability boundary tests for Phase 2C."""
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

from avuhz_engineering.local_worktree_lease import (
    LeaseReleaseResult,
    LocalWorktreeLease,
    acquire_local_worktree_lease,
)


class LocalWorktreeLeaseBoundaryTests(unittest.TestCase):
    def test_module_has_no_command_network_git_or_process_surface(self):
        path = ROOT / "src/avuhz_engineering/local_worktree_lease.py"
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        imports: set[str] = set()
        calls: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.add(node.module or "")
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    calls.add(node.func.id)
                elif isinstance(node.func, ast.Attribute):
                    calls.add(node.func.attr)
        forbidden = {
            "subprocess", "socket", "urllib", "urllib.request", "http.client", "requests",
            "httpx", "git", "multiprocessing", "threading", "asyncio",
        }
        self.assertFalse(imports & forbidden)
        self.assertTrue({"run", "Popen", "system", "fork", "exec", "eval"}.isdisjoint(calls))
        self.assertNotIn("shell", inspect.signature(acquire_local_worktree_lease).parameters)
        self.assertNotIn("command", inspect.signature(acquire_local_worktree_lease).parameters)
        self.assertNotIn("lockfile", inspect.signature(acquire_local_worktree_lease).parameters)
        self.assertNotIn("lease_directory", inspect.signature(acquire_local_worktree_lease).parameters)

    def test_lock_is_nonblocking_retained_fd_and_filename_is_not_client_controlled(self):
        source = (ROOT / "src/avuhz_engineering/local_worktree_lease.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("fcntl.LOCK_EX | fcntl.LOCK_NB", source)
        self.assertIn("lease._descriptor = descriptor", source)
        self.assertIn('b"AVUHZ_LOCAL_WORKTREE_LEASE_V1\\0"', source)
        self.assertIn("O_NOFOLLOW", source)
        self.assertIn("st_nlink != 1", source)

    def test_live_owner_verification_is_owner_scoped_read_only_and_returns_nothing(self):
        signature = inspect.signature(LocalWorktreeLease.verify_live_owner)
        self.assertEqual(str(signature), "(self, *, owner_id: 'str') -> 'None'")
        source = (ROOT / "src/avuhz_engineering/local_worktree_lease.py").read_text(
            encoding="utf-8"
        )
        tree = ast.parse(source)
        method = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == "verify_live_owner"
        )
        calls = {
            node.func.attr
            for node in ast.walk(method)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }
        names = {node.id for node in ast.walk(method) if isinstance(node, ast.Name)}
        self.assertNotIn("flock", calls)
        self.assertTrue({"LOCK_EX", "LOCK_UN", "LOCK_NB"}.isdisjoint(names))
        self.assertIn("_read_fdinfo", names)
        self.assertIn("_verify_same_open_file_description", names)
        self.assertIn("_LIVE_LEASES", names)

    def test_all_public_result_types_deny_authority_and_isolation(self):
        release_defaults = {field.name: field.default for field in fields(LeaseReleaseResult)}
        self.assertIs(release_defaults["execution_authorized"], False)
        self.assertIs(release_defaults["os_isolation_certified"], False)
        self.assertEqual(release_defaults["provider_authority"], "NONE")
        with self.assertRaises(TypeError):
            LeaseReleaseResult(execution_authorized=True)
        release = LeaseReleaseResult()
        with self.assertRaises((AttributeError, TypeError)):
            release.execution_authorized = True
        uninitialized = object.__new__(LocalWorktreeLease)
        for member, forged in (
            ("execution_authorized", True),
            ("os_isolation_certified", True),
            ("provider_authority", "ALL"),
        ):
            with self.assertRaises(AttributeError):
                setattr(uninitialized, member, forged)
        for member in (
            "execution_authorized", "os_isolation_certified", "provider_authority",
            "deadline_enforced",
        ):
            self.assertIsInstance(inspect.getattr_static(LocalWorktreeLease, member), property)

    def test_schema_is_strict_and_cannot_claim_authority(self):
        schema = json.loads(
            (ROOT / "docs/schemas/local-worktree-lease-v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertFalse(schema["additionalProperties"])
        self.assertFalse(schema["properties"]["source"]["additionalProperties"])
        self.assertEqual(schema["properties"]["provider_authority"]["const"], "NONE")
        self.assertIs(schema["properties"]["execution_authorized"]["const"], False)
        self.assertIs(schema["properties"]["os_isolation_certified"]["const"], False)
        self.assertIs(schema["properties"]["deadline_enforced"]["const"], False)

    def test_documentation_preserves_advisory_and_future_sandbox_boundary(self):
        document = (ROOT / "docs/local-worktree-lease-v1.md").read_text(encoding="utf-8")
        normalized = " ".join(document.split())
        for required in (
            "does not turn the Phase 2B `observed_source` into authorization",
            "`flock` is advisory",
            "same UNIX UID",
            "repeat",
            "while the lease is held",
            "distinct principal",
            "isolated mount",
            "no inherited secrets",
            "no-network",
            "resource",
            "cannot execute a Codex job",
            "cooperative lock ownership at one instant",
            "never calls `flock`",
            "not ownership proof",
        ):
            self.assertIn(required, normalized)


if __name__ == "__main__":
    unittest.main()
