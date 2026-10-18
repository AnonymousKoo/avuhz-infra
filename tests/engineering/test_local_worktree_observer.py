"""Synthetic LOCAL tests for trusted source/worktree observation."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

import avuhz_engineering.local_worktree_observer as observer_module
from avuhz_engineering.local_codex_admission import TrustedRepositoryObservation
from avuhz_engineering.local_worktree_observer import (
    ObservationDenied,
    observe_local_worktree,
)


class LocalWorktreeObserverTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.primary = self.base / "primary"
        self.worktree = self.base / "isolated"
        self._git("init", "-b", "main", str(self.primary), cwd=self.base)
        self._git("config", "user.name", "Synthetic Test", cwd=self.primary)
        self._git("config", "user.email", "synthetic@example.invalid", cwd=self.primary)
        (self.primary / "tracked.txt").write_text("clean\n", encoding="utf-8")
        self._git("add", "tracked.txt", cwd=self.primary)
        self._git("commit", "-m", "synthetic baseline", cwd=self.primary)
        self._git("worktree", "add", "-b", "observer", str(self.worktree), cwd=self.primary)
        self.common = self.primary / ".git"
        self.commit = self._git("rev-parse", "HEAD", cwd=self.worktree).strip()
        self.tree = self._git("rev-parse", "HEAD^{tree}", cwd=self.worktree).strip()
        self.reviewed = "sha256:" + "a" * 64
        self.isolation_id = "worktree.phase2b.synthetic"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _git(self, *arguments: str, cwd: Path) -> str:
        result = subprocess.run(
            ("/usr/bin/git", *arguments), cwd=cwd, env={"LANG": "C", "LC_ALL": "C"},
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        return result.stdout

    def _arguments(self, **overrides):
        values = {
            "worktree_root": self.worktree,
            "expected_worktree_root": self.worktree,
            "expected_common_git_dir": self.common,
            "expected_branch": "refs/heads/observer",
            "expected_commit": self.commit,
            "expected_tree": self.tree,
            "expected_reviewed_digest": self.reviewed,
            "isolation_id": self.isolation_id,
            "timeout_seconds": 5.0,
        }
        values.update(overrides)
        return values

    def _observe(self, **overrides):
        return observe_local_worktree(**self._arguments(**overrides))

    def assert_denied(self, code: str, **overrides) -> None:
        with self.assertRaises(ObservationDenied) as raised:
            self._observe(**overrides)
        self.assertEqual(raised.exception.code, code)
        self.assertEqual(str(raised.exception), code)

    def test_clean_registered_worktree_returns_phase2a_shape_and_schema(self):
        result = self._observe()
        self.assertIs(type(result.observed_source), TrustedRepositoryObservation)
        self.assertEqual(result.observed_source.repository, "AnonymousKoo/avuhz-infra")
        self.assertEqual(result.observed_source.commit, self.commit)
        self.assertEqual(result.observed_source.tree, self.tree)
        self.assertTrue(result.observed_source.worktree_clean)
        self.assertFalse(result.execution_authorized)
        self.assertFalse(result.os_isolation_certified)
        self.assertTrue(result.exclusive_lease_required)
        self.assertTrue(result.repeat_at_execution_required)
        projected = result.as_dict()
        self.assertEqual(projected, result.as_dict())
        schema = json.loads(
            (ROOT / "docs/schemas/local-worktree-observation-v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(list(Draft202012Validator(schema).iter_errors(projected)), [])

    def test_dirty_tracked_and_untracked_are_denied(self):
        (self.worktree / "tracked.txt").write_text("dirty\n", encoding="utf-8")
        self.assert_denied("WORKTREE_DIRTY")
        (self.worktree / "tracked.txt").write_text("clean\n", encoding="utf-8")
        (self.worktree / "untracked.txt").write_text("synthetic\n", encoding="utf-8")
        self.assert_denied("WORKTREE_DIRTY")

    def test_assume_unchanged_and_skip_worktree_cannot_hide_tracked_drift(self):
        self._git("update-index", "--assume-unchanged", "tracked.txt", cwd=self.worktree)
        (self.worktree / "tracked.txt").write_text("hidden dirty\n", encoding="utf-8")
        self.assert_denied("WORKTREE_CLEANLINESS_UNTRUSTED")
        self._git("update-index", "--no-assume-unchanged", "tracked.txt", cwd=self.worktree)
        (self.worktree / "tracked.txt").write_text("clean\n", encoding="utf-8")
        self._git("update-index", "--skip-worktree", "tracked.txt", cwd=self.worktree)
        (self.worktree / "tracked.txt").write_text("hidden dirty again\n", encoding="utf-8")
        self.assert_denied("WORKTREE_CLEANLINESS_UNTRUSTED")

    def test_stale_commit_wrong_tree_branch_and_injection_are_denied(self):
        self.assert_denied("COMMIT_MISMATCH", expected_commit="f" * 40)
        self.assert_denied("TREE_MISMATCH", expected_tree="e" * 40)
        self.assert_denied("BRANCH_MISMATCH", expected_branch="refs/heads/main")
        sentinel = self.base / "must-not-exist"
        self.assert_denied(
            "EXPECTED_SOURCE_INVALID",
            expected_branch=f"refs/heads/main;touch-{sentinel.name}",
        )
        self.assertFalse(sentinel.exists())
        self.assert_denied("EXPECTED_SOURCE_INVALID", expected_branch="--upload-pack=bad")

    def test_wrong_root_common_directory_and_registry_are_denied(self):
        self.assert_denied("WORKTREE_ROOT_MISMATCH", expected_worktree_root=self.primary)
        other = self.base / "other-common"
        other.mkdir()
        self.assert_denied("COMMON_GIT_DIR_MISMATCH", expected_common_git_dir=other)
        registry = Path((self.worktree / ".git").read_text(encoding="utf-8")[8:].strip())
        (registry / "gitdir").write_text(str(self.primary / ".git") + "\n", encoding="utf-8")
        self.assert_denied("WORKTREE_REGISTRY_INVALID")

    def test_missing_non_git_locked_and_symlinked_roots_are_denied(self):
        plain = self.base / "plain"
        plain.mkdir()
        self.assert_denied(
            "WORKTREE_REGISTRY_INVALID", worktree_root=plain, expected_worktree_root=plain,
        )
        registry = Path((self.worktree / ".git").read_text(encoding="utf-8")[8:].strip())
        (registry / "index.lock").write_text("synthetic lock\n", encoding="utf-8")
        self.assert_denied("WORKTREE_LOCKED")
        (registry / "index.lock").unlink()
        linked = self.base / "linked-repo"
        linked.symlink_to(self.worktree, target_is_directory=True)
        self.assert_denied(
            "WORKTREE_INVALID", worktree_root=linked, expected_worktree_root=linked,
        )

    def test_git_environment_config_alternates_and_tracked_symlink_are_denied(self):
        with mock.patch.dict(os.environ, {"GIT_CONFIG_PARAMETERS": "synthetic"}, clear=False):
            self.assert_denied("GIT_ENVIRONMENT_UNTRUSTED")
        self._git("config", "core.fsmonitor", "touch synthetic-sentinel", cwd=self.worktree)
        self.assert_denied("GIT_CONFIG_UNTRUSTED")
        self._git("config", "--unset", "core.fsmonitor", cwd=self.worktree)
        alternates = self.common / "objects" / "info" / "alternates"
        alternates.write_text(str(self.base / "foreign-objects") + "\n", encoding="utf-8")
        self.assert_denied("GIT_ALTERNATES_PROHIBITED")
        alternates.unlink()
        (self.worktree / "linked-file").symlink_to(self.base / "outside")
        self._git("add", "linked-file", cwd=self.worktree)
        self.assert_denied("SYMLINK_ESCAPE_RISK")

    def test_submodule_drift_is_denied_without_network(self):
        subrepo = self.base / "subrepo"
        self._git("init", "-b", "main", str(subrepo), cwd=self.base)
        self._git("config", "user.name", "Synthetic Test", cwd=subrepo)
        self._git("config", "user.email", "synthetic@example.invalid", cwd=subrepo)
        (subrepo / "child.txt").write_text("clean\n", encoding="utf-8")
        self._git("add", "child.txt", cwd=subrepo)
        self._git("commit", "-m", "synthetic child", cwd=subrepo)
        self._git(
            "-c", "protocol.file.allow=always", "submodule", "add", str(subrepo), "child",
            cwd=self.worktree,
        )
        self._git("commit", "-am", "synthetic submodule", cwd=self.worktree)
        self.commit = self._git("rev-parse", "HEAD", cwd=self.worktree).strip()
        self.tree = self._git("rev-parse", "HEAD^{tree}", cwd=self.worktree).strip()
        self.assert_denied("SUBMODULE_UNSUPPORTED")
        (self.worktree / "child" / "child.txt").write_text("drift\n", encoding="utf-8")
        self.assert_denied("SUBMODULE_UNSUPPORTED")

    def test_git_process_timeout_and_failure_are_stable_and_redacted(self):
        slow = self.base / "slow-git"
        slow.write_text("#!/bin/sh\nsleep 2\n", encoding="utf-8")
        slow.chmod(0o755)
        with mock.patch.object(observer_module, "_GIT_EXECUTABLE", slow):
            self.assert_denied("GIT_TIMEOUT", timeout_seconds=0.05)
        failed = self.base / "failed-git"
        failed.write_text("#!/bin/sh\nprintf 'sensitive synthetic path' >&2\nexit 7\n", encoding="utf-8")
        failed.chmod(0o755)
        with mock.patch.object(observer_module, "_GIT_EXECUTABLE", failed):
            self.assert_denied("GIT_READ_FAILED")
        noisy = self.base / "noisy-git"
        noisy.write_text("#!/bin/sh\nyes x | head -c 1100000\n", encoding="utf-8")
        noisy.chmod(0o755)
        with mock.patch.object(observer_module, "_GIT_EXECUTABLE", noisy):
            self.assert_denied("GIT_OUTPUT_LIMIT")

    def test_symlinked_git_metadata_and_common_lock_are_denied(self):
        config = self.common / "config"
        real_config = self.base / "synthetic-config"
        config.replace(real_config)
        config.symlink_to(real_config)
        self.assert_denied("GIT_CONFIG_UNTRUSTED")
        config.unlink()
        real_config.replace(config)
        (self.common / "packed-refs.lock").write_text("synthetic lock\n", encoding="utf-8")
        self.assert_denied("WORKTREE_LOCKED")

    def test_loose_object_symlink_and_unsafe_root_text_are_denied(self):
        object_directory = next(
            path for path in (self.common / "objects").iterdir()
            if path.is_dir() and len(path.name) == 2
        )
        object_file = next(object_directory.iterdir())
        copied = self.base / "synthetic-object"
        copied.write_bytes(object_file.read_bytes())
        object_file.unlink()
        object_file.symlink_to(copied)
        self.assert_denied("GIT_SYMLINK_UNTRUSTED")
        unsafe = self.base / "unsafe\nroot"
        unsafe.mkdir()
        self.assert_denied(
            "WORKTREE_INVALID", worktree_root=unsafe, expected_worktree_root=unsafe,
        )

    def test_worktree_scoped_config_injection_is_denied(self):
        self._git("config", "extensions.worktreeConfig", "true", cwd=self.primary)
        self._git("config", "--worktree", "core.fsmonitor", "synthetic-helper", cwd=self.worktree)
        self.assert_denied("GIT_CONFIG_UNTRUSTED")


if __name__ == "__main__":
    unittest.main()
