"""Negative-first tests for the non-executing LOCAL engineering queue."""
from __future__ import annotations

import copy
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.local_engineering_queue import (
    LocalEngineeringQueue,
    ManifestValidationError,
    QueueError,
    ReplayError,
    approval_digest,
    approval_scope,
    canonical_digest,
    load_manifest,
    validate_manifest,
)


class LocalEngineeringQueueTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="avuhz-local-queue-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.repository = self.base / "checkout"
        self.repository.mkdir()
        self.state_dir = (self.base / "state").absolute()

    def manifest(self, *, manifest_id: str = "manifest.local-one", task_id: str = "task.local-one") -> dict:
        value = {
            "schema_version": 1,
            "manifest_id": manifest_id,
            "environment": "LOCAL",
            "namespace": "AAE/local",
            "repository": "AnonymousKoo/avuhz-infra",
            "scope": "repository-local-engineering",
            "worktree": {
                "root": str(self.repository.resolve()),
                "ownership": "EXCLUSIVE_LOCAL_WORKTREE",
            },
            "allowed_file_paths": ["src/local_controller.py"],
            "target_baselines": [{"path": "src/local_controller.py", "digest": "ABSENT"}],
            "tasks": [{
                "task_id": task_id,
                "resource_reference": "repository.local-controller",
                "allowed_file_paths": ["src/local_controller.py"],
                "acceptance_criteria": ["tests.focused.pass"],
                "stop_conditions": ["scope.drift", "target.changed"],
            }],
        }
        approval = {
            "approval_id": "approval.local-one",
            "approved_task_ids": [task_id],
            "scope_digest": canonical_digest(approval_scope(value)),
            "approval_digest": "sha256:" + "0" * 64,
            "authority_effect": "REPOSITORY_LOCAL_ONLY",
            "immutable": True,
            "provider_authority": False,
        }
        approval["approval_digest"] = approval_digest(approval)
        value["approval"] = approval
        return value

    def rebind_approval(self, value: dict) -> None:
        value["approval"]["scope_digest"] = canonical_digest(approval_scope(value))
        value["approval"]["approval_digest"] = approval_digest(value["approval"])

    def assert_manifest_code(self, value: dict, code: str) -> None:
        with self.assertRaises(ManifestValidationError) as raised:
            validate_manifest(value, self.repository)
        self.assertEqual(raised.exception.code, code)

    def test_full_dry_run_is_deterministic_non_executing_and_persistent(self):
        value = self.manifest()
        queue = LocalEngineeringQueue(self.repository, self.state_dir)

        summary = queue.run_resumable_dry_run(value)

        self.assertEqual(summary.status, "DRY_RUN_VERIFIED")
        self.assertEqual(summary.task_ids, ("task.local-one",))
        self.assertFalse(summary.execution_performed)
        self.assertFalse(summary.provider_authority)
        state = json.loads((self.state_dir / "queue-state.json").read_text(encoding="utf-8"))
        record = state["records"]["manifest.local-one"]
        self.assertEqual(record["transitions"], ["QUEUED", "READY", "DRY_RUN_VERIFIED"])
        serialized = json.dumps(summary.as_dict(), sort_keys=True)
        self.assertNotIn("credential", serialized.lower())
        self.assertNotIn("model", serialized.lower())
        self.assertFalse((self.repository / "src/local_controller.py").exists())

    def test_restart_resumes_ready_state_without_requeue(self):
        value = self.manifest()
        first = LocalEngineeringQueue(self.repository, self.state_dir)
        self.assertEqual(first.enqueue(value).status, "QUEUED")
        self.assertEqual(first.prepare(value).status, "READY")

        restarted = LocalEngineeringQueue(self.repository, self.state_dir)
        summary = restarted.run_resumable_dry_run(value)

        self.assertEqual(summary.status, "DRY_RUN_VERIFIED")
        state = json.loads((self.state_dir / "queue-state.json").read_text(encoding="utf-8"))
        self.assertEqual(state["records"]["manifest.local-one"]["transitions"], ["QUEUED", "READY", "DRY_RUN_VERIFIED"])

    def test_verified_manifest_replay_is_rejected(self):
        value = self.manifest()
        queue = LocalEngineeringQueue(self.repository, self.state_dir)
        queue.run_resumable_dry_run(value)
        with self.assertRaises(ReplayError) as raised:
            queue.run_resumable_dry_run(value)
        self.assertEqual(raised.exception.code, "manifest_replay")

    def test_duplicate_task_ids_and_cross_manifest_task_replay_are_rejected(self):
        duplicate = self.manifest()
        duplicate["tasks"].append(copy.deepcopy(duplicate["tasks"][0]))
        duplicate["approval"]["approved_task_ids"].append("task.local-one")
        self.rebind_approval(duplicate)
        self.assert_manifest_code(duplicate, "duplicate_task_id")

        queue = LocalEngineeringQueue(self.repository, self.state_dir)
        queue.enqueue(self.manifest())
        second = self.manifest(manifest_id="manifest.local-two")
        with self.assertRaises(ReplayError) as raised:
            queue.enqueue(second)
        self.assertEqual(raised.exception.code, "task_id_replay")

    def test_manifest_mismatch_blocks_persisted_record(self):
        value = self.manifest()
        queue = LocalEngineeringQueue(self.repository, self.state_dir)
        queue.enqueue(value)
        changed = copy.deepcopy(value)
        changed["tasks"][0]["acceptance_criteria"] = ["tests.negative.pass"]
        self.rebind_approval(changed)

        with self.assertRaises(QueueError) as raised:
            queue.prepare(changed)

        self.assertEqual(raised.exception.code, "manifest_mismatch")
        state = json.loads((self.state_dir / "queue-state.json").read_text(encoding="utf-8"))
        self.assertEqual(state["records"]["manifest.local-one"]["status"], "BLOCKED")
        self.assertEqual(state["records"]["manifest.local-one"]["block_code"], "manifest_mismatch")

    def test_dirty_target_after_approval_blocks_without_modifying_target(self):
        value = self.manifest()
        queue = LocalEngineeringQueue(self.repository, self.state_dir)
        queue.enqueue(value)
        target = self.repository / "src/local_controller.py"
        target.parent.mkdir()
        target.write_text("owner work\n", encoding="utf-8")

        with self.assertRaises(QueueError) as raised:
            queue.prepare(value)

        self.assertEqual(raised.exception.code, "target_baseline_mismatch")
        self.assertEqual(target.read_text(encoding="utf-8"), "owner work\n")
        state = json.loads((self.state_dir / "queue-state.json").read_text(encoding="utf-8"))
        self.assertEqual(state["records"]["manifest.local-one"]["status"], "BLOCKED")

    def test_non_local_unknown_command_provider_and_secret_surfaces_are_denied(self):
        non_local = self.manifest()
        non_local["environment"] = "DEVELOPMENT"
        self.assert_manifest_code(non_local, "local_boundary_invalid")

        command = self.manifest()
        command["tasks"][0]["command"] = "python test.py"
        self.assert_manifest_code(command, "task_keys_invalid")

        encoded_command = self.manifest()
        encoded_command["tasks"][0]["acceptance_criteria"] = ["command.python"]
        self.rebind_approval(encoded_command)
        self.assert_manifest_code(encoded_command, "prohibited_scope")

        provider = self.manifest()
        provider["tasks"][0]["resource_reference"] = "provider.database"
        self.rebind_approval(provider)
        self.assert_manifest_code(provider, "prohibited_scope")

        secret = self.manifest()
        secret["allowed_file_paths"] = [".env"]
        secret["target_baselines"] = [{"path": ".env", "digest": "ABSENT"}]
        secret["tasks"][0]["allowed_file_paths"] = [".env"]
        self.rebind_approval(secret)
        self.assert_manifest_code(secret, "prohibited_path")

    def test_path_traversal_absolute_path_and_symlink_are_denied(self):
        traversal = self.manifest()
        traversal["allowed_file_paths"] = ["../escape.py"]
        traversal["target_baselines"] = [{"path": "../escape.py", "digest": "ABSENT"}]
        traversal["tasks"][0]["allowed_file_paths"] = ["../escape.py"]
        self.rebind_approval(traversal)
        self.assert_manifest_code(traversal, "path_escape")

        absolute = self.manifest()
        absolute["allowed_file_paths"] = ["/tmp/escape.py"]
        absolute["target_baselines"] = [{"path": "/tmp/escape.py", "digest": "ABSENT"}]
        absolute["tasks"][0]["allowed_file_paths"] = ["/tmp/escape.py"]
        self.rebind_approval(absolute)
        self.assert_manifest_code(absolute, "path_escape")

        shell_path = self.manifest()
        shell_path["allowed_file_paths"] = ["src/file;echo"]
        shell_path["target_baselines"] = [{"path": "src/file;echo", "digest": "ABSENT"}]
        shell_path["tasks"][0]["allowed_file_paths"] = ["src/file;echo"]
        self.rebind_approval(shell_path)
        self.assert_manifest_code(shell_path, "allowed_path_invalid")

        outside = self.base / "outside"
        outside.mkdir()
        os.symlink(outside, self.repository / "src")
        self.assert_manifest_code(self.manifest(), "path_symlink")

    def test_state_dir_must_be_explicit_and_outside_checkout(self):
        with self.assertRaises(QueueError) as relative:
            LocalEngineeringQueue(self.repository, Path("relative-state"))
        self.assertEqual(relative.exception.code, "state_dir_must_be_absolute")
        with self.assertRaises(QueueError) as inside:
            LocalEngineeringQueue(self.repository, self.repository / ".state")
        self.assertEqual(inside.exception.code, "state_dir_inside_repository")

    def test_corrupt_persisted_record_fails_closed_with_stable_code(self):
        queue = LocalEngineeringQueue(self.repository, self.state_dir)
        queue.enqueue(self.manifest())
        state = json.loads((self.state_dir / "queue-state.json").read_text(encoding="utf-8"))
        state["records"]["manifest.local-one"]["transitions"] = ["DRY_RUN_VERIFIED"]
        (self.state_dir / "queue-state.json").write_text(json.dumps(state), encoding="utf-8")

        with self.assertRaises(QueueError) as raised:
            LocalEngineeringQueue(self.repository, self.state_dir).prepare(self.manifest())

        self.assertEqual(raised.exception.code, "state_shape_invalid")

    def test_approval_digest_and_approved_task_set_are_enforced(self):
        widened = self.manifest()
        widened["allowed_file_paths"].append("docs/extra.md")
        widened["target_baselines"].append({"path": "docs/extra.md", "digest": "ABSENT"})
        widened["tasks"][0]["allowed_file_paths"].append("docs/extra.md")
        self.assert_manifest_code(widened, "approval_scope_digest_mismatch")

        unapproved = self.manifest()
        unapproved["approval"]["approved_task_ids"] = ["task.different"]
        unapproved["approval"]["approval_digest"] = approval_digest(unapproved["approval"])
        self.assert_manifest_code(unapproved, "approved_tasks_mismatch")

    def test_loader_rejects_duplicate_json_keys_and_symlink_manifest(self):
        manifest_path = self.base / "manifest.json"
        manifest_path.write_text('{"schema_version":1,"schema_version":1}\n', encoding="utf-8")
        with self.assertRaises(ManifestValidationError) as duplicate:
            load_manifest(manifest_path)
        self.assertEqual(duplicate.exception.code, "duplicate_json_key")

        target = self.base / "real.json"
        target.write_text("{}\n", encoding="utf-8")
        link = self.base / "linked.json"
        link.symlink_to(target)
        with self.assertRaises(ManifestValidationError) as symlink:
            load_manifest(link)
        self.assertEqual(symlink.exception.code, "manifest_not_regular_file")


if __name__ == "__main__":
    unittest.main()
