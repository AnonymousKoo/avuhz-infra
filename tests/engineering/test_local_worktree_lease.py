"""Offline synthetic tests for the LOCAL exclusive worktree lease."""
from __future__ import annotations

import copy
import fcntl
import json
import os
import pickle
import stat
import sys
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from jsonschema import Draft202012Validator
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.local_codex_admission import TrustedRepositoryObservation
import avuhz_engineering.local_worktree_lease as lease_module
from avuhz_engineering.local_worktree_lease import (
    LeaseDenied,
    LocalWorktreeLease,
    _worktree_key,
    acquire_local_worktree_lease,
)

NOW = datetime(2026, 10, 18, 16, 0, 0, tzinfo=timezone.utc)
DEADLINE = datetime(2026, 10, 18, 16, 10, 0, tzinfo=timezone.utc)


class LocalWorktreeLeaseTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="avuhz-lease-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.worktree = self.base / "isolated-worktree"
        self.worktree.mkdir(mode=0o700)
        (self.worktree / "synthetic.txt").write_text("unchanged\n", encoding="utf-8")
        self.leases = self.base / "private-leases"
        self.leases.mkdir(mode=0o700)
        fixed_directory = mock.patch.object(lease_module, "_FIXED_LEASE_DIRECTORY", self.leases)
        fixed_directory.start()
        self.addCleanup(fixed_directory.stop)
        self.commit = "7" * 40
        self.tree = "b" * 40
        self.reviewed = "sha256:" + "c" * 64
        self.isolation = "worktree.phase2c.synthetic"
        self.observation = TrustedRepositoryObservation(
            repository="AnonymousKoo/avuhz-infra",
            branch="refs/heads/synthetic",
            commit=self.commit,
            tree=self.tree,
            reviewed_digest=self.reviewed,
            worktree_clean=True,
            worktree_root=str(self.worktree),
            isolation_id=self.isolation,
        )

    def _arguments(self, **overrides):
        values = {
            "observed_source": self.observation,
            "expected_repository": "AnonymousKoo/avuhz-infra",
            "expected_environment": "LOCAL",
            "expected_namespace": "AAE/local",
            "expected_worktree_root": self.worktree,
            "expected_commit": self.commit,
            "expected_tree": self.tree,
            "expected_reviewed_digest": self.reviewed,
            "expected_isolation_id": self.isolation,
            "owner_id": "owner.synthetic.one",
            "acquired_at": NOW,
            "deadline_utc": DEADLINE,
        }
        values.update(overrides)
        return values

    def _acquire(self, **overrides):
        lease = acquire_local_worktree_lease(**self._arguments(**overrides))
        self.addCleanup(self._force_cleanup, lease)
        return lease

    @staticmethod
    def _force_cleanup(lease: LocalWorktreeLease) -> None:
        registration = lease_module._LIVE_LEASES.pop(id(lease), None)
        if registration is not None:
            try:
                os.close(registration.proof_descriptor)
            except OSError:
                pass
        for member in ("_descriptor", "_directory_fd"):
            descriptor = getattr(lease, member, -1)
            if isinstance(descriptor, int) and descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
                setattr(lease, member, -1)

    def assert_denied(self, code: str, **overrides) -> None:
        with self.assertRaises(LeaseDenied) as raised:
            self._acquire(**overrides)
        self.assertEqual(raised.exception.code, code)
        self.assertEqual(str(raised.exception), code)

    def _lock_path(self, worktree: Path | None = None) -> Path:
        key = _worktree_key(worktree or self.worktree)
        return self.leases / f"worktree-{key}.lock"

    def _state_path(self, worktree: Path | None = None) -> Path:
        key = _worktree_key(worktree or self.worktree)
        return self.leases / f"worktree-{key}.state.json"

    def _snapshot_worktree(self) -> dict[str, tuple[int, bytes]]:
        return {
            str(path.relative_to(self.worktree)): (stat.S_IMODE(path.lstat().st_mode), path.read_bytes())
            for path in self.worktree.rglob("*") if path.is_file()
        }

    def test_successful_acquire_release_is_schema_valid_and_does_not_write_repo(self):
        before = self._snapshot_worktree()
        lease = self._acquire()
        self.assertIsNone(lease.verify_live_owner(owner_id=lease.owner_id))
        self.assertFalse(lease.closed)
        self.assertFalse(lease.execution_authorized)
        self.assertFalse(lease.os_isolation_certified)
        self.assertEqual(lease.provider_authority, "NONE")
        self.assertFalse(lease.deadline_enforced)
        projected = lease.as_dict()
        schema = json.loads(
            (ROOT / "docs/schemas/local-worktree-lease-v1.schema.json").read_text(encoding="utf-8")
        )
        self.assertEqual(list(Draft202012Validator(schema).iter_errors(projected)), [])
        released = lease.release(owner_id="owner.synthetic.one", released_at=DEADLINE)
        self.assertEqual(released.status, "LEASE_RELEASED")
        self.assertTrue(lease.closed)
        self.assertEqual(before, self._snapshot_worktree())
        self.assertEqual(stat.S_IMODE(self._lock_path().stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self._state_path().stat().st_mode), 0o600)

    def test_verification_is_non_mutating_and_deadline_is_not_ownership(self):
        stale = datetime(2020, 1, 1, tzinfo=timezone.utc)
        lease = self._acquire(deadline_utc=stale)
        state_before = self._state_path().read_bytes()
        lock_before = self._lock_path().stat()
        descriptor_before = os.fstat(lease._descriptor)
        with mock.patch.object(fcntl, "flock", side_effect=AssertionError("must not flock")):
            self.assertIsNone(lease.verify_live_owner(owner_id=lease.owner_id))
        self.assertEqual(self._state_path().read_bytes(), state_before)
        lock_after = self._lock_path().stat()
        descriptor_after = os.fstat(lease._descriptor)
        self.assertEqual(
            (lock_before.st_dev, lock_before.st_ino, lock_before.st_mode, lock_before.st_size),
            (lock_after.st_dev, lock_after.st_ino, lock_after.st_mode, lock_after.st_size),
        )
        self.assertEqual(
            (descriptor_before.st_dev, descriptor_before.st_ino),
            (descriptor_after.st_dev, descriptor_after.st_ino),
        )
        lease.release(owner_id=lease.owner_id, released_at=NOW)

    def test_constructor_fabrication_copy_and_deserialization_are_denied(self):
        with self.assertRaisesRegex(LeaseDenied, "LEASE_CONSTRUCTION_DENIED"):
            LocalWorktreeLease(descriptor=0, directory_fd=0, state_name="fake", state={})
        fabricated = object.__new__(LocalWorktreeLease)
        with self.assertRaisesRegex(LeaseDenied, "LEASE_PROVENANCE_INVALID"):
            fabricated.verify_live_owner(owner_id="owner.synthetic.one")

        lease = self._acquire()
        clones = (copy.copy(lease), copy.deepcopy(lease), pickle.loads(pickle.dumps(lease)))
        for clone in clones:
            with self.subTest(clone=type(clone).__name__):
                with self.assertRaisesRegex(LeaseDenied, "LEASE_PROVENANCE_INVALID"):
                    clone.verify_live_owner(owner_id=lease.owner_id)
        lease.release(owner_id=lease.owner_id, released_at=DEADLINE)

    def test_wrong_owner_and_changed_clock_state_are_denied(self):
        class DeceptiveOwner:
            def __eq__(self, other):
                return True

            def __ne__(self, other):
                return False

        lease = self._acquire()
        with self.assertRaisesRegex(LeaseDenied, "LEASE_OWNER_MISMATCH"):
            lease.verify_live_owner(owner_id="owner.synthetic.wrong")
        deceptive = DeceptiveOwner()
        with self.assertRaisesRegex(LeaseDenied, "LEASE_OWNER_MISMATCH"):
            lease.verify_live_owner(owner_id=deceptive)  # type: ignore[arg-type]
        with self.assertRaisesRegex(LeaseDenied, "RELEASE_OWNER_MISMATCH"):
            lease.release(owner_id=deceptive, released_at=NOW)  # type: ignore[arg-type]
        original_deadline = lease._state["deadline_utc"]
        lease._state["deadline_utc"] = "2030-01-01T00:00:00Z"
        with self.assertRaisesRegex(LeaseDenied, "LEASE_OWNER_NOT_VERIFIED"):
            lease.verify_live_owner(owner_id=lease.owner_id)
        lease._state["deadline_utc"] = original_deadline
        lease.release(owner_id=lease.owner_id, released_at=DEADLINE)

    def test_changed_persisted_state_and_lock_path_are_denied(self):
        lease = self._acquire()
        original_state = self._state_path().read_bytes()
        changed = json.loads(original_state)
        changed["deadline_utc"] = "2030-01-01T00:00:00Z"
        self._state_path().write_bytes(
            json.dumps(changed, sort_keys=True, separators=(",", ":")).encode("ascii")
        )
        with self.assertRaisesRegex(LeaseDenied, "LEASE_OWNER_NOT_VERIFIED"):
            lease.verify_live_owner(owner_id=lease.owner_id)
        self._state_path().write_bytes(original_state)

        displaced = self.leases / "displaced.lock"
        self._lock_path().replace(displaced)
        self._lock_path().touch(mode=0o600)
        with self.assertRaisesRegex(LeaseDenied, "LEASE_OWNER_NOT_VERIFIED"):
            lease.verify_live_owner(owner_id=lease.owner_id)

    def test_replaced_private_lease_directory_is_denied(self):
        lease = self._acquire()
        displaced = self.base / "displaced-leases"
        self.leases.replace(displaced)
        self.leases.mkdir(mode=0o700)
        with self.assertRaisesRegex(LeaseDenied, "LEASE_OWNER_NOT_VERIFIED"):
            lease.verify_live_owner(owner_id=lease.owner_id)

    def test_live_owner_contends_across_process_and_stale_deadline_cannot_steal(self):
        stale = datetime(2020, 1, 1, tzinfo=timezone.utc)
        lease = self._acquire(deadline_utc=stale)
        read_fd, write_fd = os.pipe()
        child = os.fork()
        if child == 0:
            os.close(read_fd)
            try:
                self._acquire(owner_id="owner.synthetic.child")
            except LeaseDenied as error:
                os.write(write_fd, error.code.encode("ascii"))
            finally:
                os._exit(0)
        os.close(write_fd)
        try:
            self.assertEqual(os.read(read_fd, 128), b"LEASE_CONTENDED")
            os.waitpid(child, 0)
        finally:
            os.close(read_fd)
        lease.release(owner_id=lease.owner_id, released_at=NOW)

    def test_process_crash_releases_kernel_lock(self):
        read_fd, write_fd = os.pipe()
        child = os.fork()
        if child == 0:
            os.close(read_fd)
            self._acquire(owner_id="owner.synthetic.crash")
            os.write(write_fd, b"acquired")
            os.close(write_fd)
            os._exit(0)
        os.close(write_fd)
        self.assertEqual(os.read(read_fd, 8), b"acquired")
        os.close(read_fd)
        os.waitpid(child, 0)
        lease = self._acquire(owner_id="owner.synthetic.after-crash")
        lease.release(owner_id=lease.owner_id, released_at=DEADLINE)

    def test_key_is_deterministic_per_worktree_and_alternate_root_is_independent(self):
        first = self._acquire()
        self.assertEqual(first.worktree_key, _worktree_key(self.worktree))
        other = self.base / "other-worktree"
        other.mkdir(mode=0o700)
        other_observation = replace(self.observation, worktree_root=str(other))
        second = self._acquire(
            observed_source=other_observation,
            expected_worktree_root=other,
            owner_id="owner.synthetic.other",
        )
        self.assertNotEqual(first.worktree_key, second.worktree_key)
        second.release(owner_id=second.owner_id, released_at=DEADLINE)
        first.release(owner_id=first.owner_id, released_at=DEADLINE)

    def test_wrong_boundary_dirty_source_and_source_pins_are_denied(self):
        self.assert_denied("LOCAL_BOUNDARY_INVALID", expected_namespace="AAE/foreign")
        self.assert_denied("LOCAL_BOUNDARY_INVALID", expected_repository="foreign/repository")
        self.assert_denied(
            "SOURCE_MISMATCH", observed_source=replace(self.observation, worktree_clean=False)
        )
        self.assert_denied("SOURCE_MISMATCH", expected_commit="8" * 40)
        self.assert_denied("SOURCE_MISMATCH", expected_tree="9" * 40)
        self.assert_denied(
            "SOURCE_MISMATCH", expected_reviewed_digest="sha256:" + "d" * 64
        )

    def test_symlinked_parent_and_foreign_permissions_are_denied(self):
        real_parent = self.base / "real-parent"
        real_parent.mkdir(mode=0o700)
        linked_parent = self.base / "linked-parent"
        linked_parent.symlink_to(real_parent, target_is_directory=True)
        linked_leases = linked_parent / "leases"
        (real_parent / "leases").mkdir(mode=0o700)
        with mock.patch.object(lease_module, "_FIXED_LEASE_DIRECTORY", linked_leases):
            self.assert_denied("LEASE_DIRECTORY_UNTRUSTED")
        self.leases.chmod(0o750)
        self.assert_denied("LEASE_DIRECTORY_UNTRUSTED")

    def test_public_api_has_one_fixed_directory_and_rejects_an_alternate(self):
        import inspect

        self.assertNotIn("lease_directory", inspect.signature(acquire_local_worktree_lease).parameters)
        alternate = self.base / "alternate-leases"
        alternate.mkdir(mode=0o700)
        with self.assertRaises(TypeError):
            acquire_local_worktree_lease(
                **self._arguments(), lease_directory=alternate  # type: ignore[call-arg]
            )

    def test_inherited_handle_cannot_unlock_creator_lease(self):
        lease = self._acquire()
        read_fd, write_fd = os.pipe()
        child = os.fork()
        if child == 0:
            os.close(read_fd)
            try:
                lease.verify_live_owner(owner_id=lease.owner_id)
            except LeaseDenied as error:
                os.write(write_fd, error.code.encode("ascii"))
            finally:
                os._exit(0)
        os.close(write_fd)
        self.assertEqual(os.read(read_fd, 128), b"LEASE_PROCESS_MISMATCH")
        os.close(read_fd)
        os.waitpid(child, 0)
        read_fd, write_fd = os.pipe()
        contender = os.fork()
        if contender == 0:
            os.close(read_fd)
            try:
                self._acquire(owner_id="owner.synthetic.after-fork")
            except LeaseDenied as error:
                os.write(write_fd, error.code.encode("ascii"))
            finally:
                os._exit(0)
        os.close(write_fd)
        self.assertEqual(os.read(read_fd, 128), b"LEASE_CONTENDED")
        os.close(read_fd)
        os.waitpid(contender, 0)
        lease.release(owner_id=lease.owner_id, released_at=DEADLINE)

    def test_closed_and_reused_descriptor_is_denied_even_for_same_inode(self):
        lease = self._acquire()
        retained = lease._descriptor
        fcntl.flock(retained, fcntl.LOCK_UN)
        os.close(retained)
        reopened = os.open(self._lock_path(), os.O_RDWR)
        if reopened != retained:
            os.dup2(reopened, retained)
            os.close(reopened)
        fcntl.flock(retained, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.assertEqual(os.fstat(retained).st_ino, self._lock_path().stat().st_ino)
        with self.assertRaisesRegex(LeaseDenied, "LEASE_KERNEL_PROOF_DENIED"):
            lease.verify_live_owner(owner_id=lease.owner_id)

    def test_unlock_through_duplicate_is_denied_and_verification_does_not_relock(self):
        lease = self._acquire()
        duplicate = os.dup(lease._descriptor)
        fcntl.flock(duplicate, fcntl.LOCK_UN)
        os.close(duplicate)
        with mock.patch.object(fcntl, "flock", side_effect=AssertionError("must not relock")):
            with self.assertRaisesRegex(LeaseDenied, "LEASE_KERNEL_PROOF_DENIED"):
                lease.verify_live_owner(owner_id=lease.owner_id)

        ready_read, ready_write = os.pipe()
        stop_read, stop_write = os.pipe()
        contender_pid = os.fork()
        if contender_pid == 0:
            os.close(ready_read)
            os.close(stop_write)
            contender = os.open(self._lock_path(), os.O_RDWR)
            fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
            os.write(ready_write, b"locked")
            os.read(stop_read, 1)
            os._exit(0)
        os.close(ready_write)
        os.close(stop_read)
        try:
            self.assertEqual(os.read(ready_read, 6), b"locked")
            with self.assertRaisesRegex(LeaseDenied, "LEASE_KERNEL_PROOF_DENIED"):
                lease.verify_live_owner(owner_id=lease.owner_id)
        finally:
            os.write(stop_write, b"x")
            os.close(stop_write)
            os.close(ready_read)
            os.waitpid(contender_pid, 0)

    def test_procfs_unavailable_and_ambiguous_kernel_proof_are_denied(self):
        with mock.patch.object(lease_module, "_KCMP_SYSCALLS", {}):
            self.assert_denied("LEASE_KERNEL_PROOF_UNAVAILABLE")
        lease = self._acquire()
        missing_proc = self.base / "missing-proc"
        with mock.patch.object(lease_module, "_PROC_ROOT", missing_proc):
            with self.assertRaisesRegex(LeaseDenied, "LEASE_KERNEL_PROOF_UNAVAILABLE"):
                lease.verify_live_owner(owner_id=lease.owner_id)
        with mock.patch.object(lease_module, "_KCMP_SYSCALLS", {}):
            with self.assertRaisesRegex(LeaseDenied, "LEASE_KERNEL_PROOF_UNAVAILABLE"):
                lease.verify_live_owner(owner_id=lease.owner_id)

        actual = lease_module._read_fdinfo(os.getpid(), lease._descriptor)
        lock_line = next(line for line in actual.splitlines() if line.startswith("lock:"))
        malformed = (
            "",
            lock_line + "\n" + lock_line,
            lock_line.replace("FLOCK", "POSIX"),
            lock_line.replace("WRITE", "READ"),
            lock_line.replace(f"WRITE {os.getpid()} ", "WRITE 999999 "),
            lock_line.rsplit(":", 1)[0] + ":999999999 0 EOF",
            lock_line.replace(" 0 EOF", " 1 EOF"),
        )
        for proof in malformed:
            with self.subTest(proof=proof):
                with mock.patch.object(lease_module, "_read_fdinfo", return_value=proof):
                    with self.assertRaisesRegex(LeaseDenied, "LEASE_KERNEL_PROOF_DENIED"):
                        lease.verify_live_owner(owner_id=lease.owner_id)
        lease.release(owner_id=lease.owner_id, released_at=DEADLINE)

    def test_non_four_digit_utc_year_is_denied(self):
        ancient = datetime(999, 1, 1, tzinfo=timezone.utc)
        self.assert_denied("ACQUIRED_TIME_INVALID", acquired_at=ancient)
        self.assert_denied("DEADLINE_INVALID", deadline_utc=ancient)

    def test_lock_symlink_hardlink_mode_and_corrupt_state_fail_closed(self):
        lease = self._acquire()
        lease.release(owner_id=lease.owner_id, released_at=DEADLINE)
        lock = self._lock_path()
        alias = self.leases / "synthetic-hardlink"
        os.link(lock, alias)
        self.assert_denied("LOCK_FILE_UNTRUSTED")
        alias.unlink()
        lock.chmod(0o640)
        self.assert_denied("LOCK_FILE_UNTRUSTED")
        lock.chmod(0o600)
        lock.write_bytes(b"corrupt-lock")
        self.assert_denied("LOCK_FILE_UNTRUSTED")
        lock.write_bytes(b"")
        self._state_path().write_text("{not-json", encoding="utf-8")
        self._state_path().chmod(0o600)
        self.assert_denied("LEASE_STATE_CORRUPT")
        self._state_path().unlink()
        target = self.leases / "target"
        target.write_bytes(b"")
        target.chmod(0o600)
        lock.unlink()
        lock.symlink_to(target)
        self.assert_denied("LOCK_FILE_UNTRUSTED")

    def test_state_symlink_and_hardlink_are_denied(self):
        lease = self._acquire()
        lease.release(owner_id=lease.owner_id, released_at=DEADLINE)
        state = self._state_path()
        alias = self.leases / "state-hardlink"
        os.link(state, alias)
        self.assert_denied("LEASE_STATE_CORRUPT")
        alias.unlink()
        original = state.read_bytes()
        state.unlink()
        target = self.leases / "state-target"
        target.write_bytes(original)
        target.chmod(0o600)
        state.symlink_to(target)
        self.assert_denied("LEASE_STATE_CORRUPT")

    def test_release_owner_scope_idempotence_and_closed_handle_replay(self):
        old = self._acquire()
        with self.assertRaisesRegex(LeaseDenied, "RELEASE_OWNER_MISMATCH"):
            old.release(owner_id="owner.synthetic.wrong", released_at=NOW)
        first = old.release(owner_id=old.owner_id, released_at=DEADLINE)
        self.assertIs(first, old.release(owner_id=old.owner_id, released_at=DEADLINE))
        current = self._acquire(owner_id="owner.synthetic.current")
        self.assertIs(first, old.release(owner_id=old.owner_id, released_at=DEADLINE))
        read_fd, write_fd = os.pipe()
        child = os.fork()
        if child == 0:
            os.close(read_fd)
            try:
                self._acquire(owner_id="owner.synthetic.replay")
            except LeaseDenied as error:
                os.write(write_fd, error.code.encode("ascii"))
            finally:
                os._exit(0)
        os.close(write_fd)
        self.assertEqual(os.read(read_fd, 128), b"LEASE_CONTENDED")
        os.close(read_fd)
        os.waitpid(child, 0)
        current.close(released_at=DEADLINE)


if __name__ == "__main__":
    unittest.main()
