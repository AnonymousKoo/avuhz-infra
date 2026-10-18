"""Fail-closed host-local exclusive worktree lease primitive.

The lease coordinates cooperating LOCAL AAE processes.  It does not authorize
execution, run commands, inspect Git, or provide an OS isolation boundary.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from avuhz_engineering.local_codex_admission import TrustedRepositoryObservation

REPOSITORY = "AnonymousKoo/avuhz-infra"
ENVIRONMENT = "LOCAL"
NAMESPACE = "AAE/local"
PROVIDER_AUTHORITY = "NONE"
SCHEMA_VERSION = 1
_STATE_VERSION = 1
_MAX_STATE_BYTES = 8192
_OBJECT_ID = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
_FIXED_LEASE_DIRECTORY = (
    Path("/run/user") / str(os.getuid()) / "avuhz-aae-local-worktree-leases-v1"
)


class LeaseDenied(ValueError):
    """A fail-closed denial carrying only a stable, non-sensitive code."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _deny(code: str) -> None:
    raise LeaseDenied(code)


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )


def _utc_second(value: object, code: str) -> str:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != timedelta(0)
        or value.microsecond != 0
        or value.year < 1000
    ):
        _deny(code)
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def _reference(value: object, code: str) -> str:
    if type(value) is not str or _REFERENCE.fullmatch(value) is None:
        _deny(code)
    return value


def _strict_absolute_directory(path: object, code: str, *, private: bool) -> Path:
    if not isinstance(path, Path) or not path.is_absolute() or str(path) != os.path.normpath(str(path)):
        _deny(code)
    if not 1 <= len(str(path)) <= 4096 or any(
        ord(character) < 0x20 or ord(character) > 0x7E for character in str(path)
    ):
        _deny(code)
    current = Path(path.anchor)
    try:
        for part in path.parts[1:]:
            current = current / part
            info = current.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                _deny(code)
        info = path.lstat()
        if path.resolve(strict=True) != path or info.st_uid != os.getuid():
            _deny(code)
        if private and stat.S_IMODE(info.st_mode) != 0o700:
            _deny(code)
    except LeaseDenied:
        raise
    except OSError:
        _deny(code)
    return path


def _worktree_key(worktree_root: Path) -> str:
    material = b"AVUHZ_LOCAL_WORKTREE_LEASE_V1\0" + os.fsencode(str(worktree_root))
    return hashlib.sha256(material).hexdigest()


def _open_directory(path: Path) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        info = os.fstat(descriptor)
        path_info = path.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700
            or (info.st_dev, info.st_ino) != (path_info.st_dev, path_info.st_ino)
        ):
            os.close(descriptor)
            _deny("LEASE_DIRECTORY_UNTRUSTED")
        return descriptor
    except LeaseDenied:
        raise
    except OSError:
        _deny("LEASE_DIRECTORY_UNTRUSTED")


def _validate_private_file(info: os.stat_result, code: str, *, maximum: int) -> None:
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_nlink != 1
        or info.st_size > maximum
    ):
        _deny(code)


def _open_lock(directory_fd: int, name: str) -> tuple[int, bool]:
    flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    created = False
    try:
        try:
            descriptor = os.open(name, flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=directory_fd)
            created = True
        except FileExistsError:
            descriptor = os.open(name, flags, dir_fd=directory_fd)
        try:
            info = os.fstat(descriptor)
            _validate_private_file(info, "LOCK_FILE_UNTRUSTED", maximum=0)
            path_info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if (info.st_dev, info.st_ino) != (path_info.st_dev, path_info.st_ino):
                _deny("LOCK_FILE_UNTRUSTED")
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor, created
    except LeaseDenied:
        raise
    except OSError:
        _deny("LOCK_FILE_UNTRUSTED")


def _read_state(directory_fd: int, name: str, *, required: bool) -> dict[str, Any] | None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=directory_fd)
    except FileNotFoundError:
        if required:
            _deny("LEASE_STATE_CORRUPT")
        return None
    except OSError:
        _deny("LEASE_STATE_CORRUPT")
    try:
        with os.fdopen(descriptor, "rb") as handle:
            info = os.fstat(handle.fileno())
            _validate_private_file(info, "LEASE_STATE_CORRUPT", maximum=_MAX_STATE_BYTES)
            path_info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if (info.st_dev, info.st_ino) != (path_info.st_dev, path_info.st_ino):
                _deny("LEASE_STATE_CORRUPT")
            raw = handle.read(_MAX_STATE_BYTES + 1)
    except LeaseDenied:
        raise
    except OSError:
        _deny("LEASE_STATE_CORRUPT")
    try:
        value = json.loads(raw, object_pairs_hook=_pairs_without_duplicates)
    except (UnicodeError, json.JSONDecodeError, ValueError):
        _deny("LEASE_STATE_CORRUPT")
    if type(value) is not dict or _canonical_bytes(value) != raw:
        _deny("LEASE_STATE_CORRUPT")
    return value


def _pairs_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, member in pairs:
        if key in value:
            raise ValueError("duplicate")
        value[key] = member
    return value


def _validate_prior_state(state: dict[str, Any] | None, key: str, root: str) -> None:
    if state is None:
        return
    acquired = {
        "state_version", "status", "repository", "environment", "namespace", "worktree_root",
        "worktree_key", "commit", "tree", "reviewed_digest", "isolation_id", "owner_id",
        "acquired_at", "deadline_utc",
    }
    released = acquired | {"released_at"}
    if set(state) not in (acquired, released):
        _deny("LEASE_STATE_CORRUPT")
    if (
        state.get("state_version") != _STATE_VERSION
        or state.get("status") not in {"ACQUIRED", "RELEASED"}
        or (state.get("status") == "ACQUIRED" and set(state) != acquired)
        or (state.get("status") == "RELEASED" and set(state) != released)
        or state.get("repository") != REPOSITORY
        or state.get("environment") != ENVIRONMENT
        or state.get("namespace") != NAMESPACE
        or state.get("worktree_root") != root
        or state.get("worktree_key") != key
        or type(state.get("commit")) is not str
        or _OBJECT_ID.fullmatch(state["commit"]) is None
        or type(state.get("tree")) is not str
        or _OBJECT_ID.fullmatch(state["tree"]) is None
        or type(state.get("reviewed_digest")) is not str
        or _DIGEST.fullmatch(state["reviewed_digest"]) is None
        or type(state.get("isolation_id")) is not str
        or _REFERENCE.fullmatch(state["isolation_id"]) is None
        or type(state.get("owner_id")) is not str
        or _REFERENCE.fullmatch(state["owner_id"]) is None
    ):
        _deny("LEASE_STATE_CORRUPT")
    for field in ("acquired_at", "deadline_utc", "released_at"):
        if field in state:
            try:
                parsed = datetime.strptime(state[field], "%Y-%m-%dT%H:%M:%SZ")
            except (TypeError, ValueError):
                _deny("LEASE_STATE_CORRUPT")
            if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != state[field]:
                _deny("LEASE_STATE_CORRUPT")


def _write_state(directory_fd: int, name: str, value: dict[str, Any]) -> None:
    raw = _canonical_bytes(value)
    temporary = name + ".tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(temporary, flags, 0o600, dir_fd=directory_fd)
        try:
            _validate_private_file(os.fstat(descriptor), "LEASE_STATE_WRITE_FAILED", maximum=0)
            offset = 0
            while offset < len(raw):
                written = os.write(descriptor, raw[offset:])
                if written <= 0:
                    _deny("LEASE_STATE_WRITE_FAILED")
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        try:
            existing = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory_fd,
            )
        except FileNotFoundError:
            existing = None
        if existing is not None:
            try:
                _validate_private_file(
                    os.fstat(existing), "LEASE_STATE_CORRUPT", maximum=_MAX_STATE_BYTES
                )
            finally:
                os.close(existing)
        os.replace(temporary, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        os.fsync(directory_fd)
    except LeaseDenied:
        raise
    except OSError:
        _deny("LEASE_STATE_WRITE_FAILED")


@dataclass(frozen=True)
class LeaseReleaseResult:
    status: str = field(init=False, default="LEASE_RELEASED")
    schema_version: int = field(init=False, default=SCHEMA_VERSION)
    environment: str = field(init=False, default=ENVIRONMENT)
    namespace: str = field(init=False, default=NAMESPACE)
    provider_authority: str = field(init=False, default=PROVIDER_AUTHORITY)
    execution_authorized: bool = field(init=False, default=False)
    os_isolation_certified: bool = field(init=False, default=False)

    def as_dict(self) -> dict[str, Any]:
        return {
            "environment": self.environment,
            "execution_authorized": self.execution_authorized,
            "namespace": self.namespace,
            "os_isolation_certified": self.os_isolation_certified,
            "provider_authority": self.provider_authority,
            "schema_version": self.schema_version,
            "status": self.status,
        }


class LocalWorktreeLease:
    """An acquired lease whose open descriptor is the ownership capability."""

    def __init__(
        self,
        *,
        descriptor: int,
        directory_fd: int,
        state_name: str,
        state: dict[str, Any],
    ) -> None:
        self._descriptor = descriptor
        self._directory_fd = directory_fd
        self._state_name = state_name
        self._state = state
        self._release_result: LeaseReleaseResult | None = None
        self._creator_pid = os.getpid()

    @property
    def status(self) -> str:
        return "LEASE_ACQUIRED"

    @property
    def schema_version(self) -> int:
        return SCHEMA_VERSION

    @property
    def environment(self) -> str:
        return ENVIRONMENT

    @property
    def namespace(self) -> str:
        return NAMESPACE

    @property
    def provider_authority(self) -> str:
        return PROVIDER_AUTHORITY

    @property
    def execution_authorized(self) -> bool:
        return False

    @property
    def os_isolation_certified(self) -> bool:
        return False

    @property
    def deadline_enforced(self) -> bool:
        return False

    @property
    def repeat_observation_required(self) -> bool:
        return True

    @property
    def owner_id(self) -> str:
        return self._state["owner_id"]

    @property
    def worktree_key(self) -> str:
        return self._state["worktree_key"]

    @property
    def closed(self) -> bool:
        return self._descriptor < 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "acquired_at": self._state["acquired_at"],
            "deadline_enforced": self.deadline_enforced,
            "deadline_utc": self._state["deadline_utc"],
            "environment": self.environment,
            "execution_authorized": self.execution_authorized,
            "isolation_id": self._state["isolation_id"],
            "namespace": self.namespace,
            "os_isolation_certified": self.os_isolation_certified,
            "owner_id": self.owner_id,
            "provider_authority": self.provider_authority,
            "repeat_observation_required": self.repeat_observation_required,
            "repository": REPOSITORY,
            "schema_version": self.schema_version,
            "source": {
                "commit": self._state["commit"],
                "reviewed_digest": self._state["reviewed_digest"],
                "tree": self._state["tree"],
            },
            "status": self.status,
            "worktree_key": self.worktree_key,
            "worktree_root": self._state["worktree_root"],
        }

    def release(self, *, owner_id: str, released_at: datetime) -> LeaseReleaseResult:
        if os.getpid() != self._creator_pid:
            _deny("LEASE_PROCESS_MISMATCH")
        if owner_id != self.owner_id:
            _deny("RELEASE_OWNER_MISMATCH")
        if self._release_result is not None:
            return self._release_result
        if self.closed:
            _deny("LEASE_HANDLE_CLOSED")
        released = dict(self._state)
        released["status"] = "RELEASED"
        released["released_at"] = _utc_second(released_at, "RELEASE_TIME_INVALID")
        _write_state(self._directory_fd, self._state_name, released)
        try:
            fcntl.flock(self._descriptor, fcntl.LOCK_UN)
        except OSError:
            _deny("LEASE_RELEASE_FAILED")
        os.close(self._descriptor)
        os.close(self._directory_fd)
        self._descriptor = -1
        self._directory_fd = -1
        self._release_result = LeaseReleaseResult()
        return self._release_result

    def close(self, *, released_at: datetime) -> LeaseReleaseResult:
        return self.release(owner_id=self.owner_id, released_at=released_at)


def acquire_local_worktree_lease(
    *,
    observed_source: TrustedRepositoryObservation,
    expected_repository: str,
    expected_environment: str,
    expected_namespace: str,
    expected_worktree_root: Path,
    expected_commit: str,
    expected_tree: str,
    expected_reviewed_digest: str,
    expected_isolation_id: str,
    owner_id: str,
    acquired_at: datetime,
    deadline_utc: datetime,
) -> LocalWorktreeLease:
    """Acquire one exclusive lease without running or authorizing any work."""
    if (
        expected_repository != REPOSITORY
        or expected_environment != ENVIRONMENT
        or expected_namespace != NAMESPACE
    ):
        _deny("LOCAL_BOUNDARY_INVALID")
    root = _strict_absolute_directory(expected_worktree_root, "WORKTREE_INVALID", private=False)
    lease_root = _strict_absolute_directory(
        _FIXED_LEASE_DIRECTORY, "LEASE_DIRECTORY_UNTRUSTED", private=True
    )
    if (
        lease_root == root
        or lease_root.is_relative_to(root)
        or root.is_relative_to(lease_root)
        or ".git" in lease_root.parts
    ):
        _deny("LEASE_DIRECTORY_INSIDE_WORKTREE")
    if type(observed_source) is not TrustedRepositoryObservation:
        _deny("SOURCE_OBSERVATION_UNTRUSTED")
    if (
        observed_source.repository != REPOSITORY
        or observed_source.worktree_root != str(root)
        or observed_source.worktree_clean is not True
        or observed_source.commit != expected_commit
        or observed_source.tree != expected_tree
        or observed_source.reviewed_digest != expected_reviewed_digest
        or observed_source.isolation_id != expected_isolation_id
    ):
        _deny("SOURCE_MISMATCH")
    if (
        type(expected_commit) is not str
        or _OBJECT_ID.fullmatch(expected_commit) is None
        or type(expected_tree) is not str
        or _OBJECT_ID.fullmatch(expected_tree) is None
        or type(expected_reviewed_digest) is not str
        or _DIGEST.fullmatch(expected_reviewed_digest) is None
    ):
        _deny("SOURCE_EXPECTATION_INVALID")
    _reference(expected_isolation_id, "SOURCE_EXPECTATION_INVALID")
    owner = _reference(owner_id, "OWNER_ID_INVALID")
    acquired_text = _utc_second(acquired_at, "ACQUIRED_TIME_INVALID")
    deadline_text = _utc_second(deadline_utc, "DEADLINE_INVALID")

    key = _worktree_key(root)
    lock_name = "worktree-" + key + ".lock"
    state_name = "worktree-" + key + ".state.json"
    directory_fd = _open_directory(lease_root)
    descriptor = -1
    try:
        descriptor, created = _open_lock(directory_fd, lock_name)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            _deny("LEASE_CONTENDED")
        except OSError:
            _deny("LEASE_LOCK_FAILED")
        prior = _read_state(directory_fd, state_name, required=not created)
        _validate_prior_state(prior, key, str(root))
        state = {
            "state_version": _STATE_VERSION,
            "status": "ACQUIRED",
            "repository": REPOSITORY,
            "environment": ENVIRONMENT,
            "namespace": NAMESPACE,
            "worktree_root": str(root),
            "worktree_key": key,
            "commit": expected_commit,
            "tree": expected_tree,
            "reviewed_digest": expected_reviewed_digest,
            "isolation_id": expected_isolation_id,
            "owner_id": owner,
            "acquired_at": acquired_text,
            "deadline_utc": deadline_text,
        }
        _write_state(directory_fd, state_name, state)
        lease = LocalWorktreeLease(
            descriptor=descriptor, directory_fd=directory_fd, state_name=state_name, state=state
        )
        descriptor = -1
        directory_fd = -1
        return lease
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if directory_fd >= 0:
            os.close(directory_fd)
