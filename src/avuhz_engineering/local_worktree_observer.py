"""Fail-closed LOCAL trusted-source/worktree observation preflight.

The observer runs a small fixed set of read-only Git commands.  It neither
admits nor executes work, and its result is only a time-of-check observation.
"""
from __future__ import annotations

import os
import re
import selectors
import signal
import stat
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from avuhz_engineering.local_codex_admission import TrustedRepositoryObservation

REPOSITORY = "AnonymousKoo/avuhz-infra"
ENVIRONMENT = "LOCAL"
NAMESPACE = "AAE/local"
SCHEMA_VERSION = 1
_GIT_EXECUTABLE = Path("/usr/bin/git")
_MAX_GIT_OUTPUT_BYTES = 1_048_576
_MAX_CONFIG_KEYS = 256
_MAX_REGISTRY_BYTES = 4096
_MAX_LOCK_ENTRIES = 100_000
_IGNORED_AMBIENT_GIT_ENV = frozenset({"GIT_PAGER"})
_OBJECT_ID = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_BRANCH = re.compile(r"^refs/heads/[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")
_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
_CONFIG_KEY = re.compile(r"^[a-z0-9][a-z0-9.-]{0,255}$")
_DANGEROUS_CONFIG = (
    re.compile(r"^include(?:if)?\."),
    re.compile(r"^alias\."),
    re.compile(r"^credential\."),
    re.compile(r"^filter\."),
    re.compile(r"^http\."),
    re.compile(r"^url\."),
    re.compile(r"^core\.(?:fsmonitor|hookspath|sshcommand|gitproxy|worktree)$"),
    re.compile(r"^diff\..*\.command$"),
    re.compile(r"^remote\..*\.(?:proxy|uploadpack|receivepack)$"),
    re.compile(r"^submodule\..*\.update$"),
)
class ObservationDenied(ValueError):
    """A denial carrying only a stable, non-sensitive code."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _deny(code: str) -> None:
    raise ObservationDenied(code)


@dataclass(frozen=True)
class LocalWorktreeObservation:
    observed_source: TrustedRepositoryObservation
    status: str = "SOURCE_OBSERVATION_PASS"
    schema_version: int = SCHEMA_VERSION
    environment: str = ENVIRONMENT
    namespace: str = NAMESPACE
    provider_authority: str = "NONE"
    execution_authorized: bool = False
    os_isolation_certified: bool = False
    exclusive_lease_required: bool = True
    repeat_at_execution_required: bool = True

    def as_dict(self) -> dict[str, Any]:
        return {
            "environment": self.environment,
            "exclusive_lease_required": self.exclusive_lease_required,
            "execution_authorized": self.execution_authorized,
            "namespace": self.namespace,
            "observed_source": asdict(self.observed_source),
            "os_isolation_certified": self.os_isolation_certified,
            "provider_authority": self.provider_authority,
            "repeat_at_execution_required": self.repeat_at_execution_required,
            "schema_version": self.schema_version,
            "status": self.status,
        }


def _safe_absolute_directory(path: object, code: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute() or path.is_symlink():
        _deny(code)
    _path_text_safe(path, code)
    try:
        resolved = path.resolve(strict=True)
        info = path.stat()
    except OSError:
        _deny(code)
    if resolved != path or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        _deny(code)
    return path


def _path_text_safe(path: Path, code: str) -> None:
    value = str(path)
    if not 1 <= len(value) <= 4096 or any(ord(character) < 0x20 or ord(character) > 0x7e for character in value):
        _deny(code)


def _regular_file(path: Path, code: str, *, maximum: int = _MAX_REGISTRY_BYTES) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_size > maximum:
                _deny(code)
            value = handle.read(maximum + 1)
    except ObservationDenied:
        raise
    except OSError:
        _deny(code)
    if len(value) > maximum:
        _deny(code)
    return value


def _one_line_path(path: Path, prefix: bytes | None, code: str) -> Path:
    raw = _regular_file(path, code)
    if prefix is not None:
        if not raw.startswith(prefix):
            _deny(code)
        raw = raw[len(prefix):]
    if not raw or b"\x00" in raw or raw.count(b"\n") > 1 or not raw.endswith(b"\n"):
        _deny(code)
    try:
        value = raw[:-1].decode("utf-8")
    except UnicodeError:
        _deny(code)
    candidate = Path(value)
    if not candidate.is_absolute() or candidate.is_symlink():
        _deny(code)
    _path_text_safe(candidate, code)
    try:
        if candidate.resolve(strict=True) != candidate:
            _deny(code)
    except OSError:
        _deny(code)
    return candidate


def _check_no_git_environment() -> None:
    for name in os.environ:
        upper = name.upper()
        if upper.startswith("GIT_") and upper not in _IGNORED_AMBIENT_GIT_ENV:
            _deny("GIT_ENVIRONMENT_UNTRUSTED")


def _owned_regular_metadata(
    path: Path, code: str, *, required: bool, maximum: int
) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        if required:
            _deny(code)
        return
    except OSError:
        _deny(code)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_size > maximum:
            _deny(code)
    finally:
        os.close(descriptor)


def _check_metadata_directory(path: Path) -> None:
    if not path.exists():
        return
    try:
        entries = list(os.scandir(path))
    except OSError:
        _deny("GIT_METADATA_UNTRUSTED")
    if len(entries) > _MAX_LOCK_ENTRIES:
        _deny("GIT_METADATA_UNTRUSTED")
    for entry in entries:
        try:
            if entry.is_symlink():
                _deny("GIT_SYMLINK_UNTRUSTED")
        except OSError:
            _deny("GIT_METADATA_UNTRUSTED")


def _check_common_root_locks(common: Path) -> None:
    try:
        entries = list(os.scandir(common))
    except OSError:
        _deny("GIT_STATE_AMBIGUOUS")
    if len(entries) > _MAX_LOCK_ENTRIES:
        _deny("GIT_STATE_AMBIGUOUS")
    if any(entry.name.endswith(".lock") for entry in entries):
        _deny("WORKTREE_LOCKED")


def _check_no_locks(paths: tuple[Path, ...]) -> None:
    visited = 0
    try:
        for root in paths:
            if not root.exists():
                continue
            for current, directories, files in os.walk(root, followlinks=False):
                visited += len(directories) + len(files)
                if visited > _MAX_LOCK_ENTRIES:
                    _deny("GIT_STATE_AMBIGUOUS")
                current_path = Path(current)
                for directory in directories:
                    if (current_path / directory).is_symlink():
                        _deny("GIT_SYMLINK_UNTRUSTED")
                if any((current_path / name).is_symlink() for name in files):
                    _deny("GIT_SYMLINK_UNTRUSTED")
                if any(name.endswith(".lock") for name in files):
                    _deny("WORKTREE_LOCKED")
    except ObservationDenied:
        raise
    except OSError:
        _deny("GIT_STATE_AMBIGUOUS")


def _terminate(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        try:
            process.kill()
        except OSError:
            pass
    try:
        process.wait(timeout=1)
    except (OSError, subprocess.TimeoutExpired):
        pass


def _bounded_communicate(process: subprocess.Popen[bytes], timeout_seconds: float) -> tuple[bytes, bytes]:
    selector = selectors.DefaultSelector()
    outputs: dict[int, bytearray] = {}
    assert process.stdout is not None and process.stderr is not None
    for stream in (process.stdout, process.stderr):
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ)
        outputs[stream.fileno()] = bytearray()
    deadline = time.monotonic() + timeout_seconds
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _terminate(process)
                _deny("GIT_TIMEOUT")
            events = selector.select(remaining)
            if not events and process.poll() is None:
                continue
            for key, _mask in events:
                try:
                    chunk = os.read(key.fd, 65_536)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                outputs[key.fd].extend(chunk)
                if len(outputs[key.fd]) > _MAX_GIT_OUTPUT_BYTES:
                    _terminate(process)
                    _deny("GIT_OUTPUT_LIMIT")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _terminate(process)
            _deny("GIT_TIMEOUT")
        returncode = process.wait(timeout=remaining)
    except ObservationDenied:
        raise
    except (OSError, subprocess.SubprocessError):
        _terminate(process)
        _deny("GIT_READ_FAILED")
    finally:
        selector.close()
    if returncode != 0:
        _deny("GIT_READ_FAILED")
    return bytes(outputs[process.stdout.fileno()]), bytes(outputs[process.stderr.fileno()])


def _run_git(
    git_dir: Path, worktree: Path, command: tuple[str, ...], timeout_seconds: float
) -> bytes:
    if not command or any(type(item) is not str for item in command):
        _deny("GIT_COMMAND_INVALID")
    argv = (
        str(_GIT_EXECUTABLE), "--no-pager", "--literal-pathspecs",
        f"--git-dir={git_dir}", f"--work-tree={worktree}",
        "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false",
        "-c", "core.hooksPath=/dev/null", "-c", "core.pager=cat",
        "-c", "pager.status=false", *command,
    )
    environment = {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "LANG": "C",
        "LC_ALL": "C",
    }
    try:
        process = subprocess.Popen(
            argv, cwd="/", env=environment, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False,
            close_fds=True, start_new_session=True,
        )
    except OSError:
        _deny("GIT_UNAVAILABLE")
    try:
        stdout, _stderr = _bounded_communicate(process, timeout_seconds)
        return stdout
    finally:
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()


def _strict_text(raw: bytes, code: str) -> str:
    try:
        value = raw.decode("ascii")
    except UnicodeError:
        _deny(code)
    if not value.endswith("\n") or value.count("\n") != 1 or "\x00" in value:
        _deny(code)
    return value[:-1]


def _validate_pins(
    expected_branch: object, expected_commit: object, expected_tree: object,
    expected_reviewed_digest: object, isolation_id: object, timeout_seconds: object,
) -> float:
    if (
        type(expected_branch) is not str or _BRANCH.fullmatch(expected_branch) is None
        or ".." in expected_branch or "//" in expected_branch or "@{" in expected_branch
        or expected_branch.endswith(("/", ".", ".lock"))
    ):
        _deny("EXPECTED_SOURCE_INVALID")
    if type(expected_commit) is not str or _OBJECT_ID.fullmatch(expected_commit) is None:
        _deny("EXPECTED_SOURCE_INVALID")
    if type(expected_tree) is not str or _OBJECT_ID.fullmatch(expected_tree) is None:
        _deny("EXPECTED_SOURCE_INVALID")
    if type(expected_reviewed_digest) is not str or _DIGEST.fullmatch(expected_reviewed_digest) is None:
        _deny("EXPECTED_SOURCE_INVALID")
    if type(isolation_id) is not str or _REFERENCE.fullmatch(isolation_id) is None:
        _deny("ISOLATION_ID_INVALID")
    if type(timeout_seconds) not in (int, float) or isinstance(timeout_seconds, bool):
        _deny("LIMIT_INVALID")
    timeout = float(timeout_seconds)
    if not 0.05 <= timeout <= 30.0:
        _deny("LIMIT_INVALID")
    return timeout


def _validate_config_keys(raw: bytes) -> None:
    keys = raw.split(b"\x00")
    if keys and keys[-1] == b"":
        keys.pop()
    if len(keys) > _MAX_CONFIG_KEYS:
        _deny("GIT_CONFIG_UNTRUSTED")
    for raw_key in keys:
        try:
            key = raw_key.decode("ascii").lower()
        except UnicodeError:
            _deny("GIT_CONFIG_UNTRUSTED")
        if _CONFIG_KEY.fullmatch(key) is None or any(pattern.match(key) for pattern in _DANGEROUS_CONFIG):
            _deny("GIT_CONFIG_UNTRUSTED")


def _validate_config(git_dir: Path, worktree: Path, timeout: float) -> None:
    _validate_config_keys(
        _run_git(
            git_dir, worktree,
            ("config", "--local", "--no-includes", "--name-only", "--null", "--list"),
            timeout,
        )
    )
    if (git_dir / "config.worktree").exists():
        _validate_config_keys(
            _run_git(
                git_dir, worktree,
                ("config", "--worktree", "--no-includes", "--name-only", "--null", "--list"),
                timeout,
            )
        )


def _validate_index(raw: bytes) -> frozenset[bytes]:
    records = raw.split(b"\x00")
    if records and records[-1] == b"":
        records.pop()
    paths: set[bytes] = set()
    for record in records:
        header, separator, path = record.partition(b"\t")
        fields = header.split(b" ")
        if separator != b"\t" or not path or len(fields) != 3:
            _deny("GIT_INDEX_UNTRUSTED")
        mode, object_id, stage = fields
        if mode == b"120000":
            _deny("SYMLINK_ESCAPE_RISK")
        if mode == b"160000":
            _deny("SUBMODULE_UNSUPPORTED")
        if mode not in {b"100644", b"100755"}:
            _deny("GIT_INDEX_UNTRUSTED")
        if _OBJECT_ID.fullmatch(object_id.decode("ascii", "ignore")) is None or stage != b"0":
            _deny("GIT_INDEX_UNTRUSTED")
        if path in paths:
            _deny("GIT_INDEX_UNTRUSTED")
        paths.add(path)
    return frozenset(paths)


def _validate_index_flags(raw: bytes, expected_paths: frozenset[bytes]) -> None:
    records = raw.split(b"\x00")
    if records and records[-1] == b"":
        records.pop()
    observed_paths: set[bytes] = set()
    for record in records:
        flag, separator, path = record.partition(b" ")
        if separator != b" " or flag != b"H" or not path or path in observed_paths:
            _deny("WORKTREE_CLEANLINESS_UNTRUSTED")
        observed_paths.add(path)
    if frozenset(observed_paths) != expected_paths:
        _deny("WORKTREE_CLEANLINESS_UNTRUSTED")


def _validate_worktree_registry(
    raw: bytes, root: Path, commit: str, branch: str
) -> None:
    fields = raw.split(b"\x00")
    entries: list[dict[bytes, bytes]] = []
    current: dict[bytes, bytes] = {}
    for field in fields:
        if not field:
            if current:
                entries.append(current)
                current = {}
            continue
        key, separator, value = field.partition(b" ")
        if not separator or key in current:
            _deny("WORKTREE_REGISTRY_INVALID")
        current[key] = value
    if current:
        _deny("WORKTREE_REGISTRY_INVALID")
    expected_root = os.fsencode(root)
    matches = [entry for entry in entries if entry.get(b"worktree") == expected_root]
    if len(matches) != 1:
        _deny("WORKTREE_REGISTRY_INVALID")
    match = matches[0]
    if (
        match.get(b"HEAD") != commit.encode("ascii")
        or match.get(b"branch") != branch.encode("ascii")
        or b"bare" in match or b"detached" in match or b"prunable" in match
    ):
        _deny("WORKTREE_REGISTRY_INVALID")


def observe_local_worktree(
    *,
    worktree_root: Path,
    expected_worktree_root: Path,
    expected_common_git_dir: Path,
    expected_branch: str,
    expected_commit: str,
    expected_tree: str,
    expected_reviewed_digest: str,
    isolation_id: str,
    timeout_seconds: float = 5.0,
) -> LocalWorktreeObservation:
    """Observe exact pinned LOCAL source facts without granting execution."""
    timeout = _validate_pins(
        expected_branch, expected_commit, expected_tree, expected_reviewed_digest,
        isolation_id, timeout_seconds,
    )
    _check_no_git_environment()
    root = _safe_absolute_directory(worktree_root, "WORKTREE_INVALID")
    expected_root = _safe_absolute_directory(expected_worktree_root, "EXPECTED_ROOT_INVALID")
    if root != expected_root:
        _deny("WORKTREE_ROOT_MISMATCH")
    common = _safe_absolute_directory(expected_common_git_dir, "COMMON_GIT_DIR_INVALID")
    if root == common or common.is_relative_to(root):
        _deny("COMMON_GIT_DIR_INVALID")
    try:
        root_before = root.stat()
        common_before = common.stat()
    except OSError:
        _deny("WORKTREE_INVALID")

    git_file = root / ".git"
    git_dir = _one_line_path(git_file, b"gitdir: ", "WORKTREE_REGISTRY_INVALID")
    try:
        git_dir.relative_to(common / "worktrees")
    except ValueError:
        _deny("COMMON_GIT_DIR_MISMATCH")
    if git_dir.parent != common / "worktrees" or git_dir.name in {"", ".", ".."}:
        _deny("WORKTREE_REGISTRY_INVALID")
    if _one_line_path(git_dir / "gitdir", None, "WORKTREE_REGISTRY_INVALID") != git_file:
        _deny("WORKTREE_REGISTRY_INVALID")
    commondir = _regular_file(git_dir / "commondir", "WORKTREE_REGISTRY_INVALID")
    if commondir != b"../..\n":
        _deny("WORKTREE_REGISTRY_INVALID")
    for critical in (common / "objects", common / "refs", common / "worktrees", git_dir):
        if critical.is_symlink():
            _deny("GIT_SYMLINK_UNTRUSTED")
    _owned_regular_metadata(common / "config", "GIT_CONFIG_UNTRUSTED", required=True, maximum=1_048_576)
    _owned_regular_metadata(git_dir / "config.worktree", "GIT_CONFIG_UNTRUSTED", required=False, maximum=1_048_576)
    _owned_regular_metadata(git_dir / "HEAD", "GIT_METADATA_UNTRUSTED", required=True, maximum=4096)
    _owned_regular_metadata(git_dir / "index", "GIT_METADATA_UNTRUSTED", required=True, maximum=67_108_864)
    _owned_regular_metadata(common / "HEAD", "GIT_METADATA_UNTRUSTED", required=True, maximum=4096)
    _owned_regular_metadata(common / "packed-refs", "GIT_METADATA_UNTRUSTED", required=False, maximum=16_777_216)
    _owned_regular_metadata(common / "shallow", "GIT_METADATA_UNTRUSTED", required=False, maximum=16_777_216)
    _check_metadata_directory(common / "objects")
    _check_metadata_directory(common / "objects" / "pack")
    _check_metadata_directory(common / "objects" / "info")
    alternates = common / "objects" / "info" / "alternates"
    if alternates.exists() or alternates.is_symlink():
        _deny("GIT_ALTERNATES_PROHIBITED")
    _check_common_root_locks(common)
    _check_no_locks((common / "worktrees", common / "refs", common / "objects"))

    try:
        executable_info = _GIT_EXECUTABLE.stat()
        if (
            _GIT_EXECUTABLE.is_symlink() or _GIT_EXECUTABLE.resolve(strict=True) != _GIT_EXECUTABLE
            or not stat.S_ISREG(executable_info.st_mode)
            or executable_info.st_mode & 0o022
        ):
            _deny("GIT_UNAVAILABLE")
    except OSError:
        _deny("GIT_UNAVAILABLE")

    _validate_config(git_dir, root, timeout)
    observed_root = _strict_text(
        _run_git(git_dir, root, ("rev-parse", "--show-toplevel"), timeout),
        "WORKTREE_IDENTITY_AMBIGUOUS",
    )
    observed_common = _strict_text(
        _run_git(git_dir, root, ("rev-parse", "--path-format=absolute", "--git-common-dir"), timeout),
        "WORKTREE_IDENTITY_AMBIGUOUS",
    )
    if observed_root != str(root):
        _deny("WORKTREE_ROOT_MISMATCH")
    if observed_common != str(common):
        _deny("COMMON_GIT_DIR_MISMATCH")
    branch = _strict_text(
        _run_git(git_dir, root, ("symbolic-ref", "--quiet", "HEAD"), timeout),
        "SOURCE_IDENTITY_AMBIGUOUS",
    )
    commit = _strict_text(
        _run_git(git_dir, root, ("rev-parse", "--verify", "HEAD^{commit}"), timeout),
        "SOURCE_IDENTITY_AMBIGUOUS",
    )
    tree = _strict_text(
        _run_git(git_dir, root, ("rev-parse", "--verify", "HEAD^{tree}"), timeout),
        "SOURCE_IDENTITY_AMBIGUOUS",
    )
    if branch != expected_branch:
        _deny("BRANCH_MISMATCH")
    if commit != expected_commit:
        _deny("COMMIT_MISMATCH")
    if tree != expected_tree:
        _deny("TREE_MISMATCH")
    _validate_worktree_registry(
        _run_git(git_dir, root, ("worktree", "list", "--porcelain", "-z"), timeout),
        root, commit, branch,
    )
    index_paths = _validate_index(
        _run_git(git_dir, root, ("ls-files", "--stage", "-z"), timeout)
    )
    _validate_index_flags(
        _run_git(git_dir, root, ("ls-files", "-v", "-z"), timeout), index_paths
    )
    status = _run_git(
        git_dir, root,
        ("status", "--porcelain=v2", "-z", "--untracked-files=all", "--ignore-submodules=none", "--no-ahead-behind"),
        timeout,
    )
    if status:
        _deny("WORKTREE_DIRTY")

    _check_common_root_locks(common)
    _check_no_locks((common / "worktrees", common / "refs", common / "objects"))
    branch_after = _strict_text(
        _run_git(git_dir, root, ("symbolic-ref", "--quiet", "HEAD"), timeout),
        "SOURCE_IDENTITY_AMBIGUOUS",
    )
    commit_after = _strict_text(
        _run_git(git_dir, root, ("rev-parse", "--verify", "HEAD^{commit}"), timeout),
        "SOURCE_IDENTITY_AMBIGUOUS",
    )
    tree_after = _strict_text(
        _run_git(git_dir, root, ("rev-parse", "--verify", "HEAD^{tree}"), timeout),
        "SOURCE_IDENTITY_AMBIGUOUS",
    )
    try:
        root_after = root.stat()
        common_after = common.stat()
    except OSError:
        _deny("SOURCE_CHANGED_DURING_OBSERVATION")
    if (
        branch_after != branch or commit_after != commit or tree_after != tree
        or (root_before.st_dev, root_before.st_ino) != (root_after.st_dev, root_after.st_ino)
        or (common_before.st_dev, common_before.st_ino) != (common_after.st_dev, common_after.st_ino)
    ):
        _deny("SOURCE_CHANGED_DURING_OBSERVATION")

    return LocalWorktreeObservation(
        observed_source=TrustedRepositoryObservation(
            repository=REPOSITORY,
            branch=branch,
            commit=commit,
            tree=tree,
            reviewed_digest=expected_reviewed_digest,
            worktree_clean=True,
            worktree_root=str(root),
            isolation_id=isolation_id,
        )
    )
