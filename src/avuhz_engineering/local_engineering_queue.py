"""Fail-closed, non-executing LOCAL engineering queue controller."""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping

SCHEMA_VERSION = 1
STATE_VERSION = 1
_REPOSITORY = "AnonymousKoo/avuhz-infra"
_NAMESPACE = "AAE/local"
_SCOPE = "repository-local-engineering"
_REFERENCE = re.compile(r"^[a-z][a-z0-9]*(?:[._:-][a-z0-9]+)*$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_RELATIVE_PATH = re.compile(r"^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$")
_PROHIBITED_REFERENCE_PARTS = frozenset(
    {
        "argv", "auth", "bash", "billing", "cmd", "command", "credential", "curl",
        "daemon", "deploy", "exec", "execution", "github", "http", "https", "migration",
        "model", "n8n", "network", "powershell", "production", "provider", "remote",
        "scheduler", "secret", "shell", "socket", "staging", "subprocess", "token", "wget",
    }
)
_PROHIBITED_PATH_PREFIXES = (
    ".git/", ".github/workflows/", "contracts/plans/", "n8n/", "n8n-workflows/",
    "supabase/",
)
_PROHIBITED_PATH_NAMES = frozenset({".env", ".n8n", "id_rsa", "id_ed25519"})
_PROHIBITED_PATH_SUFFIXES = (".key", ".pem", ".p12", ".pfx")
_SECRET_VALUE = re.compile(
    r"(?i)(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|(?:bearer|basic)\s+[a-z0-9._~+/=-]{8,}|"
    r"(?:api[_-]?key|access[_-]?token|client[_-]?secret|password)\s*[:=])"
)


class QueueError(ValueError):
    """A safe queue failure with a stable, non-sensitive code."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class ManifestValidationError(QueueError):
    pass


class ReplayError(QueueError):
    pass


@dataclass(frozen=True)
class QueueSummary:
    manifest_id: str
    status: str
    task_ids: tuple[str, ...]
    task_count: int
    manifest_digest: str
    authority_effect: str = "NONE"
    provider_authority: bool = False
    execution_performed: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "authority_effect": self.authority_effect,
            "execution_performed": self.execution_performed,
            "manifest_digest": self.manifest_digest,
            "manifest_id": self.manifest_id,
            "provider_authority": self.provider_authority,
            "status": self.status,
            "task_count": self.task_count,
            "task_ids": list(self.task_ids),
        }


def _pairs_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ManifestValidationError("duplicate_json_key")
        value[key] = item
    return value


def load_manifest(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ManifestValidationError("manifest_not_regular_file")
    try:
        if path.stat().st_size > 1_048_576:
            raise ManifestValidationError("manifest_too_large")
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_pairs_without_duplicates)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ManifestValidationError("manifest_json_invalid") from exc
    if not isinstance(value, dict):
        raise ManifestValidationError("manifest_type_invalid")
    return value


def canonical_digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise QueueError("target_not_regular_file")
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
    except OSError as exc:
        raise QueueError("target_unreadable") from exc
    return "sha256:" + digest.hexdigest()


def approval_scope(manifest: Mapping[str, Any]) -> dict[str, Any]:
    return {key: manifest[key] for key in (
        "schema_version", "manifest_id", "environment", "namespace", "repository", "scope",
        "worktree", "allowed_file_paths", "target_baselines", "tasks",
    )}


def approval_digest(approval: Mapping[str, Any]) -> str:
    return canonical_digest({key: value for key, value in approval.items() if key != "approval_digest"})


def manifest_digest(manifest: Mapping[str, Any]) -> str:
    return canonical_digest(manifest)


def _exact_keys(value: Mapping[str, Any], expected: set[str], code: str) -> None:
    if set(value) != expected:
        raise ManifestValidationError(code)


def _bounded_list(value: Any, code: str, *, maximum: int = 64) -> list[Any]:
    if not isinstance(value, list) or not value or len(value) > maximum:
        raise ManifestValidationError(code)
    return value


def _reference(value: Any, code: str) -> str:
    if not isinstance(value, str) or not 3 <= len(value) <= 128 or not _REFERENCE.fullmatch(value):
        raise ManifestValidationError(code)
    parts = set(re.split(r"[._:-]", value))
    if parts & _PROHIBITED_REFERENCE_PARTS:
        raise ManifestValidationError("prohibited_scope")
    return value


def _relative_path(value: Any, code: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 512 or "\\" in value:
        raise ManifestValidationError(code)
    if _SECRET_VALUE.search(value) or any(char in value for char in ("\x00", "\n", "\r", "\t")):
        raise ManifestValidationError(code)
    path = PurePosixPath(value)
    if path.is_absolute() or str(path) != value or any(part in {"", ".", ".."} for part in path.parts):
        raise ManifestValidationError("path_escape")
    if not _RELATIVE_PATH.fullmatch(value):
        raise ManifestValidationError(code)
    lowered = value.lower()
    if (
        lowered in _PROHIBITED_PATH_NAMES
        or any(part.lower() in _PROHIBITED_PATH_NAMES for part in path.parts)
        or lowered.startswith(_PROHIBITED_PATH_PREFIXES)
        or lowered.endswith(_PROHIBITED_PATH_SUFFIXES)
    ):
        raise ManifestValidationError("prohibited_path")
    return value


def _unique_strings(values: list[Any], parser: Callable[[Any, str], str], code: str) -> list[str]:
    parsed = [parser(item, code) for item in values]
    if len(set(parsed)) != len(parsed):
        raise ManifestValidationError("duplicate_value")
    return parsed


def _safe_target(repository_root: Path, relative: str) -> Path:
    current = repository_root
    for part in PurePosixPath(relative).parts:
        current = current / part
        if current.is_symlink():
            raise ManifestValidationError("path_symlink")
    try:
        current.resolve(strict=False).relative_to(repository_root)
    except ValueError as exc:
        raise ManifestValidationError("path_escape") from exc
    return current


def validate_manifest(manifest: Mapping[str, Any], repository_root: Path) -> dict[str, Any]:
    """Validate an exact LOCAL manifest using only the Python standard library."""
    root = repository_root.resolve(strict=True)
    if not root.is_dir() or repository_root.is_symlink():
        raise ManifestValidationError("repository_root_invalid")
    expected = {
        "schema_version", "manifest_id", "environment", "namespace", "repository", "scope",
        "worktree", "allowed_file_paths", "target_baselines", "tasks", "approval",
    }
    _exact_keys(manifest, expected, "manifest_keys_invalid")
    if manifest["schema_version"] != SCHEMA_VERSION or isinstance(manifest["schema_version"], bool):
        raise ManifestValidationError("schema_version_invalid")
    manifest_id = _reference(manifest["manifest_id"], "manifest_id_invalid")
    if manifest["environment"] != "LOCAL" or manifest["namespace"] != _NAMESPACE:
        raise ManifestValidationError("local_boundary_invalid")
    if manifest["repository"] != _REPOSITORY or manifest["scope"] != _SCOPE:
        raise ManifestValidationError("repository_scope_invalid")

    worktree = manifest["worktree"]
    if not isinstance(worktree, dict):
        raise ManifestValidationError("worktree_invalid")
    _exact_keys(worktree, {"root", "ownership"}, "worktree_keys_invalid")
    if worktree["ownership"] != "EXCLUSIVE_LOCAL_WORKTREE":
        raise ManifestValidationError("worktree_ownership_invalid")
    if not isinstance(worktree["root"], str) or not Path(worktree["root"]).is_absolute():
        raise ManifestValidationError("worktree_root_invalid")
    if Path(worktree["root"]).resolve(strict=False) != root or worktree["root"] != str(root):
        raise ManifestValidationError("worktree_root_mismatch")

    allowed = _unique_strings(
        _bounded_list(manifest["allowed_file_paths"], "allowed_paths_invalid"),
        _relative_path,
        "allowed_path_invalid",
    )
    for relative in allowed:
        _safe_target(root, relative)

    baselines = _bounded_list(manifest["target_baselines"], "target_baselines_invalid")
    baseline_paths: list[str] = []
    for baseline in baselines:
        if not isinstance(baseline, dict):
            raise ManifestValidationError("target_baseline_invalid")
        _exact_keys(baseline, {"path", "digest"}, "target_baseline_keys_invalid")
        baseline_paths.append(_relative_path(baseline["path"], "baseline_path_invalid"))
        digest = baseline["digest"]
        if digest != "ABSENT" and (not isinstance(digest, str) or not _DIGEST.fullmatch(digest)):
            raise ManifestValidationError("baseline_digest_invalid")
    if len(set(baseline_paths)) != len(baseline_paths) or set(baseline_paths) != set(allowed):
        raise ManifestValidationError("baseline_coverage_invalid")

    tasks = _bounded_list(manifest["tasks"], "tasks_invalid")
    task_ids: list[str] = []
    owned_paths: list[str] = []
    for task in tasks:
        if not isinstance(task, dict):
            raise ManifestValidationError("task_invalid")
        _exact_keys(
            task,
            {"task_id", "resource_reference", "allowed_file_paths", "acceptance_criteria", "stop_conditions"},
            "task_keys_invalid",
        )
        task_ids.append(_reference(task["task_id"], "task_id_invalid"))
        resource = _reference(task["resource_reference"], "resource_reference_invalid")
        if not resource.startswith("repository."):
            raise ManifestValidationError("resource_reference_invalid")
        task_paths = _unique_strings(
            _bounded_list(task["allowed_file_paths"], "task_paths_invalid"),
            _relative_path,
            "task_path_invalid",
        )
        if not set(task_paths) <= set(allowed):
            raise ManifestValidationError("task_path_not_allowed")
        owned_paths.extend(task_paths)
        _unique_strings(
            _bounded_list(task["acceptance_criteria"], "acceptance_criteria_invalid", maximum=32),
            _reference,
            "acceptance_criterion_invalid",
        )
        _unique_strings(
            _bounded_list(task["stop_conditions"], "stop_conditions_invalid", maximum=32),
            _reference,
            "stop_condition_invalid",
        )
    if len(set(task_ids)) != len(task_ids):
        raise ManifestValidationError("duplicate_task_id")
    if len(owned_paths) != len(set(owned_paths)) or set(owned_paths) != set(allowed):
        raise ManifestValidationError("resource_ownership_invalid")

    approval = manifest["approval"]
    if not isinstance(approval, dict):
        raise ManifestValidationError("approval_invalid")
    _exact_keys(
        approval,
        {"approval_id", "approved_task_ids", "scope_digest", "approval_digest", "authority_effect", "immutable", "provider_authority"},
        "approval_keys_invalid",
    )
    _reference(approval["approval_id"], "approval_id_invalid")
    approved = _unique_strings(
        _bounded_list(approval["approved_task_ids"], "approved_tasks_invalid"),
        _reference,
        "approved_task_id_invalid",
    )
    if approved != task_ids:
        raise ManifestValidationError("approved_tasks_mismatch")
    if approval["authority_effect"] != "REPOSITORY_LOCAL_ONLY" or approval["immutable"] is not True:
        raise ManifestValidationError("approval_authority_invalid")
    if approval["provider_authority"] is not False:
        raise ManifestValidationError("provider_authority_prohibited")
    if approval["scope_digest"] != canonical_digest(approval_scope(manifest)):
        raise ManifestValidationError("approval_scope_digest_mismatch")
    if approval["approval_digest"] != approval_digest(approval):
        raise ManifestValidationError("approval_digest_mismatch")
    if _SECRET_VALUE.search(json.dumps(manifest, sort_keys=True, separators=(",", ":"))):
        raise ManifestValidationError("secret_material_prohibited")
    return dict(manifest)


class LocalEngineeringQueue:
    """Persistent state machine that verifies manifests but never executes tasks."""

    def __init__(self, repository_root: Path, state_dir: Path):
        self.repository_root = repository_root.resolve(strict=True)
        if not state_dir.is_absolute():
            raise QueueError("state_dir_must_be_absolute")
        self.state_dir = state_dir.resolve(strict=False)
        try:
            self.state_dir.relative_to(self.repository_root)
        except ValueError:
            pass
        else:
            raise QueueError("state_dir_inside_repository")
        if state_dir.is_symlink():
            raise QueueError("state_dir_symlink")
        self.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not self.state_dir.is_dir():
            raise QueueError("state_dir_invalid")
        if stat.S_IMODE(self.state_dir.stat().st_mode) & 0o077:
            raise QueueError("state_dir_permissions_invalid")
        self.state_path = self.state_dir / "queue-state.json"

    def _empty_state(self) -> dict[str, Any]:
        return {"records": {}, "state_version": STATE_VERSION, "task_claims": {}}

    def _load_state(self) -> dict[str, Any]:
        if not self.state_path.exists():
            return self._empty_state()
        if self.state_path.is_symlink() or not self.state_path.is_file():
            raise QueueError("state_file_invalid")
        try:
            value = json.loads(self.state_path.read_text(encoding="utf-8"), object_pairs_hook=_pairs_without_duplicates)
        except (OSError, UnicodeError, json.JSONDecodeError, ManifestValidationError) as exc:
            raise QueueError("state_file_invalid") from exc
        if not isinstance(value, dict) or set(value) != {"records", "state_version", "task_claims"}:
            raise QueueError("state_shape_invalid")
        if value["state_version"] != STATE_VERSION or not isinstance(value["records"], dict) or not isinstance(value["task_claims"], dict):
            raise QueueError("state_shape_invalid")
        expected_claims: dict[str, str] = {}
        allowed_statuses = {"QUEUED", "READY", "DRY_RUN_VERIFIED", "BLOCKED"}
        normal_transitions = ["QUEUED", "READY", "DRY_RUN_VERIFIED"]
        for manifest_id, record in value["records"].items():
            if not isinstance(record, dict) or set(record) != {
                "block_code", "manifest_digest", "manifest_id", "status", "task_ids", "transitions",
            }:
                raise QueueError("state_shape_invalid")
            if record["manifest_id"] != manifest_id or not isinstance(manifest_id, str) or not _REFERENCE.fullmatch(manifest_id):
                raise QueueError("state_shape_invalid")
            if not isinstance(record["manifest_digest"], str) or not _DIGEST.fullmatch(record["manifest_digest"]):
                raise QueueError("state_shape_invalid")
            status = record["status"]
            transitions = record["transitions"]
            task_ids = record["task_ids"]
            if status not in allowed_statuses or not isinstance(transitions, list) or not isinstance(task_ids, list) or not task_ids:
                raise QueueError("state_shape_invalid")
            if status == "BLOCKED":
                if (
                    not isinstance(record["block_code"], str)
                    or not re.fullmatch(r"[a-z][a-z0-9_]{2,63}", record["block_code"])
                    or not transitions
                    or transitions[-1] != "BLOCKED"
                    or transitions[:-1] not in (["QUEUED"], ["QUEUED", "READY"], normal_transitions)
                ):
                    raise QueueError("state_shape_invalid")
            else:
                expected_transitions = normal_transitions[: normal_transitions.index(status) + 1]
                if record["block_code"] is not None or transitions != expected_transitions:
                    raise QueueError("state_shape_invalid")
            if len(set(task_ids)) != len(task_ids):
                raise QueueError("state_shape_invalid")
            for task_id in task_ids:
                if not isinstance(task_id, str) or not _REFERENCE.fullmatch(task_id) or task_id in expected_claims:
                    raise QueueError("state_shape_invalid")
                expected_claims[task_id] = manifest_id
        if value["task_claims"] != expected_claims:
            raise QueueError("state_shape_invalid")
        return value

    def _write_state(self, state: Mapping[str, Any]) -> None:
        payload = json.dumps(state, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
        descriptor, temporary_name = tempfile.mkstemp(prefix=".queue-state-", suffix=".tmp", dir=self.state_dir)
        temporary = Path(temporary_name)
        try:
            os.fchmod(descriptor, stat.S_IRUSR | stat.S_IWUSR)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.state_path)
            directory = os.open(self.state_dir, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if temporary.exists():
                temporary.unlink()

    def _validated(self, manifest: Mapping[str, Any]) -> tuple[dict[str, Any], str, tuple[str, ...]]:
        validated = validate_manifest(manifest, self.repository_root)
        return validated, manifest_digest(validated), tuple(task["task_id"] for task in validated["tasks"])

    def _record(self, state: Mapping[str, Any], manifest_id: str) -> dict[str, Any]:
        record = state["records"].get(manifest_id)
        if not isinstance(record, dict):
            raise QueueError("manifest_not_queued")
        return record

    def _summary(self, record: Mapping[str, Any]) -> QueueSummary:
        return QueueSummary(
            manifest_id=record["manifest_id"], status=record["status"],
            task_ids=tuple(record["task_ids"]), task_count=len(record["task_ids"]),
            manifest_digest=record["manifest_digest"],
        )

    def enqueue(self, manifest: Mapping[str, Any]) -> QueueSummary:
        validated, digest, task_ids = self._validated(manifest)
        state = self._load_state()
        manifest_id = validated["manifest_id"]
        if manifest_id in state["records"]:
            raise ReplayError("manifest_replay")
        if any(task_id in state["task_claims"] for task_id in task_ids):
            raise ReplayError("task_id_replay")
        record = {
            "block_code": None,
            "manifest_digest": digest,
            "manifest_id": manifest_id,
            "status": "QUEUED",
            "task_ids": list(task_ids),
            "transitions": ["QUEUED"],
        }
        state["records"][manifest_id] = record
        for task_id in task_ids:
            state["task_claims"][task_id] = manifest_id
        self._write_state(state)
        return self._summary(record)

    def _matching(self, manifest: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        validated, digest, _ = self._validated(manifest)
        state = self._load_state()
        record = self._record(state, validated["manifest_id"])
        if record.get("manifest_digest") != digest:
            record["status"] = "BLOCKED"
            record["block_code"] = "manifest_mismatch"
            if record["transitions"][-1] != "BLOCKED":
                record["transitions"].append("BLOCKED")
            self._write_state(state)
            raise QueueError("manifest_mismatch")
        return validated, state, record

    def _verify_targets(self, manifest: Mapping[str, Any]) -> None:
        for baseline in manifest["target_baselines"]:
            target = _safe_target(self.repository_root, baseline["path"])
            expected = baseline["digest"]
            if expected == "ABSENT":
                if target.exists() or target.is_symlink():
                    raise QueueError("target_baseline_mismatch")
            elif target.is_symlink() or not target.is_file() or file_digest(target) != expected:
                raise QueueError("target_baseline_mismatch")

    def _block(self, state: dict[str, Any], record: dict[str, Any], code: str) -> None:
        record["status"] = "BLOCKED"
        record["block_code"] = code
        if record["transitions"][-1] != "BLOCKED":
            record["transitions"].append("BLOCKED")
        self._write_state(state)

    def prepare(self, manifest: Mapping[str, Any]) -> QueueSummary:
        validated, state, record = self._matching(manifest)
        if record["status"] == "BLOCKED":
            raise QueueError("queue_blocked")
        if record["status"] != "QUEUED":
            raise ReplayError("transition_replay")
        try:
            self._verify_targets(validated)
        except QueueError as exc:
            self._block(state, record, exc.code)
            raise
        record["status"] = "READY"
        record["transitions"].append("READY")
        self._write_state(state)
        return self._summary(record)

    def verify_dry_run(self, manifest: Mapping[str, Any]) -> QueueSummary:
        validated, state, record = self._matching(manifest)
        if record["status"] == "BLOCKED":
            raise QueueError("queue_blocked")
        if record["status"] != "READY":
            raise ReplayError("transition_replay")
        try:
            self._verify_targets(validated)
        except QueueError as exc:
            self._block(state, record, exc.code)
            raise
        record["status"] = "DRY_RUN_VERIFIED"
        record["transitions"].append("DRY_RUN_VERIFIED")
        self._write_state(state)
        return self._summary(record)

    def run_resumable_dry_run(self, manifest: Mapping[str, Any]) -> QueueSummary:
        validated, digest, _ = self._validated(manifest)
        state = self._load_state()
        record = state["records"].get(validated["manifest_id"])
        if record is None:
            self.enqueue(validated)
            record = self._load_state()["records"][validated["manifest_id"]]
        elif record.get("manifest_digest") != digest:
            self._matching(validated)
        if record["status"] == "QUEUED":
            self.prepare(validated)
            record = self._load_state()["records"][validated["manifest_id"]]
        if record["status"] == "READY":
            return self.verify_dry_run(validated)
        if record["status"] == "DRY_RUN_VERIFIED":
            raise ReplayError("manifest_replay")
        raise QueueError("queue_blocked")
