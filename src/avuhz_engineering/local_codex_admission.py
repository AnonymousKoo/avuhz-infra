"""Signed, offline, PREFLIGHT_ONLY admission for the LOCAL engineering queue.

This module deliberately has no command runner, subprocess, network, Git, retry,
or worker surface.  Trusted source observations and an independently pinned
Ed25519 public key are inputs.  Validation is pure; nonce consumption is a
separate durable local decision.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import sqlite3
import stat
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Mapping
from urllib.parse import quote

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from avuhz_engineering.local_engineering_queue import (
    canonical_digest,
    manifest_digest as queue_manifest_digest,
    validate_manifest as validate_queue_manifest,
)

SCHEMA_VERSION = 1
REPOSITORY = "AnonymousKoo/avuhz-infra"
NAMESPACE = "AAE/local"
ENVIRONMENT = "LOCAL"
MODE = "PREFLIGHT_ONLY"
PROVIDER_AUTHORITY = "NONE"
PURPOSE = "AVUHZ_LOCAL_CODEX_ADMISSION_V1"
MAX_VALIDITY = timedelta(minutes=10)

COMMAND_PROFILE_IDS = frozenset(
    {
        "edit.allowed-paths.v1",
        "inspect.source.v1",
        "test.baseline.v1",
        "test.engineering.v1",
        "test.focused.v1",
    }
)
COMMAND_PROFILE_CATALOG_DIGEST = canonical_digest(sorted(COMMAND_PROFILE_IDS))
STOP_CONDITION_IDS = frozenset(
    {
        "approval.invalid",
        "limits.exceeded",
        "path.boundary-changed",
        "replay.detected",
        "source.dirty",
        "source.stale",
        "verification.failed",
    }
)
REQUIRED_STOP_CONDITIONS = STOP_CONDITION_IDS

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_GIT_OBJECT = re.compile(r"^[0-9a-f]{40}$")
_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
_NONCE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
_BRANCH = re.compile(r"^refs/heads/[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")
_PATH = re.compile(r"^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$")
_SIGNATURE = re.compile(r"^[A-Za-z0-9_-]{86}$")
_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_REPLAY_TABLE = "avuhz_local_codex_admission_nonce_v1"
_REPLAY_COLUMNS = (
    ("nonce_digest", "TEXT", 1, 1),
    ("task_digest", "TEXT", 1, 0),
    ("manifest_digest", "TEXT", 1, 0),
    ("claimed_at", "TEXT", 1, 0),
)


class AdmissionStop(ValueError):
    """Fail-closed rejection containing only a stable public status code."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _deny(code: str) -> None:
    raise AdmissionStop(code)


@dataclass(frozen=True)
class TrustedRepositoryObservation:
    """Source facts collected and authenticated outside this preflight module."""

    repository: str
    branch: str
    commit: str
    tree: str
    reviewed_digest: str
    worktree_clean: bool
    worktree_root: str
    isolation_id: str


@dataclass(frozen=True)
class AdmissionCandidate:
    """Verified but not yet replay-consumed; never an execution permit."""

    task_id: str
    nonce: str
    manifest_digest: str
    queue_manifest_digest: str
    expires_at: str
    status: str = "PREFLIGHT_VERIFIED_REPLAY_UNCLAIMED"
    mode: str = MODE
    execution_authorized: bool = False
    retry_authorized: bool = False


@dataclass(frozen=True)
class AdmissionResult:
    task_id: str
    manifest_digest: str
    queue_manifest_digest: str
    status: str = "PREFLIGHT_ADMITTED"
    mode: str = MODE
    nonce_claimed: bool = True
    execution_performed: bool = False
    execution_authorized: bool = False
    retry_authorized: bool = False
    network_authorized: bool = False
    github_mutation_authorized: bool = False
    provider_authority: str = PROVIDER_AUTHORITY


def _duplicates_denied(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _deny("MANIFEST_JSON_INVALID")
        result[key] = value
    return result


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def load_canonical_manifest(raw_manifest: bytes) -> dict[str, Any]:
    if type(raw_manifest) is not bytes or not raw_manifest or len(raw_manifest) > 131_072:
        _deny("MANIFEST_JSON_INVALID")
    try:
        document = json.loads(
            raw_manifest.decode("utf-8"), object_pairs_hook=_duplicates_denied,
            parse_constant=lambda _value: _deny("MANIFEST_JSON_INVALID"),
        )
    except (UnicodeError, json.JSONDecodeError, AdmissionStop):
        _deny("MANIFEST_JSON_INVALID")
    if type(document) is not dict:
        _deny("MANIFEST_SHAPE_INVALID")
    if not hmac.compare_digest(raw_manifest, canonical_bytes(document)):
        _deny("MANIFEST_NONCANONICAL")
    return document


def _exact(value: object, fields: set[str], code: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        _deny(code)
    return value


def _digest(value: object, code: str = "MANIFEST_BINDING_INVALID") -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        _deny(code)
    return value


def _reference(value: object, code: str = "MANIFEST_BINDING_INVALID") -> str:
    if type(value) is not str or _REFERENCE.fullmatch(value) is None:
        _deny(code)
    return value


def _utc(value: object) -> datetime:
    if type(value) is not str or _UTC.fullmatch(value) is None:
        _deny("TIME_INVALID")
    try:
        result = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except (TypeError, ValueError, OverflowError):
        _deny("TIME_INVALID")
    return result


def _strict_string_list(
    value: object, *, allowed: frozenset[str] | None = None, maximum: int = 64
) -> list[str]:
    if (
        type(value) is not list
        or not value
        or len(value) > maximum
        or any(type(item) is not str for item in value)
        or len(set(value)) != len(value)
    ):
        _deny("MANIFEST_BINDING_INVALID")
    if allowed is not None and not set(value) <= allowed:
        _deny("PROFILE_OR_STOP_CONDITION_INVALID")
    return value


def _safe_path(root: Path, value: object) -> str:
    if type(value) is not str or len(value) > 512 or _PATH.fullmatch(value) is None:
        _deny("PATH_INVALID")
    path = PurePosixPath(value)
    if path.is_absolute() or str(path) != value or any(p in {"", ".", ".."} for p in path.parts):
        _deny("PATH_ESCAPE")
    current = root
    for part in path.parts:
        current = current / part
        if current.is_symlink():
            _deny("PATH_SYMLINK")
    try:
        current.resolve(strict=False).relative_to(root)
    except (OSError, ValueError):
        _deny("PATH_ESCAPE")
    return value


def _branch(value: object) -> str:
    if (
        type(value) is not str
        or _BRANCH.fullmatch(value) is None
        or ".." in value
        or "//" in value
        or "@{" in value
        or value.endswith(("/", ".", ".lock"))
    ):
        _deny("SOURCE_INVALID")
    return value


def _positive_int(value: object, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        _deny("LIMITS_INVALID")
    return value


def _validate_limits(value: object) -> None:
    limits = _exact(
        value,
        {
            "wall_clock_seconds",
            "cpu_seconds",
            "max_processes",
            "memory_bytes",
            "output_bytes",
        },
        "LIMITS_INVALID",
    )
    wall = _positive_int(limits["wall_clock_seconds"], 1, 3600)
    cpu = _positive_int(limits["cpu_seconds"], 1, 1800)
    _positive_int(limits["max_processes"], 1, 16)
    _positive_int(limits["memory_bytes"], 67_108_864, 4_294_967_296)
    _positive_int(limits["output_bytes"], 1, 10_485_760)
    if cpu > wall:
        _deny("LIMITS_INVALID")


def _decode_signature(value: object) -> bytes:
    if type(value) is not str or _SIGNATURE.fullmatch(value) is None:
        _deny("SIGNATURE_INVALID")
    try:
        signature = base64.urlsafe_b64decode(value + "==")
    except (ValueError, binascii.Error):
        _deny("SIGNATURE_INVALID")
    if len(signature) != 64 or base64.urlsafe_b64encode(signature).rstrip(b"=").decode() != value:
        _deny("SIGNATURE_INVALID")
    return signature


def _verify_signature(
    payload: Mapping[str, Any], signature: bytes, *, pinned_public_key: bytes,
    pinned_public_key_digest: str,
) -> None:
    if (
        type(pinned_public_key) is not bytes
        or len(pinned_public_key) != 32
        or type(pinned_public_key_digest) is not str
        or _DIGEST.fullmatch(pinned_public_key_digest) is None
    ):
        _deny("TRUST_ANCHOR_UNVERIFIED")
    observed_digest = "sha256:" + hashlib.sha256(pinned_public_key).hexdigest()
    if not hmac.compare_digest(observed_digest, pinned_public_key_digest):
        _deny("TRUST_ANCHOR_UNVERIFIED")
    try:
        Ed25519PublicKey.from_public_bytes(pinned_public_key).verify(
            signature, canonical_bytes(dict(payload))
        )
    except (InvalidSignature, TypeError, ValueError):
        _deny("SIGNATURE_INVALID")


def validate_signed_admission(
    raw_manifest: bytes,
    *,
    repository_root: Path,
    queue_manifest: Mapping[str, Any],
    observed_source: TrustedRepositoryObservation,
    at_utc: datetime,
    pinned_issuer: str,
    pinned_key_id: str,
    pinned_public_key: bytes,
    pinned_public_key_digest: str,
) -> AdmissionCandidate:
    """Purely validate a signed admission; does not consume its nonce."""
    if (
        not isinstance(repository_root, Path)
        or repository_root.is_symlink()
        or not repository_root.is_absolute()
        or not repository_root.is_dir()
        or repository_root.resolve(strict=True) != repository_root
    ):
        _deny("WORKTREE_INVALID")
    root = repository_root.resolve(strict=True)
    if type(observed_source) is not TrustedRepositoryObservation:
        _deny("SOURCE_OBSERVATION_UNTRUSTED")
    if not isinstance(at_utc, datetime) or at_utc.tzinfo is None or at_utc.utcoffset() != timedelta(0):
        _deny("TIME_INVALID")
    if type(pinned_issuer) is not str or type(pinned_key_id) is not str:
        _deny("TRUST_ANCHOR_UNVERIFIED")

    document = load_canonical_manifest(raw_manifest)
    _exact(document, {"payload", "signature"}, "MANIFEST_KEYS_INVALID")
    payload = _exact(
        document["payload"],
        {
            "version", "purpose", "namespace", "environment", "repository", "issuer",
            "source", "queue_manifest", "task_id", "nonce", "prompt_digest",
            "command_profile_ids", "command_catalog_digest", "allowed_target_paths",
            "stop_conditions", "isolation_id", "limits", "network", "provider_authority",
            "github_mutation", "mode", "issued_at", "not_before", "expires_at",
        },
        "PAYLOAD_KEYS_INVALID",
    )
    signature_envelope = _exact(
        document["signature"], {"algorithm", "key_id", "value"}, "SIGNATURE_ENVELOPE_INVALID"
    )
    if payload["version"] != SCHEMA_VERSION or type(payload["version"]) is bool:
        _deny("VERSION_INVALID")
    if payload["purpose"] != PURPOSE:
        _deny("PURPOSE_INVALID")
    if payload["namespace"] != NAMESPACE or payload["environment"] != ENVIRONMENT:
        _deny("LOCAL_BOUNDARY_INVALID")
    if payload["repository"] != REPOSITORY:
        _deny("REPOSITORY_INVALID")
    if (
        payload["issuer"] != pinned_issuer
        or signature_envelope["key_id"] != pinned_key_id
        or signature_envelope["algorithm"] != "Ed25519"
    ):
        _deny("TRUST_ANCHOR_UNVERIFIED")
    _reference(payload["issuer"])
    _reference(signature_envelope["key_id"])
    task_id = _reference(payload["task_id"])
    isolation_id = _reference(payload["isolation_id"])
    if type(payload["nonce"]) is not str or _NONCE.fullmatch(payload["nonce"]) is None:
        _deny("NONCE_INVALID")
    _digest(payload["prompt_digest"])
    _digest(payload["command_catalog_digest"])
    if payload["command_catalog_digest"] != COMMAND_PROFILE_CATALOG_DIGEST:
        _deny("COMMAND_CATALOG_INVALID")
    profiles = _strict_string_list(payload["command_profile_ids"], allowed=COMMAND_PROFILE_IDS)
    if profiles != sorted(profiles):
        _deny("PROFILE_OR_STOP_CONDITION_INVALID")
    stops = _strict_string_list(payload["stop_conditions"], allowed=STOP_CONDITION_IDS)
    if set(stops) != REQUIRED_STOP_CONDITIONS or stops != sorted(stops):
        _deny("PROFILE_OR_STOP_CONDITION_INVALID")
    _validate_limits(payload["limits"])
    if (
        payload["network"] is not False
        or payload["provider_authority"] != PROVIDER_AUTHORITY
        or payload["github_mutation"] is not False
        or payload["mode"] != MODE
    ):
        _deny("AUTHORITY_INVALID")

    source = _exact(
        payload["source"], {"branch", "commit", "tree", "reviewed_digest"}, "SOURCE_INVALID"
    )
    if (
        type(source["commit"]) is not str or _GIT_OBJECT.fullmatch(source["commit"]) is None
        or type(source["tree"]) is not str or _GIT_OBJECT.fullmatch(source["tree"]) is None
    ):
        _deny("SOURCE_INVALID")
    _branch(source["branch"])
    _digest(source["reviewed_digest"], "SOURCE_INVALID")
    if (
        observed_source.repository != REPOSITORY
        or observed_source.branch != source["branch"]
        or observed_source.commit != source["commit"]
        or observed_source.tree != source["tree"]
        or observed_source.reviewed_digest != source["reviewed_digest"]
    ):
        _deny("SOURCE_MISMATCH")
    if (
        observed_source.worktree_root != str(root)
        or observed_source.isolation_id != isolation_id
    ):
        _deny("ISOLATION_INVALID")
    if type(observed_source.worktree_clean) is not bool:
        _deny("SOURCE_OBSERVATION_UNTRUSTED")
    if observed_source.worktree_clean:
        pass
    else:
        _deny("WORKTREE_DIRTY")

    queue_binding = _exact(
        payload["queue_manifest"],
        {"manifest_id", "manifest_digest", "approval_digest"},
        "QUEUE_BINDING_INVALID",
    )
    _reference(queue_binding["manifest_id"], "QUEUE_BINDING_INVALID")
    _digest(queue_binding["manifest_digest"], "QUEUE_BINDING_INVALID")
    _digest(queue_binding["approval_digest"], "QUEUE_BINDING_INVALID")
    try:
        validated_queue = validate_queue_manifest(queue_manifest, root)
    except (TypeError, ValueError, OSError):
        _deny("QUEUE_MANIFEST_INVALID")
    observed_queue_digest = queue_manifest_digest(validated_queue)
    if (
        queue_binding["manifest_id"] != validated_queue["manifest_id"]
        or queue_binding["manifest_digest"] != observed_queue_digest
        or queue_binding["approval_digest"] != validated_queue["approval"]["approval_digest"]
    ):
        _deny("QUEUE_BINDING_INVALID")
    matching_tasks = [task for task in validated_queue["tasks"] if task["task_id"] == task_id]
    if len(matching_tasks) != 1:
        _deny("TASK_BINDING_INVALID")
    paths = _strict_string_list(payload["allowed_target_paths"])
    checked_paths = [_safe_path(root, value) for value in paths]
    if checked_paths != sorted(checked_paths) or checked_paths != sorted(matching_tasks[0]["allowed_file_paths"]):
        _deny("PATH_BINDING_INVALID")
    if validated_queue["worktree"]["root"] != observed_source.worktree_root:
        _deny("ISOLATION_INVALID")

    issued = _utc(payload["issued_at"])
    not_before = _utc(payload["not_before"])
    expires = _utc(payload["expires_at"])
    now = at_utc.astimezone(timezone.utc).replace(microsecond=0)
    if (
        issued > not_before
        or not_before > now
        or now >= expires
        or expires <= issued
        or expires - issued > MAX_VALIDITY
    ):
        _deny("TIME_WINDOW_INVALID")

    signature = _decode_signature(signature_envelope["value"])
    _verify_signature(
        payload, signature, pinned_public_key=pinned_public_key,
        pinned_public_key_digest=pinned_public_key_digest,
    )
    return AdmissionCandidate(
        task_id=task_id,
        nonce=payload["nonce"],
        manifest_digest=canonical_digest(document),
        queue_manifest_digest=observed_queue_digest,
        expires_at=payload["expires_at"],
    )


def _checked_replay_store(path: Path, repository_root: Path) -> str:
    if not isinstance(path, Path) or not path.is_absolute() or path.suffix != ".sqlite3":
        _deny("REPLAY_STORE_UNTRUSTED")
    try:
        if path.resolve(strict=True) != path:
            _deny("REPLAY_STORE_UNTRUSTED")
        path.resolve(strict=True).relative_to(repository_root.resolve(strict=True))
    except ValueError:
        pass
    except OSError:
        _deny("REPLAY_STORE_UNAVAILABLE")
    else:
        _deny("REPLAY_STORE_UNTRUSTED")
    try:
        file_info = path.lstat()
        parent_info = path.parent.lstat()
    except OSError:
        _deny("REPLAY_STORE_UNAVAILABLE")
    if (
        not stat.S_ISREG(file_info.st_mode)
        or stat.S_ISLNK(file_info.st_mode)
        or file_info.st_uid != os.getuid()
        or file_info.st_mode & 0o077
        or not stat.S_ISDIR(parent_info.st_mode)
        or parent_info.st_uid != os.getuid()
        or parent_info.st_mode & 0o077
    ):
        _deny("REPLAY_STORE_UNTRUSTED")
    return "file:" + quote(str(path), safe="/") + "?mode=rw"


def _verify_replay_schema(connection: sqlite3.Connection) -> None:
    rows = connection.execute(f"PRAGMA table_info({_REPLAY_TABLE})").fetchall()
    observed = tuple((row[1], row[2], row[3], row[5]) for row in rows)
    if observed != _REPLAY_COLUMNS:
        _deny("REPLAY_STORE_CORRUPT")
    objects = connection.execute(
        "SELECT type, name, tbl_name FROM sqlite_master "
        "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
    ).fetchall()
    if objects != [("table", _REPLAY_TABLE, _REPLAY_TABLE)]:
        _deny("REPLAY_STORE_CORRUPT")


def admit_preflight(
    raw_manifest: bytes,
    *,
    replay_store_path: Path,
    repository_root: Path,
    queue_manifest: Mapping[str, Any],
    observed_source: TrustedRepositoryObservation,
    at_utc: datetime,
    pinned_issuer: str,
    pinned_key_id: str,
    pinned_public_key: bytes,
    pinned_public_key_digest: str,
) -> AdmissionResult:
    """Revalidate signed input, then atomically consume its nonce.

    No public replay API accepts an ``AdmissionCandidate``.  The raw signed
    document and all trusted observations are rechecked immediately before the
    exclusive transaction so a caller cannot manufacture or retain claimable
    validation state.
    """
    candidate = validate_signed_admission(
        raw_manifest,
        repository_root=repository_root,
        queue_manifest=queue_manifest,
        observed_source=observed_source,
        at_utc=at_utc,
        pinned_issuer=pinned_issuer,
        pinned_key_id=pinned_key_id,
        pinned_public_key=pinned_public_key,
        pinned_public_key_digest=pinned_public_key_digest,
    )
    uri = _checked_replay_store(replay_store_path, repository_root)
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(uri, uri=True, timeout=3, isolation_level=None)
        connection.execute("PRAGMA synchronous=FULL")
        if connection.execute("PRAGMA journal_mode=DELETE").fetchone()[0].lower() != "delete":
            _deny("REPLAY_STORE_UNVERIFIED")
        if connection.execute("PRAGMA integrity_check(1)").fetchone() != ("ok",):
            _deny("REPLAY_STORE_CORRUPT")
        connection.execute("BEGIN EXCLUSIVE")
        _verify_replay_schema(connection)
        connection.execute(
            f"INSERT INTO {_REPLAY_TABLE} "
            "(nonce_digest, task_digest, manifest_digest, claimed_at) VALUES (?, ?, ?, ?)",
            (
                canonical_digest(candidate.nonce),
                canonical_digest(candidate.task_id),
                candidate.manifest_digest,
                at_utc.astimezone(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ"),
            ),
        )
        connection.execute("COMMIT")
        directory = os.open(replay_store_path.parent, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except sqlite3.IntegrityError:
        if connection is not None and connection.in_transaction:
            connection.rollback()
        _deny("NONCE_REPLAY")
    except AdmissionStop:
        if connection is not None and connection.in_transaction:
            connection.rollback()
        raise
    except (OSError, sqlite3.Error):
        if connection is not None and connection.in_transaction:
            connection.rollback()
        _deny("REPLAY_STORE_UNVERIFIED")
    finally:
        if connection is not None:
            connection.close()
    return AdmissionResult(
        task_id=candidate.task_id,
        manifest_digest=candidate.manifest_digest,
        queue_manifest_digest=candidate.queue_manifest_digest,
    )
