"""Fail-closed file persistence for bounded authorization-plan execution progress.

The certified initial progress artifact remains immutable. Runtime execution progress is
stored separately and advanced one engine-produced record version at a time. This
module is provider-neutral and performs no provider contact or remote mutation.
"""
from __future__ import annotations

import copy
import json
import os
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Callable

from .authorization_plan import (
    AuthorizationPlanError,
    AuthorizationPlanStop,
    validate_progress,
)


Transition = Callable[[dict], dict]


def _utc(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError) as exc:
        raise AuthorizationPlanError("PROGRESS_TIMESTAMP_INVALID") from exc
    if parsed.tzinfo is None:
        raise AuthorizationPlanError("PROGRESS_TIMESTAMP_INVALID")
    return parsed


def _load_json(path: Path) -> dict:
    try:
        with path.open(encoding="utf-8") as handle:
            value = json.load(handle)
    except FileNotFoundError as exc:
        raise AuthorizationPlanStop("PROGRESS_FILE_MISSING") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise AuthorizationPlanError("PROGRESS_FILE_INVALID") from exc
    if not isinstance(value, dict):
        raise AuthorizationPlanError("PROGRESS_FILE_INVALID")
    return value


def _atomic_write_json(path: Path, value: dict) -> None:
    if not path.parent.is_dir():
        raise AuthorizationPlanStop("PROGRESS_DIRECTORY_MISSING")
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary_path = Path(handle.name)
            json.dump(value, handle, indent=2, ensure_ascii=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    except OSError as exc:
        raise AuthorizationPlanError("PROGRESS_WRITE_FAILED") from exc
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()


class FileAuthorizationProgressStore:
    """Persist the latest resumable progress without mutating its certified baseline."""

    def __init__(
        self,
        *,
        plan: dict,
        schema_root: Path,
        initial_progress_path: Path,
        execution_progress_path: Path,
    ) -> None:
        self.plan = copy.deepcopy(plan)
        self.schema_root = schema_root
        self.initial_progress_path = initial_progress_path
        self.execution_progress_path = execution_progress_path

    def _initial(self) -> dict:
        initial = _load_json(self.initial_progress_path)
        validate_progress(self.plan, initial, self.schema_root)
        return initial

    def _validate_lineage(self, initial: dict, current: dict) -> None:
        if current["progress_id"] != initial["progress_id"]:
            raise AuthorizationPlanStop("PROGRESS_ID_MISMATCH")
        if current["record_version"] < initial["record_version"]:
            raise AuthorizationPlanStop("PROGRESS_VERSION_ROLLBACK")
        if (
            current["record_version"] == initial["record_version"]
            and current != initial
        ):
            raise AuthorizationPlanStop("PROGRESS_BASELINE_DIVERGED")
        if _utc(current["updated_at"]) < _utc(initial["updated_at"]):
            raise AuthorizationPlanStop("PROGRESS_TIMESTAMP_ROLLBACK")

    def load_current(self) -> dict:
        """Return the latest valid execution progress or the immutable baseline."""
        initial = self._initial()
        if not self.execution_progress_path.exists():
            return copy.deepcopy(initial)
        current = _load_json(self.execution_progress_path)
        validate_progress(self.plan, current, self.schema_root)
        self._validate_lineage(initial, current)
        return current

    def bootstrap_execution_progress(self) -> dict:
        """Create the separate execution artifact as an exact baseline copy if absent."""
        initial = self._initial()
        if self.execution_progress_path.exists():
            return self.load_current()
        _atomic_write_json(self.execution_progress_path, initial)
        persisted = self.load_current()
        if persisted != initial:
            raise AuthorizationPlanStop("PROGRESS_PERSISTENCE_MISMATCH")
        return persisted

    def persist_transition(
        self,
        *,
        expected_progress_digest: str,
        transition: Transition,
    ) -> dict:
        """Apply and atomically persist exactly one versioned engine transition.

        The optimistic digest check prevents stale or concurrent writers. A transition
        must produce exactly the next record version; this prevents an authorize and
        outcome pair from being silently collapsed into one persisted update.
        """
        current = self.load_current()
        if current["progress_digest"] != expected_progress_digest:
            raise AuthorizationPlanStop("PROGRESS_STALE_WRITE")
        candidate = transition(copy.deepcopy(current))
        if not isinstance(candidate, dict):
            raise AuthorizationPlanError("PROGRESS_TRANSITION_INVALID")
        validate_progress(self.plan, candidate, self.schema_root)
        if candidate["progress_id"] != current["progress_id"]:
            raise AuthorizationPlanStop("PROGRESS_ID_MISMATCH")
        if candidate["record_version"] != current["record_version"] + 1:
            raise AuthorizationPlanStop("PROGRESS_VERSION_NOT_MONOTONIC")
        if _utc(candidate["updated_at"]) < _utc(current["updated_at"]):
            raise AuthorizationPlanStop("PROGRESS_TIMESTAMP_ROLLBACK")
        if candidate["progress_digest"] == current["progress_digest"]:
            raise AuthorizationPlanStop("PROGRESS_TRANSITION_EMPTY")

        _atomic_write_json(self.execution_progress_path, candidate)
        persisted = self.load_current()
        if persisted != candidate:
            raise AuthorizationPlanStop("PROGRESS_PERSISTENCE_MISMATCH")
        return persisted
