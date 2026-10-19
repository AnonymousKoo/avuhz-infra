"""LOCAL/TEST-only atomic, non-authoritative shared n8n receipt proof.

This is a repository test adapter, NOT an n8n node, hosted HTTP endpoint,
provider credential, deployment, or DATA table. Native webhook authentication
and authorized tenant/event selection MUST occur before an approved hosted
receiver could call an equivalent durable store. No raw event body is retained.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping

_FIELDS = frozenset({
    "event_id", "event_type", "tenant_id", "correlation_id", "occurred_at",
    "authoritative_subject_reference", "authoritative_subject_version",
    "delivery_idempotency_key",
})
_DELIVERY_KEY = re.compile(r"[A-Za-z0-9._:-]{8,128}\Z", re.ASCII)
_RECEIPT_CONTRACTS = {
    "acquisition.intake.received": ("ACQUISITION_INTAKE", frozenset({1})),
    "work_intake.opened": ("WORK_ITEM", frozenset({1})),
}


class InvalidReceipt(ValueError):
    pass


class UnauthorizedReceipt(PermissionError):
    pass


class ConflictingReceipt(ValueError):
    pass


class ReceiptStoreUnavailable(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class Receipt:
    status: int
    duplicate: bool


def _uuid(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        return str(uuid.UUID(value)) == value
    except (ValueError, TypeError, AttributeError):
        return False


def _valid_utc(value: object) -> bool:
    if type(value) is not str or not value.endswith("Z"):
        return False
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except (OverflowError, ValueError):
        return False
    return parsed.tzinfo == timezone.utc


class LocalN8nReceiptStore:
    """SQLite LOCAL/TEST contract for atomic unique receipt-before-ACK.

    Receives only already-authenticated, already-configured server-side calls.
    Never expose this API directly to a browser, arbitrary webhook, or network.
    A hosted n8n receiver requires independently approved credentials, storage
    and transport; SQLite storage does not replace tenant RLS in Supabase.
    """

    def __init__(self, path: Path, *, trusted_tenant_id: str,
                 allowed_event_types: frozenset[str]):
        if (not isinstance(path, Path) or not path.is_absolute()
                or not _uuid(trusted_tenant_id)
                or type(allowed_event_types) is not frozenset
                or not allowed_event_types
                or any(type(event) is not str or not event
                       or event not in _RECEIPT_CONTRACTS
                       for event in allowed_event_types)):
            raise ValueError("trusted LOCAL/TEST receipt configuration required")
        parent = path.parent
        if (not parent.is_dir()
                or stat.S_IMODE(parent.stat().st_mode) & 0o077):
            raise ValueError("private LOCAL/TEST receipt directory required")
        if path.is_symlink():
            raise ValueError("symlink receipt database forbidden")
        if not path.exists():
            try:
                fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
                os.close(fd)
            except FileExistsError:
                pass
        if not path.is_file() or stat.S_IMODE(path.stat().st_mode) & 0o077:
            raise ValueError("private receipt database required")
        self._path = path
        self._tenant_id = trusted_tenant_id
        self._allowed = allowed_event_types
        try:
            with sqlite3.connect(self._path, timeout=5) as db:
                db.execute("PRAGMA synchronous=FULL")
                db.execute("""
                    CREATE TABLE IF NOT EXISTS local_n8n_receipts (
                        trusted_tenant_id TEXT NOT NULL,
                        delivery_key TEXT NOT NULL,
                        event_id TEXT NOT NULL,
                        envelope_digest TEXT NOT NULL,
                        received_at TEXT NOT NULL,
                        PRIMARY KEY (trusted_tenant_id, delivery_key)
                    )
                """)
        except sqlite3.Error:
            raise ReceiptStoreUnavailable("receipt_store_unavailable") from None

    def _validated_digest(self, envelope: Mapping[str, object], *, delivery_header: object) -> str:
        """Strict common shape + SHA-256 validation, without any storage write."""
        if type(envelope) is not dict or set(envelope) != _FIELDS:
            raise InvalidReceipt("invalid_event_envelope")
        if envelope["tenant_id"] != self._tenant_id:
            raise UnauthorizedReceipt("tenant_not_allowed")
        if (type(envelope["event_type"]) is not str
                or envelope["event_type"] not in self._allowed):
            raise UnauthorizedReceipt("event_type_not_allowed")
        key = envelope["delivery_idempotency_key"]
        expected_reference_type, allowed_versions = _RECEIPT_CONTRACTS[
            envelope["event_type"]
        ]
        reference = envelope["authoritative_subject_reference"]
        version = envelope["authoritative_subject_version"]
        if (type(key) is not str or not _DELIVERY_KEY.fullmatch(key)
                or delivery_header != key
                or not _uuid(envelope["event_id"])
                or not _uuid(envelope["correlation_id"])
                or not _valid_utc(envelope["occurred_at"])
                or type(reference) is not dict
                or set(reference) != {"reference_type", "reference_id"}
                or reference["reference_type"] != expected_reference_type
                or not _uuid(reference["reference_id"])
                or type(version) is not int or version not in allowed_versions):
            raise InvalidReceipt("invalid_event_envelope")
        try:
            raw = json.dumps(envelope, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True, allow_nan=False).encode("utf-8")
        except (TypeError, ValueError, OverflowError):
            raise InvalidReceipt("invalid_event_envelope") from None
        if len(raw) > 4096:
            raise InvalidReceipt("event_envelope_too_large")
        return hashlib.sha256(raw).hexdigest()


    def committed(self, envelope: Mapping[str, object], *, delivery_header: object) -> bool:
        """Check that this EXACT authenticated-transport receipt already committed.

        This check is read-only, never reserves a missing receipt, and is not
        owner or tenant business authorization. It is paired with a separate
        server-owned acquisition lookup and shared Work Item identity guard.
        """
        digest = self._validated_digest(envelope, delivery_header=delivery_header)
        try:
            with sqlite3.connect(f"file:{self._path}?mode=ro", uri=True, timeout=5) as db:
                row = db.execute(
                    "SELECT envelope_digest FROM local_n8n_receipts "
                    "WHERE trusted_tenant_id=? AND delivery_key=?",
                    (self._tenant_id, envelope["delivery_idempotency_key"]),
                ).fetchone()
                return row is not None and row[0] == digest
        except sqlite3.Error:
            raise ReceiptStoreUnavailable("receipt_store_unavailable") from None

    def receive(self, envelope: Mapping[str, object],
                *, delivery_header: object) -> Receipt:
        digest = self._validated_digest(envelope, delivery_header=delivery_header)
        key = envelope["delivery_idempotency_key"]
        try:
            with sqlite3.connect(self._path, timeout=5, isolation_level=None) as db:
                db.execute("PRAGMA synchronous=FULL")
                db.execute("BEGIN IMMEDIATE")
                prior = db.execute(
                    "SELECT envelope_digest FROM local_n8n_receipts "
                    "WHERE trusted_tenant_id=? AND delivery_key=?",
                    (self._tenant_id, key),
                ).fetchone()
                if prior is not None:
                    if prior[0] != digest:
                        raise ConflictingReceipt("delivery_key_conflict")
                    db.commit()
                    return Receipt(status=202, duplicate=True)
                db.execute(
                    "INSERT INTO local_n8n_receipts "
                    "(trusted_tenant_id,delivery_key,event_id,envelope_digest,received_at) "
                    "VALUES (?,?,?,?,?)",
                    (self._tenant_id, key, envelope["event_id"], digest,
                     datetime.now(timezone.utc).isoformat()),
                )
                db.commit()
                return Receipt(status=202, duplicate=False)
        except ConflictingReceipt:
            raise
        except sqlite3.Error:
            raise ReceiptStoreUnavailable("receipt_store_unavailable") from None
