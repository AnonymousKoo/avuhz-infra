"""Private LOCAL/TEST n8n aggregate transport envelope (source-only).

This HMAC proves transport integrity ONLY; never treat it as owner, tenant,
Avuhz event or workflow execution authorization. It requires a separate
Avuhz-governed ingest endpoint with durable replay and tenant policy checks.
No outbound transport, key provisioning, listener or cron is implemented.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import time
from collections.abc import Callable, Mapping

from scripts.local_n8n_activity_snapshot import EXPECTED_SOURCE, KNOWN_EXECUTION_STATES

VERSION = "avuhz.local-n8n.aggregate.v1"
MAX_AGE_SECONDS = 300
_MAX_PAYLOAD_BYTES = 2500
_NONCE = re.compile(r"^[a-f0-9]{32}$")
_ENVELOPE_KEYS = frozenset({"version", "observed_at", "nonce", "evidence", "mac"})
_PAYLOAD_KEYS = frozenset({"schema_version", "source", "connection_to_command_center",
                           "read_only", "workflows", "executions", "system_001"})


def _integer(value: object, maximum: int = 1_000_000_000) -> bool:
    return type(value) is int and 0 <= value <= maximum


def _validate_evidence(evidence: object) -> bool:
    if type(evidence) is not dict or evidence.keys() != _PAYLOAD_KEYS:
        return False
    if (evidence.get("schema_version") != 1
        or evidence.get("source") != EXPECTED_SOURCE
        or evidence.get("read_only") is not True
        or evidence.get("connection_to_command_center") is not False):
        return False
    work = evidence.get("workflows")
    exc = evidence.get("executions")
    sys = evidence.get("system_001")
    if type(work) is not dict or work.keys() != {"stored", "active", "inactive"}:
        return False
    if not all(_integer(work[k]) for k in work):
        return False
    if work["stored"] != work["active"] + work["inactive"]:
        return False
    if type(exc) is not dict or exc.keys() != {"total", "statuses", "other"}:
        return False
    statuses = exc.get("statuses")
    if type(statuses) is not dict or statuses.keys() != set(KNOWN_EXECUTION_STATES):
        return False
    if not all(_integer(x) for x in statuses.values()):
        return False
    if not _integer(exc["other"]) or not _integer(exc["total"]):
        return False
    if exc["total"] != sum(statuses.values()) + exc["other"]:
        return False
    if type(sys) is not dict or sys.keys() != {
        "matching_candidate_workflows", "active_candidates", "runtime_certified"
    }:
        return False
    if not _integer(sys["matching_candidate_workflows"]) or not _integer(sys["active_candidates"]):
        return False
    if (sys["runtime_certified"] is not False
        or sys["active_candidates"] > sys["matching_candidate_workflows"]
        or sys["matching_candidate_workflows"] > work["stored"]
        or sys["active_candidates"] > work["active"]):
        return False
    return True


def _canonical(value: Mapping[str, object]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _message(version: str, observed_at: int, nonce: str, evidence: dict) -> bytes:
    return _canonical({"version": version, "observed_at": observed_at,
                       "nonce": nonce, "evidence": evidence})


def create_envelope(
    evidence: dict, key: bytes, *,
    now: int | None = None, nonce: str | None = None,
) -> dict:
    """Build a signed packet in memory; do not export/publish automatically."""
    if not _validate_evidence(evidence) or type(key) is not bytes or len(key) < 32:
        raise ValueError("invalid_aggregate_or_transport_key")
    stamp = int(time.time()) if now is None else now
    n = secrets.token_hex(16) if nonce is None else nonce
    if not _integer(stamp, 10_000_000_000) or type(n) is not str or not _NONCE.fullmatch(n):
        raise ValueError("invalid_timestamp_or_nonce")
    message = _message(VERSION, stamp, n, evidence)
    if len(message) > _MAX_PAYLOAD_BYTES:
        raise ValueError("oversized_aggregate")
    mac = hmac.new(key, message, hashlib.sha256).hexdigest()
    return {"version": VERSION, "observed_at": stamp,
            "nonce": n, "evidence": evidence, "mac": mac}


def verify_envelope(
    packet: object, key: bytes, *,
    now: int | None = None, replay_seen: Callable[[str], bool] | None = None,
) -> bool:
    """Integrity/freshness precheck, NOT the durable replay reservation.

    The authoritative receiving service MUST reserve each accepted nonce
    atomically in its own bounded replay store before acknowledging receipt,
    and MUST independently authenticate the source/tenant. A replay_seen
    callback only rejects already-used nonces; it is not an atomic claim.
    """
    if (type(packet) is not dict or packet.keys() != _ENVELOPE_KEYS
        or type(key) is not bytes or len(key) < 32
        or replay_seen is None):
        return False
    try:
        version, stamp, nonce, data, mac = (packet[k] for k in (
            "version", "observed_at", "nonce", "evidence", "mac"))
        if (version != VERSION or not _integer(stamp, 10_000_000_000)
            or type(nonce) is not str or not _NONCE.fullmatch(nonce)
            or type(mac) is not str or re.fullmatch(r"[a-f0-9]{64}", mac) is None
            or not _validate_evidence(data)):
            return False
        current = int(time.time()) if now is None else now
        if type(current) is not int or abs(current - stamp) > MAX_AGE_SECONDS:
            return False
        payload = _message(version, stamp, nonce, data)
        if len(payload) > _MAX_PAYLOAD_BYTES:
            return False
        correct = hmac.new(key, payload, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(mac, correct):
            return False
        return not replay_seen(nonce)
    except (TypeError, ValueError, KeyError):
        return False
