"""R2 source-only fictional LOCAL/TEST contract validation; no execution authority.

The caller MUST supply binding, observation, replay snapshot and UTC clock from
separate higher-trust boundaries, independently of the request. Their provenance,
identity and approval are NOT verified here. Constructing these dataclasses is
not attestation. Never deserialize request content into trusted inputs. No
cryptographic authentication, durable replay prevention or exactly-once effects
are provided. JSON ingestion must reject duplicate keys before producing a dict;
this API rejects non-dicts and cannot recover keys discarded by a JSON parser.
"""
from dataclasses import dataclass, fields
from datetime import datetime, timezone
import hashlib
import json
import re

_ID = re.compile(r"[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*\Z", re.ASCII)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z", re.ASCII)
_TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z", re.ASCII)
_MAX_AGE_SECONDS = 300
_MAX_VERSION = 2147483647


class LocalInfrastructureDenied(ValueError):
    """Only fixed diagnostic codes are raised; never echo supplied values."""


@dataclass(frozen=True, slots=True)
class ResourceScope:
    identity_id: str
    tenant_id: str
    environment: str
    namespace: str
    resource_class: str
    resource_id: str
    owner_id: str


@dataclass(frozen=True, slots=True)
class TrustedBinding:
    """Independently approved immutable manifest binding supplied by the caller."""

    scope: ResourceScope
    manifest_digest: str
    manifest_version: int
    desired_digest: str
    desired_version: int
    expected_current_digest: str
    expected_current_version: int
    request_id: str
    challenge: str
    observation_id: str
    issued_at: datetime
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class TrustedObservation:
    """Independent observation, not client evidence or a verified flag."""

    scope: ResourceScope
    observation_id: str
    current_digest: str
    current_version: int
    observed_at: datetime
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class ReplayEntry:
    request_id: str
    challenge: str
    operation_digest: str


@dataclass(frozen=True, slots=True)
class TrustedReplaySnapshot:
    """Immutable global snapshot; its completeness/freshness is caller-owned."""

    entries: tuple[ReplayEntry, ...]


@dataclass(frozen=True, slots=True)
class LocalContractResult:
    operation_digest: str
    outcome: str = "CONTRACT_MATCH"
    authority_effect: str = "NONE"


def _deny(code: str) -> None:
    raise LocalInfrastructureDenied(code)


def _id(value: object) -> bool:
    return type(value) is str and 3 <= len(value) <= 64 and bool(_ID.fullmatch(value))


def _digest(value: object) -> bool:
    return type(value) is str and bool(_DIGEST.fullmatch(value))


def _version(value: object) -> bool:
    return type(value) is int and 1 <= value <= _MAX_VERSION


def _clock(value: object) -> bool:
    return type(value) is datetime and value.tzinfo is timezone.utc and value.fold == 0


def _scope(value: object) -> bool:
    return (
        type(value) is ResourceScope
        and all(_id(getattr(value, key)) for key in ("identity_id", "tenant_id", "owner_id"))
        and type(value.environment) is str and value.environment in ("LOCAL", "TEST")
        and type(value.namespace) is str and value.namespace == "fictional.lab"
        and type(value.resource_class) is str and value.resource_class == "COMPONENT"
        and type(value.resource_id) is str and value.resource_id == "fictional.component01"
    )


def _fresh(start: datetime, end: datetime, now: datetime) -> bool:
    return start <= now < end and 0 < (end - start).total_seconds() <= _MAX_AGE_SECONDS


def validate_local_resource_contract(
    request: object, *, trusted_binding: TrustedBinding,
    trusted_observation: TrustedObservation,
    trusted_replay_snapshot: TrustedReplaySnapshot, now: datetime,
) -> LocalContractResult:
    """Compare a closed primitive dict against independent injected facts.

    A match is only a local contract result, never approval, dispatch permission
    or verification. Every ID/challenge already in the snapshot is denied,
    including identical retries. Nothing is persisted or consumed by this call.
    The caller owns a trustworthy clock and atomic replay handling elsewhere.
    """
    b, o, snapshot = trusted_binding, trusted_observation, trusted_replay_snapshot
    if not _clock(now):
        _deny("INVALID_CLOCK")
    if (
        type(b) is not TrustedBinding or not _scope(b.scope)
        or not all(_digest(getattr(b, k)) for k in
                   ("manifest_digest", "desired_digest", "expected_current_digest"))
        or not all(_version(getattr(b, k)) for k in
                   ("manifest_version", "desired_version", "expected_current_version"))
        or not all(_id(getattr(b, k)) for k in ("request_id", "challenge", "observation_id"))
        or not _clock(b.issued_at) or not _clock(b.expires_at)
        or b.issued_at.microsecond != 0 or b.expires_at.microsecond != 0
    ):
        _deny("INVALID_BINDING")
    if not _fresh(b.issued_at, b.expires_at, now):
        _deny("BINDING_TIME_INVALID")
    if (
        type(o) is not TrustedObservation or not _scope(o.scope)
        or not _id(o.observation_id) or not _digest(o.current_digest)
        or not _version(o.current_version)
        or not _clock(o.observed_at) or not _clock(o.expires_at)
    ):
        _deny("INVALID_OBSERVATION")
    if o.scope != b.scope or o.observation_id != b.observation_id:
        _deny("OBSERVATION_MISMATCH")
    if not _fresh(o.observed_at, o.expires_at, now):
        _deny("OBSERVATION_TIME_INVALID")
    if o.current_digest != b.expected_current_digest or o.current_version != b.expected_current_version:
        _deny("PRECONDITION_MISMATCH")
    if type(snapshot) is not TrustedReplaySnapshot or type(snapshot.entries) is not tuple or len(snapshot.entries) > 10000:
        _deny("INVALID_REPLAY_SNAPSHOT")
    ids, challenges = set(), set()
    for entry in snapshot.entries:
        if (type(entry) is not ReplayEntry or not _id(entry.request_id)
                or not _id(entry.challenge) or not _digest(entry.operation_digest)):
            _deny("INVALID_REPLAY_SNAPSHOT")
        if entry.request_id in ids or entry.challenge in challenges:
            _deny("INVALID_REPLAY_SNAPSHOT")
        ids.add(entry.request_id)
        challenges.add(entry.challenge)

    # Only built-in primitives reach equality/serialization. Copy first to avoid
    # retaining any alias to the mutable request. Concurrent caller mutation is
    # not supported; no caller objects are retained in the result.
    if type(request) is not dict:
        _deny("INVALID_REQUEST")
    r = request.copy()
    if any(type(k) is not str or type(v) not in (str, int) for k, v in r.items()):
        _deny("INVALID_REQUEST")
    expected = {f.name: getattr(b.scope, f.name) for f in fields(ResourceScope)}
    expected.update({f.name: getattr(b, f.name) for f in fields(TrustedBinding)
                     if f.name not in ("scope", "issued_at", "expires_at")})
    expected.update(schema_version=1, operation="COMPARE_FICTIONAL_STATE",
                    issued_at=b.issued_at.isoformat().replace("+00:00", "Z"),
                    expires_at=b.expires_at.isoformat().replace("+00:00", "Z"))
    if r.keys() != expected.keys():
        _deny("INVALID_REQUEST")
    for key, value in r.items():
        if type(value) is not type(expected[key]):
            _deny("INVALID_REQUEST")
        if key in ("issued_at", "expires_at") and not _TIME.fullmatch(value):
            _deny("INVALID_REQUEST")
        if value != expected[key]:
            _deny("REQUEST_BINDING_MISMATCH")
    if r["request_id"] in ids or r["challenge"] in challenges:
        _deny("REPLAY_DETECTED")
    canonical = json.dumps(r, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    digest = "sha256:" + hashlib.sha256(
        b"avuhz.local-infrastructure-authority.v1\n" + canonical.encode("ascii")
    ).hexdigest()
    return LocalContractResult(operation_digest=digest)
