"""Test-owned in-process capabilities for fictional contract comparison only.

Provisioning is a trusted test-harness operation. Give requesters only compare
and the two selected handles, never provisioning access. Python reflection and
object.__setattr__ are outside this model; this is not an authentication sandbox.
"""
from dataclasses import dataclass, field, fields, replace
from datetime import datetime

from avuhz_runtime.local_infrastructure_authority import (
    LocalContractResult, LocalInfrastructureDenied, ReplayEntry, ResourceScope,
    TrustedBinding, TrustedObservation, TrustedReplaySnapshot,
    _clock, _digest, _fresh, _id, _scope, _version,
    validate_local_resource_contract,
)


@dataclass(frozen=True, slots=True)
class IdentityGrant:
    scope: ResourceScope
    role: str
    status: str
    issued_at: datetime
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class ResourceOwnership:
    scope: ResourceScope


@dataclass(frozen=True, slots=True)
class ApprovedManifest:
    """Entry in the test-owned approval registry, not an approval flag."""
    manifest_id: str
    scope: ResourceScope
    manifest_digest: str
    manifest_version: int
    desired_digest: str
    desired_version: int
    expected_current_digest: str
    expected_current_version: int


@dataclass(frozen=True, slots=True)
class SimulatedObservation:
    """Collected separately from the manifest's expected-current fields."""
    observation_id: str
    scope: ResourceScope
    observer_id: str
    current_digest: str
    current_version: int
    observed_at: datetime
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class ComparisonSlot:
    principal_id: str
    manifest_id: str
    observation_id: str
    request_id: str
    challenge: str
    issued_at: datetime
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class TestClock:
    now: datetime
    issued_at: datetime
    expires_at: datetime


def _deny(code):
    raise LocalInfrastructureDenied(code)


def _record(record, kind):
    # Exact types before any equality/hash or datetime operation. No nested
    # mutable structures or caller-defined primitive subclasses are accepted.
    if type(record) is not kind:
        _deny('INVALID_TRUST_RECORD')
    for f in fields(kind):
        value = getattr(record, f.name)
        if f.name == 'scope':
            valid = _scope(value)
        elif f.name in ('now', 'issued_at', 'expires_at', 'observed_at'):
            valid = _clock(value) and value.microsecond == 0
        elif f.name.endswith('_digest') or f.name == 'operation_digest':
            valid = _digest(value)
        elif f.name.endswith('_version'):
            valid = _version(value)
        elif f.name == 'role':
            valid = type(value) is str and value in ('PRINCIPAL', 'OBSERVER')
        elif f.name == 'status':
            valid = type(value) is str and value in ('ACTIVE', 'REVOKED')
        else:
            valid = _id(value)
        if not valid:
            _deny('INVALID_TRUST_RECORD')


def _registry(records, kind, key):
    if type(records) is not tuple or len(records) > 256:
        _deny('INVALID_TRUST_REGISTRY')
    seen = set()
    for record in records:
        _record(record, kind)
        identity = key(record)
        if identity in seen:
            _deny('DUPLICATE_TRUST_RECORD')
        seen.add(identity)


def _one(records, key, value):
    for record in records:
        if key(record) == value:
            return record
    _deny('MISSING_TRUST_RECORD')


def _resolve(registry, handle):
    if type(handle) is not object:
        _deny('INVALID_TRUST_HANDLE')
    for registered, record in registry:
        if registered is handle:
            return record
    _deny('INVALID_TRUST_HANDLE')


@dataclass(frozen=True, slots=True, init=False, eq=False, repr=False)
class LocalTrustAdapter:
    """Immutable test composition. Constructor belongs exclusively to the harness.

    Handles are minted internally and kept alive; lookup uses `is`, never IDs
    serialized as strings, equality, or hashing. Each instance has new handles.
    Registry accessors are for trusted harness provisioning only.
    """
    _principals: tuple = field(repr=False)
    _slots: tuple = field(repr=False)
    _grants: tuple = field(repr=False)
    _ownership: tuple = field(repr=False)
    _manifests: tuple = field(repr=False)
    _observations: tuple = field(repr=False)
    _clock_source: TestClock = field(repr=False)
    _replay: TrustedReplaySnapshot = field(repr=False)

    def __init__(self, *, grants, ownership, manifests, observations, slots,
                 clock, replay):
        if hasattr(self, '_principals'):
            _deny('TRUST_ALREADY_INITIALIZED')
        _registry(grants, IdentityGrant, lambda r: r.scope.identity_id)
        _registry(ownership, ResourceOwnership, lambda r: (
            r.scope.tenant_id, r.scope.environment, r.scope.namespace,
            r.scope.resource_class, r.scope.resource_id))
        _registry(manifests, ApprovedManifest, lambda r: r.manifest_id)
        _registry(observations, SimulatedObservation, lambda r: r.observation_id)
        _registry(slots, ComparisonSlot, lambda r: r.request_id)
        if len({s.challenge for s in slots}) != len(slots):
            _deny('DUPLICATE_TRUST_RECORD')
        _record(clock, TestClock)
        if type(replay) is not TrustedReplaySnapshot:
            _deny('INVALID_REPLAY_SNAPSHOT')
        _registry(replay.entries, ReplayEntry, lambda r: r.request_id)
        if len({r.challenge for r in replay.entries}) != len(replay.entries):
            _deny('DUPLICATE_TRUST_RECORD')
        for name, value in (
            ('_grants', grants), ('_ownership', ownership),
            ('_manifests', manifests), ('_observations', observations),
            ('_clock_source', clock), ('_replay', replay),
            ('_principals', tuple((object(), g) for g in grants)),
            ('_slots', tuple((object(), s) for s in slots)),
        ):
            object.__setattr__(self, name, value)

    @property
    def identity_handles(self):
        """Harness-only provisioning, in the independently registered order."""
        return tuple(handle for handle, _ in self._principals)

    @property
    def comparison_handles(self):
        """Harness-only provisioning, in the independently registered order."""
        return tuple(handle for handle, _ in self._slots)

    def compare(self, request, *, principal_handle, comparison_handle) -> LocalContractResult:
        principal = _resolve(self._principals, principal_handle)
        slot = _resolve(self._slots, comparison_handle)
        clock = self._clock_source
        now = clock.now
        if not _fresh(clock.issued_at, clock.expires_at, now):
            _deny('TRUST_CLOCK_TIME_INVALID')
        if principal.role != 'PRINCIPAL' or principal.scope.identity_id != slot.principal_id:
            _deny('PRINCIPAL_MISMATCH')
        manifest = _one(self._manifests, lambda r: r.manifest_id, slot.manifest_id)
        observation = _one(self._observations, lambda r: r.observation_id, slot.observation_id)
        scope = principal.scope
        if manifest.scope != scope or observation.scope != scope:
            _deny('TRUST_SCOPE_MISMATCH')
        _one(self._ownership, lambda r: r.scope, scope)
        observer = _one(self._grants, lambda r: r.scope.identity_id, observation.observer_id)
        if (observer.role != 'OBSERVER' or observer.scope.identity_id == scope.identity_id
                or observer.scope != replace(scope, identity_id=observation.observer_id)):
            _deny('OBSERVER_MISMATCH')
        for grant in (principal, observer):
            if grant.status != 'ACTIVE':
                _deny('IDENTITY_REVOKED')
            if not _fresh(grant.issued_at, grant.expires_at, now):
                _deny('GRANT_TIME_INVALID')
        # Scope identity remains the principal for compatibility with PR760.
        # Observer identity is exclusively internal source metadata above.
        binding = TrustedBinding(
            scope, manifest.manifest_digest, manifest.manifest_version,
            manifest.desired_digest, manifest.desired_version,
            manifest.expected_current_digest, manifest.expected_current_version,
            slot.request_id, slot.challenge, observation.observation_id,
            slot.issued_at, slot.expires_at,
        )
        observed = TrustedObservation(
            scope, observation.observation_id, observation.current_digest,
            observation.current_version, observation.observed_at, observation.expires_at,
        )
        return validate_local_resource_contract(
            request, trusted_binding=binding, trusted_observation=observed,
            trusted_replay_snapshot=self._replay, now=now,
        )
