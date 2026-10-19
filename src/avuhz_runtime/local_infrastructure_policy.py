"""R2 fictional policy/approval diagnostics, exclusively provisioned by tests.

No runtime registration, authentication, execution or durable consumption. The
constructor and handle accessors belong to a trusted harness, never a requester.
Reflection, monkeypatching and object.__setattr__ are outside this Python model.
"""
from dataclasses import asdict, dataclass, field, fields, replace
from datetime import datetime
import hashlib
import json

from avuhz_runtime.local_infrastructure_authority import (
    ResourceScope, _clock, _digest, _fresh, _id, _scope, _version,
)
from avuhz_runtime.local_infrastructure_trust import (
    ApprovedManifest, ComparisonSlot, IdentityGrant, LocalTrustAdapter,
    SimulatedObservation, _deny, _one, _record, _resolve,
)

EXECUTOR = 'fictional.executor01'
OPERATION = 'COMPARE_FICTIONAL_STATE'


def _hash(domain, value):
    def encode(item):
        if type(item) is datetime:
            return item.isoformat().replace('+00:00', 'Z')
        raise TypeError('INVALID_CANONICAL_VALUE')
    wire = json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, default=encode)
    return 'sha256:' + hashlib.sha256(domain + wire.encode('ascii')).hexdigest()


def source_observation_digest(observation, observer):
    """Harness utility: SOURCE provenance, distinct from the operation digest.

    Includes observation identity, scope, state, both timestamps, and the
    independently registered observer's identity, role, status and grant window.
    Hashing is deterministic binding, not cryptographic attestation.
    """
    _record(observation, SimulatedObservation)
    _record(observer, IdentityGrant)
    return _hash(b'avuhz.local-infrastructure-policy.SOURCE.v1\n',
                 {'observation': asdict(observation), 'observer': asdict(observer)})


@dataclass(frozen=True, slots=True)
class EvidencePins:
    manifest: ApprovedManifest
    observation: SimulatedObservation
    slot: ComparisonSlot
    source_digest: str
    operation_digest: str
    operation: str = OPERATION


@dataclass(frozen=True, slots=True)
class PolicyRule:
    policy_id: str
    policy_version: int
    pins: EvidencePins
    decision: str  # Closed ALLOW / DENY; never execution authority.


@dataclass(frozen=True, slots=True)
class HumanGrant:
    scope: ResourceScope
    role: str
    capability: str
    status: str
    issued_at: datetime
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class ExplicitApproval:
    approval_id: str
    approval_version: int
    human_id: str
    pins: EvidencePins
    policy_id: str
    policy_version: int
    policy_decision_digest: str
    decision: str
    executor_id: str
    issued_at: datetime
    expires_at: datetime
    max_attempts: int
    max_recoveries: int


@dataclass(frozen=True, slots=True)
class ConsumptionEntry:
    approval_id: str
    approval_version: int
    request_id: str
    challenge: str
    operation_digest: str
    status: str


@dataclass(frozen=True, slots=True)
class ConsumptionSnapshot:
    entries: tuple[ConsumptionEntry, ...]


@dataclass(frozen=True, slots=True)
class PolicyDiagnostic:
    reason_code: str
    operation_digest: str
    source_digest: str
    policy_decision_digest: str
    authority_effect: str = field(default='NONE', init=False)


def policy_decision_digest(rule):
    """Harness utility for independently prepared approval evidence."""
    _validate(rule, PolicyRule)
    return _hash(b'avuhz.local-infrastructure-policy.DECISION.v1\n', asdict(rule))


def _validate(value, kind):
    if type(value) is not kind:
        _deny('INVALID_POLICY_RECORD')
    nested = {'pins': EvidencePins, 'manifest': ApprovedManifest,
              'observation': SimulatedObservation, 'slot': ComparisonSlot}
    choices = {'role': ('HUMAN',), 'capability': ('REVIEW_FICTIONAL_POLICY',),
               'status': ('ACTIVE', 'REVOKED', 'CONSUMED'),
               'decision': ('ALLOW', 'DENY') if kind is PolicyRule else ('APPROVE', 'DENY'),
               'operation': (OPERATION,), 'executor_id': (EXECUTOR,)}
    for f in fields(kind):
        item = getattr(value, f.name)
        if f.name in nested:
            child = nested[f.name]
            if child in (ApprovedManifest, SimulatedObservation, ComparisonSlot):
                _record(item, child)
            else:
                _validate(item, child)
            continue
        if f.name == 'scope':
            valid = _scope(item)
        elif f.name in ('issued_at', 'expires_at'):
            valid = _clock(item) and item.microsecond == 0
        elif f.name.endswith('_digest'):
            valid = _digest(item)
        elif f.name.endswith('_version'):
            valid = _version(item)
        elif f.name in ('max_attempts', 'max_recoveries'):
            valid = type(item) is int and item == (1 if f.name == 'max_attempts' else 0)
        elif f.name in choices:
            valid = type(item) is str and item in choices[f.name]
        else:
            valid = _id(item)
        if not valid:
            _deny('INVALID_POLICY_RECORD')
    if kind is HumanGrant and value.status not in ('ACTIVE', 'REVOKED'):
        _deny('INVALID_POLICY_RECORD')
    if kind is ConsumptionEntry and value.status not in ('CONSUMED', 'REVOKED'):
        _deny('INVALID_POLICY_RECORD')


def _registry(records, kind, keys):
    if type(records) is not tuple or len(records) > 256:
        _deny('INVALID_POLICY_REGISTRY')
    for record in records:
        _validate(record, kind)
    for key in keys:
        values = tuple(key(r) for r in records)
        if len(set(values)) != len(values):
            _deny('DUPLICATE_POLICY_RECORD')


@dataclass(frozen=True, slots=True, init=False, eq=False, repr=False)
class LocalTestInfrastructurePolicyAdapter:
    """Test-only composition retaining original, independently supplied sources.

    Callers receive selected handles and the two review methods only. No method
    accepts a comparison, callback, clock, policy, approval or source injection.
    Repeated reviews with an unchanged empty snapshot remain possible.
    """
    _trust: LocalTrustAdapter = field(repr=False)
    _grants: tuple = field(repr=False)
    _manifests: tuple = field(repr=False)
    _observations: tuple = field(repr=False)
    _slots: tuple = field(repr=False)
    _policies: tuple = field(repr=False)
    _humans: tuple = field(repr=False)
    _approvals: tuple = field(repr=False)
    _consumption: ConsumptionSnapshot = field(repr=False)
    _clock: object = field(repr=False)

    def __init__(self, *, grants, ownership, manifests, observations, slots,
                 clock, replay, policies, humans, approvals, consumption):
        if hasattr(self, '_trust'):
            _deny('POLICY_ALREADY_INITIALIZED')
        trust = LocalTrustAdapter(grants=grants, ownership=ownership,
                                 manifests=manifests, observations=observations,
                                 slots=slots, clock=clock, replay=replay)
        # Validate all source relationships at construction, not just the slot
        # eventually selected by a caller. Existing PR761 records stay intact.
        for manifest in manifests:
            principal = _one(grants, lambda r: r.scope.identity_id, manifest.scope.identity_id)
            if principal.role != 'PRINCIPAL' or principal.scope != manifest.scope:
                _deny('SOURCE_SCOPE_MISMATCH')
            _one(ownership, lambda r: r.scope, manifest.scope)
        for observation in observations:
            principal = _one(grants, lambda r: r.scope.identity_id, observation.scope.identity_id)
            observer = _one(grants, lambda r: r.scope.identity_id, observation.observer_id)
            if (principal.role != 'PRINCIPAL' or principal.scope != observation.scope
                    or observer.role != 'OBSERVER'
                    or observer.scope != replace(observation.scope, identity_id=observation.observer_id)
                    or observer.scope.identity_id == principal.scope.identity_id):
                _deny('SOURCE_SCOPE_MISMATCH')
            _one(ownership, lambda r: r.scope, observation.scope)
        for slot in slots:
            manifest = _one(manifests, lambda r: r.manifest_id, slot.manifest_id)
            observation = _one(observations, lambda r: r.observation_id, slot.observation_id)
            if manifest.scope != observation.scope or slot.principal_id != manifest.scope.identity_id:
                _deny('SOURCE_SCOPE_MISMATCH')
        for owner in ownership:
            principal = _one(grants, lambda r: r.scope.identity_id, owner.scope.identity_id)
            if principal.role != 'PRINCIPAL' or principal.scope != owner.scope:
                _deny('SOURCE_SCOPE_MISMATCH')
        _registry(policies, PolicyRule, (lambda r: r.policy_id, lambda r: r.pins.slot.request_id,
                                       lambda r: r.pins.slot.challenge))
        _registry(humans, HumanGrant, (lambda r: r.scope.identity_id,))
        _registry(approvals, ExplicitApproval, (lambda r: r.approval_id,
                  lambda r: r.pins.slot.request_id, lambda r: r.pins.slot.challenge))
        if type(consumption) is not ConsumptionSnapshot:
            _deny('INVALID_CONSUMPTION_SNAPSHOT')
        _registry(consumption.entries, ConsumptionEntry, (lambda r: r.approval_id,
                  lambda r: r.request_id, lambda r: r.challenge))
        for approval in approvals:
            _one(humans, lambda r: r.scope.identity_id, approval.human_id)
        for name, value in (
            ('_trust', trust), ('_grants', grants), ('_manifests', manifests),
            ('_observations', observations), ('_slots', slots), ('_clock', clock),
            ('_policies', policies), ('_consumption', consumption),
            ('_humans', tuple((object(), h) for h in humans)),
            ('_approvals', tuple((object(), a) for a in approvals)),
        ):
            object.__setattr__(self, name, value)

    @property
    def principal_handles(self):
        return self._trust.identity_handles

    @property
    def comparison_handles(self):
        return self._trust.comparison_handles

    @property
    def approver_handles(self):
        return tuple(h for h, _ in self._humans)

    @property
    def approval_handles(self):
        return tuple(h for h, _ in self._approvals)

    def _evaluate(self, request, principal_handle, comparison_handle):
        compared = self._trust.compare(request, principal_handle=principal_handle,
                                       comparison_handle=comparison_handle)
        if compared.outcome != 'CONTRACT_MATCH' or compared.authority_effect != 'NONE':
            _deny('INVALID_COMPARISON_OUTCOME')
        slot = next(s for h, s in zip(self.comparison_handles, self._slots)
                    if h is comparison_handle)
        manifest = _one(self._manifests, lambda r: r.manifest_id, slot.manifest_id)
        observation = _one(self._observations, lambda r: r.observation_id, slot.observation_id)
        observer = _one(self._grants, lambda r: r.scope.identity_id, observation.observer_id)
        source = source_observation_digest(observation, observer)
        pins = EvidencePins(manifest, observation, slot, source, compared.operation_digest)
        rule = next((r for r in self._policies if r.pins.slot.request_id == slot.request_id), None)
        decision_digest = '' if rule is None else policy_decision_digest(rule)
        if rule is None:
            reason = 'POLICY_MISSING'
        elif rule.policy_version != 1:
            reason = 'POLICY_VERSION_UNKNOWN'
        elif rule.pins != pins:
            reason = 'POLICY_PIN_MISMATCH'
        elif rule.decision != 'ALLOW':
            reason = 'POLICY_DENIED'
        else:
            reason = 'POLICY_ALLOW_DIAGNOSTIC'
        return PolicyDiagnostic(reason, compared.operation_digest, source, decision_digest), pins, rule

    def evaluate_policy(self, request, *, principal_handle, comparison_handle):
        return self._evaluate(request, principal_handle, comparison_handle)[0]

    def review_approval(self, request, *, principal_handle, comparison_handle,
                        approver_handle, approval_handle):
        result, pins, rule = self._evaluate(request, principal_handle, comparison_handle)
        if result.reason_code != 'POLICY_ALLOW_DIAGNOSTIC':
            return result
        human = _resolve(self._humans, approver_handle)
        approval = _resolve(self._approvals, approval_handle)
        scope = pins.manifest.scope
        now = self._clock.now
        if (human.scope != replace(scope, identity_id=approval.human_id)
                or human.scope.identity_id in (scope.identity_id, pins.observation.observer_id, EXECUTOR)):
            reason = 'HUMAN_SCOPE_OR_SEPARATION_DENIED'
        elif human.status != 'ACTIVE' or not _fresh(human.issued_at, human.expires_at, now):
            reason = 'HUMAN_GRANT_INACTIVE'
        elif (approval.pins != pins or approval.policy_id != rule.policy_id
              or approval.policy_version != 1
              or approval.policy_decision_digest != result.policy_decision_digest):
            reason = 'APPROVAL_BINDING_MISMATCH'
        elif not _fresh(approval.issued_at, approval.expires_at, now):
            reason = 'APPROVAL_TIME_INVALID'
        elif any(e.approval_id == approval.approval_id or e.request_id == pins.slot.request_id
                 or e.challenge == pins.slot.challenge or e.operation_digest == result.operation_digest
                 for e in self._consumption.entries):
            reason = 'APPROVAL_UNAVAILABLE'
        elif approval.decision != 'APPROVE':
            reason = 'HUMAN_DENIED'
        else:
            reason = 'APPROVAL_MATCH_DIAGNOSTIC'
        return replace(result, reason_code=reason)
