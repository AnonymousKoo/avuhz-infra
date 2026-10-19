"""R2 TEST-harness SQLite simulation; no runtime or provider authority.

Provisioning and filesystem access are trusted. Requesters receive execute plus
selected identity handles only. Python reflection and hostile database writers
are outside this model. The fixture clock is not wall-clock attestation.
"""
from contextlib import closing
from dataclasses import asdict, dataclass, field, fields, replace
from pathlib import Path
import json
import sqlite3

from avuhz_runtime.local_infrastructure_authority import (
    ResourceScope, _digest, _fresh, _id, _scope, _version,
)
from avuhz_runtime.local_infrastructure_policy import (
    EXECUTOR, ExplicitApproval, LocalTestInfrastructurePolicyAdapter, _hash, _validate,
)
from avuhz_runtime.local_infrastructure_trust import _deny, _resolve


@dataclass(frozen=True, slots=True)
class ExecutionApproval:
    """Separately provisioned affirmative state-change authority, never inferred."""
    execution_id: str
    execution_version: int
    diagnostic: ExplicitApproval
    operation: str
    status: str
    # Diagnostic supplies exact scope, desired/prestate, source, policy, human,
    # approval ID/version, request/challenge, executor, window and attempt limits.


@dataclass(frozen=True, slots=True)
class SimulatedState:
    scope: ResourceScope
    digest: str
    version: int


@dataclass(frozen=True, slots=True)
class TestFailures:
    reservation_refusal: bool = False
    crash_after_reservation: bool = False
    change_before_effect: bool = False
    effect_write_failure: bool = False
    lost_ack: bool = False
    outcome_write_failure: bool = False


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    reason_code: str
    authority_effect: str = field(default='NONE', init=False)


def _scope_key(scope):
    return json.dumps(asdict(scope), sort_keys=True, separators=(',', ':'))


def _approval_digest(approval):
    return _hash(b'avuhz.local-infrastructure-execution.APPLY.v1\n',
                 asdict(replace(approval, status='ACTIVE')))


@dataclass(frozen=True, slots=True, init=False, eq=False, repr=False)
class LocalTestInfrastructureExecution:
    """One exact approval per immutable harness instance; shared durable ledger.

    Construct independently from requests. Reopening never resets state, consumes
    another attempt, clears revocation or overwrites a registration. New instances
    mint new handles. SQLite serialization coordinates processes as well as threads.
    """
    _path: str
    _policy: object
    _approval: ExecutionApproval
    _handles: tuple
    _principal: object
    _comparison: object
    _human: object
    _diagnostic: object
    _failures: TestFailures

    def __init__(self, *, database_path, policy_sources, execution_approval,
                 initial_state, failures=TestFailures()):
        if hasattr(self, '_path'):
            _deny('ALREADY_INITIALIZED')
        a = execution_approval
        if type(a) is not ExecutionApproval:
            _deny('INVALID_EXECUTION_APPROVAL')
        _validate(a.diagnostic, ExplicitApproval)
        if (not _id(a.execution_id) or not _version(a.execution_version)
                or type(a.operation) is not str or a.operation != 'APPLY_FICTIONAL_STATE'
                or type(a.status) is not str or a.status not in ('ACTIVE', 'REVOKED')
                or a.diagnostic.decision != 'APPROVE' or a.diagnostic.executor_id != EXECUTOR):
            _deny('INVALID_EXECUTION_APPROVAL')
        if (type(initial_state) is not SimulatedState or not _scope(initial_state.scope)
                or not _digest(initial_state.digest) or not _version(initial_state.version)
                or initial_state.scope != a.diagnostic.pins.manifest.scope):
            _deny('INVALID_INITIAL_STATE')
        if type(failures) is not TestFailures or any(
                type(getattr(failures, f.name)) is not bool for f in fields(TestFailures)):
            _deny('INVALID_FAILURE_FIXTURE')
        # Explicit TEST file, never supplied to execute. No URI or memory fallback.
        if type(database_path) is not str or not database_path.startswith('/tmp/'):
            _deny('INVALID_TEST_DATABASE_PATH')
        path = Path(database_path)
        if path.is_symlink() or not path.resolve().is_relative_to(Path('/tmp')):
            _deny('INVALID_TEST_DATABASE_PATH')
        if type(policy_sources) is not dict:
            _deny('INVALID_POLICY_SOURCES')
        policy = LocalTestInfrastructurePolicyAdapter(**policy_sources)
        d = a.diagnostic
        matches = [(h, r) for h, r in policy._approvals if r == d]
        if len(matches) != 1:
            _deny('DIAGNOSTIC_REGISTRATION_MISMATCH')
        principal = next((h for h, r in policy._trust._principals
                          if r.scope == d.pins.manifest.scope), None)
        comparison = next((h for h, r in policy._trust._slots if r == d.pins.slot), None)
        human = next((h for h, r in policy._humans if r.scope.identity_id == d.human_id), None)
        if principal is None or comparison is None or human is None:
            _deny('MISSING_EXECUTION_SOURCE')
        for key, value in dict(_path=str(path.resolve()), _policy=policy, _approval=a,
                               _handles=((object(), a),), _principal=principal,
                               _comparison=comparison, _human=human,
                               _diagnostic=matches[0][0], _failures=failures).items():
            object.__setattr__(self, key, value)
        try:
            self._provision(initial_state)
        except sqlite3.Error:
            _deny('REGISTRY_UNAVAILABLE')

    @property
    def execution_handle(self):
        """Harness-only distribution; not a public registration endpoint."""
        return self._handles[0][0]

    @property
    def principal_handle(self):
        return self._principal

    def _connect(self):
        db = sqlite3.connect(self._path, timeout=5, isolation_level=None)
        db.execute('PRAGMA synchronous=FULL')
        return db

    def _provision(self, state):
        a, d = self._approval, self._approval.diagnostic
        with closing(self._connect()) as db, db:
            db.execute('BEGIN IMMEDIATE')
            new = db.execute("SELECT 1 FROM sqlite_master WHERE name='execution_registry'").fetchone() is None
            db.execute('''CREATE TABLE IF NOT EXISTS execution_registry (
                execution_id TEXT PRIMARY KEY, execution_version INTEGER NOT NULL,
                approval_id TEXT UNIQUE NOT NULL, approval_version INTEGER NOT NULL,
                request_id TEXT UNIQUE NOT NULL, challenge TEXT UNIQUE NOT NULL,
                scope TEXT NOT NULL, digest TEXT UNIQUE NOT NULL,
                revoked INTEGER NOT NULL, consumed INTEGER NOT NULL DEFAULT 0)''')
            db.execute('''CREATE TABLE IF NOT EXISTS simulated_resource_state (
                scope TEXT PRIMARY KEY, digest TEXT NOT NULL, version INTEGER NOT NULL)''')
            db.execute('''CREATE TABLE IF NOT EXISTS local_attempts (
                execution_id TEXT PRIMARY KEY, execution_version INTEGER NOT NULL,
                approval_id TEXT UNIQUE NOT NULL, approval_version INTEGER NOT NULL,
                request_id TEXT UNIQUE NOT NULL, challenge TEXT UNIQUE NOT NULL,
                scope TEXT NOT NULL, digest TEXT UNIQUE NOT NULL,
                outcome TEXT NOT NULL CHECK(outcome IN ('ATTEMPTED','UNCERTAIN')))''')
            if new:
                db.execute('INSERT INTO simulated_resource_state VALUES (?,?,?)',
                           (_scope_key(state.scope), state.digest, state.version))
            scope, digest = _scope_key(d.pins.manifest.scope), _approval_digest(a)
            old = db.execute('SELECT scope,digest FROM execution_registry WHERE execution_id=?',
                             (a.execution_id,)).fetchone()
            if old is None:
                db.execute('INSERT INTO execution_registry VALUES (?,?,?,?,?,?,?,?,?,0)',
                           (a.execution_id, a.execution_version, d.approval_id, d.approval_version,
                            d.pins.slot.request_id, d.pins.slot.challenge, scope, digest,
                            int(a.status == 'REVOKED')))
            elif old != (scope, digest):
                _deny('REGISTRATION_CONFLICT')
            if a.status == 'REVOKED':
                db.execute('UPDATE execution_registry SET revoked=1 WHERE execution_id=? AND scope=?',
                           (a.execution_id, scope))

    def _observe(self):
        # Independent pre-state connection cannot write; it never certifies execution.
        with closing(sqlite3.connect(Path(self._path).as_uri() + '?mode=ro', uri=True,
                                     timeout=5)) as db:
            return db.execute('SELECT digest,version FROM simulated_resource_state WHERE scope=?',
                              (_scope_key(self._approval.diagnostic.pins.manifest.scope),)).fetchone()

    def execute(self, request, *, principal_handle, execution_handle):
        a = _resolve(self._handles, execution_handle)
        # No caller may submit a diagnostic as authority or choose approval sources.
        result = self._policy.review_approval(
            request, principal_handle=principal_handle, comparison_handle=self._comparison,
            approver_handle=self._human, approval_handle=self._diagnostic)
        if result.reason_code != 'APPROVAL_MATCH_DIAGNOSTIC' or result.authority_effect != 'NONE':
            return ExecutionResult('DIAGNOSTIC_DENIED')
        d, m = a.diagnostic, a.diagnostic.pins.manifest
        if (a.status != 'ACTIVE' or not _fresh(d.issued_at, d.expires_at, self._policy._clock.now)
                or result.source_digest != d.pins.source_digest
                or result.policy_decision_digest != d.policy_decision_digest):
            return ExecutionResult('AUTHORIZATION_DENIED')
        scope, digest = _scope_key(m.scope), _approval_digest(a)
        expected = (m.expected_current_digest, m.expected_current_version)
        try:
            with closing(self._connect()) as db, db:
                db.execute('BEGIN IMMEDIATE')
                registered = db.execute('SELECT scope,digest,revoked,consumed FROM execution_registry '
                                        'WHERE execution_id=?', (a.execution_id,)).fetchone()
                if registered is None or registered[:3] != (scope, digest, 0):
                    return ExecutionResult('AUTHORIZATION_DENIED')
                prior = db.execute('SELECT scope,digest,outcome FROM local_attempts WHERE execution_id=?',
                                   (a.execution_id,)).fetchone()
                if prior is not None:
                    if prior[:2] != (scope, digest):
                        return ExecutionResult('REPLAY_DENIED')
                    # Legacy or injected outcomes are never execution certification.
                    return ExecutionResult(prior[2] if prior[2] in
                                           ('ATTEMPTED', 'UNCERTAIN') else 'UNCERTAIN')
                if registered[3] != 0:
                    return ExecutionResult('REPLAY_DENIED')
                # Writer reservation prevents concurrent effects between observation and commit.
                if self._observe() != expected:
                    return ExecutionResult('PRESTATE_DENIED')
                if self._failures.reservation_refusal:
                    raise sqlite3.OperationalError('TEST_REFUSAL')
                db.execute('INSERT INTO local_attempts VALUES (?,?,?,?,?,?,?,?,?)',
                           (a.execution_id, a.execution_version, d.approval_id, d.approval_version,
                            d.pins.slot.request_id, d.pins.slot.challenge, scope, digest, 'ATTEMPTED'))
                db.execute('UPDATE execution_registry SET consumed=1 WHERE execution_id=? AND scope=?',
                           (a.execution_id, scope))
            # Reservation/consumption is committed before any fake dispatch.
        except sqlite3.Error:
            return ExecutionResult('RESERVATION_UNAVAILABLE')
        if self._failures.crash_after_reservation:
            return ExecutionResult('ATTEMPTED')
        outcome = 'UNCERTAIN'
        try:
            if self._failures.change_before_effect:
                with closing(self._connect()) as db, db:
                    db.execute('BEGIN IMMEDIATE')
                    db.execute('UPDATE simulated_resource_state SET version=version+1 WHERE scope=?', (scope,))
            with closing(self._connect()) as db, db:
                db.execute('BEGIN IMMEDIATE')
                # Recheck durable revocation at the effect serialization point.
                active = db.execute('SELECT revoked FROM execution_registry WHERE execution_id=? '
                                    'AND scope=? AND digest=?', (a.execution_id, scope, digest)).fetchone()
                if active != (0,) or self._failures.effect_write_failure:
                    raise sqlite3.OperationalError('TEST_EFFECT_REFUSED')
                affected = db.execute('UPDATE simulated_resource_state SET digest=?,version=? '
                                      'WHERE scope=? AND digest=? AND version=?',
                                      (m.desired_digest, m.desired_version, scope, *expected)).rowcount
            # Gate 5 acknowledgment only; Gate 6 needs an independent verifier.
            if affected == 1 and not self._failures.lost_ack:
                outcome = 'ATTEMPTED'
        except sqlite3.Error:
            outcome = 'UNCERTAIN'
        try:
            with closing(self._connect()) as db, db:
                db.execute('BEGIN IMMEDIATE')
                if self._failures.outcome_write_failure:
                    raise sqlite3.OperationalError('TEST_OUTCOME_REFUSED')
                changed = db.execute('UPDATE local_attempts SET outcome=? WHERE execution_id=? '
                                     "AND scope=? AND digest=? AND outcome='ATTEMPTED'",
                                     (outcome, a.execution_id, scope, digest)).rowcount
                if changed != 1:
                    raise sqlite3.OperationalError('OUTCOME_NOT_RECORDED')
        except sqlite3.Error:
            return ExecutionResult('UNCERTAIN')
        return ExecutionResult(outcome)
