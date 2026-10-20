"""Fresh-authority fictional recovery, exclusively for the trusted LOCAL harness.

No provider transport, enrollment or hosted endpoint. All registration inputs are
independent harness pins, never deserialized requester claims. Python/filesystem/
SQLite ownership and consistent updated executor code remain trusted.
"""
from contextlib import closing
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime
import json
import sqlite3

from avuhz_runtime.local_infrastructure_authority import (
    LocalInfrastructureDenied, ResourceScope, _clock, _digest, _fresh, _id, _scope,
)
from avuhz_runtime.local_infrastructure_execution import _approval_digest, _scope_key
from avuhz_runtime.local_infrastructure_policy import _hash
from avuhz_runtime.local_infrastructure_recovery import (
    LocalTestInfrastructureRecovery, RecoveryCase, RecoveryObservation,
    _case_digest, _current_clock, _evidence_schema, _immutable_schema,
    _observation_digest, _observation_row, _record_hash, _schema as _reconciliation_schema,
    _stamp, _validate_case, _validate_grant,
)
from avuhz_runtime.local_infrastructure_trust import _deny, _resolve
from avuhz_runtime import local_infrastructure_fencing as fencing


@dataclass(frozen=True, slots=True)
class RecoveryActionRequest:
    action_id: str
    request_id: str
    challenge: str
    scope: ResourceScope
    original_execution_digest: str
    original_attempt_digest: str
    original_case_digest: str
    reconciliation_digest: str
    observation_case: RecoveryCase
    observation: RecoveryObservation
    desired_digest: str
    desired_version: int
    operation: str = 'RECOVER_FICTIONAL_STATE'


@dataclass(frozen=True, slots=True)
class RecoveryActionPolicy:
    policy_id: str
    policy_version: int
    request_digest: str
    decision: str


@dataclass(frozen=True, slots=True)
class RecoveryActionAuthorization:
    """Exact human decision registered independently by the trusted harness."""
    authorization_id: str
    authorization_version: int
    human_id: str
    executor_id: str
    intent_digest: str
    issued_at: datetime
    expires_at: datetime
    status: str = 'ACTIVE'
    max_attempts: int = 1


@dataclass(frozen=True, slots=True)
class RecoveryActionResult:
    state: str
    evidence_digest: str = ''
    authority_effect: str = field(default='NONE', init=False)


def request_digest(request):
    return _hash(b'avuhz.local-recovery-action.REQUEST.v1\n', asdict(request))


def action_intent_digest(request, policy, grants):
    return _hash(b'avuhz.local-recovery-action.INTENT.v1\n',
                 dict(request=asdict(request), policy=asdict(policy),
                      grants=[asdict(g) for g in grants]))


# Separate append-only records; one reservation per original execution as well as
# one action identity. State history never overwrites the original failure.
_REGISTRATION = _immutable_schema('local_recovery_action_registrations',
    'action_id TEXT PRIMARY KEY NOT NULL, original_id TEXT UNIQUE NOT NULL, binding TEXT NOT NULL, request_id TEXT UNIQUE NOT NULL, challenge TEXT UNIQUE NOT NULL, authorization_id TEXT UNIQUE NOT NULL, evidence_digest TEXT NOT NULL',
    'action_id', 'original_id')
_RESERVATION = _immutable_schema('local_recovery_action_reservations',
    'action_id TEXT PRIMARY KEY NOT NULL, original_id TEXT UNIQUE NOT NULL, binding TEXT NOT NULL, recorded_at TEXT NOT NULL, evidence_digest TEXT NOT NULL',
    'action_id', 'original_id')
_EVENTS = _immutable_schema('local_recovery_action_events',
    'event_id TEXT PRIMARY KEY NOT NULL, identity TEXT UNIQUE NOT NULL, action_id TEXT NOT NULL, state TEXT NOT NULL, binding TEXT NOT NULL, observation TEXT NOT NULL, recorded_at TEXT NOT NULL, evidence_digest TEXT NOT NULL',
    'event_id', 'identity')
_REVOCATIONS = _immutable_schema('local_recovery_action_revocations',
    'action_id TEXT PRIMARY KEY NOT NULL, authorization_id TEXT UNIQUE NOT NULL, binding TEXT NOT NULL, evidence_digest TEXT NOT NULL',
    'action_id', 'authorization_id')
_VERIFICATIONS = _immutable_schema('local_recovery_action_verifications',
    'event_id TEXT PRIMARY KEY NOT NULL, identity TEXT UNIQUE NOT NULL, action_id TEXT NOT NULL, state TEXT NOT NULL, binding TEXT NOT NULL, observation TEXT NOT NULL, recorded_at TEXT NOT NULL, evidence_digest TEXT NOT NULL',
    'event_id', 'identity')
_SCHEMA = _REGISTRATION + _RESERVATION + _EVENTS + _REVOCATIONS + _VERIFICATIONS
_TABLES = {'local_recovery_action_registrations', 'local_recovery_action_reservations',
           'local_recovery_action_events', 'local_recovery_action_revocations',
           'local_recovery_action_verifications'}


def _hash_row(row):
    return _hash(b'avuhz.local-recovery-action.RECORD.v1\n', row)


def _schema(db):
    expected = {n: (k, sql) for n, k, sql in _SCHEMA}
    for table in _TABLES:
        for i in range(1, 6 if table == 'local_recovery_action_registrations' else 3):
            expected[f'sqlite_autoindex_{table}_{i}'] = ('index', None)
    actual = {n: (k, sql) for k, n, table, sql in db.execute(
        'SELECT type,name,tbl_name,sql FROM sqlite_master') if table in _TABLES or n in expected}
    if actual != expected:
        _deny('ACTION_SCHEMA_CONFLICT')


def _authorizer(mode):
    def authorize(action, table, column, database, trigger):
        if action == sqlite3.SQLITE_READ:
            if table == 'simulated_resource_state' and mode == 'executor':
                return sqlite3.SQLITE_OK
            if (database == 'main' and table in ({'sqlite_master', 'execution_registry', 'local_attempts',
                    'local_recovery_cases', 'local_recovery_observations', 'local_recovery_decisions',
                    'local_verification_evidence', 'local_audit_evidence'} | _TABLES | set(fencing._TABLES))):
                return sqlite3.SQLITE_OK
            if column == '' and database is None and table in _TABLES | set(fencing._TABLES) and trigger == table + '_insert':
                return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_INSERT:
            allowed = {'local_recovery_action_events'} if mode == 'executor' else (
                {'local_recovery_action_verifications'} if mode == 'verifier' else {'local_recovery_action_revocations'})
            if mode == 'executor':
                allowed |= {'local_recovery_action_reservations', 'local_execution_fences'}
            if table in allowed and database == 'main' and trigger is None:
                return sqlite3.SQLITE_OK
        if (action == sqlite3.SQLITE_UPDATE and mode == 'executor'
                and table == 'simulated_resource_state' and column in ('digest', 'version')
                and database == 'main' and trigger is None):
            return sqlite3.SQLITE_OK
        if action in (sqlite3.SQLITE_SELECT, sqlite3.SQLITE_TRANSACTION):
            return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_FUNCTION and column in ('count', 'raise', 'length', 'typeof', 'substr', 'glob'):
            return sqlite3.SQLITE_OK
        return sqlite3.SQLITE_DENY
    return authorize


@dataclass(frozen=True, slots=True, init=False, eq=False, repr=False)
class LocalTestRecoveryAction:
    """A new action capability, distinct from reconciliation consent.

    One durable reservation, one physical fake effect, separate verifier read.
    A RESERVED replay never dispatches: uncertainty consumes the action forever.
    """
    _reconciliation: object
    _request: RecoveryActionRequest
    _policy: RecoveryActionPolicy
    _consent: RecoveryActionAuthorization
    _grants: tuple
    _clock: object
    _binding: str
    _handles: tuple

    def __init__(self, *, reconciliation_sources, request, policy, authorization,
                 grants, clock):
        if hasattr(self, '_request'):
            _deny('ACTION_ALREADY_INITIALIZED')
        rec = LocalTestInfrastructureRecovery(**reconciliation_sources)
        _current_clock(clock)
        r, a = request, authorization
        if type(r) is not RecoveryActionRequest:
            _deny('INVALID_ACTION_REQUEST')
        _validate_case(r.observation_case)
        o = r.observation
        m = rec._audit._approval.diagnostic.pins.manifest
        d = rec._audit._approval.diagnostic
        if (not all(_id(v) for v in (r.action_id, r.request_id, r.challenge))
                or len({r.action_id, r.request_id, r.challenge}) != 3
                or not _scope(r.scope) or r.scope != rec._case.scope
                or type(r.operation) is not str or r.operation != 'RECOVER_FICTIONAL_STATE'
                or type(r.desired_version) is not int
                or (r.desired_digest, r.desired_version) != (m.desired_digest, m.desired_version)
                or not all(_digest(v) for v in (r.original_execution_digest, r.original_attempt_digest,
                    r.original_case_digest, r.reconciliation_digest, r.desired_digest))
                or r.original_execution_digest != _approval_digest(rec._audit._approval)
                or r.original_case_digest != _case_digest(rec._case)
                or type(o) is not RecoveryObservation or o.scope != r.scope
                or o.case_id != r.observation_case.case_id or o.challenge != r.observation_case.challenge
                or r.observation_case.scope != r.scope
                or r.observation_case.execution_id != rec._case.execution_id
                or r.observation_case.audit_digest != rec._audit_digest
                or r.observation_case.source_digest != rec._case.source_digest
                or not r.observation_case.opened_at < o.observed_at
                or (o.observed_digest, o.observed_version) != (m.expected_current_digest, m.expected_current_version)
                or not _id(o.observation_id) or not _id(o.observer_id)
                or not _clock(o.observed_at) or o.observed_at.microsecond):
            _deny('ACTION_REQUEST_MISMATCH')
        old_ids = {rec._case.execution_id, rec._case.case_id, rec._case.challenge,
                   rec._authorization.authorization_id, d.approval_id,
                   d.pins.slot.request_id, d.pins.slot.challenge,
                   rec._observation.observation_id, rec._observation.case_id,
                   rec._observation.challenge}
        new_ids = (r.action_id, r.request_id, r.challenge, r.observation_case.case_id,
                   r.observation_case.challenge, o.observation_id)
        if len(set(new_ids)) != len(new_ids) or old_ids.intersection(new_ids):
            _deny('REUSED_ACTION_IDENTITY')
        if type(grants) is not tuple or len(grants) != 4:
            _deny('INVALID_ACTION_GRANTS')
        for grant, role in zip(grants, ('HUMAN', 'EXECUTOR', 'OBSERVER', 'VERIFIER')):
            _validate_grant(grant, role, role + '_FICTIONAL_RECOVERY_ACTION')
            if grant.scope != replace(r.scope, identity_id=grant.scope.identity_id):
                _deny('ACTION_SCOPE_MISMATCH')
        identities = [g.scope.identity_id for g in grants]
        prior = {r.scope.identity_id, d.pins.observation.observer_id, d.human_id,
                 d.executor_id, rec._audit._verification.verifier_id,
                 rec._audit._binding.auditor_id, rec._observer.scope.identity_id,
                 rec._human.scope.identity_id}
        if len(set(identities)) != 4 or prior.intersection(identities) or identities[2] != o.observer_id:
            _deny('ACTION_ROLE_CONFLICT')
        if (type(policy) is not RecoveryActionPolicy or not _id(policy.policy_id)
                or type(policy.policy_version) is not int or policy.policy_version != 1
                or policy.request_digest != request_digest(r)
                or type(policy.decision) is not str or policy.decision != 'ALLOW'):
            _deny('ACTION_POLICY_DENIED')
        if (type(a) is not RecoveryActionAuthorization or not _id(a.authorization_id)
                or a.authorization_id in old_ids or a.authorization_id in new_ids
                or type(a.authorization_version) is not int or a.authorization_version != 1
                or type(a.max_attempts) is not int or a.max_attempts != 1
                or (a.human_id, a.executor_id) != tuple(identities[:2])
                or a.intent_digest != action_intent_digest(r, policy, grants)
                or type(a.status) is not str or a.status not in ('ACTIVE', 'REVOKED')
                or not _clock(a.issued_at) or not _clock(a.expires_at)
                or a.issued_at.microsecond or a.expires_at.microsecond):
            _deny('INVALID_ACTION_AUTHORIZATION')
        binding = _hash(b'avuhz.local-recovery-action.BINDING.v1\n',
                        dict(intent=a.intent_digest, authorization=asdict(a)))
        for k, v in dict(_reconciliation=rec, _request=r, _policy=policy,
                         _consent=a, _grants=grants, _clock=clock,
                         _binding=binding, _handles=tuple((object(), g) for g in grants)).items():
            object.__setattr__(self, k, v)
        with closing(rec._audit._connect()) as db, db:
            db.execute('BEGIN IMMEDIATE')
            self._sources(db)
            if db.execute("SELECT 1 FROM sqlite_master WHERE name='local_recovery_action_events'").fetchone() is None:
                for _, _, sql in _SCHEMA:
                    db.execute(sql)
            _schema(db)
            row = (r.action_id, rec._case.execution_id, binding, r.request_id, r.challenge, a.authorization_id)
            existing = db.execute('SELECT * FROM local_recovery_action_registrations WHERE action_id=? OR original_id=?',
                                  row[:2]).fetchall()
            if existing:
                if existing != [(*row, _hash_row(row))]:
                    _deny('ACTION_REGISTRATION_CONFLICT')
            else:
                db.execute('INSERT INTO local_recovery_action_registrations VALUES (?,?,?,?,?,?,?)', (*row, _hash_row(row)))
                self._event(db, 'PROPOSED')
                self._event(db, 'AUTHORIZED')

    @property
    def executor_handle(self):
        return self._handles[1][0]

    @property
    def authorization_handle(self):
        return self._handles[0][0]

    @property
    def verifier_handle(self):
        return self._handles[3][0]

    def _sources(self, db):
        rec, r, a = self._reconciliation, self._request, self._consent
        _current_clock(self._clock)
        now = self._clock.now
        if db.execute("SELECT 1 FROM sqlite_master WHERE name='local_recovery_action_revocations'").fetchone():
            if db.execute('SELECT 1 FROM local_recovery_action_revocations WHERE action_id=?', (r.action_id,)).fetchone():
                _deny('ACTION_REVOKED')
        if (a.status != 'ACTIVE' or not _fresh(a.issued_at, a.expires_at, now)
                or not r.observation.observed_at < a.issued_at <= now
                or not 0 <= (now - r.observation.observed_at).total_seconds() <= 60
                or any(g.status != 'ACTIVE' or not _fresh(g.issued_at, g.expires_at, now)
                       or not _fresh(g.issued_at, g.expires_at, r.observation.observed_at)
                       for g in self._grants)):
            _deny('ACTION_AUTHORIZATION_DENIED')
        _reconciliation_schema(db)
        if rec._sources(db) != 'HOLD':
            _deny('ACTION_ORIGINAL_UNRESOLVED')
        decision = db.execute('SELECT * FROM local_recovery_decisions WHERE execution_id=?',
                              (rec._case.execution_id,)).fetchone()
        if (decision is None or decision[:-1] != rec._row('HOLD', decision[9])
                or decision[-1] != _record_hash(decision[:-1])
                or decision[-1] != r.reconciliation_digest
                or not rec._authorization.issued_at <= datetime.fromisoformat(decision[9].replace('Z', '+00:00')) < r.observation_case.opened_at):
            _deny('ACTION_RECONCILIATION_CONFLICT')
        audit = db.execute('SELECT * FROM local_audit_evidence WHERE execution_id=?',
                           (rec._case.execution_id,)).fetchone()
        if audit[13] != r.original_attempt_digest:
            _deny('ACTION_ATTEMPT_CONFLICT')
        _evidence_schema(db)
        case, o = r.observation_case, r.observation
        if db.execute('SELECT * FROM local_recovery_cases WHERE case_id=?', (case.case_id,)).fetchall() != [
                (case.case_id, case.challenge, _scope_key(case.scope), case.execution_id,
                 case.audit_digest, case.source_digest, _stamp(case.opened_at), _case_digest(case))]:
            _deny('ACTION_CASE_CONFLICT')
        # Action uses its own observer grant; collection uses the existing trusted
        # read-only observer capability, then this separate role pin is checked.
        collection_grant = replace(self._grants[2], capability='OBSERVE_FICTIONAL_RECOVERY')
        evidence = _observation_row(case, o, collection_grant)
        if db.execute('SELECT * FROM local_recovery_observations WHERE observation_id=?', (o.observation_id,)).fetchall() != [
                (*evidence, _observation_digest(evidence))]:
            _deny('ACTION_OBSERVATION_CONFLICT')

    def _event(self, db, state, observation=''):
        identity = self._request.action_id + '.' + state.lower()
        row = (identity, identity, self._request.action_id, state, self._binding, observation, _stamp(self._clock.now))
        table = 'local_recovery_action_verifications' if state in ('VERIFIED', 'UNVERIFIED') else 'local_recovery_action_events'
        db.execute('INSERT INTO ' + table + ' VALUES (?,?,?,?,?,?,?,?)', (*row, _hash_row(row)))
        return _hash_row(row)

    def _reservation(self):
        return (self._request.action_id, self._reconciliation._case.execution_id, self._binding)

    def execute(self, *, executor_handle, authorization_handle):
        reserved = False
        try:
            _resolve((self._handles[1],), executor_handle)
            _resolve((self._handles[0],), authorization_handle)
            rec, r = self._reconciliation, self._request
            with closing(rec._audit._connect()) as db, db:
                db.execute('BEGIN IMMEDIATE')
                db.set_authorizer(_authorizer('executor'))
                _schema(db)
                self._sources(db)
                prior = db.execute('SELECT * FROM local_recovery_action_reservations WHERE action_id=? OR original_id=?',
                                   self._reservation()[:2]).fetchall()
                if prior:
                    if (len(prior) != 1 or prior[0][:3] != self._reservation()
                            or prior[0][-1] != _hash_row(prior[0][:-1])):
                        _deny('ACTION_RESERVATION_CONFLICT')
                    # A committed reservation never provides dispatch authority again.
                    return RecoveryActionResult('UNCERTAIN', prior[0][-1])
                expected = (r.observation.observed_digest, r.observation.observed_version)
                if db.execute('SELECT digest,version FROM simulated_resource_state WHERE scope=?',
                              (_scope_key(r.scope),)).fetchall() != [expected]:
                    _deny('ACTION_PRESTATE_CHANGED')
                fencing.fence(db, rec._case.execution_id, _scope_key(r.scope), r.original_execution_digest)
                row = (*self._reservation(), _stamp(self._clock.now))
                reserved = True
                db.execute('INSERT INTO local_recovery_action_reservations VALUES (?,?,?,?,?)', (*row, _hash_row(row)))
                self._event(db, 'RESERVED')
            # Irreversible consumption and original fencing are durable first.
            with closing(rec._audit._connect()) as db, db:
                db.execute('BEGIN IMMEDIATE')
                db.set_authorizer(_authorizer('executor'))
                _schema(db)
                self._sources(db)
                fencing.fence(db, rec._case.execution_id, _scope_key(r.scope), r.original_execution_digest)
                row = db.execute('SELECT * FROM local_recovery_action_reservations WHERE action_id=?', (r.action_id,)).fetchone()
                if row is None or row[:3] != self._reservation() or row[-1] != _hash_row(row[:-1]):
                    _deny('ACTION_RESERVATION_CONFLICT')
                changed = db.execute('UPDATE simulated_resource_state SET digest=?,version=? WHERE scope=? AND digest=? AND version=?',
                                     (r.desired_digest, r.desired_version, _scope_key(r.scope), *expected)).rowcount
                if changed != 1:
                    _deny('ACTION_PRESTATE_CHANGED')
                evidence = self._event(db, 'ATTEMPTED')
            return RecoveryActionResult('ATTEMPTED', evidence)
        except (LocalInfrastructureDenied, sqlite3.Error, OSError):
            # Cannot assert whether commit reached disk. No retry path exists.
            if reserved:
                self._record_uncertain()
            return RecoveryActionResult('UNCERTAIN' if reserved else 'DENIED')

    def _record_uncertain(self):
        # Best effort only: a storage outage may leave RESERVED as the last
        # durable state. Either way the reservation can never dispatch again.
        try:
            with closing(self._reconciliation._audit._connect()) as db, db:
                db.execute('BEGIN IMMEDIATE')
                db.set_authorizer(_authorizer('executor'))
                _schema(db)
                row = db.execute('SELECT * FROM local_recovery_action_reservations WHERE action_id=?',
                                 (self._request.action_id,)).fetchone()
                if row and row[:3] == self._reservation() and row[-1] == _hash_row(row[:-1]):
                    identity = self._request.action_id + '.uncertain'
                    if not db.execute('SELECT 1 FROM local_recovery_action_events WHERE event_id=?', (identity,)).fetchone():
                        self._event(db, 'UNCERTAIN')
        except (LocalInfrastructureDenied, sqlite3.Error, OSError):
            pass

    def revoke(self, *, authorization_handle):
        """Human capability permanently closes this action, across restart."""
        try:
            _resolve((self._handles[0],), authorization_handle)
            with closing(self._reconciliation._audit._connect()) as db, db:
                db.execute('BEGIN IMMEDIATE')
                db.set_authorizer(_authorizer('revoker'))
                _schema(db)
                self._sources(db)
                row = (self._request.action_id, self._consent.authorization_id, self._binding)
                db.execute('INSERT INTO local_recovery_action_revocations VALUES (?,?,?,?)', (*row, _hash_row(row)))
            return RecoveryActionResult('DENIED', _hash_row(row))
        except (LocalInfrastructureDenied, sqlite3.Error, OSError):
            return RecoveryActionResult('DENIED')

    def verify(self, *, verifier_handle):
        """Independent physical read and immutable result, never executor output."""
        try:
            _resolve((self._handles[3],), verifier_handle)
            r = self._request
            with closing(self._reconciliation._audit._connect()) as db, db:
                db.execute('BEGIN IMMEDIATE')
                _schema(db)
                self._sources(db)
                row = db.execute('SELECT * FROM local_recovery_action_events WHERE event_id=?',
                                 (r.action_id + '.attempted',)).fetchone()
                if row is None or row[4] != self._binding or row[-1] != _hash_row(row[:-1]):
                    _deny('ACTION_NOT_ATTEMPTED')
                prior = db.execute("SELECT * FROM local_recovery_action_verifications WHERE action_id=? AND state IN ('VERIFIED','UNVERIFIED')", (r.action_id,)).fetchall()
                if prior:
                    if len(prior) != 1 or prior[0][4] != self._binding or prior[0][-1] != _hash_row(prior[0][:-1]):
                        _deny('ACTION_VERIFICATION_CONFLICT')
                    return RecoveryActionResult(prior[0][3], prior[0][-1])
                # Distinct read-only connection sees actual committed state.
                from pathlib import Path
                with closing(sqlite3.connect(Path(self._reconciliation._audit._path).as_uri() + '?mode=ro', uri=True)) as observer:
                    actual = observer.execute('SELECT digest,version FROM simulated_resource_state WHERE scope=?', (_scope_key(r.scope),)).fetchall()
                db.set_authorizer(_authorizer('verifier'))
                state = 'VERIFIED' if actual == [(r.desired_digest, r.desired_version)] else 'UNVERIFIED'
                evidence = self._event(db, state, json.dumps(actual, separators=(',', ':')))
            return RecoveryActionResult(state, evidence)
        except (LocalInfrastructureDenied, sqlite3.Error, OSError):
            return RecoveryActionResult('UNVERIFIED')
