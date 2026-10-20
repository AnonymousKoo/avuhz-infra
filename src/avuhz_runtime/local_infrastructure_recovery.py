"""Reconciliation-only LOCAL/TEST terminal records. Never retry authority.

Trusted harness provisioning, filesystem, SQLite and Python retain the preceding
simulation trust model. Handles are capabilities, hashes are consistency pins,
not authentication. Never construct trusted inputs from requester content.
"""
from contextlib import closing
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime
from pathlib import Path
import sqlite3

from avuhz_runtime.local_infrastructure_authority import (
    LocalInfrastructureDenied, ResourceScope, _clock, _digest, _fresh, _id, _scope, _version,
)
from avuhz_runtime.local_infrastructure_audit import (
    LocalTestInfrastructureAudit, _audit_hash, _schema as _audit_schema, _time,
)
from avuhz_runtime.local_infrastructure_execution import _scope_key
from avuhz_runtime.local_infrastructure_policy import _hash
from avuhz_runtime.local_infrastructure_trust import _deny, _resolve


@dataclass(frozen=True, slots=True)
class RecoveryGrant:
    scope: ResourceScope
    role: str
    capability: str
    status: str
    issued_at: datetime
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class RecoveryCase:
    case_id: str
    challenge: str
    scope: ResourceScope
    execution_id: str
    audit_digest: str
    source_digest: str
    opened_at: datetime


@dataclass(frozen=True, slots=True)
class RecoveryObservation:
    observation_id: str
    case_id: str
    challenge: str
    scope: ResourceScope
    observer_id: str
    observed_digest: str
    observed_version: int
    observed_at: datetime


@dataclass(frozen=True, slots=True)
class RecoveryConsent:
    authorization_id: str
    authorization_version: int
    human_id: str
    intent_digest: str
    decision: str
    status: str
    issued_at: datetime
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class RecoveryResult:
    reason_code: str
    decision: str = ''
    evidence_kind: str = 'NONE'
    evidence_digest: str = ''
    retry_authorized: bool = field(default=False, init=False)
    authority_effect: str = field(default='NONE', init=False)


def recovery_intent_digest(*, case, audit_digest, observation, observer_grant, human_grant, decision):
    """Harness pin of exact audit chain, new observation, grants and disposition."""
    return _hash(b'avuhz.local-infrastructure-recovery.INTENT.v1\n',
                 dict(case=asdict(case), audit_digest=audit_digest, observation=asdict(observation),
                      observer=asdict(observer_grant), human=asdict(human_grant), decision=decision,
                      observation_digest=_observation_digest(_observation_row(case, observation, observer_grant))))


_TABLE = '''CREATE TABLE local_recovery_decisions (
    execution_id TEXT PRIMARY KEY NOT NULL, scope TEXT NOT NULL,
    authorization_id TEXT UNIQUE NOT NULL, intent_digest TEXT NOT NULL,
    audit_digest TEXT NOT NULL, observation_digest TEXT NOT NULL,
    authorization_digest TEXT NOT NULL,
    decision TEXT NOT NULL CHECK(decision IN ('HOLD','REVIEW_REQUIRED','NO_RETRY_AUTHORIZED')),
    retry_authorized INTEGER NOT NULL CHECK(retry_authorized=0),
    recorded_at TEXT NOT NULL, evidence_digest TEXT NOT NULL)'''
_UPDATE = '''CREATE TRIGGER local_recovery_no_update BEFORE UPDATE ON local_recovery_decisions
    BEGIN SELECT RAISE(ABORT, 'IMMUTABLE_RECOVERY'); END'''
_DELETE = '''CREATE TRIGGER local_recovery_no_delete BEFORE DELETE ON local_recovery_decisions
    BEGIN SELECT RAISE(ABORT, 'IMMUTABLE_RECOVERY'); END'''
_INSERT = '''CREATE TRIGGER local_recovery_bounded_insert BEFORE INSERT ON local_recovery_decisions
    BEGIN
      SELECT RAISE(ABORT, 'IMMUTABLE_RECOVERY') WHERE EXISTS
        (SELECT 1 FROM local_recovery_decisions WHERE execution_id=NEW.execution_id
         OR authorization_id=NEW.authorization_id);
      SELECT RAISE(ABORT, 'RECOVERY_CAPACITY') WHERE
        (SELECT count(*) FROM local_recovery_decisions)>=256;
    END'''
_SCHEMA = (('local_recovery_decisions', 'table', _TABLE),
           ('local_recovery_no_update', 'trigger', _UPDATE),
           ('local_recovery_no_delete', 'trigger', _DELETE),
           ('local_recovery_bounded_insert', 'trigger', _INSERT))
_READS = ('sqlite_master', 'execution_registry', 'local_attempts',
          'local_recovery_cases', 'local_recovery_observations', 'local_verification_evidence',
          'local_audit_evidence', 'local_recovery_decisions')



def _immutable_schema(table, columns, key, unique):
    # Constant identifiers from this module only; no requester-controlled SQL.
    return (
        (table, 'table', f'CREATE TABLE {table} ({columns})'),
        (table + '_update', 'trigger', f"CREATE TRIGGER {table}_update BEFORE UPDATE ON {table} BEGIN SELECT RAISE(ABORT, 'IMMUTABLE'); END"),
        (table + '_delete', 'trigger', f"CREATE TRIGGER {table}_delete BEFORE DELETE ON {table} BEGIN SELECT RAISE(ABORT, 'IMMUTABLE'); END"),
        (table + '_insert', 'trigger', f"CREATE TRIGGER {table}_insert BEFORE INSERT ON {table} BEGIN SELECT RAISE(ABORT, 'IMMUTABLE') WHERE EXISTS (SELECT 1 FROM {table} WHERE {key}=NEW.{key} OR {unique}=NEW.{unique}); SELECT RAISE(ABORT, 'CAPACITY') WHERE (SELECT count(*) FROM {table})>=256; END"),
    )


_CASE_SCHEMA = _immutable_schema('local_recovery_cases',
    'case_id TEXT PRIMARY KEY NOT NULL, challenge TEXT UNIQUE NOT NULL, scope TEXT NOT NULL, execution_id TEXT NOT NULL, audit_digest TEXT NOT NULL, source_digest TEXT NOT NULL, opened_at TEXT NOT NULL, evidence_digest TEXT NOT NULL', 'case_id', 'challenge')
_OBSERVATION_SCHEMA = _immutable_schema('local_recovery_observations',
    'observation_id TEXT PRIMARY KEY NOT NULL, case_id TEXT UNIQUE NOT NULL, challenge TEXT NOT NULL, scope TEXT NOT NULL, observer_id TEXT NOT NULL, observed_digest TEXT NOT NULL, observed_version INTEGER NOT NULL, observed_at TEXT NOT NULL, case_digest TEXT NOT NULL, grant_digest TEXT NOT NULL, evidence_digest TEXT NOT NULL', 'observation_id', 'case_id')


def _stamp(value):
    return value.isoformat().replace('+00:00', 'Z')


def _case_row(case):
    return (case.case_id, case.challenge, _scope_key(case.scope), case.execution_id,
            case.audit_digest, case.source_digest, _stamp(case.opened_at))


def _case_digest(case):
    return _hash(b'avuhz.local-recovery.CASE.v1\n', asdict(case))


def _observation_row(case, observation, grant):
    o = observation
    return (o.observation_id, o.case_id, o.challenge, _scope_key(o.scope), o.observer_id,
            o.observed_digest, o.observed_version, _stamp(o.observed_at), _case_digest(case),
            _hash(b'avuhz.local-recovery.GRANT.v1\n', asdict(grant)))


def _observation_digest(row):
    return _hash(b'avuhz.local-recovery.OBSERVATION.v1\n', row)


def _evidence_schema(db):
    specifications = _CASE_SCHEMA + _OBSERVATION_SCHEMA
    expected = {n: (k, sql) for n, k, sql in specifications}
    tables = {'local_recovery_cases', 'local_recovery_observations'}
    for table in tables:
        for i in (1, 2):
            expected[f'sqlite_autoindex_{table}_{i}'] = ('index', None)
    actual = {n: (k, sql) for k, n, table, sql in db.execute(
        'SELECT type,name,tbl_name,sql FROM sqlite_master') if table in tables or n in expected}
    if actual != expected:
        _deny('RECOVERY_EVIDENCE_SCHEMA_CONFLICT')


def _historical(audit_sources, audit_digest):
    """Use immutable original times, never extend or reactivate an old grant."""
    if type(audit_sources) is not dict or not _digest(audit_digest):
        _deny('INVALID_RECOVERY_SOURCE')
    path = audit_sources.get('database_path')
    if type(path) is not str or not path.startswith('/tmp/'):
        _deny('INVALID_TEST_DATABASE_PATH')
    p = Path(path)
    if p.is_symlink() or not p.resolve().is_relative_to(Path('/tmp')) or not p.is_file():
        _deny('INVALID_TEST_DATABASE_PATH')
    with closing(sqlite3.connect(p.resolve().as_uri() + '?mode=ro', uri=True)) as db:
        _audit_schema(db, audit=True)
        rows = db.execute('SELECT * FROM local_audit_evidence WHERE execution_id=?',
                          (audit_sources['audit_binding'].execution_id,)).fetchall()
    if len(rows) != 1 or rows[0][-1] != audit_digest or _audit_hash(rows[0][:-1]) != audit_digest:
        _deny('RECOVERY_AUDIT_CONFLICT')
    original = audit_sources['clock']
    historical_time = _time(rows[0][23])
    if not _fresh(original.issued_at, original.expires_at, historical_time):
        _deny('INVALID_HISTORICAL_CLOCK')
    historical_clock = replace(original, now=historical_time)
    sources = dict(audit_sources, clock=historical_clock,
                   policy_sources=dict(audit_sources['policy_sources'], clock=historical_clock))
    audit = LocalTestInfrastructureAudit(**sources)
    # Validate original approval/observation/slot at their original times as facts.
    d = audit._approval.diagnostic
    pins, policy = d.pins, audit._policy
    observed = pins.observation
    principal = next(g for g in policy._grants if g.scope == pins.manifest.scope)
    observer = next(g for g in policy._grants if g.scope.identity_id == observed.observer_id)
    if (principal.role != 'PRINCIPAL' or observer.role != 'OBSERVER'
            or not _fresh(observer.issued_at, observer.expires_at, observed.observed_at)
            or not observed.observed_at <= d.issued_at <= _time(rows[0][22]) <= historical_time
            or not _fresh(observed.observed_at, observed.expires_at, d.issued_at)
            or not _fresh(pins.slot.issued_at, pins.slot.expires_at, d.issued_at)
            or not _fresh(d.issued_at, d.expires_at, d.issued_at)
            or not any(r.scope == pins.manifest.scope for r in policy._trust._ownership)
            or any(g.status != 'ACTIVE' or not _fresh(g.issued_at, g.expires_at, d.issued_at)
                   for g in (*policy._grants, *(h for _, h in policy._humans)))):
        _deny('INVALID_HISTORICAL_AUTHORITY')
    # Pin complete harness sources, including ownership, policy, approval and clocks.
    def canonical(value):
        if hasattr(value, '__dataclass_fields__'):
            return asdict(value)
        if type(value) is dict:
            return {k: canonical(v) for k, v in value.items()}
        if type(value) is tuple:
            return tuple(canonical(v) for v in value)
        return value
    source_digest = _hash(b'avuhz.local-recovery.SOURCES.v1\n',
        canonical({k: v for k, v in audit_sources.items() if k != 'database_path'}))
    return audit, source_digest


def _current_clock(clock):
    from avuhz_runtime.local_infrastructure_trust import TestClock, _record
    _record(clock, TestClock)
    if not _fresh(clock.issued_at, clock.expires_at, clock.now):
        _deny('RECOVERY_CLOCK_DENIED')


def open_recovery_case(*, audit_sources, audit_digest, case_id, challenge, clock):
    """Trusted harness ONLY: durably open a challenge before evidence collection."""
    _current_clock(clock)
    if not _id(case_id) or not _id(challenge):
        _deny('INVALID_RECOVERY_CASE')
    audit, source_digest = _historical(audit_sources, audit_digest)
    with closing(audit._connect()) as db, db:
        db.execute('BEGIN IMMEDIATE')
        row = db.execute('SELECT * FROM local_audit_evidence WHERE execution_id=?',
                         (audit._binding.execution_id,)).fetchone()
        if row[-1] != audit_digest or not _time(row[23]) < clock.now:
            _deny('RECOVERY_CASE_TIME_DENIED')
        audit._sources(db)  # Includes current durable execution revocation/consumption.
        case = RecoveryCase(case_id, challenge, audit._binding.scope,
                            audit._binding.execution_id, audit_digest, source_digest, clock.now)
        if db.execute("SELECT 1 FROM sqlite_master WHERE name='local_recovery_cases'").fetchone() is None:
            for _, _, sql in _CASE_SCHEMA + _OBSERVATION_SCHEMA:
                db.execute(sql)
        _evidence_schema(db)
        db.execute('INSERT INTO local_recovery_cases VALUES (?,?,?,?,?,?,?,?)',
                   (*_case_row(case), _case_digest(case)))
    return case


def _observer_authorizer(action, table, column, database, trigger):
    if action == sqlite3.SQLITE_INSERT:
        return sqlite3.SQLITE_OK if table == 'local_recovery_observations' and trigger is None and database == 'main' else sqlite3.SQLITE_DENY
    if action == sqlite3.SQLITE_READ and table == 'simulated_resource_state' and database == 'main':
        return sqlite3.SQLITE_OK
    return _write_authorizer(action, table, column, database, trigger)


def collect_recovery_observation(*, audit_sources, case, observer_grant, observation_id, clock):
    """Trusted independent observer ONLY: read physical state and persist once.

    Separate transaction and writer privilege from reconciliation. No caller state.
    """
    _current_clock(clock)
    _validate_case(case)
    _validate_grant(observer_grant, 'OBSERVER', 'OBSERVE_FICTIONAL_RECOVERY')
    audit, source = _historical(audit_sources, case.audit_digest)
    d = audit._approval.diagnostic
    prior = {case.scope.identity_id, d.pins.observation.observer_id, d.human_id,
             d.executor_id, audit._verification.verifier_id, audit._binding.auditor_id}
    if (not _id(observation_id) or observer_grant.scope != replace(case.scope, identity_id=observer_grant.scope.identity_id)
            or observer_grant.scope.identity_id in prior or observer_grant.status != 'ACTIVE'
            or not _fresh(observer_grant.issued_at, observer_grant.expires_at, clock.now)
            or not case.opened_at < clock.now or source != case.source_digest
            or case.scope != audit._binding.scope or case.execution_id != audit._binding.execution_id):
        _deny('RECOVERY_OBSERVER_DENIED')
    with closing(audit._connect()) as db, db:
        db.set_authorizer(_observer_authorizer)
        db.execute('BEGIN IMMEDIATE')
        _audit_schema(db, audit=True)
        _evidence_schema(db)
        audit._sources(db)
        if db.execute('SELECT * FROM local_recovery_cases WHERE case_id=?', (case.case_id,)).fetchall() != [(*_case_row(case), _case_digest(case))]:
            _deny('RECOVERY_CASE_CONFLICT')
        state = db.execute('SELECT digest,version FROM simulated_resource_state WHERE scope=?',
                           (_scope_key(case.scope),)).fetchall()
        if len(state) != 1 or not _digest(state[0][0]) or not _version(state[0][1]):
            _deny('RECOVERY_STATE_CONFLICT')
        observation = RecoveryObservation(observation_id, case.case_id, case.challenge,
            case.scope, observer_grant.scope.identity_id, *state[0], clock.now)
        row = _observation_row(case, observation, observer_grant)
        db.execute('INSERT INTO local_recovery_observations VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                   (*row, _observation_digest(row)))
        if db.execute('SELECT * FROM local_recovery_observations WHERE case_id=?', (case.case_id,)).fetchall() != [(*row, _observation_digest(row))]:
            _deny('RECOVERY_OBSERVATION_CONFLICT')
    return observation


def _validate_case(case):
    if (type(case) is not RecoveryCase or not _id(case.case_id) or not _id(case.challenge)
            or not _scope(case.scope) or not _id(case.execution_id)
            or not _digest(case.audit_digest) or not _digest(case.source_digest)
            or not _clock(case.opened_at) or case.opened_at.microsecond):
        _deny('INVALID_RECOVERY_CASE')


def _validate_grant(g, role, capability):
    if (type(g) is not RecoveryGrant or not _scope(g.scope)
            or type(g.role) is not str or g.role != role
            or type(g.capability) is not str or g.capability != capability
            or type(g.status) is not str or g.status not in ('ACTIVE', 'REVOKED')
            or not _clock(g.issued_at) or not _clock(g.expires_at)
            or g.issued_at.microsecond or g.expires_at.microsecond):
        _deny('INVALID_RECOVERY_GRANT')

def _write_authorizer(action, table, column, database, trigger):
    if (action == sqlite3.SQLITE_READ and table in ('local_recovery_decisions', 'local_recovery_observations')
            and column == '' and database is None and trigger in ('local_recovery_bounded_insert', 'local_recovery_observations_insert')):
        return sqlite3.SQLITE_OK
    if database == 'main':
        if action == sqlite3.SQLITE_INSERT and table == 'local_recovery_decisions' and trigger is None:
            return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_READ and table in _READS:
            return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_SELECT:
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_TRANSACTION and table in ('BEGIN', 'COMMIT', 'ROLLBACK'):
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_FUNCTION and column in ('count', 'raise'):
        return sqlite3.SQLITE_OK
    return sqlite3.SQLITE_DENY


def _schema(db):
    _audit_schema(db, audit=True)
    _evidence_schema(db)
    expected = {n: (k, sql) for n, k, sql in _SCHEMA}
    expected.update({f'sqlite_autoindex_local_recovery_decisions_{i}': ('index', None)
                     for i in (1, 2)})
    actual = {n: (k, sql) for k, n, table, sql in db.execute(
        'SELECT type,name,tbl_name,sql FROM sqlite_master')
              if table == 'local_recovery_decisions' or n in expected}
    if actual != expected:
        _deny('RECOVERY_SCHEMA_CONFLICT')


def _record_hash(row):
    return _hash(b'avuhz.local-infrastructure-recovery.RECORD.v1\n', row)


@dataclass(frozen=True, slots=True, init=False, eq=False, repr=False)
class LocalTestInfrastructureRecovery:
    """One immutable terminal decision per prior attempt; no executor interface.

    Trusted registration takes complete original audit sources, separate observer
    and human grants and a separately pinned authorization. Public reconciliation
    accepts only instance-local handles. All reads and the sole decision INSERT
    are serialized in one FULL synchronous transaction. Replays revalidate fresh
    inputs and return history without replacing evidence or resetting consumption.
    """
    _audit: object
    _case: RecoveryCase
    _clock: object
    _observation: RecoveryObservation
    _observer: RecoveryGrant
    _human: RecoveryGrant
    _authorization: RecoveryConsent
    _audit_digest: str
    _handles: tuple

    def __init__(self, *, audit_sources, observation, observer_grant, human_grant,
                 authorization, audit_digest, case, clock):
        if hasattr(self, '_audit'):
            _deny('RECOVERY_ALREADY_INITIALIZED')
        _validate_case(case)
        _current_clock(clock)
        try:
            audit, source_digest = _historical(audit_sources, audit_digest)
        except (sqlite3.Error, OSError, ValueError, RuntimeError, TypeError, KeyError):
            _deny('RECOVERY_SOURCE_UNAVAILABLE')
        if (case.audit_digest != audit_digest or case.source_digest != source_digest
                or case.scope != audit._binding.scope or case.execution_id != audit._binding.execution_id):
            _deny('RECOVERY_CASE_CONFLICT')
        o, a = observation, authorization
        if (type(o) is not RecoveryObservation or not _id(o.observation_id) or not _scope(o.scope)
                or not _id(o.case_id) or not _id(o.challenge)
                or (o.case_id, o.challenge) != (case.case_id, case.challenge)
                or not _id(o.observer_id) or not _digest(o.observed_digest)
                or not _version(o.observed_version) or not _clock(o.observed_at) or o.observed_at.microsecond):
            _deny('INVALID_RECOVERY_OBSERVATION')
        for g, role, capability in ((observer_grant, 'OBSERVER', 'OBSERVE_FICTIONAL_RECOVERY'),
                                    (human_grant, 'HUMAN', 'RECORD_FICTIONAL_RECOVERY')):
            _validate_grant(g, role, capability)
        if (type(a) is not RecoveryConsent or not _id(a.authorization_id)
                or not _version(a.authorization_version) or a.authorization_version != 1
                or not _id(a.human_id) or not _digest(a.intent_digest)
                or type(a.decision) is not str or a.decision not in ('HOLD', 'REVIEW_REQUIRED', 'NO_RETRY_AUTHORIZED')
                or type(a.status) is not str or a.status not in ('ACTIVE', 'REVOKED')
                or not _clock(a.issued_at) or not _clock(a.expires_at)
                or a.issued_at.microsecond or a.expires_at.microsecond):
            _deny('INVALID_RECOVERY_AUTHORIZATION')
        scope, d = audit._binding.scope, audit._approval.diagnostic
        prior = {scope.identity_id, d.pins.observation.observer_id, d.human_id,
                 d.executor_id, audit._verification.verifier_id, audit._binding.auditor_id}
        if (o.scope != scope or observer_grant.scope != replace(scope, identity_id=o.observer_id)
                or human_grant.scope != replace(scope, identity_id=a.human_id)
                or o.observer_id in prior or a.human_id in prior or o.observer_id == a.human_id
                or a.intent_digest != recovery_intent_digest(case=case, audit_digest=audit_digest,
                    observation=o, observer_grant=observer_grant, human_grant=human_grant, decision=a.decision)):
            _deny('RECOVERY_BINDING_MISMATCH')
        for key, value in dict(_audit=audit, _case=case, _clock=clock, _observation=o, _observer=observer_grant,
                               _human=human_grant, _authorization=a, _audit_digest=audit_digest,
                               _handles=((object(), observer_grant), (object(), a))).items():
            object.__setattr__(self, key, value)
        try:
            with closing(audit._connect()) as db, db:
                db.execute('BEGIN IMMEDIATE')
                _evidence_schema(db)
                self._sources(db)
                if db.execute("SELECT 1 FROM sqlite_master WHERE name='local_recovery_decisions'").fetchone() is None:
                    for _, _, sql in _SCHEMA:
                        db.execute(sql)
                _schema(db)
        except (sqlite3.Error, OSError):
            _deny('RECOVERY_STORAGE_UNAVAILABLE')

    @property
    def observer_handle(self):
        return self._handles[0][0]

    @property
    def authorization_handle(self):
        return self._handles[1][0]

    def _sources(self, db):
        audit, o, a = self._audit, self._observation, self._authorization
        now = self._clock.now
        _current_clock(self._clock)
        if (a.status != 'ACTIVE'
                or not _fresh(a.issued_at, a.expires_at, now)
                or not self._case.opened_at < o.observed_at < a.issued_at <= now
                or not 0 <= (now - o.observed_at).total_seconds() <= 60
                or any(g.status != 'ACTIVE' or not _fresh(g.issued_at, g.expires_at, now)
                       or not _fresh(g.issued_at, g.expires_at, o.observed_at)
                       for g in (self._observer, self._human))):
            _deny('RECOVERY_AUTHORIZATION_DENIED')
        registry, attempt, verification = audit._sources(db)
        rows = db.execute('SELECT * FROM local_audit_evidence WHERE execution_id=?',
                          (audit._binding.execution_id,)).fetchall()
        if len(rows) != 1 or len(rows[0]) != 25:
            _deny('RECOVERY_AUDIT_CONFLICT')
        row = rows[0]
        historical = (*attempt[:8], row[17])
        if (row[17] not in ('ATTEMPTED', 'UNCERTAIN')
                or (row[17] == 'UNCERTAIN' and attempt[8] != 'UNCERTAIN')
                or not _time(row[22]) <= _time(row[23]) < o.observed_at
                or not _fresh(audit._grant.issued_at, audit._grant.expires_at, _time(row[23]))
                or row[:-1] != audit._row(registry, historical, verification, row[23])
                or row[-1] != _audit_hash(row[:-1]) or row[-1] != self._audit_digest):
            _deny('RECOVERY_AUDIT_CONFLICT')
        case = self._case
        if db.execute('SELECT * FROM local_recovery_cases WHERE case_id=?', (case.case_id,)).fetchall() != [(*_case_row(case), _case_digest(case))]:
            _deny('RECOVERY_CASE_CONFLICT')
        evidence = _observation_row(case, o, self._observer)
        if db.execute('SELECT * FROM local_recovery_observations WHERE case_id=?', (case.case_id,)).fetchall() != [(*evidence, _observation_digest(evidence))]:
            _deny('RECOVERY_OBSERVATION_CONFLICT')
        m = audit._approval.diagnostic.pins.manifest
        observed = (o.observed_digest, o.observed_version)
        decision = ('REVIEW_REQUIRED' if attempt[8] == 'UNCERTAIN'
                    else 'NO_RETRY_AUTHORIZED' if observed == (m.desired_digest, m.desired_version)
                    else 'HOLD' if observed == (m.expected_current_digest, m.expected_current_version)
                    else 'REVIEW_REQUIRED')
        if a.decision != decision:
            _deny('RECOVERY_DECISION_CONFLICT')
        return decision

    def _row(self, decision, recorded):
        a, o = self._authorization, self._observation
        return (self._audit._binding.execution_id, _scope_key(o.scope), a.authorization_id,
                a.intent_digest, self._audit_digest,
                _observation_digest(_observation_row(self._case, o, self._observer)),
                _hash(b'avuhz.local-infrastructure-recovery.AUTHORIZATION.v1\n', asdict(a)),
                decision, 0, recorded)

    def reconcile(self, *, observer_handle, authorization_handle):
        try:
            _resolve((self._handles[0],), observer_handle)
            _resolve((self._handles[1],), authorization_handle)
        except LocalInfrastructureDenied:
            return RecoveryResult('AUTHORIZATION_DENIED')
        try:
            with closing(self._audit._connect()) as db, db:
                db.set_authorizer(_write_authorizer)
                db.execute('BEGIN IMMEDIATE')
                _schema(db)
                decision = self._sources(db)
                rows = db.execute('SELECT * FROM local_recovery_decisions WHERE execution_id=? OR authorization_id=?',
                                  (self._audit._binding.execution_id, self._authorization.authorization_id)).fetchall()
                if rows:
                    row = rows[0]
                    if (len(rows) != 1 or len(row) != 11
                            or not self._authorization.issued_at <= _time(row[9]) <= self._clock.now
                            or row[:-1] != self._row(decision, row[9])
                            or row[-1] != _record_hash(row[:-1])):
                        _deny('RECOVERY_TERMINAL_CONFLICT')
                    kind = 'HISTORICAL_REPLAY'
                else:
                    row = self._row(decision, self._clock.now.isoformat().replace('+00:00', 'Z'))
                    row = (*row, _record_hash(row))
                    db.execute('INSERT INTO local_recovery_decisions VALUES (?,?,?,?,?,?,?,?,?,?,?)', row)
                    if db.execute('SELECT * FROM local_recovery_decisions WHERE execution_id=?',
                                  (row[0],)).fetchall() != [row]:
                        _deny('RECOVERY_TERMINAL_CONFLICT')
                    kind = 'SYNTHETIC_LOCAL_RECORD'
            return RecoveryResult('RECOVERY_RECORDED', decision, kind, row[-1])
        except (sqlite3.Error, OSError, LocalInfrastructureDenied):
            return RecoveryResult('CONFLICT')
