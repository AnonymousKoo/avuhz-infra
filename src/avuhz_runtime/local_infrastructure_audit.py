"""Bounded, append-only synthetic LOCAL/TEST evidence; never live authority.

Provisioning, Python, SQLite and the filesystem retain the preceding harness
trust model. Digests bind sanitized fictional evidence, not secrets or payloads.
No executor, verifier, physical observer, recovery or dispatch is invoked here.
"""
from contextlib import closing
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
import sqlite3

from avuhz_runtime.local_infrastructure_authority import (
    LocalInfrastructureDenied, ResourceScope, _clock, _digest, _fresh, _id, _scope, _version,
)
from avuhz_runtime.local_infrastructure_execution import _approval_digest, _scope_key
from avuhz_runtime.local_infrastructure_policy import LocalTestInfrastructurePolicyAdapter, _hash
from avuhz_runtime.local_infrastructure_trust import TestClock, _deny, _record, _resolve
from avuhz_runtime.local_infrastructure_verification import (
    _SCHEMA as _VERIFICATION_SCHEMA, _evidence_hash as _verification_hash,
    _grant_binding, _source,
)


@dataclass(frozen=True, slots=True)
class AuditGrant:
    grant_id: str
    grant_version: int
    scope: ResourceScope  # Auditor identity, with the exact execution resource.
    role: str
    capability: str
    status: str
    issued_at: datetime
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class AuditBinding:
    scope: ResourceScope  # Original execution principal, never the auditor.
    execution_id: str
    execution_version: int
    execution_digest: str
    verification_binding_digest: str
    verification_evidence_digest: str
    auditor_id: str
    grant_id: str
    grant_version: int


@dataclass(frozen=True, slots=True)
class AuditResult:
    reason_code: str
    evidence_kind: str = 'NONE'
    execution_outcome: str = ''
    verification_execution_outcome: str = ''
    observation_reason: str = ''
    verification_evidence_digest: str = ''
    observed_at: str = ''
    recorded_at: str = ''
    evidence_digest: str = ''
    authority_effect: str = field(default='NONE', init=False)


MAX_RECORDS = 256  # One immutable row per globally unique executor reservation.
_DIGEST_COLUMNS = (
    'binding_digest', 'source_digest', 'execution_digest', 'operation_digest',
    'policy_digest', 'approval_digest', 'manifest_digest', 'observation_digest',
    'reservation_digest', 'attempt_digest', 'verification_binding_digest',
    'verification_evidence_digest', 'observed_digest', 'evidence_digest',
)
_COLUMNS = (
    'execution_id', 'execution_version', 'scope', 'auditor_id', 'binding_digest',
    'source_digest', 'execution_digest', 'operation_digest', 'policy_digest',
    'approval_digest', 'manifest_digest', 'observation_digest', 'reservation_digest',
    'attempt_digest', 'verification_binding_digest', 'verification_evidence_digest',
    'verifier_id', 'execution_outcome', 'verification_execution_outcome',
    'observation_reason', 'observed_digest', 'observed_version', 'observed_at',
    'recorded_at', 'evidence_digest',
)
_TABLE = '''CREATE TABLE local_audit_evidence (
    execution_id TEXT PRIMARY KEY NOT NULL CHECK(length(execution_id) BETWEEN 3 AND 64),
    execution_version INTEGER NOT NULL CHECK(typeof(execution_version)='integer' AND execution_version BETWEEN 1 AND 2147483647),
    scope TEXT NOT NULL CHECK(length(scope) BETWEEN 1 AND 512),
    auditor_id TEXT NOT NULL CHECK(length(auditor_id) BETWEEN 3 AND 64),
    binding_digest TEXT NOT NULL, source_digest TEXT NOT NULL,
    execution_digest TEXT NOT NULL, operation_digest TEXT NOT NULL,
    policy_digest TEXT NOT NULL, approval_digest TEXT NOT NULL,
    manifest_digest TEXT NOT NULL, observation_digest TEXT NOT NULL,
    reservation_digest TEXT NOT NULL, attempt_digest TEXT NOT NULL,
    verification_binding_digest TEXT NOT NULL, verification_evidence_digest TEXT NOT NULL,
    verifier_id TEXT NOT NULL CHECK(length(verifier_id) BETWEEN 3 AND 64),
    execution_outcome TEXT NOT NULL CHECK(execution_outcome IN ('ATTEMPTED','UNCERTAIN')),
    verification_execution_outcome TEXT NOT NULL CHECK(verification_execution_outcome IN ('ATTEMPTED','UNCERTAIN')),
    observation_reason TEXT NOT NULL CHECK(observation_reason IN ('LOCAL_STATE_MATCH','PENDING','MISMATCH')),
    observed_digest TEXT NOT NULL,
    observed_version INTEGER NOT NULL CHECK(typeof(observed_version)='integer' AND observed_version BETWEEN 1 AND 2147483647),
    observed_at TEXT NOT NULL CHECK(length(observed_at)=20),
    recorded_at TEXT NOT NULL CHECK(length(recorded_at)=20),
    evidence_digest TEXT NOT NULL'''
_TABLE += ''.join(
    ", CHECK(typeof({0})='text' AND length({0})=71 AND substr({0},1,7)='sha256:' "
    "AND substr({0},8) NOT GLOB '*[^0-9a-f]*')".format(column)
    for column in _DIGEST_COLUMNS) + ')'
_UPDATE = '''CREATE TRIGGER local_audit_no_update BEFORE UPDATE ON local_audit_evidence
    BEGIN SELECT RAISE(ABORT, 'IMMUTABLE_AUDIT'); END'''
_DELETE = '''CREATE TRIGGER local_audit_no_delete BEFORE DELETE ON local_audit_evidence
    BEGIN SELECT RAISE(ABORT, 'IMMUTABLE_AUDIT'); END'''
_INSERT = '''CREATE TRIGGER local_audit_bounded_insert BEFORE INSERT ON local_audit_evidence
    BEGIN
      SELECT RAISE(ABORT, 'IMMUTABLE_AUDIT') WHERE EXISTS
        (SELECT 1 FROM local_audit_evidence WHERE execution_id=NEW.execution_id);
      SELECT RAISE(ABORT, 'AUDIT_CAPACITY') WHERE
        (SELECT count(*) FROM local_audit_evidence)>=256;
    END'''
_SCHEMA = (('local_audit_evidence', 'table', _TABLE),
           ('local_audit_no_update', 'trigger', _UPDATE),
           ('local_audit_no_delete', 'trigger', _DELETE),
           ('local_audit_bounded_insert', 'trigger', _INSERT))

# Exact original executor structures; no migration, repair or ledger write.
# Whitespace normalization accommodates the original constructor's indentation.
_EXECUTION_TABLES = {
    'execution_registry': '''CREATE TABLE execution_registry (
        execution_id TEXT PRIMARY KEY, execution_version INTEGER NOT NULL,
        approval_id TEXT UNIQUE NOT NULL, approval_version INTEGER NOT NULL,
        request_id TEXT UNIQUE NOT NULL, challenge TEXT UNIQUE NOT NULL,
        scope TEXT NOT NULL, digest TEXT UNIQUE NOT NULL,
        revoked INTEGER NOT NULL, consumed INTEGER NOT NULL DEFAULT 0)''',
    'local_attempts': '''CREATE TABLE local_attempts (
        execution_id TEXT PRIMARY KEY, execution_version INTEGER NOT NULL,
        approval_id TEXT UNIQUE NOT NULL, approval_version INTEGER NOT NULL,
        request_id TEXT UNIQUE NOT NULL, challenge TEXT UNIQUE NOT NULL,
        scope TEXT NOT NULL, digest TEXT UNIQUE NOT NULL,
        outcome TEXT NOT NULL CHECK(outcome IN ('ATTEMPTED','UNCERTAIN')))''',
    'simulated_resource_state': '''CREATE TABLE simulated_resource_state (
        scope TEXT PRIMARY KEY, digest TEXT NOT NULL, version INTEGER NOT NULL)''',
}
_SOURCE_COLUMNS = ('execution_id,execution_version,approval_id,approval_version,'
                   'request_id,challenge,scope,digest')
_READ_TABLES = ('sqlite_master', 'execution_registry', 'local_attempts',
                'local_verification_evidence', 'local_audit_evidence')


def _audit_hash(row):
    return _hash(b'avuhz.local-infrastructure-audit.RECORD.v1\n', row)


def _time(value):
    if type(value) is not str or len(value) != 20:
        _deny('AUDIT_CLOCK_CONFLICT')
    try:
        parsed = datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    except ValueError:
        _deny('AUDIT_CLOCK_CONFLICT')
    if parsed.isoformat().replace('+00:00', 'Z') != value:
        _deny('AUDIT_CLOCK_CONFLICT')
    return parsed


def _write_authorizer(action, table, column, database, trigger):
    """No DDL, arbitrary functions, attachment, state reads, or source writes."""
    # SQLite reports an optimized count(*) as a columnless read without a
    # database name. Permit only the fixed capacity trigger's audit-table count.
    if (action == sqlite3.SQLITE_READ and table == 'local_audit_evidence'
            and column == '' and database is None and trigger == 'local_audit_bounded_insert'):
        return sqlite3.SQLITE_OK
    if database == 'main':
        if action == sqlite3.SQLITE_INSERT and table == 'local_audit_evidence' and trigger is None:
            return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_READ and table in _READ_TABLES:
            return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_SELECT:
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_TRANSACTION and table in ('BEGIN', 'COMMIT', 'ROLLBACK'):
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_FUNCTION and column in ('count', 'raise', 'length', 'typeof', 'substr', 'glob'):
        return sqlite3.SQLITE_OK
    return sqlite3.SQLITE_DENY


def _schema(db, *, audit):
    """Reject replaced tables, extra indexes/triggers, and hostile source views."""
    specifications = tuple((n, 'table', sql) for n, sql in _EXECUTION_TABLES.items())
    specifications += _VERIFICATION_SCHEMA + (_SCHEMA if audit else ())
    tables = set(_EXECUTION_TABLES) | {'local_verification_evidence'}
    if audit:
        tables.add('local_audit_evidence')
    expected = {}
    for name, kind, sql in specifications:
        expected[name] = (kind, ' '.join(sql.split()) if name in _EXECUTION_TABLES else sql)
    for table in tables:
        for i in range(1, (5 if table in ('execution_registry', 'local_attempts') else 1) + 1):
            expected['sqlite_autoindex_' + table + '_' + str(i)] = ('index', None)
    actual = {}
    for kind, name, table, sql in db.execute('SELECT type,name,tbl_name,sql FROM sqlite_master'):
        if table in tables or name in expected:
            actual[name] = (kind, ' '.join(sql.split()) if name in _EXECUTION_TABLES and sql is not None else sql)
    if actual != expected:
        _deny('AUDIT_SCHEMA_CONFLICT')


@dataclass(frozen=True, slots=True, init=False, eq=False, repr=False)
class LocalTestInfrastructureAudit:
    """Trusted harness registration; requesters get append and two handles only.

    All source sampling and the sole INSERT share one FULL synchronous SQLite
    transaction. Replays return immutable history, with fresh authorization and
    revalidation of sources, but without observing or changing physical state.
    """
    _path: str
    _approval: object
    _policy: object
    _verifier: object
    _verification: object
    _grant: AuditGrant
    _binding: AuditBinding
    _clock: TestClock
    _source_digest: str
    _verification_digest: str
    _binding_digest: str
    _auditors: tuple
    _bindings: tuple

    def __init__(self, *, database_path, policy_sources, execution_approval,
                 verifier_grant, verification_binding, audit_grant, audit_binding, clock):
        if hasattr(self, '_path'):
            _deny('AUDIT_ALREADY_INITIALIZED')
        source = _source(execution_approval, policy_sources)
        _grant_binding(verifier_grant, verification_binding, execution_approval)
        _record(clock, TestClock)
        g, b, a = audit_grant, audit_binding, execution_approval
        if (type(g) is not AuditGrant or not _id(g.grant_id) or not _version(g.grant_version)
                or not _scope(g.scope) or type(g.role) is not str or g.role != 'AUDITOR'
                or type(g.capability) is not str or g.capability != 'APPEND_FICTIONAL_AUDIT'
                or type(g.status) is not str or g.status not in ('ACTIVE', 'REVOKED')
                or not _clock(g.issued_at) or not _clock(g.expires_at)
                or g.issued_at.microsecond or g.expires_at.microsecond):
            _deny('INVALID_AUDIT_GRANT')
        if (type(b) is not AuditBinding or not _scope(b.scope)
                or not all(_id(v) for v in (b.execution_id, b.auditor_id, b.grant_id))
                or not _version(b.execution_version) or not _version(b.grant_version)
                or not all(_digest(v) for v in (b.execution_digest, b.verification_binding_digest,
                                               b.verification_evidence_digest))):
            _deny('INVALID_AUDIT_BINDING')
        v_digest = _hash(b'avuhz.local-infrastructure-verification.BINDING.v1\n',
                         {'binding': asdict(verification_binding), 'grant': asdict(verifier_grant)})
        d, m = a.diagnostic, a.diagnostic.pins.manifest
        if (b.scope != m.scope or g.scope != replace(b.scope, identity_id=b.auditor_id)
                or b.auditor_id in (m.scope.identity_id, d.pins.observation.observer_id,
                                   d.human_id, d.executor_id, verification_binding.verifier_id)
                or (b.execution_id, b.execution_version, b.execution_digest)
                != (a.execution_id, a.execution_version, _approval_digest(a))
                or b.verification_binding_digest != v_digest
                or (b.grant_id, b.grant_version) != (g.grant_id, g.grant_version)
                or (d.pins.observation.current_digest, d.pins.observation.current_version)
                != (m.expected_current_digest, m.expected_current_version)):
            _deny('AUDIT_BINDING_MISMATCH')
        if (type(database_path) is not str or not database_path.startswith('/tmp/')
                or len(database_path) > 4096 or '\x00' in database_path):
            _deny('INVALID_TEST_DATABASE_PATH')
        try:
            path = Path(database_path)
            if path.is_symlink() or not path.resolve().is_relative_to(Path('/tmp')) or not path.is_file():
                _deny('INVALID_TEST_DATABASE_PATH')
        except (OSError, ValueError, RuntimeError):
            _deny('INVALID_TEST_DATABASE_PATH')
        for key, value in dict(
                _path=str(path.resolve()), _approval=a,
                _policy=LocalTestInfrastructurePolicyAdapter(**policy_sources),
                _verifier=verifier_grant, _verification=verification_binding,
                _grant=g, _binding=b, _clock=clock, _source_digest=source,
                _verification_digest=v_digest, _binding_digest=_hash(
                    b'avuhz.local-infrastructure-audit.BINDING.v1\n',
                    {'binding': asdict(b), 'grant': asdict(g)}),
                _auditors=((object(), g),), _bindings=((object(), b),)).items():
            object.__setattr__(self, key, value)
        if not self._authorized():
            _deny('AUDIT_AUTHORIZATION_DENIED')
        try:
            with closing(self._connect()) as db, db:
                db.execute('BEGIN IMMEDIATE')
                _schema(db, audit=False)
                # Check registered inputs before even provisioning audit storage.
                self._sources(db)
                found = db.execute('SELECT 1 FROM sqlite_master WHERE name=?',
                                   ('local_audit_evidence',)).fetchone()
                if found is None:
                    # Constant DDL only, under the trusted harness constructor.
                    for _, _, sql in _SCHEMA:
                        db.execute(sql)
                _schema(db, audit=True)
        except (sqlite3.Error, OSError):
            _deny('AUDIT_STORAGE_UNAVAILABLE')

    @property
    def auditor_handle(self):
        """Harness-only distribution; no public enrollment surface."""
        return self._auditors[0][0]

    @property
    def binding_handle(self):
        return self._bindings[0][0]

    def _connect(self):
        db = sqlite3.connect(Path(self._path).as_uri() + '?mode=rw', uri=True,
                             timeout=5, isolation_level=None, cached_statements=0)
        try:
            db.execute('PRAGMA trusted_schema=OFF')
            db.execute('PRAGMA recursive_triggers=ON')
            db.execute('PRAGMA synchronous=FULL')
            if (db.execute('PRAGMA synchronous').fetchone() != (2,)
                    or db.execute('PRAGMA journal_mode').fetchone()[0]
                    not in ('delete', 'truncate', 'persist', 'wal')):
                _deny('AUDIT_DURABILITY_UNAVAILABLE')
            return db
        except BaseException:
            db.close()
            raise

    def _authorized(self):
        now, p, d = self._clock.now, self._policy, self._approval.diagnostic
        grants = (self._grant, self._verifier, *p._grants, *(h for _, h in p._humans))
        if (self._approval.status != 'ACTIVE'
                or not _fresh(self._clock.issued_at, self._clock.expires_at, now)
                or p._clock.now != now or not _fresh(p._clock.issued_at, p._clock.expires_at, now)
                or not _fresh(d.issued_at, d.expires_at, now)
                or any(g.status != 'ACTIVE' or not _fresh(g.issued_at, g.expires_at, now) for g in grants)):
            return False
        # CONSUMED is historical reservation evidence, never reusable permission.
        for e in p._consumption.entries:
            if (e.approval_id == d.approval_id or e.request_id == d.pins.slot.request_id
                    or e.challenge == d.pins.slot.challenge or e.operation_digest == d.pins.operation_digest):
                if (e.status != 'CONSUMED' or (e.approval_id, e.approval_version, e.request_id,
                        e.challenge, e.operation_digest) != (d.approval_id, d.approval_version,
                        d.pins.slot.request_id, d.pins.slot.challenge, d.pins.operation_digest)):
                    return False
        for e in p._trust._replay.entries:
            if (e.request_id == d.pins.slot.request_id or e.challenge == d.pins.slot.challenge):
                if (e.request_id, e.challenge, e.operation_digest) != (
                        d.pins.slot.request_id, d.pins.slot.challenge, d.pins.operation_digest):
                    return False
        return True

    def _sources(self, db):
        a, d, b = self._approval, self._approval.diagnostic, self._binding
        expected = (a.execution_id, a.execution_version, d.approval_id, d.approval_version,
                    d.pins.slot.request_id, d.pins.slot.challenge, _scope_key(b.scope), _approval_digest(a))
        registry = db.execute('SELECT ' + _SOURCE_COLUMNS + ',revoked,consumed FROM execution_registry '
                              'WHERE execution_id=?', (b.execution_id,)).fetchall()
        attempts = db.execute('SELECT ' + _SOURCE_COLUMNS + ',outcome FROM local_attempts '
                              'WHERE execution_id=?', (b.execution_id,)).fetchall()
        if (len(registry) != 1 or len(attempts) != 1 or registry[0] != (*expected, 0, 1)
                or attempts[0][:8] != expected
                or any(type(v) is not type(e) for v, e in zip(registry[0], (*expected, 0, 1)))
                or any(type(v) is not type(e) for v, e in zip(attempts[0][:8], expected))
                or attempts[0][8] not in ('ATTEMPTED', 'UNCERTAIN')):
            _deny('AUDIT_EXECUTION_CONFLICT')
        rows = db.execute('SELECT * FROM local_verification_evidence WHERE execution_id=? '
                          'AND scope=? AND verifier_id=?',
                          (b.execution_id, expected[6], self._verification.verifier_id)).fetchall()
        m = d.pins.manifest
        prefix = (b.execution_id, expected[6], self._verification.verifier_id,
                  self._verification_digest, self._source_digest, b.execution_digest,
                  d.pins.operation_digest, m.desired_digest, m.desired_version,
                  m.expected_current_digest, m.expected_current_version)
        if len(rows) != 1 or len(rows[0]) != 17:
            _deny('AUDIT_VERIFICATION_CONFLICT')
        v = rows[0]
        if (v[:11] != prefix or any(type(x) is not type(y) for x, y in zip(v[:11], prefix))
                or not _digest(v[11]) or not _version(v[12])
                or type(v[13]) is not str or v[13] not in ('ATTEMPTED', 'UNCERTAIN')
                or type(v[14]) is not str or v[14] not in ('LOCAL_STATE_MATCH', 'PENDING', 'MISMATCH')
                or type(v[15]) is not str or len(v[15]) != 20 or not _digest(v[16])
                or (v[13] == 'UNCERTAIN' and attempts[0][8] != 'UNCERTAIN')
                or v[16] != _verification_hash(v[:16]) or v[16] != b.verification_evidence_digest):
            _deny('AUDIT_VERIFICATION_CONFLICT')
        reason = ('LOCAL_STATE_MATCH' if v[11:13] == (m.desired_digest, m.desired_version)
                  else 'PENDING' if v[11:13] == (m.expected_current_digest, m.expected_current_version)
                  else 'MISMATCH')
        observed = _time(v[15])
        if (v[14] != reason or observed > self._clock.now
                or not _fresh(self._verifier.issued_at, self._verifier.expires_at, observed)
                or not _fresh(d.issued_at, d.expires_at, observed)):
            _deny('AUDIT_VERIFICATION_CONFLICT')
        return registry[0], attempts[0], v

    def _row(self, registry, attempt, verification, recorded_at):
        b, d, v = self._binding, self._approval.diagnostic, verification
        return (b.execution_id, b.execution_version, _scope_key(b.scope), b.auditor_id,
                self._binding_digest, self._source_digest, b.execution_digest,
                d.pins.operation_digest, d.policy_decision_digest,
                _hash(b'avuhz.local-infrastructure-audit.APPROVAL.v1\n', asdict(d)),
                d.pins.manifest.manifest_digest, d.pins.source_digest,
                _hash(b'avuhz.local-infrastructure-audit.RESERVATION.v1\n', registry),
                _hash(b'avuhz.local-infrastructure-audit.ATTEMPT.v1\n', attempt),
                self._verification_digest, v[16], v[2], attempt[8], v[13], v[14],
                v[11], v[12], v[15], recorded_at)

    def append(self, *, auditor_handle, binding_handle):
        try:
            _resolve(self._auditors, auditor_handle)
            _resolve(self._bindings, binding_handle)
        except LocalInfrastructureDenied:
            return AuditResult('AUTHORIZATION_DENIED')
        if not self._authorized():
            return AuditResult('AUTHORIZATION_DENIED')
        try:
            with closing(self._connect()) as db, db:
                db.set_authorizer(_write_authorizer)
                db.execute('BEGIN IMMEDIATE')
                _schema(db, audit=True)
                registry, attempt, verification = self._sources(db)
                rows = db.execute('SELECT * FROM local_audit_evidence WHERE execution_id=? '
                                  'OR binding_digest=? OR verification_evidence_digest=?',
                                  (self._binding.execution_id, self._binding_digest,
                                   self._binding.verification_evidence_digest)).fetchall()
                if rows:
                    row = rows[0]
                    if len(rows) != 1 or len(row) != len(_COLUMNS):
                        _deny('AUDIT_EVIDENCE_CONFLICT')
                    recorded = _time(row[23])
                    # Outcome may advance ATTEMPTED -> UNCERTAIN after sampling.
                    # Reconstruct the historical attempt digest, never upgrade it.
                    historical = (*attempt[:8], row[17])
                    if (row[17] not in ('ATTEMPTED', 'UNCERTAIN')
                            or (row[17] == 'UNCERTAIN' and attempt[8] != 'UNCERTAIN')
                            or not _time(row[22]) <= recorded <= self._clock.now
                            or not _fresh(self._grant.issued_at, self._grant.expires_at, recorded)
                            or row[:-1] != self._row(registry, historical, verification, row[23])
                            or row[-1] != _audit_hash(row[:-1])):
                        _deny('AUDIT_EVIDENCE_CONFLICT')
                    kind = 'HISTORICAL_REPLAY'
                else:
                    row = self._row(registry, attempt, verification,
                                    self._clock.now.isoformat().replace('+00:00', 'Z'))
                    row = (*row, _audit_hash(row))
                    db.execute('INSERT INTO local_audit_evidence VALUES (' +
                               ','.join('?' for _ in _COLUMNS) + ')', row)
                    # Detect a trigger that suppresses an insert before returning evidence.
                    if db.execute('SELECT * FROM local_audit_evidence WHERE execution_id=?',
                                  (self._binding.execution_id,)).fetchall() != [row]:
                        _deny('AUDIT_EVIDENCE_CONFLICT')
                    kind = 'SYNTHETIC_LOCAL_RECORD'
            # Return only after commit succeeds, including replay transaction close.
            return AuditResult('AUDIT_RECORDED', kind, row[17], row[18], row[19], row[15],
                               row[22], row[23], row[24])
        except (sqlite3.Error, OSError, LocalInfrastructureDenied):
            return AuditResult('CONFLICT')
