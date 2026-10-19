"""Synthetic LOCAL/TEST poststate observations, never execution certification.

Harness provisioning, filesystem and SQLite are trusted. Handles are in-process
capabilities, not authentication. Hashes detect inconsistent evidence, not a
coherent rewrite by a hostile database owner. No causal or timing attestation.
"""
from contextlib import closing
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime
from pathlib import Path
import sqlite3

from avuhz_runtime.local_infrastructure_authority import (
    LocalInfrastructureDenied, ResourceScope, _clock, _digest, _fresh, _id, _scope, _version,
)
from avuhz_runtime.local_infrastructure_execution import (
    ExecutionApproval, _approval_digest, _scope_key,
)
from avuhz_runtime.local_infrastructure_policy import (
    ExplicitApproval, LocalTestInfrastructurePolicyAdapter, _hash, _validate,
    policy_decision_digest, source_observation_digest,
)
from avuhz_runtime.local_infrastructure_trust import TestClock, _deny, _record, _resolve


@dataclass(frozen=True, slots=True)
class VerifierGrant:
    grant_id: str
    grant_version: int
    scope: ResourceScope  # Identity is the verifier, never the requester.
    role: str
    capability: str
    status: str
    issued_at: datetime
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class VerificationBinding:
    scope: ResourceScope  # Exact execution principal and resource scope.
    execution_id: str
    execution_version: int
    execution_digest: str
    verifier_id: str
    grant_id: str
    grant_version: int


@dataclass(frozen=True, slots=True)
class VerificationResult:
    reason_code: str
    observation_kind: str = 'NONE'
    observed_digest: str = ''
    observed_version: int = 0
    evidence_digest: str = ''
    authority_effect: str = field(default='NONE', init=False)


_TABLE = '''CREATE TABLE local_verification_evidence (
    execution_id TEXT NOT NULL, scope TEXT NOT NULL, verifier_id TEXT NOT NULL,
    binding_digest TEXT NOT NULL, source_digest TEXT NOT NULL,
    execution_digest TEXT NOT NULL, operation_digest TEXT NOT NULL,
    desired_digest TEXT NOT NULL, desired_version INTEGER NOT NULL CHECK(desired_version>0),
    prestate_digest TEXT NOT NULL, prestate_version INTEGER NOT NULL CHECK(prestate_version>0),
    observed_digest TEXT NOT NULL CHECK(length(observed_digest)=71),
    observed_version INTEGER NOT NULL CHECK(observed_version>0),
    execution_outcome TEXT NOT NULL CHECK(execution_outcome IN ('ATTEMPTED','UNCERTAIN')),
    reason_code TEXT NOT NULL CHECK(reason_code IN ('LOCAL_STATE_MATCH','PENDING','MISMATCH')),
    observed_at TEXT NOT NULL, evidence_digest TEXT NOT NULL CHECK(length(evidence_digest)=71),
    PRIMARY KEY(execution_id,scope,verifier_id))'''
_UPDATE = '''CREATE TRIGGER local_verification_no_update BEFORE UPDATE ON local_verification_evidence
    BEGIN SELECT RAISE(ABORT, 'IMMUTABLE_EVIDENCE'); END'''
_DELETE = '''CREATE TRIGGER local_verification_no_delete BEFORE DELETE ON local_verification_evidence
    BEGIN SELECT RAISE(ABORT, 'IMMUTABLE_EVIDENCE'); END'''
_INSERT = '''CREATE TRIGGER local_verification_no_replace BEFORE INSERT ON local_verification_evidence
    WHEN EXISTS (SELECT 1 FROM local_verification_evidence WHERE execution_id=NEW.execution_id
                 AND scope=NEW.scope AND verifier_id=NEW.verifier_id)
    BEGIN SELECT RAISE(ABORT, 'IMMUTABLE_EVIDENCE'); END'''
_SCHEMA = (('local_verification_evidence', 'table', _TABLE),
           ('local_verification_no_replace', 'trigger', _INSERT),
           ('local_verification_no_update', 'trigger', _UPDATE),
           ('local_verification_no_delete', 'trigger', _DELETE))
_COLUMNS = ('execution_id,execution_version,approval_id,approval_version,request_id,'
            'challenge,scope,digest')


def _source(approval, sources):
    """Validate pinned historical sources without comparing poststate to prestate."""
    if type(approval) is not ExecutionApproval or type(sources) is not dict:
        _deny('INVALID_EXECUTION_SOURCE')
    _validate(approval.diagnostic, ExplicitApproval)
    if (not _id(approval.execution_id) or not _version(approval.execution_version)
            or type(approval.operation) is not str or approval.operation != 'APPLY_FICTIONAL_STATE'
            or type(approval.status) is not str or approval.status != 'ACTIVE'):
        _deny('INVALID_EXECUTION_SOURCE')
    keys = ('grants', 'ownership', 'manifests', 'observations', 'slots', 'clock',
            'replay', 'policies', 'humans', 'approvals', 'consumption')
    if any(type(k) is not str for k in sources) or set(sources) != set(keys):
        _deny('INVALID_EXECUTION_SOURCE')
    p = LocalTestInfrastructurePolicyAdapter(**sources)
    d, pins = approval.diagnostic, approval.diagnostic.pins
    m, o, s = pins.manifest, pins.observation, pins.slot
    rule = next((r for r in p._policies if r.policy_id == d.policy_id), None)
    observer = next((g for g in p._grants if g.scope.identity_id == o.observer_id), None)
    human = next((h for _, h in p._humans if h.scope.identity_id == d.human_id), None)
    principal = next((g for g in p._grants if g.scope == m.scope), None)
    request = asdict(m.scope)
    request.update({k: getattr(m, k) for k in ('manifest_digest', 'manifest_version',
                   'desired_digest', 'desired_version', 'expected_current_digest',
                   'expected_current_version')})
    request.update(schema_version=1, operation='COMPARE_FICTIONAL_STATE',
                   request_id=s.request_id, challenge=s.challenge, observation_id=o.observation_id,
                   issued_at=s.issued_at.isoformat().replace('+00:00', 'Z'),
                   expires_at=s.expires_at.isoformat().replace('+00:00', 'Z'))
    if (not any(a == d for _, a in p._approvals) or m not in p._manifests
            or o not in p._observations or s not in p._slots or rule is None
            or s.manifest_id != m.manifest_id or s.observation_id != o.observation_id
            or s.principal_id != m.scope.identity_id or o.scope != m.scope
            or observer is None or human is None or principal is None
            or human.scope != replace(m.scope, identity_id=d.human_id)
            or len({m.scope.identity_id, o.observer_id, d.human_id, d.executor_id}) != 4
            or any(g.status != 'ACTIVE' for g in (principal, observer, human))
            or d.decision != 'APPROVE' or rule.decision != 'ALLOW'
            or d.policy_version != 1 or rule.policy_version != 1 or rule.pins != pins
            or d.policy_decision_digest != policy_decision_digest(rule)
            or pins.source_digest != source_observation_digest(o, observer)
            or pins.operation_digest != _hash(b'avuhz.local-infrastructure-authority.v1\n', request)):
        _deny('EXECUTION_SOURCE_MISMATCH')
    # Historical source consistency only. Do not rerun compare/review_approval or
    # check the old observation's freshness against the verification clock.
    return _hash(b'avuhz.local-infrastructure-verification.SOURCE.v1\n',
                 {'execution': asdict(approval), 'rule': asdict(rule),
                  'principal': asdict(principal), 'observer': asdict(observer),
                  'human': asdict(human)})


def _grant_binding(grant, binding, approval):
    if (type(grant) is not VerifierGrant or not _id(grant.grant_id)
            or not _version(grant.grant_version) or not _scope(grant.scope)
            or type(grant.role) is not str or grant.role != 'VERIFIER'
            or type(grant.capability) is not str or grant.capability != 'OBSERVE_FICTIONAL_POSTSTATE'
            or type(grant.status) is not str or grant.status not in ('ACTIVE', 'REVOKED')
            or not _clock(grant.issued_at) or not _clock(grant.expires_at)
            or grant.issued_at.microsecond or grant.expires_at.microsecond):
        _deny('INVALID_VERIFIER_GRANT')
    if (type(binding) is not VerificationBinding or not _scope(binding.scope)
            or not all(_id(v) for v in (binding.execution_id, binding.verifier_id, binding.grant_id))
            or not _version(binding.execution_version) or not _version(binding.grant_version)
            or not _digest(binding.execution_digest)):
        _deny('INVALID_VERIFICATION_BINDING')
    d = approval.diagnostic
    if (binding.scope != d.pins.manifest.scope
            or grant.scope != replace(binding.scope, identity_id=binding.verifier_id)
            or binding.verifier_id in (binding.scope.identity_id, d.pins.observation.observer_id,
                                      d.human_id, d.executor_id)
            or (binding.execution_id, binding.execution_version, binding.execution_digest)
            != (approval.execution_id, approval.execution_version, _approval_digest(approval))
            or (binding.grant_id, binding.grant_version) != (grant.grant_id, grant.grant_version)):
        _deny('VERIFICATION_BINDING_MISMATCH')


def _evidence_hash(row):
    return _hash(b'avuhz.local-infrastructure-verification.OBSERVATION.v1\n', row)


def _write_authorizer(action, table, column, database, trigger):
    # Applied after schema provisioning. Even an injected INSERT trigger cannot
    # write an execution table. This is defense in depth, not an OS boundary.
    if action == sqlite3.SQLITE_INSERT and table == 'local_verification_evidence' and trigger is None:
        return sqlite3.SQLITE_OK
    if action in (sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_TRANSACTION,
                  sqlite3.SQLITE_FUNCTION):
        return sqlite3.SQLITE_OK
    return sqlite3.SQLITE_DENY


@dataclass(frozen=True, slots=True, init=False, eq=False, repr=False)
class LocalTestInfrastructureVerification:
    """Harness-only immutable registration; public calls take two opaque handles.

    Serial writer reservation surrounds a separate read-only snapshot. Only the
    evidence table is written. Replays return the stored HISTORICAL observation;
    no continuing state, execution success, or causal effect is asserted.
    """
    _path: str
    _approval: ExecutionApproval
    _grant: VerifierGrant
    _binding: VerificationBinding
    _clock: TestClock
    _source_digest: str
    _binding_digest: str
    _verifiers: tuple
    _bindings: tuple

    def __init__(self, *, database_path, policy_sources, execution_approval,
                 verifier_grant, verification_binding, clock):
        if hasattr(self, '_path'):
            _deny('ALREADY_INITIALIZED')
        source = _source(execution_approval, policy_sources)
        _grant_binding(verifier_grant, verification_binding, execution_approval)
        _record(clock, TestClock)
        if (type(database_path) is not str or not database_path.startswith('/tmp/')
                or len(database_path) > 4096 or '\x00' in database_path):
            _deny('INVALID_TEST_DATABASE_PATH')
        try:
            path = Path(database_path)
            if path.is_symlink() or not path.resolve().is_relative_to(Path('/tmp')) or not path.is_file():
                _deny('INVALID_TEST_DATABASE_PATH')
        except (OSError, ValueError, RuntimeError):
            _deny('INVALID_TEST_DATABASE_PATH')
        for key, value in dict(_path=str(path.resolve()), _approval=execution_approval,
                               _grant=verifier_grant, _binding=verification_binding, _clock=clock,
                               _source_digest=source, _binding_digest=_hash(
                                   b'avuhz.local-infrastructure-verification.BINDING.v1\n',
                                   {'binding': asdict(verification_binding),
                                    'grant': asdict(verifier_grant)}),
                               _verifiers=((object(), verifier_grant),),
                               _bindings=((object(), verification_binding),)).items():
            object.__setattr__(self, key, value)
        try:
            with closing(self._connect('rw')) as db, db:
                db.execute('BEGIN IMMEDIATE')
                self._snapshot(require_attempt=False)
                existing = db.execute("SELECT type FROM sqlite_master WHERE name=?",
                                      ('local_verification_evidence',)).fetchone()
                if existing is None:
                    for _, _, sql in _SCHEMA:
                        db.execute(sql)
                self._schema(db)
        except (sqlite3.Error, OSError):
            _deny('VERIFICATION_STORAGE_UNAVAILABLE')

    @property
    def verifier_handle(self):
        return self._verifiers[0][0]

    @property
    def binding_handle(self):
        return self._bindings[0][0]

    def _connect(self, mode):
        return sqlite3.connect(Path(self._path).as_uri() + '?mode=' + mode,
                               uri=True, timeout=5, isolation_level=None)

    def _schema(self, db):
        for name, kind, sql in _SCHEMA:
            if db.execute('SELECT type,sql FROM sqlite_master WHERE name=?', (name,)).fetchone() != (kind, sql):
                _deny('VERIFICATION_SCHEMA_CONFLICT')
        if db.execute("SELECT name FROM sqlite_master WHERE type='trigger' AND "
                      "tbl_name='local_verification_evidence' ORDER BY name").fetchall() != [
                          ('local_verification_no_delete',), ('local_verification_no_replace',),
                          ('local_verification_no_update',)]:
            _deny('VERIFICATION_SCHEMA_CONFLICT')

    def _snapshot(self, *, require_attempt=True):
        a, d = self._approval, self._approval.diagnostic
        expected = (a.execution_id, a.execution_version, d.approval_id, d.approval_version,
                    d.pins.slot.request_id, d.pins.slot.challenge,
                    _scope_key(d.pins.manifest.scope), _approval_digest(a))
        with closing(self._connect('ro')) as db:
            db.execute('BEGIN')
            for name in ('execution_registry', 'local_attempts', 'simulated_resource_state'):
                if db.execute('SELECT type FROM sqlite_master WHERE name=?', (name,)).fetchone() != ('table',):
                    _deny('EXECUTION_SCHEMA_CONFLICT')
            registry = db.execute('SELECT ' + _COLUMNS + ',revoked,consumed FROM execution_registry '
                                  'WHERE execution_id=?', (a.execution_id,)).fetchall()
            attempts = db.execute('SELECT ' + _COLUMNS + ',outcome FROM local_attempts '
                                  'WHERE execution_id=?', (a.execution_id,)).fetchall()
            states = db.execute('SELECT digest,version FROM simulated_resource_state WHERE scope=?',
                                (expected[6],)).fetchall()
        if (len(registry) != 1
                or any(type(v) is not type(e) for v, e in zip(registry[0][:8], expected))
                or registry[0][:8] != expected or registry[0][8] != 0
                or type(registry[0][8]) is not int or type(registry[0][9]) is not int
                or registry[0][9] not in (0, 1)):
            _deny('EXECUTION_REGISTRY_CONFLICT')
        if not attempts and not require_attempt and registry[0][9] == 0:
            return None, states
        if (len(attempts) != 1
                or any(type(v) is not type(e) for v, e in zip(attempts[0][:8], expected))
                or attempts[0][:8] != expected or registry[0][9] != 1
                or attempts[0][8] not in ('ATTEMPTED', 'UNCERTAIN')):
            _deny('EXECUTION_ATTEMPT_CONFLICT')
        return attempts[0][8], states

    def _prefix(self):
        b, m = self._binding, self._approval.diagnostic.pins.manifest
        return (b.execution_id, _scope_key(b.scope), b.verifier_id, self._binding_digest,
                self._source_digest, b.execution_digest, self._approval.diagnostic.pins.operation_digest,
                m.desired_digest, m.desired_version, m.expected_current_digest, m.expected_current_version)

    def _reason(self, digest, version):
        m = self._approval.diagnostic.pins.manifest
        if (digest, version) == (m.desired_digest, m.desired_version):
            return 'LOCAL_STATE_MATCH'
        if (digest, version) == (m.expected_current_digest, m.expected_current_version):
            return 'PENDING'
        return 'MISMATCH'

    def verify(self, *, verifier_handle, binding_handle):
        try:
            _resolve(self._verifiers, verifier_handle)
            _resolve(self._bindings, binding_handle)
            g, c = self._grant, self._clock
            if (g.status != 'ACTIVE' or not _fresh(g.issued_at, g.expires_at, c.now)
                    or not _fresh(c.issued_at, c.expires_at, c.now)):
                return VerificationResult('AUTHORIZATION_DENIED')
            with closing(self._connect('rw')) as db, db:
                db.execute('PRAGMA synchronous=FULL')
                db.set_authorizer(_write_authorizer)
                db.execute('BEGIN IMMEDIATE')
                self._schema(db)
                outcome, states = self._snapshot()
                prefix = self._prefix()
                rows = db.execute('SELECT * FROM local_verification_evidence WHERE '
                                  'execution_id=? AND scope=? AND verifier_id=?', prefix[:3]).fetchall()
                if rows:
                    row = rows[0]
                    if (len(rows) != 1 or len(row) != 17 or row[:11] != prefix
                            or not _digest(row[11]) or not _version(row[12])
                            or row[13] not in ('ATTEMPTED', 'UNCERTAIN')
                            or row[14] != self._reason(row[11], row[12])
                            or type(row[15]) is not str or len(row[15]) != 20
                            or row[16] != _evidence_hash(row[:16])):
                        _deny('EVIDENCE_CONFLICT')
                    return VerificationResult(row[14], 'HISTORICAL', row[11], row[12], row[16])
                if len(states) != 1 or not _digest(states[0][0]) or not _version(states[0][1]):
                    _deny('OBSERVATION_CONFLICT')
                digest, version = states[0]
                reason = self._reason(digest, version)
                row = (*prefix, digest, version, outcome, reason,
                       c.now.isoformat().replace('+00:00', 'Z'))
                evidence = _evidence_hash(row)
                db.execute('INSERT INTO local_verification_evidence VALUES '
                           '(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', (*row, evidence))
            return VerificationResult(reason, 'SYNTHETIC_LOCAL_SNAPSHOT', digest, version, evidence)
        except (sqlite3.Error, OSError, LocalInfrastructureDenied):
            return VerificationResult('CONFLICT')
