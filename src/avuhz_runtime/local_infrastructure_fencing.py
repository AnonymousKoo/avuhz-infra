"""Durable pre-dispatch fencing for the trusted LOCAL/TEST SQLite harness.

Every fictional physical write by the original executor shares the transaction
that checks this protocol and records dispatch. No external dispatcher exists.
Legacy executions are deliberately never enrolled after registration.
"""
from avuhz_runtime.local_infrastructure_trust import _deny


def _definition(name):
    table = f'''CREATE TABLE {name} (
    execution_id TEXT PRIMARY KEY NOT NULL, scope TEXT NOT NULL, digest TEXT NOT NULL)'''
    return (
        (name, 'table', table),
        (name + '_update', 'trigger', f"CREATE TRIGGER {name}_update BEFORE UPDATE ON {name} BEGIN SELECT RAISE(ABORT, 'IMMUTABLE_FENCE'); END"),
        (name + '_delete', 'trigger', f"CREATE TRIGGER {name}_delete BEFORE DELETE ON {name} BEGIN SELECT RAISE(ABORT, 'IMMUTABLE_FENCE'); END"),
        (name + '_insert', 'trigger', f"CREATE TRIGGER {name}_insert BEFORE INSERT ON {name} BEGIN SELECT RAISE(ABORT, 'IMMUTABLE_FENCE') WHERE EXISTS (SELECT 1 FROM {name} WHERE execution_id=NEW.execution_id); SELECT RAISE(ABORT, 'FENCE_CAPACITY') WHERE (SELECT count(*) FROM {name})>=256; END"),
    )


_TABLES = ('local_execution_fence_protocol', 'local_execution_dispatches', 'local_execution_fences')
_SCHEMA = tuple(item for name in _TABLES for item in _definition(name))


def _schema(db):
    if not db.in_transaction:
        _deny('FENCE_TRANSACTION_REQUIRED')
    expected = {name: (kind, sql) for name, kind, sql in _SCHEMA}
    expected.update({f'sqlite_autoindex_{name}_1': ('index', None) for name in _TABLES})
    actual = {name: (kind, sql) for kind, name, table, sql in db.execute(
        'SELECT type,name,tbl_name,sql FROM sqlite_master') if table in _TABLES or name in expected}
    if actual != expected:
        _deny('FENCE_SCHEMA_CONFLICT')


def provision(db):
    """Trusted execution provisioning only; never enrolls existing executions."""
    if not db.in_transaction:
        _deny('FENCE_TRANSACTION_REQUIRED')
    existing = db.execute('SELECT name FROM sqlite_master WHERE name IN (?,?,?)', _TABLES).fetchall()
    if not existing:
        for _, _, sql in _SCHEMA:
            db.execute(sql)
    _schema(db)


def register(db, execution_id, scope, digest):
    """Called solely alongside a NEW execution_registry INSERT, never backfilled."""
    _schema(db)
    row = db.execute('SELECT scope,digest,revoked,consumed FROM execution_registry WHERE execution_id=?',
                     (execution_id,)).fetchone()
    if row not in ((scope, digest, 0, 0), (scope, digest, 1, 0)):
        _deny('FENCE_REGISTRATION_DENIED')
    db.execute('INSERT INTO local_execution_fence_protocol VALUES (?,?,?)',
               (execution_id, scope, digest))


def _registered(db, execution_id, scope, digest):
    _schema(db)
    expected = (execution_id, scope, digest)
    if db.execute('SELECT * FROM local_execution_fence_protocol WHERE execution_id=?',
                  (execution_id,)).fetchall() != [expected]:
        _deny('FENCE_PROTOCOL_REQUIRED')
    registry = db.execute('SELECT scope,digest,revoked,consumed FROM execution_registry WHERE execution_id=?',
                          (execution_id,)).fetchall()
    attempts = db.execute('SELECT scope,digest,outcome FROM local_attempts WHERE execution_id=?',
                          (execution_id,)).fetchall()
    if registry != [(scope, digest, 0, 1)] or attempts != [(scope, digest, 'ATTEMPTED')]:
        _deny('FENCE_ORIGINAL_UNRESOLVED')
    return expected


def dispatch(db, execution_id, scope, digest):
    """Same BEGIN IMMEDIATE transaction as ALL original physical mutations."""
    expected = _registered(db, execution_id, scope, digest)
    if db.execute('SELECT 1 FROM local_execution_fences WHERE execution_id=?', (execution_id,)).fetchone():
        _deny('ORIGINAL_EXECUTION_FENCED')
    if db.execute('SELECT 1 FROM local_execution_dispatches WHERE execution_id=?', (execution_id,)).fetchone():
        _deny('ORIGINAL_ALREADY_DISPATCHED')
    db.execute('INSERT INTO local_execution_dispatches VALUES (?,?,?)', expected)


def fence(db, execution_id, scope, digest):
    """Prove no committed dispatch and permanently close future original writes.

    Caller MUST hold BEGIN IMMEDIATE; the original dispatch uses the same writer
    lock. A competing dispatcher either commits a receipt first (deny), or sees
    this immutable fence before any physical mutation (deny original dispatch).
    No outcome, observation, HOLD, timeout or caller quiescence claim is proof.
    """
    expected = _registered(db, execution_id, scope, digest)
    if db.execute('SELECT 1 FROM local_execution_dispatches WHERE execution_id=?', (execution_id,)).fetchone():
        _deny('ORIGINAL_ALREADY_DISPATCHED')
    old = db.execute('SELECT * FROM local_execution_fences WHERE execution_id=?', (execution_id,)).fetchall()
    if old:
        if old != [expected]:
            _deny('FENCE_BINDING_CONFLICT')
    else:
        db.execute('INSERT INTO local_execution_fences VALUES (?,?,?)', expected)
    return expected
