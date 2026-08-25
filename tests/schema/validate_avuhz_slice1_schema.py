"""Provider-neutral PostgreSQL catalog assertions for the Slice 1 schema."""
from __future__ import annotations
import os, re, subprocess, sys

TABLES = ('avuhz_acquisition_handoffs', 'avuhz_engagements', 'avuhz_diagnostic_scopes', 'avuhz_human_approvals', 'avuhz_idempotency_records', 'avuhz_lifecycle_events', 'avuhz_outbox_deliveries')
LEGACY = ('tenant_users', 'engagements', 'engagement_events')
VERSIONED = ('avuhz_engagements', 'avuhz_diagnostic_scopes', 'avuhz_idempotency_records', 'avuhz_outbox_deliveries')
FK_TARGETS = {'avuhz_engagements': 'avuhz_acquisition_handoffs', 'avuhz_diagnostic_scopes': 'avuhz_engagements', 'avuhz_human_approvals': 'avuhz_diagnostic_scopes', 'avuhz_outbox_deliveries': 'avuhz_lifecycle_events'}

def query(sql):
    dsn = os.environ.get("AVUHZ_POSTGRES_DSN")
    if dsn:
        import psycopg
        with psycopg.connect(dsn) as connection:
            with connection.cursor() as cursor:
                cursor.execute(sql)
                return ["t" if row[0] is True else "f" if row[0] is False else str(row[0]) for row in cursor.fetchall() if row[0] is not None]
    command = os.environ.get("SCHEMA_ASSERTION_PSQL")
    if not command: raise RuntimeError("AVUHZ_POSTGRES_DSN or SCHEMA_ASSERTION_PSQL must name a local PostgreSQL connection")
    result = subprocess.run(["bash", "-lc", f"{command} -At -v ON_ERROR_STOP=1 -c \"{sql}\""], check=True, capture_output=True, text=True)
    return [line for line in result.stdout.splitlines() if line]

def rejects_unknown_lifecycle_event_type():
    dsn = os.environ.get("AVUHZ_POSTGRES_DSN")
    if not dsn:
        try:
            query("begin; insert into public.avuhz_lifecycle_events (lifecycle_event_id, tenant_id, event_type, idempotency_key) values ('f4000000-0000-4000-8000-000000000001', 'f4000000-0000-4000-8000-000000000002', 'payment.verified', 'schema-assertion-unknown-event'); rollback;")
        except subprocess.CalledProcessError:
            return True
        return False
    import psycopg
    from psycopg.errors import CheckViolation
    try:
        with psycopg.connect(dsn) as connection:
            connection.execute("insert into public.avuhz_lifecycle_events (lifecycle_event_id, tenant_id, event_type, idempotency_key) values (%s, %s, %s, %s)", ("f4000000-0000-4000-8000-000000000001", "f4000000-0000-4000-8000-000000000002", "payment.verified", "schema-assertion-unknown-event"))
    except CheckViolation:
        return True
    return False

def accepts_diagnostic_scope_canonicalized_event_type():
    dsn = os.environ.get("AVUHZ_POSTGRES_DSN")
    if not dsn:
        try:
            query("begin; insert into public.avuhz_lifecycle_events (lifecycle_event_id, tenant_id, event_type, idempotency_key) values ('f4000000-0000-4000-8000-000000000003', 'f4000000-0000-4000-8000-000000000004', 'diagnostic_scope.canonicalized', 'schema-assertion-canonicalized-event'); rollback;")
        except subprocess.CalledProcessError:
            return False
        return True
    import psycopg
    with psycopg.connect(dsn) as connection:
        connection.execute("insert into public.avuhz_lifecycle_events (lifecycle_event_id, tenant_id, event_type, idempotency_key) values (%s, %s, %s, %s)", ("f4000000-0000-4000-8000-000000000003", "f4000000-0000-4000-8000-000000000004", "diagnostic_scope.canonicalized", "schema-assertion-canonicalized-event"))
        connection.rollback()
    return True



def rejects_unknown_idempotency_command_type():
    dsn = os.environ.get("AVUHZ_POSTGRES_DSN")
    if not dsn:
        try:
            query("begin; insert into public.avuhz_idempotency_records (id, tenant_id, trusted_principal_id, command_type, subject_type, subject_id, subject_version, idempotency_key, semantic_request_fingerprint, fingerprint_schema_version, processing_status, retention_class, attempt_count) values ('f5000000-0000-4000-8000-000000000001', 'f5000000-0000-4000-8000-000000000002', 'schema-assertion-principal', 'FutureCanonicalizeCommand', 'DIAGNOSTIC_SCOPE', 'f5000000-0000-4000-8000-000000000003', 1, 'schema-assertion-unknown-command', 'fpv1:schemaassertionunknowncommand', 'v1', 'RESERVED', 'OPERATIONAL_DEDUPLICATION', 0); rollback;")
        except subprocess.CalledProcessError:
            return True
        return False
    import psycopg
    from psycopg.errors import CheckViolation
    try:
        with psycopg.connect(dsn) as connection:
            connection.execute("insert into public.avuhz_idempotency_records (id, tenant_id, trusted_principal_id, command_type, subject_type, subject_id, subject_version, idempotency_key, semantic_request_fingerprint, fingerprint_schema_version, processing_status, retention_class, attempt_count) values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)", ("f5000000-0000-4000-8000-000000000001", "f5000000-0000-4000-8000-000000000002", "schema-assertion-principal", "FutureCanonicalizeCommand", "DIAGNOSTIC_SCOPE", "f5000000-0000-4000-8000-000000000003", 1, "schema-assertion-unknown-command", "fpv1:schemaassertionunknowncommand", "v1", "RESERVED", "OPERATIONAL_DEDUPLICATION", 0))
    except CheckViolation:
        return True
    return False

def accepts_canonicalize_diagnostic_scope_command_type():
    dsn = os.environ.get("AVUHZ_POSTGRES_DSN")
    if not dsn:
        try:
            query("begin; insert into public.avuhz_idempotency_records (id, tenant_id, trusted_principal_id, command_type, subject_type, subject_id, subject_version, idempotency_key, semantic_request_fingerprint, fingerprint_schema_version, processing_status, retention_class, attempt_count) values ('f5000000-0000-4000-8000-000000000004', 'f5000000-0000-4000-8000-000000000005', 'schema-assertion-principal', 'CanonicalizeDiagnosticScope', 'DIAGNOSTIC_SCOPE', 'f5000000-0000-4000-8000-000000000006', 1, 'schema-assertion-canonicalize-command', 'fpv1:schemaassertioncanonicalizecmd', 'v1', 'RESERVED', 'OPERATIONAL_DEDUPLICATION', 0); rollback;")
        except subprocess.CalledProcessError:
            return False
        return True
    import psycopg
    with psycopg.connect(dsn) as connection:
        connection.execute("insert into public.avuhz_idempotency_records (id, tenant_id, trusted_principal_id, command_type, subject_type, subject_id, subject_version, idempotency_key, semantic_request_fingerprint, fingerprint_schema_version, processing_status, retention_class, attempt_count) values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)", ("f5000000-0000-4000-8000-000000000004", "f5000000-0000-4000-8000-000000000005", "schema-assertion-principal", "CanonicalizeDiagnosticScope", "DIAGNOSTIC_SCOPE", "f5000000-0000-4000-8000-000000000006", 1, "schema-assertion-canonicalize-command", "fpv1:schemaassertioncanonicalizecmd", "v1", "RESERVED", "OPERATIONAL_DEDUPLICATION", 0))
        connection.rollback()
    return True


def require(ok, message):
    if not ok: raise AssertionError(message)
def sql_string_literals(expression):
    return frozenset(value.replace("''", "'") for value in re.findall(r"'((?:''|[^'])*)'", expression))

def main():
    available = set(query("select tablename from pg_tables where schemaname = 'public'"))
    require(set(TABLES) <= available, 'missing Slice 1 table')
    require(set(LEGACY) <= available, 'missing legacy coexistence table')
    for table in TABLES:
        columns = set(query(f"select column_name from information_schema.columns where table_schema = 'public' and table_name = '{table}'"))
        require({'tenant_id', 'created_at'} <= columns, f'{table} lacks tenant_id or created_at')
        require(query(f"select is_nullable from information_schema.columns where table_schema = 'public' and table_name = '{table}' and column_name = 'tenant_id'") == ['NO'], f'{table}.tenant_id is nullable')
        require(query(f"select conname from pg_constraint where contype = 'p' and conrelid = 'public.{table}'::regclass"), f'{table} lacks primary key')
        require(query(f"select rowsecurity::text from pg_tables where schemaname = 'public' and tablename = '{table}'") == ['true'], f'{table} RLS disabled')
        require(not query(f"select policyname from pg_policies where schemaname = 'public' and tablename = '{table}' and (qual = 'true' or with_check = 'true')"), f'{table} has broad direct-write policy')
        require(not query(f"select privilege_type from information_schema.role_table_grants where table_schema = 'public' and table_name = '{table}' and grantee in ('anon', 'authenticated', 'PUBLIC') and privilege_type in ('SELECT', 'INSERT', 'UPDATE', 'DELETE')"), f'{table} has broad application data grant')
        for role in ('anon', 'authenticated'):
            for privilege in ('SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER'):
                require(query(f"select has_table_privilege('{role}', 'public.{table}', '{privilege}')") == ['f'], f'{role} retains {privilege} on {table}')
    for table in VERSIONED:
        require(query(f"select column_name from information_schema.columns where table_schema = 'public' and table_name = '{table}' and column_name = 'record_version'") == ['record_version'], f'{table} lacks record_version')
    for table, target in FK_TARGETS.items():
        fks = set(query(f"select confrelid::regclass::text from pg_constraint where contype = 'f' and conrelid = 'public.{table}'::regclass"))
        require(target in fks or f'public.{target}' in fks, f'{table} lacks FK to {target}')
    checks = query("select conname from pg_constraint where contype = 'c' and conrelid in ('public.avuhz_engagements'::regclass, 'public.avuhz_diagnostic_scopes'::regclass)")
    require(len(checks) >= 3, 'closed vocabulary checks missing')
    for table, column in (('avuhz_acquisition_handoffs', 'accepted_at'), ('avuhz_diagnostic_scopes', 'canonical_scope_digest'), ('avuhz_outbox_deliveries', 'destination_reference'), ('avuhz_outbox_deliveries', 'delivery_idempotency_key')):
        require(query(f"select is_nullable from information_schema.columns where table_schema = 'public' and table_name = '{table}' and column_name = '{column}'") == ['YES'], f'{table}.{column} must represent absent runtime value')
    for column in ('event_schema_version', 'authoritative_subject_type', 'authoritative_subject_id', 'authoritative_subject_version', 'occurred_at', 'producer_reference', 'correlation_id', 'visibility', 'sanitized_metadata'):
        require(query(f"select is_nullable from information_schema.columns where table_schema = 'public' and table_name = 'avuhz_lifecycle_events' and column_name = '{column}'") == ['YES'], f'lifecycle event envelope cannot represent {column}')
    event_check = query("select pg_get_constraintdef(oid) from pg_constraint where conrelid = 'public.avuhz_lifecycle_events'::regclass and conname = 'avuhz_lifecycle_events_event_type_check'")
    require(len(event_check) == 1, 'lifecycle event type check is missing')
    event_literals = sql_string_literals(event_check[0])
    for event_type in ('engagement.handoff.accepted', 'engagement.opened', 'diagnostic_scope.submitted', 'diagnostic_scope.approved', 'diagnostic_scope.rejected', 'human_approval.recorded', 'diagnostic_scope.canonicalized', 'diagnostic_payment.verified', 'diagnostic_payment.invalidated'):
        require(event_type in event_literals, f'lifecycle event type {event_type} is not allowed')
    for event_type in ('payment.verified', 'payment.invalidated'):
        require(event_type not in event_literals, f'lifecycle event type {event_type} is not closed')
    require(accepts_diagnostic_scope_canonicalized_event_type(), 'diagnostic_scope.canonicalized lifecycle event type was rejected')
    require(rejects_unknown_lifecycle_event_type(), 'unsupported lifecycle event type was accepted')
    idempotency_check = query("select pg_get_constraintdef(oid) from pg_constraint where conrelid = 'public.avuhz_idempotency_records'::regclass and conname = 'avuhz_idempotency_records_command_type_check'")
    idempotency_unique = query("select pg_get_constraintdef(oid) from pg_constraint where conrelid = 'public.avuhz_idempotency_records'::regclass and contype = 'u'")
    require(any('UNIQUE (tenant_id, trusted_principal_id, command_type, subject_type, idempotency_scope, idempotency_key)' in definition for definition in idempotency_unique), 'command-scoped idempotency uniqueness drifted')
    require(len(idempotency_check) == 1 and 'RecordHumanApproval' in idempotency_check[0], 'RecordHumanApproval idempotency command type is not allowed')
    require('CanonicalizeDiagnosticScope' in idempotency_check[0], 'CanonicalizeDiagnosticScope idempotency command type is not allowed')
    require(accepts_canonicalize_diagnostic_scope_command_type(), 'CanonicalizeDiagnosticScope idempotency command type was rejected')
    require('FutureCanonicalizeCommand' not in idempotency_check[0], 'idempotency command type check is not closed')
    require(rejects_unknown_idempotency_command_type(), 'unsupported idempotency command type was accepted')
    require(query("select column_default is not null from information_schema.columns where table_schema = 'public' and table_name = 'avuhz_outbox_deliveries' and column_name = 'outbox_delivery_id'") == ['t'], 'outbox ID requires persistence-owned default')
    for column in ('approving_principal_reference', 'approving_organization_reference', 'decision', 'conditions', 'effective_at', 'evidence_reference', 'correlation_id', 'idempotency_key'):
        require(query(f"select is_nullable from information_schema.columns where table_schema = 'public' and table_name = 'avuhz_human_approvals' and column_name = '{column}'") == ['YES'], f'human approval future field {column} must be optional')
    for column in ('tenant_id', 'approval_role', 'authority_category', 'status'):
        require(query(f"select is_nullable from information_schema.columns where table_schema = 'public' and table_name = 'avuhz_human_approvals' and column_name = '{column}'") == ['NO'], f'human approval shared authority binding {column} must be required')
    print('avuhz Slice 1 schema assertion: PASS')

if __name__ == '__main__':
    try: main()
    except (AssertionError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f'avuhz Slice 1 schema assertion: FAIL: {error}', file=sys.stderr); raise SystemExit(1)
