"""Provider-neutral PostgreSQL catalog assertions for the Slice 1 schema."""
from __future__ import annotations
import os, subprocess, sys

TABLES = ('avuhz_acquisition_handoffs', 'avuhz_engagements', 'avuhz_diagnostic_scopes', 'avuhz_human_approvals', 'avuhz_idempotency_records', 'avuhz_lifecycle_events', 'avuhz_outbox_deliveries')
LEGACY = ('tenant_users', 'engagements', 'engagement_events')
VERSIONED = ('avuhz_engagements', 'avuhz_diagnostic_scopes', 'avuhz_idempotency_records', 'avuhz_outbox_deliveries')
FK_TARGETS = {'avuhz_engagements': 'avuhz_acquisition_handoffs', 'avuhz_diagnostic_scopes': 'avuhz_engagements', 'avuhz_human_approvals': 'avuhz_diagnostic_scopes', 'avuhz_outbox_deliveries': 'avuhz_lifecycle_events'}

def query(sql):
    command = os.environ.get('SCHEMA_ASSERTION_PSQL')
    if not command: raise RuntimeError('SCHEMA_ASSERTION_PSQL must name a local PostgreSQL psql command')
    result = subprocess.run(['bash', '-lc', f'{command} -At -v ON_ERROR_STOP=1 -c "{sql}"'], check=True, capture_output=True, text=True)
    return [line for line in result.stdout.splitlines() if line]

def require(ok, message):
    if not ok: raise AssertionError(message)

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
    for table in VERSIONED:
        require(query(f"select column_name from information_schema.columns where table_schema = 'public' and table_name = '{table}' and column_name = 'record_version'") == ['record_version'], f'{table} lacks record_version')
    for table, target in FK_TARGETS.items():
        fks = set(query(f"select confrelid::regclass::text from pg_constraint where contype = 'f' and conrelid = 'public.{table}'::regclass"))
        require(target in fks or f'public.{target}' in fks, f'{table} lacks FK to {target}')
    checks = query("select conname from pg_constraint where contype = 'c' and conrelid in ('public.avuhz_engagements'::regclass, 'public.avuhz_diagnostic_scopes'::regclass)")
    require(len(checks) >= 3, 'closed vocabulary checks missing')
    print('avuhz Slice 1 schema assertion: PASS')

if __name__ == '__main__':
    try: main()
    except (AssertionError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f'avuhz Slice 1 schema assertion: FAIL: {error}', file=sys.stderr); raise SystemExit(1)
