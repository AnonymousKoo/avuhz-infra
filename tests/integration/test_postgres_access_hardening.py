"""Local-only adversarial direct-SQL coverage for the Phase 4C boundary."""
from __future__ import annotations
import os, sys, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path[:0]=[str(ROOT/'src'),str(ROOT/'tests'/'contracts')]
import psycopg
from psycopg.errors import InsufficientPrivilege

DSN=os.environ.get('AVUHZ_POSTGRES_DSN')
TABLES=('avuhz_acquisition_handoffs','avuhz_engagements','avuhz_diagnostic_scopes','avuhz_human_approvals','avuhz_idempotency_records','avuhz_lifecycle_events','avuhz_outbox_deliveries')

@unittest.skipUnless(DSN, 'AVUHZ_POSTGRES_DSN is required for local integration tests')
class AccessHardeningTests(unittest.TestCase):
 def denied(self, role, sql):
  with psycopg.connect(DSN) as connection:
   connection.execute(f'set local role {role}')
   with self.assertRaises(InsufficientPrivilege): connection.execute(sql)
 def test_anon_and_authenticated_cannot_read_or_mutate_authoritative_tables(self):
  for role in ('anon','authenticated'):
   for table in TABLES:
    self.denied(role,f'select * from public.{table}')
    self.denied(role,f'insert into public.{table} default values')
    self.denied(role,f'update public.{table} set tenant_id = tenant_id')
    self.denied(role,f'delete from public.{table}')
 def test_authenticated_status_and_application_capabilities_are_not_sql_authority(self):
  # SQL roles have no representation of scope:submit/scope:approve.  Even a
  # locally authenticated role remains unable to fabricate either approval role.
  self.denied('authenticated', "insert into public.avuhz_human_approvals default values")
  self.denied('authenticated', "insert into public.avuhz_idempotency_records default values")
  self.denied('authenticated', "insert into public.avuhz_lifecycle_events default values")
  self.denied('authenticated', "insert into public.avuhz_outbox_deliveries default values")
  self.denied('authenticated', "update public.avuhz_outbox_deliveries set status='PUBLISHED'")

if __name__=='__main__': unittest.main()
