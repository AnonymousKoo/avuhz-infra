"""One-table organization state ACL: static and disposable PG17 negatives."""
from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / 'supabase/migrations/20261015235500_grant_shared_org_state_metadata_read.sql'
CONTAINER = os.getenv('AVUHZ_LOCAL_POSTGRES_CONTAINER')
IMAGE = os.getenv('AVUHZ_POSTGRES_IMAGE')
DATABASE = 'avuhz_org_state_metadata_forward_v1'
TENANT_A = 'a4730000-0000-4000-8000-000000000001'
TENANT_B = 'a4730000-0000-4000-8000-000000000002'

DDL = """
CREATE ROLE avuhz_command_service NOLOGIN NOINHERIT NOBYPASSRLS;
CREATE ROLE avuhz_data_migration_service_dev NOLOGIN NOINHERIT NOBYPASSRLS;
CREATE ROLE avuhz_data_runtime_service_dev LOGIN NOINHERIT NOBYPASSRLS;
GRANT avuhz_command_service TO avuhz_data_migration_service_dev
  WITH ADMIN TRUE, INHERIT FALSE, SET FALSE;
GRANT avuhz_command_service TO avuhz_data_runtime_service_dev
  WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;
GRANT avuhz_data_runtime_service_dev TO postgres
  WITH ADMIN TRUE, INHERIT FALSE, SET FALSE;
GRANT avuhz_data_migration_service_dev TO postgres
  WITH ADMIN TRUE, INHERIT FALSE, SET FALSE;
CREATE ROLE avuhz_acquisition_service_dev NOLOGIN;
CREATE ROLE anon NOLOGIN;
CREATE ROLE authenticated NOLOGIN;
CREATE TABLE public.avuhz_tenant_organizations (
  tenant_id uuid NOT NULL PRIMARY KEY,
  organization_id uuid NOT NULL UNIQUE,
  business_reference text NOT NULL,
  lifecycle_state text NOT NULL,
  record_version integer NOT NULL
);
ALTER TABLE public.avuhz_tenant_organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.avuhz_tenant_organizations FORCE ROW LEVEL SECURITY;
CREATE POLICY avuhz_command_service_tenant_isolation
 ON public.avuhz_tenant_organizations FOR ALL TO avuhz_command_service
 USING (tenant_id = nullif(current_setting('avuhz.tenant_id'::text,true),'')::uuid)
 WITH CHECK (tenant_id = nullif(current_setting('avuhz.tenant_id'::text,true),'')::uuid);
CREATE POLICY avuhz_acquisition_select
 ON public.avuhz_tenant_organizations FOR SELECT TO avuhz_acquisition_service_dev
 USING (tenant_id = nullif(current_setting('avuhz.tenant_id'::text,true),'')::uuid);
CREATE POLICY avuhz_acquisition_lock_only
 ON public.avuhz_tenant_organizations FOR UPDATE TO avuhz_acquisition_service_dev
 USING (tenant_id = nullif(current_setting('avuhz.tenant_id'::text,true),'')::uuid)
 WITH CHECK (false);
GRANT USAGE ON SCHEMA public TO avuhz_command_service;
"""
# PostgreSQL roles are cluster-global, unlike the per-test disposable databases.
# Establish roles exactly once in the separately isolated test container.
ROLES, SCHEMA = DDL.split('CREATE TABLE public.avuhz_tenant_organizations', 1)
SCHEMA = 'CREATE TABLE public.avuhz_tenant_organizations' + SCHEMA
SCHEMA = SCHEMA.replace('GRANT USAGE ON SCHEMA public TO avuhz_command_service;', '')


class StaticContract(unittest.TestCase):
    def test_one_table_only_no_hosted_execution_or_broad_grants(self):
        text = MIGRATION.read_text()
        for marker in (
            'Remote execution is unauthorized by default',
            'gnuqaefotwgkwurjpyik ONLY',
            'AVUHZ_ORG_METADATA_PREFLIGHT_STOP',
            'AVUHZ_ORG_METADATA_POSTCONDITION_STOP',
            'relforcerowsecurity',
            'avuhz_command_service_tenant_isolation',
            'GRANT SELECT (tenant_id,organization_id,lifecycle_state)',
            'ON public.avuhz_tenant_organizations TO avuhz_command_service',
        ):
            self.assertIn(marker, text)
        for forbidden in (
            'GRANT ALL', 'GRANT SELECT ON public.', 'TO anon;',
            'TO authenticated;', 'TO service_role;', 'CREATE ROLE ',
            'CREATE TABLE ', 'CREATE POLICY ', 'SECURITY DEFINER',
            'INSERT INTO ', 'DELETE FROM ', 'DISABLE ROW LEVEL SECURITY',
            'ON public.avuhz_tenant_owner_memberships TO',
        ):
            self.assertNotIn(forbidden, text)
        self.assertTrue(text.rstrip().endswith('COMMIT;'))


@unittest.skipUnless(CONTAINER and IMAGE, 'dedicated disposable PostgreSQL 17 required')
class Pg17GrantTest(unittest.TestCase):
    @classmethod
    def docker_cmd(cls, *args, data=None):
        return subprocess.run(args, input=data.encode() if data is not None else None,
                              capture_output=True, check=False, timeout=30)

    @classmethod
    def sql(cls, script, *, check=True):
        p = cls.docker_cmd('docker', 'exec', '-i', cls.container, 'psql', '-X', '-v', 'ON_ERROR_STOP=1',
                    '-At', '-U', 'postgres', '-d', DATABASE, data=script)
        if check and p.returncode:
            raise AssertionError('disposable SQL test failed: ' + p.stderr.decode()[-800:])
        return p

    @classmethod
    def setUpClass(cls):
        if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,75}', CONTAINER or ''):
            raise RuntimeError('invalid test prefix')
        if not re.fullmatch(r'[^\s]+@sha256:[0-9a-f]{64}', IMAGE or ''):
            raise RuntimeError('must use digest-pinned PostgreSQL image')
        cls.name = CONTAINER + '-orgstate'
        if cls.docker_cmd('docker','container','inspect',cls.name).returncode == 0:
            raise RuntimeError('disposable fixture name already exists')
        p = cls.docker_cmd('docker','run','--detach','--rm','--network','none',
                    '--name',cls.name,'--env','POSTGRES_HOST_AUTH_METHOD=trust',IMAGE)
        if p.returncode or not re.fullmatch(rb'[a-f0-9]{64}\s*',p.stdout):
            raise RuntimeError('isolated PostgreSQL fixture unavailable')
        cls.container = p.stdout.decode().strip()
        try:
            previous = None
            stable = 0
            for _ in range(80):
                ready = cls.docker_cmd('docker','exec',cls.container,'psql','-X','-At',
                                '-U','postgres','-d','postgres',
                                '-c','select pg_postmaster_start_time();')
                current = ready.stdout.strip() if ready.returncode == 0 else None
                stable = stable + 1 if current and current == previous else (1 if current else 0)
                previous = current
                if stable >= 5: break
                time.sleep(.25)
            else: raise RuntimeError('stable PostgreSQL fixture not ready')
            version = cls.docker_cmd('docker','exec',cls.container,'psql','-X','-At',
                              '-U','postgres','-d','postgres','-c','show server_version_num;')
            if version.returncode or not version.stdout.decode().strip().startswith('17'):
                raise RuntimeError('PostgreSQL 17 required')
            roles = cls.run_roles()
            if roles.returncode:
                raise RuntimeError('isolated role fixture setup failed')
        except BaseException:
            cls.tearDownClass()
            raise

    @classmethod
    def run_roles(cls):
        return cls.docker_cmd('docker','exec','-i',cls.container,'psql',
                              '-X','-v','ON_ERROR_STOP=1','-At','-U','postgres',
                              '-d','postgres',data=ROLES)

    @classmethod
    def tearDownClass(cls):
        if getattr(cls,'container',None):
            cls.docker_cmd('docker','rm','--force',cls.container)
            cls.container = None

    def setUp(self):
        self.docker_cmd('docker','exec',self.container,'dropdb','--if-exists','-U','postgres',DATABASE)
        p = self.docker_cmd('docker','exec',self.container,'createdb','-U','postgres',DATABASE)
        if p.returncode: raise AssertionError('could not create disposable test database')
        self.sql(SCHEMA)
        self.sql(f"INSERT INTO public.avuhz_tenant_organizations "
                 "(tenant_id,organization_id,business_reference,lifecycle_state,record_version) VALUES "
                 f"('{TENANT_A}','a4730000-0000-4000-8000-000000000011','avuhz.qa.one','ACTIVE',1),"
                 f"('{TENANT_B}','a4730000-0000-4000-8000-000000000022','avuhz.qa.two','ACTIVE',1);")

    def tearDown(self):
        self.docker_cmd('docker','exec',self.container,'dropdb','--if-exists','-U','postgres',DATABASE)

    def test_exact_scoped_access_and_no_pii_or_write(self):
        self.sql(MIGRATION.read_text())
        for tenant, organization in ((TENANT_A,'a4730000-0000-4000-8000-000000000011'),
                                     (TENANT_B,'a4730000-0000-4000-8000-000000000022')):
            result = self.sql('BEGIN; SET LOCAL ROLE avuhz_command_service; '
                              f"SELECT set_config('avuhz.tenant_id','{tenant}',true); "
                              'SELECT tenant_id,organization_id,lifecycle_state '
                              'FROM public.avuhz_tenant_organizations; ROLLBACK;')
            rows = result.stdout.decode()
            self.assertIn(organization,rows)
            self.assertNotIn(TENANT_B if tenant==TENANT_A else TENANT_A,rows)
        result=self.sql('BEGIN; SET LOCAL ROLE avuhz_command_service; '
                        'SELECT COUNT(*) FROM public.avuhz_tenant_organizations; ROLLBACK;')
        self.assertIn('0',result.stdout.decode().splitlines())
        for attempt in (
            'SELECT business_reference FROM public.avuhz_tenant_organizations;',
            'UPDATE public.avuhz_tenant_organizations SET lifecycle_state=\'ACTIVE\';',
            'DELETE FROM public.avuhz_tenant_organizations;',
        ):
            p=self.sql('BEGIN; SET LOCAL ROLE avuhz_command_service; '+attempt,check=False)
            self.assertNotEqual(p.returncode,0)
        self.assertNotEqual(self.sql('SET ROLE anon; SELECT tenant_id FROM '
                                     'public.avuhz_tenant_organizations;',check=False).returncode,0)

    def test_reapply_fails_with_original_grants_intact(self):
        self.sql(MIGRATION.read_text())
        self.assertNotEqual(self.sql(MIGRATION.read_text(),check=False).returncode,0)
        cols=self.sql("SELECT count(*) FROM pg_attribute a CROSS JOIN LATERAL aclexplode(a.attacl) acl "
                      "WHERE a.attrelid='public.avuhz_tenant_organizations'::regclass "
                      "AND acl.grantee=(SELECT oid FROM pg_roles WHERE rolname='avuhz_command_service');")
        self.assertIn('3',cols.stdout.decode().splitlines())

    def test_policy_drift_blocks_grant(self):
        self.sql('DROP POLICY avuhz_command_service_tenant_isolation ON public.avuhz_tenant_organizations;')
        self.assertNotEqual(self.sql(MIGRATION.read_text(),check=False).returncode,0)
        self.assertFalse(self.sql('SELECT has_any_column_privilege(\'avuhz_command_service\','
                                  '\'public.avuhz_tenant_organizations\',\'SELECT\');').stdout.strip()==b't')

    def test_rls_disabled_blocks_grant(self):
        self.sql('ALTER TABLE public.avuhz_tenant_organizations DISABLE ROW LEVEL SECURITY;')
        self.assertNotEqual(self.sql(MIGRATION.read_text(),check=False).returncode,0)
        self.assertEqual(self.sql("SELECT has_any_column_privilege('avuhz_command_service',"
                                  "'public.avuhz_tenant_organizations','SELECT');").stdout.strip(),b'f')

    def test_public_broad_acl_blocks_grant(self):
        self.sql('GRANT SELECT ON public.avuhz_tenant_organizations TO PUBLIC;')
        self.assertNotEqual(self.sql(MIGRATION.read_text(),check=False).returncode,0)
        self.assertEqual(self.sql("SELECT count(*) FROM pg_attribute a CROSS JOIN LATERAL aclexplode(a.attacl) acl "
                                  "WHERE a.attrelid='public.avuhz_tenant_organizations'::regclass "
                                  "AND acl.grantee=(SELECT oid FROM pg_roles WHERE rolname='avuhz_command_service');").stdout.strip(),b'0')

    def test_existing_command_grant_blocks_upgrade(self):
        self.sql('GRANT SELECT (business_reference) ON public.avuhz_tenant_organizations TO avuhz_command_service;')
        self.assertNotEqual(self.sql(MIGRATION.read_text(),check=False).returncode,0)
        self.assertEqual(self.sql("SELECT has_column_privilege('avuhz_command_service',"
                                  "'public.avuhz_tenant_organizations','organization_id','SELECT');").stdout.strip(),b'f')


if __name__ == '__main__':
    unittest.main()
