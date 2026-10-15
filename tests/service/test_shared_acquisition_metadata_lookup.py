"""LOCAL/TEST shared acquisition metadata read: independent authority negatives."""
from __future__ import annotations

import dataclasses
import unittest
from pathlib import Path

from avuhz_runtime.guards import TrustedExecutionContext
from avuhz_runtime.postgres import PostgresStore
from avuhz_service.shared_acquisition_metadata_lookup import (
    AcquisitionMetadataDenied, SharedAcquisitionMetadataLookup,
    VerifiedAcquisitionMetadata,
)

TENANT = 'a4730000-0000-4000-8000-000000000001'
OTHER = 'a4730000-0000-4000-8000-000000000002'
INTAKE = 'a4730000-0000-4000-8000-000000000011'
ORG = 'a4730000-0000-4000-8000-000000000021'


class FakeConnection:
    autocommit = False

    def __init__(self, row=None, bounded=True, error=None):
        self.row = row
        self.bounded = bounded
        self.error = error
        self.calls = []
        self.rollback_count = 0
        self.close_count = 0
        self._last = ''

    def execute(self, sql, params=None):
        if self.error is not None:
            raise RuntimeError(self.error)
        self.calls.append((sql, params))
        self._last = sql
        return self

    def fetchone(self):
        if ' as bounded' in self._last:
            return {'bounded': self.bounded}
        return self.row

    def rollback(self):
        self.rollback_count += 1

    def close(self):
        self.close_count += 1


def trusted(tenant=TENANT, **updates):
    ctx = TrustedExecutionContext(
        True, 'worker.owner', 'HUMAN', tenant, ORG,
        frozenset({'work_intake:create'}), frozenset(),
        'DEVELOPMENT', 'avuhz-command-api', 'STRONG', False,
        '2026-10-13T00:00:00Z', '2099-01-01T00:00:00Z',
    )
    return dataclasses.replace(ctx, **updates)


class LookupTests(unittest.TestCase):
    def setUp(self):
        self.conn = FakeConnection(row={
            'tenant_id': TENANT, 'intake_id': INTAKE,
            'organization_id': ORG, 'intake_state': 'RECEIVED',
            'record_version': 3,
        })
        self.identities = {'owner': trusted(), 'other': trusted(OTHER)}
        self.member_enabled = True
        self.resolver_calls = []
        self.member_calls = []
        self.lookup = SharedAcquisitionMetadataLookup(
            PostgresStore(lambda: self.conn),
            resolve_identity=self.identity,
            resolve_tenant_member=self.membership,
        )

    def identity(self, evidence):
        self.resolver_calls.append(evidence)
        return self.identities[evidence]

    def membership(self, conn, tenant, principal):
        self.member_calls.append((conn, tenant, principal))
        return principal if self.member_enabled else None

    def assert_denied(self, evidence='owner', intake=INTAKE):
        with self.assertRaisesRegex(AcquisitionMetadataDenied, '^acquisition metadata unavailable$'):
            self.lookup.lookup(evidence, intake)

    def test_valid_read_exact_tenant_and_columns_no_write(self):
        found = self.lookup.lookup('owner', INTAKE)
        self.assertEqual(found, VerifiedAcquisitionMetadata(TENANT, INTAKE, ORG, 'RECEIVED', 3))
        self.assertEqual(len(self.member_calls), 1)
        self.assertIs(self.member_calls[0][0], self.conn)
        self.assertEqual(len(self.conn.calls), 3)
        _, query = self.conn.calls[-1]
        self.assertEqual(query, (TENANT, INTAKE))
        sql = self.conn.calls[-1][0].lower()
        self.assertIn('from public.avuhz_acquisition_intake_requests', sql)
        self.assertNotIn('contact_email', sql)
        self.assertNotIn('contact_phone', sql)
        self.assertNotIn('diagnostic_summary', sql)
        self.assertNotIn('select *', sql)
        self.assertEqual((self.conn.rollback_count, self.conn.close_count), (1,1))

    def test_untrusted_tenant_and_bad_id_fail_before_provider(self):
        self.assert_denied('owner', 'not-a-uuid')
        self.assert_denied(trusted(), INTAKE)
        self.assertEqual(self.conn.calls, [])
        self.assertEqual(self.resolver_calls, [])

    def test_no_independent_membership(self):
        self.member_enabled = False
        self.assert_denied()
        self.assertEqual(len(self.conn.calls), 2)
        self.assertEqual((self.conn.rollback_count, self.conn.close_count), (1,1))

    def test_cross_tenant_record(self):
        self.conn.row['tenant_id'] = OTHER
        self.assert_denied()

    def test_wrong_organization_rejected(self):
        self.conn.row['organization_id'] = OTHER
        self.assert_denied()

    def test_no_row_or_non_received_state(self):
        for row in (None, {**self.conn.row, 'intake_state': 'REJECTED'}):
            with self.subTest(row=row is None):
                self.setUp()
                self.conn.row = row
                self.assert_denied()

    def test_bad_record_version(self):
        for version in (0, -1, '1', True):
            with self.subTest(version=version):
                self.setUp()
                self.conn.row['record_version'] = version
                self.assert_denied()

    def test_missing_capability_and_authentication(self):
        for changes in (
            {'capabilities': frozenset()}, {'authenticated': False},
            {'caller_type': 'SERVICE'}, {'authentication_strength': 'WEAK'},
            {'environment': 'PRODUCTION'}, {'audience': 'unexpected'},
            {'expires_at': '2020-01-01T00:00:00Z'},
            {'authority_roles': frozenset({'OWNER'})},
            {'principal_id': 'private email@example.invalid'},
            {'tenant_id': None},
            {'organization_id': None},
            {'organization_id': 'another-organization'},
        ):
            with self.subTest(changes=changes):
                self.setUp()
                self.identities['owner'] = trusted(**changes)
                self.assert_denied()
                self.assertEqual(self.conn.calls, [])

    def test_inaccessible_role_and_rejected_catalog_drift(self):
        self.conn.bounded = False
        self.assert_denied()
        self.assertEqual(len(self.conn.calls), 2)

    def test_sql_exception_never_exposes_diagnostics(self):
        self.conn.error = 'private connection string and sensitive SQL diagnostic'
        self.assert_denied()
        # Constructor fail-closed closes directly before a UoW is returned.
        self.assertEqual((self.conn.rollback_count, self.conn.close_count), (0,1))

    def test_missing_owner_evidence_never_substituted_from_row(self):
        self.conn.row['owner_reference'] = 'worker.owner'
        self.assertEqual(self.lookup.lookup('owner', INTAKE),
                         VerifiedAcquisitionMetadata(TENANT, INTAKE, ORG, 'RECEIVED', 3))
        self.assertNotIn('owner_reference', self.conn.calls[-1][0])

    def test_denies_identity_resolver_error(self):
        self.assert_denied('unknown')
        self.assertEqual(self.conn.calls, [])

    def test_only_expected_authority_policy_and_grants(self):
        from avuhz_service.shared_acquisition_metadata_lookup import _BOUNDARY
        self.assertIn("current_user='avuhz_command_service'", _BOUNDARY)
        self.assertIn('relforcerowsecurity', _BOUNDARY)
        self.assertIn('avuhz_command_service_tenant_isolation', _BOUNDARY)
        self.assertIn('count(*)', _BOUNDARY)
        self.assertIn('not has_any_column_privilege', _BOUNDARY)
        self.assertIn('not has_table_privilege', _BOUNDARY)


if __name__ == '__main__':
    unittest.main()
