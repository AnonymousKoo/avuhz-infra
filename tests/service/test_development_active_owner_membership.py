"""Fail-closed owner read: test-only AUTH/MFA stubs are NOT hosted proof."""
from __future__ import annotations
import unittest
from unittest.mock import patch
from avuhz_runtime.postgres import PostgresStore
from avuhz_service.development_active_owner_membership import (
    DevelopmentActiveOwnerMembershipCheck, _BOUNDARY, _POLICY, _LOOKUP,
)
from avuhz_service.development_owner_authentication import (
    DevelopmentOwnerAuthenticationCheckpoint, ProvisionalOwnerAuthentication,
)
from avuhz_service.development_owner_mfa_freshness import DevelopmentOwnerMfaFreshnessCheck

TENANT = "a4730000-0000-4000-8000-000000000001"
OTHER = "a4730000-0000-4000-8000-000000000002"
ORG = "a4730000-0000-4000-8000-000000000011"
DIGEST = "sha256:" + "a" * 64


class FakeConnection:
    autocommit = False
    def __init__(self):
        self.boundary = True
        self.verified = True
        self.error = None
        self.calls = []
        self.last = None
        self.rollbacks = 0
        self.closes = 0
    def execute(self, sql, args=None):
        if self.error is not None:
            raise RuntimeError("sensitive provider SQL credentials must not leak")
        self.calls.append((sql, args))
        self.last = sql
        return self
    def fetchone(self):
        if " AS bounded" in self.last:
            return {"bounded": self.boundary}
        if "SELECT true AS member_verified" in self.last:
            return {"member_verified": True} if self.verified else None
        return None
    def rollback(self):
        self.rollbacks += 1
    def close(self):
        self.closes += 1


class ReadOnlyOwnerMembershipTests(unittest.TestCase):
    def setUp(self):
        self.conn = FakeConnection()
        self.auth = object.__new__(DevelopmentOwnerAuthenticationCheckpoint)
        self.mfa = object.__new__(DevelopmentOwnerMfaFreshnessCheck)
        self.provisional = ProvisionalOwnerAuthentication(
            DIGEST, "2026-10-16T00:00:00Z"
        )
        self.mfa_ok = True
        self.auth_calls = []
        self.mfa_calls = []
        # Test doubles are never allowed in hosted AUTH/DATA composition.
        self.auth_patcher = patch.object(
            DevelopmentOwnerAuthenticationCheckpoint, "inspect",
            lambda _, bearer: self.probe_auth(bearer),
        )
        self.mfa_patcher = patch.object(
            DevelopmentOwnerMfaFreshnessCheck, "__call__",
            lambda _, bearer, digest: self.probe_mfa(bearer, digest),
        )
        self.auth_patcher.start()
        self.mfa_patcher.start()
        self.addCleanup(self.auth_patcher.stop)
        self.addCleanup(self.mfa_patcher.stop)
        self.reader = DevelopmentActiveOwnerMembershipCheck(
            PostgresStore(lambda: self.conn), self.auth, self.mfa
        )
    def probe_auth(self, bearer):
        self.auth_calls.append(bearer)
        return self.provisional
    def probe_mfa(self, bearer, digest):
        self.mfa_calls.append((bearer, digest))
        return self.mfa_ok
    def test_valid_synthetic_bound_read_only(self):
        self.assertTrue(self.reader("signed-fake-bearer", TENANT, ORG))
        self.assertEqual(self.mfa_calls, [("signed-fake-bearer", DIGEST)])
        self.assertEqual(len(self.conn.calls), 3)
        self.assertEqual(self.conn.calls[0][1], (TENANT,))
        self.assertEqual(self.conn.calls[1][1], (_POLICY, _POLICY))
        self.assertEqual(self.conn.calls[2][1], (TENANT, ORG, DIGEST))
        self.assertEqual((self.conn.rollbacks, self.conn.closes), (1, 1))
    def test_invalid_ids_rejected_before_auth_or_data(self):
        for tenant, org in ((OTHER.upper(), ORG), (TENANT, "wrong"),
                            (None, ORG), (TENANT, None), (True, ORG),
                            (TENANT, True)):
            with self.subTest(tenant=type(tenant), org=type(org)):
                self.assertFalse(self.reader("signed-fake-bearer", tenant, org))
        self.assertEqual(self.auth_calls, [])
        self.assertEqual(self.conn.calls, [])
    def test_auth_failure_closed_without_db(self):
        def fail(_bearer):
            raise RuntimeError("sensitive auth subject and private token")
        self.probe_auth = fail
        self.assertFalse(self.reader("bad token", TENANT, ORG))
        self.assertEqual(self.conn.calls, [])
    def test_bogus_provisional_and_synthetic_digest_denied(self):
        for bad in (None, {}, "owner", ProvisionalOwnerAuthentication(
                "sha256:incomplete", "2026-10-16T00:00:00Z"
        ), ProvisionalOwnerAuthentication(
                DIGEST, "2026-10-16T00:00:00Z", registration_authorized=True
        )):
            with self.subTest(bad=type(bad)):
                self.provisional = bad
                self.assertFalse(self.reader("fake", TENANT, ORG))
        self.assertEqual(self.mfa_calls, [])
        self.assertEqual(self.conn.calls, [])
    def test_mfa_or_active_session_missing(self):
        self.mfa_ok = False
        self.assertFalse(self.reader("fake", TENANT, ORG))
        self.assertEqual(self.conn.calls, [])
    def test_role_or_rls_privilege_drift_denied(self):
        self.conn.boundary = False
        self.assertFalse(self.reader("fake", TENANT, ORG))
        self.assertEqual(len(self.conn.calls), 2)
        self.assertEqual((self.conn.rollbacks, self.conn.closes), (1, 1))
    def test_owner_not_active_or_unverified_denied(self):
        self.conn.verified = False
        self.assertFalse(self.reader("fake", TENANT, ORG))
        self.assertEqual((self.conn.rollbacks, self.conn.closes), (1, 1))
    def test_sql_unavailable_is_sanitized_and_closed(self):
        self.conn.error = "do not expose bearer, digest, PII or database DSN"
        self.assertFalse(self.reader("fake", TENANT, ORG))
        self.assertEqual(self.conn.closes, 1)
    def test_exact_sql_never_returns_digest_or_identity(self):
        self.assertIn("principal_subject_digest=%s", _LOOKUP)
        self.assertIn("member.membership_state='ACTIVE'", _LOOKUP)
        self.assertIn("member.verified_at IS NOT NULL", _LOOKUP)
        self.assertIn("org.lifecycle_state='ACTIVE'", _LOOKUP)
        self.assertTrue(_LOOKUP.lstrip().startswith("SELECT true"))
        self.assertNotIn("SELECT *", _LOOKUP.upper())
        self.assertIn("relforcerowsecurity", _BOUNDARY)
        self.assertIn("current_user='avuhz_command_service'", _BOUNDARY)
        self.assertIn("has_any_column_privilege('authenticated'", _BOUNDARY)
        self.assertNotIn("INSERT INTO", _LOOKUP.upper())
        self.assertNotIn("UPDATE ", _LOOKUP.upper())
        self.assertNotIn("DELETE FROM", _LOOKUP.upper())


if __name__ == "__main__":
    unittest.main()
