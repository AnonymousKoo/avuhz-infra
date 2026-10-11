"""Disposable PostgreSQL 17 proof of reusable Avuhz company enrollment.

End-to-end PENDING registration -> ACTIVE company and owner membership using
the *existing shared* registration/activation service code and exact generic
tenant/owner schema candidates. Two unrelated synthetic companies. No
Supabase AUTH/DATA, network owner directory, secret, customer or production use.

Temporary column-specific role grants exist ONLY in a disposable test database
created/destroyed by this suite. They must never be applied to hosted DATA
without fresh independent approval and authoritative owner proof.
"""
from __future__ import annotations

import hashlib
import os
import re
import runpy
import subprocess
import sys
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

import jwt
import psycopg
from cryptography.hazmat.primitives.asymmetric import ec
from psycopg.rows import dict_row

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_runtime.postgres import PostgresStore
from avuhz_service.development import DEVELOPMENT_AUTH_ISSUER
from avuhz_service.development_pretenant_supabase_jwt import (
    DevelopmentPreTenantEs256JwtVerifier,
)
from avuhz_service.development_owner_authentication import (
    DevelopmentOwnerAuthenticationCheckpoint,
)
from avuhz_service.development_owner_mfa_freshness import (
    DevelopmentOwnerMfaFreshnessCheck,
)
from avuhz_service.development_tenant_registration import (
    DevelopmentTenantRegistrationCandidate,
)
from avuhz_service.development_company_activation import (
    CompanyActivationUnavailable,
    DevelopmentCompanyActivationCandidate,
)

CONTAINER = os.environ.get("AVUHZ_LOCAL_POSTGRES_CONTAINER")
DATABASE = "avuhz_shared_company_enrollment_v1"
BASELINE = ROOT / "supabase/migrations/20260831120000_rebaseline_provider_neutral_avuhz.sql"
ORG_FILE = ROOT / "tests/integration/test_development_data_tenant_organization_candidate.py"
OWNER_FILE = ROOT / "tests/integration/test_development_data_tenant_owner_membership_candidate.py"
ORG_SQL = runpy.run_path(str(ORG_FILE))["INSTALLATION_CANDIDATE_SQL"]
OWNER_SQL = runpy.run_path(str(OWNER_FILE))["INSTALLATION_CANDIDATE_SQL"]

SUBJECT_A = "a4770000-0000-4000-8000-000000000021"
SUBJECT_B = "a4770000-0000-4000-8000-000000000022"
SESSION_A = "a4770000-0000-4000-8000-000000000031"
SESSION_B = "a4770000-0000-4000-8000-000000000032"
BUSINESS_A = "business.fictional-alpha"
BUSINESS_B = "business.fictional-beta"


def digest(subject):
    return "sha256:" + hashlib.sha256(subject.encode("ascii")).hexdigest()


class _SyntheticJwks:
    def __init__(self, public):
        self.public = public

    def get_signing_key_from_jwt(self, _):
        return SimpleNamespace(key=self.public)


@unittest.skipUnless(CONTAINER, "exact CI disposable PostgreSQL 17 required")
class SharedCompanyEnrollmentPostgresTests(unittest.TestCase):
    """No persistent provider contact. Test credentials are generated in RAM."""

    @classmethod
    def _run_container(cls, *args, input_bytes=None):
        argv = ["docker", "exec"]
        if input_bytes is not None:
            argv.append("-i")
        argv += [CONTAINER, *args]
        result = subprocess.run(
            argv, input=input_bytes, capture_output=True, check=False,
            timeout=90,
        )
        if result.returncode:
            raise AssertionError("DISPOSABLE_COMPANY_ENROLLMENT_SETUP_FAILED")
        return result

    @classmethod
    def _apply(cls, sql):
        return cls._run_container(
            "psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1",
            "-U", "postgres", "-d", DATABASE, input_bytes=sql.encode("utf-8"),
        )

    @classmethod
    def setUpClass(cls):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", CONTAINER or ""):
            raise AssertionError("DISPOSABLE_COMPANY_ENROLLMENT_CONTAINER_REQUIRED")
        cls._run_container("dropdb", "--if-exists", "-U", "postgres", DATABASE)
        cls._run_container("createdb", "-U", "postgres", DATABASE)
        try:
            cls._apply(BASELINE.read_text(encoding="utf-8"))
            cls._apply(ORG_SQL)
            cls._apply(OWNER_SQL)
            # LOCAL TEST DATABASE ONLY. No LOGIN, service_role, DDL or bypassrls.
            # Direct public/authenticated API roles remain entirely revoked.
            cls._apply("""
                GRANT SELECT (tenant_id, organization_id, business_reference,
                              lifecycle_state, record_version),
                      INSERT (tenant_id, organization_id, business_reference),
                      UPDATE (lifecycle_state, record_version, updated_at)
                  ON TABLE public.avuhz_tenant_organizations
                  TO avuhz_command_service;
                GRANT SELECT (tenant_id, organization_id,
                              principal_subject_digest, member_role,
                              membership_state, verified_at, record_version),
                      INSERT (tenant_id, organization_id, principal_subject_digest),
                      UPDATE (membership_state, verified_at, record_version, updated_at)
                  ON TABLE public.avuhz_tenant_owner_memberships
                  TO avuhz_command_service;
            """)
        except Exception:
            cls._run_container("dropdb", "--if-exists", "-U", "postgres", DATABASE)
            raise

    @classmethod
    def tearDownClass(cls):
        cls._run_container("dropdb", "--if-exists", "-U", "postgres", DATABASE)

    @staticmethod
    def _admin():
        return psycopg.connect(
            host="127.0.0.1", port=5432, dbname=DATABASE, user="postgres",
            row_factory=dict_row,
        )

    @staticmethod
    def _limited():
        # Locally simulate an existing NOLOGIN scoped command-service role.
        # Never connect as postgres to execute runtime business mutations.
        connection = SharedCompanyEnrollmentPostgresTests._admin()
        connection.execute("SET ROLE avuhz_command_service")
        return connection

    def setUp(self):
        with self._admin() as db:
            db.execute(
                "alter table public.avuhz_tenant_organizations "
                "drop constraint if exists avuhz_test_block_organization_activation"
            )
            db.execute("truncate table public.avuhz_tenant_owner_memberships")
            db.execute("truncate table public.avuhz_tenant_organizations")
        self.private = ec.generate_private_key(ec.SECP256R1())
        verifier = DevelopmentPreTenantEs256JwtVerifier(
            _SyntheticJwks(self.private.public_key())
        )
        self.checkpoint = DevelopmentOwnerAuthenticationCheckpoint(verifier)
        self.session_checks = []
        self.owner_checks = []
        self.owner_directory = {
            BUSINESS_A: digest(SUBJECT_A),
            BUSINESS_B: digest(SUBJECT_B),
        }

        def synthetic_live_auth(subject, session, bearer):
            self.session_checks.append((subject, session))
            # This is a mock, not hosted AUTH provider proof.
            return subject in (SUBJECT_A, SUBJECT_B) and bool(bearer)

        def synthetic_owner_directory(subject_digest, business, environment):
            self.owner_checks.append((subject_digest, business, environment))
            # In production, replace with independently authenticated evidence.
            return environment == "DEVELOPMENT" and (
                self.owner_directory.get(business) == subject_digest
            )

        self.mfa = DevelopmentOwnerMfaFreshnessCheck(
            verifier, confirm_live_session=synthetic_live_auth
        )
        self.store = PostgresStore(self._limited)
        self.registration = DevelopmentTenantRegistrationCandidate(
            self.store, self.checkpoint,
            check_fresh_auth_mfa=self.mfa,
            check_business_owner=synthetic_owner_directory,
        )
        self.activation = DevelopmentCompanyActivationCandidate(
            self.store, self.checkpoint,
            check_fresh_auth_mfa=self.mfa,
            check_business_owner=synthetic_owner_directory,
        )

    def token(self, subject, session):
        now = int(time.time())
        return jwt.encode({
            "iss": DEVELOPMENT_AUTH_ISSUER,
            "aud": "authenticated",
            "sub": subject,
            "session_id": session,
            "role": "authenticated",
            "is_anonymous": False,
            "aal": "aal2",
            "iat": now - 1,
            "exp": now + 180,
            "amr": [{"method": "totp", "timestamp": now - 2}],
        }, self.private, algorithm="ES256")

    def enroll(self, business, subject, session):
        bearer = self.token(subject, session)
        pending = self.registration.propose(
            untrusted_bearer=bearer,
            business_reference=business,
        )
        self.assertEqual(pending.state, "PENDING_VERIFICATION")
        active = self.activation.activate(
            untrusted_bearer=bearer,
            tenant_id=pending.tenant_id,
            organization_id=pending.organization_id,
            business_reference=business,
        )
        self.assertEqual(active.state, "ACTIVE")
        self.assertFalse(active.duplicate)
        return pending, active

    def test_real_rls_two_independent_companies_pending_to_active(self):
        a, a_active = self.enroll(BUSINESS_A, SUBJECT_A, SESSION_A)
        b, b_active = self.enroll(BUSINESS_B, SUBJECT_B, SESSION_B)
        self.assertNotEqual(a.tenant_id, b.tenant_id)
        self.assertNotEqual(a.organization_id, b.organization_id)
        self.assertEqual(len(self.session_checks), 4)
        self.assertEqual(len(self.owner_checks), 4)
        with self._admin() as db:
            orgs = db.execute(
                "select tenant_id, lifecycle_state, record_version "
                "from public.avuhz_tenant_organizations order by business_reference"
            ).fetchall()
            owners = db.execute(
                "select tenant_id, membership_state, record_version, verified_at "
                "from public.avuhz_tenant_owner_memberships order by tenant_id"
            ).fetchall()
        self.assertEqual(len(orgs), 2)
        self.assertEqual(len(owners), 2)
        self.assertEqual({str(x["tenant_id"]) for x in orgs},
                         {a.tenant_id, b.tenant_id})
        self.assertTrue(all(x["lifecycle_state"] == "ACTIVE" and
                            x["record_version"] == 2 for x in orgs))
        self.assertTrue(all(x["membership_state"] == "ACTIVE" and
                            x["verified_at"] is not None and
                            x["record_version"] == 2 for x in owners))
        self.assertFalse(a_active.duplicate or b_active.duplicate)

    def test_rls_denies_cross_tenant_views_and_direct_public_access(self):
        a, _ = self.enroll(BUSINESS_A, SUBJECT_A, SESSION_A)
        b, _ = self.enroll(BUSINESS_B, SUBJECT_B, SESSION_B)
        with self._limited() as db:
            # No RLS tenant context: no rows, even with column SELECT rights.
            self.assertEqual(db.execute(
                "select tenant_id from public.avuhz_tenant_organizations"
            ).fetchall(), [])
            db.execute("select set_config('avuhz.tenant_id', %s, true)", (a.tenant_id,))
            visible = db.execute(
                "select tenant_id from public.avuhz_tenant_organizations"
            ).fetchall()
            owner_visible = db.execute(
                "select tenant_id from public.avuhz_tenant_owner_memberships"
            ).fetchall()
            self.assertEqual([str(x["tenant_id"]) for x in visible], [a.tenant_id])
            self.assertEqual([str(x["tenant_id"]) for x in owner_visible], [a.tenant_id])
            self.assertNotEqual(a.tenant_id, b.tenant_id)
        with self._admin() as db:
            rows = db.execute(
                "select relname,relrowsecurity,relforcerowsecurity "
                "from pg_class where oid in ("
                "'public.avuhz_tenant_organizations'::regclass, "
                "'public.avuhz_tenant_owner_memberships'::regclass)"
            ).fetchall()
            self.assertEqual(len(rows), 2)
            self.assertTrue(all(row["relrowsecurity"] and row["relforcerowsecurity"]
                                for row in rows))
            for table in ("avuhz_tenant_organizations",
                          "avuhz_tenant_owner_memberships"):
                for privilege in ("DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"):
                    self.assertFalse(db.execute(
                        "select has_table_privilege(%s,%s,%s) as permitted",
                        ("avuhz_command_service", "public." + table, privilege),
                    ).fetchone()["permitted"])
                # Provider-neutral local PG does not necessarily create
                # Supabase's anon role; never fabricate an AUTH/API role.
                anon_exists = db.execute(
                    "select exists(select 1 from pg_roles where rolname='anon') as present"
                ).fetchone()["present"]
                if anon_exists:
                    self.assertFalse(db.execute(
                        "select has_table_privilege(%s,%s,%s) as permitted",
                        ("anon", "public." + table, "SELECT"),
                    ).fetchone()["permitted"])

    def test_wrong_verified_owner_cannot_activate_another_tenant(self):
        pending = self.registration.propose(
            untrusted_bearer=self.token(SUBJECT_B, SESSION_B),
            business_reference=BUSINESS_B,
        )
        # Owner A has genuine authorization for A but cannot access B's rows.
        with self.assertRaisesRegex(
            PermissionError, "^company_activation_not_authorized$"
        ):
            self.activation.activate(
                untrusted_bearer=self.token(SUBJECT_A, SESSION_A),
                tenant_id=pending.tenant_id,
                organization_id=pending.organization_id,
                business_reference=BUSINESS_A,
            )
        with self._admin() as db:
            record = db.execute(
                "select lifecycle_state from public.avuhz_tenant_organizations "
                "where tenant_id=%s", (pending.tenant_id,)
            ).fetchone()
            self.assertEqual(record["lifecycle_state"], "PENDING_VERIFICATION")

    def test_second_update_error_rolls_back_first_verified_owner_update(self):
        pending = self.registration.propose(
            untrusted_bearer=self.token(SUBJECT_A, SESSION_A),
            business_reference=BUSINESS_A,
        )
        with self._admin() as db:
            db.execute(
                "alter table public.avuhz_tenant_organizations "
                "add constraint avuhz_test_block_organization_activation "
                "check (lifecycle_state <> 'ACTIVE')"
            )
        with self.assertRaisesRegex(
            CompanyActivationUnavailable, "^company_activation_unavailable$"
        ):
            self.activation.activate(
                untrusted_bearer=self.token(SUBJECT_A, SESSION_A),
                tenant_id=pending.tenant_id,
                organization_id=pending.organization_id,
                business_reference=BUSINESS_A,
            )
        with self._admin() as db:
            org = db.execute(
                "select lifecycle_state,record_version "
                "from public.avuhz_tenant_organizations where tenant_id=%s",
                (pending.tenant_id,),
            ).fetchone()
            owner = db.execute(
                "select membership_state,record_version,verified_at "
                "from public.avuhz_tenant_owner_memberships where tenant_id=%s",
                (pending.tenant_id,),
            ).fetchone()
        self.assertEqual((org["lifecycle_state"], org["record_version"]),
                         ("PENDING_VERIFICATION", 1))
        self.assertEqual((owner["membership_state"], owner["record_version"],
                          owner["verified_at"]), ("PENDING_VERIFICATION", 1, None))

    def test_reauthenticated_activation_replay_is_read_only(self):
        pending, _ = self.enroll(BUSINESS_A, SUBJECT_A, SESSION_A)
        replay = self.activation.activate(
            untrusted_bearer=self.token(SUBJECT_A, SESSION_A),
            tenant_id=pending.tenant_id,
            organization_id=pending.organization_id,
            business_reference=BUSINESS_A,
        )
        self.assertTrue(replay.duplicate)
        with self._admin() as db:
            versions = db.execute(
                "select record_version from public.avuhz_tenant_organizations "
                "where tenant_id=%s", (pending.tenant_id,),
            ).fetchone()
        self.assertEqual(versions["record_version"], 2)


if __name__ == "__main__":
    unittest.main()
