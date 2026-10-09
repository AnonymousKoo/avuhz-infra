"""Isolated local PostgreSQL-only security tests for shared four-stage claims.

Creates and removes its own schema and NOLOGIN writer in the disposable CI
database. No deployed Supabase migration, provider access or live handoff.
"""
from __future__ import annotations

import os
import sys
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

import psycopg

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "src")]
DSN = os.environ.get("AVUHZ_POSTGRES_DSN")

from avuhz_engineering.development_handoff_approval_gate import EXPECTED_STAGES
from avuhz_engineering.development_handoff_durable_claim_candidate import (
    DurableHandoffClaimStop, DurableStageClaim, claim_four_stages_candidate,
)
from avuhz_service.development import (
    DEVELOPMENT_AUTH_PROJECT_REF, DEVELOPMENT_DATA_PROJECT_REF,
)

TENANT = "1ad3998c-92ab-4a36-9d1c-ed97f2fa98f0"
OTHER = "1ad3998c-92ab-4a36-9d1c-ed97f2fa98f1"
TABLE = "avuhz_handoff_control.avuhz_handoff_approval_claims"
ROLE = "avuhz_handoff_claim_writer"
SOURCE_SHA = "a" * 40
AUTH_SET = "sha256:" + "b" * 64
COMMAND = "sha256:" + "c" * 64

# Test fixture only. This DDL is not a Supabase migration and is never invoked
# by the application or shipped with a GitHub Actions execution workflow.
LOCAL_FIXTURE_DDL = """
create role avuhz_handoff_claim_writer nologin nosuperuser nobypassrls
  noinherit nocreatedb nocreaterole noreplication;
create schema avuhz_handoff_control;
revoke all on schema avuhz_handoff_control from public;
create table avuhz_handoff_control.avuhz_handoff_approval_claims (
  tenant_id uuid not null,
  stage text not null check (stage in (
    'AUTH_GLOBAL_LOGOUT','AUTH_GENERATE','AUTH_VERIFY','DATA_COMMAND')),
  plan_id text not null,
  step_id text not null,
  plan_digest text not null check (plan_digest ~ '^sha256:[0-9a-f]{64}$'),
  approval_digest text not null check (approval_digest ~ '^sha256:[0-9a-f]{64}$'),
  project_reference text not null,
  authorization_set_digest text not null check (
    authorization_set_digest ~ '^sha256:[0-9a-f]{64}$'),
  command_digest text not null check (command_digest ~ '^sha256:[0-9a-f]{64}$'),
  source_sha text not null check (source_sha ~ '^[0-9a-f]{40}$'),
  claimed_at timestamptz not null default clock_timestamp(),
  primary key (tenant_id,plan_id,step_id),
  unique (approval_digest),
  unique (tenant_id,authorization_set_digest,stage),
  unique (tenant_id,command_digest,stage)
);
alter table avuhz_handoff_control.avuhz_handoff_approval_claims
  enable row level security;
alter table avuhz_handoff_control.avuhz_handoff_approval_claims
  force row level security;
revoke all on avuhz_handoff_control.avuhz_handoff_approval_claims from public;
create policy avuhz_handoff_claim_writer_tenant on
  avuhz_handoff_control.avuhz_handoff_approval_claims
  for insert to avuhz_handoff_claim_writer
  with check (
    tenant_id = nullif(current_setting('avuhz.handoff_claim_tenant', true),'')::uuid
  );
grant usage on schema avuhz_handoff_control to avuhz_handoff_claim_writer;
grant insert on avuhz_handoff_control.avuhz_handoff_approval_claims
  to avuhz_handoff_claim_writer;
"""


@unittest.skipUnless(DSN, "disposable local PostgreSQL DSN is required")
class DurableHandoffCandidatePostgresTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        with psycopg.connect(DSN, autocommit=True) as db:
            db.execute(LOCAL_FIXTURE_DDL)

    @classmethod
    def tearDownClass(cls):
        with psycopg.connect(DSN, autocommit=True) as db:
            db.execute("drop schema avuhz_handoff_control cascade")
            db.execute("drop role avuhz_handoff_claim_writer")
        super().tearDownClass()

    def setUp(self):
        with psycopg.connect(DSN, autocommit=True) as db:
            db.execute(f"truncate {TABLE}")

    @staticmethod
    def writer():
        db = psycopg.connect(DSN)
        try:
            db.execute("set role avuhz_handoff_claim_writer")
            db.commit()
        except Exception:
            db.close()
            raise
        return db

    def claims(self):
        return tuple(
            DurableStageClaim(
                stage=stage,
                plan_id=f"fictional.plan.{i}",
                step_id=f"handoff.stage.{i}",
                plan_digest="sha256:" + format(i, "064x"),
                approval_digest="sha256:" + format(i + 10, "064x"),
                project_reference=(
                    DEVELOPMENT_DATA_PROJECT_REF if stage == "DATA_COMMAND"
                    else DEVELOPMENT_AUTH_PROJECT_REF
                ),
            )
            for i, stage in enumerate(EXPECTED_STAGES, start=1)
        )

    def run_claim(self, **overrides):
        args = dict(
            connection_factory=self.writer,
            tenant_id=TENANT,
            source_sha=SOURCE_SHA,
            authorization_set_digest=AUTH_SET,
            command_digest=COMMAND,
            auth_project_ref=DEVELOPMENT_AUTH_PROJECT_REF,
            data_project_ref=DEVELOPMENT_DATA_PROJECT_REF,
            claims=self.claims(),
        )
        args.update(overrides)
        return claim_four_stages_candidate(**args)

    def rows(self):
        with psycopg.connect(DSN) as db:
            return db.execute(
                f"select tenant_id::text,stage,approval_digest from {TABLE} "
                "order by stage"
            ).fetchall()

    def test_all_four_commit_once_and_replay_never_resumes(self):
        result = self.run_claim()
        self.assertEqual(result.claimed_stage_count, 4)
        self.assertFalse(result.live_execution_authorized)
        self.assertFalse(result.provider_environment_installed)
        self.assertFalse(result.signed_approval_authority_verified)
        self.assertFalse(result.human_owner_binding_verified)
        self.assertFalse(result.retry_authorized)
        self.assertEqual(len(self.rows()), 4)
        with self.assertRaisesRegex(
            DurableHandoffClaimStop, "HANDOFF_DURABLE_CLAIM_ALREADY_CONSUMED"
        ):
            self.run_claim()
        self.assertEqual(len(self.rows()), 4)

    def test_concurrent_independent_connections_commit_only_one_set(self):
        with ThreadPoolExecutor(max_workers=6) as pool:
            futures = [pool.submit(self.run_claim) for _ in range(6)]
            successful, denied = [], []
            for future in futures:
                try:
                    successful.append(future.result())
                except DurableHandoffClaimStop as exc:
                    denied.append(str(exc))
        self.assertEqual(len(successful), 1)
        self.assertEqual(
            denied, ["HANDOFF_DURABLE_CLAIM_ALREADY_CONSUMED"] * 5
        )
        self.assertEqual(len(self.rows()), 4)

    def test_existing_one_stage_claim_rolls_back_three_new_claims(self):
        first = self.claims()[2]
        with psycopg.connect(DSN) as db:
            db.execute(
                f"insert into {TABLE} (tenant_id,stage,plan_id,step_id,"
                "plan_digest,approval_digest,project_reference,"
                "authorization_set_digest,command_digest,source_sha)"
                " values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (TENANT, first.stage, first.plan_id, first.step_id,
                 first.plan_digest, first.approval_digest,
                 first.project_reference, AUTH_SET, COMMAND, SOURCE_SHA)
            )
        with self.assertRaisesRegex(
            DurableHandoffClaimStop, "HANDOFF_DURABLE_CLAIM_ALREADY_CONSUMED"
        ):
            self.run_claim()
        self.assertEqual(len(self.rows()), 1)

    def test_authorization_cannot_be_reused_with_rebound_source(self):
        self.run_claim()
        with self.assertRaisesRegex(
            DurableHandoffClaimStop, "HANDOFF_DURABLE_CLAIM_ALREADY_CONSUMED"
        ):
            self.run_claim(source_sha="e" * 40)
        self.assertEqual(len(self.rows()), 4)

    def test_cross_tenant_insert_is_denied_by_forced_rls(self):
        with self.writer() as db:
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                with db.transaction():
                    db.execute(
                        "select set_config('avuhz.handoff_claim_tenant',%s,true)",
                        (OTHER,)
                    )
                    db.execute(
                        f"insert into {TABLE} (tenant_id,stage,plan_id,step_id,"
                        "plan_digest,approval_digest,project_reference,"
                        "authorization_set_digest,command_digest,source_sha)"
                        " values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                        (TENANT, *(
                            self.claims()[0].stage,
                            self.claims()[0].plan_id,
                            self.claims()[0].step_id,
                            self.claims()[0].plan_digest,
                            self.claims()[0].approval_digest,
                            self.claims()[0].project_reference,
                        ), AUTH_SET, COMMAND, SOURCE_SHA),
                    )
        self.assertEqual(self.rows(), [])

    def test_role_is_separate_from_command_service_and_exposed_roles(self):
        with psycopg.connect(DSN) as db:
            role = db.execute(
                "select rolcanlogin,rolsuper,rolbypassrls,rolinherit,"
                "rolcreatedb,rolcreaterole from pg_roles where rolname=%s",
                (ROLE,)
            ).fetchone()
            self.assertEqual(role, (False,) * 6)
            relations = db.execute(
                "select relrowsecurity,relforcerowsecurity from pg_class "
                "where oid=to_regclass(%s)", (TABLE,)
            ).fetchone()
            self.assertEqual(relations, (True, True))
            for name in ("PUBLIC", "anon", "authenticated",
                         "service_role", "avuhz_command_service"):
                can_insert = db.execute(
                    "select has_table_privilege(%s,%s,'INSERT')",
                    (name, TABLE)
                ).fetchone()[0] if name != "PUBLIC" and db.execute(
                    "select 1 from pg_roles where rolname=%s",
                    (name,)
                ).fetchone() else None
                self.assertFalse(can_insert)
            count = db.execute(
                "select count(*) from pg_policies where "
                "schemaname='avuhz_handoff_control' "
                "and tablename='avuhz_handoff_approval_claims'"
            ).fetchone()[0]
            self.assertEqual(count, 1)
        with self.writer() as writer:
            self.assertEqual(
                writer.execute(
                    "select has_table_privilege(current_user,%s,'SELECT')",
                    (TABLE,)
                ).fetchone()[0],
                False
            )

    def test_wrong_role_and_invalid_scope_never_insert(self):
        with self.assertRaisesRegex(
            DurableHandoffClaimStop, "HANDOFF_DURABLE_CLAIM_WRITER_UNTRUSTED"
        ):
            self.run_claim(connection_factory=lambda: psycopg.connect(DSN))
        cases = (
            {"tenant_id": OTHER, "data_project_ref": DEVELOPMENT_AUTH_PROJECT_REF},
            {"source_sha": "b" * 39},
            {"claims": self.claims()[:3]},
            {"claims": tuple(replace(c, project_reference=DEVELOPMENT_DATA_PROJECT_REF)
                              if c.stage == "AUTH_VERIFY" else c
                              for c in self.claims())},
            {"claims": tuple(replace(c, approval_digest=self.claims()[0].approval_digest)
                              if c.stage == "AUTH_VERIFY" else c
                              for c in self.claims())},
        )
        for invalid in cases:
            with self.subTest(invalid=tuple(invalid)), self.assertRaisesRegex(
                DurableHandoffClaimStop, "HANDOFF_DURABLE_CLAIM_SCOPE_INVALID"
            ):
                self.run_claim(**invalid)
        self.assertEqual(self.rows(), [])

    def test_unavailable_store_never_reports_an_unconsumed_approval(self):
        def fail():
            raise OSError("synthetic hidden host diagnostic")
        with self.assertRaisesRegex(
            DurableHandoffClaimStop, "HANDOFF_DURABLE_CLAIM_OUTCOME_UNVERIFIED"
        ) as exc:
            self.run_claim(connection_factory=fail)
        self.assertNotIn("synthetic hidden host diagnostic", str(exc.exception))
        self.assertEqual(self.rows(), [])


if __name__ == "__main__":
    unittest.main()
