"""Disposable PostgreSQL validation for signed approval -> durable claim bridge.

No hosted Supabase, GitHub workflow dispatch, credentials, AUTH, or HTTPS.
The original offline SQLite executor remains isolated from these tests.
"""
from __future__ import annotations

import os
import sys
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import psycopg
from psycopg.conninfo import conninfo_to_dict

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [
    str(ROOT / "src"), str(ROOT / "tests/integration"),
    str(ROOT / "tests/security"), str(ROOT / "tests/service"),
]

from development_handoff_claim_installation_candidate import INSTALLATION_CANDIDATE_SQL
from test_development_handoff_trusted_one_shot_executor import (
    TrustedOneShotExecutorTests,
)
from avuhz_engineering.development_handoff_trusted_one_shot_executor import (
    SignedStageProof, TrustedOneShotStop,
    claim_signed_handoff_stages_postgres_candidate,
)
from avuhz_engineering.development_handoff_owner_trust_anchor import ENV_PUBLIC_KEY
from avuhz_service.development import (
    DEVELOPMENT_AUTH_PROJECT_REF, DEVELOPMENT_DATA_PROJECT_REF,
)

DSN = os.environ.get("AVUHZ_POSTGRES_DSN")
SCHEMA = "avuhz_handoff_control"
TABLE = "avuhz_handoff_control.avuhz_handoff_approval_claims"
ROLE = "avuhz_handoff_claim_writer"


def disposable_scope() -> None:
    if not DSN:
        raise RuntimeError("DISPOSABLE_POSTGRES_DSN_MISSING")
    p = conninfo_to_dict(DSN)
    if (
        p.get("host") not in ("localhost", "127.0.0.1", "::1")
        or p.get("user") != "postgres"
        or not os.environ.get("AVUHZ_INTEGRATION_DATABASE")
        or p.get("dbname") != os.environ["AVUHZ_INTEGRATION_DATABASE"]
    ):
        raise RuntimeError("DISPOSABLE_POSTGRES_SCOPE_INVALID")


@unittest.skipUnless(DSN, "disposable PostgreSQL only")
class SignedPostgresHandoffBridgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        disposable_scope()

    def setUp(self) -> None:
        disposable_scope()
        self.signed = TrustedOneShotExecutorTests(
            methodName="test_four_exact_signed_stage_claims_precede_single_send_and_logout"
        )
        self.signed.setUp()
        self.addCleanup(self.signed.doCleanups)
        with psycopg.connect(DSN, autocommit=True) as db:
            if db.execute(
                "select to_regnamespace(%s) is not null or "
                "exists(select 1 from pg_roles where rolname=%s)",
                (SCHEMA, ROLE),
            ).fetchone()[0]:
                raise AssertionError("DISPOSABLE_CLAIM_SCHEMA_NOT_CLEAN")
            db.execute(INSTALLATION_CANDIDATE_SQL)

    def tearDown(self) -> None:
        disposable_scope()
        with psycopg.connect(DSN, autocommit=True) as db:
            db.execute("drop schema if exists avuhz_handoff_control cascade")
            db.execute("drop role if exists avuhz_handoff_claim_writer")
        super().tearDown()

    @staticmethod
    def writer():
        disposable_scope()
        db = psycopg.connect(DSN)
        try:
            db.execute("set role avuhz_handoff_claim_writer")
            db.commit()
            return db
        except Exception:
            db.close()
            raise

    def args(self):
        s = self.signed
        return dict(
            request=s.f.fixture.command,
            source=s.source,
            github_environment=s.env,
            github_event=s.event,
            observed_checkout_sha=s.source.canonical_main_sha,
            observed_remote_main_sha=s.source.canonical_main_sha,
            observed_git_origin="https://github.com/AnonymousKoo/avuhz-infra",
            at_utc=__import__("test_development_handoff_approval_gate").AT,
            stages=s.f.fixture.stages,
            signed_proofs=s.signed_proofs,
            owner_public_key=s.f.public,
            independently_pinned_key_digest=s.f.anchor,
            connection_factory=self.writer,
        )

    def claim(self, **updates):
        p = self.args()
        p.update(updates)
        return claim_signed_handoff_stages_postgres_candidate(**p)

    def count(self) -> int:
        disposable_scope()
        with psycopg.connect(DSN) as db:
            return db.execute(f"select count(*) from {TABLE}").fetchone()[0]

    def test_signed_four_stage_set_claims_atomically_without_live_authority(self):
        receipt = self.claim()
        self.assertEqual(receipt.claimed_stage_count, 4)
        self.assertEqual(self.count(), 4)
        self.assertFalse(receipt.live_execution_authorized)
        self.assertFalse(receipt.signed_approval_authority_verified)
        self.assertFalse(receipt.human_owner_binding_verified)
        self.assertFalse(receipt.retry_authorized)
        with psycopg.connect(DSN) as db:
            observed = dict(db.execute(
                f"select stage,project_reference from {TABLE}"
            ).fetchall())
        self.assertEqual(observed, {
            "AUTH_GLOBAL_LOGOUT": DEVELOPMENT_AUTH_PROJECT_REF,
            "AUTH_GENERATE": DEVELOPMENT_AUTH_PROJECT_REF,
            "AUTH_VERIFY": DEVELOPMENT_AUTH_PROJECT_REF,
            "DATA_COMMAND": DEVELOPMENT_DATA_PROJECT_REF,
        })
        # The offline SQLite ledger was not used by this bridge.
        self.assertEqual(self.signed.ledger_rows(), [])

    def test_signed_replay_is_terminal_and_never_claims_again(self):
        self.claim()
        with self.assertRaisesRegex(
            TrustedOneShotStop, "HANDOFF_DURABLE_CLAIM_ALREADY_CONSUMED"
        ):
            self.claim()
        self.assertEqual(self.count(), 4)

    def test_forged_final_stage_stops_before_opening_any_connection(self):
        bad = dict(self.signed.signed_proofs)
        original = bad["DATA_COMMAND"]
        bad["DATA_COMMAND"] = SignedStageProof(
            claims=original.claims, signature=b"0" * 64
        )
        def must_not_open():
            raise AssertionError("untrusted proof reached database")
        with self.assertRaisesRegex(
            TrustedOneShotStop, "HANDOFF_STAGE_OWNER_SIGNATURE_UNVERIFIED"
        ):
            self.claim(signed_proofs=bad, connection_factory=must_not_open)
        self.assertEqual(self.count(), 0)

    def test_source_and_public_pin_drift_stops_before_database(self):
        def must_not_open():
            raise AssertionError("untrusted source reached database")
        with self.assertRaisesRegex(
            TrustedOneShotStop, "HANDOFF_TRUSTED_GITHUB_INVOCATION_DENIED"
        ):
            self.claim(
                observed_remote_main_sha="f" * 40,
                connection_factory=must_not_open,
            )
        with self.assertRaisesRegex(
            TrustedOneShotStop, "HANDOFF_OWNER_SIGNING_PIN_UNVERIFIED"
        ):
            self.claim(
                github_environment={
                    **self.signed.env,
                    ENV_PUBLIC_KEY: "invalid-owner-public-pin",
                },
                connection_factory=must_not_open,
            )
        self.assertEqual(self.count(), 0)

    def test_wrong_writer_and_connection_failure_stop_without_leaks(self):
        with self.assertRaisesRegex(
            TrustedOneShotStop, "HANDOFF_DURABLE_CLAIM_WRITER_UNTRUSTED"
        ):
            self.claim(connection_factory=lambda: psycopg.connect(DSN))
        def unavailable():
            raise OSError("private test transport diagnostic")
        with self.assertRaisesRegex(
            TrustedOneShotStop, "HANDOFF_DURABLE_CLAIM_OUTCOME_UNVERIFIED"
        ) as caught:
            self.claim(connection_factory=unavailable)
        self.assertNotIn("private test transport diagnostic", str(caught.exception))
        self.assertEqual(self.count(), 0)

    def test_four_connections_contend_single_winner(self):
        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = [pool.submit(self.claim) for _ in range(4)]
            wins, stops = [], []
            for future in futures:
                try:
                    wins.append(future.result())
                except TrustedOneShotStop as err:
                    stops.append(str(err))
        self.assertEqual(len(wins), 1)
        self.assertEqual(
            stops, ["HANDOFF_DURABLE_CLAIM_ALREADY_CONSUMED"] * 3
        )
        self.assertEqual(self.count(), 4)

    def test_conflicting_existing_stage_rolls_back_other_three(self):
        s = self.signed
        stage = "AUTH_VERIFY"
        doc = s.f.fixture.stages[stage]
        with psycopg.connect(DSN) as db:
            db.execute(
                f"insert into {TABLE} "
                "(tenant_id,stage,plan_id,step_id,plan_digest,approval_digest,"
                "project_reference,authorization_set_digest,command_digest,source_sha)"
                " values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (
                    s.source.tenant_id, stage, doc.plan["plan_id"],
                    doc.plan["steps"][0]["step_id"], doc.plan["plan_digest"],
                    doc.approval["approval_digest"],
                    DEVELOPMENT_AUTH_PROJECT_REF,
                    s.source.authorization_plan_digest, s.source.command_digest,
                    s.source.canonical_main_sha,
                ),
            )
        with self.assertRaisesRegex(
            TrustedOneShotStop, "HANDOFF_DURABLE_CLAIM_ALREADY_CONSUMED"
        ):
            self.claim()
        self.assertEqual(self.count(), 1)


if __name__ == "__main__":
    unittest.main()
