"""Credential-free tests for composed first GitHub DEVELOPMENT handoff execution."""
from __future__ import annotations

import json
import sqlite3
import sys
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [
    str(ROOT / "src"), str(ROOT / "tests/security"),
    str(ROOT / "tests/service"),
]

from test_development_handoff_single_use_claim import SignedSingleUseClaimTests
from test_development_handoff_approval_gate import AT
from test_development_handoff_trusted_github_invocation import context
from test_development_source_bound_handoff_lifecycle import callbacks

from avuhz_engineering.development_handoff_trusted_one_shot_executor import (
    SignedStageProof, TrustedOneShotStop, execute_trusted_development_handoff_once,
)


class TrustedOneShotExecutorTests(unittest.TestCase):
    def setUp(self):
        self.f = SignedSingleUseClaimTests(methodName="test_signed_claim_once_then_replay_denied")
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.source = self.f.fixture.source
        self.env, self.event = context()
        sha = self.source.canonical_main_sha
        for key in ("GITHUB_SHA", "GITHUB_WORKFLOW_SHA", "AVUHZ_EXPECTED_SOURCE_SHA"):
            self.env[key] = sha
        self.event["inputs"]["source_sha"] = sha
        self.env["AVUHZ_AUTHORIZATION_SET_DIGEST"] = self.source.authorization_plan_digest
        self.event["inputs"]["authorization_set_digest"] = self.source.authorization_plan_digest
        self.signed_proofs = {}
        for stage in self.f.fixture.stages:
            claims = self.f.claims(stage)
            encoded = json.dumps(
                claims, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ).encode()
            self.signed_proofs[stage] = SignedStageProof(
                claims=claims, signature=self.f.private.sign(encoded)
            )

    def run_once(self, events, **changes):
        opts, credential, session = callbacks(events)
        opts.pop("authorize_stage")
        params = dict(
            request=self.f.fixture.command,
            source=self.source,
            github_environment=self.env,
            github_event=self.event,
            observed_checkout_sha=self.source.canonical_main_sha,
            observed_remote_main_sha=self.source.canonical_main_sha,
            observed_git_origin="https://github.com/AnonymousKoo/avuhz-infra",
            at_utc=AT,
            stages=self.f.fixture.stages,
            signed_proofs=self.signed_proofs,
            owner_public_key=self.f.public,
            independently_pinned_key_digest=self.f.anchor,
            shared_runner_ledger=self.f.ledger,
            **opts,
        )
        params.update(changes)
        result = execute_trusted_development_handoff_once(**params)
        return result, credential, session

    def ledger_rows(self):
        with sqlite3.connect(self.f.ledger) as db:
            try:
                return db.execute(
                    "SELECT stage FROM avuhz_offline_handoff_stage_claim ORDER BY stage"
                ).fetchall()
            except sqlite3.OperationalError:
                return []

    def test_four_exact_signed_stage_claims_precede_single_send_and_logout(self):
        events = []
        result, credential, session = self.run_once(events)
        self.assertEqual(result.claimed_stage_count, 4)
        self.assertEqual(result.lifecycle.classification,
                         "SYNTHETIC_COMMAND_ACCEPTED_PENDING_DATA_VERIFICATION")
        self.assertTrue(result.lifecycle.command_attempted)
        self.assertTrue(result.lifecycle.global_logout_accepted)
        self.assertTrue(result.lifecycle.data_readback_required)
        self.assertTrue(result.lifecycle.session_state_readback_required)
        self.assertFalse(result.data_readback_verified)
        self.assertFalse(result.temporary_credential_retirement_verified)
        self.assertFalse(result.distributed_across_runners_verified)
        self.assertFalse(result.owner_key_enrollment_verified_by_runner)
        self.assertFalse(result.retry_authorized)
        self.assertEqual(len(self.ledger_rows()), 4)
        self.assertEqual([e[0] for e in events], [
            "resolve", "resolve", "resolve",
            "generate", "verify", "validate", "send", "logout",
        ])
        self.assertTrue(credential.is_cleared)
        self.assertTrue(session.is_cleared)

    def test_same_workflow_cannot_consume_four_claims_twice(self):
        self.run_once([])
        events = []
        with self.assertRaisesRegex(TrustedOneShotStop, "HANDOFF_LIFECYCLE_ALREADY_CLAIMED"):
            self.run_once(events)
        self.assertEqual(events, [])
        self.assertEqual(len(self.ledger_rows()), 4)

    def test_forged_one_stage_signature_rejects_entire_set_before_any_claim(self):
        bad = dict(self.signed_proofs)
        proof = bad["DATA_COMMAND"]
        bad["DATA_COMMAND"] = SignedStageProof(
            claims=proof.claims, signature=b"0" * 64
        )
        events = []
        with self.assertRaisesRegex(TrustedOneShotStop, "HANDOFF_STAGE_OWNER_SIGNATURE_UNVERIFIED"):
            self.run_once(events, signed_proofs=bad)
        self.assertEqual(events, [])
        self.assertEqual(self.ledger_rows(), [])

    def test_wrong_main_or_wrong_owner_reject_before_claim(self):
        events = []
        with self.assertRaisesRegex(TrustedOneShotStop, "HANDOFF_TRUSTED_GITHUB_INVOCATION_DENIED"):
            self.run_once(events, observed_remote_main_sha="b" * 40)
        self.assertEqual(self.ledger_rows(), [])
        env = dict(self.env)
        env["GITHUB_ACTOR_ID"] = "9999"
        with self.assertRaisesRegex(TrustedOneShotStop, "HANDOFF_TRUSTED_GITHUB_INVOCATION_DENIED"):
            self.run_once(events, github_environment=env)
        self.assertEqual(events, [])

    def test_one_existing_stage_claim_rolls_back_other_three_atomically(self):
        # Another owner-approved one-stage claim already used same plan.
        self.f.invoke("DATA_COMMAND")
        events = []
        with self.assertRaisesRegex(TrustedOneShotStop, "HANDOFF_LIFECYCLE_ALREADY_CLAIMED"):
            self.run_once(events)
        self.assertEqual(self.ledger_rows(), [("DATA_COMMAND",)])
        self.assertEqual(events, [])

    def test_concurrent_all_stage_claims_allow_only_one_lifecycle(self):
        event_sets = [[] for _ in range(5)]
        with ThreadPoolExecutor(max_workers=5) as pool:
            futures = [pool.submit(self.run_once, e) for e in event_sets]
            results, failures = [], []
            for f in futures:
                try:
                    results.append(f.result()[0])
                except TrustedOneShotStop as exc:
                    failures.append(str(exc))
        self.assertEqual(len(results), 1)
        self.assertEqual(failures, ["HANDOFF_LIFECYCLE_ALREADY_CLAIMED"] * 4)
        self.assertEqual(sum(e[0] == "send" for es in event_sets for e in es), 1)
        self.assertEqual(len(self.ledger_rows()), 4)

    def test_claim_remains_consumed_after_ambiguous_transport_outcome(self):
        events = []
        options, credential, session = callbacks(events, transport_failure=True)
        options.pop("authorize_stage")
        outcome, _, _ = self.run_once(events, **options)
        self.assertEqual(
            outcome.lifecycle.classification,
            "SYNTHETIC_COMMAND_OUTCOME_UNVERIFIED"
        )
        self.assertEqual([e[0] for e in events].count("send"), 1)
        self.assertFalse(outcome.retry_authorized)
        self.assertEqual(len(self.ledger_rows()), 4)
        with self.assertRaises(TrustedOneShotStop):
            self.run_once([])
        self.assertTrue(credential.is_cleared)
        self.assertTrue(session.is_cleared)


if __name__ == "__main__":
    unittest.main()
