"""No-provider security tests for one-shot trusted GitHub DEVELOPMENT dispatch."""
from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.development_handoff_trusted_github_invocation import (
    CONFIRMATION, OWNER_ACCOUNT_ID, OWNER_LOGIN, REPOSITORY, REPOSITORY_ID,
    WORKFLOW_REF, TrustedInvocationStop, verify_trusted_github_invocation,
)

SHA = "a10daf2033b0959197c1bdc5924ae9a820eee830"
DIGEST = "sha256:" + "a" * 64
ORIGIN = "https://github.com/AnonymousKoo/avuhz-infra"


def context():
    env = {
        "GITHUB_ACTIONS": "true",
        "GITHUB_REPOSITORY": REPOSITORY,
        "GITHUB_REPOSITORY_ID": REPOSITORY_ID,
        "GITHUB_ACTOR": OWNER_LOGIN,
        "GITHUB_ACTOR_ID": OWNER_ACCOUNT_ID,
        "GITHUB_TRIGGERING_ACTOR": OWNER_LOGIN,
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_SHA": SHA,
        "GITHUB_WORKFLOW_REF": WORKFLOW_REF,
        "GITHUB_WORKFLOW_SHA": SHA,
        "GITHUB_RUN_NUMBER": "1",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_RUN_ID": "9876543210",
        "AVUHZ_ENVIRONMENT": "development",
        "AVUHZ_CONFIRMATION": CONFIRMATION,
        "AVUHZ_EXPECTED_SOURCE_SHA": SHA,
        "AVUHZ_AUTHORIZATION_SET_DIGEST": DIGEST,
    }
    event = {
        "ref": "refs/heads/main",
        "sender": {"id": int(OWNER_ACCOUNT_ID), "login": OWNER_LOGIN},
        "repository": {"id": int(REPOSITORY_ID), "full_name": REPOSITORY},
        "inputs": {
            "confirmation": CONFIRMATION,
            "source_sha": SHA,
            "authorization_set_digest": DIGEST,
        },
    }
    return env, event


class TrustedGitHubInvocationTests(unittest.TestCase):
    def invoke(self, *, env=None, event=None, checkout=SHA, main=SHA, origin=ORIGIN):
        initial_env, initial_event = context()
        return verify_trusted_github_invocation(
            initial_env if env is None else env,
            initial_event if event is None else event,
            observed_checkout_sha=checkout,
            observed_remote_main_sha=main,
            observed_git_origin=origin,
        )

    def test_exact_first_owner_main_dispatch_is_only_offline_evidence(self):
        result = self.invoke()
        self.assertEqual(result.canonical_main_sha, SHA)
        self.assertEqual(result.authorization_set_claimed_digest, DIGEST)
        self.assertEqual(result.github_run_id, "9876543210")
        self.assertTrue(result.github_first_attempt_verified)
        self.assertTrue(result.invocation_source_verified)
        self.assertFalse(result.owner_approval_verified)
        self.assertFalse(result.authorization_set_verified)
        self.assertFalse(result.distributed_authorization_consumed)
        self.assertFalse(result.credential_resolution_authorized)
        self.assertFalse(result.live_command_authorized)
        self.assertFalse(result.provider_contact_attempted)

    def test_other_actor_trigger_or_account_id_is_denied(self):
        for field, value in (
            ("GITHUB_ACTOR", "untrusted-fork"),
            ("GITHUB_ACTOR_ID", "9999"),
            ("GITHUB_TRIGGERING_ACTOR", "reviewer"),
            ("GITHUB_REPOSITORY_ID", "9999"),
            ("GITHUB_REPOSITORY", "AnonymousKoo/another-repo"),
            ("GITHUB_ACTIONS", "false"),
        ):
            with self.subTest(field=field):
                env, event = context()
                env[field] = value
                with self.assertRaises(TrustedInvocationStop):
                    self.invoke(env=env, event=event)

    def test_replayed_rerun_or_nonmanual_dispatch_is_denied(self):
        for field, value in (
            ("GITHUB_RUN_NUMBER", "2"),
            ("GITHUB_RUN_ATTEMPT", "2"),
            ("GITHUB_EVENT_NAME", "pull_request"),
            ("GITHUB_REF", "refs/heads/feature"),
            ("GITHUB_RUN_ID", "0"),
            ("GITHUB_RUN_ID", "some-string"),
            ("AVUHZ_ENVIRONMENT", "production"),
            ("GITHUB_WORKFLOW_REF", "AnonymousKoo/avuhz-infra/.github/workflows/other.yml@refs/heads/main"),
        ):
            with self.subTest(field=field):
                env, event = context()
                env[field] = value
                with self.assertRaises(TrustedInvocationStop):
                    self.invoke(env=env, event=event)

    def test_source_checkout_workflow_sha_remote_drift_denied(self):
        env, event = context()
        for changed in (
            {"checkout": "b" * 40},
            {"main": "b" * 40},
            {"origin": "https://example.invalid/another-repo"},
        ):
            with self.subTest(changed=changed), self.assertRaisesRegex(
                TrustedInvocationStop, "HANDOFF_GITHUB_SOURCE_DRIFT"
            ):
                self.invoke(env=env, event=event, **changed)
        env["GITHUB_WORKFLOW_SHA"] = "b" * 40
        with self.assertRaisesRegex(TrustedInvocationStop, "HANDOFF_GITHUB_SOURCE_DRIFT"):
            self.invoke(env=env, event=event)

    def test_mismatched_event_sender_repository_or_inputs_denied(self):
        for change in (
            lambda e: e["sender"].update(id=42),
            lambda e: e["sender"].update(login="someone-else"),
            lambda e: e["repository"].update(id=123),
            lambda e: e.update(ref="refs/heads/other"),
            lambda e: e["inputs"].update(confirmation="BAD"),
            lambda e: e["inputs"].update(source_sha="b" * 40),
            lambda e: e["inputs"].update(authorization_set_digest="sha256:" + "f" * 64),
            lambda e: e["inputs"].update(extra="UNEXPECTED"),
        ):
            env, event = context()
            change(event)
            with self.assertRaisesRegex(TrustedInvocationStop, "HANDOFF_GITHUB_EVENT_MISMATCH"):
                self.invoke(env=env, event=event)

    def test_unsigned_digest_is_never_mistaken_for_owner_approval(self):
        env, event = context()
        env["AVUHZ_AUTHORIZATION_SET_DIGEST"] = "sha256:" + "0" * 64
        event["inputs"]["authorization_set_digest"] = env["AVUHZ_AUTHORIZATION_SET_DIGEST"]
        with self.assertRaisesRegex(TrustedInvocationStop, "HANDOFF_GITHUB_DIGEST_INVALID"):
            self.invoke(env=env, event=event)
        env, event = context()
        env["AVUHZ_AUTHORIZATION_SET_DIGEST"] = "invalid"
        event["inputs"]["authorization_set_digest"] = "invalid"
        with self.assertRaisesRegex(TrustedInvocationStop, "HANDOFF_GITHUB_DIGEST_INVALID"):
            self.invoke(env=env, event=event)

    def test_missing_environment_and_malformed_event_fail_closed(self):
        env, event = context()
        del env["GITHUB_ACTOR_ID"]
        with self.assertRaisesRegex(TrustedInvocationStop, "HANDOFF_GITHUB_INVOCATION_MISSING"):
            self.invoke(env=env, event=event)
        with self.assertRaisesRegex(TrustedInvocationStop, "HANDOFF_GITHUB_INVOCATION_MISSING"):
            self.invoke(event={})


if __name__ == "__main__":
    unittest.main()
