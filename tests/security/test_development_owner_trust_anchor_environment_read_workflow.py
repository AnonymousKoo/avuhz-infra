"""Static, offline guardrails for the separate read-only GitHub environment check.

These tests do not call GitHub, consume the existing one-shot workflow, or
claim the actual environment variable contents are already verified.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/development-owner-trust-anchor-environment-read-v1.yml"
ONE_SHOT = ROOT / ".github/workflows/development-first-handoff-trusted-dispatch-v1.yml"


class DevelopmentOwnerTrustAnchorEnvironmentReadWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = WORKFLOW.read_text()
        cls.oneshot = ONE_SHOT.read_text()

    def test_distinct_read_only_dispatch_never_changes_one_shot(self):
        self.assertNotEqual(WORKFLOW, ONE_SHOT)
        self.assertIn("on:\n  workflow_dispatch:", self.text)
        self.assertIn("environment: development", self.text)
        self.assertNotIn("github.run_number == 1", self.text)
        self.assertIn("github.run_number == 1", self.oneshot)
        self.assertIn("github.run_attempt == 1", self.oneshot)
        self.assertIn("OFFLINE ONLY", self.oneshot)

    def test_owner_and_protected_main_required_before_job(self):
        for required in (
            "github.ref == 'refs/heads/main'",
            "github.actor == 'AnonymousKoo'",
            "github.actor_id == 168945054",
            "github.triggering_actor == 'AnonymousKoo'",
            "github.repository == 'AnonymousKoo/avuhz-infra'",
            "github.run_attempt == 1",
            'g["GITHUB_REPOSITORY_ID"] == "1231399336"',
            'g["GITHUB_WORKFLOW_SHA"] == g["GITHUB_SHA"]',
            'git_value("ls-remote", "--exit-code", "origin", "refs/heads/main")',
        ):
            with self.subTest(required=required):
                self.assertIn(required, self.text)

    def test_read_only_permissions_fixed_checkout_and_no_credentials(self):
        self.assertIn("permissions:\n  contents: read", self.text)
        self.assertIn(
            "uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683",
            self.text
        )
        self.assertIn("persist-credentials: false", self.text)
        self.assertIn("ref: ${{ github.sha }}", self.text)
        for forbidden in (
            "${{ secrets.", "service_role", "supabase login", "n8n",
            "curl ", "wget ", "gh api ", "gh workflow run ",
            "/v1/commands", "supabase db", "workflow_call",
            "schedule:", "push:", "pull_request:",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, self.text)

    def test_exact_two_values_read_from_environment_variables_only(self):
        self.assertIn(
            "AVUHZ_OBSERVED_OWNER_PUBLIC_KEY: "
            "${{ vars.AVUHZ_HANDOFF_OWNER_ED25519_PUBLIC_KEY_BASE64 }}",
            self.text
        )
        self.assertIn(
            "AVUHZ_OBSERVED_OWNER_FINGERPRINT: "
            "${{ vars.AVUHZ_HANDOFF_OWNER_ED25519_FINGERPRINT }}",
            self.text
        )
        self.assertIn("prepare_development_owner_trust_anchor_candidate(", self.text)
        self.assertIn("ENV_PUBLIC_KEY: g.get(", self.text)
        self.assertIn("ENV_FINGERPRINT: g.get(", self.text)

    def test_no_authorization_or_sensitive_value_emitted(self):
        for forbidden in (
            "print(candidate.public_key", "print(candidate.public_key_fingerprint",
            "print(g[", "print(os.environ", "print(env", "echo ${{",
            "set -x", "secrets.AVUHZ_HANDOFF",
            "owner_key_enrolled_in_trusted_runner=true",
            "live_command_authorized=true",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, self.text)
        self.assertIn("human_owner_binding_verified=false", self.text)
        self.assertIn("live_command_authorized=false", self.text)
        self.assertIn("credential_resolution_authorized=false", self.text)
        self.assertIn("supabase_contact_attempted=false", self.text)

    def test_workflow_python_block_has_no_syntax_errors(self):
        match = re.search(r"          python3 - <<'PY'\n(.*?)\n          PY\n",
                          self.text, flags=re.DOTALL)
        self.assertIsNotNone(match)
        script = "\n".join(
            line[10:] if line.startswith("          ") else line
            for line in match.group(1).splitlines()
        )
        compile(script, str(WORKFLOW), "exec")


if __name__ == "__main__":
    unittest.main()
