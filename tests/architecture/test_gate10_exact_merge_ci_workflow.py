"""Offline review checks: no workflow dispatch, packages, services or provider calls."""
import os
import re
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from ruamel.yaml import YAML

ROOT = Path(__file__).resolve().parents[2]
SOURCE = "047828fe59e743932162df7776fcb37f25647689"
WORKFLOW = ROOT / ".github/workflows/gate10-exact-merge-ci.yml"


def load_workflow():
    return YAML(typ="safe").load(WORKFLOW.read_text())


def historical_job():
    raw = subprocess.check_output(
        ["git", "show", SOURCE + ":.github/workflows/main-pr-gate.yml"], cwd=ROOT
    )
    return YAML(typ="safe").load(raw)["jobs"]["main-pr-gate"]


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.workflow = load_workflow()
        self.job = self.workflow["jobs"]["exact-merge-evidence"]
        self.steps = {step["name"]: step for step in self.job["steps"]}
        self.bootstrap = self.steps["Verify exact source and record non-certified identity"]["run"]

    def test_manual_known_repository_first_attempt_and_least_privilege(self):
        self.assertEqual(self.workflow["on"], {"workflow_dispatch": {"inputs": {
            "expected_workflow_sha": {
                "description": "Reviewed current main commit SHA; evidence binding only, not authorization",
                "required": True, "type": "string",
            },
        }}})
        self.assertEqual(self.workflow["permissions"], {"contents": "read"})
        self.assertEqual(len(self.workflow["jobs"]), 1)
        self.assertEqual(
            self.job["if"],
            "github.repository == 'AnonymousKoo/avuhz-infra' && "
            "github.event_name == 'workflow_dispatch' && "
            "github.ref == 'refs/heads/main' && "
            "github.actor == 'AnonymousKoo' && github.actor_id == '168945054' && "
            "github.run_attempt == 1 && "
            "inputs.expected_workflow_sha != '' && "
            "inputs.expected_workflow_sha == github.sha && "
            "inputs.expected_workflow_sha == github.workflow_sha",
        )
        self.assertEqual(set(self.job), {"if", "runs-on", "timeout-minutes", "env", "steps"})
        text = WORKFLOW.read_text()
        for expression in ("secrets.", "id-token:", "environment:", "upload-artifact@",
                           "retention-days:", "pull_request_target:"):
            self.assertNotIn(expression, text)
        self.assertNotIn("${{", "\n".join(s.get("run", "") for s in self.job["steps"]))

    def test_job_guard_rejects_unmatched_dispatch_context(self):
        # Evaluate the actual restricted conjunction, not a second hand-written guard.
        # GitHub comparisons are case-insensitive and coerce numeric equality;
        # exact spelling, SHA shape and attempt spelling are rechecked by Bash.
        context = {
            "github.repository": "AnonymousKoo/avuhz-infra",
            "github.event_name": "workflow_dispatch", "github.ref": "refs/heads/main",
            "github.actor": "AnonymousKoo", "github.actor_id": "168945054",
            "github.run_attempt": "1", "github.sha": "a" * 40,
            "github.workflow_sha": "a" * 40, "inputs.expected_workflow_sha": "a" * 40,
        }

        def permits(values):
            outcomes = []
            for clause in self.job["if"].split(" && "):
                match = re.fullmatch(
                    r"((?:github|inputs)\.[a-z_]+) (==|!=) ('[^']*'|1|(?:github|inputs)\.[a-z_]+)",
                    clause,
                )
                self.assertIsNotNone(match, "unsupported guard expression")
                left, operator, right = match.groups()
                lhs = values.get(left, "")
                if right == "1":
                    try:
                        equal = float(lhs or 0) == 1
                    except ValueError:
                        equal = False
                else:
                    rhs = right[1:-1] if right.startswith("'") else values.get(right, "")
                    equal = lhs.casefold() == rhs.casefold()
                outcomes.append(equal if operator == "==" else not equal)
            return all(outcomes)

        self.assertTrue(permits(context))
        for key, value in (
            ("github.repository", "fork/avuhz-infra"), ("github.event_name", "push"),
            ("github.ref", "refs/heads/feature"), ("github.ref", "refs/tags/main"),
            ("github.actor", "reviewer"), ("github.actor_id", "168945055"),
            ("github.run_attempt", "2"), ("github.run_attempt", "0"),
            ("inputs.expected_workflow_sha", ""), ("inputs.expected_workflow_sha", "b" * 40),
            ("github.sha", "b" * 40), ("github.workflow_sha", "b" * 40),
        ):
            with self.subTest(key=key, value=value):
                self.assertFalse(permits({**context, key: value}))
        for key in context:
            with self.subTest(missing=key):
                self.assertFalse(permits({k: v for k, v in context.items() if k != key}))

    def test_only_checkout_is_an_action_and_source_is_immutable(self):
        actions = [s for s in self.job["steps"] if "uses" in s]
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["uses"], "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683")
        self.assertEqual(actions[0]["with"], {
            "repository": "AnonymousKoo/avuhz-infra", "ref": SOURCE,
            "fetch-depth": 2, "persist-credentials": False,
            "clean": True, "submodules": False, "lfs": False,
        })
        self.assertEqual(self.job["env"]["SOURCE_SHA"], SOURCE)
        self.assertEqual(self.job["env"]["WORKFLOW_SHA"], "${{ github.workflow_sha }}")
        self.assertEqual(self.job["env"]["EXPECTED_WORKFLOW_SHA"],
                         "${{ inputs.expected_workflow_sha }}")
        self.assertIn('test "$(git rev-parse HEAD)" = "$SOURCE_SHA"', self.bootstrap)

    def test_historical_environment_and_substantive_steps_have_exact_parity(self):
        historical = historical_job()
        for key, value in historical["env"].items():
            self.assertEqual(self.job["env"][key], value, key)
        # The current branch is deliberately not the recipe source.
        self.assertIn("ef257d85f76e48da", self.job["env"]["AVUHZ_POSTGRES_IMAGE"])
        for original in historical["steps"][2:-3]:
            with self.subTest(step=original["name"]):
                self.assertIn(original["run"], self.steps[original["name"]]["run"])
        self.assertIn(historical["steps"][-1]["run"], self.steps["Remove disposable PostgreSQL"]["run"])
        self.assertEqual(self.steps["Remove disposable PostgreSQL"]["if"], "always()")
        for name in ("Run PostgreSQL migration suites", "Run disposable PostgreSQL integration suites"):
            self.assertIn("skipped=[1-9][0-9]*", self.steps[name]["run"])
        self.assertIn('--require-hashes --only-binary=:all:',
                      self.steps["Install pinned local validation dependencies"]["run"])

    def test_pr_adaptation_and_clean_source_build_copy(self):
        runs = "\n".join(s.get("run", "") for s in self.job["steps"])
        self.assertNotIn("github.event.pull_request", runs)
        self.assertIn('git diff --check "$SOURCE_SHA^1" "$SOURCE_SHA"', runs)
        self.assertIn('cp -a "$GITHUB_WORKSPACE/." "$build_source/"', runs)
        self.assertNotIn("git archive", runs)
        self.assertIn('python3 "$RUNNER_TEMP/gate10-integrity.py"',
                      self.steps["Verify final raw checkout integrity"]["run"])

    def test_evidence_is_non_certified_with_separate_provenance_identities(self):
        for field in ("evidence_class=non-certified", "provenance=absent", "workflow_sha=%s",
                      "source_sha=%s", "actor=%s", "run_id=%s", "attempt=%s"):
            self.assertIn(field, self.bootstrap)
        self.assertIn("certification_granted=false", self.steps["Record non-certified completion"]["run"])
        self.assertIn("runner network", WORKFLOW.read_text())

    def test_every_shell_script_parses_without_execution(self):
        for step in self.job["steps"]:
            if "run" in step:
                with self.subTest(step=step["name"]):
                    result = subprocess.run(["bash", "-n"], input=step["run"], text=True,
                                            capture_output=True)
                    self.assertEqual(result.returncode, 0, result.stderr)

    def test_failure_wrapper_stops_before_later_success(self):
        # Execute only the wrapper with a synthetic failure, never historical commands.
        step = self.steps["Run canonical repository baseline"]["run"]
        historical = next(s for s in historical_job()["steps"]
                          if s["name"] == "Run canonical repository baseline")
        script = step.replace(historical["run"], 'set -euo pipefail\nfalse\necho unsafe_continuation\n')
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(["bash"], input=script, text=True, capture_output=True,
                                    env={**os.environ, "RUNNER_TEMP": tmp})
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("unsafe_continuation", Path(tmp, "gate10-step-output").read_text())
            self.assertNotIn("historical_check=passed", result.stdout)
            self.assertIn("raw output withheld", result.stdout)

    def test_skipped_postgres_suites_cannot_record_success(self):
        # Replace only the unittest invocation with synthetic output. Execute the
        # real skip guard and failure wrapper; no database or historical suite runs.
        for name in ("Run PostgreSQL migration suites", "Run disposable PostgreSQL integration suites"):
            run = self.steps[name]["run"]
            start = run.index("python3 -m unittest discover")
            end = run.index(' | tee "$output"', start)
            command = run[start:end]
            for report, accepted in (("OK", True), ("OK (skipped=1)", False),
                                     ("test_example ... skipped 'unavailable'", False)):
                with self.subTest(step=name, report=report), tempfile.TemporaryDirectory() as tmp:
                    script = run.replace(command, "printf '%s\\n' "+repr(report))
                    self.assertNotIn("python3 -m unittest", script)
                    result = subprocess.run(["bash"], input=script, text=True, capture_output=True,
                                            env={"PATH": os.environ["PATH"], "RUNNER_TEMP": tmp})
                    self.assertEqual(result.returncode == 0, accepted, result.stderr)
                    self.assertEqual("historical_check=passed" in result.stdout, accepted)

    def test_identity_and_database_denials_before_any_tool_or_service(self):
        # Only the preflight prefix runs. Stub Git HEAD; all substantive CI is excluded.
        prefix = self.bootstrap.split("cat >", 1)[0]
        with tempfile.TemporaryDirectory() as tmp:
            git = Path(tmp, "git")
            git.write_text('#!/bin/sh\nprintf "%s\\n" "$FIXTURE_HEAD"\n')
            git.chmod(0o755)
            env = {"PATH": tmp + os.pathsep + os.environ["PATH"],
                   "GITHUB_REPOSITORY": "AnonymousKoo/avuhz-infra",
                   "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_RUN_ATTEMPT": "1",
                   "SOURCE_SHA": SOURCE, "FIXTURE_HEAD": SOURCE, "WORKFLOW_SHA": "a" * 40,
                   "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": "a" * 40,
                   "EXPECTED_WORKFLOW_SHA": "a" * 40,
                   "GITHUB_ACTOR": "AnonymousKoo", "GITHUB_ACTOR_ID": "168945054",
                   "GITHUB_RUN_ID": "123",
                   "AVUHZ_POSTGRES_DSN": self.job["env"]["AVUHZ_POSTGRES_DSN"]}
            result = subprocess.run(["bash"], input=prefix, text=True, capture_output=True, env=env)
            self.assertEqual(result.returncode, 0, result.stderr)
            for key, value in (("GITHUB_REPOSITORY", "fork/avuhz-infra"),
                               ("GITHUB_EVENT_NAME", "push"), ("GITHUB_RUN_ATTEMPT", "2"),
                               ("GITHUB_REF", "refs/heads/feature"), ("GITHUB_REF", "refs/tags/main"),
                               ("GITHUB_REF", "refs/heads/Main"),
                               ("GITHUB_ACTOR", "reviewer"), ("GITHUB_ACTOR", "anonymouskoo"),
                               ("GITHUB_ACTOR_ID", "168945055"),
                               ("GITHUB_RUN_ATTEMPT", "0"), ("GITHUB_RUN_ATTEMPT", ""),
                               ("EXPECTED_WORKFLOW_SHA", ""), ("EXPECTED_WORKFLOW_SHA", "b" * 40),
                               ("EXPECTED_WORKFLOW_SHA", "A" * 40),
                               ("EXPECTED_WORKFLOW_SHA", '$(echo unsafe_injection)'),
                               ("GITHUB_SHA", "b" * 40), ("GITHUB_SHA", ""),
                               ("SOURCE_SHA", "b" * 40), ("FIXTURE_HEAD", "b" * 40),
                               ("WORKFLOW_SHA", SOURCE),
                               ("WORKFLOW_SHA", "b" * 40), ("WORKFLOW_SHA", ""),
                               ("GITHUB_ACTOR", "bad\nactor"), ("GITHUB_RUN_ID", "1\ninjected"),
                               ("PGHOST", "hosted.invalid"), ("PGSERVICE", "hosted"),
                               ("AVUHZ_POSTGRES_DSN", "host=hosted.invalid"),
                               ("SUPABASE_URL", "hosted.invalid"),
                               ("AVUHZ_RUN_UNIFIED_LOCAL_ACCEPTANCE_PG", "1")):
                with self.subTest(key=key, value=value):
                    result = subprocess.run(["bash"], input=prefix, text=True,
                                            capture_output=True, env={**env, key: value})
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, "")
                    expected_error = ("unexpected_database_environment\n" if key in {
                        "PGHOST", "PGSERVICE", "SUPABASE_URL", "AVUHZ_RUN_UNIFIED_LOCAL_ACCEPTANCE_PG"
                    } else "")
                    self.assertEqual(result.stderr, expected_error)
            # Missing required context also fails closed; never inherit host GitHub values.
            for key in ("GITHUB_REF", "GITHUB_SHA", "GITHUB_ACTOR", "GITHUB_ACTOR_ID",
                        "EXPECTED_WORKFLOW_SHA", "SOURCE_SHA", "WORKFLOW_SHA",
                        "GITHUB_REPOSITORY", "GITHUB_EVENT_NAME", "GITHUB_RUN_ID",
                        "GITHUB_RUN_ATTEMPT"):
                with self.subTest(missing=key):
                    result = subprocess.run(["bash"], input=prefix, text=True, capture_output=True,
                                            env={k: v for k, v in env.items() if k != key})
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, "")


class RawIntegrityTests(unittest.TestCase):
    def setUp(self):
        bootstrap = load_workflow()["jobs"]["exact-merge-evidence"]["steps"][1]["run"]
        code = bootstrap.split("<<'PYINTEGRITY'\n", 1)[1].split("\nPYINTEGRITY", 1)[0]
        self.namespace = {"__name__": "gate10_test"}
        exec(compile(code, "<workflow-integrity>", "exec"), self.namespace)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.git("init", "-q")
        self.git("config", "core.autocrlf", "false")
        (self.root / "tracked").write_bytes(b"canonical\n")
        (self.root / ".gitignore").write_text("ignored\n")
        self.seal()

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.root), *args], stderr=subprocess.DEVNULL)

    def seal(self):
        # Synthetic temporary index/tree only: never create a commit, ref or worktree.
        self.git("add", ".")
        self.tree = self.git("write-tree").decode().strip()

    def verify(self, dirty=False):
        real_git = self.namespace["git"]

        def fixture_git(root, *args, **kwargs):
            if args[0] == "status":
                return b" M tracked\n" if dirty else b""
            return real_git(root, *args, **kwargs)

        with patch.dict(self.namespace, git=fixture_git):
            self.namespace["verify"](self.root, self.tree)

    def test_exact_tree_and_git_metadata_exclusion(self):
        (self.root / ".git" / "excluded-metadata").write_text("excluded")
        self.verify()

    def test_raw_byte_substitution_denied_even_if_git_reports_clean(self):
        (self.root / "tracked").write_bytes(b"substituted\r\n")
        with self.assertRaisesRegex(ValueError, "raw_blob_mismatch"):
            self.verify()

    def test_file_mode_change_denied(self):
        (self.root / "tracked").chmod(0o755)
        with self.assertRaisesRegex(ValueError, "file_mode_mismatch"):
            self.verify()

    def test_untracked_ignored_and_empty_directory_denied(self):
        for name, directory in (("extra", False), ("ignored", False), ("empty", True)):
            with self.subTest(name=name):
                path = self.root / name
                path.mkdir() if directory else path.write_text("extra")
                with self.assertRaises(ValueError):
                    self.verify()
                path.rmdir() if directory else path.unlink()

    def test_missing_file_and_dirty_status_denied(self):
        with self.assertRaisesRegex(ValueError, "dirty_source"):
            self.verify(dirty=True)
        (self.root / "tracked").unlink()
        with self.assertRaisesRegex(ValueError, "missing_file"):
            self.verify()

    def test_file_and_directory_symlinks_denied(self):
        for target in ("tracked", ".git"):
            path = self.root / "extra-link"
            path.symlink_to(target)
            with self.assertRaisesRegex(ValueError, "extra_or_special_file"):
                self.verify()
            path.unlink()
        (self.root / "tracked").unlink()
        (self.root / "tracked").symlink_to(".gitignore")
        self.seal()
        with self.assertRaisesRegex(ValueError, "unsupported_tree_entry"):
            self.verify()

    def test_submodule_mode_denied(self):
        self.git("update-index", "--add", "--cacheinfo", "160000," + SOURCE + ",module")
        self.tree = self.git("write-tree").decode().strip()
        with self.assertRaisesRegex(ValueError, "unsupported_tree_entry"):
            self.verify()

    def test_filter_attribute_denied_without_executing_filter(self):
        (self.root / ".gitattributes").write_text("tracked filter=forbidden\n")
        self.seal()
        with self.assertRaisesRegex(ValueError, "filter_attribute"):
            self.verify()

    def test_index_change_denied(self):
        (self.root / "tracked").write_bytes(b"changed\n")
        self.git("add", "tracked")
        with self.assertRaisesRegex(ValueError, "index_mismatch"):
            self.verify()


if __name__ == "__main__":
    unittest.main()
