"""Offline review checks: no workflow dispatch, packages, services or provider calls."""
import os
import copy
import hashlib
import json
import re
import shlex
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
        self.signer = self.workflow["jobs"]["attest-exact-wheel"]
        self.steps = {step["name"]: step for step in self.job["steps"]}
        self.bootstrap = self.steps["Verify exact source and record non-certified identity"]["run"]

    def fixture_env(self, tmp):
        code = self.bootstrap.split("<<'PYEVIDENCE'\n", 1)[1].split("\nPYEVIDENCE", 1)[0]
        Path(tmp, "gate10-evidence.py").write_text(code)
        return {"PATH": os.environ["PATH"], "RUNNER_TEMP": tmp,
                "GITHUB_OUTPUT": str(Path(tmp, "outputs"))}

    def test_manual_known_repository_first_attempt_and_least_privilege(self):
        self.assertEqual(self.workflow["on"], {"workflow_dispatch": {"inputs": {
            "expected_workflow_sha": {
                "description": "Reviewed eventual main merge commit SHA; evidence binding only, not authorization",
                "required": True, "type": "string",
            },
        }}})
        self.assertEqual(self.workflow["permissions"], {"contents": "read"})
        self.assertEqual(set(self.workflow["jobs"]), {"exact-merge-evidence", "attest-exact-wheel"})
        self.assertEqual(
            self.job["if"],
            "github.repository == 'AnonymousKoo/avuhz-infra' && "
            "github.repository_owner == 'AnonymousKoo' && github.repository_owner_id == '168945054' && "
            "github.workflow_ref == 'AnonymousKoo/avuhz-infra/.github/workflows/gate10-exact-merge-ci.yml@refs/heads/main' && "
            "github.event_name == 'workflow_dispatch' && "
            "github.ref == 'refs/heads/main' && "
            "github.actor == 'AnonymousKoo' && github.actor_id == '168945054' && "
            "github.run_attempt == 1 && "
            "inputs.expected_workflow_sha != '' && "
            "inputs.expected_workflow_sha == github.sha && "
            "inputs.expected_workflow_sha == github.workflow_sha",
        )
        self.assertEqual(set(self.job), {"if", "permissions", "outputs", "runs-on", "timeout-minutes", "env", "steps"})
        text = WORKFLOW.read_text()
        for expression in ("secrets.", "environment:", "pull_request_target:"):
            self.assertNotIn(expression, text)
        self.assertNotIn("${{", "\n".join(s.get("run", "") for s in self.job["steps"]))

    def assert_retention_contract(self, job, signer):
        self.assertEqual(job["permissions"], {"contents": "read"})
        self.assertEqual(job["outputs"], {
            "wheel_sha256": "${{ steps.wheel_subject.outputs.wheel_sha256 }}",
            "artifact_id": "${{ steps.upload.outputs.artifact-id }}",
        })
        self.assertEqual(signer["permissions"], {
            "contents": "read", "id-token": "write", "attestations": "write",
            "artifact-metadata": "write",
        })
        self.assertEqual(signer["needs"], ["exact-merge-evidence"])
        self.assertEqual(signer["if"], job["if"])
        self.assertEqual(signer["runs-on"], "ubuntu-latest")
        steps = {s["id"]: s for s in job["steps"]}
        signed = {s["id"]: s for s in signer["steps"]}
        path = "${{ steps.wheel_subject.outputs.wheel_path }}"
        self.assertNotIn("attest", steps)
        self.assertEqual(signed["attest"], {
            "name": "Attest exact CI wheel", "id": "attest",
            "uses": "actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6",
            "with": {"subject-path": path},
        })
        self.assertEqual(steps["upload"], {
            "name": "Upload exact CI wheel for temporary retrieval", "id": "upload",
            "uses": "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
            "with": {"name": "gate10-wheel-${{ github.sha }}-${{ github.run_id }}-${{ github.run_attempt }}",
                     "path": path, "if-no-files-found": "error", "retention-days": 30},
        })
        self.assertEqual(signed["download"]["uses"],
                         "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093")
        self.assertEqual(signed["download"]["with"], {
            "artifact-ids": "${{ needs.exact-merge-evidence.outputs.artifact_id }}",
            "path": "${{ runner.temp }}/gate10-signer-wheel", "merge-multiple": True,
        })
        self.assertEqual(steps["wheel_subject"]["env"], {
            "VERIFIED_WHEEL_SHA256": "${{ steps.wheel_contents.outputs.wheel_sha256 }}",
        })
        self.assertEqual(signer["env"], {
            **{k: job["env"][k] for k in ("SOURCE_SHA", "WORKFLOW_REF", "REPOSITORY_OWNER",
                                          "REPOSITORY_OWNER_ID", "WORKFLOW_SHA", "EXPECTED_WORKFLOW_SHA")},
            "PRODUCER_RESULT": "${{ needs.exact-merge-evidence.result }}",
            "ARTIFACT_ID": "${{ needs.exact-merge-evidence.outputs.artifact_id }}",
            "VERIFIED_WHEEL_SHA256": "${{ needs.exact-merge-evidence.outputs.wheel_sha256 }}",
            "DOWNLOAD_PATH": "${{ runner.temp }}/gate10-signer-wheel",
        })
        for stage in ("wheel_subject", "upload"):
            self.assertNotIn("if", steps[stage])
            self.assertNotIn("continue-on-error", steps[stage])
        self.assertEqual([s["id"] for s in signer["steps"]],
                         ["signer_guard", "download", "wheel_subject", "attest", "summary"])
        for step in signer["steps"]:
            self.assertNotIn("continue-on-error", step)
            if step["id"] == "summary":
                self.assertEqual(step["if"], "always()")
            else:
                self.assertNotIn("if", step)
            if "run" in step:
                self.assertNotIn("${{", step["run"])
                self.assertIn("python3 -B -I -", step["run"])
                for forbidden in ("pip ", "checkout", "subprocess", "os.system", "exec(", "eval("):
                    self.assertNotIn(forbidden, step["run"])
        self.assertEqual([s["uses"] for s in signer["steps"] if "uses" in s],
                         [signed["download"]["uses"], signed["attest"]["uses"]])

    def test_retention_contract_and_negative_permission_pin_path_upload_bypasses(self):
        self.assert_retention_contract(self.job, self.signer)
        for target, stage, key, value in (
            ("signer", "attest", "uses", "actions/attest@v4"),
            ("signer", "download", "uses", "actions/download-artifact@v4"),
            ("producer", "upload", "uses", "actions/upload-artifact@v4"),
            ("signer", "attest", "if", "always()"),
            ("producer", "upload", "continue-on-error", True),
            ("producer", "wheel_subject", "if", "always()"),
            ("signer", "download", "continue-on-error", True),
            ("signer", "signer_guard", "if", "always()"),
        ):
            job, signer = copy.deepcopy(self.job), copy.deepcopy(self.signer)
            changed = signer if target == "signer" else job
            next(s for s in changed["steps"] if s["id"] == stage)[key] = value
            with self.subTest(target=target, stage=stage, key=key):
                with self.assertRaises(AssertionError):
                    self.assert_retention_contract(job, signer)
        for target, stage, key, value in (
            ("signer", "attest", "subject-path", "*.whl"),
            ("producer", "upload", "path", "/tmp/substitute.whl"),
            ("producer", "upload", "if-no-files-found", "warn"),
            ("producer", "upload", "retention-days", 90),
            ("producer", "upload", "name", "gate10-wheel"),
            ("signer", "download", "artifact-ids", "1,2"),
            ("signer", "download", "name", "gate10-wheel-*"),
            ("signer", "download", "path", "../escape"),
            ("signer", "download", "run-id", "123"),
            ("signer", "download", "github-token", "untrusted"),
            ("signer", "download", "merge-multiple", False),
        ):
            job, signer = copy.deepcopy(self.job), copy.deepcopy(self.signer)
            changed = signer if target == "signer" else job
            next(s for s in changed["steps"] if s["id"] == stage)["with"][key] = value
            with self.subTest(target=target, stage=stage, key=key):
                with self.assertRaises(AssertionError):
                    self.assert_retention_contract(job, signer)
        for target in ("producer", "signer"):
            for key in ("contents", "id-token", "attestations", "artifact-metadata", "actions"):
                for value in (None, "write-all"):
                    job, signer = copy.deepcopy(self.job), copy.deepcopy(self.signer)
                    changed = signer if target == "signer" else job
                    if value is None and key in changed["permissions"]:
                        del changed["permissions"][key]
                    else:
                        changed["permissions"][key] = value or "write"
                    with self.subTest(target=target, permission=key, value=value):
                        with self.assertRaises(AssertionError):
                            self.assert_retention_contract(job, signer)
        for key, value in (("needs", []), ("if", "always()"), ("runs-on", "self-hosted")):
            signer = copy.deepcopy(self.signer)
            signer[key] = value
            with self.assertRaises(AssertionError):
                self.assert_retention_contract(self.job, signer)
        for key in ("wheel_sha256", "artifact_id"):
            job = copy.deepcopy(self.job)
            job["outputs"][key] = "untrusted"
            with self.assertRaises(AssertionError):
                self.assert_retention_contract(job, self.signer)

    def test_wheel_subject_revalidates_bytes_and_rejects_unsafe_paths(self):
        script = next(s["run"] for s in self.job["steps"] if s["id"] == "wheel_subject")
        cases = ("valid", "missing", "multiple", "substituted", "symlink", "directory",
                 "fifo", "parent_symlink", "digest_missing", "digest_upper", "digest_injection",
                 "name_newline", "name_glob", "temp_newline", "temp_relative")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                wheel_dir = root / "avuhz-main-pr-gate-wheel"
                wheel_dir.mkdir()
                wheel = wheel_dir / "avuhz_service-0.1.0-py3-none-any.whl"
                data = b"synthetic wheel bytes\n"
                wheel.write_bytes(data)
                output = root / "outputs"
                env = {"PATH": os.environ["PATH"], "PYTHONDONTWRITEBYTECODE": "1",
                       "RUNNER_TEMP": tmp, "GITHUB_OUTPUT": str(output),
                       "VERIFIED_WHEEL_SHA256": hashlib.sha256(data).hexdigest()}
                if case == "missing":
                    wheel.unlink()
                elif case == "multiple":
                    (wheel_dir / "other.whl").write_bytes(data)
                elif case == "substituted":
                    wheel.write_bytes(b"substituted")
                elif case in ("symlink", "directory", "fifo"):
                    wheel.unlink()
                    if case == "symlink":
                        target = root / "target"
                        target.write_bytes(data)
                        wheel.symlink_to(target)
                    elif case == "directory":
                        wheel.mkdir()
                    else:
                        os.mkfifo(wheel)
                elif case == "parent_symlink":
                    wheel_dir.rename(root / "real")
                    wheel_dir.symlink_to(root / "real", target_is_directory=True)
                elif case == "digest_missing":
                    del env["VERIFIED_WHEEL_SHA256"]
                elif case == "digest_upper":
                    env["VERIFIED_WHEEL_SHA256"] = "A" * 64
                elif case == "digest_injection":
                    env["VERIFIED_WHEEL_SHA256"] += "\ninjected=true"
                elif case.startswith("name_"):
                    wheel.rename(wheel_dir / ("bad\nname.whl" if case == "name_newline" else "bad*.whl"))
                elif case == "temp_newline":
                    nested = root / "bad\npath"
                    nested.mkdir()
                    wheel_dir.rename(nested / wheel_dir.name)
                    env["RUNNER_TEMP"] = str(nested)
                elif case == "temp_relative":
                    env["RUNNER_TEMP"] = os.path.relpath(root)
                result = subprocess.run(["bash"], input=script, env=env, text=True,
                                        capture_output=True, timeout=10)
                if case == "valid":
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(output.read_text(),
                                     f"wheel_path={wheel}\nwheel_sha256={hashlib.sha256(data).hexdigest()}\n")
                    self.assertEqual(result.stdout + result.stderr, "")
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(output.exists())
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(result.stderr, "wheel_subject_verification=failed\n")

    def test_job_guard_rejects_unmatched_dispatch_context(self):
        # Evaluate the actual restricted conjunction, not a second hand-written guard.
        # GitHub comparisons are case-insensitive and coerce numeric equality;
        # exact spelling, SHA shape and attempt spelling are rechecked by Bash.
        context = {
            "github.repository": "AnonymousKoo/avuhz-infra",
            "github.repository_owner": "AnonymousKoo", "github.repository_owner_id": "168945054",
            "github.workflow_ref": "AnonymousKoo/avuhz-infra/.github/workflows/gate10-exact-merge-ci.yml@refs/heads/main",
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
            ("github.event_name", "pull_request"), ("github.ref", "refs/pull/1/merge"),
            ("github.repository_owner", "fork"), ("github.repository_owner_id", "9"),
            ("github.workflow_ref", "AnonymousKoo/avuhz-infra/.github/workflows/other.yml@refs/heads/main"),
            ("github.workflow_ref", "AnonymousKoo/avuhz-infra/.github/workflows/gate10-exact-merge-ci.yml@refs/heads/feature"),
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

    def test_only_pinned_checkout_attest_upload_actions_and_source_is_immutable(self):
        actions = [s for s in self.job["steps"] if "uses" in s]
        self.assertEqual([s["uses"] for s in actions], [
            "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683",
            "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
        ])
        self.assertEqual(actions[0]["uses"], "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683")
        self.assertEqual(actions[0]["with"], {
            "repository": "AnonymousKoo/avuhz-infra", "ref": "${{ github.sha }}",
            "fetch-depth": 0, "persist-credentials": False,
            "clean": True, "submodules": False, "lfs": False,
        })
        self.assertEqual(self.job["env"]["SOURCE_SHA"], "${{ github.sha }}")
        self.assertEqual(self.job["env"]["WORKFLOW_SHA"], "${{ github.workflow_sha }}")
        self.assertEqual(self.job["env"]["EXPECTED_WORKFLOW_SHA"],
                         "${{ inputs.expected_workflow_sha }}")
        self.assertIn('test "$(git rev-parse HEAD)" = "$SOURCE_SHA"', self.bootstrap)

    def test_historical_checkout_requires_full_history_and_exact_source_pin(self):
        # Release candidate validation reads an older baseline with git show;
        # depth 2 omits that object even when every checked-out byte is identical.
        checkout = self.steps["Checkout exact main merge source"]["with"]
        self.assertEqual(checkout["fetch-depth"], 0)
        self.assertEqual(checkout["ref"], "${{ github.sha }}")
        self.assertEqual(self.job["env"]["SOURCE_SHA"], "${{ github.sha }}")
        self.assertEqual(checkout["fetch-depth"],
                         historical_job()["steps"][0]["with"]["fetch-depth"])
        self.assertNotRegex(WORKFLOW.read_text(), r"(?m)^\s*fetch-depth:\s*[1-9][0-9]*\s*$")

    def test_historical_environment_and_substantive_steps_have_exact_parity(self):
        historical = historical_job()
        for key, value in historical["env"].items():
            self.assertEqual(self.job["env"][key], value, key)
        # The historical recipe remains a comparison; execution uses the exact merge source.
        self.assertIn("ef257d85f76e48da", self.job["env"]["AVUHZ_POSTGRES_IMAGE"])
        for original in historical["steps"][2:-3]:
            with self.subTest(step=original["name"]):
                if original["name"] == "Run portable repository unit suites":
                    def commands(script):
                        return [shlex.split(line.strip()) for line in script.splitlines()
                                if line.strip().startswith("python3 -m unittest ")]
                    actual = self.steps[original["name"]]["run"]
                    self.assertEqual(commands(actual), commands(original["run"]))
                    # Retain the six literal historical invocations as well as argv.
                    for line in original["run"].splitlines():
                        if line.startswith("python3 -m unittest "):
                            self.assertEqual(actual.count(line), 1)
                else:
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

    def test_evidence_is_non_certified_with_bound_provenance_identities(self):
        for field in ("evidence_class=non-certified", "provenance=absent", "workflow_sha=%s",
                      "source_sha=%s", "actor=%s", "run_id=%s", "attempt=%s"):
            self.assertIn(field, self.bootstrap)
        self.assertIn("certification_granted=false", self.steps["Record non-certified completion"]["run"])
        self.assertIn("runner network", WORKFLOW.read_text())

    def test_every_shell_script_parses_without_execution(self):
        for step in self.job["steps"] + self.signer["steps"]:
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

    def test_portable_diagnostics_are_bounded_and_preserve_failure_status(self):
        run = self.steps["Run portable repository unit suites"]["run"]
        suites = ("runtime", "service", "worker", "architecture", "engineering", "security")
        commands = [f"python3 -m unittest discover -s tests/{suite} -p 'test_*.py' -v"
                    for suite in suites]
        # Replace only historical test processes. Run the actual diagnostic wrapper.
        # The fixture emits untrusted text on both streams; none may reach CI output.
        for failed in (*suites, None):
            with self.subTest(failed=failed), tempfile.TemporaryDirectory() as tmp:
                script = run
                for suite, command in zip(suites, commands):
                    fixture = ("printf 'untrusted_raw_contents\\n'; "
                               "printf 'untrusted_exception_path\\n' >&2; ")
                    fixture += "(exit 37)" if suite == failed else "true"
                    script = script.replace(command, fixture)
                result = subprocess.run(["bash"], input=script, text=True, capture_output=True,
                                        env={**self.fixture_env(tmp),
                                             "portable_suite": "untrusted_inherited_state"})
                reached = len(suites) if failed is None else suites.index(failed) + 1
                expected = "".join(f"gate10_portable_stage={s}\n" for s in suites[:reached])
                expected += ("historical_check=passed\n" if failed is None
                             else f"gate10_portable_failed_suite={failed}\n")
                self.assertEqual(result.returncode, 0 if failed is None else 37)
                self.assertEqual(result.stdout, expected)
                self.assertEqual(result.stderr, "")
                self.assertIn("untrusted_raw_contents", Path(tmp, "gate10-step-output").read_text())
        # Invalid state must select a fixed unknown token, never interpolate its value.
        for state in ("unknown", "", "runtime\nuntrusted_state", "$(echo untrusted_state)"):
            with self.subTest(state=state), tempfile.TemporaryDirectory() as tmp:
                script = run.replace(
                    "portable_suite=runtime",
                    "portable_suite=" + shlex.quote(state) + "\n        (exit 41)", 1)
                result = subprocess.run(["bash"], input=script, text=True, capture_output=True,
                                        env=self.fixture_env(tmp))
                self.assertEqual(result.returncode, 41)
                self.assertEqual(result.stdout, "gate10_portable_failed_suite=unknown\n")
                self.assertEqual(result.stderr, "")
        # A sandbox/output setup failure also emits only the fixed unknown code.
        with tempfile.TemporaryDirectory() as tmp:
            blocked = Path(tmp, "untrusted_path")
            blocked.write_text("not a directory")
            result = subprocess.run(["bash"], input=run, text=True, capture_output=True,
                                    env={"PATH": os.environ["PATH"], "RUNNER_TEMP": str(blocked)})
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "gate10_portable_failed_suite=unknown\n")
            self.assertEqual(result.stderr, "")

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
                                            env=self.fixture_env(tmp))
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
                   "SOURCE_SHA": "a" * 40, "FIXTURE_HEAD": "a" * 40, "WORKFLOW_SHA": "a" * 40,
                   "REPOSITORY_OWNER": "AnonymousKoo", "REPOSITORY_OWNER_ID": "168945054",
                   "WORKFLOW_REF": "AnonymousKoo/avuhz-infra/.github/workflows/gate10-exact-merge-ci.yml@refs/heads/main",
                   "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": "a" * 40,
                   "EXPECTED_WORKFLOW_SHA": "a" * 40,
                   "GITHUB_ACTOR": "AnonymousKoo", "GITHUB_ACTOR_ID": "168945054",
                   "GITHUB_RUN_ID": "123",
                   "AVUHZ_POSTGRES_DSN": self.job["env"]["AVUHZ_POSTGRES_DSN"]}
            result = subprocess.run(["bash"], input=prefix, text=True, capture_output=True, env=env)
            self.assertEqual(result.returncode, 0, result.stderr)
            # Arbitrary future merge identities pass when every binding agrees;
            # the historical recipe commit is never substituted for checkout.
            for merge_sha in ("c" * 40, "de" * 20):
                bound = {**env, **{key: merge_sha for key in (
                    "SOURCE_SHA", "FIXTURE_HEAD", "GITHUB_SHA", "WORKFLOW_SHA",
                    "EXPECTED_WORKFLOW_SHA")}}
                result = subprocess.run(["bash"], input=prefix, text=True,
                                        capture_output=True, env=bound)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout + result.stderr, "")
            for key, value in (("GITHUB_REPOSITORY", "fork/avuhz-infra"),
                               ("GITHUB_EVENT_NAME", "push"), ("GITHUB_RUN_ATTEMPT", "2"),
                               ("GITHUB_EVENT_NAME", "pull_request"), ("GITHUB_REF", "refs/pull/1/merge"),
                               ("REPOSITORY_OWNER", "fork"), ("REPOSITORY_OWNER_ID", "9"),
                               ("WORKFLOW_REF", "AnonymousKoo/avuhz-infra/.github/workflows/other.yml@refs/heads/main"),
                               ("WORKFLOW_REF", "AnonymousKoo/avuhz-infra/.github/workflows/gate10-exact-merge-ci.yml@refs/tags/main"),
                               ("WORKFLOW_REF", "fork/avuhz-infra/.github/workflows/gate10-exact-merge-ci.yml@refs/heads/main"),
                               ("SOURCE_SHA", SOURCE), ("FIXTURE_HEAD", SOURCE),
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
                        "GITHUB_RUN_ATTEMPT", "WORKFLOW_REF", "REPOSITORY_OWNER", "REPOSITORY_OWNER_ID"):
                with self.subTest(missing=key):
                    result = subprocess.run(["bash"], input=prefix, text=True, capture_output=True,
                                            env={k: v for k, v in env.items() if k != key})
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, "")


    def test_required_ids_and_summary_order_are_closed(self):
        expected = ["checkout", "identity", "dependencies", "baseline", "portable", "schema",
                    "portability_gap", "postgres", "migrations", "replay", "integrations",
                    "wheel_build", "wheel_contents", "diff", "integrity", "cleanup",
                    "wheel_subject", "upload", "summary"]
        self.assertEqual([s["id"] for s in self.job["steps"]], expected)
        summary = self.job["steps"][-1]
        self.assertEqual(summary["if"], "always()")
        self.assertEqual(summary["env"], {"STEP_RESULTS": "${{ toJSON(steps) }}"})
        for step in self.job["steps"]:
            self.assertNotIn("continue-on-error", step)
            if step["id"] not in ("cleanup", "summary"):
                self.assertNotIn("if", step)
        self.assertEqual(self.job["env"]["WORKFLOW_REF"], "${{ github.workflow_ref }}")
        self.assertEqual(self.job["env"]["REPOSITORY_OWNER"], "${{ github.repository_owner }}")
        self.assertEqual(self.job["env"]["REPOSITORY_OWNER_ID"], "${{ github.repository_owner_id }}")
        # Each job writes its own sanitized summary; the producer follows cleanup.
        self.assertEqual(WORKFLOW.read_text().count('os.environ["GITHUB_STEP_SUMMARY"]'), 2)
        self.assertNotIn("GITHUB_STEP_SUMMARY", self.bootstrap)

    def successful_records(self):
        records = {s["id"]: {"outcome": "success", "conclusion": "success",
                              "outputs": {} if s["id"] in ("checkout", "wheel_subject", "upload")
                              else {"evidence_sha256": "d" * 64}}
                   for s in self.job["steps"][:-1]}
        for stage in ("identity", "integrity"):
            records[stage]["outputs"]["source_tree_sha256"] = "e" * 64
        records["postgres"]["outputs"]["postgres_version_num"] = "170006"
        records["wheel_contents"]["outputs"]["wheel_sha256"] = "f" * 64
        records["wheel_subject"]["outputs"]["wheel_sha256"] = "f" * 64
        records["replay"]["outputs"]["baseline_sha256"] = "a" * 64
        records["upload"]["outputs"]["artifact-id"] = "123"
        for stage in ("migrations", "integrations"):
            records[stage]["outputs"]["required_skips"] = "0"
        return records

    def run_summary(self, records, **identity):
        with tempfile.TemporaryDirectory() as tmp:
            summary = Path(tmp, "summary")
            env = {"PATH": os.environ["PATH"], "GITHUB_STEP_SUMMARY": str(summary),
                   "STEP_RESULTS": json.dumps(records), "SOURCE_SHA": "c" * 40,
                   "GITHUB_SHA": "c" * 40, "WORKFLOW_SHA": "c" * 40,
                   "EXPECTED_WORKFLOW_SHA": "c" * 40, **identity}
            result = subprocess.run(["bash"], input=self.job["steps"][-1]["run"],
                                    text=True, capture_output=True, env=env)
            return result, summary.read_text() if summary.exists() else ""

    def test_summary_accepts_only_complete_success_and_sanitized_evidence(self):
        result, summary = self.run_summary(self.successful_records())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "")
        for field in ("exact_merge_producer_checks=passed", "evidence_class=non-certified",
                      "provenance=not_independently_verified", "certification_granted=false",
                      "signing_state=pending_separate_job", "cleanup_outcome=success",
                      "migrations_required_skips=0", "integrations_required_skips=0",
                      "postgres_version_num=170006", "wheel_contents_wheel_sha256=" + "f" * 64,
                      "replay_baseline_sha256=" + "a" * 64):
            self.assertIn(field + "\n", summary)
        self.assertIn(self.job["env"]["AVUHZ_POSTGRES_IMAGE"], summary)
        self.assertLess(len(summary), 6000)
        self.assertEqual(len(summary.splitlines()), len(set(summary.splitlines())))

    def test_every_required_status_missing_skipped_failed_cancelled_denies_summary_pass(self):
        for stage in self.successful_records():
            for field in ("outcome", "conclusion"):
                for status in (None, "skipped", "failure", "cancelled", "untrusted\n::notice::raw"):
                    records = self.successful_records()
                    if status is None:
                        del records[stage][field]
                    else:
                        records[stage][field] = status
                    with self.subTest(stage=stage, field=field, status=status):
                        result, summary = self.run_summary(records)
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn("exact_merge_producer_checks=failed_or_incomplete\n", summary)
                        self.assertNotIn("exact_merge_producer_checks=passed", summary)
                        self.assertNotIn("untrusted", summary + result.stdout + result.stderr)
            records = self.successful_records()
            del records[stage]
            with self.subTest(missing_stage=stage):
                result, summary = self.run_summary(records)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(stage + "_outcome=missing", summary)

    def test_missing_forged_or_unbounded_hashes_versions_and_skips_deny_summary(self):
        for stage, record in self.successful_records().items():
            if stage == "checkout":
                continue
            for key in record["outputs"]:
                for value in (None, "untrusted\n::notice::raw", "A" * 64, "a" * 65, 0):
                    records = self.successful_records()
                    if value is None:
                        del records[stage]["outputs"][key]
                    else:
                        records[stage]["outputs"][key] = value
                    with self.subTest(stage=stage, key=key, value=value):
                        result, summary = self.run_summary(records)
                        self.assertNotEqual(result.returncode, 0)
                        self.assertNotIn("exact_merge_producer_checks=passed", summary)
                        self.assertNotIn("untrusted", summary + result.stdout + result.stderr)
        for stage, key, value in (("migrations", "required_skips", "1"),
                                  ("integrations", "required_skips", "1"),
                                  ("postgres", "postgres_version_num", "180001"),
                                  ("integrity", "source_tree_sha256", "b" * 64),
                                  ("wheel_subject", "wheel_sha256", "b" * 64)):
            records = self.successful_records()
            records[stage]["outputs"][key] = value
            result, summary = self.run_summary(records)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("exact_merge_producer_checks=failed_or_incomplete", summary)

    def test_summary_malformed_context_and_untrusted_extra_fields_do_not_escape(self):
        for records in (None, [], {}, {"identity": None}, {"identity": {"outputs": []}}):
            result, summary = self.run_summary(records)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("exact_merge_producer_checks=failed_or_incomplete", summary)
        records = self.successful_records()
        records["untrusted\n::notice::raw"] = {"outcome": "untrusted"}
        records["baseline"]["outputs"]["raw_log"] = "untrusted\n::notice::raw"
        result, summary = self.run_summary(records)
        self.assertEqual(result.returncode, 0)
        self.assertNotIn("untrusted", summary + result.stdout + result.stderr)
        for key in ("SOURCE_SHA", "GITHUB_SHA", "WORKFLOW_SHA", "EXPECTED_WORKFLOW_SHA"):
            for value in ("", SOURCE, "untrusted\n::notice::raw", "C" * 40):
                result, summary = self.run_summary(self.successful_records(), **{key: value})
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("untrusted", summary + result.stdout + result.stderr)

    def test_evidence_utility_hashes_actual_bytes_and_rejects_missing_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = self.fixture_env(tmp)
            output = Path(env["GITHUB_OUTPUT"])
            root = Path(tmp)
            log = root / "private-log"
            log.write_bytes(b"untrusted_raw_output\n")
            # Replay and wheel hashes use actual local bytes, not echoed declarations.
            baseline = root / "supabase/migrations/20260831120000_rebaseline_provider_neutral_avuhz.sql"
            baseline.parent.mkdir(parents=True)
            baseline.write_bytes(b"fictional baseline\n")
            wheel_dir = root / "avuhz-main-pr-gate-wheel"
            wheel_dir.mkdir()
            wheel = wheel_dir / "avuhz_service-0.1.0-py3-none-any.whl"
            wheel.write_bytes(b"fictional wheel\n")
            for stage, key, data in (("baseline", "evidence_sha256", log.read_bytes()),
                                     ("cleanup", "evidence_sha256", log.read_bytes()),
                                     ("replay", "baseline_sha256", baseline.read_bytes()),
                                     ("wheel_contents", "wheel_sha256", wheel.read_bytes()),
                                     ("migrations", "required_skips", None),
                                     ("integrations", "required_skips", None)):
                output.unlink(missing_ok=True)
                result = subprocess.run(["python3", str(root / "gate10-evidence.py"), stage, str(log)],
                                        env=env, cwd=root, text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                fields = dict(line.split("=", 1) for line in output.read_text().splitlines())
                self.assertEqual(fields[key], "0" if data is None else hashlib.sha256(data).hexdigest())
                self.assertEqual(result.stdout + result.stderr, "")
                self.assertNotIn("untrusted", output.read_text())
            log.unlink()
            output.unlink()
            result = subprocess.run(["python3", str(root / "gate10-evidence.py"), "baseline", str(log)],
                                    env=env, cwd=root, text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stderr, "evidence_record=failed\n")
            self.assertFalse(output.exists())

    def test_cleanup_failure_cannot_record_success_or_hash(self):
        # Replace the substantive historical cleanup with a failing synthetic process.
        run = self.steps["Remove disposable PostgreSQL"]["run"]
        script = run.replace(historical_job()["steps"][-1]["run"],
                             "set -euo pipefail\n(exit 37)\necho unsafe_continuation\n")
        with tempfile.TemporaryDirectory() as tmp:
            env = self.fixture_env(tmp)
            result = subprocess.run(["bash"], input=script, text=True, capture_output=True, env=env)
            self.assertEqual(result.returncode, 37)
            self.assertEqual(result.stdout, "::error::Disposable PostgreSQL cleanup failed.\n")
            self.assertNotIn("unsafe_continuation", Path(tmp, "gate10-cleanup-output").read_text())
            self.assertFalse(Path(env["GITHUB_OUTPUT"]).exists())


    def signer_env(self, tmp):
        return {
            "PATH": os.environ["PATH"], "PYTHONDONTWRITEBYTECODE": "1",
            "RUNNER_TEMP": tmp, "DOWNLOAD_PATH": str(Path(tmp, "gate10-signer-wheel")),
            "GITHUB_OUTPUT": str(Path(tmp, "outputs")),
            "GITHUB_STEP_SUMMARY": str(Path(tmp, "summary")),
            "GITHUB_REPOSITORY": "AnonymousKoo/avuhz-infra",
            "REPOSITORY_OWNER": "AnonymousKoo", "REPOSITORY_OWNER_ID": "168945054",
            "WORKFLOW_REF": "AnonymousKoo/avuhz-infra/.github/workflows/gate10-exact-merge-ci.yml@refs/heads/main",
            "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/heads/main",
            "GITHUB_ACTOR": "AnonymousKoo", "GITHUB_ACTOR_ID": "168945054",
            "GITHUB_RUN_ATTEMPT": "1", "GITHUB_RUN_ID": "1234",
            "PRODUCER_RESULT": "success", "ARTIFACT_ID": "5678",
            "GITHUB_SHA": "c" * 40, "SOURCE_SHA": "c" * 40,
            "WORKFLOW_SHA": "c" * 40, "EXPECTED_WORKFLOW_SHA": "c" * 40,
            "VERIFIED_WHEEL_SHA256": hashlib.sha256(b"synthetic wheel\n").hexdigest(),
        }

    def signer_script(self, stage):
        return next(s["run"] for s in self.signer["steps"] if s["id"] == stage)

    def signer_run(self, stage, env):
        return subprocess.run(["bash"], input=self.signer_script(stage), env=env,
                              capture_output=True, text=True, timeout=10)

    def signer_bad_contexts(self):
        return (
            ("GITHUB_REPOSITORY", "fork/avuhz-infra"),
            ("GITHUB_REPOSITORY", "anonymouskoo/avuhz-infra"),
            ("REPOSITORY_OWNER", "fork"), ("REPOSITORY_OWNER_ID", "9"),
            ("WORKFLOW_REF", "AnonymousKoo/avuhz-infra/.github/workflows/other.yml@refs/heads/main"),
            ("GITHUB_EVENT_NAME", "push"), ("GITHUB_EVENT_NAME", "pull_request"),
            ("GITHUB_EVENT_NAME", "pull_request_target"),
            ("GITHUB_REF", "refs/heads/feature"), ("GITHUB_REF", "refs/tags/main"),
            ("GITHUB_REF", "refs/heads/Main"),
            ("GITHUB_ACTOR", "reviewer"), ("GITHUB_ACTOR", "anonymouskoo"),
            ("GITHUB_ACTOR_ID", "9"), ("GITHUB_RUN_ATTEMPT", "2"),
            ("GITHUB_RUN_ATTEMPT", "01"), ("GITHUB_RUN_ATTEMPT", "1.0"),
            ("GITHUB_RUN_ID", "1\ninjected"), ("GITHUB_RUN_ID", "0"),
            ("ARTIFACT_ID", "1,2"), ("ARTIFACT_ID", "0"), ("ARTIFACT_ID", "-1"),
            ("ARTIFACT_ID", "01"), ("ARTIFACT_ID", "1\ninjected"),
            ("VERIFIED_WHEEL_SHA256", "A" * 64),
            ("VERIFIED_WHEEL_SHA256", "a" * 63),
            ("VERIFIED_WHEEL_SHA256", "a" * 64 + "\ninjected"),
            ("GITHUB_SHA", "C" * 40), ("GITHUB_SHA", "d" * 40),
            ("SOURCE_SHA", "d" * 40), ("WORKFLOW_SHA", "d" * 40),
            ("EXPECTED_WORKFLOW_SHA", "d" * 40),
            ("EXPECTED_WORKFLOW_SHA", "$(echo unsafe_injection)"),
            ("PRODUCER_RESULT", "failure"), ("PRODUCER_RESULT", "skipped"),
            ("PRODUCER_RESULT", "cancelled"),
            ("DOWNLOAD_PATH", "/tmp/escape"), ("DOWNLOAD_PATH", "../escape"),
            ("RUNNER_TEMP", "relative"),
        )

    def test_signer_independent_guard_rejects_missing_or_malicious_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = self.signer_env(tmp)
            result = self.signer_run("signer_guard", env)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout + result.stderr, "")
            root = Path(env["DOWNLOAD_PATH"])
            self.assertTrue(root.is_dir())
            self.assertFalse(Path(env["GITHUB_OUTPUT"]).exists())
            self.assertNotEqual(self.signer_run("signer_guard", env).returncode, 0)
            root.rmdir()
            root.symlink_to(tmp, target_is_directory=True)
            self.assertNotEqual(self.signer_run("signer_guard", env).returncode, 0)
            root.unlink()
            cases = [{**env, key: value} for key, value in self.signer_bad_contexts()]
            for key in env:
                if key not in ("PATH", "PYTHONDONTWRITEBYTECODE", "GITHUB_OUTPUT", "GITHUB_STEP_SUMMARY"):
                    cases.append({k: v for k, v in env.items() if k != key})
            for index, altered in enumerate(cases):
                with self.subTest(index=index):
                    result = self.signer_run("signer_guard", altered)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(result.stderr, "signer_context=failed\n")
                    self.assertFalse(root.exists())
                    self.assertFalse(Path(env["GITHUB_OUTPUT"]).exists())

    def test_signer_subject_rejects_extra_files_paths_and_digest_substitution(self):
        cases = ("valid", "missing", "extra_file", "extra_wheel", "extra_directory",
                 "extra_symlink", "symlink", "directory", "fifo", "parent_symlink",
                 "substitution", "digest_upper", "digest_missing", "name_wrong_prefix",
                 "name_wrong_tags", "name_glob", "name_newline", "context_changed", "traversal")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                env = self.signer_env(tmp)
                self.assertEqual(self.signer_run("signer_guard", env).returncode, 0)
                root = Path(env["DOWNLOAD_PATH"])
                wheel = root / "avuhz_service-0.1.0-py3-none-any.whl"
                wheel.write_bytes(b"synthetic wheel\n")
                if case == "missing":
                    wheel.unlink()
                elif case in ("extra_file", "extra_wheel"):
                    (root / ("extra.txt" if case == "extra_file" else "other.whl")).write_bytes(b"extra")
                elif case == "extra_directory":
                    (root / "extra").mkdir()
                elif case == "extra_symlink":
                    (root / "extra").symlink_to(wheel)
                elif case in ("symlink", "directory", "fifo"):
                    wheel.unlink()
                    if case == "symlink":
                        target = Path(tmp, "target")
                        target.write_bytes(b"synthetic wheel\n")
                        wheel.symlink_to(target)
                    elif case == "directory":
                        wheel.mkdir()
                    else:
                        os.mkfifo(wheel)
                elif case == "parent_symlink":
                    root.rename(Path(tmp, "real"))
                    root.symlink_to(Path(tmp, "real"), target_is_directory=True)
                elif case == "substitution":
                    wheel.write_bytes(b"substituted")
                elif case == "digest_upper":
                    env["VERIFIED_WHEEL_SHA256"] = "A" * 64
                elif case == "digest_missing":
                    del env["VERIFIED_WHEEL_SHA256"]
                elif case.startswith("name_"):
                    wheel.rename(root / {
                        "name_wrong_prefix": "other-0.1.0-py3-none-any.whl",
                        "name_wrong_tags": "avuhz_service-0.1.0-py2-none-any.whl",
                        "name_glob": "bad*.whl", "name_newline": "bad\nname.whl",
                    }[case])
                elif case == "context_changed":
                    env["GITHUB_ACTOR"] = "reviewer"
                elif case == "traversal":
                    env["DOWNLOAD_PATH"] = str(root / "..")
                result = self.signer_run("wheel_subject", env)
                output = Path(env["GITHUB_OUTPUT"])
                if case == "valid":
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(output.read_text(),
                                     f"wheel_path={wheel}\nwheel_sha256={env['VERIFIED_WHEEL_SHA256']}\n")
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(output.exists())
                    self.assertEqual(result.stderr, "wheel_subject_verification=failed\n")
                self.assertEqual(result.stdout, "")

    def test_signer_summary_denies_failed_skipped_cancelled_missing_and_untrusted(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = self.signer_env(tmp)
            records = {s: {"outcome": "success", "conclusion": "success", "outputs": {}}
                       for s in ("signer_guard", "download", "wheel_subject", "attest")}
            records["wheel_subject"]["outputs"] = {
                "wheel_sha256": env["VERIFIED_WHEEL_SHA256"],
                "wheel_path": str(Path(env["DOWNLOAD_PATH"], "avuhz_service-0.1.0-py3-none-any.whl")),
            }

            def run(values, context=None):
                Path(env["GITHUB_STEP_SUMMARY"]).unlink(missing_ok=True)
                result = self.signer_run("summary", {
                    **env, "STEP_RESULTS": json.dumps(values), **(context or {}),
                })
                summary = Path(env["GITHUB_STEP_SUMMARY"]).read_text()
                self.assertEqual(result.stdout, "")
                self.assertIn("evidence_class=non-certified\n", summary)
                self.assertIn("provenance=not_independently_verified\n", summary)
                self.assertIn("certification_granted=false\n", summary)
                self.assertNotIn("untrusted", summary + result.stdout + result.stderr)
                return result, summary

            result, summary = run(records)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("exact_merge_ci_checks=passed\n", summary)
            for stage in records:
                for field in ("outcome", "conclusion"):
                    for status in (None, "failure", "skipped", "cancelled", "untrusted\n::notice::raw"):
                        altered = copy.deepcopy(records)
                        if status is None:
                            del altered[stage][field]
                        else:
                            altered[stage][field] = status
                        with self.subTest(stage=stage, field=field, status=status):
                            result, summary = run(altered)
                            self.assertNotEqual(result.returncode, 0)
                            self.assertNotIn("exact_merge_ci_checks=passed", summary)
                altered = copy.deepcopy(records)
                del altered[stage]
                self.assertNotEqual(run(altered)[0].returncode, 0)
            for values in (None, [], {}, {"attest": None}):
                self.assertNotEqual(run(values)[0].returncode, 0)
            for key, value in self.signer_bad_contexts():
                with self.subTest(key=key, value=value):
                    self.assertNotEqual(run(records, {key: value})[0].returncode, 0)
            for key in env:
                if key not in ("PATH", "PYTHONDONTWRITEBYTECODE", "GITHUB_OUTPUT", "GITHUB_STEP_SUMMARY"):
                    self.assertNotEqual(run(records, {key: ""})[0].returncode, 0)
            for key, value in (("wheel_sha256", "a" * 64), ("wheel_sha256", "A" * 64),
                               ("wheel_sha256", None), ("wheel_sha256", "untrusted\nraw"),
                               ("wheel_path", "/tmp/substitute.whl"),
                               ("wheel_path", str(Path(env["DOWNLOAD_PATH"], "bad*.whl")))):
                altered = copy.deepcopy(records)
                altered["wheel_subject"]["outputs"][key] = value
                self.assertNotEqual(run(altered)[0].returncode, 0)

    def test_producer_summary_cannot_claim_signing_or_workflow_completion(self):
        result, summary = self.run_summary(self.successful_records())
        self.assertEqual(result.returncode, 0)
        self.assertIn("exact_merge_producer_checks=passed\n", summary)
        self.assertIn("signing_state=pending_separate_job\n", summary)
        self.assertNotIn("exact_merge_ci_checks=passed", summary)
        self.assertNotIn("attest_outcome=success", summary)
        self.assertNotIn("attest", self.successful_records())


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
