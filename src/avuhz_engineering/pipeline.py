"""Fixed-command local CI evidence pipeline and non-authoritative dry run."""
from __future__ import annotations

import json
import os
import platform
import re
import subprocess
import sys
import tomllib
import uuid
import zipfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from avuhz_runtime.implementation_handoff import canonical_digest

from .evidence import bundle_digest, file_digest, git_identity, repository_digest, step_digest, validate_bundle, verify_bundle

PIPELINE_VERSION = 1
_SIMULATION_REFERENCE = re.compile(r"^[a-z][a-z0-9]*(?:[._:-][a-z0-9]+)*$")
_REMOTE_ENV_PARTS = ("SUPABASE", "DATABASE_URL", "POSTGRES_DSN", "AUTH_URL", "PROVIDER_URL")

_COMMANDS = {
    "BUILD": (("build.wheel-local", ("python", "-m", "pip", "wheel", ".", "--no-deps", "--no-build-isolation", "--disable-pip-version-check", "-w", "{artifact_dir}")),),
    "TESTS": (
        ("tests.runtime", ("python", "-m", "unittest", "discover", "-s", "tests/runtime", "-p", "test_*.py", "-v")),
        ("tests.service", ("python", "-m", "unittest", "discover", "-s", "tests/service", "-p", "test_*.py", "-v")),
        ("tests.worker", ("python", "-m", "unittest", "discover", "-s", "tests/worker", "-p", "test_*.py", "-v")),
        ("tests.architecture", ("python", "-m", "unittest", "discover", "-s", "tests/architecture", "-p", "test_*.py", "-v")),
        ("tests.engineering", ("python", "-m", "unittest", "discover", "-s", "tests/engineering", "-p", "test_*.py", "-v")),
    ),
    "CONTRACTS": (
        ("contracts.orchestration", ("python", "tests/contracts/validate_orchestration_foundation.py")),
        ("contracts.phase5d-package", ("python", "tests/contracts/validate_phase5d_implementation_package_architecture.py")),
        ("contracts.phase5d-authority", ("python", "tests/contracts/validate_phase5d_build_qa_deployment_authority.py")),
        ("contracts.phase5d-deployment", ("python", "tests/contracts/validate_phase5d_deployment_execution_verification.py")),
        ("contracts.runtime-schema", ("python", "tests/schema/validate_runtime_schema_representability.py")),
    ),
    "MIGRATIONS": (
        ("migrations.static-local", ("python", "-m", "unittest", "discover", "-s", "tests/migrations", "-p", "test_*.py", "-v")),
        ("migrations.outbox-adapter-local", ("python", "-m", "unittest", "tests.integration.test_postgres_outbox_worker_persistence", "-v")),
    ),
    "SECURITY": (("security.baseline-local", ("scripts/check-baseline.sh",)),),
    "PACKAGE_VERIFICATION": (("package.verify-local", ("internal", "verify-wheel")),),
}


@dataclass(frozen=True)
class PipelineResult:
    status: str
    evidence_path: Path
    artifact_path: Path | None
    bundle_digest: str


class LocalCommandRunner:
    def run(self, command: tuple[str, ...], repository_root: Path, environment: dict[str, str]) -> int:
        result = subprocess.run(command, cwd=repository_root, env=environment, check=False)
        return result.returncode


def _timestamp(moment: datetime) -> str:
    if moment.tzinfo is None:
        raise ValueError("pipeline clock must be timezone-aware")
    return moment.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _safe_environment() -> dict[str, str]:
    environment = {
        key: value for key, value in os.environ.items()
        if not any(part in key.upper() for part in _REMOTE_ENV_PARTS)
    }
    environment.update({"PIP_NO_INDEX": "1", "PIP_DISABLE_PIP_VERSION_CHECK": "1", "PYTHONDONTWRITEBYTECODE": "1"})
    return environment


def _catalog_digest() -> str:
    return canonical_digest({
        "pipeline_version": PIPELINE_VERSION,
        "commands": [{"step": step, "reference": reference, "template": list(command)} for step, values in _COMMANDS.items() for reference, command in values],
    })


class DryRunPipeline:
    def __init__(self, repository_root: Path, *, runner=None, clock=None):
        self.repository_root = repository_root.resolve()
        self.runner = runner or LocalCommandRunner()
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def _prepare_output(self, output_dir: Path) -> tuple[Path, Path]:
        output = output_dir.resolve()
        try:
            output.relative_to(self.repository_root)
        except ValueError:
            pass
        else:
            raise ValueError("evidence output must remain outside the repository")
        if output.exists():
            if output.is_symlink() or any(output.iterdir()):
                raise ValueError("evidence output must be a new empty local directory")
        else:
            output.mkdir(parents=True)
        artifacts = output / "artifacts"
        artifacts.mkdir()
        return output, artifacts

    def _run_step(self, step_id: str, artifacts: Path, environment: dict[str, str], skipped=()):
        started = self.clock(); codes = []
        for _, template in _COMMANDS[step_id]:
            if template[0] == "internal":
                continue
            command = tuple(
                str(artifacts) if value == "{artifact_dir}" else sys.executable if value == "python" else value
                for value in template
            )
            try:
                code = self.runner.run(command, self.repository_root, environment)
            except Exception:
                code = 127
            codes.append(code)
            if code != 0:
                break
        completed = self.clock()
        step = {
            "step_id": step_id, "status": "PASS" if codes and all(code == 0 for code in codes) and len(codes) == len(_COMMANDS[step_id]) else "FAIL",
            "command_references": [reference for reference, _ in _COMMANDS[step_id]],
            "started_at": _timestamp(started), "completed_at": _timestamp(completed),
            "check_count": len(_COMMANDS[step_id]), "passed_count": sum(code == 0 for code in codes),
            "failed_count": sum(code != 0 for code in codes) + (len(_COMMANDS[step_id]) - len(codes)),
            "skipped_checks": list(skipped),
        }
        step["result_digest"] = step_digest(step)
        return step

    def _artifact(self, artifacts: Path):
        wheels = sorted(artifacts.glob("*.whl"))
        if len(wheels) != 1:
            return None, None
        wheel = wheels[0]
        project = tomllib.loads((self.repository_root / "pyproject.toml").read_text(encoding="utf-8"))["project"]
        with zipfile.ZipFile(wheel) as archive:
            names = set(archive.namelist())
            metadata_files = sorted(name for name in names if name.endswith(".dist-info/METADATA"))
            if len(metadata_files) != 1:
                return None, None
            metadata_lines = archive.read(metadata_files[0]).decode("utf-8").splitlines()
        metadata = {
            key: value.strip() for line in metadata_lines if ":" in line
            for key, value in (line.split(":", 1),)
        }
        if metadata.get("Name") != project["name"] or metadata.get("Version") != project["version"]:
            return None, None
        service = any(name.startswith("avuhz_service/") for name in names)
        worker = any(name.startswith("avuhz_worker/") for name in names)
        artifact = {
            "artifact_filename": wheel.name, "package_name": project["name"], "package_version": project["version"],
            "artifact_digest": file_digest(wheel), "size_bytes": wheel.stat().st_size,
            "service_module_included": service, "worker_module_included": worker,
            "dependency_inventory": sorted(project.get("dependencies", [])),
        }
        return artifact, wheel

    def _package_step(self, artifact, wheel):
        started = self.clock()
        passed = bool(artifact and wheel and artifact["service_module_included"] and artifact["worker_module_included"] and artifact["artifact_digest"] == file_digest(wheel))
        completed = self.clock()
        step = {
            "step_id": "PACKAGE_VERIFICATION", "status": "PASS" if passed else "FAIL",
            "command_references": ["package.verify-local"], "started_at": _timestamp(started),
            "completed_at": _timestamp(completed), "check_count": 1,
            "passed_count": 1 if passed else 0, "failed_count": 0 if passed else 1,
            "skipped_checks": [],
        }
        step["result_digest"] = step_digest(step)
        return step

    def run(self, output_dir: Path, *, simulated_approval="NOT_RECORDED", reviewer_reference=None) -> PipelineResult:
        if simulated_approval not in {"APPROVE", "DECLINE", "NOT_RECORDED"}:
            raise ValueError("bounded simulated approval is required")
        if simulated_approval == "NOT_RECORDED":
            if reviewer_reference is not None: raise ValueError("reviewer is not accepted without a simulation decision")
        elif not isinstance(reviewer_reference, str) or not _SIMULATION_REFERENCE.fullmatch(reviewer_reference):
            raise ValueError("bounded simulation reviewer reference is required")
        output, artifacts = self._prepare_output(output_dir)
        commit, branch, clean = git_identity(self.repository_root)
        source_digest = repository_digest(self.repository_root)
        epoch_result = subprocess.run(
            ["git", "show", "-s", "--format=%ct", commit], cwd=self.repository_root,
            text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False,
        )
        if epoch_result.returncode or not epoch_result.stdout.strip().isdigit():
            raise ValueError("source commit timestamp is unavailable")
        source_date_epoch = int(epoch_result.stdout.strip())
        environment = _safe_environment()
        environment["SOURCE_DATE_EPOCH"] = str(source_date_epoch)
        environment["PYTHONHASHSEED"] = "0"
        steps = []
        steps.append(self._run_step("BUILD", artifacts, environment))
        artifact, wheel = self._artifact(artifacts)
        steps.append(self._run_step("TESTS", artifacts, environment))
        steps.append(self._run_step("CONTRACTS", artifacts, environment))
        skipped = ["persistence.postgres-disposable"] if not os.environ.get("AVUHZ_LOCAL_POSTGRES_CONTAINER") else []
        steps.append(self._run_step("MIGRATIONS", artifacts, environment, skipped))
        steps.append(self._run_step("SECURITY", artifacts, environment))
        steps.append(self._package_step(artifact, wheel))
        all_pass = artifact is not None and all(step["status"] == "PASS" for step in steps)
        review_status = "READY_FOR_SIMULATED_REVIEW" if all_pass else "BLOCKED"
        if not all_pass:
            approval_status = "BLOCKED_BY_EVIDENCE"
        elif simulated_approval == "APPROVE":
            approval_status = "SIMULATED_APPROVAL_RECORDED"
        elif simulated_approval == "DECLINE":
            approval_status = "SIMULATED_DECLINE_RECORDED"
        else:
            approval_status = "NOT_RECORDED"
        missing = ["step." + step["step_id"].lower().replace("_", "-") for step in steps if step["status"] != "PASS"]
        if artifact is None: missing.append("artifact.wheel")
        if approval_status != "SIMULATED_APPROVAL_RECORDED": missing.append("simulated.approval")
        decision_status = "SIMULATION_READY" if not missing and review_status == "READY_FOR_SIMULATED_REVIEW" else "BLOCKED"
        created = self.clock(); expires = created + timedelta(minutes=30)
        artifact_digest = artifact["artifact_digest"] if artifact else "sha256:" + "0" * 64
        evidence_id = str(uuid.uuid5(uuid.NAMESPACE_URL, source_digest + ":" + _timestamp(created) + ":" + artifact_digest))
        bundle = {
            "evidence_id": evidence_id, "schema_version": 1,
            "source": {"repository_reference": "repository.avuhz-infra", "git_commit": commit, "git_branch": branch, "source_digest": source_digest, "working_tree_clean": clean},
            "provenance": {"pipeline_reference": "engineering.dry-run-local", "pipeline_version": PIPELINE_VERSION, "python_version": platform.python_version(), "operating_system": platform.system().lower(), "command_catalog_digest": _catalog_digest(), "source_date_epoch": source_date_epoch},
            "artifact": artifact, "steps": steps,
            "review_gate": {"status": review_status, "required_step_digests": [step["result_digest"] for step in steps], "authority_effect": "NONE"},
            "simulated_approval": {"requested_decision": simulated_approval, "status": approval_status, "reviewer_reference": reviewer_reference, "authority_effect": "NONE", "human_authority_established": False, "production_authority_established": False},
            "readiness_decision": {"status": decision_status, "environment_class": "LOCAL", "production_ready": False, "deployment_authorized": False, "production_mutation_performed": False, "missing_requirements": sorted(set(missing))},
            "created_at": _timestamp(created), "expires_at": _timestamp(expires),
        }
        bundle["bundle_digest"] = bundle_digest(bundle)
        validate_bundle(bundle, self.repository_root / "contracts/schemas/v1")
        issues = verify_bundle(bundle, self.repository_root, wheel, created)
        if issues:
            mapped = ["verification." + issue.lower().replace("_", "-") for issue in issues]
            bundle["readiness_decision"]["status"] = "BLOCKED"
            bundle["readiness_decision"]["missing_requirements"] = sorted(set(bundle["readiness_decision"]["missing_requirements"] + mapped))
            bundle["bundle_digest"] = bundle_digest(bundle)
            validate_bundle(bundle, self.repository_root / "contracts/schemas/v1")
        evidence_path = output / "engineering-evidence.json"
        with evidence_path.open("x", encoding="utf-8") as handle:
            json.dump(bundle, handle, sort_keys=True, separators=(",", ":")); handle.write("\n")
        evidence_path.chmod(0o444)
        if wheel: wheel.chmod(0o444)
        return PipelineResult(bundle["readiness_decision"]["status"], evidence_path, wheel, bundle["bundle_digest"])
