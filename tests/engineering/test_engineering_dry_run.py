"""Focused local CI evidence and autonomous dry-run governance tests."""
from __future__ import annotations

import copy
import json
import stat
import sys
import tempfile
import unittest
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.evidence import (
    EvidenceValidationError, bundle_digest, load_bundle, validate_bundle, verify_bundle,
)
from avuhz_engineering.pipeline import DryRunPipeline, _COMMANDS, _safe_environment

T0 = datetime(2030, 1, 15, 15, 0, tzinfo=timezone.utc)


class Clock:
    def __init__(self): self.value = T0
    def __call__(self):
        current = self.value; self.value += timedelta(seconds=1); return current


class FakeRunner:
    def __init__(self, fail_token=None): self.fail_token = fail_token; self.calls = []
    def run(self, command, repository_root, environment):
        self.calls.append(tuple(command))
        if "pip" in command and "wheel" in command:
            destination = Path(command[command.index("-w") + 1])
            wheel = destination / "avuhz_service-0.1.0-py3-none-any.whl"
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr("avuhz_service/__init__.py", "")
                archive.writestr("avuhz_worker/__init__.py", "")
                archive.writestr("avuhz_service-0.1.0.dist-info/METADATA", "Name: avuhz-service\nVersion: 0.1.0\n")
        if self.fail_token and any(self.fail_token in item for item in command): return 1
        return 0


class EngineeringDryRunTests(unittest.TestCase):
    def run_pipeline(self, *, decision="APPROVE", fail_token=None):
        temporary = tempfile.TemporaryDirectory(prefix="avuhz-evidence-test-")
        output = Path(temporary.name) / "run"
        clock = Clock(); runner = FakeRunner(fail_token)
        result = DryRunPipeline(ROOT, runner=runner, clock=clock).run(
            output, simulated_approval=decision,
            reviewer_reference="simulation.local-reviewer" if decision != "NOT_RECORDED" else None,
        )
        return temporary, clock, runner, result, load_bundle(result.evidence_path)

    def test_complete_flow_is_digest_bound_and_simulation_only(self):
        temporary, clock, runner, result, bundle = self.run_pipeline()
        self.addCleanup(temporary.cleanup)
        self.assertEqual(result.status, "SIMULATION_READY")
        self.assertEqual([step["step_id"] for step in bundle["steps"]], ["BUILD", "TESTS", "CONTRACTS", "MIGRATIONS", "SECURITY", "PACKAGE_VERIFICATION"])
        self.assertTrue(all(step["status"] == "PASS" for step in bundle["steps"]))
        self.assertTrue(bundle["artifact"]["service_module_included"])
        self.assertTrue(bundle["artifact"]["worker_module_included"])
        self.assertEqual(bundle["review_gate"]["authority_effect"], "NONE")
        self.assertEqual(bundle["simulated_approval"]["status"], "SIMULATED_APPROVAL_RECORDED")
        self.assertFalse(bundle["simulated_approval"]["human_authority_established"])
        self.assertEqual(bundle["readiness_decision"], {
            "status": "SIMULATION_READY", "environment_class": "LOCAL", "production_ready": False,
            "deployment_authorized": False, "production_mutation_performed": False, "missing_requirements": [],
        })
        validate_bundle(bundle, ROOT / "contracts/schemas/v1")
        created = datetime.fromisoformat(bundle["created_at"].replace("Z", "+00:00"))
        self.assertEqual(verify_bundle(bundle, ROOT, result.artifact_path, created), ())
        self.assertFalse(result.evidence_path.stat().st_mode & stat.S_IWUSR)
        self.assertFalse(result.artifact_path.stat().st_mode & stat.S_IWUSR)

    def test_failed_required_security_evidence_blocks_simulated_approval(self):
        temporary, _, _, result, bundle = self.run_pipeline(fail_token="check-baseline.sh")
        self.addCleanup(temporary.cleanup)
        self.assertEqual(result.status, "BLOCKED")
        self.assertEqual(bundle["review_gate"]["status"], "BLOCKED")
        self.assertEqual(bundle["simulated_approval"]["status"], "BLOCKED_BY_EVIDENCE")
        self.assertIn("step.security", bundle["readiness_decision"]["missing_requirements"])
        self.assertFalse(bundle["readiness_decision"]["production_ready"])
        validate_bundle(bundle, ROOT / "contracts/schemas/v1")

    def test_missing_explicit_simulated_approval_blocks_readiness(self):
        temporary, _, _, result, bundle = self.run_pipeline(decision="NOT_RECORDED")
        self.addCleanup(temporary.cleanup)
        self.assertEqual(result.status, "BLOCKED")
        self.assertEqual(bundle["review_gate"]["status"], "READY_FOR_SIMULATED_REVIEW")
        self.assertEqual(bundle["simulated_approval"]["status"], "NOT_RECORDED")
        self.assertIn("simulated.approval", bundle["readiness_decision"]["missing_requirements"])

    def test_stale_source_artifact_and_missing_evidence_fail_closed(self):
        temporary, _, _, result, bundle = self.run_pipeline()
        self.addCleanup(temporary.cleanup)
        expires = datetime.fromisoformat(bundle["expires_at"].replace("Z", "+00:00"))
        self.assertIn("EVIDENCE_STALE", verify_bundle(bundle, ROOT, result.artifact_path, expires))
        result.artifact_path.chmod(0o644); result.artifact_path.write_bytes(result.artifact_path.read_bytes() + b"changed")
        self.assertIn("ARTIFACT_DIGEST_MISMATCH", verify_bundle(bundle, ROOT, result.artifact_path, T0))
        stale = copy.deepcopy(bundle); stale["source"]["source_digest"] = "sha256:" + "0" * 64; stale["bundle_digest"] = bundle_digest(stale)
        self.assertIn("SOURCE_BINDING_STALE", verify_bundle(stale, ROOT, result.artifact_path, T0))
        missing = copy.deepcopy(bundle); missing["steps"] = missing["steps"][:-1]; missing["bundle_digest"] = bundle_digest(missing)
        self.assertEqual(verify_bundle(missing, ROOT, result.artifact_path, T0), ("EVIDENCE_SCHEMA_INVALID",))

    def test_sensitive_material_and_evidence_rewrite_are_rejected(self):
        temporary, _, _, result, bundle = self.run_pipeline()
        self.addCleanup(temporary.cleanup)
        sensitive = copy.deepcopy(bundle)
        sensitive["simulated_approval"]["reviewer_reference"] = "author" + "ization=fictional-sensitive-value"
        sensitive["bundle_digest"] = bundle_digest(sensitive)
        with self.assertRaisesRegex(EvidenceValidationError, "SENSITIVE_VALUE_PROHIBITED"):
            validate_bundle(sensitive, ROOT / "contracts/schemas/v1")
        rewritten = copy.deepcopy(bundle); rewritten["steps"][0]["passed_count"] = 0; rewritten["bundle_digest"] = bundle_digest(rewritten)
        with self.assertRaisesRegex(EvidenceValidationError, "STEP_DIGEST_INVALID"):
            validate_bundle(rewritten, ROOT / "contracts/schemas/v1")

    def test_command_catalog_is_local_fixed_and_has_no_deploy_or_provider_path(self):
        flattened = [item for values in _COMMANDS.values() for _, command in values for item in command]
        joined = " ".join(flattened).lower()
        for forbidden in ("supabase", "curl", "wget", "deploy.py", "provider-cli", "https://", "http://"):
            self.assertNotIn(forbidden, joined)
        environment = _safe_environment()
        self.assertEqual(environment["PIP_NO_INDEX"], "1")
        self.assertFalse(any("SUPABASE" in key.upper() or "POSTGRES_DSN" in key.upper() for key in environment))

    def test_recomputed_provenance_or_approval_spoofing_fails_closed(self):
        temporary, _, _, result, bundle = self.run_pipeline()
        self.addCleanup(temporary.cleanup)
        stale_catalog = copy.deepcopy(bundle)
        stale_catalog["provenance"]["command_catalog_digest"] = "sha256:" + "0" * 64
        stale_catalog["bundle_digest"] = bundle_digest(stale_catalog)
        self.assertIn("PIPELINE_CATALOG_STALE", verify_bundle(stale_catalog, ROOT, result.artifact_path, T0))
        spoofed = copy.deepcopy(bundle)
        spoofed["simulated_approval"]["requested_decision"] = "DECLINE"
        spoofed["bundle_digest"] = bundle_digest(spoofed)
        with self.assertRaisesRegex(EvidenceValidationError, "SIMULATED_APPROVAL_DERIVATION_INVALID"):
            validate_bundle(spoofed, ROOT / "contracts/schemas/v1")

    def test_output_and_simulation_inputs_are_bounded(self):
        with tempfile.TemporaryDirectory(prefix="avuhz-evidence-test-") as temporary:
            output = Path(temporary) / "occupied"; output.mkdir(); (output / "existing").write_text("bounded")
            with self.assertRaises(ValueError): DryRunPipeline(ROOT, runner=FakeRunner(), clock=Clock()).run(output)
        with tempfile.TemporaryDirectory(prefix="avuhz-evidence-test-") as temporary:
            with self.assertRaises(ValueError):
                DryRunPipeline(ROOT, runner=FakeRunner(), clock=Clock()).run(Path(temporary) / "run", simulated_approval="APPROVE")


if __name__ == "__main__":
    unittest.main()
