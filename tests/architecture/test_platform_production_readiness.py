"""Focused certification for the platform production-readiness control plane."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
ARCHITECTURE = (ROOT / "docs/architecture.md").read_text()
SECURITY = (ROOT / "SECURITY.md").read_text()
STATE = (ROOT / "docs/current-build-state.md").read_text()
ROADMAP = (ROOT / "docs/roadmap.md").read_text()


class PlatformProductionReadinessTests(unittest.TestCase):
    def test_platform_and_client_deployment_are_distinct(self):
        for phrase in (
            "Avuhz platform production boundary",
            "distinct from deploying a client-system artifact",
            "stateless command/query API", "require `engagement:read`",
            "separate idempotent outbox worker",
            "isolated PostgreSQL DATA storage",
            "AUTH issuer",
            "approved secret manager",
            "immutable versioned application artifacts",
            "structured sanitized logging",
            "backups, point-in-time recovery, and restore testing",
        ):
            self.assertIn(phrase, ARCHITECTURE)
        self.assertIn("Client-system `DeploymentAuthorization` is separate", SECURITY)

    def test_environment_registry_and_agent_boundary_are_complete(self):
        for environment in ("`LOCAL`", "`DEVELOPMENT`", "`STAGING`", "`PRODUCTION`"):
            self.assertIn(environment, ARCHITECTURE)
        for field in (
            "DATA project/database", "AUTH project/issuer", "tenant identity claim",
            "TrustedExecutionContext.tenant_id -> avuhz.tenant_id", "RLS policy/version",
            "trusted command-service identity", "migration-runner", "secret-manager",
            "artifact-registry", "recovery-point objective", "recovery-time objective",
        ):
            self.assertIn(field, ARCHITECTURE)
        self.assertIn("Codex, Claude, and other engineering agents", ARCHITECTURE)
        self.assertIn("This boundary introduces no Phase 6", ARCHITECTURE)

    def test_ci_secrets_change_policy_and_evidence_gates_are_defined(self):
        for heading in (
            "## Production secrets and provider configuration",
            "## GitHub and CI/CD controls",
            "## Engineering and production change policy",
            "## Platform deployment evidence gate",
        ):
            self.assertIn(heading, SECURITY)
        for control in (
            "protected from direct/force pushes", "CODEOWNERS", "short-lived OIDC",
            "Untrusted/fork pull requests receive no secrets", "dependency lock/SBOM",
            "point-in-time recovery", "post-deploy verification independent of the deploy step",
        ):
            self.assertIn(control, SECURITY)
        for risk in ("`R0`", "`R1`", "`R2`", "`R3`"):
            self.assertIn(risk, SECURITY)

    def test_autonomous_dry_run_is_bounded_and_non_authoritative(self):
        self.assertIn("## Autonomous engineering dry-run", ARCHITECTURE)
        for step in (
            "Pin an exact source commit", "Build one immutable artifact", "Run contract, runtime",
            "an agent may draft but not approve", "Deploy only to a disposable local target",
            "Verify health, exact artifact digest", "Rehearse application rollback",
            "sanitized evidence bundle",
        ):
            self.assertIn(step, ARCHITECTURE)
        self.assertIn("runner cannot deploy a target, contact remote infrastructure, establish human approval", ARCHITECTURE)

    def test_certification_truth_matches_current_repository(self):
        self.assertIn("`PLATFORM_PRODUCTION_READINESS`: `NOT_READY`", STATE)
        self.assertIn("`READY_FOR_PHASE6`: `NO`", STATE)
        for blocker in (
            "production outbox identity/provider sink", "production AUTH/DATA registry",
            "GitHub workflows/branch/environment protections", "observability/alerting",
            "backup/PITR RPO/RTO", "deployment/rollback rehearsal",
        ):
            self.assertIn(blocker, STATE)
        self.assertFalse((ROOT / ".github/workflows").exists())
        self.assertFalse(any(ROOT.glob("Dockerfile*")))
        self.assertTrue((ROOT / "pyproject.toml").is_file())
        self.assertTrue((ROOT / "src/avuhz_service/__main__.py").is_file())
        self.assertTrue((ROOT / "scripts/run-engineering-dry-run.py").is_file())
        self.assertTrue((ROOT / "contracts/schemas/v1/orchestration/engineering-dry-run-evidence.schema.json").is_file())
        self.assertIn("local CI artifact/evidence pipeline and autonomous dry-run harness. — COMPLETE", ROADMAP)
        self.assertIn("owner-approved AUTH/DATA/environment registry values", ROADMAP)
        self.assertIn("Phase 6", ROADMAP)
        self.assertIn("DO NOT START YET", ROADMAP)


if __name__ == "__main__":
    unittest.main()
