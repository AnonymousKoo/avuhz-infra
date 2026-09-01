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

    def test_owner_approved_project_selection_is_exact_and_non_authorizing(self):
        for value in (
            "pwlhruwutoitnieactol", "https://pwlhruwutoitnieactol.supabase.co",
            "gnuqaefotwgkwurjpyik", "https://gnuqaefotwgkwurjpyik.supabase.co",
            "TrustedExecutionContext.tenant_id -> avuhz.tenant_id",
            "Registration does not authorize connection, migration, deployment, or mutation",
            "Production is unconfigured and its project does not exist",
        ):
            self.assertIn(value, ARCHITECTURE)
        self.assertIn("registration grants no connection or mutation authority", SECURITY)
        self.assertIn("no remote mutation is authorized", STATE)

    def test_environment_reference_model_is_distinct_tenant_bound_and_fail_closed(self):
        for value in (
            "avuhz_command_service_dev", "avuhz_command_service_staging",
            "avuhz_outbox_worker_dev", "avuhz_outbox_worker_staging",
            "avuhz_migration_service_dev", "avuhz_migration_service_staging",
            "avuhz_ci_service_dev", "avuhz_ci_service_staging",
            "auth-issuer.avuhz.development", "auth-issuer.avuhz.staging",
            "audience.avuhz.command-service.development", "audience.avuhz.command-service.staging",
            "audience.avuhz.outbox-worker.development", "audience.avuhz.outbox-worker.staging",
            "audience.avuhz.migration.development", "audience.avuhz.migration.staging",
            "audience.avuhz.ci.development", "audience.avuhz.ci.staging",
            "policy.avuhz.tenant-rls.development.v1", "policy.avuhz.tenant-rls.staging.v1",
            "secrets.avuhz.development", "secrets.avuhz.staging",
            "observability.avuhz.development", "observability.avuhz.staging",
            "runtime-target.avuhz.development", "runtime-target.avuhz.staging",
            "network-boundary.avuhz.development", "network-boundary.avuhz.staging",
            "recovery.avuhz.development", "recovery.avuhz.staging",
            "rollback.avuhz.development", "rollback.avuhz.staging",
            "approval-owner.platform.avuhz.development", "approval-owner.platform.avuhz.staging",
            "approval-owner.security.avuhz.development", "approval-owner.security.avuhz.staging",
            "approval-owner.data-migration.avuhz.development", "approval-owner.data-migration.avuhz.staging",
            "approval-owner.deployment.avuhz.development", "approval-owner.deployment.avuhz.staging",
            "DEFINED_LOGICAL", "OWNER_VALUE_REQUIRED",
            "must never own authoritative tables or receive `BYPASSRLS`",
            "migration identity is separate from command, worker, and CI identities",
            "Production has no logical or provider references",
        ):
            self.assertIn(value, ARCHITECTURE)
        self.assertIn("| AUTH issuer reference | `auth-issuer.avuhz.development` | `OWNER_VALUE_REQUIRED`", ARCHITECTURE)
        self.assertIn("Application/runtime identities never receive table ownership", SECURITY)
        self.assertIn("every `OWNER_VALUE_REQUIRED` development/staging reference", STATE)

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
