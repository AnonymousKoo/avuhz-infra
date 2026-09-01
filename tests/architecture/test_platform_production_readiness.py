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
            "DEFINED_LOGICAL", "OWNER_VALUE_REQUIRED",
            "must never own authoritative tables or receive `BYPASSRLS`",
            "migration identity is separate from command, worker, and CI identities",
            "Production has no logical or provider references",
        ):
            self.assertIn(value, ARCHITECTURE)
        self.assertIn("OWNER_APPROVED_BINDING", ARCHITECTURE)
        self.assertIn("OWNER_APPROVED_POLICY", ARCHITECTURE)
        self.assertIn("Application/runtime identities never receive table ownership", SECURITY)
        self.assertIn("Concrete environment-scoped services", STATE)

    def test_owner_bindings_provider_choices_and_nonproduction_policies_are_exact(self):
        for value in (
            "github:AnonymousKoo",
            "Render runtime secrets plus GitHub CI/environment secrets",
            "Grafana Cloud via OpenTelemetry",
            "https://pwlhruwutoitnieactol.supabase.co/auth/v1",
            "https://gnuqaefotwgkwurjpyik.supabase.co/auth/v1",
            "Git migrations are canonical",
            "Recovery is rebuild, replay canonical migrations, and seed approved synthetic data",
            "No point-in-time-recovery capability is claimed",
            "Application rollback uses the preceding exact application artifact",
            "Database changes use forward correction by default",
            "Destructive migrations are prohibited",
            "Data-restoration rollback remains unauthorized",
            "Public ingress is permitted only to the command/query service",
            "worker has no public inbound endpoint",
            "Outbound access is restricted to the approved environment's Supabase and telemetry destinations",
            "Concrete Render, Supabase, Grafana/OpenTelemetry, DNS, firewall, routing, origin, and egress enforcement bindings",
        ):
            self.assertIn(value, ARCHITECTURE)
        self.assertIn("No Render service or deployment-target identifier is defined", ARCHITECTURE)
        self.assertIn("no remote mutation is authorized", STATE)

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

    def test_development_auth_data_validation_package_is_bounded(self):
        for value in (
            "DEVELOPMENT AUTH/DATA adapter and connected-validation package",
            "DevelopmentIdentityVerifier.verify",
            "DevelopmentTrustedIdentityResolver",
            "PostgresStore",
            "PostgresUnitOfWork",
            "TrustedExecutionContext.tenant_id` to `avuhz.tenant_id",
            "no provider credential",
            "service-role key is not an acceptable substitute",
            "OWNER_VALUE_REQUIRED",
            "AUTH discovery",
            "DATA catalog/RLS validation",
            "one credential-free `GET`",
            "immediately begin a read-only transaction",
            "I, `github:AnonymousKoo`, authorize the bounded DEVELOPMENT AUTH discovery validation",
            "I, `github:AnonymousKoo`, authorize the bounded DEVELOPMENT DATA catalog/RLS validation",
            "Neither the consumed AUTH authorization nor the unapplied DATA authorization permits credential creation",
        ):
            self.assertIn(value, ARCHITECTURE)
        self.assertIn("AUTH and DATA are separately reviewable and separately authorized", ARCHITECTURE)
        self.assertIn("DATA remains unauthorized after that call", ARCHITECTURE)

    def test_one_use_development_jwks_evidence_is_bounded_and_consumed(self):
        for value in (
            "endpoint class `DEVELOPMENT_AUTH_JWKS`",
            "HTTP `200`",
            "key count `1`",
            "supported metadata `ES256/EC/P-256`",
            "private key material absent",
            "validation `PASS`",
            "c13eec4a0c453116e035e0ff652a1e7395471422ec70f9aa1eb0c6391bfb73af",
            "one-use DEVELOPMENT AUTH JWKS read authorization was consumed",
            "No further AUTH call, DATA access",
            "live hosted DEVELOPMENT composition still uses its unavailable real-provider resolver",
        ):
            self.assertIn(value, STATE)
        self.assertIn("raw-response persistence", STATE)

    def test_development_owner_decisions_are_canonical_and_non_authorizing(self):
        for value in (
            "### OWNER_DECISIONS",
            "Top-level `avuhz_tenant_id`",
            "Exactly one canonical tenant UUID per token",
            "Tenant switching requires a newly issued token",
            "`audience.avuhz.command-service.development`",
            "default Supabase `aud=authenticated` is rejected by Avuhz",
            "JWT `role`, `roles`, `permissions`, `scope`, `capability`, `capabilities`",
            "Environment-scoped injected server-owned allowlist",
            "`(issuer, audience, subject, tenant_id, caller_type)`",
            "`HUMAN`",
            "`engagement:read`",
            "Synthetic authority roles",
            "Provider-assigned opaque `sub`",
            "Ephemeral local injection only",
            "Supabase is an AUTH/DATA adapter; Avuhz core remains provider-neutral",
            "not evidence of production-grade AUTH/DATA isolation",
            "Required by the current Supabase adapter design",
            "must emit no Avuhz capability or authority-role claims",
            "remains uncreated and disabled",
        ):
            self.assertIn(value, ARCHITECTURE)
        self.assertIn("grant no connection, hook creation/enablement", ARCHITECTURE)

    def test_local_observability_is_recorded_without_hosted_claims(self):
        for value in (
            "### Local observability evidence",
            "Prometheus is healthy and ready",
            "self-scrape is `UP`",
            "`node_exporter` scrape is `UP`",
            "Grafana `12.4.2`",
            "`127.0.0.1:3002`",
            "recovered persistent Grafana data",
            "Grafana-to-Prometheus query path",
            "port `3000`",
            "controlled Docker maintenance window",
            "not Render-hosted telemetry",
            "does not establish any Grafana Cloud",
        ):
            self.assertIn(value, ARCHITECTURE)
        self.assertIn("no Grafana Cloud resource is claimed", STATE)

    def test_phase_b_state_is_reconciled_through_canonical_initial_migration(self):
        for value in (
            "5591dd6a99dd2d56dba6b682ab45198143d7539f",
            "https://avuhz-command-dev.onrender.com",
            "GET /health/live = 200",
            "GET /health/ready = 503",
            "deterministic fake positive/negative identity tests are implemented and green",
            "disposable local PostgreSQL DEVELOPMENT DATA composition and UnitOfWork tests are green",
            "default Supabase `aud=authenticated` is rejected by Avuhz",
            "clean disposable replay passes nine PostgreSQL tests",
            "No hook migration exists",
            "Define the bounded DEVELOPMENT AUTH integration authorization plan",
        ):
            self.assertIn(value, STATE)

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
