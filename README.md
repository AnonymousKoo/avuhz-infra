# Avuhz Infrastructure

Avuhz is a provider-neutral governed foundation and home for reusable cross-domain systems.

Canonical project controls:

- [Architecture source of truth](ARCHITECTURE.md)
- [Agent rules](AGENTS.md)
- [Security model](SECURITY.md)
- [Current build state](docs/current-build-state.md)
- [Roadmap](docs/roadmap.md)
- [Detailed historical architecture notes](docs/architecture.md)

Run the local baseline gate with `./scripts/check-baseline.sh`.

## Local command/query service

The runnable service artifact is a framework-neutral WSGI application with a loopback-only standalone entry point. It uses the existing governed `Executor`, trusted context, UnitOfWork, repositories, and Phase 5 read services; it adds no mutation path.

```bash
PYTHONPATH=src \
AVUHZ_LOCAL_TENANT_ID=00000000-0000-4000-8000-000000000001 \
AVUHZ_SERVICE_ENVIRONMENT=LOCAL \
python3 -m avuhz_service
```

The default local identity has no command capabilities and no human authority roles. A bounded comma-separated `AVUHZ_LOCAL_CAPABILITIES` value may enable only registered command capabilities or the read-only `engagement:read` capability for explicit local testing. The standalone service refuses non-loopback binding and non-LOCAL/TEST environments.

Routes are `POST /v1/commands`, `POST /v1/queries`, and `GET /health/startup`, `/health/live`, or `/health/ready`. Health output is sanitized and readiness covers the configured local data and identity dependencies. This service does not contact Supabase or another remote system, publish the outbox, deploy client artifacts, or establish production readiness.

## Local engineering evidence dry run

The fixed local runner builds the wheel containing both service and worker modules, runs the repository's bounded test/contract/migration/security gates, and writes read-only digest-bound evidence outside the repository. The approval is explicitly simulated and creates no human, deployment, or production authority.

```bash
evidence_dir="$(mktemp -d /tmp/avuhz-engineering-dry-run.XXXXXX)"
python3 scripts/run-engineering-dry-run.py run \
  --output-dir "$evidence_dir" \
  --simulated-approval APPROVE \
  --reviewer-reference simulation.local-reviewer
```

The runner is local-only, removes configured remote DATA/AUTH/provider variables from child processes, performs no deployment, and fails closed on failed, missing, expired, or source/artifact-stale evidence.

## Render development service preparation

The DEVELOPMENT entry point is deployed to the registered Render service but remains intentionally fail-closed for dependency readiness. It reuses the existing governed command/query application and never uses the local static identity resolver. Current canonical code still injects unavailable hosted DATA and identity dependencies: `/health/live` may return `200`, while readiness remains `503` and command/query requests fail at trusted identity resolution.

- Render build command: `python -m pip install .`
- Render start command: `avuhz-service-development`
- Render health path: `/health/live`

Render supplies `PORT`; the DEVELOPMENT server binds `0.0.0.0:$PORT`. Required non-secret configuration names are `AVUHZ_SERVICE_ENVIRONMENT`, `AVUHZ_DATA_PROJECT_REF`, `AVUHZ_DATA_PROJECT_URL`, `AVUHZ_AUTH_PROJECT_REF`, `AVUHZ_AUTH_ISSUER`, `AVUHZ_SERVICE_AUDIENCE`, `AVUHZ_TENANT_BRIDGE`, `AVUHZ_RLS_POLICY_REFERENCE`, and `AVUHZ_COMMAND_SERVICE_IDENTITY`. Values must match the canonical DEVELOPMENT registry described in `ARCHITECTURE.md` and the detailed notes under `docs/architecture.md`.

AUTH v16 and DATA v3 are complete at the provider-foundation layer, but that does not automatically authorize hosted adapter wiring. The real hosted identity and DATA adapters remain separate future boundaries. No staging or production mode is supported.
