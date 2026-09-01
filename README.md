# Avuhz Infrastructure

Avuhz is a provider-neutral governed foundation and home for reusable cross-domain systems.

Canonical project controls:

- [Agent rules](AGENTS.md)
- [Security model](SECURITY.md)
- [Architecture source of truth](docs/architecture.md)
- [Current build state](docs/current-build-state.md)
- [Roadmap](docs/roadmap.md)

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
