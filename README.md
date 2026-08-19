# Avuhz Infrastructure Contracts

Clean, provider-neutral contract baseline for Avuhz infrastructure.

This repository starts with Slice 1 contract foundations only. Authoritative changes will eventually flow through bounded command APIs; n8n will be an orchestration client and will not write authoritative state directly.

Current implemented contract resource:

- `contracts/schemas/v1/common/identifiers.schema.json`

Local checks:

```bash
./scripts/check-baseline.sh
```

No legacy workflows, migrations, project-link metadata, credentials, provider payloads, or external-system configuration belong in this repository.
