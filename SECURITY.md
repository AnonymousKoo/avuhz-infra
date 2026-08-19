# Security Baseline

## Non-negotiable rules

1. No raw credential material in this repository.
2. No legacy workflow export, migration, project-link metadata, environment file, provider payload, or forensic artifact may be copied into this tree.
3. No direct n8n authoritative database write surface is permitted.
4. Canonical internal identifiers are distinct from opaque external/provider references.
5. Contract fixtures use only explicit fictional test values.
6. Every commit must pass schema validation, fixture validation, secret scanning, and forbidden-file/path checks.

## Local security gate

Run `./scripts/check-baseline.sh` before staging or committing. A failed check blocks the commit. Tool or rule exceptions require explicit security-owner review and must never disclose a suspected value.

## External systems

This baseline is unconnected. It contains no Supabase project selection, n8n credential, provider integration, SQL, migration, or deployment configuration.
