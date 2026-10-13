# DEVELOPMENT first-client readiness rebaseline

**Read-only provider checks and local tests, 2026-10-13. SOURCE ONLY: this file authorizes no hosted changes or customer intake.**

This updates the live state of [the October 12 acquisition readiness plan](development-acquisition-auth-tenant-binding-readiness-20261012.md). The old snapshot is retained as historical evidence. Apply no historical approval a second time.

## Exact namespaces

- DEVELOPMENT AUTH: pwlhruwutoitnieactol. Only authenticated identity and independent business-owner proof.
- DEVELOPMENT DATA: gnuqaefotwgkwurjpyik. Shared Avuhz tenant/owner registry, acquisition intake, counters, event/outbox and Sekinfra OIA tables.
- Sekinfra website is in AnonymousKoo/sekinfra. Its public POST /api/diagnostic-intake still returns 503 and the existing server-side Avuhz adapter is deliberately unmounted.
- Shared Avuhz receiver code is in AnonymousKoo/avuhz-infra. Hosted acquisition route, acquisition AUTH workload, private DATA connection credential and authenticated n8n receiver are not certified.
- Never conflate AUTH/DATA; never build vertical-specific auth, billing or orchestration paths.

## Current verified aggregate state

| Boundary | Read-only result | Meaning |
| --- | --- | --- |
| AUTH | ACTIVE_HEALTHY, 3 users, 1 verified MFA factor, 0 unverified factors, 1 session | Does not establish which subject owns a company or whether a session and MFA ceremony are fresh |
| DATA acquisition | 0 tenant organizations, 0 owner memberships, 0 intake requests | No legitimate owner/business target is active |
| DATA rate counter | Installed, FORCE RLS, 2 policies (including the acquisition service), 4 acquisition-role column grants and SET-only membership | G4 migration already applied; this does not provide a private login credential, authorize a tenant or prove runtime |
| DATA migration history | development_data_acquisition_counter_role_access_v1 version 20261012202521 | Do NOT repeat G4 |
| Sekinfra OIA | 4 installed FORCE RLS persistence tables, no runtime policies | No actual assessment, payment or bounded access is enabled |

Do not treat an MFA-factor count or a signed JWT as independent owner verification. Do not read or expose individual AUTH identities in this report.

## Evidence from current Avuhz main

- Baseline commit: 398ae8907a804c4187660dac2d81c575531bca19.
- Counter source digest SHA-256: 1de3ff0bca523e22c5a0ff9cbd3908d9614af5504c3cc23a46b33e4c84d56f51.
- Synthetic intake HTTP → event/outbox → n8n tests: 4 passed.
- Acquisition service boundary tests: 36 passed.
- Owner registration, activation, MFA freshness and signed-directory tests: 43 passed.
- Counter policy/ACL tests: 6 passed with disposable PostgreSQL 17.6 using the dedicated least-privilege login; checked 10 requests and 11th denial, cross-tenant access, improper UPDATE/DELETE, replay, rollback and ACL drift.
- Local proof container removed. Tests did not use hosted AUTH/DATA, Render or real client records.

## Fastest safe critical path — source batching, hosted changes separately

1. **G0/G1 verified owner and company:** identify the first genuine business and consenting owner. Fresh AUTH owner MFA plus independently signed business-owner-directory evidence is required. Then separately authorize one PENDING enrollment and a distinct ACTIVE transition with tenant-scoped DATA writes. Never insert fake owner or tenant rows.
2. **G2 AUTH acquisition workload:** enroll one distinct server-owned acquisition service identity and exact single capability; do not reuse the human owner or provider-adapter subject.
3. **G3 private DATA credential:** complete the existing dedicated acquisition runtime login and private secret lifecycle (no source, logs, workflow JSON or service_role fallback).
4. **G4 shared rate limiter:** DATA migration and permissions already installed. Still verify retention/pruning and public per-visitor abuse limits before opening the front door.
5. **G5 hosted synthetic certification:** separately approve DEVELOPMENT Render composition mounting the existing authenticated HTTP ingress. Verify verified owner binding, restricted DATA connection, real limiter, tenant RLS, safe outbox and replay before customer data.
6. **G6 authenticated shared n8n receipt:** verify the specific local/hosted deployment, encrypted credentials, allowed events and durable idempotent receiver. Local n8n and mock/loopback tests are not hosted proof.
7. **G7 first controlled Sekinfra pilot:** only after a complete synthetic transaction, connect the website form and pass one consented prospect through the shared intake. Confirm limits, fail-closed behavior, review ownership and rollback plan. Payment verification and inspection authority remain separate OIA gates.

**Business lane:** proceed with real prospect discovery using Sekinfra's current email/copy workflow while automation remains disabled. This is a sales fallback, not certified automated onboarding.

**Next action:** confirm the first business and independently authenticated owner proof route (G0), then prepare a source-bound G0/G1 execution plan; source development and tests for G2/G3 can be batched, but each hosted mutation requires exact separate approval. Command Center remains deferred.
