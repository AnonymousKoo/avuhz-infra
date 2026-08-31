# Avuhz Architecture Source of Truth

## Foundation and ownership

Avuhz is the governed foundation for building, operating, monitoring, automating, and improving systems. It owns reusable execution governance and may own reusable cross-domain systems.

Systems are not domains. A system belongs in Avuhz when unrelated domains can use its core implementation through provider-neutral policies, configuration, and contracts. A domain-specific system belongs in its domain or company repository.

Company business meaning, methodology, policies, offers, ICP, pricing and commercial rules, and specialized lifecycle behavior do not belong in Avuhz core. Avuhz must not hard-code branches for particular companies.

The conceptual composition is:

`SYSTEM -> DOMAIN -> COMPANY INSTANCE`

## Public boundary and dependency law

Domain/company code may depend on Avuhz public contracts. Avuhz must never depend on company or domain implementation internals. Shared databases and circular imports are not public integration contracts.

- `domain/company -> Avuhz public contracts`: allowed
- `Avuhz -> domain/company internals`: prohibited

JSON Schema 2020-12 is the canonical provider-neutral contract source. Commands request changes, authoritative records determine truth, and events describe accepted changes. Exact tenant, identity, version, digest, authority, idempotency, concurrency, and transactional-outbox boundaries remain mandatory.

## Sekinfra boundary

Sekinfra owns business-architecture consulting and OIA. OIA is a system, but it is owned by the Sekinfra domain because its methodology and business meaning are specialized.

Sekinfra discovers and defines approved work; Avuhz governs execution of that approved work. Avuhz must not know Sekinfra or OIA internals. Sekinfra may produce a provider-neutral `ImplementationHandoff` through Avuhz's public contract. `ImplementationBrief` binds the exact handoff ID, version, and digest and creates no authority beyond its governed lifecycle.
