# Bounded authorization plans and DEVELOPMENT AUTH integration

## Reusable control model

A bounded authorization plan is an immutable provider-neutral definition, a separate attributable owner approval, and a versioned progress record. The plan definition binds exact target, environment, resources, operations, ordering, dependencies, evidence, postconditions, credential classes, prohibitions, stop conditions, and correction references. Its digest excludes only the `plan_digest` field itself. Any definition change requires a new plan version and digest.

Owner approval is a separate record binding exact `plan_id`, `plan_version`, `plan_digest`, owner, environment, effective time, and expiry. Approval has `EXACT_PLAN_ONLY` scope: it creates no caller/JWT/domain authority and cannot authorize an unlisted resource, action, credential class, environment, or responsibility. A draft with unresolved bindings cannot be approved or executed.

Progress is separately versioned and digest-bound to the approved plan. Each step tracks authorization, execution, verification, evidence, postcondition, safe error, and authorization consumption. A step becomes executable only after its own exact preflight. A verified success consumes that step's authorization; the next step still requires a new preflight. Thus one plan approval can permit automatic continuation without turning the sequence into a batched or atomic multi-resource mutation.

The schemas are:

- `bounded-authorization-plan:v1`
- `bounded-authorization-plan-approval:v1`
- `bounded-authorization-plan-progress:v1`

The local enforcement model is `avuhz_engineering.authorization_plan`. It validates contracts and digests, exact approval binding, sequence, evidence, expiry, resource/operation/credential scope, stop conditions, and resumable progress. It has no provider client, remote executor, migration runner, token issuer, or deployment path.

## Enforcement semantics

- Only the first uncompleted step can be authorized. Skipping, reordering, or blindly replaying a verified success stops.
- Every prior step must be independently `SUCCEEDED` and `PASS`, with consumed authorization and exact evidence, before the next step can pass preflight.
- Preflight must exactly match plan ID/version/digest, environment, provider/project, responsibility, issuer/audience, step, resource/version/digest, operation, execution class, permitted credential class, and all prior/required evidence.
- Unexpected remote state, extra privilege, unauthorized migration surface, scope expansion, missing/stale evidence, target drift, or any binding mismatch returns an explicit stop. The mechanism never self-repairs.
- Failed, partial, or ambiguous outcomes consume the attempted step authorization, stop all later steps, and require review. Mutations are never silently retried.
- Expired, revoked, superseded, mismatched, or inactive approval cannot start another step. Consumed step authority cannot be replayed.
- Resume validates the immutable plan, approval, and latest progress digest, skips only already verified successes, and starts from the next uncompleted authorized boundary.
- DEVELOPMENT cannot target staging/production; AUTH cannot target DATA. Scope expansion requires a new plan version/digest and new owner approval.
- Credential classes are metadata only. Credential values, synthetic tokens, raw provider payloads, and authenticated connection material are prohibited from plan, approval, progress, evidence, logs, docs, Git, and command output.
- JWT role, roles, permissions, scope, capability, capabilities, or authority claims cannot authorize the plan or grant Avuhz authority. Trusted server policy remains authoritative.

The same core model can later describe DATA migrations, Render changes, worker deployment, observability resources, staging promotion, and controlled rollback/recovery. Provider details belong only in plan instances and provider adapters.

## Mandatory per-step preflight

Before every provider read or mutation, enforcement must verify:

1. exact plan ID, version, digest, active approval, and unexpired window;
2. exact environment, provider project, responsibility, issuer/audience, resource, operation, execution class, and credential class;
3. that authorization is neither incorrectly consumed nor replayed;
4. exact prior-step and required evidence digests;
5. exact expected prior remote state and absence of unexpected objects;
6. least privilege with no extra role, grant, credential class, or migration surface;
7. no staging/production target, DATA operation, scope expansion, skip, or reorder; and
8. the exact expected postcondition and stop conditions for independent verification.

Any mismatch is `STOP`; no correction, retry, widening, or next-step execution occurs.

## DEVELOPMENT AUTH plan instance

Canonical artifacts:

- `contracts/plans/v1/development-auth-integration.plan.json`
- `contracts/plans/v1/development-auth-integration.progress.json`
- `contracts/plans/v1/development-auth-step1-baseline.evidence.json` (historical v2 lineage)
- `contracts/plans/v1/development-auth-provider-preflight.evidence.json` (sanitized historical DEVELOPMENT AUTH provider observation)
- `contracts/plans/v1/development-auth-step1-v5-local.evidence.json` (historical failed-v5 candidate lineage)
- `contracts/plans/v1/development-auth-step1-v6-local.evidence.json` (rejected pre-commit v6 lineage)
- `contracts/plans/v1/development-auth-step1-v7-local.evidence.json` (current forward-correction evidence)

| Binding | Current value |
|---|---|
| Plan ID | `a7100000-0000-4000-8000-000000000101` |
| Plan version | `7` |
| Plan digest | `sha256:c7dd1770ae91aa0aea570c739cfeb358890e69a3a3ff81260ab70e0c5ad94938` |
| Definition status | `DRAFT_BLOCKED` |
| Environment | `DEVELOPMENT` |
| Provider/project | Supabase / `pwlhruwutoitnieactol` |
| Responsibility | `AUTH` only |
| Issuer | `https://pwlhruwutoitnieactol.supabase.co/auth/v1` |
| Expected audience | `audience.avuhz.command-service.development` |
| Planned hook | `public.avuhz_development_custom_access_token_hook_v1(jsonb)` |
| Current v7 local evidence | `contracts/plans/v1/development-auth-step1-v7-local.evidence.json` |
| Current v7 local evidence digest | `sha256:75568298af56a7f02ab826118902d3e8b1f62e290e57bea93da770b7f82a6211` |
| Progress plan version | `7` |
| Progress digest | `sha256:0dc83c7b72fccb4fde50baa3e37e30f4e8e14770406e0510ba67328fb2b36d52` |
| Progress record_version | `1` |
| Approval record | Not created |
| Authorization window | Unresolved |
| Execution | Not started; all 13 step authorizations remain pending |

This draft is not owner approval and grants no provider access or change authority. Local artifact certification does not mark Step 1 executed and does not authorize any provider step.

## v5 PostgreSQL certification failure, rejected v6, and v7 forward correction

The historical v5 candidate at commit `bf4eae2b6157e43f8f79bfabde0de2776e79f804` was exercised by GitHub Actions run `34377965523` against PostgreSQL 17.11. That certification concluded `FAILURE`. Before failing, it passed bounded authorization-plan validation, the migration-identity bootstrap PostgreSQL suite, and the dedicated NOSUPERUSER `SET ROLE` regression. It then failed during hook effective-role ordering certification.

The failure occurred because a `NULL` `pg_database.datacl` was replaced with an artificial empty `aclitem[]` before `aclexplode`, producing a zero-dimensional array. PostgreSQL returned `ACL arrays must be one-dimensional`. No raw CI logs are reproduced here, and v5 was not certified.

### Rejected pre-commit v6 lineage

Plan v6 was a local forward-correction draft with plan digest `sha256:38ff584ad6aee636cef2c1f75ce44f528900e159754f106f7378e3de7c9b7243` and evidence digest `sha256:d39fa647a374e8e60c62227077683acd1b84a1aad7736cfc1ac98a589447102c`. It was never committed as the forward correction, never reached fresh CI, and caused no provider execution.

Final local review found the same `NULL` `pg_database.datacl` / `aclexplode` defect still present in the bootstrap postcondition and in the seal preflight and postcondition. Plan v6 was therefore rejected and superseded before commit. Because plan definitions are immutable, correcting those digest-bound artifacts required advancing to plan v7 rather than rewriting v6 in place.

### Current v7 correction set

Plan v7 binds the current bootstrap migration at `sha256:b2af6edacb283afc5a5ad7d1c1ebdc5fdbd572bddd1cb115459caa6344acda45`, hook migration at `sha256:234a27973d4f9468dfb59ff5002f2ae1b7523dac9bd80b26fd01fbc64c8bc783`, and seal migration at `sha256:aafec1973fa60e3a2b7076f36c989a373fb1115a1e9e3760781a0ef41ca9b1ad`.

The hook and bootstrap each contain one corrected direct `pg_database.datacl` inspection. The seal contains two, one in preflight and one in postcondition. Every corrected inspection passes `database_record.datacl` directly to `aclexplode`; a `NULL` ACL therefore means no explicit ACL rows for this direct-grant inspection.

These corrections removed no direct database ACL security check, widened no privilege, changed no role attribute or `SET ROLE` semantic, changed no hook claim behavior or hook ACL, changed no seal mutation surface, changed no provider target or AUTH/DATA responsibility boundary, and changed no ambient PUBLIC database ACL policy.

### Current PostgreSQL 17 certification truth

The current v7 bootstrap, hook, and seal artifacts are each **not PostgreSQL-17 certified**, and the complete current v7 artifact set is **not PostgreSQL-17 certified**. Certification is digest-specific: the historical v5 bootstrap observation applies only to the superseded bootstrap digest `sha256:640fb4d2dbff9962f21b83b862cc455fe5e8be2ff5dd4b34bdf99cf3b0721356`, not the current bootstrap or seal. The corrected hook did not complete fresh PostgreSQL 17 certification. Fresh GitHub Actions PostgreSQL-17 certification of the exact current digests remains required.

The local GitHub Actions workflow is internally aligned as `DEVELOPMENT AUTH Plan v7 PostgreSQL Certification` and is configured to certify the exact current v7 candidate with disposable PostgreSQL 17. It has not yet run against the current v7 candidate, so fresh PostgreSQL-17 certification remains pending; this documentation correction does not execute the workflow or establish CI success, provider execution, approval, or authorization.

## Exact ordered sequence

| Step | Class | Exact resource/change | Allowed credential class | Required gate and postcondition |
|---|---|---|---|---|
| 1 | Local-only | Validate the ordered bootstrap, effective-role hook, and immediate seal artifacts | `NONE` | Current v7 local evidence binds the corrected bootstrap, hook, seal, and focused tests; nothing has been applied or enabled, and the exact current set has not been PostgreSQL-17 certified |
| 2 | Provider mutation | Bootstrap only `avuhz_migration_service_dev`, one bounded membership edge, and its temporary schema envelope | `OWNER_INTERACTIVE_SESSION` | Exact `session_user=current_user=postgres`; restricted NOLOGIN role; postgres may SET but not inherit/admin; no direct database/table/sequence/provider-schema privilege; non-grantable public USAGE/CREATE only; admin grants public USAGE to `supabase_auth_admin`; hook absent |
| 3 | Provider mutation | Apply exactly the hardened hook migration under the dedicated effective role | `MIGRATION_IDENTITY` | Exact bootstrap and artifact evidence; `SET LOCAL ROLE avuhz_migration_service_dev`; `current_user` transition proven before exact function/ACL creation; schema ACL unchanged; hook disabled |
| 4 | Provider mutation | Seal the migration identity immediately after hook application | `OWNER_INTERACTIVE_SESSION` | Exact step-3 application evidence and preflight; revoke migration-role public CREATE/USAGE and postgres membership only; function owner/ACL and `supabase_auth_admin` access remain |
| 5 | Provider read | Verify sealed role, exact v1 function body/owner/ACL, and disabled hook | `OWNER_INTERACTIVE_SESSION` | Exact seal evidence; bounded read only, with no mutation or repair |
| 6 | Provider mutation | Create one dedicated synthetic DEVELOPMENT Auth identity | `OWNER_INTERACTIVE_SESSION` | Exact disabled-hook evidence; one provider-assigned opaque subject |
| 7 | Provider mutation | Set only provider-controlled `app_metadata.avuhz_tenant_id` | `OWNER_INTERACTIVE_SESSION` | Exact identity evidence; one dedicated DEVELOPMENT canonical tenant UUID |
| 8 | Local-only | Bind exact `(issuer, audience, subject, tenant_id, HUMAN)` allowlist tuple | `NONE` | Exact subject/tenant evidence; only `engagement:read`, empty authority roles |
| 9 | Provider mutation | Enable only the exact approved DEVELOPMENT hook | `OWNER_INTERACTIVE_SESSION` | Exact server-policy evidence; no other hook or claim widening |
| 10 | Provider mutation | Issue one short-lived synthetic DEVELOPMENT access token | `SYNTHETIC_IDENTITY` | Exact hook evidence; ephemeral delivery only and no retention |
| 11 | Provider read | Fetch exact DEVELOPMENT public JWKS once | `NONE` | Credential-free bounded read; validate and discard raw response |
| 12 | Local-only | Validate the ephemeral token locally | `EPHEMERAL_SYNTHETIC_ACCESS_TOKEN` | Exact JWKS evidence; issuer/audience/signature/tenant/subject/policy checks pass |
| 13 | Local-only | Record sanitized evidence and terminate | `NONE` | Exact step-12 evidence; no token, credential, raw payload, customer data, or authority claim |

The seal is deliberately immediate: hook verification cannot interpose while public-schema CREATE remains directly granted. Each row remains one separately authorized, preflighted, executed, and verified resource boundary.

## Migration identity and privilege lifecycle

`MIGRATION_IDENTITY` is an effective-role execution boundary, not a login credential and not an alias for postgres or `OWNER_INTERACTIVE_SESSION`. It means all of:

- `session_user=postgres`;
- the exact one-way membership `postgres -> avuhz_migration_service_dev` with SET true, INHERIT false, and ADMIN false;
- `SET LOCAL ROLE avuhz_migration_service_dev`; and
- `current_user=avuhz_migration_service_dev` before hook DDL.

The bootstrap role is exactly NOLOGIN, NOSUPERUSER, NOINHERIT, NOCREATEDB, NOCREATEROLE, NOREPLICATION, and NOBYPASSRLS, with no password, reciprocal membership, broad inherited role, or direct database/table/sequence/AUTH/storage/DATA privilege. During the one hook migration it has direct, non-grantable USAGE and CREATE on `public`. The administrative bootstrap—not the restricted migration role—grants public-schema USAGE to `supabase_auth_admin`. The migration role owns the created function and grants only EXECUTE on that function to `supabase_auth_admin`.

No direct database ACL is granted to `avuhz_migration_service_dev`. PostgreSQL/Supabase ambient PUBLIC CONNECT or TEMPORARY privileges may remain effective; they are provider baseline privileges, not Avuhz grants. The role is NOLOGIN, the migrations create no temporary object, widening or reducing the PUBLIC database ACL is prohibited, and that unrelated database-wide policy is outside this AUTH plan.

The seal removes the migration role's direct public CREATE and USAGE and removes the postgres membership edge. The role remains restricted and owns the intact hook, while `supabase_auth_admin` retains schema USAGE and function EXECUTE. This is the intended steady state.

## Frozen identity and authority boundary

The hook may emit only the top-level `avuhz_tenant_id` and exact DEVELOPMENT service audience needed by the adapter. Each token selects exactly one canonical tenant UUID, and tenant switching requires a newly issued token. The hook emits no Avuhz capabilities or authority roles.

The server-owned environment allowlist is keyed by exact `(issuer, audience, subject, tenant_id, caller_type)`. The synthetic caller type is `HUMAN`, initial capability is only `engagement:read`, and authority roles are empty. The provider-assigned opaque subject and dedicated DEVELOPMENT tenant UUID are not yet known and are not invented.

Supabase remains an adapter. AUTH and DATA are logically separate even while DEVELOPMENT selects the same physical project; this plan authorizes no DATA operation.

## Current blockers

Plan v7 remains intentionally `DRAFT_BLOCKED`. Its active bindings are:

- bootstrap migration SHA-256 `sha256:b2af6edacb283afc5a5ad7d1c1ebdc5fdbd572bddd1cb115459caa6344acda45`;
- hook migration SHA-256 `sha256:234a27973d4f9468dfb59ff5002f2ae1b7523dac9bd80b26fd01fbc64c8bc783`;
- seal migration SHA-256 `sha256:aafec1973fa60e3a2b7076f36c989a373fb1115a1e9e3760781a0ef41ca9b1ad`;
- v7 evidence canonical digest `sha256:75568298af56a7f02ab826118902d3e8b1f62e290e57bea93da770b7f82a6211`; and
- progress digest `sha256:0dc83c7b72fccb4fde50baa3e37e30f4e8e14770406e0510ba67328fb2b36d52`.

The historical v2 evidence remains immutable lineage. The rejected, uncommitted v3/v4 drafts are superseded and are not current artifacts. The v5 evidence at `contracts/plans/v1/development-auth-step1-v5-local.evidence.json`, canonical digest `sha256:8d73fcd2b1ae9475a213716b8cd314803c5215b6b17eaa99dcb37d0e06d8a07e`, is preserved only as historical failed-certification lineage. The v6 evidence is preserved only as rejected pre-commit lineage. Current v7 local evidence binds the forward-corrected artifacts without claiming PostgreSQL certification or provider execution.

Fresh PostgreSQL 17 certification of the exact v7 artifact set remains pending. The migration identity binding and authorization window remain unresolved, and no approval exists. The function/provider verification binding, synthetic DEVELOPMENT Auth identity, provider subject, DEVELOPMENT tenant UUID, server-policy/capability digest, hook configuration reference, and ephemeral token/JWKS evidence remain unresolved where applicable.

Progress record version `1` remains `NOT_STARTED`: all 13 authorization states are `PENDING`, all execution and verification states are `NOT_STARTED`, no authorization is consumed, and no progress evidence is recorded. No Supabase migration has been applied, `avuhz_migration_service_dev` has not been created remotely, the hook has not been created or enabled, no synthetic identity has been created, and no token has been issued. No provider contact or mutation occurred during the local v6 or v7 corrections.

Every provider step requires a new exact authorization after its prior evidence exists; any binding change requires a new plan version and digest. The locally aligned v7 workflow has not yet run against the current candidate, so fresh PostgreSQL-17 certification remains pending.
