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
- `contracts/plans/v1/development-auth-step1-v5-local.evidence.json`

| Binding | Current value |
|---|---|
| Plan ID | `a7100000-0000-4000-8000-000000000101` |
| Plan version | `4` |
| Plan digest | `sha256:fd7b0760ff2939da616a2fdf8a476ac3772de39ccd5858e4d5b6e589a1384a3f` |
| Definition status | `DRAFT_BLOCKED` |
| Environment | `DEVELOPMENT` |
| Provider/project | Supabase / `pwlhruwutoitnieactol` |
| Responsibility | `AUTH` only |
| Issuer | `https://pwlhruwutoitnieactol.supabase.co/auth/v1` |
| Expected audience | `audience.avuhz.command-service.development` |
| Planned hook | `public.avuhz_development_custom_access_token_hook_v1(jsonb)` |
| Step 1 v5 local evidence | `(recomputed in the v5 evidence artifact)` |
| Approval record | Not created |
| Authorization window | Unresolved |
| Execution | Not started; all 13 step authorizations pending |

This draft is not owner approval and grants no provider access or change authority. Local artifact certification does not mark Step 1 executed and does not authorize any provider step.

## Exact ordered sequence

| Step | Class | Exact resource/change | Allowed credential class | Required gate and postcondition |
|---|---|---|---|---|
| 1 | Local-only | Validate the ordered bootstrap, effective-role hook, and immediate seal artifacts | `NONE` | Fresh v5 local evidence binds all three migrations and focused tests; nothing applied or enabled |
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

Plan v5 remains intentionally `DRAFT_BLOCKED`. It binds:

- bootstrap migration SHA-256 `1706c13211cc64b4996c779b8b9745be7cb7670261f9a9e613f7e67a05dc8635`;
- hook migration SHA-256 `1773c54ef1ec6706b26fa9e38f2820f073832097c8767cb3160fcfec7eb01376`; and
- seal migration SHA-256 `0b8450e0b5984988a191fc81cd992ba0ef20bb805dc7d71123019244af8830b5`.

The historical v2 evidence remains immutable lineage. The rejected, uncommitted v3 evidence is superseded and is not a current artifact. Fresh v5 evidence binds the corrected migrations and tests without provider claims.

Nothing has been applied to Supabase. The migration identity binding remains unresolved until Step 2 is separately authorized, executed, and independently verified. No authorization window or approval exists. Later unresolved values include verification identity/function digest, provider synthetic identity and subject, DEVELOPMENT tenant UUID, server-policy digest, hook configuration reference, and ephemeral credential-delivery procedure. Every provider step requires a new exact authorization after its prior evidence exists; any binding change requires a new plan version and digest.
