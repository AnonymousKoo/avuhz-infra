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

| Binding | Current value |
|---|---|
| Plan ID | `a7100000-0000-4000-8000-000000000101` |
| Plan version | `1` |
| Plan digest | `sha256:97079c0a9cc171b5c6adc21b5de7cba5be6aeb6d4b8bf6f398a67129669b042f` |
| Definition status | `DRAFT_BLOCKED` |
| Environment | `DEVELOPMENT` |
| Provider/project | Supabase / `pwlhruwutoitnieactol` |
| Responsibility | `AUTH` only |
| Issuer | `https://pwlhruwutoitnieactol.supabase.co/auth/v1` |
| Expected audience | `audience.avuhz.command-service.development` |
| Planned hook | `public.avuhz_development_custom_access_token_hook_v1(jsonb)` |
| Approval record | Not created |
| Execution | Not started; all step authorizations pending |

This draft is not owner approval and grants no provider access or change authority.

## Exact ordered sequence

| Step | Class | Exact resource/change | Allowed credential class | Required gate and postcondition |
|---|---|---|---|---|
| 1 | Local-only | Create and validate only the ordered v1 hook migration artifact | `NONE` | Green canonical baseline; committed migration digest and security evidence; nothing applied or enabled |
| 2 | Provider mutation | Apply exactly that migration to the approved DEVELOPMENT project | `MIGRATION_IDENTITY` | Exact step-1 artifact evidence; atomic function-plus-ACL creation; hook remains disabled |
| 3 | Provider read | Verify exact v1 function body, ACL, and disabled state | `MIGRATION_IDENTITY` | Exact step-2 application evidence; no ACL widening or repair |
| 4 | Provider mutation | Create one dedicated synthetic DEVELOPMENT Auth identity | `OWNER_INTERACTIVE_SESSION` | Exact disabled-hook evidence; one provider-assigned opaque subject |
| 5 | Provider mutation | Set only provider-controlled `app_metadata.avuhz_tenant_id` for that identity | `OWNER_INTERACTIVE_SESSION` | Exact identity evidence; one dedicated DEVELOPMENT canonical tenant UUID |
| 6 | Local-only | Bind exact `(issuer, audience, subject, tenant_id, HUMAN)` allowlist tuple | `NONE` | Exact subject/tenant evidence; only `engagement:read`, empty authority roles |
| 7 | Provider mutation | Enable only the exact approved DEVELOPMENT hook | `OWNER_INTERACTIVE_SESSION` | Exact server-policy evidence; no other hook or claim widening |
| 8 | Provider mutation | Issue one short-lived synthetic DEVELOPMENT access token | `SYNTHETIC_IDENTITY` | Exact hook evidence; ephemeral delivery only and no retention |
| 9 | Provider read | Fetch exact DEVELOPMENT public JWKS once | `NONE` | Credential-free bounded read; validate and discard raw response |
| 10 | Local-only | Validate the ephemeral token locally | `EPHEMERAL_SYNTHETIC_ACCESS_TOKEN` | Exact JWKS evidence; issuer/audience/signature/tenant/subject/policy checks pass |
| 11 | Local-only | Record sanitized evidence and terminate | `NONE` | Exact step-10 evidence; no token, credential, raw payload, customer data, or authority claim |

Each row remains one independently preflighted, executed, and verified resource boundary. Plan approval can allow the next row to proceed without another owner prompt only after every exact prior gate passes.

## Frozen identity and authority boundary

The hook may emit only the top-level `avuhz_tenant_id` and exact DEVELOPMENT service audience needed by the adapter. Each token selects exactly one canonical tenant UUID, and tenant switching requires a newly issued token. The hook emits no Avuhz capabilities or authority roles.

The server-owned environment allowlist is keyed by exact `(issuer, audience, subject, tenant_id, caller_type)`. The synthetic caller type is `HUMAN`, initial capability is only `engagement:read`, and authority roles are empty. The provider-assigned opaque subject and dedicated DEVELOPMENT tenant UUID are not yet known and are not invented.

Supabase remains an adapter. AUTH and DATA are logically separate even while DEVELOPMENT selects the same physical project; this plan authorizes no DATA operation.

## Current blockers

The v1 plan is intentionally `DRAFT_BLOCKED`. No authorization window or owner approval exists. The hook migration, filename, commit, and digest do not exist. Migration/verification identity bindings, provider synthetic identity/subject, dedicated tenant UUID, server-policy digest, hook configuration reference, and ephemeral credential-delivery procedure remain unresolved. Resolving any definition binding changes the immutable plan and therefore requires a new plan version/digest before owner approval.
