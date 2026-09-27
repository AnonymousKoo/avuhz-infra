# DEVELOPMENT AUTH recovery-verification shape diagnostic v1

Status: DRAFT — NOT AUTHORIZED FOR PROVIDER EXECUTION

## Exact boundary

- Environment: `DEVELOPMENT`
- Provider: Supabase
- Project ref: `pwlhruwutoitnieactol`
- Responsibility: `AUTH` only
- Issuer: `https://pwlhruwutoitnieactol.supabase.co/auth/v1`
- Canonical source baseline: `d2bc359d97cf1b1ce6700c7873dcb9d525c806fc`
- Diagnostic primitive digest: `sha256:19c7c16c8cc495e0b4ab886ab897804251245c979b536498b14c7d94086809ce`
- Target synthetic identity: `avuhz-development-synthetic@example.invalid`
- Owner approval: not created
- Authorization window: unresolved
- Provider execution: not started

This document is a planning artifact only. It grants no provider authority.

## Purpose

Determine the structural shape of exactly one DEVELOPMENT AUTH direct recovery-verification response after the prior cleanup-v4 attempt stopped with `RECOVERY_VERIFICATION_RESPONSE_SHAPE_INVALID`.

The only retained diagnostic result may be the fixed labels emitted by `classify_recovery_verification_response_shape`, such as type/presence labels and `identity_layout`. No token value, refresh token, UUID, email, arbitrary provider key, header, credential value, or raw provider payload may be retained.

## Ordered boundaries

1. Local-only: validate this plan against canonical `main`, the merged diagnostic primitive, and the exact DEVELOPMENT AUTH target. No provider contact.
2. Credential boundary: only after separate explicit owner approval, create/bind a fresh least-privilege ephemeral credential appropriate to the exact diagnostic operation. The retired `cleanup-v2-ephemeral` credential must not be recreated or reused.
3. Provider diagnostic attempt: after a fresh step-specific preflight, perform exactly one recovery generation and exactly one direct recovery verification for the named synthetic DEVELOPMENT identity, solely to classify the verification response shape.
4. Evidence boundary: retain only sanitized fixed structural metadata. Clear/discard credentials, recovery material, access/refresh tokens, and raw provider payloads.
5. STOP: return the sanitized evidence for review. No cleanup retry, global logout, session revocation, repair, parser widening, second provider attempt, or automatic continuation is authorized.

Each provider-affecting boundary requires its own exact preflight and explicit authorization. A failed, partial, ambiguous, or mismatched attempt stops and is not retried.

## Explicit prohibitions

This plan does not authorize:

- production or staging access;
- the DATA project or any DATA responsibility;
- global logout, session cleanup, revocation, user deletion, hook changes, migrations, SQL, RLS changes, or schema changes;
- reuse or recreation of the retired `cleanup-v2-ephemeral` credential;
- storing secrets or credentials in GitHub files, workflow JSON, logs, docs, evidence, or command output;
- retaining access tokens, refresh tokens, recovery credentials, raw provider payloads, UUIDs, or email/PII in diagnostic evidence;
- parser acceptance changes based on an unverified assumption;
- retrying cleanup-v4 or any consumed historical execution surface.

## Stop conditions

STOP before provider contact if the environment, project ref, AUTH responsibility, canonical commit, diagnostic digest, synthetic identity, credential class, approval, or authorization window does not match the reviewed boundary.

STOP immediately after the first diagnostic attempt if the provider response is unexpected, the classifier cannot reduce it to fixed non-secret metadata, any secret/PII would be exposed, or the outcome is ambiguous.

STOP after sanitized evidence is produced. Further code or provider action requires a new reviewed boundary.

## Required approval before execution

Before any credential creation or provider call, create a separate exact owner approval binding this plan version/content, DEVELOPMENT, Supabase project `pwlhruwutoitnieactol`, AUTH responsibility, a short explicit authorization window, and the exact first provider-affecting step.

Until that approval exists and passes preflight, provider execution remains unauthorized.
