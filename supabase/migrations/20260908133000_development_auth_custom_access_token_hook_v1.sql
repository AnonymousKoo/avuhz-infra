-- DEVELOPMENT AUTH custom access-token hook migration artifact.
-- Remote application is unauthorized by default. This file is local Step 1 preparation only.
-- Applying this migration, enabling the hook, creating identities, or touching any other
-- environment requires separate exact owner authorization and provider-side preflight.
-- The migration creates only one versioned hook function plus its least-privilege ACL.

begin;

do $avuhz_development_auth_hook_preflight$
begin
  if not exists (select 1 from pg_namespace where nspname = 'public') then
    raise exception 'Avuhz DEVELOPMENT Auth hook migration requires the public schema';
  end if;

  if not has_schema_privilege(current_user, 'public', 'USAGE')
     or not has_schema_privilege(current_user, 'public', 'CREATE') then
    raise exception 'Avuhz DEVELOPMENT Auth hook migration identity lacks public schema privileges';
  end if;

  if not exists (select 1 from pg_roles where rolname = 'supabase_auth_admin') then
    raise exception 'Avuhz DEVELOPMENT Auth hook migration requires supabase_auth_admin';
  end if;

  if to_regprocedure('public.avuhz_development_custom_access_token_hook_v1(jsonb)') is not null then
    raise exception 'Avuhz DEVELOPMENT Auth hook v1 already exists unexpectedly';
  end if;
end
$avuhz_development_auth_hook_preflight$;

create function public.avuhz_development_custom_access_token_hook_v1(event jsonb)
returns jsonb
language plpgsql
stable
set search_path = pg_catalog
as $avuhz_development_custom_access_token_hook_v1$
declare
  claims jsonb;
  app_metadata jsonb;
  tenant_id_text text;
begin
  if event is null or jsonb_typeof(event) <> 'object' then
    raise exception 'Avuhz DEVELOPMENT Auth hook received an invalid event';
  end if;

  claims := event -> 'claims';
  if claims is null or jsonb_typeof(claims) <> 'object' then
    raise exception 'Avuhz DEVELOPMENT Auth hook received invalid claims';
  end if;

  claims := claims - 'avuhz_tenant_id';
  app_metadata := claims -> 'app_metadata';

  if app_metadata is null or jsonb_typeof(app_metadata) <> 'object' then
    return jsonb_set(event, '{claims}', claims, true);
  end if;

  tenant_id_text := app_metadata ->> 'avuhz_tenant_id';
  if tenant_id_text is null then
    return jsonb_set(event, '{claims}', claims, true);
  end if;

  if tenant_id_text !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' then
    raise exception 'Avuhz DEVELOPMENT Auth hook tenant binding is invalid';
  end if;

  claims := jsonb_set(
    claims,
    '{aud}',
    to_jsonb('audience.avuhz.command-service.development'::text),
    true
  );

  claims := jsonb_set(
    claims,
    '{avuhz_tenant_id}',
    to_jsonb(tenant_id_text),
    true
  );

  return jsonb_set(event, '{claims}', claims, true);
end
$avuhz_development_custom_access_token_hook_v1$;

revoke all on function public.avuhz_development_custom_access_token_hook_v1(jsonb) from public;

do $avuhz_development_auth_hook_acl$
declare
  grantee_name text;
begin
  foreach grantee_name in array array['anon', 'authenticated', 'service_role'] loop
    if exists (select 1 from pg_roles where rolname = grantee_name) then
      execute format(
        'revoke all on function public.avuhz_development_custom_access_token_hook_v1(jsonb) from %I',
        grantee_name
      );
    end if;
  end loop;
end
$avuhz_development_auth_hook_acl$;

grant usage on schema public to supabase_auth_admin;

grant execute on function public.avuhz_development_custom_access_token_hook_v1(jsonb)
  to supabase_auth_admin;

commit;
