-- DEVELOPMENT AUTH custom access-token hook v2 forward-correction artifact.
-- Remote application is unauthorized by default. This artifact requires the exact hosted
-- v2 migration-identity membership envelope and keeps the hook disabled after creation.
-- It creates only the existing logical v1 hook function plus its least-privilege ACL.

begin;

do $avuhz_development_auth_hook_v2_executor_preflight$
begin
  if session_user <> 'postgres' or current_user <> 'postgres' then
    raise exception 'Avuhz DEVELOPMENT Auth hook v2 requires the exact approved postgres executor session';
  end if;
end
$avuhz_development_auth_hook_v2_executor_preflight$;

set local role avuhz_migration_service_dev;

do $avuhz_development_auth_hook_v2_effective_role_preflight$
declare
  migration_role_oid oid;
  postgres_role_oid oid;
  role_record record;
begin
  if session_user <> 'postgres'
     or current_user <> 'avuhz_migration_service_dev' then
    raise exception 'Avuhz DEVELOPMENT Auth hook v2 bounded effective-role transition failed';
  end if;

  select oid, rolcanlogin, rolsuper, rolinherit, rolcreatedb, rolcreaterole,
         rolreplication, rolbypassrls
    into strict role_record
    from pg_roles
   where rolname = 'avuhz_migration_service_dev';

  migration_role_oid := role_record.oid;
  select oid into strict postgres_role_oid
    from pg_roles where rolname = 'postgres';

  if role_record.rolcanlogin
     or role_record.rolsuper
     or role_record.rolinherit
     or role_record.rolcreatedb
     or role_record.rolcreaterole
     or role_record.rolreplication
     or role_record.rolbypassrls then
    raise exception 'Avuhz DEVELOPMENT Auth hook v2 migration identity attributes mismatch';
  end if;

  if (
    select count(*)
      from pg_auth_members membership
      join pg_roles grantor_role on grantor_role.oid = membership.grantor
     where membership.roleid = migration_role_oid
       and membership.member = postgres_role_oid
       and membership.admin_option
       and not membership.inherit_option
       and not membership.set_option
       and grantor_role.rolsuper
       and grantor_role.oid <> postgres_role_oid
  ) <> 1
     or (
       select count(*)
         from pg_auth_members membership
        where membership.roleid = migration_role_oid
          and membership.member = postgres_role_oid
          and membership.grantor = postgres_role_oid
          and not membership.admin_option
          and not membership.inherit_option
          and membership.set_option
     ) <> 1
     or (
       select count(*)
         from pg_auth_members membership
        where membership.roleid = migration_role_oid
           or membership.member = migration_role_oid
     ) <> 2 then
    raise exception 'Avuhz DEVELOPMENT Auth hook v2 migration identity membership envelope mismatch';
  end if;

  if not has_schema_privilege(current_user, 'public', 'USAGE')
     or not has_schema_privilege(current_user, 'public', 'CREATE') then
    raise exception 'Avuhz DEVELOPMENT Auth hook v2 migration identity public schema privilege mismatch';
  end if;

  if not exists (select 1 from pg_roles where rolname = 'supabase_auth_admin') then
    raise exception 'Avuhz DEVELOPMENT Auth hook v2 requires supabase_auth_admin';
  end if;

  if to_regprocedure('public.avuhz_development_custom_access_token_hook_v1(jsonb)') is not null then
    raise exception 'Avuhz DEVELOPMENT Auth hook v1 already exists unexpectedly';
  end if;

  if exists (
    select 1
      from pg_namespace namespace
     where namespace.nspname in ('auth', 'storage')
       and has_schema_privilege(current_user, namespace.oid, 'USAGE,CREATE')
  ) then
    raise exception 'Avuhz DEVELOPMENT Auth hook v2 migration identity has unexpected provider schema privilege';
  end if;

  if exists (
    select 1
      from pg_class relation
      join pg_namespace namespace on namespace.oid = relation.relnamespace
     where namespace.nspname in ('public', 'auth', 'storage')
       and relation.relkind in ('r', 'p', 'v', 'm', 'f')
       and has_table_privilege(
         current_user,
         relation.oid,
         'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
       )
  ) then
    raise exception 'Avuhz DEVELOPMENT Auth hook v2 migration identity has unexpected table privilege';
  end if;
end
$avuhz_development_auth_hook_v2_effective_role_preflight$;

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

do $avuhz_development_auth_hook_v2_acl$
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
$avuhz_development_auth_hook_v2_acl$;

grant execute on function public.avuhz_development_custom_access_token_hook_v1(jsonb)
  to supabase_auth_admin;

commit;
