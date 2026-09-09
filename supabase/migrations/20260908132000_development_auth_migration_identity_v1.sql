-- DEVELOPMENT AUTH migration-identity bootstrap artifact.
-- Remote execution is unauthorized by default. A future exact owner/admin session may
-- apply only this role boundary before the separately authorized hook migration.
-- The role is deliberately NOLOGIN and receives no reusable credential or DATA access.

begin;

do $avuhz_development_auth_migration_identity_preflight$
begin
  if session_user <> 'postgres' or current_user <> 'postgres' then
    raise exception 'Avuhz DEVELOPMENT Auth migration identity bootstrap requires the exact approved postgres executor session';
  end if;

  if exists (
    select 1 from pg_roles where rolname = 'avuhz_migration_service_dev'
  ) then
    raise exception 'Avuhz DEVELOPMENT Auth migration identity already exists unexpectedly';
  end if;

  if not exists (select 1 from pg_namespace where nspname = 'public') then
    raise exception 'Avuhz DEVELOPMENT Auth migration identity requires the public schema';
  end if;

  if not exists (select 1 from pg_roles where rolname = 'supabase_auth_admin') then
    raise exception 'Avuhz DEVELOPMENT Auth migration identity requires supabase_auth_admin';
  end if;

  if to_regprocedure('public.avuhz_development_custom_access_token_hook_v1(jsonb)') is not null then
    raise exception 'Avuhz DEVELOPMENT Auth hook v1 already exists unexpectedly';
  end if;
end
$avuhz_development_auth_migration_identity_preflight$;

create role avuhz_migration_service_dev
  nologin
  nosuperuser
  noinherit
  nocreatedb
  nocreaterole
  noreplication
  nobypassrls;

do $avuhz_development_auth_migration_identity_database_acl$
begin
  execute format(
    'revoke all privileges on database %I from avuhz_migration_service_dev',
    current_database()
  );
end
$avuhz_development_auth_migration_identity_database_acl$;

revoke all privileges on schema public from avuhz_migration_service_dev;
grant usage on schema public to avuhz_migration_service_dev;
grant create on schema public to avuhz_migration_service_dev;

grant usage on schema public to supabase_auth_admin;

revoke avuhz_migration_service_dev from postgres;

grant avuhz_migration_service_dev to postgres
  with admin false, inherit false, set true;

do $avuhz_development_auth_migration_identity_postcondition$
declare
  migration_role_oid oid;
  postgres_role_oid oid;
  role_record record;
begin
  select oid, rolcanlogin, rolsuper, rolinherit, rolcreatedb, rolcreaterole,
         rolreplication, rolbypassrls
    into strict role_record
    from pg_roles
   where rolname = 'avuhz_migration_service_dev';

  migration_role_oid := role_record.oid;
  select oid into strict postgres_role_oid from pg_roles where rolname = 'postgres';

  if role_record.rolcanlogin
     or role_record.rolsuper
     or role_record.rolinherit
     or role_record.rolcreatedb
     or role_record.rolcreaterole
     or role_record.rolreplication
     or role_record.rolbypassrls then
    raise exception 'Avuhz DEVELOPMENT Auth migration identity attributes mismatch';
  end if;

  if (
    select count(*)
      from pg_auth_members membership
     where membership.roleid = migration_role_oid
       and membership.member = postgres_role_oid
       and not membership.admin_option
       and not membership.inherit_option
       and membership.set_option
  ) <> 1
     or exists (
       select 1
         from pg_auth_members membership
        where (membership.roleid = migration_role_oid
               or membership.member = migration_role_oid)
          and not (
            membership.roleid = migration_role_oid
            and membership.member = postgres_role_oid
            and not membership.admin_option
            and not membership.inherit_option
            and membership.set_option
          )
     ) then
    raise exception 'Avuhz DEVELOPMENT Auth migration identity membership mismatch';
  end if;

  if exists (
    select 1
      from pg_database database_record
      cross join lateral aclexplode(
        coalesce(database_record.datacl, '{}'::aclitem[])
      ) database_acl
     where database_record.datname = current_database()
       and database_acl.grantee = migration_role_oid
  ) then
    raise exception 'Avuhz DEVELOPMENT Auth migration identity has unexpected direct database privilege';
  end if;

  if not has_schema_privilege(
    'avuhz_migration_service_dev', 'public', 'USAGE'
  )
     or not has_schema_privilege(
       'avuhz_migration_service_dev', 'public', 'CREATE'
     )
     or (
       select count(*)
         from pg_namespace namespace
         cross join lateral aclexplode(
           coalesce(namespace.nspacl, '{}'::aclitem[])
         ) schema_acl
        where namespace.nspname = 'public'
          and schema_acl.grantee = migration_role_oid
          and schema_acl.privilege_type in ('USAGE', 'CREATE')
          and not schema_acl.is_grantable
     ) <> 2
     or exists (
       select 1
         from pg_namespace namespace
         cross join lateral aclexplode(
           coalesce(namespace.nspacl, '{}'::aclitem[])
         ) schema_acl
        where namespace.nspname = 'public'
          and schema_acl.grantee = migration_role_oid
          and (
            schema_acl.privilege_type not in ('USAGE', 'CREATE')
            or schema_acl.is_grantable
          )
     ) then
    raise exception 'Avuhz DEVELOPMENT Auth migration identity public schema privilege mismatch';
  end if;

  if not exists (
    select 1
      from pg_namespace namespace
      cross join lateral aclexplode(
        coalesce(namespace.nspacl, '{}'::aclitem[])
      ) schema_acl
      join pg_roles grantee on grantee.oid = schema_acl.grantee
     where namespace.nspname = 'public'
       and grantee.rolname = 'supabase_auth_admin'
       and schema_acl.privilege_type = 'USAGE'
       and not schema_acl.is_grantable
  ) then
    raise exception 'Avuhz DEVELOPMENT Auth bootstrap did not grant exact public schema usage to supabase_auth_admin';
  end if;

  if exists (
    select 1
      from pg_namespace namespace
     where namespace.nspname in ('auth', 'storage')
       and has_schema_privilege(
         'avuhz_migration_service_dev', namespace.oid, 'USAGE,CREATE'
       )
  ) then
    raise exception 'Avuhz DEVELOPMENT Auth migration identity has unexpected provider schema privilege';
  end if;

  if exists (
    select 1
      from pg_class relation
      join pg_namespace namespace on namespace.oid = relation.relnamespace
     where namespace.nspname in ('public', 'auth', 'storage')
       and relation.relkind in ('r', 'p', 'v', 'm', 'f')
       and has_table_privilege(
         'avuhz_migration_service_dev',
         relation.oid,
         'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
       )
  ) then
    raise exception 'Avuhz DEVELOPMENT Auth migration identity has unexpected table privilege';
  end if;

  if exists (
    select 1
      from pg_class sequence
      join pg_namespace namespace on namespace.oid = sequence.relnamespace
     where namespace.nspname in ('public', 'auth', 'storage')
       and case
         when sequence.relkind = 'S' then has_sequence_privilege(
           'avuhz_migration_service_dev', sequence.oid, 'USAGE,SELECT,UPDATE'
         )
         else false
       end
  ) then
    raise exception 'Avuhz DEVELOPMENT Auth migration identity has unexpected sequence privilege';
  end if;

  if exists (
    select 1
      from pg_proc function
      join pg_namespace namespace on namespace.oid = function.pronamespace
     where namespace.nspname in ('public', 'auth', 'storage')
       and has_function_privilege(
         'avuhz_migration_service_dev', function.oid, 'EXECUTE'
       )
  ) then
    raise exception 'Avuhz DEVELOPMENT Auth migration identity has unexpected function privilege';
  end if;

  if to_regprocedure('public.avuhz_development_custom_access_token_hook_v1(jsonb)') is not null then
    raise exception 'Avuhz DEVELOPMENT Auth hook v1 was created during identity bootstrap';
  end if;
end
$avuhz_development_auth_migration_identity_postcondition$;

set local role avuhz_migration_service_dev;

do $avuhz_development_auth_migration_identity_effective_role$
begin
  if session_user <> 'postgres'
     or current_user <> 'avuhz_migration_service_dev' then
    raise exception 'Avuhz DEVELOPMENT Auth migration identity bounded SET ROLE transition failed';
  end if;
end
$avuhz_development_auth_migration_identity_effective_role$;

reset role;

commit;
