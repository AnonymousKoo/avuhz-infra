-- DEVELOPMENT AUTH migration-identity seal artifact.
-- Remote execution is unauthorized by default. A future exact owner/admin session may
-- apply only this seal after separately verified exact hook-migration application.
-- The seal removes the temporary SET ROLE edge and direct public-schema DDL envelope.

begin;

do $avuhz_development_auth_migration_identity_seal_preflight$
declare
  hook_oid oid;
  migration_role_oid oid;
  postgres_role_oid oid;
  role_record record;
begin
  if session_user <> 'postgres' or current_user <> 'postgres' then
    raise exception 'Avuhz DEVELOPMENT Auth migration identity seal requires the exact approved postgres executor session';
  end if;

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
    raise exception 'Avuhz DEVELOPMENT Auth migration identity seal role attributes mismatch';
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
    raise exception 'Avuhz DEVELOPMENT Auth migration identity seal membership mismatch';
  end if;

  if exists (
    select 1
      from pg_database database_record
      cross join lateral aclexplode(database_record.datacl) database_acl
     where database_record.datname = current_database()
       and database_acl.grantee = migration_role_oid
  ) then
    raise exception 'Avuhz DEVELOPMENT Auth migration identity seal found direct database privilege';
  end if;

  if (
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
    raise exception 'Avuhz DEVELOPMENT Auth migration identity seal public schema privilege mismatch';
  end if;

  if exists (
    select 1
      from pg_namespace namespace
     where namespace.nspname in ('auth', 'storage')
       and has_schema_privilege(
         'avuhz_migration_service_dev', namespace.oid, 'USAGE,CREATE'
       )
  ) then
    raise exception 'Avuhz DEVELOPMENT Auth migration identity seal found provider schema privilege';
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
    raise exception 'Avuhz DEVELOPMENT Auth migration identity seal found table privilege';
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
    raise exception 'Avuhz DEVELOPMENT Auth migration identity seal found sequence privilege';
  end if;

  hook_oid := to_regprocedure(
    'public.avuhz_development_custom_access_token_hook_v1(jsonb)'
  );
  if hook_oid is null then
    raise exception 'Avuhz DEVELOPMENT Auth migration identity seal requires the exact hook';
  end if;

  if not exists (
    select 1
      from pg_proc function
     where function.oid = hook_oid
       and function.proowner = migration_role_oid
       and not function.prosecdef
       and function.provolatile = 's'
       and function.proconfig = array['search_path=pg_catalog']
  ) then
    raise exception 'Avuhz DEVELOPMENT Auth migration identity seal hook definition mismatch';
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
    raise exception 'Avuhz DEVELOPMENT Auth migration identity seal requires exact supabase_auth_admin schema usage';
  end if;

  if (
    select count(*)
      from pg_proc function
      cross join lateral aclexplode(
        coalesce(function.proacl, acldefault('f', function.proowner))
      ) function_acl
      join pg_roles grantee on grantee.oid = function_acl.grantee
     where function.oid = hook_oid
       and grantee.rolname = 'supabase_auth_admin'
       and function_acl.privilege_type = 'EXECUTE'
       and not function_acl.is_grantable
  ) <> 1
     or exists (
       select 1
         from pg_proc function
         cross join lateral aclexplode(
           coalesce(function.proacl, acldefault('f', function.proowner))
         ) function_acl
        where function.oid = hook_oid
          and function_acl.grantee not in (
            migration_role_oid,
            (select oid from pg_roles where rolname = 'supabase_auth_admin')
          )
     ) then
    raise exception 'Avuhz DEVELOPMENT Auth migration identity seal hook ACL mismatch';
  end if;
end
$avuhz_development_auth_migration_identity_seal_preflight$;

revoke create on schema public from avuhz_migration_service_dev;
revoke usage on schema public from avuhz_migration_service_dev;
revoke avuhz_migration_service_dev from postgres;

do $avuhz_development_auth_migration_identity_seal_postcondition$
declare
  hook_oid oid;
  migration_role_oid oid;
  role_record record;
begin
  select oid, rolcanlogin, rolsuper, rolinherit, rolcreatedb, rolcreaterole,
         rolreplication, rolbypassrls
    into strict role_record
    from pg_roles
   where rolname = 'avuhz_migration_service_dev';

  migration_role_oid := role_record.oid;

  if role_record.rolcanlogin
     or role_record.rolsuper
     or role_record.rolinherit
     or role_record.rolcreatedb
     or role_record.rolcreaterole
     or role_record.rolreplication
     or role_record.rolbypassrls then
    raise exception 'Avuhz DEVELOPMENT Auth sealed migration identity attributes mismatch';
  end if;

  if exists (
    select 1
      from pg_auth_members membership
     where membership.roleid = migration_role_oid
        or membership.member = migration_role_oid
  ) then
    raise exception 'Avuhz DEVELOPMENT Auth sealed migration identity retains membership';
  end if;

  if exists (
    select 1
      from pg_database database_record
      cross join lateral aclexplode(database_record.datacl) database_acl
     where database_record.datname = current_database()
       and database_acl.grantee = migration_role_oid
  ) then
    raise exception 'Avuhz DEVELOPMENT Auth sealed migration identity retains direct database privilege';
  end if;

  if exists (
    select 1
      from pg_namespace namespace
      cross join lateral aclexplode(
        coalesce(namespace.nspacl, '{}'::aclitem[])
      ) schema_acl
     where namespace.nspname = 'public'
       and schema_acl.grantee = migration_role_oid
  ) then
    raise exception 'Avuhz DEVELOPMENT Auth sealed migration identity retains direct public schema privilege';
  end if;

  if exists (
    select 1
      from pg_namespace namespace
     where namespace.nspname in ('auth', 'storage')
       and has_schema_privilege(
         'avuhz_migration_service_dev', namespace.oid, 'USAGE,CREATE'
       )
  ) then
    raise exception 'Avuhz DEVELOPMENT Auth sealed migration identity retains provider schema privilege';
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
    raise exception 'Avuhz DEVELOPMENT Auth sealed migration identity retains table privilege';
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
    raise exception 'Avuhz DEVELOPMENT Auth sealed migration identity retains sequence privilege';
  end if;

  hook_oid := to_regprocedure(
    'public.avuhz_development_custom_access_token_hook_v1(jsonb)'
  );
  if hook_oid is null
     or not exists (
       select 1
         from pg_proc function
        where function.oid = hook_oid
          and function.proowner = migration_role_oid
          and not function.prosecdef
          and function.provolatile = 's'
          and function.proconfig = array['search_path=pg_catalog']
     ) then
    raise exception 'Avuhz DEVELOPMENT Auth sealed hook changed unexpectedly';
  end if;

  if not has_schema_privilege('supabase_auth_admin', 'public', 'USAGE')
     or not has_function_privilege(
       'supabase_auth_admin', hook_oid, 'EXECUTE'
     ) then
    raise exception 'Avuhz DEVELOPMENT Auth sealed hook lost supabase_auth_admin access';
  end if;

  if exists (
    select 1
      from pg_proc function
      cross join lateral aclexplode(
        coalesce(function.proacl, acldefault('f', function.proowner))
      ) function_acl
     where function.oid = hook_oid
       and function_acl.grantee not in (
         migration_role_oid,
         (select oid from pg_roles where rolname = 'supabase_auth_admin')
       )
  ) then
    raise exception 'Avuhz DEVELOPMENT Auth sealed hook ACL widened unexpectedly';
  end if;
end
$avuhz_development_auth_migration_identity_seal_postcondition$;

commit;
