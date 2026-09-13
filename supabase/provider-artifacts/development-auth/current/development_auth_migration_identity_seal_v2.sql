-- DEVELOPMENT AUTH migration-identity seal v2 forward-correction artifact.
-- Remote execution is unauthorized by default. This seal removes only the temporary
-- self-granted SET edge and direct public-schema DDL envelope. The provider-imposed
-- bootstrap-superuser ADMIN/NOSET/NOINHERIT edge is verified and intentionally remains.

begin;

do $avuhz_development_auth_migration_identity_seal_v2_preflight$
declare
  hook_oid oid;
  migration_role_oid oid;
  postgres_role_oid oid;
  role_record record;
begin
  if session_user <> 'postgres' or current_user <> 'postgres' then
    raise exception 'Avuhz DEVELOPMENT Auth migration identity seal v2 requires the exact approved postgres executor session';
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
    raise exception 'Avuhz DEVELOPMENT Auth migration identity seal v2 role attributes mismatch';
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
    raise exception 'Avuhz DEVELOPMENT Auth migration identity seal v2 membership envelope mismatch';
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
  ) <> 2 then
    raise exception 'Avuhz DEVELOPMENT Auth migration identity seal v2 public schema privilege mismatch';
  end if;

  hook_oid := to_regprocedure(
    'public.avuhz_development_custom_access_token_hook_v1(jsonb)'
  );
  if hook_oid is null then
    raise exception 'Avuhz DEVELOPMENT Auth migration identity seal v2 requires the exact hook';
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
    raise exception 'Avuhz DEVELOPMENT Auth migration identity seal v2 hook definition mismatch';
  end if;
end
$avuhz_development_auth_migration_identity_seal_v2_preflight$;

revoke create on schema public from avuhz_migration_service_dev;
revoke usage on schema public from avuhz_migration_service_dev;
revoke avuhz_migration_service_dev from postgres
  granted by postgres;

do $avuhz_development_auth_migration_identity_seal_v2_postcondition$
declare
  hook_oid oid;
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
  select oid into strict postgres_role_oid
    from pg_roles where rolname = 'postgres';

  if role_record.rolcanlogin
     or role_record.rolsuper
     or role_record.rolinherit
     or role_record.rolcreatedb
     or role_record.rolcreaterole
     or role_record.rolreplication
     or role_record.rolbypassrls then
    raise exception 'Avuhz DEVELOPMENT Auth sealed migration identity v2 attributes mismatch';
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
     or exists (
       select 1
         from pg_auth_members membership
        where (membership.roleid = migration_role_oid
               or membership.member = migration_role_oid)
          and not (
            membership.roleid = migration_role_oid
            and membership.member = postgres_role_oid
            and membership.admin_option
            and not membership.inherit_option
            and not membership.set_option
            and exists (
              select 1
                from pg_roles grantor_role
               where grantor_role.oid = membership.grantor
                 and grantor_role.rolsuper
                 and grantor_role.oid <> postgres_role_oid
            )
          )
     ) then
    raise exception 'Avuhz DEVELOPMENT Auth sealed migration identity v2 membership mismatch';
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
    raise exception 'Avuhz DEVELOPMENT Auth sealed migration identity v2 retains direct public schema privilege';
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
    raise exception 'Avuhz DEVELOPMENT Auth sealed hook v2 changed unexpectedly';
  end if;

  if not has_schema_privilege('supabase_auth_admin', 'public', 'USAGE')
     or not has_function_privilege(
       'supabase_auth_admin', hook_oid, 'EXECUTE'
     ) then
    raise exception 'Avuhz DEVELOPMENT Auth sealed hook v2 lost supabase_auth_admin access';
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
    raise exception 'Avuhz DEVELOPMENT Auth sealed hook v2 ACL widened unexpectedly';
  end if;
end
$avuhz_development_auth_migration_identity_seal_v2_postcondition$;

commit;
