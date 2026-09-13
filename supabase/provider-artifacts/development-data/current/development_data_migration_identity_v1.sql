-- DEVELOPMENT DATA migration-identity bootstrap v1.
-- Remote execution is unauthorized by default. This artifact is only for the exact
-- DEVELOPMENT DATA project after a fresh empty-baseline preflight.
-- The broad hosted postgres owner is used only to bootstrap a non-login migration role.
-- The migration role receives the minimum temporary authority required by the existing
-- canonical initial migration: CREATEROLE, USAGE WITH GRANT OPTION on public, and CREATE
-- on public. It receives no reusable credential, database privilege, row-data privilege,
-- provider-schema privilege, superuser authority, CREATEDB, replication, or BYPASSRLS.

begin;

do $avuhz_development_data_migration_identity_v1_preflight$
begin
  if session_user <> 'postgres' or current_user <> 'postgres' then
    raise exception 'Avuhz DEVELOPMENT DATA migration identity v1 requires the exact approved postgres bootstrap session';
  end if;

  if not exists (
    select 1 from pg_roles
     where rolname = 'postgres'
       and not rolsuper
       and rolcreaterole
  ) then
    raise exception 'Avuhz DEVELOPMENT DATA migration identity v1 requires hosted NOSUPERUSER CREATEROLE postgres semantics';
  end if;

  if exists (select 1 from pg_roles where rolname = 'avuhz_data_migration_service_dev') then
    raise exception 'Avuhz DEVELOPMENT DATA migration identity already exists unexpectedly';
  end if;

  if exists (select 1 from pg_roles where rolname = 'avuhz_command_service') then
    raise exception 'Avuhz DEVELOPMENT DATA command-service role already exists unexpectedly';
  end if;

  if not exists (select 1 from pg_namespace where nspname = 'public')
     or not has_schema_privilege(current_user, 'public', 'USAGE')
     or not has_schema_privilege(current_user, 'public', 'CREATE') then
    raise exception 'Avuhz DEVELOPMENT DATA bootstrap session lacks required public schema authority';
  end if;

  if exists (
      select 1 from pg_namespace where nspname = 'avuhz' or nspname like 'avuhz\_%' escape '\'
    ) or exists (
      select 1 from pg_class c join pg_namespace n on n.oid = c.relnamespace
       where n.nspname = 'public' and c.relname like 'avuhz\_%' escape '\'
    ) or exists (
      select 1 from pg_proc p join pg_namespace n on n.oid = p.pronamespace
       where n.nspname = 'public' and p.proname like 'avuhz\_%' escape '\'
    ) or exists (
      select 1 from pg_type t join pg_namespace n on n.oid = t.typnamespace
       where n.nspname = 'public' and t.typname like 'avuhz\_%' escape '\'
    ) or exists (
      select 1 from pg_trigger where not tgisinternal and tgname like 'avuhz\_%' escape '\'
    ) or exists (
      select 1 from pg_policy where polname like 'avuhz\_%' escape '\'
    ) then
    raise exception 'Avuhz DEVELOPMENT DATA migration identity refuses non-empty Avuhz state';
  end if;
end
$avuhz_development_data_migration_identity_v1_preflight$;

create role avuhz_data_migration_service_dev
  nologin
  nosuperuser
  noinherit
  nocreatedb
  createrole
  noreplication
  nobypassrls;

grant avuhz_data_migration_service_dev to postgres
  with admin false, inherit false, set true
  granted by current_user;

do $avuhz_development_data_migration_identity_v1_database_acl$
begin
  execute format(
    'revoke all privileges on database %I from avuhz_data_migration_service_dev',
    current_database()
  );
end
$avuhz_development_data_migration_identity_v1_database_acl$;

revoke all privileges on schema public from avuhz_data_migration_service_dev;
grant usage on schema public to avuhz_data_migration_service_dev with grant option;
grant create on schema public to avuhz_data_migration_service_dev;

do $avuhz_development_data_migration_identity_v1_postcondition$
declare
  migration_role_oid oid;
  postgres_role_oid oid;
  role_record record;
  provider_edge_count integer;
  explicit_set_edge_count integer;
  total_membership_edge_count integer;
begin
  select oid, rolcanlogin, rolsuper, rolinherit, rolcreatedb, rolcreaterole,
         rolreplication, rolbypassrls
    into strict role_record
    from pg_roles
   where rolname = 'avuhz_data_migration_service_dev';

  migration_role_oid := role_record.oid;
  select oid into strict postgres_role_oid from pg_roles where rolname = 'postgres';

  if role_record.rolcanlogin
     or role_record.rolsuper
     or role_record.rolinherit
     or role_record.rolcreatedb
     or not role_record.rolcreaterole
     or role_record.rolreplication
     or role_record.rolbypassrls then
    raise exception 'Avuhz DEVELOPMENT DATA migration identity attributes mismatch';
  end if;

  select count(*) into provider_edge_count
    from pg_auth_members membership
    join pg_roles grantor_role on grantor_role.oid = membership.grantor
   where membership.roleid = migration_role_oid
     and membership.member = postgres_role_oid
     and membership.admin_option
     and not membership.inherit_option
     and not membership.set_option
     and grantor_role.rolsuper
     and grantor_role.oid <> postgres_role_oid;

  select count(*) into explicit_set_edge_count
    from pg_auth_members membership
   where membership.roleid = migration_role_oid
     and membership.member = postgres_role_oid
     and membership.grantor = postgres_role_oid
     and not membership.admin_option
     and not membership.inherit_option
     and membership.set_option;

  select count(*) into total_membership_edge_count
    from pg_auth_members membership
   where membership.roleid = migration_role_oid
      or membership.member = migration_role_oid;

  if provider_edge_count not in (0, 1)
     or explicit_set_edge_count <> 1
     or total_membership_edge_count <> provider_edge_count + explicit_set_edge_count then
    raise exception 'Avuhz DEVELOPMENT DATA migration identity membership envelope mismatch';
  end if;

  if exists (
    select 1 from pg_database database_record
    cross join lateral aclexplode(database_record.datacl) database_acl
     where database_record.datname = current_database()
       and database_acl.grantee = migration_role_oid
  ) then
    raise exception 'Avuhz DEVELOPMENT DATA migration identity has unexpected direct database privilege';
  end if;

  if not has_schema_privilege('avuhz_data_migration_service_dev', 'public', 'USAGE')
     or not has_schema_privilege('avuhz_data_migration_service_dev', 'public', 'CREATE')
     or (
       select count(*) from pg_namespace namespace
       cross join lateral aclexplode(coalesce(namespace.nspacl, '{}'::aclitem[])) schema_acl
        where namespace.nspname = 'public'
          and schema_acl.grantee = migration_role_oid
          and schema_acl.privilege_type = 'USAGE'
          and schema_acl.is_grantable
     ) <> 1
     or (
       select count(*) from pg_namespace namespace
       cross join lateral aclexplode(coalesce(namespace.nspacl, '{}'::aclitem[])) schema_acl
        where namespace.nspname = 'public'
          and schema_acl.grantee = migration_role_oid
          and schema_acl.privilege_type = 'CREATE'
          and not schema_acl.is_grantable
     ) <> 1
     or exists (
       select 1 from pg_namespace namespace
       cross join lateral aclexplode(coalesce(namespace.nspacl, '{}'::aclitem[])) schema_acl
        where namespace.nspname = 'public'
          and schema_acl.grantee = migration_role_oid
          and (
            schema_acl.privilege_type not in ('USAGE', 'CREATE')
            or (schema_acl.privilege_type = 'USAGE' and not schema_acl.is_grantable)
            or (schema_acl.privilege_type = 'CREATE' and schema_acl.is_grantable)
          )
     ) then
    raise exception 'Avuhz DEVELOPMENT DATA migration identity public schema privilege mismatch';
  end if;

  if exists (
    select 1 from pg_namespace namespace
     where namespace.nspname in ('auth', 'storage')
       and has_schema_privilege('avuhz_data_migration_service_dev', namespace.oid, 'USAGE,CREATE')
  ) then
    raise exception 'Avuhz DEVELOPMENT DATA migration identity has unexpected provider-schema privilege';
  end if;

  if exists (
    select 1 from pg_class relation
    join pg_namespace namespace on namespace.oid = relation.relnamespace
     where namespace.nspname in ('public', 'auth', 'storage')
       and relation.relkind in ('r', 'p', 'v', 'm', 'f')
       and has_table_privilege(
         'avuhz_data_migration_service_dev', relation.oid,
         'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
       )
  ) then
    raise exception 'Avuhz DEVELOPMENT DATA migration identity has unexpected table privilege';
  end if;

  if exists (
    select 1 from pg_class sequence
    join pg_namespace namespace on namespace.oid = sequence.relnamespace
    cross join lateral aclexplode(
      coalesce(sequence.relacl, acldefault('S', sequence.relowner))
    ) sequence_acl
     where namespace.nspname in ('public', 'auth', 'storage')
       and sequence.relkind = 'S'
       and sequence_acl.grantee = migration_role_oid
       and sequence_acl.privilege_type in ('USAGE', 'SELECT', 'UPDATE')
  ) then
    raise exception 'Avuhz DEVELOPMENT DATA migration identity has unexpected sequence privilege';
  end if;

  if exists (
    select 1 from pg_proc function
    join pg_namespace namespace on namespace.oid = function.pronamespace
    cross join lateral aclexplode(coalesce(function.proacl, acldefault('f', function.proowner))) function_acl
     where namespace.nspname in ('public', 'auth', 'storage')
       and function_acl.grantee = migration_role_oid
       and function_acl.privilege_type = 'EXECUTE'
  ) then
    raise exception 'Avuhz DEVELOPMENT DATA migration identity has unexpected direct function privilege';
  end if;

  if exists (select 1 from pg_roles where rolname = 'avuhz_command_service') then
    raise exception 'Avuhz DEVELOPMENT DATA bootstrap unexpectedly created command-service role';
  end if;
end
$avuhz_development_data_migration_identity_v1_postcondition$;

set local role avuhz_data_migration_service_dev;

do $avuhz_development_data_migration_identity_v1_effective_role$
begin
  if session_user <> 'postgres'
     or current_user <> 'avuhz_data_migration_service_dev' then
    raise exception 'Avuhz DEVELOPMENT DATA bounded SET ROLE transition failed';
  end if;
end
$avuhz_development_data_migration_identity_v1_effective_role$;

reset role;

commit;
