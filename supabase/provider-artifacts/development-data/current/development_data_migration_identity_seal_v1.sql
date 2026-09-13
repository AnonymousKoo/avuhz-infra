-- DEVELOPMENT DATA migration-identity seal v1.
-- Remote execution is unauthorized by default. Run only after the exact bound initial
-- migration succeeds under avuhz_data_migration_service_dev.
-- This seal removes temporary CREATEROLE, public-schema DDL authority, and the explicit
-- postgres SET edge. A provider-imposed ADMIN/NOSET/NOINHERIT bootstrap edge may remain.

begin;

do $avuhz_development_data_migration_identity_seal_v1_preflight$
declare
  migration_role_oid oid;
  postgres_role_oid oid;
  role_record record;
  provider_edge_count integer;
  explicit_set_edge_count integer;
  total_membership_edge_count integer;
begin
  if session_user <> 'postgres' or current_user <> 'postgres' then
    raise exception 'Avuhz DEVELOPMENT DATA migration identity seal requires the exact approved postgres owner session';
  end if;

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
    raise exception 'Avuhz DEVELOPMENT DATA pre-seal migration identity attributes mismatch';
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
     or total_membership_edge_count < provider_edge_count + explicit_set_edge_count then
    raise exception 'Avuhz DEVELOPMENT DATA pre-seal membership envelope mismatch';
  end if;

  if not has_schema_privilege('avuhz_data_migration_service_dev', 'public', 'USAGE')
     or not has_schema_privilege('avuhz_data_migration_service_dev', 'public', 'CREATE') then
    raise exception 'Avuhz DEVELOPMENT DATA pre-seal public schema authority mismatch';
  end if;

  if (
    select count(*)
      from pg_class relation
      join pg_namespace namespace on namespace.oid = relation.relnamespace
     where namespace.nspname = 'public'
       and relation.relkind in ('r', 'p')
       and relation.relname like 'avuhz\_%' escape '\'
  ) <> 16 then
    raise exception 'Avuhz DEVELOPMENT DATA seal requires exactly 16 Avuhz tables';
  end if;

  if (
    select count(*)
      from pg_class relation
      join pg_namespace namespace on namespace.oid = relation.relnamespace
     where namespace.nspname = 'public'
       and relation.relkind in ('r', 'p')
       and relation.relname like 'avuhz\_%' escape '\'
       and relation.relrowsecurity
  ) <> 16 then
    raise exception 'Avuhz DEVELOPMENT DATA seal requires RLS on all 16 Avuhz tables';
  end if;

  if not exists (
    select 1 from pg_roles
     where rolname = 'avuhz_command_service'
       and not rolcanlogin
       and not rolsuper
       and not rolinherit
       and not rolcreaterole
       and not rolcreatedb
       and not rolreplication
       and not rolbypassrls
  ) then
    raise exception 'Avuhz DEVELOPMENT DATA command-service role mismatch before seal';
  end if;
end
$avuhz_development_data_migration_identity_seal_v1_preflight$;

alter role avuhz_data_migration_service_dev nocreaterole;
revoke create on schema public from avuhz_data_migration_service_dev;
revoke usage on schema public from avuhz_data_migration_service_dev;
revoke avuhz_data_migration_service_dev from postgres granted by postgres;

do $avuhz_development_data_migration_identity_seal_v1_postcondition$
declare
  migration_role_oid oid;
  postgres_role_oid oid;
  role_record record;
  provider_edge_count integer;
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
     or role_record.rolcreaterole
     or role_record.rolreplication
     or role_record.rolbypassrls then
    raise exception 'Avuhz DEVELOPMENT DATA sealed migration identity attributes mismatch';
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

  select count(*) into total_membership_edge_count
    from pg_auth_members membership
   where membership.roleid = migration_role_oid
      or membership.member = migration_role_oid;

  if provider_edge_count not in (0, 1)
     or total_membership_edge_count < provider_edge_count
     or exists (
       select 1 from pg_auth_members membership
        where membership.roleid = migration_role_oid
          and membership.member = postgres_role_oid
          and membership.grantor = postgres_role_oid
          and membership.set_option
     ) then
    raise exception 'Avuhz DEVELOPMENT DATA sealed migration identity membership mismatch';
  end if;

  if pg_has_role('postgres', 'avuhz_data_migration_service_dev', 'SET') then
    raise exception 'Avuhz DEVELOPMENT DATA sealed migration identity remains SET-accessible';
  end if;

  if exists (
    select 1 from pg_namespace namespace
    cross join lateral aclexplode(coalesce(namespace.nspacl, '{}'::aclitem[])) schema_acl
     where namespace.nspname = 'public'
       and schema_acl.grantee = migration_role_oid
  ) then
    raise exception 'Avuhz DEVELOPMENT DATA sealed migration identity retains direct public schema privilege';
  end if;

  if (
    select count(*)
      from pg_class relation
      join pg_namespace namespace on namespace.oid = relation.relnamespace
     where namespace.nspname = 'public'
       and relation.relkind in ('r', 'p')
       and relation.relname like 'avuhz\_%' escape '\'
       and relation.relrowsecurity
  ) <> 16 then
    raise exception 'Avuhz DEVELOPMENT DATA sealed state lost RLS coverage';
  end if;

  if (
    select count(*)
      from pg_policy policy
      join pg_class relation on relation.oid = policy.polrelid
      join pg_namespace namespace on namespace.oid = relation.relnamespace
     where namespace.nspname = 'public'
       and relation.relname like 'avuhz\_%' escape '\'
       and policy.polname = 'avuhz_command_service_tenant_isolation'
  ) <> 16 then
    raise exception 'Avuhz DEVELOPMENT DATA sealed state tenant policy count mismatch';
  end if;

  if exists (
    select 1
      from information_schema.role_table_grants grants
     where grants.table_schema = 'public'
       and grants.table_name like 'avuhz\_%' escape '\'
       and grants.grantee in ('PUBLIC', 'anon', 'authenticated', 'service_role')
  ) then
    raise exception 'Avuhz DEVELOPMENT DATA sealed state exposes Avuhz table grants';
  end if;

  if not exists (
    select 1 from pg_roles
     where rolname = 'avuhz_command_service'
       and not rolcanlogin
       and not rolsuper
       and not rolinherit
       and not rolcreaterole
       and not rolcreatedb
       and not rolreplication
       and not rolbypassrls
  ) then
    raise exception 'Avuhz DEVELOPMENT DATA sealed command-service role mismatch';
  end if;
end
$avuhz_development_data_migration_identity_seal_v1_postcondition$;

commit;
