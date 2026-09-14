-- DEVELOPMENT DATA outbox-trigger search_path repair v1.
-- Remote execution is unauthorized by default. This artifact is intentionally one-shot.
-- The sealed migration role owns the target function and is not SET-accessible. PostgreSQL 17
-- therefore requires the hosted NOSUPERUSER CREATEROLE postgres role, which retains ADMIN on
-- the migration role, to create one explicit transactional SET edge to itself. The edge is
-- used only to SET LOCAL ROLE for the single ALTER FUNCTION, then is revoked before commit.

begin;

do $avuhz_development_data_outbox_search_path_repair_v1_preflight$
declare
  migration_role_oid oid;
  postgres_role_oid oid;
  command_role_oid oid;
  function_record record;
  function_acl_count integer;
  owner_execute_acl_count integer;
  trigger_count integer;
  function_trigger_count integer;
  provider_edge_count integer;
  explicit_set_edge_count integer;
  command_admin_edge_count integer;
  total_membership_edge_count integer;
begin
  if session_user <> 'postgres' or current_user <> 'postgres' then
    raise exception 'Avuhz DEVELOPMENT DATA outbox search_path repair requires the exact approved postgres owner session';
  end if;

  select oid into strict postgres_role_oid
    from pg_roles
   where rolname = 'postgres'
     and not rolsuper
     and rolcreaterole;

  select oid into strict migration_role_oid
    from pg_roles
   where rolname = 'avuhz_data_migration_service_dev'
     and not rolcanlogin
     and not rolsuper
     and not rolinherit
     and not rolcreatedb
     and not rolcreaterole
     and not rolreplication
     and not rolbypassrls;

  select oid into strict command_role_oid
    from pg_roles
   where rolname = 'avuhz_command_service'
     and not rolcanlogin
     and not rolsuper
     and not rolinherit
     and not rolcreatedb
     and not rolcreaterole
     and not rolreplication
     and not rolbypassrls;

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
     and membership.grantor = postgres_role_oid;

  select count(*) into command_admin_edge_count
    from pg_auth_members membership
    join pg_roles grantor_role on grantor_role.oid = membership.grantor
   where membership.roleid = command_role_oid
     and membership.member = migration_role_oid
     and membership.admin_option
     and not membership.inherit_option
     and not membership.set_option
     and grantor_role.rolsuper
     and grantor_role.oid <> migration_role_oid;

  select count(*) into total_membership_edge_count
    from pg_auth_members membership
   where membership.roleid = migration_role_oid
      or membership.member = migration_role_oid;

  if provider_edge_count <> 1
     or explicit_set_edge_count <> 0
     or command_admin_edge_count <> 1
     or total_membership_edge_count <> 2
     or not pg_has_role('postgres', 'avuhz_data_migration_service_dev', 'MEMBER')
     or pg_has_role('postgres', 'avuhz_data_migration_service_dev', 'USAGE')
     or pg_has_role('postgres', 'avuhz_data_migration_service_dev', 'SET')
     or pg_has_role('avuhz_data_migration_service_dev', 'avuhz_command_service', 'SET') then
    raise exception 'Avuhz DEVELOPMENT DATA outbox search_path repair requires the exact sealed membership envelope';
  end if;

  select function.oid,
         function.proowner,
         owner_role.rolname as owner_name,
         function.prosecdef,
         function.proconfig,
         function.proacl,
         function.provolatile,
         function.proleakproof,
         function.prorettype,
         language.lanname,
         function.prosrc
    into strict function_record
    from pg_proc function
    join pg_namespace namespace on namespace.oid = function.pronamespace
    join pg_roles owner_role on owner_role.oid = function.proowner
    join pg_language language on language.oid = function.prolang
   where namespace.nspname = 'public'
     and function.proname = 'avuhz_guard_outbox_transition'
     and pg_get_function_identity_arguments(function.oid) = '';

  if function_record.proowner <> migration_role_oid
     or function_record.owner_name <> 'avuhz_data_migration_service_dev'
     or function_record.prosecdef
     or function_record.proconfig is not null
     or function_record.provolatile <> 'v'
     or function_record.proleakproof
     or function_record.prorettype <> 'pg_catalog.trigger'::regtype
     or function_record.lanname <> 'plpgsql'
     or position('invalid outbox delivery transition' in function_record.prosrc) = 0
     or position('outbox attempt history cannot be rewritten' in function_record.prosrc) = 0
     or position('jsonb_array_length' in function_record.prosrc) = 0 then
    raise exception 'Avuhz DEVELOPMENT DATA outbox function pre-repair state mismatch';
  end if;

  select count(*),
         count(*) filter (
           where function_acl.grantee = function_record.proowner
             and function_acl.grantor = function_record.proowner
             and function_acl.privilege_type = 'EXECUTE'
             and not function_acl.is_grantable
         )
    into function_acl_count, owner_execute_acl_count
    from aclexplode(coalesce(function_record.proacl, acldefault('f', function_record.proowner))) function_acl;

  if function_acl_count <> 1 or owner_execute_acl_count <> 1 then
    raise exception 'Avuhz DEVELOPMENT DATA outbox function ACL mismatch';
  end if;

  select count(*) into trigger_count
    from pg_trigger trigger
    join pg_class relation on relation.oid = trigger.tgrelid
    join pg_namespace namespace on namespace.oid = relation.relnamespace
   where not trigger.tgisinternal
     and trigger.tgfoid = function_record.oid
     and trigger.tgname = 'avuhz_guard_outbox_transition'
     and namespace.nspname = 'public'
     and relation.relname = 'avuhz_outbox_deliveries'
     and trigger.tgtype = 19
     and trigger.tgenabled = 'O';

  select count(*) into function_trigger_count
    from pg_trigger trigger
   where not trigger.tgisinternal
     and trigger.tgfoid = function_record.oid;

  if trigger_count <> 1 or function_trigger_count <> 1 then
    raise exception 'Avuhz DEVELOPMENT DATA outbox trigger binding mismatch';
  end if;

  if (
    select count(*)
      from pg_class relation
      join pg_namespace namespace on namespace.oid = relation.relnamespace
     where namespace.nspname = 'public'
       and relation.relkind in ('r', 'p')
       and relation.relname like 'avuhz\_%' escape '\'
  ) <> 16
     or (
       select count(*)
         from pg_class relation
         join pg_namespace namespace on namespace.oid = relation.relnamespace
        where namespace.nspname = 'public'
          and relation.relkind in ('r', 'p')
          and relation.relname like 'avuhz\_%' escape '\'
          and relation.relrowsecurity
     ) <> 16
     or (
       select count(*)
         from pg_policy policy
         join pg_class relation on relation.oid = policy.polrelid
         join pg_namespace namespace on namespace.oid = relation.relnamespace
        where namespace.nspname = 'public'
          and relation.relname like 'avuhz\_%' escape '\'
          and policy.polname = 'avuhz_command_service_tenant_isolation'
     ) <> 16 then
    raise exception 'Avuhz DEVELOPMENT DATA outbox search_path repair tenant surface mismatch';
  end if;

  if exists (
    select 1
      from information_schema.role_table_grants grants
     where grants.table_schema = 'public'
       and grants.table_name like 'avuhz\_%' escape '\'
       and grants.grantee in ('PUBLIC', 'anon', 'authenticated', 'service_role')
  ) then
    raise exception 'Avuhz DEVELOPMENT DATA outbox search_path repair found exposed table grants';
  end if;

  if not has_schema_privilege('avuhz_command_service', 'public', 'USAGE')
     or has_schema_privilege('avuhz_command_service', 'public', 'CREATE') then
    raise exception 'Avuhz DEVELOPMENT DATA command-service schema privilege mismatch';
  end if;
end
$avuhz_development_data_outbox_search_path_repair_v1_preflight$;

-- PostgreSQL 17 object-owner access is opened only inside this transaction and only for
-- the exact sealed migration role. Any later failure rolls this membership change back.
grant avuhz_data_migration_service_dev to postgres
  with admin false, inherit false, set true
  granted by current_user;

set local role avuhz_data_migration_service_dev;
alter function public.avuhz_guard_outbox_transition() set search_path to '';
reset role;

revoke avuhz_data_migration_service_dev from postgres granted by postgres;

do $avuhz_development_data_outbox_search_path_repair_v1_postcondition$
declare
  migration_role_oid oid;
  postgres_role_oid oid;
  command_role_oid oid;
  function_record record;
  function_acl_count integer;
  owner_execute_acl_count integer;
  trigger_count integer;
  function_trigger_count integer;
  provider_edge_count integer;
  explicit_set_edge_count integer;
  command_admin_edge_count integer;
  total_membership_edge_count integer;
begin
  select oid into strict postgres_role_oid from pg_roles where rolname = 'postgres';
  select oid into strict migration_role_oid
    from pg_roles
   where rolname = 'avuhz_data_migration_service_dev'
     and not rolcanlogin
     and not rolsuper
     and not rolinherit
     and not rolcreatedb
     and not rolcreaterole
     and not rolreplication
     and not rolbypassrls;
  select oid into strict command_role_oid from pg_roles where rolname = 'avuhz_command_service';

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
     and membership.grantor = postgres_role_oid;

  select count(*) into command_admin_edge_count
    from pg_auth_members membership
    join pg_roles grantor_role on grantor_role.oid = membership.grantor
   where membership.roleid = command_role_oid
     and membership.member = migration_role_oid
     and membership.admin_option
     and not membership.inherit_option
     and not membership.set_option
     and grantor_role.rolsuper
     and grantor_role.oid <> migration_role_oid;

  select count(*) into total_membership_edge_count
    from pg_auth_members membership
   where membership.roleid = migration_role_oid
      or membership.member = migration_role_oid;

  if provider_edge_count <> 1
     or explicit_set_edge_count <> 0
     or command_admin_edge_count <> 1
     or total_membership_edge_count <> 2
     or pg_has_role('postgres', 'avuhz_data_migration_service_dev', 'USAGE')
     or pg_has_role('postgres', 'avuhz_data_migration_service_dev', 'SET')
     or pg_has_role('avuhz_data_migration_service_dev', 'avuhz_command_service', 'SET') then
    raise exception 'Avuhz DEVELOPMENT DATA sealed membership envelope was not restored after repair';
  end if;

  select function.oid,
         function.proowner,
         owner_role.rolname as owner_name,
         function.prosecdef,
         function.proconfig,
         function.proacl,
         function.provolatile,
         function.proleakproof,
         function.prorettype,
         language.lanname,
         function.prosrc
    into strict function_record
    from pg_proc function
    join pg_namespace namespace on namespace.oid = function.pronamespace
    join pg_roles owner_role on owner_role.oid = function.proowner
    join pg_language language on language.oid = function.prolang
   where namespace.nspname = 'public'
     and function.proname = 'avuhz_guard_outbox_transition'
     and pg_get_function_identity_arguments(function.oid) = '';

  if function_record.proowner <> migration_role_oid
     or function_record.owner_name <> 'avuhz_data_migration_service_dev'
     or function_record.prosecdef
     or function_record.provolatile <> 'v'
     or function_record.proleakproof
     or function_record.prorettype <> 'pg_catalog.trigger'::regtype
     or function_record.lanname <> 'plpgsql'
     or position('invalid outbox delivery transition' in function_record.prosrc) = 0
     or position('outbox attempt history cannot be rewritten' in function_record.prosrc) = 0
     or position('jsonb_array_length' in function_record.prosrc) = 0 then
    raise exception 'Avuhz DEVELOPMENT DATA outbox function changed outside search_path';
  end if;

  if function_record.proconfig is null
     or cardinality(function_record.proconfig) <> 1
     or not exists (
       select 1
         from unnest(function_record.proconfig) setting
        where setting in ('search_path=', 'search_path=""')
     ) then
    raise exception 'Avuhz DEVELOPMENT DATA outbox function search_path was not pinned empty';
  end if;

  select count(*),
         count(*) filter (
           where function_acl.grantee = function_record.proowner
             and function_acl.grantor = function_record.proowner
             and function_acl.privilege_type = 'EXECUTE'
             and not function_acl.is_grantable
         )
    into function_acl_count, owner_execute_acl_count
    from aclexplode(coalesce(function_record.proacl, acldefault('f', function_record.proowner))) function_acl;

  if function_acl_count <> 1 or owner_execute_acl_count <> 1 then
    raise exception 'Avuhz DEVELOPMENT DATA outbox function ACL changed during repair';
  end if;

  select count(*) into trigger_count
    from pg_trigger trigger
    join pg_class relation on relation.oid = trigger.tgrelid
    join pg_namespace namespace on namespace.oid = relation.relnamespace
   where not trigger.tgisinternal
     and trigger.tgfoid = function_record.oid
     and trigger.tgname = 'avuhz_guard_outbox_transition'
     and namespace.nspname = 'public'
     and relation.relname = 'avuhz_outbox_deliveries'
     and trigger.tgtype = 19
     and trigger.tgenabled = 'O';

  select count(*) into function_trigger_count
    from pg_trigger trigger
   where not trigger.tgisinternal
     and trigger.tgfoid = function_record.oid;

  if trigger_count <> 1 or function_trigger_count <> 1 then
    raise exception 'Avuhz DEVELOPMENT DATA outbox trigger changed during repair';
  end if;

  if (
    select count(*)
      from pg_class relation
      join pg_namespace namespace on namespace.oid = relation.relnamespace
     where namespace.nspname = 'public'
       and relation.relkind in ('r', 'p')
       and relation.relname like 'avuhz\_%' escape '\'
  ) <> 16
     or (
       select count(*)
         from pg_class relation
         join pg_namespace namespace on namespace.oid = relation.relnamespace
        where namespace.nspname = 'public'
          and relation.relkind in ('r', 'p')
          and relation.relname like 'avuhz\_%' escape '\'
          and relation.relrowsecurity
     ) <> 16
     or (
       select count(*)
         from pg_policy policy
         join pg_class relation on relation.oid = policy.polrelid
         join pg_namespace namespace on namespace.oid = relation.relnamespace
        where namespace.nspname = 'public'
          and relation.relname like 'avuhz\_%' escape '\'
          and policy.polname = 'avuhz_command_service_tenant_isolation'
     ) <> 16 then
    raise exception 'Avuhz DEVELOPMENT DATA outbox search_path repair changed tenant surface';
  end if;

  if exists (
    select 1
      from information_schema.role_table_grants grants
     where grants.table_schema = 'public'
       and grants.table_name like 'avuhz\_%' escape '\'
       and grants.grantee in ('PUBLIC', 'anon', 'authenticated', 'service_role')
  ) then
    raise exception 'Avuhz DEVELOPMENT DATA outbox search_path repair exposed table grants';
  end if;

  if not has_schema_privilege('avuhz_command_service', 'public', 'USAGE')
     or has_schema_privilege('avuhz_command_service', 'public', 'CREATE') then
    raise exception 'Avuhz DEVELOPMENT DATA command-service schema privilege changed during repair';
  end if;
end
$avuhz_development_data_outbox_search_path_repair_v1_postcondition$;

commit;
