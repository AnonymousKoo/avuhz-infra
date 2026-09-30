begin;

do $preflight$
declare
  migration_oid oid;
  command_oid oid;
  postgres_oid oid;
begin
  if current_user <> 'postgres' or session_user <> 'postgres' then
    raise exception 'Avuhz DEVELOPMENT DATA owner identity mismatch';
  end if;
  if current_setting('avuhz.runtime_login_password', true) is null
     or length(current_setting('avuhz.runtime_login_password', true)) < 32 then
    raise exception 'Avuhz DEVELOPMENT DATA runtime login password handoff missing';
  end if;
  if exists (select 1 from pg_roles where rolname='avuhz_data_runtime_service_dev') then
    raise exception 'Avuhz DEVELOPMENT DATA runtime login already exists';
  end if;

  select oid into strict postgres_oid from pg_roles
   where rolname='postgres' and not rolsuper and rolcreaterole;
  select oid into strict migration_oid from pg_roles
   where rolname='avuhz_data_migration_service_dev'
     and not rolcanlogin and not rolsuper and not rolinherit and not rolcreatedb
     and not rolcreaterole and not rolreplication and not rolbypassrls;
  select oid into strict command_oid from pg_roles
   where rolname='avuhz_command_service'
     and not rolcanlogin and not rolsuper and not rolinherit and not rolcreatedb
     and not rolcreaterole and not rolreplication and not rolbypassrls;

  if (select count(*) from pg_auth_members m join pg_roles g on g.oid=m.grantor
      where m.roleid=migration_oid and m.member=postgres_oid
        and m.admin_option and not m.inherit_option and not m.set_option
        and g.rolsuper and g.oid<>postgres_oid) <> 1
     or (select count(*) from pg_auth_members m
         where m.roleid=migration_oid and m.member=postgres_oid
           and m.grantor=postgres_oid) <> 0
     or (select count(*) from pg_auth_members m join pg_roles g on g.oid=m.grantor
         where m.roleid=command_oid and m.member=migration_oid
           and m.admin_option and not m.inherit_option and not m.set_option
           and g.rolsuper and g.oid<>migration_oid) <> 1
     or not pg_has_role('postgres','avuhz_data_migration_service_dev','MEMBER WITH ADMIN OPTION')
     or pg_has_role('postgres','avuhz_data_migration_service_dev','SET')
     or not pg_has_role('avuhz_data_migration_service_dev','avuhz_command_service','MEMBER WITH ADMIN OPTION')
     or pg_has_role('avuhz_data_migration_service_dev','avuhz_command_service','SET') then
    raise exception 'Avuhz DEVELOPMENT DATA sealed role envelope mismatch';
  end if;
end
$preflight$;

do $create_runtime$
declare
  runtime_password text := current_setting('avuhz.runtime_login_password', true);
begin
  execute format(
    'create role avuhz_data_runtime_service_dev login password %L nosuperuser nocreatedb nocreaterole noinherit noreplication nobypassrls',
    runtime_password
  );
end
$create_runtime$;

grant avuhz_data_migration_service_dev to postgres
  with admin false, inherit false, set true;

do $temporary_set_edge$
declare
  migration_oid oid;
  postgres_oid oid;
begin
  select oid into strict postgres_oid from pg_roles where rolname='postgres';
  select oid into strict migration_oid from pg_roles where rolname='avuhz_data_migration_service_dev';

  if (select count(*) from pg_auth_members m
      where m.roleid=migration_oid and m.member=postgres_oid
        and m.grantor=postgres_oid and not m.admin_option
        and not m.inherit_option and m.set_option) <> 1
     or not pg_has_role('postgres','avuhz_data_migration_service_dev','SET') then
    raise exception 'Avuhz DEVELOPMENT DATA temporary migration SET edge mismatch';
  end if;
end
$temporary_set_edge$;

grant avuhz_command_service to avuhz_data_runtime_service_dev
  with admin false, inherit false, set true
  granted by avuhz_data_migration_service_dev;

revoke avuhz_data_migration_service_dev from postgres
  granted by postgres;

do $postcondition$
declare
  migration_oid oid;
  command_oid oid;
  runtime_oid oid;
  postgres_oid oid;
begin
  select oid into strict postgres_oid from pg_roles where rolname='postgres';
  select oid into strict migration_oid from pg_roles where rolname='avuhz_data_migration_service_dev';
  select oid into strict command_oid from pg_roles where rolname='avuhz_command_service';
  select oid into strict runtime_oid from pg_roles
   where rolname='avuhz_data_runtime_service_dev'
     and rolcanlogin and not rolsuper and not rolinherit and not rolcreatedb
     and not rolcreaterole and not rolreplication and not rolbypassrls;

  if (select count(*) from pg_auth_members m join pg_roles g on g.oid=m.grantor
      where m.roleid=migration_oid and m.member=postgres_oid
        and m.admin_option and not m.inherit_option and not m.set_option
        and g.rolsuper and g.oid<>postgres_oid) <> 1
     or (select count(*) from pg_auth_members m
         where m.roleid=migration_oid and m.member=postgres_oid
           and m.grantor=postgres_oid) <> 0
     or pg_has_role('postgres','avuhz_data_migration_service_dev','SET')
     or (select count(*) from pg_auth_members m join pg_roles g on g.oid=m.grantor
         where m.roleid=command_oid and m.member=migration_oid
           and m.admin_option and not m.inherit_option and not m.set_option
           and g.rolsuper and g.oid<>migration_oid) <> 1
     or (select count(*) from pg_auth_members m
         where m.roleid=command_oid and m.member=runtime_oid
           and m.grantor=migration_oid and not m.admin_option
           and not m.inherit_option and m.set_option) <> 1
     or (select count(*) from pg_auth_members m join pg_roles g on g.oid=m.grantor
         where m.roleid=runtime_oid and m.member=postgres_oid
           and m.admin_option and not m.inherit_option and not m.set_option
           and g.rolsuper and g.oid<>postgres_oid) <> 1
     or (select count(*) from information_schema.role_table_grants g
         where g.grantee='avuhz_data_runtime_service_dev') <> 0 then
    raise exception 'Avuhz DEVELOPMENT DATA runtime login postcondition mismatch';
  end if;
end
$postcondition$;

commit;
