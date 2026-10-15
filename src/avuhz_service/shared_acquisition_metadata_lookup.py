"""Fail-closed shared acquisition metadata read inside Avuhz's existing UoW.

DEVELOPMENT source candidate only: no hosted registration, n8n execution,
credential, customer enrollment, new storage or authorization shortcut.
The five allowed DATA columns cannot establish a work owner, deadline,
source, classification, or organization membership. A receipt is not authority.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Callable

from avuhz_runtime.guards import TrustedExecutionContext
from avuhz_runtime.postgres import PostgresUnitOfWork
from .shared_work_intake_candidate import _fresh, _opaque


class AcquisitionMetadataDenied(PermissionError):
    """One safe response for missing, unauthorized, or unavailable records."""


@dataclass(frozen=True, slots=True)
class VerifiedAcquisitionMetadata:
    tenant_id: str
    intake_id: str
    organization_id: str
    intake_state: str
    record_version: int


def _uuid(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        return str(uuid.UUID(value)) == value
    except (ValueError, TypeError, AttributeError):
        return False


# Exact authorized column shape from the already-applied DEVELOPMENT DATA ACL.
# This role check runs in the same tenant-bound transaction as the read.
_BOUNDARY = """
select (
 current_user='avuhz_command_service'
 and current_setting('row_security')='on'
 and exists (select 1 from pg_roles r where r.rolname=current_user
   and not r.rolcanlogin and not r.rolsuper and not r.rolbypassrls
   and not r.rolinherit and not r.rolcreatedb and not r.rolcreaterole
   and not r.rolreplication)
 and not exists (select 1 from pg_auth_members m join pg_roles r
   on r.oid=m.member where r.rolname=current_user)
 and exists (select 1 from pg_class c join pg_namespace n on n.oid=c.relnamespace
   where n.nspname='public' and c.relname='avuhz_acquisition_intake_requests'
   and c.relkind='r' and c.relrowsecurity and c.relforcerowsecurity
   and c.relowner<>(select oid from pg_roles where rolname=current_user))
 and (select count(*) from pg_policies p where p.schemaname='public'
   and p.tablename='avuhz_acquisition_intake_requests'
   and p.policyname='avuhz_command_service_tenant_isolation'
   and p.roles=ARRAY['avuhz_command_service']::name[]
   and p.cmd='ALL' and p.permissive='PERMISSIVE'
   and p.qual='(tenant_id = (NULLIF(current_setting(''avuhz.tenant_id''::text, true), ''''::text))::uuid)'
   and p.with_check='(tenant_id = (NULLIF(current_setting(''avuhz.tenant_id''::text, true), ''''::text))::uuid)')=1
 and not exists (select 1 from pg_policies p where p.schemaname='public'
   and p.tablename='avuhz_acquisition_intake_requests'
   and p.policyname<>'avuhz_command_service_tenant_isolation'
   and p.roles && ARRAY['avuhz_command_service','public']::name[])
 and not has_table_privilege(current_user,'public.avuhz_acquisition_intake_requests','SELECT')
 and not has_table_privilege(current_user,'public.avuhz_acquisition_intake_requests','INSERT')
 and not has_table_privilege(current_user,'public.avuhz_acquisition_intake_requests','UPDATE')
 and not has_table_privilege(current_user,'public.avuhz_acquisition_intake_requests','DELETE')
 and (select count(*) from pg_attribute a
   cross join lateral aclexplode(a.attacl) acl
   where a.attrelid='public.avuhz_acquisition_intake_requests'::regclass
     and a.attnum>0 and not a.attisdropped
     and acl.grantee=(select oid from pg_roles where rolname=current_user)
     and a.attname in ('intake_id','tenant_id','organization_id','intake_state','record_version')
     and acl.privilege_type='SELECT' and not acl.is_grantable)=5
 and (select count(*) from pg_attribute a
   cross join lateral aclexplode(a.attacl) acl
   where a.attrelid='public.avuhz_acquisition_intake_requests'::regclass
     and a.attnum>0 and not a.attisdropped
     and acl.grantee=(select oid from pg_roles where rolname=current_user))=5
 and not has_any_column_privilege('anon','public.avuhz_acquisition_intake_requests','SELECT')
 and not has_any_column_privilege('authenticated','public.avuhz_acquisition_intake_requests','SELECT')
 and not has_column_privilege('avuhz_acquisition_service_dev',
     'public.avuhz_acquisition_intake_requests','intake_state','SELECT')
) as bounded
"""

_READ = """select intake_id,tenant_id,organization_id,intake_state,record_version
 from public.avuhz_acquisition_intake_requests
 where tenant_id=%s and intake_id=%s"""


class SharedAcquisitionMetadataLookup:
    """Read only authorized metadata; never derive a work assignment from it.

    `resolve_identity` must be a server-controlled authenticated HUMAN resolver,
    not a callback trusting browser/event/n8n claims. `resolve_tenant_member`
    must independently consult live tenant authority in the same UoW. No
    production or hosted route may mount a synthetic resolver.
    """

    def __init__(
        self, store, *,
        resolve_identity: Callable[[object], TrustedExecutionContext],
        resolve_tenant_member: Callable[[object, str, str], str | None],
    ) -> None:
        if (store is None or not callable(getattr(store, 'connection_factory', None))
                or not callable(resolve_identity) or not callable(resolve_tenant_member)):
            raise ValueError('trusted acquisition lookup dependencies required')
        self._store = store
        self._identity = resolve_identity
        self._member = resolve_tenant_member

    def lookup(self, identity_evidence: object, intake_id: object) -> VerifiedAcquisitionMetadata:
        """Fetch one trusted-tenant row only, never a caller-selected tenant."""
        if (not _uuid(intake_id) or type(identity_evidence) is TrustedExecutionContext):
            raise AcquisitionMetadataDenied('acquisition metadata unavailable')
        uow = None
        try:
            context = self._identity(identity_evidence)
            if (type(context) is not TrustedExecutionContext
                    or context.authenticated is not True
                    or context.caller_type != 'HUMAN'
                    or context.environment != 'DEVELOPMENT'
                    or context.audience != 'avuhz-command-api'
                    or context.authentication_strength != 'STRONG'
                    or not _uuid(context.tenant_id)
                    or not _uuid(context.organization_id)
                    or not _opaque(context.principal_id)
                    or type(context.capabilities) is not frozenset
                    or 'work_intake:create' not in context.capabilities
                    or type(context.authority_roles) is not frozenset
                    or context.authority_roles
                    or not _fresh(context)):
                raise AcquisitionMetadataDenied('acquisition metadata unavailable')
            uow = PostgresUnitOfWork(self._store, trusted_context=context)
            conn = uow.connection
            role = conn.execute(_BOUNDARY).fetchone()
            if role is None or role['bounded'] is not True:
                raise AcquisitionMetadataDenied('acquisition metadata unavailable')
            member = self._member(conn, context.tenant_id, context.principal_id)
            if member != context.principal_id:
                raise AcquisitionMetadataDenied('acquisition metadata unavailable')
            row = conn.execute(_READ, (context.tenant_id, intake_id)).fetchone()
            if row is None or row['intake_state'] != 'RECEIVED':
                raise AcquisitionMetadataDenied('acquisition metadata unavailable')
            tenant = str(row['tenant_id'])
            organization = str(row['organization_id'])
            actual_intake = str(row['intake_id'])
            version = row['record_version']
            if (tenant != context.tenant_id or actual_intake != intake_id
                    or not _uuid(organization)
                    or context.organization_id != organization
                    or type(version) is not int or version < 1):
                raise AcquisitionMetadataDenied('acquisition metadata unavailable')
            return VerifiedAcquisitionMetadata(tenant, actual_intake, organization, 'RECEIVED', version)
        except Exception:
            # Do not leak SQL, identity, scope, PII, or whether the row exists.
            raise AcquisitionMetadataDenied('acquisition metadata unavailable') from None
        finally:
            if uow is not None:
                # This is a read-only UnitOfWork. Close even when the
                # database is unavailable during rollback, and never leak
                # driver diagnostics to the caller.
                try:
                    uow.rollback()
                except Exception:
                    pass
                try:
                    uow.close()
                except Exception:
                    pass
