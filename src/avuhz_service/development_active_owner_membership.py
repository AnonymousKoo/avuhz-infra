"""Dormant DEVELOPMENT-only read of an existing, independently verified owner.

The *existing* AUTH checkpoint and MFA/session checker must establish that
the bearer belongs to a current AAL2 human. Then only the two already-
existing DATA tenant-scoped tables may establish whether the exact digest
is an ACTIVE, verified OWNER of an ACTIVE organization.

This boolean is NOT a TrustedExecutionContext, an opaque principal mapping,
a business-owner directory result, a hosted route, or Work Item authorization.
In particular, do not derive the Work Item principal reference from the
pseudonymous digest or from an n8n receipt. No provider calls on import.
"""
from __future__ import annotations

import re
import uuid

from avuhz_runtime.guards import TrustedExecutionContext
from avuhz_runtime.postgres import PostgresUnitOfWork
from .development_owner_authentication import (
    DevelopmentOwnerAuthenticationCheckpoint, ProvisionalOwnerAuthentication,
)
from .development_owner_mfa_freshness import DevelopmentOwnerMfaFreshnessCheck


def _uuid(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        return str(uuid.UUID(value)) == value
    except (ValueError, TypeError, AttributeError):
        return False


# The same *already-applied* tenant RLS must exist on both existing tables.
# The corresponding minimal column ACL sources are in PRs #704 and #705.
# Both grants are still independently gated for hosted DEVELOPMENT DATA.
_POLICY = (
    "(tenant_id = (NULLIF(current_setting('avuhz.tenant_id'::text, true), "
    "''::text))::uuid)"
)
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$", re.ASCII)
_BOUNDARY = """
SELECT
 current_user='avuhz_command_service'
 AND current_setting('row_security')='on'
 AND EXISTS (SELECT 1 FROM pg_roles r WHERE r.rolname=current_user
   AND NOT r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolbypassrls
   AND NOT r.rolinherit AND NOT r.rolcreatedb AND NOT r.rolcreaterole
   AND NOT r.rolreplication)
 AND NOT EXISTS (SELECT 1 FROM pg_auth_members m JOIN pg_roles r
   ON r.oid=m.member WHERE r.rolname=current_user)
 AND (
   SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname='public'
     AND c.relname IN ('avuhz_tenant_organizations',
                       'avuhz_tenant_owner_memberships')
     AND c.relkind='r' AND c.relrowsecurity AND c.relforcerowsecurity
     AND c.relowner<>(SELECT oid FROM pg_roles WHERE rolname=current_user)
 )=2
 AND (
   SELECT count(*) FROM pg_policies p
   WHERE p.schemaname='public'
   AND p.tablename IN ('avuhz_tenant_organizations',
                       'avuhz_tenant_owner_memberships')
 )=6
 AND (
   SELECT count(*) FROM pg_policies p
   WHERE p.schemaname='public'
   AND p.tablename IN ('avuhz_tenant_organizations',
                       'avuhz_tenant_owner_memberships')
     AND p.policyname='avuhz_command_service_tenant_isolation'
     AND p.roles=ARRAY['avuhz_command_service']::name[]
     AND p.cmd='ALL' AND p.permissive='PERMISSIVE'
     AND p.qual=%s AND p.with_check=%s
 )=2
 AND NOT EXISTS (
   SELECT 1 FROM pg_policies p
   WHERE p.schemaname='public'
     AND p.tablename IN ('avuhz_tenant_organizations',
                         'avuhz_tenant_owner_memberships')
     AND p.policyname<>'avuhz_command_service_tenant_isolation'
     AND p.roles && ARRAY['avuhz_command_service','public']::name[]
 )
 AND NOT EXISTS (
   SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname='public'
     AND c.relname IN ('avuhz_tenant_organizations',
                       'avuhz_tenant_owner_memberships')
     AND (has_table_privilege(current_user,c.oid,'SELECT')
       OR has_table_privilege(current_user,c.oid,'INSERT')
       OR has_table_privilege(current_user,c.oid,'UPDATE')
       OR has_table_privilege(current_user,c.oid,'DELETE')
       OR has_any_column_privilege('anon',c.oid,'SELECT')
       OR has_any_column_privilege('authenticated',c.oid,'SELECT'))
 )
 AND (
   SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    JOIN pg_attribute a ON a.attrelid=c.oid
    CROSS JOIN LATERAL aclexplode(a.attacl) acl
   WHERE n.nspname='public' AND a.attnum>0 AND NOT a.attisdropped
     AND c.relname='avuhz_tenant_organizations'
     AND acl.grantee=(SELECT oid FROM pg_roles WHERE rolname=current_user)
     AND acl.privilege_type='SELECT' AND NOT acl.is_grantable
     AND a.attname IN ('tenant_id','organization_id','lifecycle_state')
 )=3
 AND (
   SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    JOIN pg_attribute a ON a.attrelid=c.oid
    CROSS JOIN LATERAL aclexplode(a.attacl) acl
   WHERE n.nspname='public' AND a.attnum>0 AND NOT a.attisdropped
     AND c.relname='avuhz_tenant_owner_memberships'
     AND acl.grantee=(SELECT oid FROM pg_roles WHERE rolname=current_user)
     AND acl.privilege_type='SELECT' AND NOT acl.is_grantable
     AND a.attname IN ('tenant_id','organization_id','principal_subject_digest',
                        'member_role','membership_state','verified_at')
 )=6
 AND (
   SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    JOIN pg_attribute a ON a.attrelid=c.oid
    CROSS JOIN LATERAL aclexplode(a.attacl) acl
   WHERE n.nspname='public' AND a.attnum>0 AND NOT a.attisdropped
     AND c.relname IN ('avuhz_tenant_organizations',
                       'avuhz_tenant_owner_memberships')
     AND acl.grantee=(SELECT oid FROM pg_roles WHERE rolname=current_user)
 )=9
 AS bounded
"""

_LOOKUP = """
SELECT true AS member_verified
FROM public.avuhz_tenant_organizations AS org
JOIN public.avuhz_tenant_owner_memberships AS member
  ON member.tenant_id=org.tenant_id
 AND member.organization_id=org.organization_id
WHERE org.tenant_id=%s AND org.organization_id=%s
  AND org.lifecycle_state='ACTIVE'
  AND member.principal_subject_digest=%s
  AND member.member_role='OWNER'
  AND member.membership_state='ACTIVE'
  AND member.verified_at IS NOT NULL
"""


class DevelopmentActiveOwnerMembershipCheck:
    """Read-only member evidence, never a business ownership attestation.

    Exactly these trusted components must be supplied by server-owned
    composition, not a request or n8n event. A synthetic token/MFA stub
    may prove local mechanics but MUST NEVER be mounted as hosted auth.
    """

    def __init__(self, store, auth_checkpoint, mfa_check):
        if (store is None
            or not callable(getattr(store, "connection_factory", None))
            or type(auth_checkpoint) is not DevelopmentOwnerAuthenticationCheckpoint
            or type(mfa_check) is not DevelopmentOwnerMfaFreshnessCheck):
            raise ValueError("trusted owner membership dependencies required")
        self._store = store
        self._auth = auth_checkpoint
        self._mfa = mfa_check

    def __call__(
        self, untrusted_bearer: object, tenant_id: object, organization_id: object
    ) -> bool:
        # IDs are selectors. They cannot establish owner identity or scope.
        if not _uuid(tenant_id) or not _uuid(organization_id):
            return False
        uow = None
        try:
            provisional = self._auth.inspect(untrusted_bearer)
            if (type(provisional) is not ProvisionalOwnerAuthentication
                or provisional.environment != "DEVELOPMENT"
                or provisional.auth_project_verified is not True
                or provisional.aal2_token_verified is not True
                or provisional.registration_authorized is not False
                or type(provisional.subject_digest) is not str
                or not _DIGEST.fullmatch(provisional.subject_digest)):
                return False
            if self._mfa(untrusted_bearer, provisional.subject_digest) is not True:
                return False

            # INTERNAL_SERVICE is *only* an RLS selector; it has no authority
            # to create work, enroll an owner, or activate a company.
            scoped = TrustedExecutionContext(
                authenticated=True, principal_id="service.owner-membership-check",
                caller_type="INTERNAL_SERVICE", tenant_id=tenant_id,
                organization_id=organization_id, capabilities=frozenset(),
                authority_roles=frozenset(), environment="DEVELOPMENT",
                audience="avuhz-command-api", authentication_strength="STRONG",
                step_up_satisfied=False, authenticated_at=None,
            )
            uow = PostgresUnitOfWork(self._store, trusted_context=scoped)
            conn = uow.connection
            role = conn.execute(_BOUNDARY, (_POLICY, _POLICY)).fetchone()
            if role is None or role["bounded"] is not True:
                return False
            row = conn.execute(
                _LOOKUP, (tenant_id, organization_id, provisional.subject_digest)
            ).fetchone()
            return row is not None and row["member_verified"] is True
        except Exception:
            # Never log or expose JWT, digest, person, business or SQL errors.
            return False
        finally:
            if uow is not None:
                try:
                    uow.rollback()
                except Exception:
                    pass
                try:
                    uow.close()
                except Exception:
                    pass
