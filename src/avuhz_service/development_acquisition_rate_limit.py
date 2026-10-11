"""Dormant shared PostgreSQL admission for DEVELOPMENT acquisition intake.

A future authorized Avuhz command-service caller can inject this callable as
the existing ReceiveAcquisitionIntakeCandidate rate_limit_admit callback.
Only that caller's previously authenticated tenant/principal is valid input.

This is NOT a migration, RLS policy, role grant, hosted service binding,
provider operation, or public endpoint. The dedicated
public.avuhz_acquisition_rate_limit_counters table DOES NOT yet exist.
Do not enable until its separately approved DEVELOPMENT DATA migration has
FORCED tenant RLS, restricted column-level INSERT/UPDATE/SELECT, proven
cross-tenant denial, and an approved retention/pruning job. There must be
no use of service_role, DDL or BYPASSRLS in an application runtime.

A single atomic PostgreSQL UPSERT serializes admission for the same
tenant/service-principal across hosts/workers. It uses the DATABASE clock and
a stable opaque tenant/principal digest, never client request IDs or IP data.
This controls the authenticated website service's shared request volume;
edge abuse limits for individual unauthenticated site visitors are separate
and required before a public launch.
"""
from __future__ import annotations

import hashlib
import re
import uuid
from collections.abc import Mapping

_TABLE = "public.avuhz_acquisition_rate_limit_counters"
_WINDOW_SECONDS = 300
_MAX_REQUESTS = 10
_SERVICE_PRINCIPAL = re.compile(r"[a-z][a-z0-9._:-]{1,127}", re.ASCII)

# The one database statement is atomic under PostgreSQL's unique-key conflict
# serialization. EXCLUDED.window_started_at is evaluated once by tick, so
# rollover, insertion and quota decisions share the same database timestamp.
# Expected table key is PRIMARY KEY (tenant_id, principal_digest).
_ATOMIC_ADMISSION_SQL = """
with tick as (select clock_timestamp() as checked_at)
insert into public.avuhz_acquisition_rate_limit_counters
  (tenant_id, principal_digest, window_started_at, request_count)
select %s, %s, tick.checked_at, 1 from tick where true
on conflict (tenant_id, principal_digest)
do update set
  window_started_at = case
    when public.avuhz_acquisition_rate_limit_counters.window_started_at
         <= excluded.window_started_at - interval '300 seconds'
    then excluded.window_started_at
    else public.avuhz_acquisition_rate_limit_counters.window_started_at
  end,
  request_count = case
    when public.avuhz_acquisition_rate_limit_counters.window_started_at
         <= excluded.window_started_at - interval '300 seconds'
    then 1
    else public.avuhz_acquisition_rate_limit_counters.request_count + 1
  end
where public.avuhz_acquisition_rate_limit_counters.window_started_at
      <= excluded.window_started_at - interval '300 seconds'
   or public.avuhz_acquisition_rate_limit_counters.request_count < 10
returning request_count
"""


def _canonical_tenant(raw: object) -> str | None:
    if type(raw) is not str:
        return None
    try:
        return raw if str(uuid.UUID(raw)) == raw else None
    except (ValueError, TypeError, AttributeError):
        return None


class DevelopmentPostgresAcquisitionRateLimiter:
    """Persistent, database-clock, fixed-window admission across instances.

    Inject this only into the shared Avuhz authenticated writer; it is not an
    HTTP, browser, or general purpose client-callable authorization function.
    The writer MUST authenticate the server and validate its tenant and
    principal before invoking this rate limiter.

    The store must supply the existing bounded PostgreSQL runtime connection
    factory. The dedicated rate table requires separately reviewed RLS and
    least-privileged grants. Missing table/grant/connection FAILS CLOSED.
    """

    def __init__(self, store: object) -> None:
        if store is None or not callable(getattr(store, "connection_factory", None)):
            raise ValueError("approved shared DATA store is required")
        self._store = store

    def __call__(self, tenant_id: str, principal_id: str) -> bool:
        tenant = _canonical_tenant(tenant_id)
        if (
            tenant is None
            or type(principal_id) is not str
            or _SERVICE_PRINCIPAL.fullmatch(principal_id) is None
        ):
            return False

        # The hash is an opaque service-counter label, not a password or
        # user identifier. Include tenant to prevent cross-tenant linkage.
        digest = hashlib.sha256(
            (tenant + "\x00" + principal_id).encode("ascii")
        ).hexdigest()

        connection = None
        committed = False
        try:
            connection = self._store.connection_factory()
            if connection.autocommit:
                connection.autocommit = False
            # The writer has already verified this tenant. This local GUC
            # scopes dedicated counter-table RLS for this transaction only.
            connection.execute(
                "select set_config('avuhz.tenant_id',%s,true)", (tenant,),
            )
            admitted = connection.execute(
                _ATOMIC_ADMISSION_SQL, (tenant, digest),
            ).fetchone()
            if (
                not isinstance(admitted, Mapping)
                or type(admitted.get("request_count")) is not int
                or not 1 <= admitted["request_count"] <= _MAX_REQUESTS
            ):
                return False
            connection.commit()
            committed = True
            return True
        except Exception:
            # No SQL details, DSN, tenant, token or PII may escape. This
            # method returns only a Boolean and the shared writer maps any
            # denial to its existing sanitized authorization response.
            return False
        finally:
            if connection is not None:
                if not committed:
                    try:
                        connection.rollback()
                    except Exception:
                        pass
                try:
                    connection.close()
                except Exception:
                    pass
