"""Commit-transaction acquisition admission for the existing shared writer.

LOCAL/TEST source only. A previously verified acquisition snapshot is only a
selector. Re-read the exact RECEIVE record from the SAME tenant-bound UoW as
the Work Item insert and outbox commit, rather than trusting PR #707's earlier
separate read. No acquisition PII, UPDATE privilege, schema or auth changes.

NOTE: This guards committed state at each transaction-local read. It is NOT
a row lock or a serializable guarantee against an *independent privileged*
intake version/state mutation. Current shared acquisition code is insert-only
and runtime roles cannot UPDATE intake_state. Any future state/version mutator
must join the same advisory-lock protocol, or a separately reviewed
narrow-purpose lock service must be implemented before hosted deployment.
"""
from __future__ import annotations

from avuhz_runtime.guards import TrustedExecutionContext
from .shared_acquisition_metadata_lookup import (
    VerifiedAcquisitionMetadata, _BOUNDARY as _ACQUISITION_BOUNDARY,
    _READ as _ACQUISITION_READ, _uuid,
)
from .shared_work_intake_candidate import WorkIntakeCommand, WorkIntakeDenied

_SAFE_DENIED = "work intake authority denied"

# The restricted acquisition runtime has a narrow UPDATE(record_version) ACL
# for its existing registry. Reject unforeseen UPDATE to identity/state columns
# and DELETE. Do NOT remove or widen existing permissions in this source PR.
_WRITE_BOUNDARY = """
select
 not has_column_privilege('avuhz_acquisition_service_dev',
 'public.avuhz_acquisition_intake_requests','intake_state','UPDATE')
 and not has_column_privilege('avuhz_acquisition_service_dev',
 'public.avuhz_acquisition_intake_requests','tenant_id','UPDATE')
 and not has_column_privilege('avuhz_acquisition_service_dev',
 'public.avuhz_acquisition_intake_requests','organization_id','UPDATE')
 and not has_column_privilege('avuhz_acquisition_service_dev',
 'public.avuhz_acquisition_intake_requests','intake_id','UPDATE')
 and not has_table_privilege('avuhz_acquisition_service_dev',
 'public.avuhz_acquisition_intake_requests','DELETE')
 and not has_any_column_privilege('avuhz_command_service',
 'public.avuhz_acquisition_intake_requests','UPDATE')
 and not has_table_privilege('avuhz_command_service',
 'public.avuhz_acquisition_intake_requests','DELETE') as bounded
"""


def require_transaction_acquisition_admission(
    connection: object,
    context: TrustedExecutionContext,
    command: WorkIntakeCommand,
    expected: VerifiedAcquisitionMetadata,
) -> None:
    """Fail closed *within the writer's own UoW*, without row lock grants.

    The caller must first take the existing per-tenant work item advisory lock.
    This method never opens/commits its own transaction and must be repeated
    just before the shared UoW commit (after all work/outbox writes).
    """
    try:
        if (
            type(context) is not TrustedExecutionContext
            or type(expected) is not VerifiedAcquisitionMetadata
            or type(command) is not WorkIntakeCommand
            or command.kind != "OPEN"
            or command.work_item_id != expected.intake_id
            or expected.intake_state != "RECEIVED"
            or context.tenant_id != expected.tenant_id
            or context.organization_id != expected.organization_id
            or not _uuid(expected.intake_id)
            or not _uuid(expected.tenant_id)
            or not _uuid(expected.organization_id)
            or type(expected.record_version) is not int
            or expected.record_version < 1
        ):
            raise PermissionError
        boundary = connection.execute(_ACQUISITION_BOUNDARY).fetchone()
        if boundary is None or boundary["bounded"] is not True:
            raise PermissionError
        role = connection.execute(_WRITE_BOUNDARY).fetchone()
        if role is None or role["bounded"] is not True:
            raise PermissionError
        row = connection.execute(
            _ACQUISITION_READ, (expected.tenant_id, expected.intake_id)
        ).fetchone()
        if (
            row is None
            or str(row["tenant_id"]) != expected.tenant_id
            or str(row["organization_id"]) != expected.organization_id
            or str(row["intake_id"]) != expected.intake_id
            or row["intake_state"] != "RECEIVED"
            or type(row["record_version"]) is not int
            or row["record_version"] != expected.record_version
        ):
            raise PermissionError
    except Exception:
        # Same safe response for missing, drifted, revoked and inaccessible.
        # Never log or echo DB exceptions, PII, identity claims or receipts.
        raise WorkIntakeDenied(_SAFE_DENIED) from None
