"""PostgreSQL repository for frozen ImplementationBrief history."""
from __future__ import annotations

import copy
import json


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _record(row):
    if not row:
        return None
    value = row["record"]
    return copy.deepcopy(json.loads(value) if isinstance(value, str) else value)


class ImplementationBriefPostgresRepository:
    def __init__(self, uow):
        self.uow = uow

    def get_version(self, tenant_id, brief_id, brief_version):
        return _record(self.uow.connection.execute(
            "select record from public.avuhz_implementation_briefs "
            "where tenant_id=%s and implementation_brief_id=%s and implementation_brief_version=%s",
            (tenant_id, brief_id, brief_version),
        ).fetchone())

    def list_versions(self, tenant_id, brief_id):
        rows = self.uow.connection.execute(
            "select record from public.avuhz_implementation_briefs "
            "where tenant_id=%s and implementation_brief_id=%s order by implementation_brief_version",
            (tenant_id, brief_id),
        ).fetchall()
        return tuple(_record(row) for row in rows)

    def get_current(self, tenant_id, brief_id):
        return _record(self.uow.connection.execute(
            "select record from public.avuhz_implementation_briefs "
            "where tenant_id=%s and implementation_brief_id=%s and state<>'SUPERSEDED' "
            "order by implementation_brief_version desc limit 1",
            (tenant_id, brief_id),
        ).fetchone())

    def _insert(self, record):
        assessment = record["source_oia_assessment_reference"]
        delivery = record["source_findings_delivery_reference"]
        conversion = record["source_conversion_decision_reference"]
        agreement = record["source_ongoing_agreement_reference"]
        payment = record["source_ongoing_payment_reference"]
        access = record["source_ongoing_access_reference"]
        cur = self.uow.connection.execute(
            "insert into public.avuhz_implementation_briefs "
            "(tenant_id,implementation_brief_id,implementation_brief_version,engagement_id,"
            "oia_assessment_id,oia_assessment_record_version,oia_findings_delivery_id,delivery_sequence,"
            "oia_conversion_decision_id,decision_version,ongoing_agreement_authority_id,agreement_version,"
            "ongoing_payment_verification_id,payment_record_version,ongoing_access_grant_id,access_record_version,"
            "source_truth_digest,implementation_brief_digest,state,record_version,record,created_at,updated_at) "
            "values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s) "
            "on conflict do nothing returning implementation_brief_id",
            (
                record["tenant_id"], record["implementation_brief_id"], record["implementation_brief_version"],
                record["engagement_id"], assessment["reference_id"], assessment["reference_version"],
                delivery["reference_id"], delivery["reference_version"], conversion["reference_id"],
                conversion["reference_version"], agreement["reference_id"], agreement["reference_version"],
                payment["reference_id"], payment["reference_version"], access["reference_id"],
                access["reference_version"], record["source_truth_digest"], record["implementation_brief_digest"],
                record["state"], record["record_version"], _json(record), record["created_at"], record["updated_at"],
            ),
        )
        if not cur.fetchone():
            raise ValueError("ImplementationBrief identity/version conflict")
        for finding in record["source_finding_revisions"]:
            self.uow.connection.execute(
                "insert into public.avuhz_implementation_brief_findings "
                "(tenant_id,implementation_brief_id,implementation_brief_version,oia_findings_delivery_id,"
                "oia_finding_id,finding_revision,content_digest) values (%s,%s,%s,%s,%s,%s,%s)",
                (
                    record["tenant_id"], record["implementation_brief_id"], record["implementation_brief_version"],
                    delivery["reference_id"], finding["oia_finding_id"], finding["finding_revision"],
                    finding["content_digest"],
                ),
            )

    def create_initial(self, record):
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        self._insert(record)
        return copy.deepcopy(record)

    def revise(self, current, replacement, revised_at):
        superseded = copy.deepcopy(current)
        superseded.update(
            state="SUPERSEDED", record_version=current["record_version"] + 1, updated_at=revised_at
        )
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        cur = self.uow.connection.execute(
            "update public.avuhz_implementation_briefs set state='SUPERSEDED',record_version=%s,"
            "record=%s::jsonb,updated_at=%s where tenant_id=%s and implementation_brief_id=%s "
            "and implementation_brief_version=%s and state='APPROVED' and record_version=%s",
            (
                superseded["record_version"], _json(superseded), revised_at, current["tenant_id"],
                current["implementation_brief_id"], current["implementation_brief_version"],
                current["record_version"],
            ),
        )
        if cur.rowcount != 1:
            raise ValueError("ImplementationBrief revision concurrency conflict")
        self._insert(replacement)
        return copy.deepcopy(replacement)

    def approve(self, current, client_approval_reference, sekinfra_approval_reference, approved_at):
        updated = copy.deepcopy(current)
        updated.update(
            state="APPROVED", client_approval_reference=copy.deepcopy(client_approval_reference),
            sekinfra_approval_reference=copy.deepcopy(sekinfra_approval_reference), approved_at=approved_at,
            record_version=current["record_version"] + 1, updated_at=approved_at,
        )
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        cur = self.uow.connection.execute(
            "update public.avuhz_implementation_briefs set state='APPROVED',record_version=%s,"
            "record=%s::jsonb,updated_at=%s where tenant_id=%s and implementation_brief_id=%s "
            "and implementation_brief_version=%s and state='DRAFT' and record_version=%s",
            (
                updated["record_version"], _json(updated), approved_at, current["tenant_id"],
                current["implementation_brief_id"], current["implementation_brief_version"],
                current["record_version"],
            ),
        )
        if cur.rowcount != 1:
            raise ValueError("ImplementationBrief approval concurrency conflict")
        return updated
