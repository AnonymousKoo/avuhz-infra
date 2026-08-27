"""PostgreSQL repositories for frozen Phase 5C authoritative resources."""
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


class _DocumentRepository:
    def __init__(self, uow):
        self.uow = uow

    def _one(self, sql, params):
        return self.uow.connection.execute(sql, params).fetchone()

    def _records(self, sql, params):
        return tuple(_record(row) for row in self.uow.connection.execute(sql, params).fetchall())


class OIAConversionDecisionPostgresRepository(_DocumentRepository):
    def get_version(self, tenant_id, decision_id, decision_version):
        return _record(self._one(
            "select record from public.avuhz_oia_conversion_decisions where tenant_id=%s and oia_conversion_decision_id=%s and decision_version=%s",
            (tenant_id, decision_id, decision_version),
        ))

    def get_current(self, tenant_id, decision_id):
        return _record(self._one(
            "select record from public.avuhz_oia_conversion_decisions where tenant_id=%s and oia_conversion_decision_id=%s order by decision_version desc limit 1",
            (tenant_id, decision_id),
        ))

    def find_current_by_engagement(self, tenant_id, engagement_id):
        return _record(self._one(
            "select record from public.avuhz_oia_conversion_decisions where tenant_id=%s and engagement_id=%s order by decision_version desc,created_at desc limit 1",
            (tenant_id, engagement_id),
        ))

    def create(self, record):
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        cur = self.uow.connection.execute(
            "insert into public.avuhz_oia_conversion_decisions (tenant_id,oia_conversion_decision_id,decision_version,engagement_id,oia_assessment_id,oia_findings_delivery_id,state,record_version,record,created_at,updated_at) values (%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s) on conflict do nothing returning oia_conversion_decision_id",
            (record["tenant_id"], record["oia_conversion_decision_id"], record["decision_version"],
             record["engagement_id"], record["oia_assessment_id"], record["oia_findings_delivery_id"],
             record["state"], record["record_version"], _json(record), record["created_at"], record["updated_at"]),
        )
        if not cur.fetchone():
            raise ValueError("conversion decision identity/version conflict")
        return copy.deepcopy(record)

    def accept(self, current, sekinfra_approval_reference, accepted_at):
        updated = copy.deepcopy(current)
        updated.update(state="ACCEPTED", sekinfra_approval_reference=copy.deepcopy(sekinfra_approval_reference),
                       accepted_at=accepted_at, record_version=current["record_version"] + 1,
                       updated_at=accepted_at)
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        cur = self.uow.connection.execute(
            "update public.avuhz_oia_conversion_decisions set state='ACCEPTED',record_version=%s,record=%s::jsonb,updated_at=%s where tenant_id=%s and oia_conversion_decision_id=%s and decision_version=%s and state='PENDING_SEKINFRA' and record_version=%s",
            (updated["record_version"], _json(updated), accepted_at, current["tenant_id"],
             current["oia_conversion_decision_id"], current["decision_version"], current["record_version"]),
        )
        if cur.rowcount != 1:
            raise ValueError("conversion acceptance concurrency conflict")
        return updated


class OngoingAgreementAuthorityPostgresRepository(_DocumentRepository):
    def get_version(self, tenant_id, agreement_id, agreement_version):
        return _record(self._one(
            "select record from public.avuhz_ongoing_agreement_authorities where tenant_id=%s and ongoing_agreement_authority_id=%s and agreement_version=%s",
            (tenant_id, agreement_id, agreement_version),
        ))

    def get_current(self, tenant_id, agreement_id):
        return _record(self._one(
            "select record from public.avuhz_ongoing_agreement_authorities where tenant_id=%s and ongoing_agreement_authority_id=%s and state<>'SUPERSEDED' order by agreement_version desc limit 1",
            (tenant_id, agreement_id),
        ))

    def find_current_by_engagement(self, tenant_id, engagement_id):
        return _record(self._one(
            "select record from public.avuhz_ongoing_agreement_authorities where tenant_id=%s and engagement_id=%s and state<>'SUPERSEDED' order by agreement_version desc,created_at desc limit 1",
            (tenant_id, engagement_id),
        ))

    def create(self, record):
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        cur = self.uow.connection.execute(
            "insert into public.avuhz_ongoing_agreement_authorities (tenant_id,ongoing_agreement_authority_id,agreement_version,engagement_id,oia_conversion_decision_id,decision_version,state,record_version,record,created_at,updated_at) values (%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s) on conflict do nothing returning ongoing_agreement_authority_id",
            (record["tenant_id"], record["ongoing_agreement_authority_id"], record["agreement_version"],
             record["engagement_id"], record["conversion_decision_reference"]["reference_id"],
             record["conversion_decision_reference"]["reference_version"], record["state"],
             record["record_version"], _json(record), record["created_at"], record["updated_at"]),
        )
        if not cur.fetchone():
            raise ValueError("Agreement #2 identity/version conflict")
        return copy.deepcopy(record)

    def activate(self, current, client_approval_reference, sekinfra_approval_reference, activated_at):
        updated = copy.deepcopy(current)
        updated.update(state="ACTIVE", client_approval_reference=copy.deepcopy(client_approval_reference),
                       sekinfra_approval_reference=copy.deepcopy(sekinfra_approval_reference),
                       activated_at=activated_at, record_version=current["record_version"] + 1,
                       updated_at=activated_at)
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        if current.get("supersedes_agreement_reference"):
            ref = current["supersedes_agreement_reference"]
            prior = self.get_version(current["tenant_id"], ref["reference_id"], ref["reference_version"])
            if not prior or prior.get("state") != "ACTIVE":
                raise ValueError("superseded active agreement is required")
            superseded = copy.deepcopy(prior)
            superseded.update(state="SUPERSEDED", terminal_at=activated_at,
                              terminal_reason="SUPERSEDED_BY_NEW_VERSION",
                              record_version=prior["record_version"] + 1, updated_at=activated_at)
            cur = self.uow.connection.execute(
                "update public.avuhz_ongoing_agreement_authorities set state='SUPERSEDED',record_version=%s,record=%s::jsonb,updated_at=%s where tenant_id=%s and ongoing_agreement_authority_id=%s and agreement_version=%s and state='ACTIVE' and record_version=%s",
                (superseded["record_version"], _json(superseded), activated_at, prior["tenant_id"],
                 prior["ongoing_agreement_authority_id"], prior["agreement_version"], prior["record_version"]),
            )
            if cur.rowcount != 1:
                raise ValueError("agreement supersession concurrency conflict")
        cur = self.uow.connection.execute(
            "update public.avuhz_ongoing_agreement_authorities set state='ACTIVE',record_version=%s,record=%s::jsonb,updated_at=%s where tenant_id=%s and ongoing_agreement_authority_id=%s and agreement_version=%s and state='DRAFT' and record_version=%s",
            (updated["record_version"], _json(updated), activated_at, current["tenant_id"],
             current["ongoing_agreement_authority_id"], current["agreement_version"], current["record_version"]),
        )
        if cur.rowcount != 1:
            raise ValueError("agreement activation concurrency conflict")
        return updated

    def terminate(self, current, state, reason, terminal_at):
        updated = copy.deepcopy(current)
        updated.update(state=state, terminal_at=terminal_at, terminal_reason=reason,
                       record_version=current["record_version"] + 1, updated_at=terminal_at)
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        cur = self.uow.connection.execute(
            "update public.avuhz_ongoing_agreement_authorities set state=%s,record_version=%s,record=%s::jsonb,updated_at=%s where tenant_id=%s and ongoing_agreement_authority_id=%s and agreement_version=%s and state='ACTIVE' and record_version=%s",
            (state, updated["record_version"], _json(updated), terminal_at, current["tenant_id"],
             current["ongoing_agreement_authority_id"], current["agreement_version"], current["record_version"]),
        )
        if cur.rowcount != 1:
            raise ValueError("agreement termination concurrency conflict")
        return updated


class OngoingPaymentVerificationPostgresRepository(_DocumentRepository):
    def get(self, tenant_id, payment_id):
        return _record(self._one("select record from public.avuhz_ongoing_payment_verifications where tenant_id=%s and ongoing_payment_verification_id=%s", (tenant_id, payment_id)))

    def find_current_by_engagement(self, tenant_id, engagement_id):
        return _record(self._one("select record from public.avuhz_ongoing_payment_verifications where tenant_id=%s and engagement_id=%s order by verified_at desc,ongoing_payment_verification_id limit 1", (tenant_id, engagement_id)))

    def create(self, record):
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        ref = record["ongoing_agreement_reference"]
        cur = self.uow.connection.execute(
            "insert into public.avuhz_ongoing_payment_verifications (tenant_id,ongoing_payment_verification_id,engagement_id,ongoing_agreement_authority_id,agreement_version,status,coverage_from,coverage_until,record_version,record,verified_at) values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s) on conflict do nothing returning ongoing_payment_verification_id",
            (record["tenant_id"], record["ongoing_payment_verification_id"], record["engagement_id"],
             ref["reference_id"], ref["reference_version"], record["status"], record["coverage_from"],
             record["coverage_until"], record["record_version"], _json(record), record["verified_at"]),
        )
        if not cur.fetchone(): raise ValueError("ongoing payment identity conflict")
        return copy.deepcopy(record)

    def invalidate(self, current, reason, invalidated_at):
        updated = copy.deepcopy(current)
        updated.update(status="INVALIDATED", invalidated_at=invalidated_at, invalidation_reason=reason,
                       record_version=current["record_version"] + 1)
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        cur = self.uow.connection.execute(
            "update public.avuhz_ongoing_payment_verifications set status='INVALIDATED',record_version=%s,record=%s::jsonb where tenant_id=%s and ongoing_payment_verification_id=%s and status='VERIFIED' and record_version=%s",
            (updated["record_version"], _json(updated), current["tenant_id"],
             current["ongoing_payment_verification_id"], current["record_version"]),
        )
        if cur.rowcount != 1: raise ValueError("commercial invalidation concurrency conflict")
        return updated


class OngoingAccessGrantPostgresRepository(_DocumentRepository):
    def get(self, tenant_id, grant_id):
        return _record(self._one("select record from public.avuhz_ongoing_access_grants where tenant_id=%s and ongoing_access_grant_id=%s", (tenant_id, grant_id)))

    def find_current_by_engagement(self, tenant_id, engagement_id):
        return _record(self._one("select record from public.avuhz_ongoing_access_grants where tenant_id=%s and engagement_id=%s order by proposed_at desc,ongoing_access_grant_id limit 1", (tenant_id, engagement_id)))

    def create(self, record):
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        cref, aref, pref = record["conversion_decision_reference"], record["ongoing_agreement_reference"], record["ongoing_payment_verification_reference"]
        cur = self.uow.connection.execute(
            "insert into public.avuhz_ongoing_access_grants (tenant_id,ongoing_access_grant_id,engagement_id,oia_conversion_decision_id,decision_version,ongoing_agreement_authority_id,agreement_version,ongoing_payment_verification_id,state,record_version,record,proposed_at) values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s) on conflict do nothing returning ongoing_access_grant_id",
            (record["tenant_id"], record["ongoing_access_grant_id"], record["engagement_id"], cref["reference_id"],
             cref["reference_version"], aref["reference_id"], aref["reference_version"], pref["reference_id"],
             record["state"], record["record_version"], _json(record), record["proposed_at"]),
        )
        if not cur.fetchone(): raise ValueError("ongoing access identity conflict")
        return copy.deepcopy(record)

    def _transition(self, current, required, state, **fields):
        updated = copy.deepcopy(current)
        updated.update(state=state, record_version=current["record_version"] + 1, **fields)
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        cur = self.uow.connection.execute(
            "update public.avuhz_ongoing_access_grants set state=%s,record_version=%s,record=%s::jsonb where tenant_id=%s and ongoing_access_grant_id=%s and state=any(%s) and record_version=%s",
            (state, updated["record_version"], _json(updated), current["tenant_id"],
             current["ongoing_access_grant_id"], list(required), current["record_version"]),
        )
        if cur.rowcount != 1: raise ValueError("ongoing access transition concurrency conflict")
        return updated

    def approve(self, current, client_approval_reference, sekinfra_approval_reference, approved_at):
        return self._transition(current, {"PROPOSED"}, "APPROVED", client_approval_reference=copy.deepcopy(client_approval_reference), sekinfra_approval_reference=copy.deepcopy(sekinfra_approval_reference), approved_at=approved_at)

    def activate(self, current, verified_at):
        return self._transition(current, {"APPROVED"}, "ACTIVE", verified_at=verified_at, active_from=verified_at)

    def revoke(self, current, reason, revoked_at):
        return self._transition(current, {"APPROVED", "ACTIVE"}, "REVOKED", revoked_at=revoked_at, revocation_reason=reason)

    def close(self, current, reason, closed_at):
        return self._transition(current, {"APPROVED", "ACTIVE"}, "CLOSED", closed_at=closed_at, closure_reason=reason)


class OngoingAccessRevocationVerificationPostgresRepository(_DocumentRepository):
    def get(self, tenant_id, verification_id):
        return _record(self._one("select record from public.avuhz_ongoing_access_revocation_verifications where tenant_id=%s and ongoing_access_revocation_verification_id=%s", (tenant_id, verification_id)))

    def list_by_grant(self, tenant_id, grant_id, offboarding_id=None):
        if offboarding_id is None:
            return self._records("select record from public.avuhz_ongoing_access_revocation_verifications where tenant_id=%s and ongoing_access_grant_id=%s order by verified_at,ongoing_access_revocation_verification_id", (tenant_id, grant_id))
        return self._records("select record from public.avuhz_ongoing_access_revocation_verifications where tenant_id=%s and ongoing_access_grant_id=%s and ongoing_offboarding_id=%s order by verified_at,ongoing_access_revocation_verification_id", (tenant_id, grant_id, offboarding_id))

    def list_by_offboarding(self, tenant_id, offboarding_id):
        return self._records("select record from public.avuhz_ongoing_access_revocation_verifications where tenant_id=%s and ongoing_offboarding_id=%s order by verified_at,ongoing_access_revocation_verification_id", (tenant_id, offboarding_id))

    def create(self, record):
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        grant = record["ongoing_access_grant_reference"]
        offboarding = record.get("offboarding_reference")
        cur = self.uow.connection.execute(
            "insert into public.avuhz_ongoing_access_revocation_verifications (tenant_id,ongoing_access_revocation_verification_id,engagement_id,ongoing_access_grant_id,grant_record_version,ongoing_offboarding_id,offboarding_record_version,record,verified_at) values (%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s) on conflict do nothing returning ongoing_access_revocation_verification_id",
            (record["tenant_id"], record["ongoing_access_revocation_verification_id"], record["engagement_id"],
             grant["reference_id"], grant["reference_version"], offboarding["reference_id"] if offboarding else None,
             offboarding["reference_version"] if offboarding else None, _json(record), record["verified_at"]),
        )
        if not cur.fetchone(): raise ValueError("revocation verification is immutable")
        return copy.deepcopy(record)


class OngoingOffboardingPostgresRepository(_DocumentRepository):
    def get(self, tenant_id, offboarding_id):
        return _record(self._one("select record from public.avuhz_ongoing_offboardings where tenant_id=%s and ongoing_offboarding_id=%s", (tenant_id, offboarding_id)))

    def find_by_engagement(self, tenant_id, engagement_id):
        return _record(self._one("select record from public.avuhz_ongoing_offboardings where tenant_id=%s and engagement_id=%s order by initiated_at desc limit 1", (tenant_id, engagement_id)))

    def create(self, record):
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        ref = record["conversion_decision_reference"]
        cur = self.uow.connection.execute(
            "insert into public.avuhz_ongoing_offboardings (tenant_id,ongoing_offboarding_id,engagement_id,oia_conversion_decision_id,decision_version,state,record_version,record,initiated_at) values (%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s) on conflict do nothing returning ongoing_offboarding_id",
            (record["tenant_id"], record["ongoing_offboarding_id"], record["engagement_id"], ref["reference_id"],
             ref["reference_version"], record["state"], record["record_version"], _json(record), record["initiated_at"]),
        )
        if not cur.fetchone(): raise ValueError("offboarding identity or engagement conflict")
        return copy.deepcopy(record)

    def complete(self, current, verification_references, completed_at, completed_by):
        updated = copy.deepcopy(current)
        updated.update(state="COMPLETED", revocation_verification_references=copy.deepcopy(verification_references),
                       completed_at=completed_at, completed_by=completed_by,
                       record_version=current["record_version"] + 1)
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        cur = self.uow.connection.execute(
            "update public.avuhz_ongoing_offboardings set state='COMPLETED',record_version=%s,record=%s::jsonb where tenant_id=%s and ongoing_offboarding_id=%s and state=any(%s) and record_version=%s",
            (updated["record_version"], _json(updated), current["tenant_id"], current["ongoing_offboarding_id"],
             ["INITIATED", "ACCESS_REVOCATION_PENDING"], current["record_version"]),
        )
        if cur.rowcount != 1: raise ValueError("offboarding completion concurrency conflict")
        return updated
