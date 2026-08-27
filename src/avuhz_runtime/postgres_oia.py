"""Phase 5B PostgreSQL repositories behind the existing provider-neutral ports."""

from __future__ import annotations

import copy
import json

from .oia_inspection_item import derive_assessment_coverage


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _record(row):
    value = row["record"]
    if isinstance(value, str):
        value = json.loads(value)
    return copy.deepcopy(value)


class _DocumentRepository:
    table = ""

    def __init__(self, uow):
        self.uow = uow

    def _one(self, sql, params):
        return self.uow.connection.execute(sql, params).fetchone()

    def _records(self, sql, params):
        return tuple(_record(row) for row in self.uow.connection.execute(sql, params).fetchall())

    def _insert_links(self, table, columns, rows):
        if not rows:
            return
        placeholders = ",".join(("%s",) * len(columns))
        names = ",".join(columns)
        for row in rows:
            self.uow.connection.execute(
                f"insert into public.{table} ({names}) values ({placeholders}) on conflict do nothing",
                row,
            )


class OIAAssessmentPostgresRepository(_DocumentRepository):
    table = "avuhz_oia_assessments"

    def get(self, tenant_id, assessment_id):
        row = self._one(
            "select record from public.avuhz_oia_assessments where tenant_id=%s and oia_assessment_id=%s",
            (tenant_id, assessment_id),
        )
        return _record(row) if row else None

    def find_by_assessment_access_grant(self, tenant_id, grant_id):
        row = self._one(
            "select record from public.avuhz_oia_assessments where tenant_id=%s and assessment_access_grant_id=%s",
            (tenant_id, grant_id),
        )
        return _record(row) if row else None

    def create(self, assessment):
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        cur = self.uow.connection.execute(
            "insert into public.avuhz_oia_assessments "
            "(tenant_id,oia_assessment_id,engagement_id,diagnostic_scope_id,diagnostic_scope_version,assessment_access_grant_id,state,record_version,record,created_at,updated_at) "
            "values (%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s) on conflict do nothing returning oia_assessment_id",
            (
                assessment["tenant_id"], assessment["oia_assessment_id"], assessment["engagement_id"],
                assessment["diagnostic_scope_id"], assessment["diagnostic_scope_version"],
                assessment["assessment_access_grant_id"], assessment["state"], assessment["record_version"],
                _json(assessment), assessment["created_at"], assessment["updated_at"],
            ),
        )
        if not cur.fetchone():
            raise ValueError("OIA assessment identity or grant binding already exists")
        return copy.deepcopy(assessment)

    def _transition(self, current, required_state, target_state, transitioned_at, **fields):
        if current.get("state") != required_state:
            raise ValueError("OIA assessment transition conflict")
        updated = copy.deepcopy(current)
        updated.update(
            state=target_state,
            record_version=current["record_version"] + 1,
            updated_at=transitioned_at,
            **fields,
        )
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        cur = self.uow.connection.execute(
            "update public.avuhz_oia_assessments set state=%s,record_version=%s,record=%s::jsonb,updated_at=%s "
            "where tenant_id=%s and oia_assessment_id=%s and state=%s and record_version=%s",
            (
                target_state, updated["record_version"], _json(updated), transitioned_at,
                current["tenant_id"], current["oia_assessment_id"], required_state,
                current["record_version"],
            ),
        )
        if cur.rowcount != 1:
            raise ValueError("OIA assessment concurrency conflict")
        return updated

    def mark_ready(self, current, ready_at):
        return self._transition(current, "IN_PROGRESS", "READY_FOR_DELIVERY", ready_at, ready_for_delivery_at=ready_at)

    def mark_delivered(self, current, delivery, delivered_at):
        return self._transition(
            current, "READY_FOR_DELIVERY", "FINDINGS_DELIVERED", delivered_at,
            findings_delivered_at=delivered_at,
            findings_delivery_id=delivery["oia_findings_delivery_id"],
        )

    def reopen_for_correction(self, current, reopened_at):
        return self._transition(current, "FINDINGS_DELIVERED", "READY_FOR_DELIVERY", reopened_at, ready_for_delivery_at=reopened_at)

    def close(self, current, closed_at):
        return self._transition(current, "FINDINGS_DELIVERED", "CLOSED", closed_at, closed_at=closed_at)

    def status_view(self, tenant_id, assessment_id, generated_at):
        record = self.get(tenant_id, assessment_id)
        if not record:
            return None
        return {name: record[name] for name in ("tenant_id", "oia_assessment_id", "engagement_id", "state", "record_version")} | {"generated_at": generated_at}


class OIAAssessmentPlanPostgresRepository(_DocumentRepository):
    table = "avuhz_oia_assessment_plans"

    def get_version(self, tenant_id, plan_id, plan_version):
        row = self._one(
            "select record from public.avuhz_oia_assessment_plans where tenant_id=%s and oia_assessment_plan_id=%s and plan_version=%s",
            (tenant_id, plan_id, plan_version),
        )
        return _record(row) if row else None

    def list_versions(self, tenant_id, plan_id):
        return self._records(
            "select record from public.avuhz_oia_assessment_plans where tenant_id=%s and oia_assessment_plan_id=%s order by plan_version",
            (tenant_id, plan_id),
        )

    def get_current(self, tenant_id, plan_id):
        row = self._one(
            "select record from public.avuhz_oia_assessment_plans where tenant_id=%s and oia_assessment_plan_id=%s and state<>'SUPERSEDED' order by plan_version desc limit 1",
            (tenant_id, plan_id),
        )
        return _record(row) if row else None

    def find_current_by_assessment(self, tenant_id, assessment_id):
        row = self._one(
            "select record from public.avuhz_oia_assessment_plans where tenant_id=%s and oia_assessment_id=%s and state<>'SUPERSEDED' order by plan_version desc limit 1",
            (tenant_id, assessment_id),
        )
        return _record(row) if row else None

    def _insert(self, plan):
        cur = self.uow.connection.execute(
            "insert into public.avuhz_oia_assessment_plans "
            "(tenant_id,oia_assessment_plan_id,plan_version,oia_assessment_id,engagement_id,state,record_version,record,created_at,updated_at) "
            "values (%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s) on conflict do nothing returning oia_assessment_plan_id",
            (
                plan["tenant_id"], plan["oia_assessment_plan_id"], plan["plan_version"],
                plan["oia_assessment_id"], plan["engagement_id"], plan["state"],
                plan["record_version"], _json(plan), plan["created_at"], plan["updated_at"],
            ),
        )
        if not cur.fetchone():
            raise ValueError("OIA assessment plan identity conflict")

    def create_initial(self, plan):
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        self._insert(plan)
        return copy.deepcopy(plan)

    def revise(self, current, replacement, revised_at):
        superseded = copy.deepcopy(current)
        superseded.update(state="SUPERSEDED", record_version=current["record_version"] + 1, updated_at=revised_at)
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        cur = self.uow.connection.execute(
            "update public.avuhz_oia_assessment_plans set state='SUPERSEDED',record_version=%s,record=%s::jsonb,updated_at=%s "
            "where tenant_id=%s and oia_assessment_plan_id=%s and plan_version=%s and state=%s and record_version=%s",
            (
                superseded["record_version"], _json(superseded), revised_at, current["tenant_id"],
                current["oia_assessment_plan_id"], current["plan_version"], current["state"], current["record_version"],
            ),
        )
        if cur.rowcount != 1:
            raise ValueError("OIA assessment plan revision conflict")
        self._insert(replacement)
        return copy.deepcopy(replacement)

    def _state_transition(self, current, required, target, actor_field, actor, time_field, at):
        updated = copy.deepcopy(current)
        updated.update(state=target, record_version=current["record_version"] + 1, updated_at=at)
        updated[actor_field] = actor
        updated[time_field] = at
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        cur = self.uow.connection.execute(
            "update public.avuhz_oia_assessment_plans set state=%s,record_version=%s,record=%s::jsonb,updated_at=%s "
            "where tenant_id=%s and oia_assessment_plan_id=%s and plan_version=%s and state=%s and record_version=%s",
            (
                target, updated["record_version"], _json(updated), at, current["tenant_id"],
                current["oia_assessment_plan_id"], current["plan_version"], required, current["record_version"],
            ),
        )
        if cur.rowcount != 1:
            raise ValueError("OIA assessment plan transition conflict")
        return updated

    def review(self, current, reviewed_by, reviewed_at):
        return self._state_transition(current, "DRAFT", "REVIEWED", "reviewed_by", reviewed_by, "reviewed_at", reviewed_at)

    def approve(self, current, approved_by, approved_at):
        return self._state_transition(current, "REVIEWED", "APPROVED", "approved_by", approved_by, "approved_at", approved_at)


class OIAEvidencePostgresRepository(_DocumentRepository):
    table = "avuhz_oia_evidence_items"

    def get(self, tenant_id, evidence_id):
        row = self._one("select record from public.avuhz_oia_evidence_items where tenant_id=%s and oia_evidence_id=%s", (tenant_id, evidence_id))
        return _record(row) if row else None

    def create(self, evidence):
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        cur = self.uow.connection.execute(
            "insert into public.avuhz_oia_evidence_items (tenant_id,oia_evidence_id,oia_assessment_id,content_digest,retention_status,record,created_at) "
            "values (%s,%s,%s,%s,%s,%s::jsonb,%s) on conflict do nothing returning oia_evidence_id",
            (
                evidence["tenant_id"], evidence["oia_evidence_id"], evidence["oia_assessment_id"],
                evidence["content_digest"], evidence["retention_status"], _json(evidence), evidence["created_at"],
            ),
        )
        if not cur.fetchone():
            raise ValueError("OIA evidence identity already exists")
        return copy.deepcopy(evidence)


class OIAInspectionItemPostgresRepository(_DocumentRepository):
    table = "avuhz_oia_inspection_items"

    def get(self, tenant_id, item_id):
        row = self._one("select record from public.avuhz_oia_inspection_items where tenant_id=%s and oia_inspection_item_id=%s", (tenant_id, item_id))
        return _record(row) if row else None

    def list_by_plan(self, tenant_id, plan_id, plan_version):
        return self._records(
            "select record from public.avuhz_oia_inspection_items where tenant_id=%s and oia_assessment_plan_id=%s and plan_version=%s order by oia_inspection_item_id",
            (tenant_id, plan_id, plan_version),
        )

    def list_by_assessment(self, tenant_id, assessment_id):
        return self._records(
            "select record from public.avuhz_oia_inspection_items where tenant_id=%s and oia_assessment_id=%s order by oia_inspection_item_id",
            (tenant_id, assessment_id),
        )

    def create(self, item):
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        cur = self.uow.connection.execute(
            "insert into public.avuhz_oia_inspection_items "
            "(tenant_id,oia_inspection_item_id,oia_assessment_id,oia_assessment_plan_id,plan_version,engagement_id,coverage_state,record_version,record,created_at,updated_at) "
            "values (%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s) on conflict do nothing returning oia_inspection_item_id",
            (
                item["tenant_id"], item["oia_inspection_item_id"], item["oia_assessment_id"],
                item["oia_assessment_plan_id"], item["plan_version"], item["engagement_id"],
                item["coverage_state"], item["record_version"], _json(item), item["created_at"], item["updated_at"],
            ),
        )
        if not cur.fetchone():
            raise ValueError("OIA inspection item identity already exists")
        return copy.deepcopy(item)

    def _replace(self, current, updated):
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        cur = self.uow.connection.execute(
            "update public.avuhz_oia_inspection_items set coverage_state=%s,record_version=%s,record=%s::jsonb,updated_at=%s "
            "where tenant_id=%s and oia_inspection_item_id=%s and record_version=%s",
            (
                updated["coverage_state"], updated["record_version"], _json(updated), updated["updated_at"],
                current["tenant_id"], current["oia_inspection_item_id"], current["record_version"],
            ),
        )
        if cur.rowcount != 1:
            raise ValueError("OIA inspection item concurrency conflict")
        self._insert_links(
            "avuhz_oia_inspection_evidence",
            ("tenant_id", "oia_inspection_item_id", "oia_evidence_id"),
            tuple((updated["tenant_id"], updated["oia_inspection_item_id"], evidence_id) for evidence_id in updated.get("linked_evidence_ids", ())),
        )
        return updated

    def update(self, current, payload, updated_by, updated_at):
        updated = copy.deepcopy(current)
        for name in ("coverage_state", "sufficiency_evaluation", "limitations", "linked_evidence_ids", "stop_reason", "stop_rationale", "intervention_class", "assessor_notes"):
            if name in payload:
                updated[name] = copy.deepcopy(payload[name])
            elif name in ("stop_reason", "stop_rationale", "intervention_class"):
                updated.pop(name, None)
        updated.pop("blocked_reason", None)
        updated.pop("blocked_explanation", None)
        updated.update(updated_by=updated_by, updated_at=updated_at, record_version=current["record_version"] + 1)
        return self._replace(current, updated)

    def block(self, current, payload, updated_by, updated_at, stop_reason):
        updated = copy.deepcopy(current)
        updated.update(
            coverage_state="BLOCKED", blocked_reason=payload["blocked_reason"],
            blocked_explanation=payload["blocked_explanation"], updated_by=updated_by,
            updated_at=updated_at, record_version=current["record_version"] + 1,
        )
        for limitation in payload["limitations"]:
            if limitation not in updated["limitations"]:
                updated["limitations"].append(copy.deepcopy(limitation))
        if updated["sufficiency_evaluation"]["state"] == "NOT_EVALUATED":
            updated["sufficiency_evaluation"].update(
                state="INSUFFICIENT", missing_material_evidence=True, confidence="LOW",
                rationale=payload["blocked_explanation"][:1000],
            )
        if stop_reason:
            updated.update(stop_reason=stop_reason, stop_rationale=payload["blocked_explanation"])
        else:
            updated.pop("stop_reason", None)
            updated.pop("stop_rationale", None)
        updated.pop("intervention_class", None)
        return self._replace(current, updated)

    def coverage_for_plan(self, tenant_id, plan_id, plan_version):
        return derive_assessment_coverage(self.list_by_plan(tenant_id, plan_id, plan_version))

    def coverage_for_current_assessment(self, tenant_id, assessment_id):
        plan = self.uow.oia_assessment_plans.find_current_by_assessment(tenant_id, assessment_id)
        if not plan or plan.get("state") != "APPROVED":
            return None
        return {
            "oia_assessment_id": assessment_id,
            "oia_assessment_plan_id": plan["oia_assessment_plan_id"],
            "plan_version": plan["plan_version"],
            **self.coverage_for_plan(tenant_id, plan["oia_assessment_plan_id"], plan["plan_version"]),
        }


class OIAObservationPostgresRepository(_DocumentRepository):
    table = "avuhz_oia_observations"

    def get(self, tenant_id, observation_id):
        row = self._one("select record from public.avuhz_oia_observations where tenant_id=%s and oia_observation_id=%s", (tenant_id, observation_id))
        return _record(row) if row else None

    def list_by_assessment(self, tenant_id, assessment_id):
        return self._records("select record from public.avuhz_oia_observations where tenant_id=%s and oia_assessment_id=%s order by created_at,oia_observation_id", (tenant_id, assessment_id))

    def list_current_by_assessment(self, tenant_id, assessment_id):
        return tuple(value for value in self.list_by_assessment(tenant_id, assessment_id) if value.get("state") == "RECORDED")

    def resolve_current(self, tenant_id, observation_id):
        current = self.get(tenant_id, observation_id)
        seen = set()
        while current and current.get("state") == "SUPERSEDED":
            if current["oia_observation_id"] in seen:
                return None
            seen.add(current["oia_observation_id"])
            current = self.get(tenant_id, current["superseded_by_observation_id"])
        return current

    def create(self, observation):
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        cur = self.uow.connection.execute(
            "insert into public.avuhz_oia_observations (tenant_id,oia_observation_id,oia_assessment_id,state,record_version,superseded_by_observation_id,record,created_at,updated_at) "
            "values (%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s) on conflict do nothing returning oia_observation_id",
            (
                observation["tenant_id"], observation["oia_observation_id"], observation["oia_assessment_id"],
                observation["state"], observation["record_version"], observation.get("superseded_by_observation_id"),
                _json(observation), observation["created_at"], observation["updated_at"],
            ),
        )
        if not cur.fetchone():
            raise ValueError("OIA observation identity already exists")
        self._insert_links(
            "avuhz_oia_observation_evidence", ("tenant_id", "oia_observation_id", "oia_evidence_id"),
            tuple((observation["tenant_id"], observation["oia_observation_id"], evidence_id) for evidence_id in observation["evidence_ids"]),
        )
        return copy.deepcopy(observation)

    def supersede(self, original, replacement, superseded_at):
        updated = copy.deepcopy(original)
        updated.update(
            state="SUPERSEDED", superseded_by_observation_id=replacement["oia_observation_id"],
            record_version=original["record_version"] + 1, updated_at=superseded_at,
        )
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        cur = self.uow.connection.execute(
            "update public.avuhz_oia_observations set state='SUPERSEDED',record_version=%s,superseded_by_observation_id=%s,record=%s::jsonb,updated_at=%s "
            "where tenant_id=%s and oia_observation_id=%s and state='RECORDED' and record_version=%s",
            (
                updated["record_version"], replacement["oia_observation_id"], _json(updated), superseded_at,
                original["tenant_id"], original["oia_observation_id"], original["record_version"],
            ),
        )
        if cur.rowcount != 1:
            raise ValueError("OIA observation supersession conflict")
        return updated


class OIARootCausePostgresRepository(_DocumentRepository):
    table = "avuhz_oia_root_causes"

    def get(self, tenant_id, root_cause_id):
        row = self._one("select record from public.avuhz_oia_root_causes where tenant_id=%s and oia_root_cause_id=%s", (tenant_id, root_cause_id))
        return _record(row) if row else None

    def list_by_assessment(self, tenant_id, assessment_id):
        return self._records("select record from public.avuhz_oia_root_causes where tenant_id=%s and oia_assessment_id=%s order by created_at,oia_root_cause_id", (tenant_id, assessment_id))

    def _links(self, root_cause):
        self._insert_links(
            "avuhz_oia_root_cause_observations", ("tenant_id", "oia_root_cause_id", "oia_observation_id"),
            tuple((root_cause["tenant_id"], root_cause["oia_root_cause_id"], value) for value in root_cause["supporting_observation_ids"]),
        )
        self._insert_links(
            "avuhz_oia_root_cause_evidence", ("tenant_id", "oia_root_cause_id", "oia_evidence_id"),
            tuple((root_cause["tenant_id"], root_cause["oia_root_cause_id"], value) for value in root_cause.get("supporting_evidence_ids", ())),
        )

    def create(self, root_cause):
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        cur = self.uow.connection.execute(
            "insert into public.avuhz_oia_root_causes (tenant_id,oia_root_cause_id,oia_assessment_id,confidence,record_version,record,created_at,updated_at) "
            "values (%s,%s,%s,%s,%s,%s::jsonb,%s,%s) on conflict do nothing returning oia_root_cause_id",
            (
                root_cause["tenant_id"], root_cause["oia_root_cause_id"], root_cause["oia_assessment_id"],
                root_cause["confidence"], root_cause["record_version"], _json(root_cause),
                root_cause["created_at"], root_cause["updated_at"],
            ),
        )
        if not cur.fetchone():
            raise ValueError("OIA root-cause identity already exists")
        self._links(root_cause)
        return copy.deepcopy(root_cause)

    def transition(self, current, payload, updated_at):
        updated = copy.deepcopy(current)
        updated.update(
            confidence=payload["confidence"],
            supporting_observation_ids=copy.deepcopy(payload["supporting_observation_ids"]),
            supporting_evidence_ids=copy.deepcopy(payload["supporting_evidence_ids"]),
            record_version=current["record_version"] + 1,
            updated_at=updated_at,
        )
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        cur = self.uow.connection.execute(
            "update public.avuhz_oia_root_causes set confidence=%s,record_version=%s,record=%s::jsonb,updated_at=%s "
            "where tenant_id=%s and oia_root_cause_id=%s and confidence=%s and record_version=%s",
            (
                updated["confidence"], updated["record_version"], _json(updated), updated_at,
                current["tenant_id"], current["oia_root_cause_id"], current["confidence"], current["record_version"],
            ),
        )
        if cur.rowcount != 1:
            raise ValueError("OIA root-cause transition conflict")
        self._links(updated)
        return updated


class OIAFindingPostgresRepository(_DocumentRepository):
    table = "avuhz_oia_findings"

    def get_revision(self, tenant_id, finding_id, finding_revision):
        row = self._one(
            "select record from public.avuhz_oia_findings where tenant_id=%s and oia_finding_id=%s and finding_revision=%s",
            (tenant_id, finding_id, finding_revision),
        )
        return _record(row) if row else None

    def get(self, tenant_id, finding_id):
        row = self._one(
            "select record from public.avuhz_oia_findings where tenant_id=%s and oia_finding_id=%s and state<>'SUPERSEDED' order by finding_revision desc limit 1",
            (tenant_id, finding_id),
        )
        return _record(row) if row else None

    def list_by_assessment(self, tenant_id, assessment_id):
        return self._records(
            "select record from public.avuhz_oia_findings where tenant_id=%s and oia_assessment_id=%s order by oia_finding_id,finding_revision",
            (tenant_id, assessment_id),
        )

    def list_current_by_assessment(self, tenant_id, assessment_id):
        return self._records(
            "select distinct on (oia_finding_id) record from public.avuhz_oia_findings "
            "where tenant_id=%s and oia_assessment_id=%s and state<>'SUPERSEDED' order by oia_finding_id,finding_revision desc",
            (tenant_id, assessment_id),
        )

    def _insert(self, finding):
        cur = self.uow.connection.execute(
            "insert into public.avuhz_oia_findings "
            "(tenant_id,oia_finding_id,finding_revision,oia_assessment_id,state,priority,content_digest,record,created_at,updated_at) "
            "values (%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s) on conflict do nothing returning oia_finding_id",
            (
                finding["tenant_id"], finding["oia_finding_id"], finding["finding_revision"],
                finding["oia_assessment_id"], finding["state"], finding["priority"],
                finding.get("content_digest"), _json(finding), finding["created_at"], finding["updated_at"],
            ),
        )
        if not cur.fetchone():
            raise ValueError("OIA Finding identity or revision conflict")
        self._insert_links(
            "avuhz_oia_finding_observations", ("tenant_id", "oia_finding_id", "finding_revision", "oia_observation_id"),
            tuple((finding["tenant_id"], finding["oia_finding_id"], finding["finding_revision"], value) for value in finding["supporting_observation_ids"]),
        )
        self._insert_links(
            "avuhz_oia_finding_evidence", ("tenant_id", "oia_finding_id", "finding_revision", "oia_evidence_id"),
            tuple((finding["tenant_id"], finding["oia_finding_id"], finding["finding_revision"], value) for value in finding["supporting_evidence_ids"]),
        )
        self._insert_links(
            "avuhz_oia_finding_root_causes", ("tenant_id", "oia_finding_id", "finding_revision", "oia_root_cause_id"),
            tuple((finding["tenant_id"], finding["oia_finding_id"], finding["finding_revision"], value) for value in finding.get("root_cause_ids", ())),
        )

    def create(self, finding):
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        self._insert(finding)
        return copy.deepcopy(finding)

    def _supersede(self, current, updated):
        cur = self.uow.connection.execute(
            "update public.avuhz_oia_findings set state='SUPERSEDED',content_digest=%s,record=%s::jsonb,updated_at=%s "
            "where tenant_id=%s and oia_finding_id=%s and finding_revision=%s and state=%s",
            (
                updated.get("content_digest"), _json(updated), updated["updated_at"], current["tenant_id"],
                current["oia_finding_id"], current["finding_revision"], current["state"],
            ),
        )
        if cur.rowcount != 1:
            raise ValueError("OIA Finding supersession conflict")

    def revise(self, current, replacement, content_digest, updated_at):
        superseded = copy.deepcopy(current)
        superseded.update(state="SUPERSEDED", content_digest=content_digest, updated_at=updated_at)
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        self._supersede(current, superseded)
        self._insert(replacement)
        return copy.deepcopy(replacement)

    def finalize(self, current, final):
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        cur = self.uow.connection.execute(
            "update public.avuhz_oia_findings set state='FINAL',content_digest=%s,record=%s::jsonb,updated_at=%s "
            "where tenant_id=%s and oia_finding_id=%s and finding_revision=%s and state='DRAFT'",
            (
                final["content_digest"], _json(final), final["updated_at"], current["tenant_id"],
                current["oia_finding_id"], current["finding_revision"],
            ),
        )
        if cur.rowcount != 1:
            raise ValueError("OIA Finding finalization conflict")
        return copy.deepcopy(final)

    def open_delivered_correction(self, original, replacement, opened_at):
        superseded = copy.deepcopy(original)
        superseded.update(state="SUPERSEDED", updated_at=opened_at)
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        self._supersede(original, superseded)
        self._insert(replacement)
        return copy.deepcopy(replacement)

    def summary_by_assessment(self, tenant_id, assessment_id, generated_at):
        finals = [finding for finding in self.list_current_by_assessment(tenant_id, assessment_id) if finding.get("state") == "FINAL"]
        return {
            "tenant_id": tenant_id, "oia_assessment_id": assessment_id,
            "finalized_finding_count": len(finals),
            "priority_counts": [
                {"priority": priority, "count": sum(finding["priority"] == priority for finding in finals)}
                for priority in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
            ],
            "generated_at": generated_at,
        }


class OIAFindingsDeliveryPostgresRepository(_DocumentRepository):
    table = "avuhz_oia_findings_deliveries"

    def get(self, tenant_id, delivery_id):
        row = self._one("select record from public.avuhz_oia_findings_deliveries where tenant_id=%s and oia_findings_delivery_id=%s", (tenant_id, delivery_id))
        return _record(row) if row else None

    def list_by_assessment(self, tenant_id, assessment_id):
        return self._records(
            "select record from public.avuhz_oia_findings_deliveries where tenant_id=%s and oia_assessment_id=%s order by delivery_sequence",
            (tenant_id, assessment_id),
        )

    def latest_by_assessment(self, tenant_id, assessment_id):
        row = self._one(
            "select record from public.avuhz_oia_findings_deliveries where tenant_id=%s and oia_assessment_id=%s order by delivery_sequence desc limit 1",
            (tenant_id, assessment_id),
        )
        return _record(row) if row else None

    def create(self, delivery):
        self.uow.failpoint("AUTHORITATIVE_WRITE")
        cur = self.uow.connection.execute(
            "insert into public.avuhz_oia_findings_deliveries "
            "(tenant_id,oia_findings_delivery_id,oia_assessment_id,delivery_sequence,manifest_digest,record,delivered_at) "
            "values (%s,%s,%s,%s,%s,%s::jsonb,%s) on conflict do nothing returning oia_findings_delivery_id",
            (
                delivery["tenant_id"], delivery["oia_findings_delivery_id"], delivery["oia_assessment_id"],
                delivery["delivery_sequence"], delivery["manifest_digest"], _json(delivery), delivery["delivered_at"],
            ),
        )
        if not cur.fetchone():
            raise ValueError("OIA findings delivery identity, sequence, or digest already exists")
        self._insert_links(
            "avuhz_oia_findings_delivery_items",
            ("tenant_id", "oia_findings_delivery_id", "oia_finding_id", "finding_revision", "content_digest"),
            tuple(
                (
                    delivery["tenant_id"], delivery["oia_findings_delivery_id"], item["oia_finding_id"],
                    item["finding_revision"], item["content_digest"],
                )
                for item in delivery["finding_revisions"]
            ),
        )
        return copy.deepcopy(delivery)

    def status_view(self, tenant_id, assessment_id, assessment_state, generated_at):
        values = self.list_by_assessment(tenant_id, assessment_id)
        view = {
            "tenant_id": tenant_id, "oia_assessment_id": assessment_id,
            "assessment_state": assessment_state, "delivery_count": len(values),
            "generated_at": generated_at,
        }
        if values:
            view["latest_delivery_id"] = values[-1]["oia_findings_delivery_id"]
        return view
