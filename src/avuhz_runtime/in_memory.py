"""Development-only in-memory governed runtime; production uses PostgreSQL."""
from __future__ import annotations

import copy
import hashlib
import json
import uuid
from dataclasses import dataclass, field

from .guards import AuthoritativeSubjectSnapshot
from .models import ValidationFailure
from .runtime import prepare_and_guard_command
from .phase5d_brief import IMPLEMENTATION_BRIEF_COMMANDS, IMPLEMENTATION_BRIEF_EVENTS, ImplementationBriefHandler
from .phase5d_authorization import IMPLEMENTATION_AUTHORIZATION_COMMANDS, IMPLEMENTATION_AUTHORIZATION_EVENTS, ImplementationAuthorizationHandler
from .phase5d_authorization_memory import ImplementationAuthorizationMemoryRepository
from .phase5d_package import CODEX_BUILD_PACKAGE_COMMANDS, CODEX_BUILD_PACKAGE_EVENTS, CodexBuildPackageHandler
from .phase5d_package_memory import CodexBuildPackageMemoryRepository
from .phase5d_build_execution import BUILD_EXECUTION_COMMANDS, BUILD_EXECUTION_EVENTS, BuildExecutionResultHandler
from .phase5d_build_execution_memory import BuildExecutionResultMemoryRepository
from .phase5d_qa_result import QA_RESULT_COMMANDS, QA_RESULT_EVENTS, QAResultHandler
from .phase5d_qa_result_memory import QAResultMemoryRepository
from .phase5d_client_acceptance import CLIENT_ACCEPTANCE_COMMANDS, CLIENT_ACCEPTANCE_EVENTS, ClientAcceptanceHandler
from .phase5d_client_acceptance_memory import ClientAcceptanceMemoryRepository
from .phase5d_deployment_authorization import DEPLOYMENT_AUTHORIZATION_COMMANDS, DEPLOYMENT_AUTHORIZATION_EVENTS, DeploymentAuthorizationHandler
from .phase5d_deployment_authorization_memory import DeploymentAuthorizationMemoryRepository
from .phase5d_deployment_execution import DEPLOYMENT_EXECUTION_COMMANDS, DEPLOYMENT_EXECUTION_EVENTS, DeploymentExecutionHandler
from .phase5d_deployment_execution_memory import DeploymentExecutionMemoryRepository


COMMAND_SCOPED_IDEMPOTENCY_COMMANDS = frozenset((
    *IMPLEMENTATION_BRIEF_COMMANDS, *IMPLEMENTATION_AUTHORIZATION_COMMANDS,
    *CODEX_BUILD_PACKAGE_COMMANDS, *BUILD_EXECUTION_COMMANDS, *QA_RESULT_COMMANDS,
    *CLIENT_ACCEPTANCE_COMMANDS,
    *DEPLOYMENT_AUTHORIZATION_COMMANDS, *DEPLOYMENT_EXECUTION_COMMANDS,
))


def idempotency_scope(command):
    return "COMMAND" if command.command_type in COMMAND_SCOPED_IDEMPOTENCY_COMMANDS else "SUBJECT:" + command.subject_id


def fingerprint(command):
    value = {key: command[key] for key in (
        "tenant_id", "command_type", "subject_type", "subject_id",
        "engagement_id", "expected_record_version", "payload",
    ) if key in command}
    return "fpv1:" + hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()


@dataclass
class MemoryStore:
    handoffs: dict = field(default_factory=dict)
    engagements: dict = field(default_factory=dict)
    implementation_handoffs: dict = field(default_factory=dict)
    implementation_briefs: dict = field(default_factory=dict)
    implementation_authorizations: dict = field(default_factory=dict)
    codex_build_packages: dict = field(default_factory=dict)
    build_execution_results: dict = field(default_factory=dict)
    qa_results: dict = field(default_factory=dict)
    client_acceptances: dict = field(default_factory=dict)
    deployment_authorizations: dict = field(default_factory=dict)
    deployment_executions: dict = field(default_factory=dict)
    approvals: dict = field(default_factory=dict)
    idempotency: dict = field(default_factory=dict)
    events: list = field(default_factory=list)
    outbox: list = field(default_factory=list)
    fail_stage: str | None = None

    @staticmethod
    def _current(data, tenant_id, identity, version_field):
        values = [value for (tenant, record_id, _), value in data.items()
                  if tenant == tenant_id and record_id == identity and value.get("state") != "SUPERSEDED"]
        return copy.deepcopy(max(values, key=lambda item: item[version_field])) if values else None

    def snapshot(self, command, trusted_context=None):
        record = None
        if command.subject_type == "ACQUISITION_HANDOFF":
            record = self.handoffs.get(command.subject_id)
        elif command.subject_type == "ENGAGEMENT":
            record = self.engagements.get(command.subject_id)
        elif command.subject_type == "IMPLEMENTATION_BRIEF":
            record = self._current(self.implementation_briefs, command.tenant_id, command.subject_id, "implementation_brief_version")
        elif command.subject_type == "IMPLEMENTATION_AUTHORIZATION":
            record = self._current(self.implementation_authorizations, command.tenant_id, command.subject_id, "authorization_version")
        elif command.subject_type == "CODEX_BUILD_PACKAGE":
            record = self._current(self.codex_build_packages, command.tenant_id, command.subject_id, "package_version")
        elif command.subject_type == "BUILD_EXECUTION_RESULT":
            record = self.build_execution_results.get((command.tenant_id, command.subject_id))
        elif command.subject_type == "QA_RESULT":
            record = self.qa_results.get((command.tenant_id, command.subject_id))
        elif command.subject_type == "CLIENT_ACCEPTANCE":
            values = [
                value for (tenant, record_id, _), value in self.client_acceptances.items()
                if tenant == command.tenant_id and record_id == command.subject_id
            ]
            record = max(values, key=lambda value: value["acceptance_version"]) if values else None
        elif command.subject_type == "DEPLOYMENT_AUTHORIZATION":
            record = self._current(
                self.deployment_authorizations,
                command.tenant_id,
                command.subject_id,
                "authorization_version",
            )
        elif command.subject_type == "DEPLOYMENT_EXECUTION":
            record = self.deployment_executions.get((command.tenant_id, command.subject_id))
        if not record:
            return None
        return AuthoritativeSubjectSnapshot(
            command.subject_type, command.subject_id, record["tenant_id"],
            record.get("record_version", 1), True, record.get("engagement_id"),
            record.get("state") or record.get("engagement_state"),
        )


class _TenantRepo:
    def __init__(self, uow, name): self.uow = uow; self.data = getattr(uow.working, name)
    def get(self, tenant_id, identity):
        value = self.data.get(identity)
        return copy.deepcopy(value) if value and value.get("tenant_id") == tenant_id else None


class AcquisitionHandoffMemoryRepository(_TenantRepo):
    def __init__(self, uow): super().__init__(uow, "handoffs")
    def save_accepted(self, record):
        self.uow.failpoint("AUTHORITATIVE_WRITE"); record = copy.deepcopy(record); record["accepted"] = True
        self.data[record["handoff_id"]] = record


class EngagementMemoryRepository(_TenantRepo):
    def __init__(self, uow): super().__init__(uow, "engagements")
    def exists(self, tenant_id, identity): return self.get(tenant_id, identity) is not None
    def save(self, record): self.uow.failpoint("AUTHORITATIVE_WRITE"); self.data[record["engagement_id"]] = copy.deepcopy(record)


class ImplementationHandoffMemoryRepository(_TenantRepo):
    def __init__(self, uow): super().__init__(uow, "implementation_handoffs")
    def get_version(self, tenant_id, identity, version):
        value = self.data.get((tenant_id, identity, version)); return copy.deepcopy(value) if value else None
    def list_versions(self, tenant_id, identity):
        return tuple(copy.deepcopy(value) for (tenant, record_id, _), value in sorted(self.data.items(), key=lambda item: item[0][2]) if tenant == tenant_id and record_id == identity)
    def get_current(self, tenant_id, identity):
        values = self.list_versions(tenant_id, identity)
        return copy.deepcopy(max(values, key=lambda value: value["handoff_version"])) if values else None
    def create(self, record):
        key = (record["tenant_id"], record["implementation_handoff_id"], record["handoff_version"])
        if key in self.data: raise ValueError("ImplementationHandoff identity/version already exists")
        self.uow.failpoint("AUTHORITATIVE_WRITE"); self.data[key] = copy.deepcopy(record); return copy.deepcopy(record)


class ImplementationBriefMemoryRepository(_TenantRepo):
    def __init__(self, uow): super().__init__(uow, "implementation_briefs")
    def get_version(self, tenant_id, identity, version):
        value = self.data.get((tenant_id, identity, version)); return copy.deepcopy(value) if value else None
    def list_versions(self, tenant_id, identity):
        return tuple(copy.deepcopy(value) for (tenant, record_id, _), value in sorted(self.data.items(), key=lambda item: item[0][2]) if tenant == tenant_id and record_id == identity)
    def get_current(self, tenant_id, identity):
        values = [value for value in self.list_versions(tenant_id, identity) if value.get("state") != "SUPERSEDED"]
        return copy.deepcopy(max(values, key=lambda value: value["implementation_brief_version"])) if values else None
    def create_initial(self, record):
        key = (record["tenant_id"], record["implementation_brief_id"], record["implementation_brief_version"])
        if key in self.data or self.list_versions(record["tenant_id"], record["implementation_brief_id"]): raise ValueError("ImplementationBrief identity already exists")
        self.uow.failpoint("AUTHORITATIVE_WRITE"); self.data[key] = copy.deepcopy(record); return copy.deepcopy(record)
    def revise(self, current, replacement, revised_at):
        key = (current["tenant_id"], current["implementation_brief_id"], current["implementation_brief_version"])
        replacement_key = (replacement["tenant_id"], replacement["implementation_brief_id"], replacement["implementation_brief_version"])
        stored = self.data.get(key)
        if stored != current or stored.get("state") != "APPROVED" or replacement_key in self.data: raise ValueError("ImplementationBrief revision conflict")
        self.uow.failpoint("AUTHORITATIVE_WRITE"); superseded = copy.deepcopy(stored)
        superseded.update(state="SUPERSEDED", record_version=stored["record_version"] + 1, updated_at=revised_at)
        self.data[key] = superseded; self.data[replacement_key] = copy.deepcopy(replacement); return copy.deepcopy(replacement)
    def approve(self, current, client_approval_reference, provider_approval_reference, approved_at):
        key = (current["tenant_id"], current["implementation_brief_id"], current["implementation_brief_version"]); stored = self.data.get(key)
        if stored != current or stored.get("state") != "DRAFT": raise ValueError("ImplementationBrief approval conflict")
        self.uow.failpoint("AUTHORITATIVE_WRITE"); updated = copy.deepcopy(stored)
        updated.update(state="APPROVED", client_approval_reference=copy.deepcopy(client_approval_reference), provider_approval_reference=copy.deepcopy(provider_approval_reference), approved_at=approved_at, record_version=stored["record_version"] + 1, updated_at=approved_at)
        self.data[key] = updated; return copy.deepcopy(updated)


class HumanApprovalMemoryRepository(_TenantRepo):
    def __init__(self, uow): super().__init__(uow, "approvals")
    def save(self, record):
        if self.get(record["tenant_id"], record["approval_id"]): raise ValueError("approval already exists")
        self.uow.failpoint("AUTHORITATIVE_WRITE"); self.data[record["approval_id"]] = copy.deepcopy(record)
    def find_active_phase5d_binding(self, tenant_id, subject_type, subject_id, subject_version, digest, authority_role):
        return next((copy.deepcopy(value) for value in self.data.values() if value.get("tenant_id") == tenant_id and value.get("subject_type") == subject_type and value.get("subject_id") == subject_id and value.get("subject_version") == subject_version and value.get("phase5d_authority", {}).get("authority_digest") == digest and value.get("actor_role") == authority_role and value.get("status") == "ACTIVE"), None)
    def record_phase5d(self, record):
        binding = record["phase5d_authority"]
        if self.find_active_phase5d_binding(record["tenant_id"], record["subject_type"], record["subject_id"], record["subject_version"], binding["authority_digest"], record["actor_role"]): raise ValueError("duplicate active Phase 5D authority")
        self.save(record)


class IdempotencyMemoryRepository:
    def __init__(self, uow): self.uow = uow; self.data = uow.working.idempotency
    def get(self, key): return self.data.get(key)
    def reserve(self, key, *_): self.uow.failpoint("IDEMPOTENCY_RESERVE")
    def save_result(self, key, result): self.uow.failpoint("IDEMPOTENCY_COMPLETE"); self.data[key] = result


class LifecycleEventMemoryRepository:
    def __init__(self, uow): self.uow = uow
    def append(self, event): self.uow.failpoint("LIFECYCLE_EVENT_APPEND"); self.uow.working.events.append(event)
    def list(self): return tuple(self.uow.working.events)


class OutboxMemoryRepository:
    def __init__(self, uow): self.uow = uow
    def append(self, intent): self.uow.failpoint("OUTBOX_APPEND"); self.uow.working.outbox.append(intent)
    def list(self): return tuple(self.uow.working.outbox)


class UnitOfWork:
    def __init__(self, store):
        self.store = store; self.working = copy.deepcopy(store)
        self.handoffs = AcquisitionHandoffMemoryRepository(self); self.engagements = EngagementMemoryRepository(self)
        self.implementation_handoffs = ImplementationHandoffMemoryRepository(self)
        self.implementation_briefs = ImplementationBriefMemoryRepository(self)
        self.implementation_authorizations = ImplementationAuthorizationMemoryRepository(self)
        self.codex_build_packages = CodexBuildPackageMemoryRepository(self)
        self.build_execution_results = BuildExecutionResultMemoryRepository(self)
        self.qa_results = QAResultMemoryRepository(self)
        self.client_acceptances = ClientAcceptanceMemoryRepository(self)
        self.deployment_authorizations = DeploymentAuthorizationMemoryRepository(self)
        self.deployment_executions = DeploymentExecutionMemoryRepository(self)
        self.human_approvals = HumanApprovalMemoryRepository(self)
        self.idempotency = IdempotencyMemoryRepository(self)
        self.lifecycle_events = LifecycleEventMemoryRepository(self); self.outbox = OutboxMemoryRepository(self)
    def failpoint(self, name):
        if self.working.fail_stage == name: raise RuntimeError("injected failpoint")
    def commit(self): self.failpoint("COMMIT"); self.store.__dict__.update(self.working.__dict__)


class Executor:
    def __init__(self, validator, pipeline, store, clock=lambda: "2030-01-15T15:00:00Z", ids=lambda: str(uuid.uuid4()), uow_factory=UnitOfWork, **_ignored):
        self.validator = validator; self.pipeline = pipeline; self.store = store
        self.clock = clock; self.ids = ids; self.uow_factory = uow_factory

    def execute(self, raw, context):
        first = self.validator.prepare(raw)
        if isinstance(first, ValidationFailure): return {"result": "VALIDATION_FAILED", "reason_code": first.reason.value}
        prepared = first.prepared
        uow = None
        try:
            uow = self.uow_factory(self.store)
            if hasattr(uow, "bind_trusted_context"):
                uow.bind_trusted_context(context)
        except (ValueError, RuntimeError):
            if uow is not None and hasattr(uow, "close"):
                uow.close()
            return {"result": "REJECTED", "reason_code": "PREREQUISITE_STATE_INVALID"}
        committed = False
        try:
            key = (prepared.tenant_id, context.principal_id, prepared.command_type, prepared.subject_type, idempotency_scope(prepared), prepared.idempotency_key)
            request_fingerprint = fingerprint(raw); prior = uow.idempotency.get(key)
            if prior:
                return {"result": "DUPLICATE", "reason_code": "DUPLICATE_REQUEST", "prior_result_reference": prior["command_id"]} if prior["fingerprint"] == request_fingerprint else {"result": "CONFLICT", "reason_code": "IDEMPOTENCY_SEMANTIC_MISMATCH"}
            guarded = prepare_and_guard_command(self.validator, self.pipeline, raw, context, self.store.snapshot(prepared, context), self.clock())
            if not hasattr(guarded, "guarded"): return {"result": "REJECTED", "reason_code": guarded.reason.value}
            race = uow.idempotency.reserve(key, request_fingerprint, prepared)
            if race: return {"result": "DUPLICATE", "reason_code": "DUPLICATE_REQUEST", "prior_result_reference": race["command_id"]} if race["fingerprint"] == request_fingerprint else {"result": "CONFLICT", "reason_code": "IDEMPOTENCY_SEMANTIC_MISMATCH"}
            uow.failpoint("AUTHORITATIVE_WRITE"); self._handle(uow, prepared, context)
            event = self._event(prepared, uow); uow.lifecycle_events.append(event)
            uow.outbox.append({"event_id": event["event_id"], "status": "PENDING"})
            uow.idempotency.save_result(key, {"fingerprint": request_fingerprint, "command_id": prepared.command_id}); uow.commit()
            committed = True
        except (ValueError, RuntimeError):
            return {"result": "REJECTED", "reason_code": "PREREQUISITE_STATE_INVALID"}
        finally:
            if not committed and hasattr(uow, "rollback"):
                uow.rollback()
            if hasattr(uow, "close"):
                uow.close()
        return {"result": "ACCEPTED", "reason_code": "COMMAND_ACCEPTED", "authoritative_record_reference": prepared.subject_id}

    def _handle(self, uow, prepared, context):
        now = self.clock()
        if prepared.command_type in DEPLOYMENT_EXECUTION_COMMANDS: return DeploymentExecutionHandler(uow).execute(prepared.command_type, prepared, context, now, prepared.command_id)
        if prepared.command_type in DEPLOYMENT_AUTHORIZATION_COMMANDS: return DeploymentAuthorizationHandler(uow).execute(prepared.command_type, prepared, context, now, prepared.command_id)
        if prepared.command_type in CLIENT_ACCEPTANCE_COMMANDS: return ClientAcceptanceHandler(uow).execute(prepared.command_type, prepared, context, now, prepared.command_id)
        if prepared.command_type in QA_RESULT_COMMANDS: return QAResultHandler(uow).execute(prepared.command_type, prepared, context, now, prepared.command_id)
        if prepared.command_type in BUILD_EXECUTION_COMMANDS: return BuildExecutionResultHandler(uow).execute(prepared.command_type, prepared, context, now, prepared.command_id)
        if prepared.command_type in CODEX_BUILD_PACKAGE_COMMANDS: return CodexBuildPackageHandler(uow).execute(prepared.command_type, prepared, context, now, prepared.command_id)
        if prepared.command_type in IMPLEMENTATION_AUTHORIZATION_COMMANDS: return ImplementationAuthorizationHandler(uow).execute(prepared.command_type, prepared, context, now, prepared.command_id)
        if prepared.command_type in IMPLEMENTATION_BRIEF_COMMANDS: return ImplementationBriefHandler(uow).execute(prepared.command_type, prepared, context, now, prepared.command_id)
        if prepared.command_type == "AcceptAcquisitionHandoff":
            record = uow.handoffs.get(prepared.tenant_id, prepared.subject_id)
            if not record or record.get("accepted"): raise ValueError("handoff unavailable")
            record["accepted_at"] = now; uow.handoffs.save_accepted(record); return record
        if prepared.command_type == "OpenEngagement":
            payload = prepared.payload; source_ref = payload["accepted_handoff_reference"]
            source = uow.handoffs.get(prepared.tenant_id, source_ref["reference_id"])
            if not source or not source.get("accepted") or source_ref["reference_version"] != source["handoff_version"] or uow.engagements.exists(prepared.tenant_id, prepared.subject_id): raise ValueError("exact accepted handoff required")
            if payload["canonical_account_reference"] != source["canonical_account_reference"] or payload["acquisition_opportunity_reference"] != source["acquisition_opportunity_reference"]: raise ValueError("source binding mismatch")
            record = {"engagement_id": prepared.subject_id, "tenant_id": prepared.tenant_id, "engagement_state": "OPEN", "record_version": 1, "engagement_version": 1, "opened_at": now, "created_at": now, "updated_at": now, **copy.deepcopy(payload)}
            uow.engagements.save(record); return record
        raise ValueError("registered command has no handler")

    def _event_record(self, prepared, event_type, record, reference_type, metadata):
        return {
            "event_id": self.ids(), "event_type": event_type, "event_schema_version": 1,
            "tenant_id": prepared.tenant_id, "engagement_id": record.get("engagement_id"),
            "authoritative_subject_reference": {"reference_type": reference_type, "reference_id": prepared.subject_id},
            "authoritative_subject_version": record["record_version"], "occurred_at": self.clock(),
            "producer_reference": "command.service-01", "correlation_id": prepared.correlation_id,
            "command_id": prepared.command_id, "subject_id": prepared.subject_id,
            "idempotency_key": prepared.idempotency_key, "visibility": "TENANT_OPERATIONAL",
            "sanitized_metadata": metadata,
        }

    def _event(self, prepared, uow):
        command = prepared.command_type
        if command in DEPLOYMENT_EXECUTION_COMMANDS:
            record = uow.deployment_executions.get(prepared.tenant_id, prepared.subject_id)
            metadata = {"authority_stage": "DEPLOYMENT_EXECUTION", "deployment_execution_id": prepared.subject_id, "execution_attempt": record["execution_attempt"], "status": record["status"]}
            return self._event_record(prepared, DEPLOYMENT_EXECUTION_EVENTS[command], record, "DEPLOYMENT_EXECUTION", metadata)
        if command in DEPLOYMENT_AUTHORIZATION_COMMANDS:
            version = prepared.payload.get("authorization_version") or prepared.payload.get("subject_version")
            record = uow.deployment_authorizations.get_version(prepared.tenant_id, prepared.subject_id, version)
            metadata = {"authority_stage": "DEPLOYMENT_AUTHORIZATION", "deployment_authorization_id": prepared.subject_id, "state": record["state"], "deployment_authorized": record["state"] == "ACTIVE"}
            if command == "RecordDeploymentAuthorizationApproval": metadata["approval_id"] = prepared.command_id
            if command == "ReviseDeploymentAuthorization": metadata["superseded_version"] = prepared.payload["supersedes_deployment_authorization_reference"]["reference_version"]
            return self._event_record(prepared, DEPLOYMENT_AUTHORIZATION_EVENTS[command], record, "DEPLOYMENT_AUTHORIZATION", metadata)
        if command in CLIENT_ACCEPTANCE_COMMANDS:
            version = prepared.payload["acceptance_version"]
            record = uow.client_acceptances.get_version(prepared.tenant_id, prepared.subject_id, version)
            metadata = {"authority_stage": "CLIENT_ACCEPTANCE", "client_acceptance_id": prepared.subject_id, "qa_passed": True, "client_accepted": record["decision"] == "ACCEPTED", "deployment_authorized": False}
            return self._event_record(prepared, CLIENT_ACCEPTANCE_EVENTS[command], record, "CLIENT_ACCEPTANCE", metadata)
        if command in QA_RESULT_COMMANDS:
            record = uow.qa_results.get(prepared.tenant_id, prepared.subject_id)
            metadata = {"authority_stage": "QA_RESULT", "qa_result_id": prepared.subject_id, "qa_attempt": record["qa_attempt"], "overall_status": record["overall_status"], "qa_passed": record["overall_status"] == "PASSED", "client_accepted": False, "deployment_authorized": False}
            return self._event_record(prepared, QA_RESULT_EVENTS[command], record, "QA_RESULT", metadata)
        if command in BUILD_EXECUTION_COMMANDS:
            record = uow.build_execution_results.get(prepared.tenant_id, prepared.subject_id)
            metadata = {"authority_stage": "BUILD_EXECUTION", "build_execution_result_id": prepared.subject_id, "execution_attempt": record["execution_attempt"], "status": record["status"], "qa_passed": False, "client_accepted": False, "deployment_authorized": False}
            return self._event_record(prepared, BUILD_EXECUTION_EVENTS[command], record, "BUILD_EXECUTION_RESULT", metadata)
        if command in CODEX_BUILD_PACKAGE_COMMANDS:
            version = prepared.payload.get("package_version") or prepared.payload.get("subject_version")
            record = uow.codex_build_packages.get_version(prepared.tenant_id, prepared.subject_id, version)
            metadata = {"authority_stage": "CODEX_BUILD_PACKAGE", "codex_build_package_id": prepared.subject_id, "state": record["state"]}
            if command == "RecordCodexBuildPackageApproval": metadata["approval_id"] = prepared.command_id
            if command == "ReviseCodexBuildPackage": metadata["superseded_version"] = prepared.payload["supersedes_codex_build_package_reference"]["reference_version"]
            return self._event_record(prepared, CODEX_BUILD_PACKAGE_EVENTS[command], record, "CODEX_BUILD_PACKAGE", metadata)
        if command in IMPLEMENTATION_AUTHORIZATION_COMMANDS:
            version = prepared.payload.get("authorization_version") or prepared.payload.get("subject_version")
            record = uow.implementation_authorizations.get_version(prepared.tenant_id, prepared.subject_id, version) if version else uow.implementation_authorizations.get_current(prepared.tenant_id, prepared.subject_id)
            metadata = {"authority_stage": "IMPLEMENTATION_AUTHORIZATION", "implementation_authorization_id": prepared.subject_id, "state": record["state"]}
            if command == "RecordImplementationAuthorizationApproval": metadata["approval_id"] = prepared.command_id
            if command == "ReviseImplementationAuthorization": metadata["superseded_version"] = prepared.payload["supersedes_implementation_authorization_reference"]["reference_version"]
            return self._event_record(prepared, IMPLEMENTATION_AUTHORIZATION_EVENTS[command], record, "IMPLEMENTATION_AUTHORIZATION", metadata)
        if command in IMPLEMENTATION_BRIEF_COMMANDS:
            version = prepared.payload.get("implementation_brief_version") or prepared.payload.get("subject_version")
            record = uow.implementation_briefs.get_version(prepared.tenant_id, prepared.subject_id, version)
            metadata = {"authority_stage": "IMPLEMENTATION_BRIEF", "implementation_brief_id": prepared.subject_id, "state": record["state"]}
            if command == "RecordImplementationBriefApproval": metadata["approval_id"] = prepared.command_id
            if command == "ReviseImplementationBrief": metadata["superseded_version"] = prepared.payload["supersedes_implementation_brief_reference"]["reference_version"]
            return self._event_record(prepared, IMPLEMENTATION_BRIEF_EVENTS[command], record, "IMPLEMENTATION_BRIEF", metadata)
        if command == "AcceptAcquisitionHandoff":
            record = uow.handoffs.get(prepared.tenant_id, prepared.subject_id); record["record_version"] = record.get("record_version", 1)
            return self._event_record(prepared, "engagement.handoff.accepted", record, "ACQUISITION_HANDOFF", {"handoff_id": prepared.subject_id})
        if command == "OpenEngagement":
            record = uow.engagements.get(prepared.tenant_id, prepared.subject_id)
            return self._event_record(prepared, "engagement.opened", record, "ENGAGEMENT", {"engagement_id": prepared.subject_id})
        raise ValueError("registered command has no event")
