"""Strict, sanitized validation for local engineering evidence bundles."""
from __future__ import annotations

import copy
import hashlib
import json
import re
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from avuhz_runtime.implementation_handoff import canonical_digest
from avuhz_runtime.schema_registry import SchemaRegistry

EVIDENCE_SCHEMA_ID = "urn:avuhz:schema:contracts:orchestration:engineering-dry-run-evidence:v1"
_REQUIRED_STEPS = ("BUILD", "TESTS", "CONTRACTS", "MIGRATIONS", "SECURITY", "PACKAGE_VERIFICATION")
_SECRET_KEYS = frozenset({"credential", "password", "private_key", "secret", "token", "authenticated_url", "connection_string"})
_SECRET_VALUE = re.compile(
    r"(?i)(?:password|passwd|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|authorization)\s*[:=]\s*\S+|"
    r"bearer\s+[a-z0-9._~+/=-]{8,}|\b(?:https?|postgres(?:ql)?|mysql)://[^\s/:]+:[^\s/@]+@"
)


class EvidenceValidationError(ValueError):
    pass


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def repository_digest(repository_root: Path) -> str:
    result = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=repository_root, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False,
    )
    if result.returncode:
        raise EvidenceValidationError("SOURCE_INVENTORY_UNAVAILABLE")
    paths = sorted(item.decode("utf-8") for item in result.stdout.split(b"\0") if item)
    digest = hashlib.sha256()
    for relative in paths:
        path = repository_root / relative
        if not path.is_file() or path.is_symlink():
            raise EvidenceValidationError("SOURCE_INVENTORY_INVALID")
        encoded = relative.encode("utf-8")
        digest.update(len(encoded).to_bytes(4, "big")); digest.update(encoded)
        content_digest = bytes.fromhex(file_digest(path).removeprefix("sha256:"))
        digest.update(content_digest)
    return "sha256:" + digest.hexdigest()


def git_identity(repository_root: Path) -> tuple[str, str, bool]:
    def value(*args):
        result = subprocess.run(["git", *args], cwd=repository_root, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False)
        if result.returncode:
            raise EvidenceValidationError("GIT_IDENTITY_UNAVAILABLE")
        return result.stdout.strip()
    commit = value("rev-parse", "HEAD")
    branch = value("branch", "--show-current") or "detached"
    clean = not value("status", "--short")
    return commit, branch, clean


def _reject_sensitive(value) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = key.lower().replace("-", "_")
            if normalized in _SECRET_KEYS or any(part in normalized for part in _SECRET_KEYS):
                raise EvidenceValidationError("SENSITIVE_FIELD_PROHIBITED")
            _reject_sensitive(child)
    elif isinstance(value, list):
        for child in value: _reject_sensitive(child)
    elif isinstance(value, str) and _SECRET_VALUE.search(value):
        raise EvidenceValidationError("SENSITIVE_VALUE_PROHIBITED")


def step_digest(step: dict) -> str:
    projection = {key: copy.deepcopy(value) for key, value in step.items() if key != "result_digest"}
    return canonical_digest(projection)


def bundle_digest(bundle: dict) -> str:
    projection = {key: copy.deepcopy(value) for key, value in bundle.items() if key != "bundle_digest"}
    return canonical_digest(projection)


def validate_bundle(bundle: dict, schema_root: Path) -> None:
    _reject_sensitive(bundle)
    registry = SchemaRegistry(schema_root)
    validator = Draft202012Validator(registry.expanded(EVIDENCE_SCHEMA_ID), format_checker=FormatChecker())
    if list(validator.iter_errors(bundle)):
        raise EvidenceValidationError("EVIDENCE_SCHEMA_INVALID")
    steps = bundle["steps"]
    if tuple(step["step_id"] for step in steps) != _REQUIRED_STEPS:
        raise EvidenceValidationError("EVIDENCE_STEP_ORDER_INVALID")
    if any(step["result_digest"] != step_digest(step) for step in steps):
        raise EvidenceValidationError("STEP_DIGEST_INVALID")
    if bundle["review_gate"]["required_step_digests"] != [step["result_digest"] for step in steps]:
        raise EvidenceValidationError("REVIEW_BINDING_INVALID")
    if bundle["bundle_digest"] != bundle_digest(bundle):
        raise EvidenceValidationError("BUNDLE_DIGEST_INVALID")
    decision = bundle["readiness_decision"]
    approval = bundle["simulated_approval"]
    all_pass = all(step["status"] == "PASS" for step in steps) and bundle["artifact"] is not None
    expected_review = "READY_FOR_SIMULATED_REVIEW" if all_pass else "BLOCKED"
    if bundle["review_gate"]["status"] != expected_review:
        raise EvidenceValidationError("REVIEW_DERIVATION_INVALID")
    requested = approval["requested_decision"]
    if all_pass:
        expected_approval = {
            "APPROVE": "SIMULATED_APPROVAL_RECORDED",
            "DECLINE": "SIMULATED_DECLINE_RECORDED",
            "NOT_RECORDED": "NOT_RECORDED",
        }[requested]
    else:
        expected_approval = "BLOCKED_BY_EVIDENCE"
    if approval["status"] != expected_approval:
        raise EvidenceValidationError("SIMULATED_APPROVAL_DERIVATION_INVALID")
    if (requested == "NOT_RECORDED") != (approval["reviewer_reference"] is None):
        raise EvidenceValidationError("SIMULATED_REVIEWER_BINDING_INVALID")
    for step in steps:
        if step["passed_count"] + step["failed_count"] != step["check_count"]:
            raise EvidenceValidationError("EVIDENCE_COUNT_INVALID")
        started = datetime.fromisoformat(step["started_at"].replace("Z", "+00:00"))
        completed = datetime.fromisoformat(step["completed_at"].replace("Z", "+00:00"))
        if completed < started:
            raise EvidenceValidationError("EVIDENCE_TIME_ORDER_INVALID")
    created = datetime.fromisoformat(bundle["created_at"].replace("Z", "+00:00"))
    expires = datetime.fromisoformat(bundle["expires_at"].replace("Z", "+00:00"))
    if expires <= created or expires - created > timedelta(minutes=30):
        raise EvidenceValidationError("EVIDENCE_VALIDITY_INVALID")
    simulation_ready = all_pass and expected_review == "READY_FOR_SIMULATED_REVIEW" and expected_approval == "SIMULATED_APPROVAL_RECORDED" and not decision["missing_requirements"]
    if (decision["status"] == "SIMULATION_READY") != simulation_ready:
        raise EvidenceValidationError("READINESS_DERIVATION_INVALID")
    if decision["production_ready"] or decision["deployment_authorized"] or decision["production_mutation_performed"]:
        raise EvidenceValidationError("PRODUCTION_AUTHORITY_PROHIBITED")


def verify_bundle(bundle: dict, repository_root: Path, artifact_path: Path | None, now: datetime) -> tuple[str, ...]:
    issues = []
    try:
        validate_bundle(bundle, repository_root / "contracts/schemas/v1")
    except EvidenceValidationError as error:
        return (str(error),)
    if now.tzinfo is None:
        return ("VERIFICATION_CLOCK_INVALID",)
    from .pipeline import _catalog_digest
    if bundle["provenance"]["command_catalog_digest"] != _catalog_digest():
        issues.append("PIPELINE_CATALOG_STALE")
    expires = datetime.fromisoformat(bundle["expires_at"].replace("Z", "+00:00"))
    if now.astimezone(timezone.utc) >= expires:
        issues.append("EVIDENCE_STALE")
    try:
        commit, branch, _ = git_identity(repository_root)
        current_source = repository_digest(repository_root)
    except EvidenceValidationError as error:
        issues.append(str(error))
    else:
        source = bundle["source"]
        if commit != source["git_commit"] or branch != source["git_branch"] or current_source != source["source_digest"]:
            issues.append("SOURCE_BINDING_STALE")
    artifact = bundle["artifact"]
    if artifact is None or artifact_path is None or not artifact_path.is_file():
        issues.append("ARTIFACT_MISSING")
    elif artifact_path.name != artifact["artifact_filename"] or file_digest(artifact_path) != artifact["artifact_digest"]:
        issues.append("ARTIFACT_DIGEST_MISMATCH")
    return tuple(sorted(set(issues)))


def load_bundle(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise EvidenceValidationError("EVIDENCE_UNREADABLE") from error
    if not isinstance(value, dict):
        raise EvidenceValidationError("EVIDENCE_SCHEMA_INVALID")
    return value
