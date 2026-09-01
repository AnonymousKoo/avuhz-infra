"""Local engineering evidence and dry-run governance."""

from .evidence import EvidenceValidationError, repository_digest, validate_bundle, verify_bundle
from .pipeline import DryRunPipeline, LocalCommandRunner, PipelineResult
from .authorization_plan import (
    AuthorizationPlanError,
    AuthorizationPlanStop,
    authorize_step,
    initial_progress,
    record_step_outcome,
    validate_approval,
    validate_plan,
    validate_progress,
)

__all__ = [
    "DryRunPipeline", "EvidenceValidationError", "LocalCommandRunner",
    "PipelineResult", "repository_digest", "validate_bundle", "verify_bundle",
    "AuthorizationPlanError", "AuthorizationPlanStop", "authorize_step",
    "initial_progress", "record_step_outcome", "validate_approval",
    "validate_plan", "validate_progress",
]
