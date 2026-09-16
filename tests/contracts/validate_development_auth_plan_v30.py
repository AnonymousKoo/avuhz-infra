#!/usr/bin/env python3
"""Validate pristine DEVELOPMENT AUTH v30 synthetic-token preparation."""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.authorization_plan import (
    approval_digest,
    authorize_step,
    initial_progress,
    plan_digest,
    record_step_outcome,
    validate_plan,
    validate_progress,
)
from avuhz_runtime.implementation_handoff import canonical_digest
from avuhz_service.development import (
    DEVELOPMENT_AUTH_ISSUER,
    DEVELOPMENT_AUTH_PROJECT_REF,
    DEVELOPMENT_SERVICE_AUDIENCE,
)

SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
BASE = ROOT / "contracts/plans/v1"
PLAN_PATH = BASE / "development-auth-integration-v30.plan.json"
PROGRESS_PATH = BASE / "development-auth-integration-v30.progress.json"
REVIEW_PATH = BASE / "development-auth-v29-precanonical-review.evidence.json"
V24_PATH = BASE / "development-auth-step1-v24-success.evidence.json"
V26_PATH = BASE / "development-auth-step1-v26-success.evidence.json"
V28_PATH = BASE / "development-auth-step1-v28-success.evidence.json"
RETIREMENT_PATH = BASE / "development-auth-admin-bootstrap-retirement.evidence.json"
WORKFLOW_PATH = ROOT / ".github/workflows/development-auth-v30-token-validation.yml"
EXECUTOR_PATH = ROOT / "scripts/development_auth_v30_token_executor.py"
JWT_PATH = ROOT / "src/avuhz_service/development_supabase_jwt.py"
IDENTITY_PATH = ROOT / "src/avuhz_service/development_supabase_identity.py"

PLAN_ID = "d89b1ba0-6a85-4897-8d40-33af4de45e4a"
PLAN_DIGEST = "sha256:8b1d92022e192c73b856d5d399843a3ee4c9dac4d08e9c7778293f765f8ebd6f"
PLAN_RAW_DIGEST = "sha256:bb2cb2507c57eaa43a2ee255de1eb730266df5c53cee642e187fd9e282669453"
PROGRESS_ID = "8255b2ec-d7bf-4276-933a-da5490e35bff"
PROGRESS_DIGEST = "sha256:ed6c3afa8aaed2f5f62431c0b6d0976ab35bde08dc7d9a0651725d33e15d7241"
PROGRESS_RAW_DIGEST = "sha256:eed7c19d3f4b8c7c208a7b700775c34e06fda4176ba62c6a811f6f49f0b37f2e"
REVIEW_RAW_DIGEST = "sha256:9177fddb267c8e7735e19813a1f9c53f60403450c2c90d62fbb5ae75cf3f1f6d"
EXECUTOR_RAW_DIGEST = "sha256:6e3e8e79cdc8f726b3f0b3981fdf00045a3beac70dece3898d91c3c81bf5d9a5"
WORKFLOW_RAW_DIGEST = "sha256:0016a395b15c34c66d0408efc7417d6c83e5452eb7fb9f99f5bd5c899824d012"
PROJECT = "pwlhruwutoitnieactol"
DATA_PROJECT = "gnuqaefotwgkwurjpyik"
WINDOW_START = "2026-09-15T23:00:00Z"
WINDOW_END = "2026-09-16T05:00:00Z"
SUBJECT_DIGEST = "sha256:96ed2639ff64f1c0712d9548f8d524c4cd7f3025d30013c8857aace8661a84a5"
TENANT_ID = "1ad3998c-92ab-4a36-9d1c-ed97f2fa98f0"
PRINCIPAL = "subject.development-synthetic-user"
RECOVERY_DIGEST = "sha256:236308020509e3c25000ac446ae0068da939880418daa624a5614ff484bfa05d"
LIFECYCLE_DIGEST = "sha256:10828dc23324d2e83e6c9dddf26261102c8a212e2531541d590622c7b7b4248e"
VALIDATION_DIGEST = "sha256:7123897737828e0f8b1d3c1e37ed12ee768e17cd674309cacab1169415327456"
V24_DIGEST = "sha256:41614e42a7a65b6686affef494ad5ea00894c4fee2507331430ec35c0f80488e"
V26_DIGEST = "sha256:15d05b54d2f337ead4b4ed6f9881aef33c6063de29ed4501a805255e7999c2ba"
V28_DIGEST = "sha256:d756b6baa3fbd4fc743b80d436e6578e66806658855b3c669690eb95dc79814c"
RETIREMENT_DIGEST = "sha256:9e310b6b114b4b4a2b71f35a6f9b6324231f3f071a2fdecc5d589d7b91e635ef"
FRESH_SECRET = "AVUHZ_DEVELOPMENT_SUPABASE_AUTH_TOKEN_VALIDATION_V30_EPHEMERAL"
PROVIDER_READ_SECRET = "AVUHZ_DEVELOPMENT_SUPABASE_PROVIDER_READ_TOKEN"
PUBLISHABLE_SECRET = "AVUHZ_DEVELOPMENT_SUPABASE_PUBLISHABLE_KEY"

STEP_IDS = [
    "development.auth.v30.step.01.generate-existing-user-recovery-link",
    "development.auth.v30.step.02.consume-token-and-revoke-session",
    "development.auth.v30.step.03.validate-token-exact",
]


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def raw_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def binding(step: dict, binding_id: str) -> dict:
    matches = [item for item in step["binding_declarations"] if item["binding_id"] == binding_id]
    assert len(matches) == 1, binding_id
    return matches[0]


def request_for(plan: dict, progress: dict, index: int, credential_class: str) -> dict:
    step = plan["steps"][index]
    required = []
    for item in step["required_evidence"]:
        if item["source_step_id"] is None:
            digest = item["exact_digest"]
        else:
            source_index = plan["ordered_step_ids"].index(item["source_step_id"])
            matches = [
                evidence
                for evidence in progress["step_states"][source_index]["evidence"]
                if evidence["evidence_type"] == item["evidence_type"]
            ]
            assert len(matches) == 1
            digest = matches[0]["evidence_digest"]
        required.append({"evidence_type": item["evidence_type"], "evidence_digest": digest})
    prior = [
        evidence["evidence_digest"]
        for state in progress["step_states"][:index]
        for evidence in state["evidence"]
    ]
    return {
        "plan_id": plan["plan_id"],
        "plan_version": plan["plan_version"],
        "plan_digest": plan["plan_digest"],
        "environment": plan["environment"],
        "provider_reference": plan["target"]["provider_reference"],
        "project_reference": plan["target"]["project_reference"],
        "responsibility": plan["target"]["responsibility"],
        "issuer_reference": plan["target"]["issuer_reference"],
        "audience_reference": plan["target"]["audience_reference"],
        "step_id": step["step_id"],
        "resource_reference": step["resource"]["resource_reference"],
        "resource_version": step["resource"]["exact_version"],
        "resource_digest": step["resource"]["exact_digest"],
        "operation": step["operation"],
        "execution_class": step["execution_class"],
        "credential_class": credential_class,
        "required_evidence": required,
        "prior_evidence_digests": prior,
        "unexpected_remote_state": False,
        "extra_privileges": False,
        "unauthorized_migration_surface": False,
        "scope_expansion": False,
    }


def assertion(binding_id: str, phase: str, value_class: str, evidence_type: str, evidence_digest: str, value_digest: str | None, recorded_at: str, source_step_id: str | None = None, digest_policy: str = "REQUIRED", persistence_policy: str = "DIGEST_ONLY") -> dict:
    return {
        "binding_id": binding_id,
        "phase": phase,
        "value_class": value_class,
        "source_step_id": source_step_id,
        "evidence_type": evidence_type,
        "evidence_digest": evidence_digest,
        "digest_policy": digest_policy,
        "persistence_policy": persistence_policy,
        "sanitized_value": None,
        "value_digest": value_digest,
        "recorded_at": recorded_at,
    }


def exercise_ephemeral_handoff(plan: dict) -> None:
    """Prove the engine carries only evidence for the token and a digest for cleanup."""
    approval = {
        "approval_id": "8ce8c47d-9d28-4c89-8c47-8bc5e8460fe2",
        "plan_id": PLAN_ID,
        "plan_version": 30,
        "plan_digest": PLAN_DIGEST,
        "owner_identity": "github:AnonymousKoo",
        "decision": "APPROVE",
        "environment": "DEVELOPMENT",
        "effective_at": WINDOW_START,
        "expires_at": WINDOW_END,
        "approved_at": "2026-09-15T22:59:00Z",
        "status": "ACTIVE",
        "authority_scope": "EXACT_PLAN_ONLY",
        "approval_digest": "",
    }
    approval["approval_digest"] = approval_digest(approval)
    progress = initial_progress(plan, SCHEMA_ROOT, "57d1bf64-a280-454d-a93d-c156c3f8a4ec", plan["created_at"])

    at1 = "2026-09-15T23:00:01Z"
    cap_digest = "sha256:" + "1" * 64
    live_digest = "sha256:" + "2" * 64
    cap_value = "sha256:" + "3" * 64
    live_value = "sha256:" + "4" * 64
    progress = authorize_step(
        plan,
        approval,
        progress,
        request_for(plan, progress, 0, "SUPABASE_AUTH_ADMIN_EPHEMERAL"),
        SCHEMA_ROOT,
        at1,
        trusted_preflight_assertions=[
            assertion("binding.development.auth.v30.admin-executor-capability", "RESOLVED_BY_STEP_PREFLIGHT", "CONFIGURATION_REFERENCE", "auth.admin-executor-capability.observed", cap_digest, cap_value, at1),
            assertion("binding.development.auth.v30.live-preflight", "RESOLVED_BY_STEP_PREFLIGHT", "CONFIGURATION_REFERENCE", "auth.synthetic-token.live-preflight.observed", live_digest, live_value, at1),
        ],
    )
    link_evidence = "sha256:" + "5" * 64
    progress = record_step_outcome(
        plan,
        approval,
        progress,
        STEP_IDS[0],
        "SUCCEEDED",
        "PASS",
        [{"evidence_type": "auth.synthetic-recovery-link.generated", "evidence_reference": "provider.execution.v30.step1.test", "evidence_digest": link_evidence, "recorded_at": at1}],
        plan["steps"][0]["expected_postcondition"],
        None,
        SCHEMA_ROOT,
        at1,
    )

    at2 = "2026-09-15T23:00:02Z"
    progress = authorize_step(plan, approval, progress, request_for(plan, progress, 1, "SYNTHETIC_IDENTITY"), SCHEMA_ROOT, at2)
    ephemeral_in = next(item for item in progress["step_states"][1]["binding_assertions"] if item["binding_id"] == "binding.development.auth.v30.synthetic-recovery-link")
    assert ephemeral_in["evidence_digest"] == link_evidence
    assert ephemeral_in["sanitized_value"] is None and ephemeral_in["value_digest"] is None

    lifecycle_evidence = "sha256:" + "6" * 64
    progress = record_step_outcome(
        plan,
        approval,
        progress,
        STEP_IDS[1],
        "SUCCEEDED",
        "PASS",
        [{"evidence_type": "auth.synthetic-session.lifecycle-completed", "evidence_reference": "provider.execution.v30.step2.test", "evidence_digest": lifecycle_evidence, "recorded_at": at2}],
        plan["steps"][1]["expected_postcondition"],
        None,
        SCHEMA_ROOT,
        at2,
        binding_assertions=[
            assertion("binding.development.auth.v30.session-cleanup", "PRODUCED_BY_CURRENT_STEP", "CONTENT_DIGEST", "auth.synthetic-session.lifecycle-completed", lifecycle_evidence, LIFECYCLE_DIGEST, at2)
        ],
    )

    at3 = "2026-09-15T23:00:03Z"
    progress = authorize_step(plan, approval, progress, request_for(plan, progress, 2, "EPHEMERAL_SYNTHETIC_ACCESS_TOKEN"), SCHEMA_ROOT, at3)
    by_id = {item["binding_id"]: item for item in progress["step_states"][2]["binding_assertions"]}
    ephemeral_token = by_id["binding.development.auth.v30.synthetic-access-token"]
    assert ephemeral_token["evidence_digest"] == lifecycle_evidence
    assert ephemeral_token["sanitized_value"] is None and ephemeral_token["value_digest"] is None
    cleanup = by_id["binding.development.auth.v30.session-cleanup"]
    assert cleanup["evidence_digest"] == lifecycle_evidence
    assert cleanup["value_digest"] == LIFECYCLE_DIGEST
    assert cleanup["sanitized_value"] is None


def main() -> int:
    plan = load(PLAN_PATH)
    progress = load(PROGRESS_PATH)
    review = load(REVIEW_PATH)
    validate_plan(plan, SCHEMA_ROOT)
    validate_progress(plan, progress, SCHEMA_ROOT)

    assert raw_digest(PLAN_PATH) == PLAN_RAW_DIGEST
    assert raw_digest(PROGRESS_PATH) == PROGRESS_RAW_DIGEST
    assert raw_digest(REVIEW_PATH) == REVIEW_RAW_DIGEST
    assert raw_digest(EXECUTOR_PATH) == EXECUTOR_RAW_DIGEST
    assert raw_digest(WORKFLOW_PATH) == WORKFLOW_RAW_DIGEST
    assert plan["plan_id"] == PLAN_ID and plan["plan_version"] == 30
    assert plan["plan_digest"] == PLAN_DIGEST and plan_digest(plan) == PLAN_DIGEST
    assert plan["definition_status"] == "READY_FOR_APPROVAL"
    assert plan["authority_effect"] == "NONE_UNTIL_SEPARATELY_APPROVED"
    assert plan["environment"] == "DEVELOPMENT"
    assert plan["owner_identity"] == "github:AnonymousKoo"
    assert DEVELOPMENT_AUTH_PROJECT_REF == PROJECT
    assert plan["target"] == {
        "provider_class": "identity.provider",
        "provider_reference": "supabase",
        "project_reference": PROJECT,
        "responsibility": "AUTH",
        "issuer_reference": DEVELOPMENT_AUTH_ISSUER,
        "audience_reference": DEVELOPMENT_SERVICE_AUDIENCE,
    }
    assert plan["authorization_window"] == {"binding_state": "BOUND", "starts_at": WINDOW_START, "expires_at": WINDOW_END}
    assert plan["ordered_step_ids"] == STEP_IDS
    assert len(plan["steps"]) == 3

    assert review["record_type"] == "DEVELOPMENT_AUTH_V29_PRECANONICAL_REVIEW"
    assert review["repository_state"] == "LOCAL_UNMERGED_DRAFT_ONLY"
    assert review["outcome"] == "REJECTED_PRECANONICAL_UNEXECUTED"
    assert review["candidate_plan_version"] == 29
    assert review["candidate_plan_digest"] == "sha256:8dbd7208e072b3a1181911823f43b8906451ab7031b188f84a264eb6758cd6a0"
    assert review["findings"] == {
        "magiclink_missing_user_behavior": "CAN_CONVERT_TO_SIGNUP_AND_CREATE_USER",
        "plan_identity_create_policy": "PROHIBITED",
        "management_api_key_reveal_behavior": "CAN_RETURN_SECRET_KEY_MATERIAL_TO_RUNNER",
        "least_privilege_result": "FAIL_CLOSED",
    }
    assert review["continuation_rule"] == "DO_NOT_MERGE_OR_EXECUTE_V29; CREATE_FRESH_FORWARD_ONLY_V30"
    assert all(value is False for value in review["effects"].values())

    assert raw_digest(V24_PATH) == V24_DIGEST
    assert raw_digest(V26_PATH) == V26_DIGEST
    assert raw_digest(V28_PATH) == V28_DIGEST
    assert raw_digest(RETIREMENT_PATH) == RETIREMENT_DIGEST

    expected = initial_progress(plan, SCHEMA_ROOT, PROGRESS_ID, plan["created_at"])
    assert progress == expected
    assert progress["progress_digest"] == PROGRESS_DIGEST
    assert progress["overall_state"] == "NOT_STARTED"
    assert all(state["authorization_state"] == "PENDING" for state in progress["step_states"])
    assert all(state["execution_state"] == "NOT_STARTED" for state in progress["step_states"])
    assert all(state["verification_state"] == "NOT_STARTED" for state in progress["step_states"])
    assert all(state["authorization_consumed"] is False for state in progress["step_states"])

    step1, step2, step3 = plan["steps"]
    assert [step["operation"] for step in plan["steps"]] == [
        "provider.auth-recovery-link.generate-existing-user-one",
        "provider.auth-recovery-link.consume-one-and-revoke-session",
        "provider.auth-token.validate-one",
    ]
    assert [step["execution_class"] for step in plan["steps"]] == ["PROVIDER_MUTATION", "PROVIDER_MUTATION", "PROVIDER_READ"]
    assert [step["resource"]["exact_digest"] for step in plan["steps"]] == [RECOVERY_DIGEST, LIFECYCLE_DIGEST, VALIDATION_DIGEST]
    assert step1["credential_policy"]["allowed_classes"] == ["SUPABASE_AUTH_ADMIN_EPHEMERAL"]
    assert step2["credential_policy"] == {"permitted": True, "allowed_classes": ["SYNTHETIC_IDENTITY"], "values_stored": False}
    assert step3["credential_policy"] == {"permitted": True, "allowed_classes": ["EPHEMERAL_SYNTHETIC_ACCESS_TOKEN"], "values_stored": False}
    assert "identity.create" in step1["prohibited_actions"] and "identity.create" in plan["prohibited_actions"]
    assert "session.issue.additional" in step2["prohibited_actions"]
    assert "session.revoke.other" in step2["prohibited_actions"]
    assert "session.issue" not in step2["prohibited_actions"]
    assert "token.issue" not in step2["prohibited_actions"]
    assert "token.issue.additional" in step2["prohibited_actions"]
    assert step2["correction_reference"] == "correction.cleanup.exact.session.or.stop.owner.review"

    required1 = {item["evidence_type"]: item["exact_digest"] for item in step1["required_evidence"]}
    assert required1 == {
        "auth.synthetic-identity.tenant-metadata.bound": V24_DIGEST,
        "server.capability-policy.verified": V26_DIGEST,
        "hook.enablement.verified": V28_DIGEST,
        "auth.admin-bootstrap.credential-retired": RETIREMENT_DIGEST,
        "auth.synthetic-token.v29-precanonical-rejected": REVIEW_RAW_DIGEST,
    }
    assert step2["dependency_step_ids"] == [STEP_IDS[0]]
    assert step3["dependency_step_ids"] == [STEP_IDS[1]]

    recovery_config = {
        "type": "recovery",
        "identity": "identity.development.synthetic-avuhz",
        "email": "avuhz-development-synthetic@example.invalid",
        "subject_digest": SUBJECT_DIGEST,
        "project_reference": PROJECT,
        "send_email": False,
        "one_time": True,
        "existing_user_required": True,
    }
    lifecycle_config = {
        "issuer": DEVELOPMENT_AUTH_ISSUER,
        "audience": DEVELOPMENT_SERVICE_AUDIENCE,
        "subject_digest": SUBJECT_DIGEST,
        "tenant_id": TENANT_ID,
        "role": "authenticated",
        "aal": "aal1",
        "is_anonymous": False,
        "max_lifetime_seconds": 3600,
        "one_session_only": True,
        "logout_scope": "local",
        "expected_session_count_after": 0,
        "expected_refresh_token_count_after": 0,
        "refresh_token_never_used": True,
    }
    validation_config = {
        "issuer": DEVELOPMENT_AUTH_ISSUER,
        "audience": DEVELOPMENT_SERVICE_AUDIENCE,
        "algorithm": "ES256",
        "tenant_id": TENANT_ID,
        "subject_digest": SUBJECT_DIGEST,
        "principal_reference": PRINCIPAL,
        "caller_type": "HUMAN",
        "capabilities": ["engagement:read"],
        "authority_roles": [],
        "session_revoked_before_validation": True,
    }
    assert canonical_digest(recovery_config) == RECOVERY_DIGEST
    assert canonical_digest(lifecycle_config) == LIFECYCLE_DIGEST
    assert canonical_digest(validation_config) == VALIDATION_DIGEST

    handoff_link = binding(step2, "binding.development.auth.v30.synthetic-recovery-link")
    handoff_token = binding(step3, "binding.development.auth.v30.synthetic-access-token")
    for item in (handoff_link, handoff_token):
        assert item["phase"] == "EPHEMERAL_HANDOFF"
        assert item["value_class"] == "EPHEMERAL_SENSITIVE"
        assert item["digest_policy"] == "PROHIBITED"
        assert item["persistence_policy"] == "PROHIBITED"
    cleanup_source = binding(step2, "binding.development.auth.v30.session-cleanup")
    cleanup_derived = binding(step3, "binding.development.auth.v30.session-cleanup")
    assert cleanup_source["phase"] == "PRODUCED_BY_CURRENT_STEP"
    assert cleanup_derived["phase"] == "DERIVED_FROM_SOURCE_STEP"

    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
    executor = EXECUTOR_PATH.read_text(encoding="utf-8")
    for fragment in (
        "name: DEVELOPMENT AUTH v30 Synthetic Token Validation",
        "workflow_dispatch:",
        "EXECUTE_V30_SYNTHETIC_TOKEN_VALIDATION",
        "environment: development",
        f"AVUHZ_EXPECTED_PROJECT_REF: {PROJECT}",
        f"AVUHZ_PLAN_ID: {PLAN_ID}",
        f"AVUHZ_PLAN_DIGEST: {PLAN_DIGEST}",
        FRESH_SECRET,
        PROVIDER_READ_SECRET,
        PUBLISHABLE_SECRET,
        "persist-credentials: false",
        "tests/contracts/validate_development_auth_plan_v30.py",
        "scripts/development_auth_v30_token_executor.py",
        "V30_EXACT_OWNER_APPROVAL_ABSENT",
    ):
        assert fragment in workflow, fragment
    assert DATA_PROJECT not in workflow
    assert "api.render.com" not in workflow
    assert "/api-keys?reveal=true" not in workflow

    for fragment in (
        '/auth/v1/admin/generate_link',
        '{"type": "recovery", "email": TARGET_EMAIL}',
        'payload.get("action_link")',
        'payload.get("id")',
        'verification_type != "recovery"',
        'V30_RECOVERY_LINK_PROVIDER_REJECTED',
        'V30_RECOVERY_LINK_REQUEST_FAILED',
        'V30_RECOVERY_LINK_RESPONSE_INVALID',
        'V30_RECOVERY_LINK_RESPONSE_SHAPE_INVALID',
        'generated = None',
        'query.get("type") != ["recovery"]',
        '/auth/v1/logout?scope=local',
        'DevelopmentSupabaseEs256JwtVerifier().verify(access_token)',
        'DevelopmentSupabaseIdentityVerifier(',
        'AVUHZ_DEVELOPMENT_SUPABASE_PUBLISHABLE_KEY',
        'publishable_key.startswith("sb_publishable_")',
        'V30_EMERGENCY_CLEANUP_REQUIRED=true',
        'management_api_key_enumeration_used',
        'V30_SANITIZED_RESULT=',
    ):
        assert fragment in executor, fragment
    assert '"type": "magiclink"' not in executor
    assert "/api-keys?reveal=true" not in executor
    assert "resolve_publishable_key" not in executor
    assert DATA_PROJECT not in executor
    assert "api.render.com" not in executor
    assert executor.index('{"type": "recovery", "email": TARGET_EMAIL}') < executor.index('/auth/v1/logout?scope=local')
    assert executor.index('/auth/v1/logout?scope=local') < executor.index('DevelopmentSupabaseEs256JwtVerifier().verify(access_token)')
    for unsafe in (
        "print(access_token", "print(refresh_token", "print(recovery_link",
        "print(admin_secret", "print(publishable_key", "sha256(admin_secret",
        "print(payload", "print(generated", "sha256(access_token",
        "sha256(refresh_token", "sha256(recovery_link", "exc.read(",
    ):
        assert unsafe not in executor, unsafe
    assert re.search(r"sb_secret_[A-Za-z0-9_-]{16,}", executor) is None
    assert re.search(r"sb_publishable_[A-Za-z0-9_-]{16,}", executor) is None
    assert re.search(r"\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", executor) is None

    jwt_source = JWT_PATH.read_text(encoding="utf-8")
    identity_source = IDENTITY_PATH.read_text(encoding="utf-8")
    assert '_ALLOWED_ALGORITHMS = ("ES256",)' in jwt_source
    assert 'audience=DEVELOPMENT_SERVICE_AUDIENCE' in jwt_source
    assert 'issuer=DEVELOPMENT_AUTH_ISSUER' in jwt_source
    assert 'role != "authenticated" or aal != "aal1" or is_anonymous is not False' in identity_source
    assert '_READ_ONLY_CAPABILITIES = frozenset({"engagement:read"})' in identity_source
    assert 'authority_roles=frozenset()' in identity_source

    assert not (BASE / "development-auth-integration-v30.approval.json").exists()
    for path in (
        BASE / "development-auth-integration-v30.execution-progress.json",
        BASE / "development-auth-step1-v30-preflight.evidence.json",
        BASE / "development-auth-step1-v30-success.evidence.json",
        BASE / "development-auth-step2-v30-success.evidence.json",
        BASE / "development-auth-step3-v30-success.evidence.json",
    ):
        assert not path.exists(), path
    assert not (BASE / "development-auth-integration-v29.plan.json").exists()
    assert not (BASE / "development-auth-integration-v29.progress.json").exists()
    assert not (BASE / "development-auth-integration-v29.approval.json").exists()
    assert not (ROOT / ".github/workflows/development-auth-v29-token-validation.yml").exists()
    assert not (ROOT / "scripts/development_auth_v29_token_executor.py").exists()

    exercise_ephemeral_handoff(plan)

    print(
        "DEVELOPMENT_AUTH_V30_PREPARED=PASS "
        "(v29 candidate rejected pre-canonical; existing-user recovery only; pre-bound publishable key; "
        "one session issued then locally revoked before JWT policy validation; ephemeral token handoff stores no token or digest; "
        "pristine/unapproved/unexecuted)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
