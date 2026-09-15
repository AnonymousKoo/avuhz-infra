#!/usr/bin/env python3
"""Execute the bounded DEVELOPMENT AUTH v30 one-token validation lifecycle.

Sensitive provider material exists only in this process memory. This executor never
prints, hashes, writes, or returns the Auth-admin credential, recovery link, access
token, refresh token, publishable API key, or raw provider subject.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import jwt

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.authorization_plan import (  # noqa: E402
    authorize_step,
    record_step_outcome,
    validate_approval,
    validate_plan,
    validate_progress,
)
from avuhz_runtime.implementation_handoff import canonical_digest  # noqa: E402
from avuhz_service.development import (  # noqa: E402
    DEVELOPMENT_AUTH_ISSUER,
    DEVELOPMENT_AUTH_PROJECT_REF,
    DEVELOPMENT_SERVICE_AUDIENCE,
)
from avuhz_service.development_supabase_identity import (  # noqa: E402
    DEVELOPMENT_SYNTHETIC_READ_ONLY_ALLOWLIST,
    DevelopmentSupabaseIdentityVerifier,
)
from avuhz_service.development_supabase_jwt import (  # noqa: E402
    DevelopmentSupabaseEs256JwtVerifier,
)

SCHEMA_ROOT = ROOT / "contracts/schemas/v1"
BASE = ROOT / "contracts/plans/v1"
PLAN_PATH = BASE / "development-auth-integration-v30.plan.json"
PROGRESS_PATH = BASE / "development-auth-integration-v30.progress.json"
APPROVAL_PATH = BASE / "development-auth-integration-v30.approval.json"
HOOK_SQL = ROOT / "supabase/provider-artifacts/development-auth/current/development_auth_custom_access_token_hook_v2.sql"

PLAN_ID = "d89b1ba0-6a85-4897-8d40-33af4de45e4a"
PLAN_DIGEST = "sha256:8b1d92022e192c73b856d5d399843a3ee4c9dac4d08e9c7778293f765f8ebd6f"
PROJECT = "pwlhruwutoitnieactol"
WINDOW_START = "2026-09-15T23:00:00Z"
WINDOW_END = "2026-09-16T05:00:00Z"
TARGET_EMAIL = "avuhz-development-synthetic@example.invalid"
SUBJECT_DIGEST = "sha256:96ed2639ff64f1c0712d9548f8d524c4cd7f3025d30013c8857aace8661a84a5"
TENANT_ID = "1ad3998c-92ab-4a36-9d1c-ed97f2fa98f0"
PRINCIPAL_REFERENCE = "subject.development-synthetic-user"
POLICY_DIGEST = "sha256:864019b6d904f790fab298f0142989e067af65fa735094edc28ffa756de406f6"
RECOVERY_CONFIG_DIGEST = "sha256:236308020509e3c25000ac446ae0068da939880418daa624a5614ff484bfa05d"
LIFECYCLE_CONFIG_DIGEST = "sha256:10828dc23324d2e83e6c9dddf26261102c8a212e2531541d590622c7b7b4248e"
CLEANUP_CONFIG_DIGEST = "sha256:10828dc23324d2e83e6c9dddf26261102c8a212e2531541d590622c7b7b4248e"
VALIDATION_CONFIG_DIGEST = "sha256:7123897737828e0f8b1d3c1e37ed12ee768e17cd674309cacab1169415327456"
HOOK_URI = "pg-functions://postgres/public/avuhz_development_custom_access_token_hook_v1"
HOOK_SIGNATURE = "public.avuhz_development_custom_access_token_hook_v1(jsonb)"
FRESH_ADMIN_ENV = "AVUHZ_DEVELOPMENT_SUPABASE_AUTH_TOKEN_VALIDATION_V30_EPHEMERAL"
PROVIDER_READ_ENV = "AVUHZ_DEVELOPMENT_SUPABASE_PROVIDER_READ_TOKEN"
PUBLISHABLE_ENV = "AVUHZ_DEVELOPMENT_SUPABASE_PUBLISHABLE_KEY"
CONFIRMATION = "EXECUTE_V30_SYNTHETIC_TOKEN_VALIDATION"

STEP1 = "development.auth.v30.step.01.generate-existing-user-recovery-link"
STEP2 = "development.auth.v30.step.02.consume-token-and-revoke-session"
STEP3 = "development.auth.v30.step.03.validate-token-exact"

_CANONICAL_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")


class SafeStop(RuntimeError):
    pass


def stop(code: str) -> None:
    if not re.fullmatch(r"[A-Z0-9_]{3,80}", code):
        code = "V30_SAFE_STOP"
    raise SafeStop(code)


def now_text() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def artifact_digest(value: dict[str, Any]) -> str:
    body = (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    return "sha256:" + hashlib.sha256(body).hexdigest()


def component_digest(value: dict[str, Any]) -> str:
    body = dict(value)
    body.pop("evidence_digest", None)
    return canonical_digest(body)


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        stop("V30_REPOSITORY_ARTIFACT_INVALID")
    if not isinstance(value, dict):
        stop("V30_REPOSITORY_ARTIFACT_INVALID")
    return value


def request_json(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: dict[str, Any] | None = None,
    expected: tuple[int, ...] = (200,),
    error_code: str,
) -> Any:
    data = None if body is None else json.dumps(body, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            if response.status not in expected:
                stop(error_code)
            raw = response.read()
    except SafeStop:
        raise
    except Exception:
        stop(error_code)
    if not raw:
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception:
        stop(error_code)


def management_headers(read_token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {read_token}", "Accept": "application/json"}


def admin_headers(admin_secret: str) -> dict[str, str]:
    return {
        "apikey": admin_secret,
        "Authorization": f"Bearer {admin_secret}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def project_headers(api_key: str, access_token: str) -> dict[str, str]:
    return {
        "apikey": api_key,
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def extract_rows(payload: Any) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            if value and all(not isinstance(child, (dict, list)) for child in value.values()):
                rows.append(value)
            else:
                for child in value.values():
                    walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(payload)
    return rows


def read_only_sql(read_token: str, query: str, error_code: str) -> list[dict[str, Any]]:
    payload = request_json(
        f"https://api.supabase.com/v1/projects/{PROJECT}/database/query/read-only",
        method="POST",
        headers={**management_headers(read_token), "Content-Type": "application/json"},
        body={"query": query},
        expected=(201,),
        error_code=error_code,
    )
    return extract_rows(payload)


def verify_project_and_hook_config(read_token: str) -> dict[str, Any]:
    project = request_json(
        f"https://api.supabase.com/v1/projects/{PROJECT}",
        headers=management_headers(read_token),
        error_code="V30_PROJECT_READ_FAILED",
    )
    if not isinstance(project, dict) or project.get("id") != PROJECT or project.get("ref") != PROJECT:
        stop("V30_PROJECT_MISMATCH")
    if project.get("name") != "DEVELOPMENT AUTH":
        stop("V30_PROJECT_MISMATCH")

    config = request_json(
        f"https://api.supabase.com/v1/projects/{PROJECT}/config/auth",
        headers=management_headers(read_token),
        error_code="V30_AUTH_CONFIG_READ_FAILED",
    )
    if not isinstance(config, dict):
        stop("V30_AUTH_CONFIG_MISMATCH")
    if config.get("hook_custom_access_token_enabled") is not True:
        stop("V30_HOOK_STATE_DRIFT")
    if config.get("hook_custom_access_token_uri") != HOOK_URI:
        stop("V30_HOOK_STATE_DRIFT")
    other_enabled = [
        key for key, value in config.items()
        if key.startswith("hook_") and key.endswith("_enabled")
        and key != "hook_custom_access_token_enabled" and value is True
    ]
    if other_enabled:
        stop("V30_OTHER_HOOK_ENABLED")
    return config



def verify_synthetic_identity(admin_secret: str) -> str:
    payload = request_json(
        f"https://{PROJECT}.supabase.co/auth/v1/admin/users?page=1&per_page=1000",
        headers=admin_headers(admin_secret),
        error_code="V30_ADMIN_CAPABILITY_FAILED",
    )
    users = payload.get("users") if isinstance(payload, dict) else None
    if not isinstance(users, list) or len(users) != 1:
        stop("V30_IDENTITY_COUNT_DRIFT")
    user = users[0]
    if not isinstance(user, dict) or user.get("email") != TARGET_EMAIL:
        stop("V30_IDENTITY_MISMATCH")
    user_id = user.get("id")
    if not isinstance(user_id, str) or not _CANONICAL_UUID.fullmatch(user_id):
        stop("V30_IDENTITY_MISMATCH")
    digest = "sha256:" + hashlib.sha256(user_id.encode("utf-8")).hexdigest()
    if digest != SUBJECT_DIGEST:
        stop("V30_IDENTITY_MISMATCH")
    app_metadata = user.get("app_metadata")
    if app_metadata != {
        "provider": "email",
        "providers": ["email"],
        "avuhz_tenant_id": TENANT_ID,
    }:
        stop("V30_TENANT_BINDING_DRIFT")
    if user.get("user_metadata") != {"email_verified": True}:
        stop("V30_IDENTITY_MISMATCH")
    if user.get("role") != "authenticated":
        stop("V30_IDENTITY_MISMATCH")
    if user.get("is_anonymous") not in (False, None):
        stop("V30_IDENTITY_MISMATCH")
    if not (user.get("email_confirmed_at") or user.get("confirmed_at")):
        stop("V30_IDENTITY_MISMATCH")
    return user_id


def hook_and_session_state(read_token: str, user_id: str) -> dict[str, Any]:
    if not _CANONICAL_UUID.fullmatch(user_id):
        stop("V30_IDENTITY_MISMATCH")
    query = f"""
    with target_hook as (
      select p.oid, p.proowner, p.prolang, p.provolatile, p.prosecdef, p.proconfig, p.prosrc
      from pg_proc p join pg_namespace n on n.oid = p.pronamespace
      where n.nspname = 'public'
        and p.proname = 'avuhz_development_custom_access_token_hook_v1'
        and pg_get_function_identity_arguments(p.oid) = 'event jsonb'
    )
    select
      current_user = 'supabase_read_only_user' as read_only_identity_ok,
      (select count(*) from auth.sessions where user_id = '{user_id}'::uuid) as session_count,
      (select count(*) from auth.refresh_tokens where user_id = '{user_id}') as refresh_token_count,
      exists(select 1 from target_hook) as hook_function_exists,
      coalesce((select pg_get_userbyid(proowner) from target_hook), '') as hook_owner,
      coalesce((select l.lanname from target_hook h join pg_language l on l.oid = h.prolang), '') as hook_language,
      coalesce((select provolatile = 's' from target_hook), false) as hook_stable,
      coalesce((select not prosecdef from target_hook), false) as hook_security_invoker,
      coalesce((select proconfig = array['search_path=pg_catalog']::text[] from target_hook), false) as hook_search_path_exact,
      coalesce((select pg_get_function_result(oid) = 'jsonb' from target_hook), false) as hook_returns_jsonb,
      coalesce((select has_function_privilege('supabase_auth_admin', oid, 'EXECUTE') from target_hook), false) as auth_admin_execute,
      coalesce((select has_function_privilege('authenticated', oid, 'EXECUTE') from target_hook), false) as authenticated_execute,
      coalesce((select has_function_privilege('anon', oid, 'EXECUTE') from target_hook), false) as anon_execute,
      coalesce((select has_function_privilege('service_role', oid, 'EXECUTE') from target_hook), false) as service_role_execute,
      coalesce((select has_function_privilege('public', oid, 'EXECUTE') from target_hook), false) as public_execute,
      coalesce(has_schema_privilege('supabase_auth_admin', 'public', 'USAGE'), false) as auth_admin_public_usage,
      coalesce((select prosrc from target_hook), '') as hook_source
    """
    rows = read_only_sql(read_token, query, "V30_READ_ONLY_PREFLIGHT_FAILED")
    if len(rows) != 1:
        stop("V30_READ_ONLY_PREFLIGHT_FAILED")
    return rows[0]


def verify_hook_state(row: dict[str, Any]) -> None:
    expected = {
        "read_only_identity_ok": True,
        "hook_function_exists": True,
        "hook_owner": "avuhz_migration_service_dev",
        "hook_language": "plpgsql",
        "hook_stable": True,
        "hook_security_invoker": True,
        "hook_search_path_exact": True,
        "hook_returns_jsonb": True,
        "auth_admin_execute": True,
        "authenticated_execute": False,
        "anon_execute": False,
        "service_role_execute": False,
        "public_execute": False,
        "auth_admin_public_usage": True,
    }
    if any(row.get(key) != value for key, value in expected.items()):
        stop("V30_HOOK_STATE_DRIFT")
    artifact = HOOK_SQL.read_text(encoding="utf-8")
    match = re.search(
        r"as \$avuhz_development_custom_access_token_hook_v1\$(.*?)"
        r"\$avuhz_development_custom_access_token_hook_v1\$;",
        artifact,
        re.DOTALL,
    )
    if match is None or str(row.get("hook_source", "")).strip() != match.group(1).strip():
        stop("V30_HOOK_BODY_DRIFT")


def validate_zero_sessions(row: dict[str, Any], *, code: str) -> None:
    if int(row.get("session_count", -1)) != 0 or int(row.get("refresh_token_count", -1)) != 0:
        stop(code)


def get_redirect_without_following(action_link: str, publishable_key: str) -> str:
    parsed = urllib.parse.urlparse(action_link)
    if parsed.scheme != "https" or parsed.hostname != f"{PROJECT}.supabase.co" or parsed.path != "/auth/v1/verify":
        stop("V30_RECOVERY_LINK_TARGET_MISMATCH")
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    if query.get("type") != ["recovery"] or not (query.get("token") or query.get("token_hash")):
        stop("V30_RECOVERY_LINK_TARGET_MISMATCH")

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
            return None

    opener = urllib.request.build_opener(NoRedirect)
    request = urllib.request.Request(action_link, method="GET", headers={"apikey": publishable_key})
    try:
        opener.open(request, timeout=30)
    except urllib.error.HTTPError as exc:
        if exc.code not in (301, 302, 303, 307, 308):
            stop("V30_RECOVERY_LINK_CONSUME_FAILED")
        location = exc.headers.get("Location")
        if not isinstance(location, str) or not location:
            stop("V30_RECOVERY_LINK_CONSUME_FAILED")
        return location
    except Exception:
        stop("V30_RECOVERY_LINK_CONSUME_FAILED")
    stop("V30_RECOVERY_LINK_REDIRECT_MISSING")


def parse_session_redirect(location: str) -> tuple[str, str, int]:
    parsed = urllib.parse.urlparse(location)
    params = urllib.parse.parse_qs(parsed.fragment, keep_blank_values=True)
    access_values = params.get("access_token")
    refresh_values = params.get("refresh_token")
    expires_values = params.get("expires_in")
    if not access_values or not refresh_values or not expires_values:
        stop("V30_SESSION_RESPONSE_MISSING")
    access_token = access_values[0]
    refresh_token = refresh_values[0]
    if not isinstance(access_token, str) or not isinstance(refresh_token, str):
        stop("V30_SESSION_RESPONSE_MISSING")
    if not 32 <= len(access_token) <= 16384 or not 16 <= len(refresh_token) <= 4096:
        stop("V30_SESSION_RESPONSE_MISSING")
    try:
        expires_in = int(expires_values[0])
    except Exception:
        stop("V30_TOKEN_LIFETIME_INVALID")
    if not 1 <= expires_in <= 3600:
        stop("V30_TOKEN_LIFETIME_INVALID")
    return access_token, refresh_token, expires_in


def evidence_raw_digest(value: dict[str, Any]) -> str:
    return artifact_digest(value)


def binding_assertion(
    binding_id: str,
    phase: str,
    value_class: str,
    evidence_type: str,
    evidence_digest: str,
    value_digest: str | None,
    recorded_at: str,
    *,
    source_step_id: str | None = None,
    digest_policy: str = "REQUIRED",
    persistence_policy: str = "DIGEST_ONLY",
) -> dict[str, Any]:
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


def request_for(plan: dict[str, Any], step: dict[str, Any], credential_class: str, progress: dict[str, Any]) -> dict[str, Any]:
    prior = [
        evidence["evidence_digest"]
        for state in progress["step_states"]
        for evidence in state["evidence"]
    ]
    required = []
    for item in step["required_evidence"]:
        if item["source_step_id"] is None:
            digest = item["exact_digest"]
        else:
            source_index = plan["ordered_step_ids"].index(item["source_step_id"])
            matches = [
                evidence for evidence in progress["step_states"][source_index]["evidence"]
                if evidence["evidence_type"] == item["evidence_type"]
            ]
            if len(matches) != 1:
                stop("V30_REQUIRED_EVIDENCE_MISSING")
            digest = matches[0]["evidence_digest"]
        required.append({"evidence_type": item["evidence_type"], "evidence_digest": digest})
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


def main() -> int:
    if os.environ.get("AVUHZ_V30_CONFIRMATION") != CONFIRMATION:
        stop("V30_CONFIRMATION_MISMATCH")
    if os.environ.get("AVUHZ_EXPECTED_PROJECT_REF") != PROJECT:
        stop("V30_ENV_PROJECT_MISMATCH")
    if DEVELOPMENT_AUTH_PROJECT_REF != PROJECT or DEVELOPMENT_AUTH_ISSUER != f"https://{PROJECT}.supabase.co/auth/v1":
        stop("V30_CODE_PROJECT_MISMATCH")
    if DEVELOPMENT_SERVICE_AUDIENCE != "audience.avuhz.command-service.development":
        stop("V30_CODE_AUDIENCE_MISMATCH")

    plan = load_json(PLAN_PATH)
    progress = load_json(PROGRESS_PATH)
    approval = load_json(APPROVAL_PATH)
    validate_plan(plan, SCHEMA_ROOT)
    validate_progress(plan, progress, SCHEMA_ROOT)
    current = now_text()
    validate_approval(plan, approval, SCHEMA_ROOT, current)
    if plan["plan_id"] != PLAN_ID or plan["plan_digest"] != PLAN_DIGEST or plan["plan_version"] != 30:
        stop("V30_PLAN_MISMATCH")
    if progress["overall_state"] != "NOT_STARTED" or any(state["authorization_consumed"] for state in progress["step_states"]):
        stop("V30_PROGRESS_NOT_PRISTINE")

    admin_secret = os.environ.get(FRESH_ADMIN_ENV)
    read_token = os.environ.get(PROVIDER_READ_ENV)
    publishable_key = os.environ.get(PUBLISHABLE_ENV)
    if not isinstance(admin_secret, str) or not admin_secret.startswith("sb_secret_"):
        stop("V30_FRESH_ADMIN_CREDENTIAL_UNAVAILABLE")
    if not isinstance(read_token, str) or len(read_token) < 20:
        stop("V30_PROVIDER_READ_CREDENTIAL_UNAVAILABLE")
    if not isinstance(publishable_key, str) or not publishable_key.startswith("sb_publishable_"):
        stop("V30_PUBLISHABLE_KEY_UNAVAILABLE")

    recovery_link: str | None = None
    access_token: str | None = None
    refresh_token: str | None = None
    user_id: str | None = None
    lifecycle_authorized = False
    cleanup_completed = False

    summary: dict[str, Any] = {
        "plan_id": PLAN_ID,
        "plan_digest": PLAN_DIGEST,
        "project_reference": PROJECT,
        "environment": "DEVELOPMENT",
        "responsibility": "AUTH",
    }

    try:
        verify_project_and_hook_config(read_token)
        user_id = verify_synthetic_identity(admin_secret)
        pre_state = hook_and_session_state(read_token, user_id)
        verify_hook_state(pre_state)
        validate_zero_sessions(pre_state, code="V30_PREEXISTING_SESSION")

        observed_at = now_text()
        capability_config = {
            "executor_reference": "github-actions.development-auth-v30-token-validation",
            "environment": "development",
            "project_reference": PROJECT,
            "operation": "auth.admin.generateLink.recovery",
            "credential_class": "SUPABASE_AUTH_ADMIN_EPHEMERAL",
            "fresh_dedicated_binding_name": FRESH_ADMIN_ENV,
        }
        capability = {
            "evidence_type": "auth.admin-executor-capability.observed",
            "environment": "DEVELOPMENT",
            "provider_reference": "supabase",
            "project_reference": PROJECT,
            "responsibility": "AUTH",
            "plan_id": PLAN_ID,
            "plan_version": 30,
            "step_id": STEP1,
            "observed_at": observed_at,
            "configuration_digest": canonical_digest(capability_config),
            "admin_list_users_capability_verified": True,
            "admin_generate_recovery_link_capability_selected": True,
            "credential_material_retained": False,
            "credential_material_logged": False,
            "provider_mutation_attempted": False,
            "result": "PASS",
        }
        capability["evidence_digest"] = component_digest(capability)

        live_config = {
            "project_reference": PROJECT,
            "auth_user_count": 1,
            "subject_digest": SUBJECT_DIGEST,
            "tenant_id": TENANT_ID,
            "session_count": 0,
            "refresh_token_count": 0,
            "hook_uri": HOOK_URI,
            "hook_owner": "avuhz_migration_service_dev",
            "hook_acl_exact": True,
            "publishable_key_binding_name": PUBLISHABLE_ENV,
            "publishable_key_prefix_verified": True,
            "management_api_key_enumeration_used": False,
        }
        live = {
            "evidence_type": "auth.synthetic-token.live-preflight.observed",
            "environment": "DEVELOPMENT",
            "provider_reference": "supabase",
            "project_reference": PROJECT,
            "responsibility": "AUTH",
            "plan_id": PLAN_ID,
            "plan_version": 30,
            "step_id": STEP1,
            "observed_at": observed_at,
            "configuration_digest": canonical_digest(live_config),
            "identity_count_verified": True,
            "subject_digest_verified": True,
            "tenant_binding_verified": True,
            "zero_sessions_verified": True,
            "zero_refresh_tokens_verified": True,
            "hook_configuration_verified": True,
            "hook_function_body_owner_acl_verified": True,
            "publishable_key_boundary_verified": True,
            "provider_mutation_attempted": False,
            "result": "PASS",
        }
        live["evidence_digest"] = component_digest(live)
        preflight_artifact = {
            "evidence_type": "auth.synthetic-token.execution-preflight.observed",
            "observation_only": True,
            "environment": "DEVELOPMENT",
            "provider_reference": "supabase",
            "project_reference": PROJECT,
            "responsibility": "AUTH",
            "plan_id": PLAN_ID,
            "plan_version": 30,
            "step_id": STEP1,
            "capability_attestation": capability,
            "live_read_only_preflight": live,
            "security_state": {
                "credential_material_retained": False,
                "credential_material_logged": False,
                "raw_provider_payload_retained": False,
                "raw_provider_subject_retained": False,
                "pii_retained": False,
                "provider_mutation_attempted": False,
                "management_api_key_enumeration_used": False,
                "data_resource_touched": False,
                "render_touched": False,
                "n8n_touched": False,
                "staging_touched": False,
                "production_touched": False,
            },
            "recorded_at": observed_at,
        }
        summary["preflight_artifact"] = preflight_artifact
        summary["preflight_raw_digest"] = evidence_raw_digest(preflight_artifact)

        step1 = plan["steps"][0]
        assertions = [
            binding_assertion(
                "binding.development.auth.v30.admin-executor-capability",
                "RESOLVED_BY_STEP_PREFLIGHT", "CONFIGURATION_REFERENCE",
                capability["evidence_type"], capability["evidence_digest"],
                capability["configuration_digest"], observed_at,
            ),
            binding_assertion(
                "binding.development.auth.v30.live-preflight",
                "RESOLVED_BY_STEP_PREFLIGHT", "CONFIGURATION_REFERENCE",
                live["evidence_type"], live["evidence_digest"],
                live["configuration_digest"], observed_at,
            ),
        ]
        progress = authorize_step(
            plan, approval, progress,
            request_for(plan, step1, "SUPABASE_AUTH_ADMIN_EPHEMERAL", progress),
            SCHEMA_ROOT, observed_at, trusted_preflight_assertions=assertions,
        )

        generated = request_json(
            f"https://{PROJECT}.supabase.co/auth/v1/admin/generate_link",
            method="POST",
            headers=admin_headers(admin_secret),
            body={"type": "recovery", "email": TARGET_EMAIL},
            expected=(200,),
            error_code="V30_RECOVERY_LINK_GENERATION_FAILED",
        )
        if not isinstance(generated, dict) or not isinstance(generated.get("properties"), dict):
            stop("V30_RECOVERY_LINK_GENERATION_FAILED")
        recovery_link = generated["properties"].get("action_link")
        verification_type = generated["properties"].get("verification_type")
        generated_user = generated.get("user")
        if not isinstance(recovery_link, str) or verification_type != "recovery" or not isinstance(generated_user, dict):
            stop("V30_RECOVERY_LINK_GENERATION_FAILED")
        generated_id = generated_user.get("id")
        if not isinstance(generated_id, str) or not _CANONICAL_UUID.fullmatch(generated_id):
            stop("V30_RECOVERY_LINK_IDENTITY_MISMATCH")
        if "sha256:" + hashlib.sha256(generated_id.encode("utf-8")).hexdigest() != SUBJECT_DIGEST or generated_id != user_id:
            stop("V30_RECOVERY_LINK_IDENTITY_MISMATCH")
        after_generate = hook_and_session_state(read_token, user_id)
        validate_zero_sessions(after_generate, code="V30_UNEXPECTED_SESSION_AFTER_LINK")

        step1_at = now_text()
        step1_evidence = {
            "evidence_type": "auth.synthetic-recovery-link.generated",
            "environment": "DEVELOPMENT",
            "responsibility": "AUTH",
            "project_reference": PROJECT,
            "plan_id": PLAN_ID,
            "plan_version": 30,
            "step_id": STEP1,
            "attempt": 1,
            "outcome": "SUCCEEDED_VERIFIED",
            "execution_observation": {
                "execution_class": "PROVIDER_MUTATION",
                "credential_class": "SUPABASE_AUTH_ADMIN_EPHEMERAL",
                "fresh_dedicated_credential_binding": FRESH_ADMIN_ENV,
                "link_type": "recovery",
                "existing_user_required": True,
                "email_sent": False,
                "provider_mutation_attempts": 1,
                "recovery_link_material_retained": False,
            },
            "provider_observation": {
                "identity_count": 1,
                "subject_digest": SUBJECT_DIGEST,
                "tenant_id": TENANT_ID,
                "session_count": 0,
                "refresh_token_count": 0,
                "hook_configuration_unchanged": True,
            },
            "security_state": {
                "identity_created": False,
                "credential_material_retained": False,
                "recovery_link_retained": False,
                "token_retained": False,
                "refresh_token_retained": False,
                "pii_retained": False,
                "data_resource_touched": False,
                "render_touched": False,
                "n8n_touched": False,
                "staging_touched": False,
                "production_touched": False,
            },
            "recorded_at": step1_at,
        }
        step1_digest = evidence_raw_digest(step1_evidence)
        progress = record_step_outcome(
            plan, approval, progress, STEP1, "SUCCEEDED", "PASS",
            [{"evidence_type": step1_evidence["evidence_type"], "evidence_reference": "provider.execution.v30.step1.attempt1.verified", "evidence_digest": step1_digest, "recorded_at": step1_at}],
            step1["expected_postcondition"], None, SCHEMA_ROOT, step1_at,
        )
        summary["step1_artifact"] = step1_evidence
        summary["step1_raw_digest"] = step1_digest

        step2 = plan["steps"][1]
        step2_auth_at = now_text()
        progress = authorize_step(
            plan, approval, progress,
            request_for(plan, step2, "SYNTHETIC_IDENTITY", progress),
            SCHEMA_ROOT, step2_auth_at,
        )
        lifecycle_authorized = True
        redirect = get_redirect_without_following(recovery_link, publishable_key)
        access_token, refresh_token, expires_in = parse_session_redirect(redirect)
        recovery_link = None
        redirect = ""
        try:
            header = jwt.get_unverified_header(access_token)
        except Exception:
            stop("V30_TOKEN_STRUCTURE_INVALID")
        if not isinstance(header, dict) or header.get("alg") != "ES256":
            stop("V30_JWT_ALGORITHM_MISMATCH")
        issued_state = hook_and_session_state(read_token, user_id)
        if int(issued_state.get("session_count", -1)) != 1 or int(issued_state.get("refresh_token_count", -1)) != 1:
            stop("V30_SESSION_COUNT_MISMATCH")

        request_json(
            f"https://{PROJECT}.supabase.co/auth/v1/logout?scope=local",
            method="POST",
            headers=project_headers(publishable_key, access_token),
            body={},
            expected=(200, 204),
            error_code="V30_LOGOUT_FAILED",
        )
        cleanup_state = hook_and_session_state(read_token, user_id)
        validate_zero_sessions(cleanup_state, code="V30_SESSION_CLEANUP_FAILED")
        cleanup_completed = True

        step2_at = now_text()
        step2_evidence = {
            "evidence_type": "auth.synthetic-session.lifecycle-completed",
            "environment": "DEVELOPMENT",
            "responsibility": "AUTH",
            "project_reference": PROJECT,
            "plan_id": PLAN_ID,
            "plan_version": 30,
            "step_id": STEP2,
            "attempt": 1,
            "outcome": "SUCCEEDED_VERIFIED",
            "execution_observation": {
                "execution_class": "PROVIDER_MUTATION",
                "credential_class": "SYNTHETIC_IDENTITY",
                "recovery_link_consumed_once": True,
                "access_token_present_in_executor_memory": True,
                "refresh_token_present_in_executor_memory": True,
                "expires_in_seconds": expires_in,
                "token_algorithm_header": "ES256",
                "logout_scope": "local",
                "logout_attempts": 1,
                "token_refresh_attempted": False,
                "token_material_persisted": False,
                "token_material_printed": False,
            },
            "provider_observation": {
                "session_count_after_issue": 1,
                "refresh_token_count_after_issue": 1,
                "session_count_after_cleanup": 0,
                "refresh_token_count_after_cleanup": 0,
                "identity_count": 1,
                "hook_configuration_unchanged": True,
            },
            "verification_observation": {
                "session_cleanup_verified": True,
                "refresh_token_cleanup_verified": True,
                "identity_preserved": True,
                "postcondition_verified": True,
            },
            "security_state": {
                "recovery_link_retained": False,
                "access_token_retained": False,
                "refresh_token_retained": False,
                "token_material_logged": False,
                "refresh_token_used": False,
                "pii_retained": False,
                "data_resource_touched": False,
                "render_touched": False,
                "n8n_touched": False,
                "staging_touched": False,
                "production_touched": False,
            },
            "recorded_at": step2_at,
        }
        step2_digest = evidence_raw_digest(step2_evidence)
        cleanup_binding = binding_assertion(
            "binding.development.auth.v30.session-cleanup",
            "PRODUCED_BY_CURRENT_STEP", "CONTENT_DIGEST",
            step2_evidence["evidence_type"], step2_digest,
            LIFECYCLE_CONFIG_DIGEST, step2_at,
        )
        progress = record_step_outcome(
            plan, approval, progress, STEP2, "SUCCEEDED", "PASS",
            [{"evidence_type": step2_evidence["evidence_type"], "evidence_reference": "provider.execution.v30.step2.attempt1.verified", "evidence_digest": step2_digest, "recorded_at": step2_at}],
            step2["expected_postcondition"], None, SCHEMA_ROOT, step2_at,
            binding_assertions=[cleanup_binding],
        )
        summary["step2_artifact"] = step2_evidence
        summary["step2_raw_digest"] = step2_digest

        step3 = plan["steps"][2]
        step3_auth_at = now_text()
        progress = authorize_step(
            plan, approval, progress,
            request_for(plan, step3, "EPHEMERAL_SYNTHETIC_ACCESS_TOKEN", progress),
            SCHEMA_ROOT, step3_auth_at,
        )
        try:
            verified_claims = DevelopmentSupabaseEs256JwtVerifier().verify(access_token)
            identity = DevelopmentSupabaseIdentityVerifier(
                DevelopmentSupabaseEs256JwtVerifier(),
                allowlist=DEVELOPMENT_SYNTHETIC_READ_ONLY_ALLOWLIST,
            ).verify(access_token)
        except Exception:
            stop("V30_TOKEN_VALIDATION_FAILED")
        if verified_claims.get("iss") != DEVELOPMENT_AUTH_ISSUER or verified_claims.get("aud") != DEVELOPMENT_SERVICE_AUDIENCE:
            stop("V30_TOKEN_VALIDATION_FAILED")
        if verified_claims.get("avuhz_tenant_id") != TENANT_ID:
            stop("V30_TOKEN_VALIDATION_FAILED")
        provider_subject = verified_claims.get("sub")
        if not isinstance(provider_subject, str) or not _CANONICAL_UUID.fullmatch(provider_subject):
            stop("V30_TOKEN_VALIDATION_FAILED")
        if "sha256:" + hashlib.sha256(provider_subject.encode("utf-8")).hexdigest() != SUBJECT_DIGEST:
            stop("V30_TOKEN_VALIDATION_FAILED")
        issued_at = verified_claims.get("iat")
        expires_at = verified_claims.get("exp")
        if isinstance(issued_at, bool) or isinstance(expires_at, bool) or not isinstance(issued_at, (int, float)) or not isinstance(expires_at, (int, float)):
            stop("V30_TOKEN_VALIDATION_FAILED")
        lifetime = int(expires_at - issued_at)
        if not 1 <= lifetime <= 3600:
            stop("V30_TOKEN_LIFETIME_INVALID")
        session_id = verified_claims.get("session_id")
        if not isinstance(session_id, str):
            stop("V30_TOKEN_VALIDATION_FAILED")
        try:
            uuid.UUID(session_id)
        except Exception:
            stop("V30_TOKEN_VALIDATION_FAILED")
        if identity.subject != PRINCIPAL_REFERENCE or identity.tenant_id != TENANT_ID:
            stop("V30_POLICY_VALIDATION_FAILED")
        if identity.caller_type != "HUMAN" or identity.capabilities != frozenset({"engagement:read"}) or identity.authority_roles != frozenset():
            stop("V30_POLICY_VALIDATION_FAILED")

        final_state = hook_and_session_state(read_token, user_id)
        validate_zero_sessions(final_state, code="V30_POST_VALIDATION_SESSION_DRIFT")
        verify_hook_state(final_state)
        verify_project_and_hook_config(read_token)

        step3_at = now_text()
        step3_evidence = {
            "evidence_type": "auth.synthetic-token.validation.verified",
            "environment": "DEVELOPMENT",
            "responsibility": "AUTH",
            "project_reference": PROJECT,
            "plan_id": PLAN_ID,
            "plan_version": 30,
            "step_id": STEP3,
            "attempt": 1,
            "outcome": "SUCCEEDED_VERIFIED",
            "execution_observation": {
                "execution_class": "PROVIDER_READ",
                "credential_class": "EPHEMERAL_SYNTHETIC_ACCESS_TOKEN",
                "validation_after_session_cleanup": True,
                "live_jwks_used": True,
                "algorithm": "ES256",
                "token_lifetime_seconds": lifetime,
                "token_material_retained": False,
                "token_material_printed": False,
                "token_refresh_attempted": False,
            },
            "identity_observation": {
                "issuer": DEVELOPMENT_AUTH_ISSUER,
                "audience": DEVELOPMENT_SERVICE_AUDIENCE,
                "subject_digest": SUBJECT_DIGEST,
                "tenant_id": TENANT_ID,
                "principal_reference": PRINCIPAL_REFERENCE,
                "caller_type": "HUMAN",
                "capabilities": ["engagement:read"],
                "authority_roles": [],
                "role": "authenticated",
                "aal": "aal1",
                "is_anonymous": False,
            },
            "verification_observation": {
                "signature_verified": True,
                "issuer_verified": True,
                "audience_verified": True,
                "expiration_verified": True,
                "tenant_verified": True,
                "subject_digest_verified": True,
                "allowlist_policy_verified": True,
                "zero_sessions_verified": True,
                "zero_refresh_tokens_verified": True,
                "hook_configuration_unchanged": True,
                "postcondition_verified": True,
            },
            "security_state": {
                "access_token_retained": False,
                "refresh_token_retained": False,
                "recovery_link_retained": False,
                "publishable_key_retained": False,
                "admin_credential_retained": False,
                "raw_provider_subject_retained": False,
                "pii_retained": False,
                "data_resource_touched": False,
                "render_touched": False,
                "n8n_touched": False,
                "staging_touched": False,
                "production_touched": False,
            },
            "recorded_at": step3_at,
        }
        step3_digest = evidence_raw_digest(step3_evidence)
        validation_binding = binding_assertion(
            "binding.development.auth.v30.validated-policy",
            "PRODUCED_BY_CURRENT_STEP", "CONTENT_DIGEST",
            step3_evidence["evidence_type"], step3_digest,
            VALIDATION_CONFIG_DIGEST, step3_at,
        )
        progress = record_step_outcome(
            plan, approval, progress, STEP3, "SUCCEEDED", "PASS",
            [{"evidence_type": step3_evidence["evidence_type"], "evidence_reference": "provider.execution.v30.step3.attempt1.verified", "evidence_digest": step3_digest, "recorded_at": step3_at}],
            step3["expected_postcondition"], None, SCHEMA_ROOT, step3_at,
            binding_assertions=[validation_binding],
        )
        validate_progress(plan, progress, SCHEMA_ROOT)
        if progress["overall_state"] != "COMPLETED":
            stop("V30_FINAL_PROGRESS_INVALID")

        summary["step3_artifact"] = step3_evidence
        summary["step3_raw_digest"] = step3_digest
        summary["execution_progress"] = progress
        summary["execution_progress_raw_digest"] = artifact_digest(progress)
        summary["result"] = "PASS"
        summary["token_material_retained"] = False
        summary["refresh_token_material_retained"] = False
        summary["recovery_link_material_retained"] = False
        summary["credential_material_retained"] = False
        summary["session_count_final"] = 0
        summary["refresh_token_count_final"] = 0

        recovery_link = None
        access_token = None
        refresh_token = None
        publishable_key = None
        admin_secret = None
        read_token = None
        user_id = None
        print("V30_SANITIZED_RESULT=" + json.dumps(summary, sort_keys=True, separators=(",", ":")))
        print("DEVELOPMENT_AUTH_V30_OUTCOME=PASS")
        return 0
    except SafeStop as exc:
        emergency_cleanup = "NOT_NEEDED"
        if lifecycle_authorized and access_token is not None and not cleanup_completed and publishable_key is not None:
            emergency_cleanup = "FAILED"
            try:
                if user_id is not None and read_token is not None:
                    observed = hook_and_session_state(read_token, user_id)
                    if int(observed.get("session_count", -1)) == 0 and int(observed.get("refresh_token_count", -1)) == 0:
                        cleanup_completed = True
                        emergency_cleanup = "PASS_ALREADY_CLEAN"
                if not cleanup_completed:
                    request_json(
                        f"https://{PROJECT}.supabase.co/auth/v1/logout?scope=local",
                        method="POST",
                        headers=project_headers(publishable_key, access_token),
                        body={},
                        expected=(200, 204),
                        error_code="V30_EMERGENCY_LOGOUT_FAILED",
                    )
                    if user_id is None or read_token is None:
                        raise SafeStop("V30_EMERGENCY_CLEANUP_UNVERIFIED")
                    observed = hook_and_session_state(read_token, user_id)
                    validate_zero_sessions(observed, code="V30_EMERGENCY_CLEANUP_UNVERIFIED")
                    cleanup_completed = True
                    emergency_cleanup = "PASS"
            except Exception:
                emergency_cleanup = "FAILED"
        print(f"DEVELOPMENT_AUTH_V30_OUTCOME=STOPPED code={exc} emergency_cleanup={emergency_cleanup}", file=sys.stderr)
        if lifecycle_authorized and access_token is not None and not cleanup_completed:
            print("V30_EMERGENCY_CLEANUP_REQUIRED=true", file=sys.stderr)
        return 2
    finally:
        recovery_link = None
        access_token = None
        refresh_token = None
        publishable_key = None
        admin_secret = None
        read_token = None
        user_id = None


if __name__ == "__main__":
    raise SystemExit(main())
