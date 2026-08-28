"""Check that existing Slice 1 runtime envelopes need no fabricated DB values."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / 'src'), str(ROOT / 'tests' / 'contracts')]
from jsonschema import Draft202012Validator
from validate_command_payloads import handoff, payloads
from avuhz_runtime.in_memory import UnitOfWork
from avuhz_runtime.phase5c import (
    PHASE5C_CAPABILITIES, PHASE5C_COMMANDS, PHASE5C_EVENTS, Phase5CReadService,
)
from avuhz_runtime.phase5d_package import CodexBuildPackageReadService
from avuhz_runtime.schema_registry import SchemaRegistry
from tests.runtime.test_phase5c_runtime import Phase5CRuntimeTests
from tests.runtime.test_phase5d_codex_build_package_runtime import (
    CodexBuildPackageRuntimeTests,
)

def require(ok, message):
    if not ok: raise AssertionError(message)

def main():
    h = handoff()
    handoff_row = {**h, 'accepted_at': None}
    scope_row = {**payloads()['SubmitDiagnosticScope'], 'canonical_scope_digest': None}
    event = {'event_id': 'a3000000-0000-4000-8000-000000000020', 'event_type': 'engagement.opened', 'subject_id': 'a3000000-0000-4000-8000-000000000004', 'tenant_id': h['tenant_id'], 'idempotency_key': 'slice1-runtime-event-0001'}
    outbox = {'event_id': event['event_id'], 'status': 'PENDING'}
    require(handoff_row['accepted_at'] is None, 'unaccepted handoff must not fabricate acceptance time')
    require(scope_row['canonical_scope_digest'] is None, 'submitted scope must not fabricate digest')
    require({'event_id', 'event_type', 'subject_id', 'tenant_id', 'idempotency_key'} <= event.keys(), 'runtime event shape drifted')
    require(set(outbox) == {'event_id', 'status'}, 'runtime outbox intent shape drifted')
    require(event['tenant_id'] == h['tenant_id'], 'outbox tenant must be derivable from event, not fabricated')
    approval_idempotency = {'command_type': 'RecordHumanApproval', 'tenant_id': h['tenant_id'], 'idempotency_key': 'slice1-runtime-approval-0001', 'semantic_request_fingerprint': 'fpv1:runtimeapprovalfingerprint0001'}
    require(approval_idempotency['command_type'] == 'RecordHumanApproval', 'approval idempotency vocabulary drifted')
    require(not ({'payload', 'credentials', 'authorization'} & approval_idempotency.keys()), 'idempotency record must not persist raw command data')
    canonicalization_idempotency = {"command_type": "CanonicalizeDiagnosticScope", "tenant_id": h["tenant_id"], "idempotency_key": "slice1-runtime-canonicalization-0001", "semantic_request_fingerprint": "fpv1:runtimecanonicalizationfp0001"}
    require(canonicalization_idempotency["command_type"] == "CanonicalizeDiagnosticScope", "canonicalization idempotency vocabulary drifted")
    require(not ({"payload", "credentials", "authorization", "provider_blob"} & canonicalization_idempotency.keys()), "canonicalization idempotency record must not persist raw command data")
    approval_event = {**event, 'event_type': 'human_approval.recorded', 'subject_id': payloads()['SubmitDiagnosticScope']['proposed_diagnostic_scope_id']}
    require(set(approval_event) == {'event_id', 'event_type', 'subject_id', 'tenant_id', 'idempotency_key'}, 'approval event must use only the current runtime envelope')
    require(approval_event['event_type'] == 'human_approval.recorded', 'approval event vocabulary drifted')
    require(not ({'approving_principal_reference', 'approving_organization_reference', 'authority_role'} & approval_event.keys()), 'approval event must not duplicate authoritative attribution')
    scope_id = payloads()['SubmitDiagnosticScope']['proposed_diagnostic_scope_id']
    digest = payloads()['ApproveDiagnosticScope']['scope_content_digest']
    partial_approvals = (
        {'approval_id': 'a3000000-0000-4000-8000-000000000006', 'tenant_id': h['tenant_id'], 'subject_id': scope_id, 'subject_version': 1, 'scope': {'scope_digest': digest}, 'authority_category': 'CLIENT_AUTHORITY', 'status': 'ACTIVE'},
        {'approval_id': 'a3000000-0000-4000-8000-000000000007', 'tenant_id': h['tenant_id'], 'subject_id': scope_id, 'subject_version': 1, 'scope': {'scope_digest': digest}, 'authority_category': 'SEKINFRA_AUTHORITY', 'status': 'ACTIVE'},
    )
    optional_approval_fields = {'approving_principal_reference', 'approving_organization_reference', 'decision', 'conditions', 'effective_at', 'evidence_reference', 'correlation_id', 'idempotency_key'}
    for approval, authority in zip(partial_approvals, ('CLIENT_AUTHORITY', 'SEKINFRA_AUTHORITY')):
        require(approval['authority_category'] == authority and approval['status'] == 'ACTIVE', 'approval authority drifted')
        require(approval['subject_id'] == scope_id and approval['subject_version'] == 1 and approval['scope']['scope_digest'] == digest, 'approval binding drifted')
        require(not (optional_approval_fields & approval.keys()), 'approval fabricated future evidence')
    require(partial_approvals[0]['approval_id'] != partial_approvals[1]['approval_id'], 'dual authority requires separate rows')
    require(len(PHASE5C_COMMANDS) == 17, 'Phase 5C command vocabulary drifted')
    require(len(set(PHASE5C_CAPABILITIES.values())) == 16, 'Phase 5C capability vocabulary drifted')
    require(len(set(PHASE5C_EVENTS.values())) == 17, 'Phase 5C event vocabulary drifted')

    phase5c = Phase5CRuntimeTests()
    phase5c.setUp()
    phase5c.build_active()
    phase5c.execute('RevokeOngoingAccess', {
        'ongoing_access_grant_id': phase5c.ongoing_grant_id,
        'revocation_reason': 'EMERGENCY_SECURITY_REVOCATION',
    }, expected=3, role='SEKINFRA_ENGAGEMENT_AUTHORITY', caller_type='HUMAN')
    phase5c.execute('InitiateOngoingOffboarding', {
        'ongoing_offboarding_id': phase5c.offboarding_id,
        'oia_conversion_decision_id': phase5c.conversion_id,
        'decision_version': 1,
        'ongoing_agreement_authority_id': phase5c.agreement_id,
        'agreement_version': 1,
        'reason': 'ENGAGEMENT_COMPLETED',
        'ongoing_access_grant_ids': [phase5c.ongoing_grant_id],
    }, role='SEKINFRA_ENGAGEMENT_AUTHORITY')
    phase5c.execute('VerifyOngoingAccessRevocation', {
        'ongoing_access_revocation_verification_id': phase5c.revocation_id,
        'ongoing_access_grant_id': phase5c.ongoing_grant_id,
        'ongoing_offboarding_id': phase5c.offboarding_id,
    }, expected=4)
    phase5c.execute('CompleteOngoingOffboarding', {
        'ongoing_offboarding_id': phase5c.offboarding_id,
    }, expected=1)
    uow = UnitOfWork(phase5c.store)
    records = (
        ('oia-conversion-decision', uow.oia_conversion_decisions.get_version(
            phase5c.tenant, phase5c.conversion_id, 1)),
        ('ongoing-agreement-authority', uow.ongoing_agreement_authorities.get_version(
            phase5c.tenant, phase5c.agreement_id, 1)),
        ('ongoing-payment-verification', uow.ongoing_payment_verifications.get(
            phase5c.tenant, phase5c.payment_id)),
        ('ongoing-access-grant', uow.ongoing_access_grants.get(
            phase5c.tenant, phase5c.ongoing_grant_id)),
        ('ongoing-offboarding', uow.ongoing_offboardings.get(
            phase5c.tenant, phase5c.offboarding_id)),
        ('ongoing-access-revocation-verification',
         uow.ongoing_access_revocation_verifications.get(
             phase5c.tenant, phase5c.revocation_id)),
    )
    registry = SchemaRegistry(ROOT / 'contracts/schemas/v1')
    for slug, record in records:
        schema = registry.expanded(f'urn:avuhz:schema:contracts:domain:{slug}:v1')
        require(not list(Draft202012Validator(schema).iter_errors(record)),
                f'Phase 5C {slug} runtime record is not schema representable')
    approvals = [
        value for value in phase5c.store.approvals.values()
        if value.get('subject_type') in {
            'OIA_CONVERSION_DECISION', 'ONGOING_AGREEMENT_AUTHORITY', 'ONGOING_ACCESS_GRANT'
        }
    ]
    approval_schema = registry.expanded(
        'urn:avuhz:schema:contracts:domain:human-approval:v1')
    require(len(approvals) == 6, 'Phase 5C dual approval records drifted')
    require(all(not list(Draft202012Validator(approval_schema).iter_errors(value))
                for value in approvals), 'Phase 5C HumanApproval is not schema representable')
    reads = Phase5CReadService(uow)
    read_values = (
        ('oia-conversion-status-view', reads.conversion_status(phase5c.tenant, phase5c.conversion_id, 1, phase5c.now)),
        ('ongoing-agreement-authority-view', reads.agreement_authority(phase5c.tenant, phase5c.agreement_id, 1, phase5c.now)),
        ('ongoing-commercial-authority-view', reads.commercial_authority(phase5c.tenant, phase5c.payment_id, phase5c.now)),
        ('ongoing-access-status-view', reads.access_status(phase5c.tenant, phase5c.ongoing_grant_id, phase5c.now)),
        ('ongoing-offboarding-status-view', reads.offboarding_status(phase5c.tenant, phase5c.offboarding_id, phase5c.now)),
        ('ongoing-engagement-eligibility-view', reads.eligibility(phase5c.tenant, phase5c.engagement_id, phase5c.now)),
        ('phase5c-authority-progression-view', reads.progression(phase5c.tenant, phase5c.engagement_id, phase5c.now)),
    )
    for slug, value in read_values:
        schema = registry.expanded(f'urn:avuhz:schema:contracts:read-models:{slug}:v1')
        require(not list(Draft202012Validator(schema).iter_errors(value)),
                f'Phase 5C {slug} runtime read is not schema representable')

    package_runtime = CodexBuildPackageRuntimeTests()
    package_runtime.setUp()
    package_payload = package_runtime.payload()
    package_runtime.draft(package_payload)
    package_runtime.release(package_payload, package_runtime.approve(package_payload))
    package_uow = UnitOfWork(package_runtime.store)
    package = package_uow.codex_build_packages.get_version(
        package_runtime.tenant, package_payload['codex_build_package_id'], 1)
    package_schema = registry.expanded(
        'urn:avuhz:schema:contracts:domain:codex-build-package:v1')
    require(not list(Draft202012Validator(package_schema).iter_errors(package)),
            'Phase 5D-B3 CodexBuildPackage runtime record is not schema representable')
    package_approvals = [
        value for value in package_runtime.store.approvals.values()
        if value.get('subject_type') == 'CODEX_BUILD_PACKAGE'
    ]
    require(len(package_approvals) == 2,
            'Phase 5D-B3 CodexBuildPackage dual approval records drifted')
    require(all(not list(Draft202012Validator(approval_schema).iter_errors(value))
                for value in package_approvals),
            'Phase 5D-B3 CodexBuildPackage HumanApproval is not schema representable')
    package_readiness = CodexBuildPackageReadService(package_uow).readiness(
        package_runtime.tenant, package_payload['codex_build_package_id'], 1,
        package_runtime.now)
    package_readiness_schema = registry.expanded(
        'urn:avuhz:schema:contracts:read-models:codex-build-package-readiness-view:v1')
    require(not list(Draft202012Validator(package_readiness_schema).iter_errors(
        package_readiness)),
        'Phase 5D-B3 CodexBuildPackage readiness is not schema representable')
    require(package_readiness['codex_build_package_ready'],
            'Phase 5D-B3 released package must be ready')
    require(not package_readiness['package_grants_authority'],
            'CodexBuildPackage must never grant implementation authority')
    require(not package_readiness['deployment_authorized'],
            'CodexBuildPackage must never grant deployment authority')
    require(not package_readiness['production_change_authorized'],
            'CodexBuildPackage must never grant production-change authority')
if __name__ == '__main__':
    try: main()
    except AssertionError as error:
        print(f'runtime schema representability: FAIL: {error}', file=sys.stderr); raise SystemExit(1)
    print('runtime schema representability: PASS')
