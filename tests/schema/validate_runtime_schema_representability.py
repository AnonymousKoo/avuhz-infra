"""Check that existing Slice 1 runtime envelopes need no fabricated DB values."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'tests' / 'contracts')]
from validate_command_payloads import handoff, payloads

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
    print('runtime schema representability: PASS')

if __name__ == '__main__':
    try: main()
    except AssertionError as error:
        print(f'runtime schema representability: FAIL: {error}', file=sys.stderr); raise SystemExit(1)
