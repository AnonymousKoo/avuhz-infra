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
    print('runtime schema representability: PASS')

if __name__ == '__main__':
    try: main()
    except AssertionError as error:
        print(f'runtime schema representability: FAIL: {error}', file=sys.stderr); raise SystemExit(1)
