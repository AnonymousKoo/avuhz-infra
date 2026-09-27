from __future__ import annotations

import json
import re
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / 'contracts/plans/v1'
BOUNDARY = 'development-auth-v32-synthetic-session-cleanup-credential-retirement-v2'
PROJECT = 'pwlhruwutoitnieactol'
DATA_PROJECT = 'gnuqaefotwgkwurjpyik'
GH_SECRET = 'AVUHZ_DEVELOPMENT_SUPABASE_AUTH_SESSION_CLEANUP_V2_EPHEMERAL'


class CleanupCredentialRetirementV2SecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.plan = json.loads((BASE / f'{BOUNDARY}.plan.json').read_text())
        self.progress = json.loads((BASE / f'{BOUNDARY}.progress.json').read_text())

    def test_exact_scope_is_two_resources_four_sequential_steps(self) -> None:
        self.assertEqual(self.plan['target']['project_reference'], PROJECT)
        self.assertNotIn(DATA_PROJECT, json.dumps(self.plan))
        self.assertEqual(len(self.plan['steps']), 4)
        self.assertEqual([s['execution_class'] for s in self.plan['steps']], ['PROVIDER_MUTATION', 'PROVIDER_MUTATION', 'PROVIDER_READ', 'PROVIDER_READ'])
        self.assertIn('cleanup-v2-ephemeral', self.plan['steps'][0]['resource']['resource_reference'])
        self.assertEqual(self.plan['steps'][1]['resource']['resource_reference'].split(':')[-1], GH_SECRET)
        self.assertEqual(self.plan['steps'][2]['resource']['resource_reference'], self.plan['steps'][0]['resource']['resource_reference'])
        self.assertEqual(self.plan['steps'][3]['resource']['resource_reference'], self.plan['steps'][1]['resource']['resource_reference'])
        for index in range(1, 4):
            self.assertEqual(self.plan['steps'][index]['dependency_step_ids'], [self.plan['steps'][index - 1]['step_id']])

    def test_retirement_never_exposes_or_recreates_credentials(self) -> None:
        serialized = json.dumps(self.plan, sort_keys=True)
        self.assertIsNone(re.search(r'sb_secret_[A-Za-z0-9._-]{8,}', serialized))
        self.assertNotIn('service_role', serialized.lower())
        self.assertIn('api-key.reveal', serialized)
        self.assertIn('retirement-resource.recreate', serialized)
        self.assertIn('github-secret.other.delete', serialized)
        self.assertIn('provider-key.other.delete', serialized)
        for step in self.plan['steps']:
            self.assertFalse(step['credential_policy']['values_stored'])
            self.assertEqual(step['credential_policy']['allowed_classes'], ['OWNER_INTERACTIVE_SESSION'])

    def test_preparation_is_pristine_and_has_no_execution_surface(self) -> None:
        self.assertEqual(self.plan['definition_status'], 'READY_FOR_APPROVAL')
        self.assertEqual(self.plan['authority_effect'], 'NONE_UNTIL_SEPARATELY_APPROVED')
        self.assertEqual(self.progress['overall_state'], 'NOT_STARTED')
        self.assertTrue(all(not state['authorization_consumed'] for state in self.progress['step_states']))
        self.assertFalse((BASE / f'{BOUNDARY}.approval.json').exists())
        self.assertFalse((BASE / f'{BOUNDARY}.execution-progress.json').exists())
        self.assertEqual(list(BASE.glob(f'{BOUNDARY}-step*.evidence.json')), [])

    def test_focused_validator_passes(self) -> None:
        result = subprocess.run([sys.executable, str(ROOT / 'tests/contracts/validate_development_auth_v32_synthetic_session_cleanup_credential_retirement_v1.py')], cwd=ROOT, env={**__import__('os').environ, 'PYTHONPATH': str(ROOT / 'src')}, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('no current execution authority', result.stdout)


if __name__ == '__main__':
    unittest.main()
