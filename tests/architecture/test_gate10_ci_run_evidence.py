"""Offline closed-schema checks for one historical, non-certified CI record.

This validates a sanitized transcription, not GitHub authenticity or release authority.
Expected facts are pinned independently here so editing the record cannot add claims.
Only the standard library is used; these tests make no network or provider calls.
"""

import copy
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / "docs/gate10-ci-run-39505222325.evidence.json"

# Closed contract: exact keys, primitive types, values, step order and scope.
EXPECTED = {'schema_version': 1,
 'evidence_class': 'non-certified',
 'environment_scope': ['LOCAL', 'TEST'],
 'repository': 'AnonymousKoo/avuhz-infra',
 'api_observed': {'observation_basis': 'Connected GitHub read API; sanitized run, job steps and '
                                       'artifact listing only.',
                  'run_id': 39505222325,
                  'run_url': 'https://github.com/AnonymousKoo/avuhz-infra/actions/runs/39505222325',
                  'event': 'workflow_dispatch',
                  'attempt': 1,
                  'head_branch': 'main',
                  'head_sha': 'a75818522c42b0a9450ae73a706ab916dd78f14a',
                  'actor_login': 'AnonymousKoo',
                  'actor_id': 168945054,
                  'status': 'completed',
                  'conclusion': 'success',
                  'workflow_path': '.github/workflows/gate10-exact-merge-ci.yml',
                  'job_id': 118912347021,
                  'job_url': 'https://github.com/AnonymousKoo/avuhz-infra/actions/runs/39505222325/job/118912347021',
                  'job_status': 'completed',
                  'job_conclusion': 'success',
                  'steps': [{'number': 1,
                             'name': 'Set up job',
                             'status': 'completed',
                             'conclusion': 'success'},
                            {'number': 2,
                             'name': 'Checkout immutable historical source',
                             'status': 'completed',
                             'conclusion': 'success'},
                            {'number': 3,
                             'name': 'Verify exact source and record non-certified identity',
                             'status': 'completed',
                             'conclusion': 'success'},
                            {'number': 4,
                             'name': 'Install pinned local validation dependencies',
                             'status': 'completed',
                             'conclusion': 'success'},
                            {'number': 5,
                             'name': 'Run canonical repository baseline',
                             'status': 'completed',
                             'conclusion': 'success'},
                            {'number': 6,
                             'name': 'Run portable repository unit suites',
                             'status': 'completed',
                             'conclusion': 'success'},
                            {'number': 7,
                             'name': 'Validate runtime schema representability',
                             'status': 'completed',
                             'conclusion': 'success'},
                            {'number': 8,
                             'name': 'Record cross-repository portability gap',
                             'status': 'completed',
                             'conclusion': 'success'},
                            {'number': 9,
                             'name': 'Start stable disposable PostgreSQL 17',
                             'status': 'completed',
                             'conclusion': 'success'},
                            {'number': 10,
                             'name': 'Run PostgreSQL migration suites',
                             'status': 'completed',
                             'conclusion': 'success'},
                            {'number': 11,
                             'name': 'Replay provider-neutral baseline locally',
                             'status': 'completed',
                             'conclusion': 'success'},
                            {'number': 12,
                             'name': 'Run disposable PostgreSQL integration suites',
                             'status': 'completed',
                             'conclusion': 'success'},
                            {'number': 13,
                             'name': 'Build repository wheel',
                             'status': 'completed',
                             'conclusion': 'success'},
                            {'number': 14,
                             'name': 'Verify repository wheel contents',
                             'status': 'completed',
                             'conclusion': 'success'},
                            {'number': 15,
                             'name': 'Check immutable commit diff hygiene',
                             'status': 'completed',
                             'conclusion': 'success'},
                            {'number': 16,
                             'name': 'Verify final raw checkout integrity',
                             'status': 'completed',
                             'conclusion': 'success'},
                            {'number': 17,
                             'name': 'Remove disposable PostgreSQL',
                             'status': 'completed',
                             'conclusion': 'success'},
                            {'number': 18,
                             'name': 'Record non-certified completion',
                             'status': 'completed',
                             'conclusion': 'success'},
                            {'number': 36,
                             'name': 'Post Checkout immutable historical source',
                             'status': 'completed',
                             'conclusion': 'success'},
                            {'number': 37,
                             'name': 'Complete job',
                             'status': 'completed',
                             'conclusion': 'success'}],
                  'run_artifact_count': 0,
                  'artifact_interpretation': 'Zero artifacts listed by the run artifact API; no '
                                             'retained digest-bound wheel is established.'},
 'log_reported': {'observation_basis': 'Allowlisted actual job output lines, excluding echoed '
                                       'commands; runner claims, not signed attestations.',
                  'workflow_sha': 'a75818522c42b0a9450ae73a706ab916dd78f14a',
                  'source_sha': '047828fe59e743932162df7776fcb37f25647689',
                  'historical_ci_checks': 'passed',
                  'evidence_class': 'non-certified',
                  'provenance': 'absent',
                  'cross_repo_suite_portable': False,
                  'certification_granted': False,
                  'disposable_postgres_cleanup': 'passed',
                  'portable_suite_stage_markers': ['runtime',
                                                   'service',
                                                   'worker',
                                                   'architecture',
                                                   'engineering',
                                                   'security']},
 'workflow_declared_claims': {'observation_basis': 'Ref is enforced by the successful bootstrap; '
                                                   'contact declarations occur in echoed cleanup '
                                                   'script with output redirected, not actual exit '
                                                   'markers.',
                              'ref': 'refs/heads/main',
                              'provider_contact_attempted': False,
                              'supabase_contact_attempted': False,
                              'remote_mutation_attempted': False,
                              'independently_verified': False},
 'limitations': {'historical_source_only': True,
                 'later_main_runtime_validated': False,
                 'interpretation': 'Successful job steps and sanitized log claims do not prove '
                                   'release readiness, external provider state or later main '
                                   'runtime behavior.',
                 'signed_attestation': False,
                 'artifact_digest_bound': False,
                 'artifact_retention_established': False,
                 'human_reviewed_sbom_and_dependency_lock_established': False,
                 'cross_repo_portability_established': False,
                 'attributable_human_gate10_approval_established': False},
 'authority': {'certification_granted': False,
               'merge_authorized': False,
               'production_authorized': False,
               'provider_mutation_authorized': False,
               'deployment_authorized': False,
               'workflow_dispatch_authorized': False,
               'human_approval_granted': False},
 'unresolved_release_conditions': ['Signed provenance bound to the exact reviewed source and '
                                   'artifact.',
                                   'Immutable digest-bound artifact with established retention.',
                                   'Independent human review of SBOM and dependency lock.',
                                   'Cross-repository portability verification.',
                                   'Attributable human Gate10 approval.']}


def reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError("non-finite JSON number")


def validate_shape(actual, expected):
    # bool is a subclass of int; equality alone would accept True as attempt 1.
    if type(actual) is not type(expected):
        raise ValueError("unexpected JSON type")
    if isinstance(expected, dict):
        if actual.keys() != expected.keys():
            raise ValueError("unexpected or missing JSON keys")
        for key in expected:
            validate_shape(actual[key], expected[key])
    elif isinstance(expected, list):
        if len(actual) != len(expected):
            raise ValueError("unexpected list length")
        for item, required in zip(actual, expected):
            validate_shape(item, required)
    elif actual != expected:
        raise ValueError("unexpected evidence claim")


def validate_evidence(text):
    value = json.loads(text, object_pairs_hook=reject_duplicates,
                       parse_constant=reject_constant)
    validate_shape(value, EXPECTED)
    return value


def nodes(value, path=()):
    yield path, value
    if isinstance(value, dict):
        for key, child in value.items():
            yield from nodes(child, path + (key,))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from nodes(child, path + (index,))


def replace_at(value, path, replacement):
    changed = copy.deepcopy(value)
    if not path:
        return replacement
    parent = changed
    for key in path[:-1]:
        parent = parent[key]
    parent[path[-1]] = replacement
    return changed


class Gate10CIRunEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.text = EVIDENCE.read_text(encoding="utf-8")
        self.record = validate_evidence(self.text)

    def reject(self, value):
        with self.assertRaises(ValueError):
            validate_evidence(json.dumps(value))

    def test_record_matches_closed_historical_contract(self):
        self.assertEqual(self.record, EXPECTED)
        self.assertNotEqual(self.record["api_observed"]["head_sha"],
                            self.record["log_reported"]["source_sha"])

    def test_every_claim_change_is_rejected(self):
        for path, value in nodes(self.record):
            if isinstance(value, (dict, list)):
                continue
            changed = (not value if type(value) is bool else
                       value + 1 if type(value) is int else value + " altered")
            with self.subTest(path=path):
                self.reject(replace_at(self.record, path, changed))

    def test_every_node_rejects_wrong_types_including_bool_integer_aliases(self):
        for path, value in nodes(self.record):
            for wrong in (None, True, False, 1, 1.0, "1", {}, []):
                if type(wrong) is type(value):
                    continue
                with self.subTest(path=path, wrong_type=type(wrong).__name__):
                    self.reject(replace_at(self.record, path, wrong))

    def test_all_objects_reject_missing_and_arbitrary_keys(self):
        for path, value in nodes(self.record):
            if not isinstance(value, dict):
                continue
            added = {**value, "arbitrary_claim": "unreviewed"}
            with self.subTest(path=path, extra=True):
                self.reject(replace_at(self.record, path, added))
            for key in value:
                missing = {k: v for k, v in value.items() if k != key}
                with self.subTest(path=path, missing=key):
                    self.reject(replace_at(self.record, path, missing))

    def test_lists_reject_omissions_additions_and_reordering(self):
        for path, value in nodes(self.record):
            if not isinstance(value, list):
                continue
            for changed in (value[:-1], value + ["unreviewed"], list(reversed(value))):
                with self.subTest(path=path):
                    self.reject(replace_at(self.record, path, changed))

    def test_duplicate_keys_rejected_even_when_values_agree(self):
        # Exercise the public parser with duplicates at every object, not just root.
        for path, value in nodes(self.record):
            if not isinstance(value, dict):
                continue
            key = next(iter(value))
            encoded = json.dumps(value)
            duplicate = encoded[:-1] + "," + json.dumps(key) + ":" + json.dumps(value[key]) + "}"
            sentinel = "duplicate_object_placeholder"
            document = json.dumps(replace_at(self.record, path, sentinel))
            document = document.replace(json.dumps(sentinel), duplicate)
            with self.subTest(path=path), self.assertRaises(ValueError):
                validate_evidence(document)

    def test_invalid_json_and_nonfinite_numbers_rejected(self):
        for text in ("", "{", self.text + "{}", "NaN", "Infinity", "-Infinity"):
            with self.subTest(text=text[:20]), self.assertRaises(ValueError):
                validate_evidence(text)

    def test_success_cannot_be_promoted_to_authority(self):
        for key in self.record["authority"]:
            with self.subTest(authority=key):
                self.reject(replace_at(self.record, ("authority", key), True))
        self.reject(replace_at(self.record, ("evidence_class",), "certified"))
        self.reject(replace_at(self.record, ("api_observed", "run_artifact_count"), 1))
        self.reject(replace_at(self.record, ("log_reported", "source_sha"),
                               self.record["api_observed"]["head_sha"]))


if __name__ == "__main__":
    unittest.main()
