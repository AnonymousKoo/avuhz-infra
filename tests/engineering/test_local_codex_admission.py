"""Offline functional tests for signed LOCAL Codex admission preflight."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from avuhz_engineering.local_codex_admission import (
    COMMAND_PROFILE_CATALOG_DIGEST,
    COMMAND_PROFILE_IDS,
    PURPOSE,
    STOP_CONDITION_IDS,
    AdmissionStop,
    TrustedRepositoryObservation,
    admit_preflight,
    canonical_bytes,
    validate_signed_admission,
)
from avuhz_engineering.local_engineering_queue import (
    approval_digest,
    approval_scope,
    canonical_digest,
    manifest_digest,
)


class LocalCodexAdmissionTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="avuhz-admission-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.repository = (self.base / "checkout").absolute()
        self.repository.mkdir(mode=0o700)
        self.private = (self.base / "private").absolute()
        self.private.mkdir(mode=0o700)
        self.replay = self.private / "replay.sqlite3"
        self._create_replay_store()
        self.now = datetime(2026, 10, 18, 16, 0, 0, tzinfo=timezone.utc)
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.public_key_digest = "sha256:" + hashlib.sha256(self.public_key).hexdigest()
        self.queue = self._queue_manifest()
        self.document = self._document()
        self.observation = TrustedRepositoryObservation(
            repository="AnonymousKoo/avuhz-infra",
            branch="refs/heads/phase2a-admission",
            commit="7" * 40,
            tree="b" * 40,
            reviewed_digest="sha256:" + "c" * 64,
            worktree_clean=True,
            worktree_root=str(self.repository),
            isolation_id="worktree.phase2a.20261018",
        )

    def _create_replay_store(self) -> None:
        connection = sqlite3.connect(self.replay)
        connection.execute(
            "CREATE TABLE avuhz_local_codex_admission_nonce_v1 ("
            "nonce_digest TEXT NOT NULL PRIMARY KEY, task_digest TEXT NOT NULL, "
            "manifest_digest TEXT NOT NULL, claimed_at TEXT NOT NULL)"
        )
        connection.commit()
        connection.close()
        os.chmod(self.replay, 0o600)

    def _queue_manifest(self) -> dict:
        value = {
            "schema_version": 1,
            "manifest_id": "manifest.phase2a-one",
            "environment": "LOCAL",
            "namespace": "AAE/local",
            "repository": "AnonymousKoo/avuhz-infra",
            "scope": "repository-local-engineering",
            "worktree": {
                "root": str(self.repository),
                "ownership": "EXCLUSIVE_LOCAL_WORKTREE",
            },
            "allowed_file_paths": ["src/local_change.py"],
            "target_baselines": [{"path": "src/local_change.py", "digest": "ABSENT"}],
            "tasks": [{
                "task_id": "task.phase2a-one",
                "resource_reference": "repository.local-change",
                "allowed_file_paths": ["src/local_change.py"],
                "acceptance_criteria": ["tests.focused.pass"],
                "stop_conditions": ["boundary.drift"],
            }],
            "approval": {
                "approval_id": "approval.phase2a-one",
                "approved_task_ids": ["task.phase2a-one"],
                "scope_digest": "",
                "approval_digest": "",
                "authority_effect": "REPOSITORY_LOCAL_ONLY",
                "immutable": True,
                "provider_authority": False,
            },
        }
        value["approval"]["scope_digest"] = canonical_digest(approval_scope(value))
        value["approval"]["approval_digest"] = approval_digest(value["approval"])
        return value

    def _document(self) -> dict:
        payload = {
            "version": 1,
            "purpose": PURPOSE,
            "namespace": "AAE/local",
            "environment": "LOCAL",
            "repository": "AnonymousKoo/avuhz-infra",
            "issuer": "operator.local-v1",
            "source": {
                "branch": "refs/heads/phase2a-admission",
                "commit": "7" * 40,
                "tree": "b" * 40,
                "reviewed_digest": "sha256:" + "c" * 64,
            },
            "queue_manifest": {
                "manifest_id": self.queue["manifest_id"],
                "manifest_digest": manifest_digest(self.queue),
                "approval_digest": self.queue["approval"]["approval_digest"],
            },
            "task_id": "task.phase2a-one",
            "nonce": "nonce_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890",
            "prompt_digest": "sha256:" + "d" * 64,
            "command_profile_ids": sorted(COMMAND_PROFILE_IDS),
            "command_catalog_digest": COMMAND_PROFILE_CATALOG_DIGEST,
            "allowed_target_paths": ["src/local_change.py"],
            "stop_conditions": sorted(STOP_CONDITION_IDS),
            "isolation_id": "worktree.phase2a.20261018",
            "limits": {
                "wall_clock_seconds": 600,
                "cpu_seconds": 300,
                "max_processes": 4,
                "memory_bytes": 536_870_912,
                "output_bytes": 1_048_576,
            },
            "network": False,
            "provider_authority": "NONE",
            "github_mutation": False,
            "mode": "PREFLIGHT_ONLY",
            "issued_at": "2026-10-18T15:59:00Z",
            "not_before": "2026-10-18T15:59:00Z",
            "expires_at": "2026-10-18T16:09:00Z",
        }
        return self._sign_payload(payload)

    def _sign_payload(self, payload: dict, *, key: Ed25519PrivateKey | None = None) -> dict:
        signing_key = key or self.private_key
        signature = signing_key.sign(canonical_bytes(payload))
        return {
            "payload": payload,
            "signature": {
                "algorithm": "Ed25519",
                "key_id": "operator-key.local-v1",
                "value": base64.urlsafe_b64encode(signature).rstrip(b"=").decode(),
            },
        }

    def _raw(self, document: dict | None = None) -> bytes:
        return canonical_bytes(document or self.document)

    def _validate(self, document: dict | None = None, **overrides):
        arguments = {
            "repository_root": self.repository,
            "queue_manifest": self.queue,
            "observed_source": self.observation,
            "at_utc": self.now,
            "pinned_issuer": "operator.local-v1",
            "pinned_key_id": "operator-key.local-v1",
            "pinned_public_key": self.public_key,
            "pinned_public_key_digest": self.public_key_digest,
        }
        arguments.update(overrides)
        return validate_signed_admission(self._raw(document), **arguments)

    def _resign(self, document: dict) -> dict:
        return self._sign_payload(document["payload"])

    def _admit(self, document: dict | None = None, **overrides):
        arguments = {
            "replay_store_path": self.replay,
            "repository_root": self.repository,
            "queue_manifest": self.queue,
            "observed_source": self.observation,
            "at_utc": self.now,
            "pinned_issuer": "operator.local-v1",
            "pinned_key_id": "operator-key.local-v1",
            "pinned_public_key": self.public_key,
            "pinned_public_key_digest": self.public_key_digest,
        }
        arguments.update(overrides)
        return admit_preflight(self._raw(document), **arguments)

    def assert_code(self, code: str, function, *args, **kwargs) -> None:
        with self.assertRaises(AdmissionStop) as raised:
            function(*args, **kwargs)
        self.assertEqual(raised.exception.code, code)
        self.assertEqual(str(raised.exception), code)

    def test_valid_signature_is_preflight_only_and_nonce_claim_is_durable(self):
        candidate = self._validate()
        self.assertFalse(candidate.execution_authorized)
        self.assertEqual(candidate.status, "PREFLIGHT_VERIFIED_REPLAY_UNCLAIMED")
        result = self._admit()
        self.assertEqual(result.status, "PREFLIGHT_ADMITTED")
        self.assertFalse(result.execution_performed)
        self.assertFalse(result.execution_authorized)
        self.assertFalse(result.retry_authorized)
        self.assertFalse(result.network_authorized)
        self.assertFalse(result.github_mutation_authorized)
        self.assertEqual(result.provider_authority, "NONE")

    def test_constructed_candidate_cannot_claim_and_drift_is_revalidated(self):
        candidate = self._validate()
        self.assert_code(
            "MANIFEST_JSON_INVALID", admit_preflight, candidate,
            replay_store_path=self.replay, repository_root=self.repository,
            queue_manifest=self.queue, observed_source=self.observation,
            at_utc=self.now, pinned_issuer="operator.local-v1",
            pinned_key_id="operator-key.local-v1", pinned_public_key=self.public_key,
            pinned_public_key_digest=self.public_key_digest,
        )
        (self.base / "outside").mkdir()
        (self.repository / "src").symlink_to(self.base / "outside")
        self.assert_code("QUEUE_MANIFEST_INVALID", self._admit)

    def test_tampered_payload_and_signature_are_rejected(self):
        tampered = copy.deepcopy(self.document)
        tampered["payload"]["prompt_digest"] = "sha256:" + "e" * 64
        self.assert_code("SIGNATURE_INVALID", self._validate, tampered)
        malformed = copy.deepcopy(self.document)
        malformed["signature"]["value"] = "a" * 86
        self.assert_code("SIGNATURE_INVALID", self._validate, malformed)

    def test_foreign_or_substituted_trust_root_is_rejected(self):
        attacker = Ed25519PrivateKey.generate()
        foreign = self._sign_payload(copy.deepcopy(self.document["payload"]), key=attacker)
        self.assert_code("SIGNATURE_INVALID", self._validate, foreign)
        attacker_public = attacker.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.assert_code(
            "TRUST_ANCHOR_UNVERIFIED", self._validate, self.document,
            pinned_public_key=attacker_public,
        )
        untrusted_key_field = copy.deepcopy(self.document)
        untrusted_key_field["public_key"] = "not-a-trust-root"
        self.assert_code("MANIFEST_KEYS_INVALID", self._validate, untrusted_key_field)

    def test_source_commit_tree_branch_review_and_dirty_state_are_bound(self):
        for field, value in (
            ("repository", "Other/repo"),
            ("commit", "8" * 40),
            ("tree", "9" * 40),
            ("reviewed_digest", "sha256:" + "a" * 64),
            ("branch", "refs/heads/other"),
        ):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.observation.__dict__)
                changed[field] = value
                self.assert_code(
                    "SOURCE_MISMATCH", self._validate, self.document,
                    observed_source=TrustedRepositoryObservation(**changed),
                )
        dirty = copy.deepcopy(self.observation.__dict__)
        dirty["worktree_clean"] = False
        self.assert_code(
            "WORKTREE_DIRTY", self._validate, self.document,
            observed_source=TrustedRepositoryObservation(**dirty),
        )
        wrong_isolation = copy.deepcopy(self.observation.__dict__)
        wrong_isolation["isolation_id"] = "worktree.foreign.20261018"
        self.assert_code(
            "ISOLATION_INVALID", self._validate, self.document,
            observed_source=TrustedRepositoryObservation(**wrong_isolation),
        )

    def test_extra_authority_network_and_excessive_limits_are_rejected(self):
        cases = (
            ("network", True, "AUTHORITY_INVALID"),
            ("provider_authority", "DEVELOPMENT", "AUTHORITY_INVALID"),
            ("github_mutation", True, "AUTHORITY_INVALID"),
            ("mode", "EXECUTE", "AUTHORITY_INVALID"),
        )
        for field, value, code in cases:
            with self.subTest(field=field):
                changed = copy.deepcopy(self.document)
                changed["payload"][field] = value
                self.assert_code(code, self._validate, self._resign(changed))
        changed = copy.deepcopy(self.document)
        changed["payload"]["limits"]["max_processes"] = 17
        self.assert_code("LIMITS_INVALID", self._validate, self._resign(changed))

    def test_expired_future_ambiguous_and_overlong_windows_are_rejected(self):
        cases = (
            ("expires_at", "2026-10-18T16:00:00Z", "TIME_WINDOW_INVALID"),
            ("not_before", "2026-10-18T16:00:01Z", "TIME_WINDOW_INVALID"),
            ("issued_at", "2026-10-18T15:58:59Z", "TIME_WINDOW_INVALID"),
            ("issued_at", "2026-10-18T15:59:00+00:00", "TIME_INVALID"),
        )
        for field, value, code in cases:
            with self.subTest(field=field):
                changed = copy.deepcopy(self.document)
                changed["payload"][field] = value
                self.assert_code(code, self._validate, self._resign(changed))

    def test_duplicate_nonce_and_corrupt_store_fail_closed(self):
        self._admit()
        self.assert_code("NONCE_REPLAY", self._admit)
        corrupt = self.private / "corrupt.sqlite3"
        corrupt.write_bytes(b"not sqlite")
        os.chmod(corrupt, 0o600)
        self.assert_code(
            "REPLAY_STORE_UNVERIFIED", self._admit,
            replay_store_path=corrupt,
        )

    def test_wrong_replay_schema_permissions_and_symlink_are_denied(self):
        wrong = self.private / "wrong.sqlite3"
        sqlite3.connect(wrong).close()
        os.chmod(wrong, 0o600)
        self.assert_code(
            "REPLAY_STORE_CORRUPT", self._admit, replay_store_path=wrong,
        )
        os.chmod(wrong, 0o644)
        self.assert_code(
            "REPLAY_STORE_UNTRUSTED", self._admit, replay_store_path=wrong,
        )
        linked = self.private / "linked.sqlite3"
        linked.symlink_to(self.replay)
        self.assert_code(
            "REPLAY_STORE_UNTRUSTED", self._admit, replay_store_path=linked,
        )

    def test_path_traversal_symlink_and_phase1_binding_are_rejected(self):
        traversal = copy.deepcopy(self.document)
        traversal["payload"]["allowed_target_paths"] = ["../escape.py"]
        self.assert_code("PATH_ESCAPE", self._validate, self._resign(traversal))

        (self.repository / "src").symlink_to(self.base / "outside")
        self.assert_code("QUEUE_MANIFEST_INVALID", self._validate, self.document)

        (self.repository / "src").unlink()
        changed_queue = copy.deepcopy(self.queue)
        changed_queue["approval"]["approval_id"] = "approval.phase2a-two"
        changed_queue["approval"]["approval_digest"] = approval_digest(changed_queue["approval"])
        self.assert_code(
            "QUEUE_BINDING_INVALID", self._validate, self.document,
            queue_manifest=changed_queue,
        )

    def test_wrong_namespace_repository_profiles_and_shell_fields_are_rejected(self):
        for field, value, code in (
            ("namespace", "AAE/other", "LOCAL_BOUNDARY_INVALID"),
            ("repository", "Other/repo", "REPOSITORY_INVALID"),
        ):
            changed = copy.deepcopy(self.document)
            changed["payload"][field] = value
            self.assert_code(code, self._validate, self._resign(changed))
        profile = copy.deepcopy(self.document)
        profile["payload"]["command_profile_ids"] = ["python -c shell"]
        self.assert_code(
            "PROFILE_OR_STOP_CONDITION_INVALID", self._validate, self._resign(profile)
        )
        shell = copy.deepcopy(self.document)
        shell["payload"]["command"] = "sh -c whoami"
        self.assert_code("PAYLOAD_KEYS_INVALID", self._validate, shell)

        secret_queue = copy.deepcopy(self.queue)
        secret_queue["allowed_file_paths"] = [".env"]
        secret_queue["target_baselines"] = [{"path": ".env", "digest": "ABSENT"}]
        secret_queue["tasks"][0]["allowed_file_paths"] = [".env"]
        secret_queue["approval"]["scope_digest"] = canonical_digest(approval_scope(secret_queue))
        secret_queue["approval"]["approval_digest"] = approval_digest(secret_queue["approval"])
        self.assert_code(
            "QUEUE_MANIFEST_INVALID", self._validate, self.document,
            queue_manifest=secret_queue,
        )

    def test_noncanonical_duplicate_and_nonfinite_json_are_rejected(self):
        raw = json.dumps(self.document, indent=2).encode()
        self.assert_code(
            "MANIFEST_NONCANONICAL", validate_signed_admission, raw,
            repository_root=self.repository, queue_manifest=self.queue,
            observed_source=self.observation, at_utc=self.now,
            pinned_issuer="operator.local-v1", pinned_key_id="operator-key.local-v1",
            pinned_public_key=self.public_key,
            pinned_public_key_digest=self.public_key_digest,
        )
        duplicate = b'{"payload":{},"payload":{},"signature":{}}'
        self.assert_code(
            "MANIFEST_JSON_INVALID", validate_signed_admission, duplicate,
            repository_root=self.repository, queue_manifest=self.queue,
            observed_source=self.observation, at_utc=self.now,
            pinned_issuer="operator.local-v1", pinned_key_id="operator-key.local-v1",
            pinned_public_key=self.public_key,
            pinned_public_key_digest=self.public_key_digest,
        )
        nonfinite = b'{"payload":NaN,"signature":{}}'
        self.assert_code(
            "MANIFEST_JSON_INVALID", validate_signed_admission, nonfinite,
            repository_root=self.repository, queue_manifest=self.queue,
            observed_source=self.observation, at_utc=self.now,
            pinned_issuer="operator.local-v1", pinned_key_id="operator-key.local-v1",
            pinned_public_key=self.public_key,
            pinned_public_key_digest=self.public_key_digest,
        )

    def test_schema_accepts_valid_document_and_matches_branch_denial(self):
        schema = json.loads(
            (ROOT / "docs/schemas/local-codex-admission-v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        validator = Draft202012Validator(schema)
        self.assertEqual(list(validator.iter_errors(self.document)), [])
        invalid = copy.deepcopy(self.document)
        invalid["payload"]["source"]["branch"] = "refs/heads/bad..branch"
        self.assertTrue(list(validator.iter_errors(invalid)))
        self.assert_code("SOURCE_INVALID", self._validate, self._resign(invalid))


if __name__ == "__main__":
    unittest.main()
