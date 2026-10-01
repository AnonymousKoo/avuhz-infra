from __future__ import annotations

import ast
import json
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from avuhz_engineering import development_data_catalog_rls_validation as validation
from avuhz_runtime.implementation_handoff import canonical_digest


def catalog_shape() -> dict:
    return {
        "tables": [["table", True, False] for _ in range(validation.EXPECTED_TABLE_COUNT)],
        "columns": [["column"] for _ in range(validation.EXPECTED_COLUMN_COUNT)],
        "constraints": [["constraint"] for _ in range(validation.EXPECTED_CONSTRAINT_COUNT)],
        "policies": [["policy"] for _ in range(validation.EXPECTED_POLICY_COUNT)],
        "table_grants": [["grant"] for _ in range(validation.EXPECTED_TABLE_GRANT_COUNT)],
        "column_grants": [["grant"] for _ in range(validation.EXPECTED_COLUMN_GRANT_COUNT)],
        "schema_usage": True,
        "schema_create": False,
    }


class FakeCursor:
    def __init__(self, row=None):
        self._row = row

    def fetchone(self):
        return self._row


class FakeConnection:
    def __init__(
        self,
        *,
        host=validation.DEVELOPMENT_DATA_ENDPOINT_HOST,
        runtime_ready=True,
        effective_ready=True,
        shape=None,
        fail_statement=None,
    ):
        self.autocommit = False
        self.info = SimpleNamespace(host=host)
        self.runtime_ready = runtime_ready
        self.effective_ready = effective_ready
        self.shape = catalog_shape() if shape is None else shape
        self.fail_statement = fail_statement
        self.executions = []
        self.rollbacks = 0
        self.closed = False

    def execute(self, statement, parameters=()):
        self.executions.append((statement, parameters))
        if self.fail_statement is not None and statement == self.fail_statement:
            raise RuntimeError("private database failure")
        if statement == validation.BEGIN_READ_ONLY_SQL:
            return FakeCursor()
        if statement == validation.RUNTIME_STATE_SQL:
            return FakeCursor({"ready": self.runtime_ready})
        if statement == validation.SET_COMMAND_ROLE_SQL:
            return FakeCursor()
        if statement == validation.EFFECTIVE_STATE_SQL:
            return FakeCursor({"ready": self.effective_ready})
        if statement == validation.CATALOG_SHAPE_SQL:
            return FakeCursor({"catalog_shape": self.shape})
        raise AssertionError(f"unexpected statement: {statement!r}")

    def rollback(self):
        self.rollbacks += 1

    def close(self):
        self.closed = True


class DevelopmentDataCatalogRlsValidationTests(unittest.TestCase):
    def inspect(self, connection: FakeConnection):
        digest = canonical_digest(connection.shape)
        with patch.object(validation, "EXPECTED_CATALOG_DIGEST", digest):
            return validation.inspect_development_data_catalog(
                connection_factory=lambda: connection,
            )

    def test_success_is_one_read_only_transaction_and_closes(self):
        connection = FakeConnection()
        result = self.inspect(connection)

        self.assertEqual(
            result.classification,
            validation.DataCatalogValidationClassification.PASS,
        )
        self.assertEqual(connection.executions[0], (validation.BEGIN_READ_ONLY_SQL, ()))
        self.assertEqual(connection.executions[1][0], validation.RUNTIME_STATE_SQL)
        self.assertEqual(
            connection.executions[1][1],
            (
                validation.DEVELOPMENT_DATA_RUNTIME_LOGIN,
                validation.CANONICAL_COMMAND_ROLE,
                validation.DEVELOPMENT_DATA_MIGRATION_IDENTITY,
                validation.DEVELOPMENT_DATA_MIGRATION_IDENTITY,
            ),
        )
        self.assertEqual(connection.executions[2], (validation.SET_COMMAND_ROLE_SQL, ()))
        self.assertEqual(connection.executions[3][0], validation.EFFECTIVE_STATE_SQL)
        self.assertEqual(connection.executions[4], (validation.CATALOG_SHAPE_SQL, ()))
        self.assertEqual(connection.rollbacks, 1)
        self.assertTrue(connection.closed)

    def test_endpoint_runtime_and_effective_role_drift_fail_closed(self):
        cases = (
            (
                FakeConnection(host="db.example.invalid"),
                "DATA_CATALOG_ENDPOINT_MISMATCH",
            ),
            (
                FakeConnection(runtime_ready=False),
                "DATA_CATALOG_RUNTIME_ROLE_MISMATCH",
            ),
            (
                FakeConnection(effective_ready=False),
                "DATA_CATALOG_EFFECTIVE_ROLE_MISMATCH",
            ),
        )
        for connection, code in cases:
            with self.subTest(code=code):
                with self.assertRaises(
                    validation.SafeDevelopmentDataValidationStop
                ) as raised:
                    self.inspect(connection)
                self.assertEqual(raised.exception.code, code)
                self.assertEqual(connection.rollbacks, 1)
                self.assertTrue(connection.closed)

    def test_connection_and_query_failures_hide_exception_text(self):
        def unavailable():
            raise RuntimeError("private credential or connection detail")

        with self.assertRaises(validation.SafeDevelopmentDataValidationStop) as raised:
            validation.inspect_development_data_catalog(connection_factory=unavailable)
        self.assertEqual(raised.exception.code, "DATA_CATALOG_CONNECTION_UNAVAILABLE")
        self.assertNotIn("private", repr(raised.exception))

        connection = FakeConnection(fail_statement=validation.RUNTIME_STATE_SQL)
        with self.assertRaises(validation.SafeDevelopmentDataValidationStop) as raised:
            self.inspect(connection)
        self.assertEqual(raised.exception.code, "DATA_CATALOG_QUERY_FAILED")
        self.assertNotIn("private", repr(raised.exception))
        self.assertEqual(connection.rollbacks, 1)
        self.assertTrue(connection.closed)

    def test_count_schema_and_digest_mismatch_fail_closed(self):
        shape = catalog_shape()
        shape["tables"] = shape["tables"][:-1]
        connection = FakeConnection(shape=shape)
        with patch.object(
            validation,
            "EXPECTED_CATALOG_DIGEST",
            canonical_digest(connection.shape),
        ):
            with self.assertRaises(
                validation.SafeDevelopmentDataValidationStop
            ) as raised:
                validation.inspect_development_data_catalog(
                    connection_factory=lambda: connection
                )
        self.assertEqual(raised.exception.code, "DATA_CATALOG_COUNT_MISMATCH")

        shape = catalog_shape()
        shape["schema_create"] = True
        connection = FakeConnection(shape=shape)
        with patch.object(
            validation,
            "EXPECTED_CATALOG_DIGEST",
            canonical_digest(connection.shape),
        ):
            with self.assertRaises(
                validation.SafeDevelopmentDataValidationStop
            ) as raised:
                validation.inspect_development_data_catalog(
                    connection_factory=lambda: connection
                )
        self.assertEqual(
            raised.exception.code,
            "DATA_CATALOG_SCHEMA_PRIVILEGE_MISMATCH",
        )

        connection = FakeConnection()
        with patch.object(
            validation,
            "EXPECTED_CATALOG_DIGEST",
            "sha256:" + "0" * 64,
        ):
            with self.assertRaises(
                validation.SafeDevelopmentDataValidationStop
            ) as raised:
                validation.inspect_development_data_catalog(
                    connection_factory=lambda: connection
                )
        self.assertEqual(raised.exception.code, "DATA_CATALOG_DIGEST_MISMATCH")

    def test_success_evidence_is_bounded_and_secret_free(self):
        connection = FakeConnection()
        result = self.inspect(connection)
        evidence = validation.sanitized_data_catalog_evidence(
            result,
            plan_id="11111111-1111-4111-8111-111111111111",
            plan_digest="sha256:" + "a" * 64,
            attempted_at="2030-02-01T15:15:00Z",
        )
        rendered = json.dumps(evidence, sort_keys=True)
        self.assertEqual(
            evidence["validation_classification"],
            "DATA_CATALOG_RLS_VALIDATED",
        )
        self.assertTrue(evidence["transaction_read_only"])
        self.assertTrue(evidence["rollback_attempted"])
        self.assertFalse(evidence["business_rows_read"])
        self.assertFalse(evidence["auth_data_read"])
        self.assertFalse(evidence["provider_mutation_attempted"])
        self.assertFalse(evidence["ddl_attempted"])
        self.assertFalse(evidence["credential_material_retained"])
        self.assertFalse(evidence["raw_catalog_metadata_retained"])
        self.assertNotIn("AVUHZ_POSTGRES_DSN", rendered)
        self.assertNotIn("postgresql://", rendered)
        self.assertNotIn(str(connection.shape), rendered)

    def test_sql_surface_is_catalog_only_and_contains_no_business_row_query(self):
        sql_values = (
            validation.RUNTIME_STATE_SQL,
            validation.EFFECTIVE_STATE_SQL,
            validation.CATALOG_SHAPE_SQL,
        )
        rendered = "\n".join(sql_values).lower()
        self.assertNotIn(" from public.avuhz_", rendered)
        self.assertNotIn(" join public.avuhz_", rendered)
        self.assertNotIn("insert into", rendered)
        self.assertNotIn("update public.", rendered)
        self.assertNotIn("delete from", rendered)
        self.assertNotIn("alter table", rendered)
        self.assertNotIn("create table", rendered)
        self.assertNotIn("drop table", rendered)
        self.assertIn("pg_catalog", rendered)
        self.assertIn("information_schema", rendered)

    def test_only_one_connection_factory_call_is_structurally_reachable(self):
        source = validation.__file__
        tree = ast.parse(Path(source).read_text(encoding="utf-8"))
        factory_calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "connection_factory"
        ]
        self.assertEqual(len(factory_calls), 1)


if __name__ == "__main__":
    unittest.main()
