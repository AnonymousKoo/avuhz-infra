"""Disposable local PostgreSQL harness for the provider-neutral Avuhz baseline."""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

import psycopg
from psycopg import sql
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "src")]
DSN = os.environ.get("AVUHZ_POSTGRES_DSN")

from avuhz_runtime.guards import GuardPipeline
from avuhz_runtime.implementation_handoff import ImplementationHandoffAcceptanceService
from avuhz_runtime.in_memory import Executor
from avuhz_runtime.postgres import PostgresStore, PostgresUnitOfWork
from avuhz_runtime.validation import CommandValidator
from tests.runtime import test_phase5d_implementation_brief_runtime as brief_runtime

TABLES = (
    "avuhz_deployment_executions", "avuhz_deployment_authorizations", "avuhz_client_acceptances", "avuhz_qa_results", "avuhz_build_execution_results", "avuhz_codex_build_packages",
    "avuhz_implementation_authorizations", "avuhz_implementation_briefs",
    "avuhz_human_approvals", "avuhz_outbox_deliveries", "avuhz_lifecycle_events",
    "avuhz_idempotency_records", "avuhz_implementation_handoffs", "avuhz_engagements",
    "avuhz_acquisition_handoffs",
)


@unittest.skipUnless(DSN, "disposable local provider-neutral PostgreSQL DSN is required")
class ProviderNeutralPostgresHarness(unittest.TestCase):
    OTHER_TENANT = "d5ff0000-0000-4000-8000-000000000099"

    @classmethod
    def owner(cls, *, autocommit=False):
        return psycopg.connect(DSN, autocommit=autocommit, row_factory=dict_row)

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if DSN:
            with cls.owner(autocommit=True) as connection:
                owner = connection.execute("select current_user").fetchone()["current_user"]
                connection.execute(
                    sql.SQL("grant avuhz_command_service to {}").format(sql.Identifier(owner))
                )

    @classmethod
    def tearDownClass(cls):
        if DSN:
            with cls.owner(autocommit=True) as connection:
                owner = connection.execute("select current_user").fetchone()["current_user"]
                connection.execute(
                    sql.SQL("revoke avuhz_command_service from {}").format(sql.Identifier(owner))
                )
        super().tearDownClass()

    @classmethod
    def service_factory(cls):
        connection = psycopg.connect(DSN, autocommit=True, row_factory=dict_row)
        connection.execute("set role avuhz_command_service")
        return connection

    def setUp(self):
        self._truncate()
        self.harness = brief_runtime.ImplementationBriefRuntimeTests()
        self.harness.setUp()
        self.harness.now = self.harness.h.now
        self.harness.executor = self.executor()
        self._seeded = False

    def tearDown(self):
        self._truncate()

    def _truncate(self):
        with self.owner() as connection:
            connection.execute("truncate " + ",".join("public." + table for table in TABLES) + " cascade")

    def executor(self, store=None):
        return Executor(
            CommandValidator(ROOT / "contracts/schemas/v1"), GuardPipeline(),
            store or PostgresStore(self.service_factory), clock=lambda: self.harness.h.now,
            ids=self.harness.next_id, uow_factory=PostgresUnitOfWork,
        )

    def build_active(self):
        if self._seeded:
            return
        h = self.harness
        acquisition_id = "d5000000-0000-4000-8000-000000000090"
        account = {"reference_type": "ACCOUNT", "reference_id": "account.fictional"}
        opportunity = {"reference_type": "OPPORTUNITY", "reference_id": "opportunity.fictional"}
        with self.owner() as connection:
            connection.execute(
                "insert into public.avuhz_acquisition_handoffs "
                "(tenant_id,handoff_id,handoff_version,canonical_account_reference,"
                "acquisition_opportunity_reference,qualification_status,target_outcome,"
                "validated_constraints,stakeholder_context,assumptions,exclusions,"
                "requested_engagement_type,source_system,source_record_version,producer_identity,"
                "produced_at,correlation_id,idempotency_key,accepted_at) "
                "values (%s,%s,1,%s,%s,'QUALIFIED','Provider-neutral implementation handoff.',"
                "%s,%s,%s,%s,'IMPLEMENTATION','fictional-provider','1','provider-adapter.fictional',"
                "%s,%s,'provider-neutral-local-seed',%s)",
                (h.tenant, acquisition_id, Jsonb(account), Jsonb(opportunity), Jsonb([]), Jsonb([]),
                 Jsonb([]), Jsonb([]), h.h.now, "d5000000-0000-4000-8000-000000000091", h.h.now),
            )
            connection.execute(
                "insert into public.avuhz_engagements "
                "(tenant_id,engagement_id,acquisition_handoff_id,acquisition_handoff_version,"
                "account_reference,acquisition_opportunity_reference,engagement_type,"
                "engagement_state,engagement_version,record_version,opened_at) "
                "values (%s,%s,%s,1,%s,%s,'IMPLEMENTATION','OPEN',1,1,%s)",
                (h.tenant, h.engagement_id, acquisition_id, Jsonb(account), Jsonb(opportunity), h.h.now),
            )
        uow = PostgresUnitOfWork(PostgresStore(self.service_factory), h.handoff_context())
        try:
            ImplementationHandoffAcceptanceService(uow).accept(h.handoff, h.handoff_context())
            uow.commit()
        except Exception:
            uow.rollback()
            raise
        finally:
            uow.close()
        self._seeded = True
