"""Local-only durability and RLS proof for the Phase 5A repositories."""
from __future__ import annotations

import copy
import os
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests" / "contracts")]

import psycopg
from psycopg.rows import dict_row

from avuhz_runtime.postgres import PostgresStore, PostgresUnitOfWork, connection_factory_from_environment
from validate_command_payloads import handoff

DSN = os.environ.get("AVUHZ_POSTGRES_DSN")
TA = "a3000000-0000-4000-8000-000000000002"
TB = "b3000000-0000-4000-8000-000000000002"
E = "a3000000-0000-4000-8000-000000000004"
S = "a3000000-0000-4000-8000-000000000005"
DIGEST = "sha256:" + "a" * 64
AUTH_DIGEST = "sha256:" + "b" * 64
NOW = "2030-01-15T15:00:00Z"
LATER = "2030-01-16T15:00:00Z"


def trusted(tenant):
    return SimpleNamespace(authenticated=True, tenant_id=tenant)


@unittest.skipUnless(DSN, "AVUHZ_POSTGRES_DSN is required for local integration tests")
class Phase5ARepositoryTests(unittest.TestCase):
    tables = (
        "avuhz_outbox_deliveries", "avuhz_lifecycle_events", "avuhz_idempotency_records",
        "avuhz_human_approvals", "avuhz_assessment_access_grants", "avuhz_assessment_access_proposals",
        "avuhz_diagnostic_payment_verifications", "avuhz_diagnostic_agreement_authorities",
        "avuhz_diagnostic_scopes", "avuhz_engagements", "avuhz_acquisition_handoffs",
    )

    def setUp(self):
        with psycopg.connect(DSN) as c:
            for table in self.tables:
                c.execute(f"delete from public.{table}")
            for tenant in (TA,):
                h = handoff(); h["tenant_id"] = tenant
                c.execute("insert into public.avuhz_acquisition_handoffs (tenant_id,handoff_id,handoff_version,canonical_account_reference,acquisition_opportunity_reference,qualification_status,target_outcome,validated_constraints,stakeholder_context,assumptions,exclusions,requested_engagement_type,source_system,source_record_version,producer_identity,produced_at,correlation_id,idempotency_key,accepted_at) values (%s,%s,%s,%s,%s,%s,%s,'[]','[]','[]','[]',%s,%s,%s,%s,%s,%s,%s,%s)", (tenant,h["handoff_id"],h["handoff_version"],__import__("json").dumps(h["canonical_account_reference"]),__import__("json").dumps(h["acquisition_opportunity_reference"]),h["qualification_status"],h["target_outcome"],h["requested_engagement_type"],h["source_system"],h["source_record_version"],h["producer_identity"],NOW,h["correlation_id"],h["idempotency_key"],NOW))
                c.execute("insert into public.avuhz_engagements (tenant_id,engagement_id,acquisition_handoff_id,acquisition_handoff_version,account_reference,acquisition_opportunity_reference,engagement_type,engagement_state,engagement_version,record_version,opened_at) values (%s,%s,%s,%s,'fictional-account','fictional-opportunity','DIAGNOSTIC_OIA','OPEN',1,1,%s)", (tenant, E, h["handoff_id"], h["handoff_version"], NOW))
                c.execute("insert into public.avuhz_diagnostic_scopes (tenant_id,diagnostic_scope_id,engagement_id,scope_version,record_version,status,canonical_scope_digest,action_set_version,target_outcome,in_scope_systems,excluded_systems,permitted_actions,prohibited_actions,assumptions,constraint_references,effective_at) values (%s,%s,%s,1,1,'APPROVED',%s,1,'fictional outcome','[{\"system_reference_id\":\"fictional-system-01\"}]','[]',array['VIEW_LOGS'],array['CREATE','MODIFY','DELETE','DEPLOY','RESTART','ROTATE','GRANT','REVOKE','CHANGE_CONFIGURATION','PRODUCTION_CHANGE'],'[]','[]',%s)", (tenant, S, E, DIGEST, NOW))
        self.store = PostgresStore(connection_factory_from_environment())

    def tearDown(self):
        with psycopg.connect(DSN) as c:
            for table in self.tables:
                c.execute(f"delete from public.{table}")

    def uow(self, context=None):
        return PostgresUnitOfWork(self.store, context)

    def agreement(self, ident="10000000-0000-4000-8000-000000000001", tenant=TA):
        return {"diagnostic_agreement_authority_id": ident, "tenant_id": tenant, "engagement_id": E,
                "agreement_type": "DIAGNOSTIC_OIA", "agreement_reference": "fictional-agreement-01",
                "status": "VERIFIED_ACTIVE", "scope_reference": {"reference_type": "DIAGNOSTIC_SCOPE", "reference_id": S, "reference_version": 1},
                "canonical_scope_digest": DIGEST, "effective_at": NOW, "verified_at": NOW, "recorded_at": NOW, "record_version": 1}

    def payment(self, agreement, ident="20000000-0000-4000-8000-000000000001"):
        return {"diagnostic_payment_verification_id": ident, "tenant_id": TA, "engagement_id": E,
                "diagnostic_agreement_authority_reference": {"reference_type": "DIAGNOSTIC_AGREEMENT_AUTHORITY", "reference_id": agreement["diagnostic_agreement_authority_id"], "reference_version": 1},
                "payment_purpose": "DIAGNOSTIC_OIA", "verification_status": "VERIFIED", "provider_reference": "fictional-payment-01", "amount_minor": 100, "currency": "USD", "verified_at": NOW, "record_version": 1}

    def proposal(self, agreement, payment, ident="30000000-0000-4000-8000-000000000001"):
        return {"assessment_access_proposal_id": ident, "tenant_id": TA, "engagement_id": E,
                "diagnostic_scope_reference": {"reference_type": "DIAGNOSTIC_SCOPE", "reference_id": S, "reference_version": 1}, "canonical_scope_digest": DIGEST,
                "assessment_access_authority_digest": AUTH_DIGEST, "action_set_version": 1,
                "diagnostic_agreement_authority_reference": payment["diagnostic_agreement_authority_reference"],
                "diagnostic_payment_verification_reference": {"reference_type": "DIAGNOSTIC_PAYMENT_VERIFICATION", "reference_id": payment["diagnostic_payment_verification_id"], "reference_version": 1},
                "target_system_references": [{"system_reference_id": "fictional-system-01"}], "permitted_actions": ["VIEW_LOGS"], "status": "OPEN", "record_version": 1, "created_at": NOW}

    def grant(self, proposal, ident):
        return {"assessment_access_grant_id": ident, "tenant_id": TA, "engagement_id": E,
                "source_assessment_access_proposal_reference": {"reference_type": "ASSESSMENT_ACCESS_PROPOSAL", "reference_id": proposal["assessment_access_proposal_id"], "reference_version": 1},
                "diagnostic_scope_reference": proposal["diagnostic_scope_reference"], "canonical_scope_digest": DIGEST, "assessment_access_authority_digest": AUTH_DIGEST, "action_set_version": 1,
                "diagnostic_agreement_authority_reference": proposal["diagnostic_agreement_authority_reference"], "diagnostic_payment_verification_reference": proposal["diagnostic_payment_verification_reference"],
                "target_system_references": proposal["target_system_references"], "permitted_actions": proposal["permitted_actions"], "status": "APPROVED", "approved_at": NOW, "record_version": 1}

    def foundation(self):
        u = self.uow(); agreement = self.agreement(); u.diagnostic_agreement_authorities.create(agreement); payment = self.payment(agreement); u.diagnostic_payment_verifications.create(payment); proposal = self.proposal(agreement, payment); u.assessment_access_proposals.create(proposal); u.commit(); u.close(); return agreement, payment, proposal

    def test_agreement_payment_proposal_durability_and_rollback(self):
        agreement, payment, proposal = self.foundation()
        u = self.uow()
        self.assertEqual(u.diagnostic_agreement_authorities.get(TA, agreement["diagnostic_agreement_authority_id"])["agreement_reference"], agreement["agreement_reference"])
        self.assertEqual(u.diagnostic_payment_verifications.get(TA, payment["diagnostic_payment_verification_id"])["verification_status"], "VERIFIED")
        self.assertEqual(u.assessment_access_proposals.get(TA, proposal["assessment_access_proposal_id"])["status"], "OPEN")
        self.assertIsNone(u.diagnostic_agreement_authorities.get(TB, agreement["diagnostic_agreement_authority_id"])); u.close()
        u = self.uow(); invalid = u.diagnostic_payment_verifications.invalidate(TA, payment["diagnostic_payment_verification_id"], LATER); self.assertEqual(invalid["record_version"], 2); u.commit(); u.close()
        u = self.uow(); saved = u.diagnostic_payment_verifications.get(TA, payment["diagnostic_payment_verification_id"]); self.assertEqual((saved["verification_status"], saved["invalidated_at"], saved["record_version"]), ("INVALIDATED", LATER, 2));
        with self.assertRaises(ValueError): u.diagnostic_payment_verifications.invalidate(TA, payment["diagnostic_payment_verification_id"], "2030-01-17T15:00:00Z")
        u.rollback(); u.close()
        u = self.uow(); u.assessment_access_proposals.consume(TA, proposal["assessment_access_proposal_id"], AUTH_DIGEST, LATER); u.commit(); u.close()
        u = self.uow(); consumed = u.assessment_access_proposals.get(TA, proposal["assessment_access_proposal_id"]); self.assertEqual((consumed["status"], consumed["consumed_at"], consumed["record_version"]), ("CONSUMED", LATER, 2)); u.close()
        u = self.uow(); transient = self.agreement("10000000-0000-4000-8000-000000000099"); u.diagnostic_agreement_authorities.create(transient); u.rollback(); u.close()
        u = self.uow(); self.assertIsNone(u.diagnostic_agreement_authorities.get(TA, transient["diagnostic_agreement_authority_id"])); u.close()

    def test_grant_lifecycles_uniqueness_and_transition_rollback(self):
        agreement, payment, proposal = self.foundation()
        paths = (("40000000-0000-4000-8000-000000000001", "active"), ("40000000-0000-4000-8000-000000000002", "expired"), ("40000000-0000-4000-8000-000000000003", "approved-revoked"), ("40000000-0000-4000-8000-000000000004", "active-revoked"), ("40000000-0000-4000-8000-000000000005", "approved-closed"), ("40000000-0000-4000-8000-000000000006", "active-closed"))
        for n, (ident, path) in enumerate(paths, 1):
            p = copy.deepcopy(proposal); p["assessment_access_proposal_id"] = f"30000000-0000-4000-8000-{n + 10:012d}"
            u = self.uow(); u.assessment_access_proposals.create(p); g = self.grant(p, ident); u.assessment_access_grants.create(g); u.commit(); u.close()
            u = self.uow()
            if path != "approved-revoked" and path != "approved-closed": u.assessment_access_grants.activate(TA, ident, AUTH_DIGEST, NOW, LATER)
            if path == "expired": u.assessment_access_grants.expire(TA, ident, LATER)
            elif path.endswith("revoked"): u.assessment_access_grants.revoke(TA, ident, LATER)
            elif path.endswith("closed"): u.assessment_access_grants.close_for_agreement_end(TA, ident, LATER)
            u.commit(); u.close()
            u = self.uow(); got = u.assessment_access_grants.get(TA, ident); self.assertEqual(got["status"], {"active":"ACTIVE", "expired":"EXPIRED", "approved-revoked":"REVOKED", "active-revoked":"REVOKED", "approved-closed":"CLOSED", "active-closed":"CLOSED"}[path]);
            if path not in ("approved-revoked", "approved-closed"): self.assertEqual((got["verified_at"], got["active_from"], got["expires_at"]), (NOW, NOW, LATER))
            u.close()
        u = self.uow(); duplicate = self.grant(proposal, "40000000-0000-4000-8000-000000000099"); u.assessment_access_grants.create(self.grant(proposal, "40000000-0000-4000-8000-000000000098"));
        with self.assertRaises(ValueError): u.assessment_access_grants.create(duplicate)
        u.rollback(); u.close()
        p = copy.deepcopy(proposal); p["assessment_access_proposal_id"] = "30000000-0000-4000-8000-000000000099"; u = self.uow(); u.assessment_access_proposals.create(p); g = self.grant(p, "40000000-0000-4000-8000-000000000097"); u.assessment_access_grants.create(g); u.commit(); u.close()
        u = self.uow(); u.assessment_access_grants.activate(TA, g["assessment_access_grant_id"], AUTH_DIGEST, NOW, LATER); u.rollback(); u.close()
        u = self.uow(); self.assertEqual(u.assessment_access_grants.get(TA, g["assessment_access_grant_id"])["status"], "APPROVED"); u.close()

    def test_assessment_approvals_snapshot_and_command_service_rls(self):
        agreement, payment, proposal = self.foundation()
        def approval(ident, role, category):
            return {"approval_id": ident, "tenant_id": TA, "engagement_id": E, "subject_id": proposal["assessment_access_proposal_id"], "actor_role": role, "authority_category": category, "actor_identity": "fictional:" + role, "actor_organization": "fictional-org", "assessment_access": {"assessment_access_proposal_id": proposal["assessment_access_proposal_id"], "assessment_access_authority_digest": AUTH_DIGEST}, "status": "ACTIVE", "decision": "APPROVE", "conditions": [], "effective_at": NOW, "correlation_id": ident, "idempotency_key": "fictional-" + ident[-4:]}
        u = self.uow(); client = approval("50000000-0000-4000-8000-000000000001", "CLIENT_DECISION_AUTHORITY", "CLIENT_AUTHORITY"); sek = approval("50000000-0000-4000-8000-000000000002", "SEKINFRA_ENGAGEMENT_AUTHORITY", "SEKINFRA_AUTHORITY"); u.human_approvals.record_assessment_access(client); u.human_approvals.record_assessment_access(sek); u.commit(); u.close()
        u = self.uow(); self.assertIsNotNone(u.human_approvals.find_active_assessment_access_binding(TA, proposal["assessment_access_proposal_id"], AUTH_DIGEST, "CLIENT_DECISION_AUTHORITY")); self.assertIsNotNone(u.human_approvals.find_active_assessment_access_binding(TA, proposal["assessment_access_proposal_id"], AUTH_DIGEST, "SEKINFRA_ENGAGEMENT_AUTHORITY"));
        with self.assertRaises(ValueError): u.human_approvals.record_assessment_access(copy.deepcopy(client))
        u.rollback(); u.close()
        class Command: subject_type="ASSESSMENT_ACCESS_PROPOSAL"; tenant_id=TA; subject_id=proposal["assessment_access_proposal_id"]
        snapshot = self.store.snapshot(Command()); self.assertEqual(snapshot.state, "OPEN"); self.assertFalse(any("credential" in key or "provider" in key for key in snapshot.__dict__))
        def role_factory():
            c = psycopg.connect(DSN, autocommit=False, row_factory=dict_row)
            try: c.execute("set role avuhz_command_service")
            except psycopg.errors.InsufficientPrivilege:
                c.close(); self.skipTest("local command-service role has no SET ROLE-capable non-owner test identity")
            return c
        role_store = PostgresStore(role_factory)
        u = PostgresUnitOfWork(role_store, trusted(TA)); self.assertIsNotNone(u.assessment_access_proposals.get(TA, proposal["assessment_access_proposal_id"])); self.assertIsNone(u.assessment_access_proposals.get(TB, proposal["assessment_access_proposal_id"])); u.rollback(); u.close()
        u = PostgresUnitOfWork(role_store); self.assertIsNone(u.assessment_access_proposals.get(TA, proposal["assessment_access_proposal_id"])); u.rollback(); u.close()
        u = PostgresUnitOfWork(role_store, trusted(TB)); self.assertIsNone(u.assessment_access_proposals.get(TA, proposal["assessment_access_proposal_id"])); u.rollback(); u.close()


if __name__ == "__main__":
    unittest.main()
