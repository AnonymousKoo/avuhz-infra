"""No hosted issuer: ephemeral test-only Ed25519 signatures and owner stubs."""
from __future__ import annotations

import hashlib
import json
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from avuhz_runtime.guards import TrustedExecutionContext
from avuhz_service.development import (
    DEVELOPMENT_AUTH_PROJECT_REF, DEVELOPMENT_DATA_PROJECT_REF,
)
from avuhz_service.development_active_owner_membership import DevelopmentActiveOwnerMembershipCheck
from avuhz_service.development_owner_authentication import (
    DevelopmentOwnerAuthenticationCheckpoint, ProvisionalOwnerAuthentication,
)
from avuhz_service.development_owner_mfa_freshness import DevelopmentOwnerMfaFreshnessCheck
from avuhz_service.development_signed_work_owner_identity import (
    DevelopmentSignedWorkOwnerIdentityResolver, SignedWorkOwnerPrincipalBinding,
    PURPOSE, ISSUER,
)
from avuhz_service.shared_work_intake_candidate import SharedWorkIntakeCandidate

TENANT = "a4730000-0000-4000-8000-000000000001"
ORG = "a4730000-0000-4000-8000-000000000011"
OTHER = "a4730000-0000-4000-8000-000000000002"
DIGEST = "sha256:" + "a" * 64
REF = "owner.registered-principal-001"


class SignedOwnerIdentityTests(unittest.TestCase):
    def setUp(self):
        self.clock = datetime.now(timezone.utc).replace(microsecond=0)
        self.key = Ed25519PrivateKey.generate()  # test memory only; never persisted
        public = self.key.public_key()
        fp = "sha256:" + hashlib.sha256(public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )).hexdigest()
        self.checkpoint = object.__new__(DevelopmentOwnerAuthenticationCheckpoint)
        self.mfa = object.__new__(DevelopmentOwnerMfaFreshnessCheck)
        self.membership = object.__new__(DevelopmentActiveOwnerMembershipCheck)
        self.provisional = ProvisionalOwnerAuthentication(
            DIGEST, self.utc(self.clock - timedelta(seconds=3))
        )
        self.mfa_ok = True
        self.membership_ok = True
        self.calls = []
        self.jwt = "private-signed-development-auth-bearer"
        self.statement = {
            "purpose": PURPOSE, "issuer": ISSUER, "environment": "DEVELOPMENT",
            "auth_project_ref": DEVELOPMENT_AUTH_PROJECT_REF,
            "data_project_ref": DEVELOPMENT_DATA_PROJECT_REF,
            "tenant_id": TENANT, "organization_id": ORG,
            "subject_digest": DIGEST, "principal_reference": REF,
            "issued_at": self.utc(self.clock - timedelta(seconds=3)),
            "expires_at": self.utc(self.clock + timedelta(seconds=70)),
        }
        patches = [
            patch.object(DevelopmentOwnerAuthenticationCheckpoint, "inspect",
                         lambda _s, jwt: self.auth(jwt)),
            patch.object(DevelopmentOwnerMfaFreshnessCheck, "__call__",
                         lambda _s, jwt, dig: self.check_mfa(jwt, dig)),
            patch.object(DevelopmentActiveOwnerMembershipCheck, "__call__",
                         lambda _s, jwt, tenant, org: self.check_member(jwt,tenant,org)),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.resolver = DevelopmentSignedWorkOwnerIdentityResolver(
            tenant_id=TENANT, organization_id=ORG,
            auth_checkpoint=self.checkpoint, mfa_check=self.mfa,
            active_owner_membership=self.membership,
            principal_public_key=public, pinned_fingerprint=fp,
            fetch_signed_binding=self.fetch,
            clock=lambda: self.clock,
        )

    @staticmethod
    def utc(t):
        return t.isoformat(timespec="seconds").replace("+00:00", "Z")

    def auth(self, jwt):
        self.calls.append("auth")
        if jwt != self.jwt:
            raise RuntimeError("untrusted fake JWT")
        return self.provisional

    def check_mfa(self, jwt, digest):
        self.calls.append("mfa")
        return self.mfa_ok and jwt == self.jwt and digest == DIGEST

    def check_member(self, jwt, tenant, org):
        self.calls.append("member")
        return self.membership_ok and jwt == self.jwt and tenant == TENANT and org == ORG

    def fetch(self, digest, tenant, org):
        self.calls.append("signed_binding")
        if (digest,tenant,org)!=(DIGEST,TENANT,ORG):
            raise RuntimeError("unapproved binding scope")
        canonical=json.dumps(self.statement,sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False).encode()
        return SignedWorkOwnerPrincipalBinding(
            self.statement, self.key.sign(canonical)
        )

    def deny(self):
        with self.assertRaisesRegex(PermissionError, "^work owner identity unavailable$"):
            self.resolver.resolve(self.jwt)

    def test_verified_owner_yields_only_exact_shared_work_capability(self):
        ctx=self.resolver.resolve(self.jwt)
        self.assertIs(type(ctx),TrustedExecutionContext)
        self.assertEqual(ctx.principal_id,REF)
        self.assertEqual(ctx.tenant_id,TENANT)
        self.assertEqual(ctx.organization_id,ORG)
        self.assertEqual(ctx.caller_type,"HUMAN")
        self.assertEqual(ctx.authenticated_at,self.provisional.verified_at)
        self.assertEqual(ctx.capabilities,frozenset({"work_intake:create"}))
        self.assertFalse(ctx.authority_roles)
        self.assertEqual(self.calls,["auth","mfa","member","signed_binding"])
        guard=SharedWorkIntakeCandidate(
            self.resolver.resolve,
            resolve_tenant_member=lambda t,m: m if (t,m)==(TENANT,REF) else None
        )
        self.assertEqual(guard._trusted(self.jwt,"work_intake:create"),ctx)

    def test_bad_or_unverified_auth_never_reaches_mfa(self):
        with self.assertRaisesRegex(PermissionError,"^work owner identity unavailable$"):
            self.resolver.resolve("event-or-n8n-claim")
        self.assertEqual(self.calls,["auth"])
        self.calls=[]
        self.provisional=replace(self.provisional, aal2_token_verified=False)
        self.deny()
        self.assertEqual(self.calls,["auth"])

    def test_missing_mfa_blocks_member_and_binding(self):
        self.mfa_ok=False;self.deny()
        self.assertEqual(self.calls,["auth","mfa"])

    def test_revoked_member_blocks_signed_mapping(self):
        self.membership_ok=False;self.deny()
        self.assertEqual(self.calls,["auth","mfa","member"])

    def test_provisional_registration_evidence_not_enough(self):
        self.provisional=replace(self.provisional, registration_authorized=True)
        self.deny()
        self.assertEqual(self.calls,["auth"])

    def test_wrong_org_tenant_digest_and_principal_not_trusted(self):
        for prop,v in (
            ("tenant_id",OTHER),("organization_id",OTHER),
            ("subject_digest","sha256:"+"b"*64),("principal_reference",""),
            ("principal_reference","sha256:"+"a"*64),
            ("principal_reference","invalid reference !")
        ):
            with self.subTest(prop=prop,val=v[:9] if type(v) is str else ""):
                self.statement[prop]=v;self.deny()
                self.statement[prop]={
                    "tenant_id":TENANT,"organization_id":ORG,
                    "subject_digest":DIGEST,"principal_reference":REF
                }[prop]

    def test_reject_wrong_auth_data_project_and_unsigned_claim(self):
        for k,v in (
            ("auth_project_ref",DEVELOPMENT_DATA_PROJECT_REF),
            ("data_project_ref",DEVELOPMENT_AUTH_PROJECT_REF),
            ("purpose","AVUHZ_UNTRUSTED"),
            ("issuer","SELF_ASSERTED"),
            ("environment","PRODUCTION"),
        ):
            with self.subTest(k=k):
                prior=self.statement[k];self.statement[k]=v
                self.deny();self.statement[k]=prior

    def test_invalid_signature_is_denied(self):
        def fraudulent(digest,tenant,org):
            val=self.fetch(digest,tenant,org)
            return SignedWorkOwnerPrincipalBinding(val.statement,bytes(64))
        self.resolver._fetch=fraudulent
        self.deny()

    def test_signature_substitution_even_if_fields_look_valid_denied(self):
        signed=self.fetch(DIGEST,TENANT,ORG)
        changed=dict(signed.statement,principal_reference="owner.attacker")
        self.resolver._fetch=lambda _d,_t,_o: SignedWorkOwnerPrincipalBinding(
            changed,signed.signature
        )
        self.deny()

    def test_expired_future_and_overlong_binding_denied(self):
        for issued,expiry in (
            (-120,10),(-3,-1),(15,60),(-3,160),(-3,-3),(-200,40),
        ):
            with self.subTest(issued=issued,exp=expiry):
                self.statement["issued_at"]=self.utc(self.clock+timedelta(seconds=issued))
                self.statement["expires_at"]=self.utc(self.clock+timedelta(seconds=expiry))
                self.deny()

    def test_stale_login_proof_denied_before_fetch(self):
        self.provisional=replace(
            self.provisional,
            verified_at=self.utc(self.clock-timedelta(minutes=6)),
        )
        self.deny()
        self.assertEqual(self.calls,["auth"])

    def test_unknown_or_overbroad_signed_fields_denied(self):
        self.statement["new_scope"]="work_intake:manage"
        self.deny()
        self.statement.pop("new_scope")
        self.statement.pop("organization_id")
        self.deny()

    def test_missing_authoritative_issuer_stops_fully(self):
        self.resolver._fetch=lambda *_: None
        self.deny()

    def test_incorrect_pinned_key_denied_at_construction(self):
        with self.assertRaises(ValueError):
            DevelopmentSignedWorkOwnerIdentityResolver(
                tenant_id=TENANT, organization_id=ORG,
                auth_checkpoint=self.checkpoint, mfa_check=self.mfa,
                active_owner_membership=self.membership,
                principal_public_key=self.key.public_key(),
                pinned_fingerprint="sha256:"+"f"*64,
                fetch_signed_binding=self.fetch,
            )


if __name__ == "__main__":
    unittest.main()
