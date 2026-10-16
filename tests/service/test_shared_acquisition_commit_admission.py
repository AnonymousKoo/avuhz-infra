"""LOCAL: acquisition admission reads same scoped connection, never trusts receipt."""
from __future__ import annotations

from dataclasses import replace
import unittest

from avuhz_runtime.guards import TrustedExecutionContext
from avuhz_service.shared_acquisition_metadata_lookup import (
    VerifiedAcquisitionMetadata, _BOUNDARY, _READ,
)
from avuhz_service.shared_acquisition_commit_admission import (
    require_transaction_acquisition_admission, _WRITE_BOUNDARY,
)
from avuhz_service.shared_work_intake_candidate import (
    WorkIntakeCommand, WorkIntakeDenied,
)

TENANT = "a4730000-0000-4000-8000-000000000001"
OTHER = "a4730000-0000-4000-8000-000000000002"
ORG = "a4730000-0000-4000-8000-000000000011"
INTAKE = "a4730000-0000-4000-8000-000000000021"


class Connection:
    def __init__(self):
        self.calls=[]
        self.boundary=True
        self.write_boundary=True
        self.row={
            "tenant_id":TENANT,"organization_id":ORG,"intake_id":INTAKE,
            "intake_state":"RECEIVED","record_version":3
        }
        self.unavailable=False

    def execute(self, sql, params=None):
        if self.unavailable:raise RuntimeError("provider error with secrets")
        self.calls.append((sql,params))
        self.sql=sql
        return self

    def fetchone(self):
        if self.sql == _BOUNDARY:return {"bounded":self.boundary}
        if self.sql == _WRITE_BOUNDARY:return {"bounded":self.write_boundary}
        if self.sql == _READ:return self.row
        raise AssertionError("unexpected privileged SQL")


class CommitAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.con=Connection()
        self.context=TrustedExecutionContext(
            True,"owner.approved.001","HUMAN",TENANT,ORG,
            frozenset({"work_intake:create"}),frozenset(),
            "DEVELOPMENT","avuhz-command-api","STRONG",False,
            "2026-10-16T00:00:00Z","2099-01-01T00:00:00Z",
        )
        self.cmd=WorkIntakeCommand(
            "OPEN",INTAKE,"Acq"+INTAKE.replace("-",""),
            source="web",classification="service_request",
            next_action_due_at="2026-10-16T00:10:00Z",
        )
        self.snapshot=VerifiedAcquisitionMetadata(TENANT,INTAKE,ORG,"RECEIVED",3)

    _UNSET = object()

    def admit(self,expected=_UNSET):
        require_transaction_acquisition_admission(
            self.con,self.context,self.cmd,
            self.snapshot if expected is self._UNSET else expected,
        )

    def denied(self, expected=_UNSET):
        with self.assertRaisesRegex(WorkIntakeDenied,"^work intake authority denied$"):
            self.admit(expected)

    def test_exact_role_rls_read_with_no_write(self):
        self.admit()
        self.assertEqual(
            self.con.calls,[(_BOUNDARY,None),(_WRITE_BOUNDARY,None),
                            (_READ,(TENANT,INTAKE))])
        self.assertIn("not has_any_column_privilege('avuhz_command_service'",_WRITE_BOUNDARY)
        self.assertNotIn("FOR SHARE",_READ.upper())
        self.assertNotIn("UPDATE public.",_READ.upper())

    def test_missing_and_stale_state_or_revision(self):
        for attr,v in [
            ("intake_state","WITHDRAWN"),("record_version",4),
            ("organization_id",OTHER),("tenant_id",OTHER),
            ("intake_id",OTHER),
        ]:
            with self.subTest(attr=attr):
                self.con.row={**Connection().row,attr:v}
                self.denied()
        self.con.row=None
        self.denied()

    def test_untrusted_snapshot_fields_fail_before_sql(self):
        for changed in (
            {"tenant_id":OTHER},{"organization_id":OTHER},
            {"intake_id":OTHER},{"intake_state":"WITHDRAWN"},
            {"record_version":True},{"record_version":0},
        ):
            with self.subTest(changed=changed):
                self.con.calls.clear()
                self.denied(replace(self.snapshot,**changed))
                self.assertEqual(self.con.calls,[])

    def test_scope_cannot_be_caller_selected(self):
        for field in ("tenant_id","organization_id"):
            with self.subTest(field=field):
                self.con.calls.clear()
                setattr(self,"context",replace(self.context,**{field:OTHER}))
                self.denied()
                self.assertFalse(self.con.calls)
                self.context=replace(self.context,**{field:TENANT if field=="tenant_id" else ORG})

    def test_non_open_cannot_admit(self):
        self.cmd=replace(self.cmd,kind="BLOCK")
        self.denied()
        self.assertFalse(self.con.calls)

    def test_role_and_write_drift_fail_closed(self):
        self.con.boundary=False
        self.denied()
        self.assertEqual(len(self.con.calls),1)
        self.con=Connection()
        self.con.write_boundary=False
        self.denied()
        self.assertEqual(len(self.con.calls),2)

    def test_provider_error_sanitized(self):
        self.con.unavailable=True
        self.denied()

    def test_second_read_catches_change_in_same_uow(self):
        self.admit()
        self.con.row["record_version"]=4
        self.denied()
        self.assertEqual(len(self.con.calls),6)

    def test_wrong_type_not_accepted_as_authority(self):
        for value in (None,True,{},self.cmd):
            self.con.calls.clear()
            self.denied(value)
            self.assertEqual(self.con.calls,[])


if __name__ == "__main__":
    unittest.main()
