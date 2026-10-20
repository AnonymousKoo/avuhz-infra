"""Persistent deterministic reconciliation regressions; fictional LOCAL/TEST only."""
import sqlite3
import tempfile
import unittest
from dataclasses import fields, replace
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch
from tests.architecture import test_local_infrastructure_recovery_v1 as r
from avuhz_runtime.local_infrastructure_recovery import (
    LocalTestInfrastructureRecovery, open_recovery_case,
    collect_recovery_observation, recovery_intent_digest,
)
from avuhz_runtime import local_infrastructure_recovery as rec
from avuhz_runtime.local_infrastructure_authority import LocalInfrastructureDenied
from avuhz_runtime.local_infrastructure_audit import LocalTestInfrastructureAudit


class RecoverySafetyTests(unittest.TestCase):
    def setUp(self):
            self.tmp=tempfile.TemporaryDirectory(prefix='avuhz-recovery-safety-', dir='/tmp')
            self.addCleanup(self.tmp.cleanup)
            self.path=str(Path(self.tmp.name)/'probe.sqlite')
            self.cfg=r.options(self.path)
    def reconcile(self,cfg=None):
            a=LocalTestInfrastructureRecovery(**(cfg or self.cfg))
            return a.reconcile(observer_handle=a.observer_handle,authorization_handle=a.authorization_handle)
    def sql(self,sql,args=()):
            with sqlite3.connect(self.path) as db: return db.execute(sql,args).fetchall()
    def case(self):
            c=self.cfg
            return open_recovery_case(audit_sources=c['audit_sources'],audit_digest=c['audit_digest'],case_id='secondcase01',challenge='secondchallenge01',clock=replace(c['clock'],now=r.fixtures.NOW+timedelta(seconds=5)))
    def observe(self,case):
            c=self.cfg
            return collect_recovery_observation(audit_sources=c['audit_sources'],case=case,observer_grant=c['observer_grant'],observation_id='secondobservation01',clock=replace(c['clock'],now=r.fixtures.NOW+timedelta(seconds=6)))
    def repin(self,c):
            c=dict(c)
            c['authorization']=replace(c['authorization'],intent_digest=recovery_intent_digest(case=c['case'],audit_digest=c['audit_digest'],observation=c['observation'],observer_grant=c['observer_grant'],human_grant=c['human_grant'],decision=c['authorization'].decision))
            return c
    def test_two_case_conflict_preserves_original_replay(self):
            first=self.reconcile()
            case=self.case(); obs=self.observe(case)
            cfg=dict(self.cfg,case=case,observation=obs,clock=replace(self.cfg['clock'],now=r.fixtures.NOW+timedelta(seconds=8)),authorization=replace(self.cfg['authorization'],authorization_id='secondconsent01',issued_at=r.fixtures.NOW+timedelta(seconds=7)))
            self.assertEqual(self.reconcile(self.repin(cfg)).reason_code,'CONFLICT')
            self.assertEqual(self.reconcile().evidence_digest,first.evidence_digest)
            self.assertEqual(self.sql('SELECT count(*) FROM local_recovery_decisions'),[(1,)])
    def test_complete_prior_human_identity_matrix(self):
            for identity in ('principal01','observer01','fictional.human01','fictional.executor01','verifier01','auditor01','recoveryobserver01'):
                cfg=dict(self.cfg,human_grant=replace(self.cfg['human_grant'],scope=replace(self.cfg['human_grant'].scope,identity_id=identity)),authorization=replace(self.cfg['authorization'],human_id=identity))
                with self.subTest(identity=identity),self.assertRaises(LocalInfrastructureDenied):
                    LocalTestInfrastructureRecovery(**self.repin(cfg))
    def test_both_grants_all_scope_dimensions(self):
            for key in ('human_grant','observer_grant'):
                for f in fields(self.cfg[key].scope):
                    val='LOCAL' if f.name=='environment' else 'different01'
                    cfg=dict(self.cfg,**{key:replace(self.cfg[key],scope=replace(self.cfg[key].scope,**{f.name:val}))})
                    with self.subTest(grant=key,dimension=f.name),self.assertRaises(LocalInfrastructureDenied):
                        LocalTestInfrastructureRecovery(**self.repin(cfg))
    def test_capacity_matrix_and_terminal_replay(self):
            first=self.reconcile()
            for table,unique in (('local_recovery_cases',(0,1)),('local_recovery_observations',(0,1)),('local_recovery_decisions',(0,2))):
                with self.subTest(table=table):
                    row=self.sql('SELECT * FROM '+table)[0]
                    with sqlite3.connect(self.path) as db:
                        query='INSERT INTO '+table+' VALUES ('+','.join('?' for _ in row)+')'
                        for i in range(255):
                            values=list(row)
                            for j in unique: values[j]='filler'+str(i)+'field'+str(j)
                            db.execute(query,values)
                        self.assertEqual(db.execute('SELECT count(*) FROM '+table).fetchone()[0],256)
                        values=list(row)
                        for j in unique: values[j]='overflowfield'+str(j)
                        with self.assertRaises(sqlite3.DatabaseError): db.execute(query,values)
                    self.assertEqual(self.reconcile().evidence_digest,first.evidence_digest)
    def test_case_and_observer_commit_failures(self):
            original=LocalTestInfrastructureAudit._connect
            historical=rec._historical(self.cfg['audit_sources'],self.cfg['audit_digest'])
            class FailedCommit:
                def __init__(inner): inner.db=original(historical[0])
                def __getattr__(inner,key): return getattr(inner.db,key)
                def __enter__(inner): inner.db.__enter__(); return inner
                def __exit__(inner,*args): inner.db.rollback(); raise sqlite3.OperationalError('FICTIONAL_PRECOMMIT_FAILURE')
            with patch.object(rec,'_historical',return_value=historical), patch.object(LocalTestInfrastructureAudit,'_connect',side_effect=FailedCommit):
                with self.assertRaises(sqlite3.Error): self.case()
            self.assertEqual(self.sql('SELECT count(*) FROM local_recovery_cases'),[(1,)])
            case=self.case()
            with patch.object(rec,'_historical',return_value=historical), patch.object(LocalTestInfrastructureAudit,'_connect',side_effect=FailedCommit):
                with self.assertRaises(sqlite3.Error): self.observe(case)
            self.assertEqual(self.sql('SELECT count(*) FROM local_recovery_observations'),[(1,)])
            self.assertEqual(self.reconcile().reason_code,'RECOVERY_RECORDED')
    def test_case_and_observer_lost_commit_ack(self):
            original=LocalTestInfrastructureAudit._connect
            historical=rec._historical(self.cfg['audit_sources'],self.cfg['audit_digest'])
            cfg=self.cfg
            class LostAck:
                def __init__(inner): inner.db=original(historical[0])
                def __getattr__(inner,key): return getattr(inner.db,key)
                def __enter__(inner): inner.db.__enter__(); return inner
                def __exit__(inner,*args): inner.db.__exit__(*args); raise sqlite3.OperationalError('FICTIONAL_LOST_ACK')
            with patch.object(rec,'_historical',return_value=historical), patch.object(LocalTestInfrastructureAudit,'_connect',side_effect=LostAck):
                with self.assertRaises(sqlite3.Error): self.case()
            self.assertEqual(self.sql('SELECT count(*) FROM local_recovery_cases'),[(2,)])
            with self.assertRaises(sqlite3.Error): self.case()
            case=replace(cfg['case'],case_id='secondcase01',challenge='secondchallenge01',opened_at=r.fixtures.NOW+timedelta(seconds=5))
            with patch.object(rec,'_historical',return_value=historical), patch.object(LocalTestInfrastructureAudit,'_connect',side_effect=LostAck):
                with self.assertRaises(sqlite3.Error): self.observe(case)
            self.assertEqual(self.sql('SELECT count(*) FROM local_recovery_observations'),[(2,)])
            with self.assertRaises(sqlite3.Error): self.observe(case)
            self.assertEqual(self.sql("SELECT count(*) FROM sqlite_master WHERE name='local_recovery_decisions'"),[(0,)])
