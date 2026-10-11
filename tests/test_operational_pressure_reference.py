import tempfile
import unittest
from datetime import datetime,timedelta,timezone
from pathlib import Path
from tools.operational_incidents import SQLiteOperationalIncidentStore
from tools.operational_pressure import PersistentPressureController,PressureObservation,PressureConflict


class PressureReferenceTest(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory();self.path=Path(self.directory.name)/'pressure.sqlite'
        self.now=datetime(2026,10,11,8,tzinfo=timezone.utc)
        self.store=SQLiteOperationalIncidentStore(self.path,clock=lambda:self.now)
        self.pressure=PersistentPressureController(self.store)
        self.scope='gateway://control-plane/etcd';self.pressure.register_scope(self.scope)
    def tearDown(self): self.store.close();self.directory.cleanup()
    def sample(self,**values):
        defaults=dict(observed_at=self.now,window_seconds=300,attempts=100,failures=0,dependency_unavailable_seconds=0,capacity_fraction=0.2,oldest_backlog_seconds=0)
        defaults.update(values);return PressureObservation(**defaults)
    def observe(self,**values):
        version=self.pressure.decision(self.scope)['version']
        return self.pressure.observe(self.scope,self.sample(**values),version)
    def advance(self,seconds=10): self.now+=timedelta(seconds=seconds)

    def test_old_incident_totals_or_operator_absence_do_not_create_crisis(self):
        self.store.open_incident(dedup_key='historical',event_type='OLD',severity='ERROR',error_code='OLD',impact_summary='Old issue remains open.')
        self.now+=timedelta(days=31)
        result=self.observe()
        self.assertEqual(result['mode'],'NORMAL');self.assertEqual(result['businessSlots'],8)
    def test_sustained_recent_failures_pause_without_historical_counts(self):
        self.assertEqual(self.observe(failures=70)['mode'],'CAUTIOUS')
        for _ in range(9): self.advance();result=self.observe(failures=70)
        self.assertEqual(result['mode'],'PAUSED');self.assertEqual(result['businessSlots'],0)
        self.assertEqual(result['reservedControlSlots'],2)
    def test_one_long_unavailable_dependency_pauses_even_with_low_sample_volume(self):
        result=self.observe(attempts=1,failures=1,dependency_unavailable_seconds=3600)
        self.assertEqual(result['mode'],'PAUSED')
    def test_storage_or_current_backlog_pressure_is_independent_of_error_rate(self):
        self.assertEqual(self.observe(capacity_fraction=.95)['mode'],'PAUSED')
        self.advance()
        self.assertEqual(self.observe(capacity_fraction=.75,oldest_backlog_seconds=1000)['mode'],'PAUSED')
    def test_recovery_is_stable_and_gradual_without_budget_or_authority_reset(self):
        self.observe(dependency_unavailable_seconds=3600)
        for _ in range(13): self.advance();result=self.observe()
        self.assertEqual(result['mode'],'PROBE');self.assertEqual(result['businessSlots'],1)
        for _ in range(3): self.advance();result=self.observe()
        self.assertEqual(result['mode'],'RECOVERING');self.assertEqual(result['businessSlots'],2)
        for _ in range(3): self.advance();result=self.observe()
        self.assertEqual(result['businessSlots'],4)
        for _ in range(3): self.advance();result=self.observe()
        self.assertEqual(result['mode'],'NORMAL');self.assertEqual(result['businessSlots'],8)
        self.assertFalse(result['executionAuthorized']);self.assertFalse(result['retryBudgetRenewed'])
    def test_hysteresis_avoids_immediate_healthy_reopen_and_flapping(self):
        self.observe(capacity_fraction=.95);self.advance()
        self.assertEqual(self.observe(capacity_fraction=.8)['mode'],'PAUSED')
        for _ in range(13): self.advance();result=self.observe()
        self.assertEqual(result['mode'],'PROBE');self.advance()
        self.assertEqual(self.observe(capacity_fraction=.8)['mode'],'PAUSED')
    def test_stale_samples_cannot_prove_continuous_recovery(self):
        self.observe(capacity_fraction=.95);self.advance();self.observe()
        self.advance(130)
        self.assertEqual(self.pressure.decision(self.scope)['mode'],'UNKNOWN')
        self.assertEqual(self.observe()['mode'],'PAUSED')
    def test_restart_retains_scope_pause_and_version(self):
        paused=self.observe(capacity_fraction=.95)
        self.store.close();self.store=SQLiteOperationalIncidentStore(self.path,clock=lambda:self.now)
        self.pressure=PersistentPressureController(self.store);self.pressure.register_scope(self.scope)
        self.assertEqual(self.pressure.decision(self.scope),paused)
    def test_independent_scope_keeps_its_own_capacity(self):
        self.observe(capacity_fraction=.95)
        independent='gateway://independent/source';self.pressure.register_scope(independent)
        decision=self.pressure.observe(independent,self.sample(),0)
        self.assertEqual(decision['mode'],'NORMAL');self.assertEqual(decision['businessSlots'],8)
    def test_duplicates_are_idempotent_and_conflicting_stale_writers_rejected(self):
        sample=self.sample();first=self.pressure.observe(self.scope,sample,0)
        self.assertEqual(self.pressure.observe(self.scope,sample,0),first)
        with self.assertRaises(PressureConflict): self.pressure.observe(self.scope,self.sample(failures=1),0)
        self.advance()
        with self.assertRaises(PressureConflict): self.pressure.observe(self.scope,self.sample(),0)
    def test_unknown_scopes_stale_or_invalid_evidence_never_create_grants(self):
        with self.assertRaises(PressureConflict): self.pressure.observe('gateway://new-job',self.sample(),0)
        for values in [dict(attempts=True),dict(failures=101),dict(capacity_fraction=float('nan')),dict(window_seconds=3600),dict(observed_at=self.now-timedelta(seconds=31)),dict(observed_at=self.now+timedelta(seconds=6)),dict(observed_at=self.now.replace(tzinfo=None))]:
            with self.assertRaises(ValueError): self.pressure.observe(self.scope,self.sample(**values),0)
        self.assertEqual(self.pressure.decision(self.scope)['mode'],'UNKNOWN')
    def test_scope_capacity_preserves_existing_control_state(self):
        self.pressure.MAX_SCOPES=2;self.pressure.register_scope('gateway://other')
        with self.assertRaises(PressureConflict): self.pressure.register_scope('gateway://third')
        self.assertEqual(self.observe()['mode'],'NORMAL')

    def test_three_hour_outage_then_recovery_keeps_finite_scope_and_independent_control(self):
        for elapsed in range(0,10800,15):
            result=self.observe(attempts=5,failures=5,dependency_unavailable_seconds=elapsed+300)
            self.assertEqual(result['mode'],'PAUSED')
            self.assertEqual(result['reservedControlSlots'],2)
            self.assertFalse(result['retryBudgetRenewed'])
            self.advance(15)
        self.assertEqual(self.store.db.execute('select count(*) from gateway_pressure_scope').fetchone()[0],1)
        for _ in range(13):
            result=self.observe();self.advance()
        self.assertEqual(result['mode'],'PROBE')


if __name__=='__main__': unittest.main()
