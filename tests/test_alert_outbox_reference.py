import json
import tempfile
import unittest
from datetime import datetime,timedelta,timezone
from pathlib import Path
from tools.operational_incidents import SQLiteOperationalIncidentStore
from tools.operational_alert_outbox import AlertOutbox,AlertDestination,AlertOutcome,AlertBlocked


class OutboxReferenceTest(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory();self.path=Path(self.directory.name)/'alerts.sqlite'
        self.now=datetime(2026,10,11,8,tzinfo=timezone.utc)
        self.store=SQLiteOperationalIncidentStore(self.path,clock=lambda:self.now)
        self.grants=True;self.actor='HUMAN'
        def authorize(action,resource):
            self.assertFalse(self.store.db.in_transaction)
            return {'allowed':self.grants,'resource':resource,'decisionRef':'fixture-decision','policyRef':'fixture-policy:1','principal':'operator','actor':self.actor,'tenant':'platform-admin-tenant'}
        self.authorize=authorize
        self.outbox=AlertOutbox(self.store,authorize,jitter=lambda:1.0)
        self.destination=AlertDestination('destination://ops','recipient://platform-operators','transport://fixture','secret://transport-config','fixture-policy:1')
        self.outbox.configure(self.destination)
        parent=self
        class Transport:
            transport_ref='transport://fixture'
            def __init__(self): self.calls=[];self.outcome=AlertOutcome('ACCEPTED','provider://receipt');self.query_outcome=AlertOutcome('UNKNOWN')
            def send(self,payload,recipient,secret,key,timeout):
                parent.assertFalse(parent.store.db.in_transaction)
                self.calls.append((payload,recipient,secret,key,timeout))
                return self.outcome
            def query(self,key,timeout):
                parent.assertFalse(parent.store.db.in_transaction)
                return self.query_outcome
        self.transport=Transport()
    def tearDown(self): self.store.close();self.directory.cleanup()
    def add(self,key='cause',severity='ERROR'):
        return self.store.open_incident(dedup_key=key,event_type='DEPENDENCY_UNAVAILABLE',severity=severity,error_code='TIMEOUT',impact_summary='Dependent work paused.')
    def prepare(self): return self.outbox.reconcile_owner_transitions(self.destination.destination_ref)
    def send(self): return self.outbox.send_once(self.destination.destination_ref,self.transport)
    def delivery(self): return self.store.db.execute('select * from gateway_alert_delivery order by rowid desc limit 1').fetchone()
    def advance(self,seconds): self.now+=timedelta(seconds=seconds)

    def test_no_authorizer_no_config_and_no_implicit_transport(self):
        with self.assertRaises(AlertBlocked): AlertOutbox(self.store).configure(self.destination)
        self.grants=False
        with self.assertRaises(AlertBlocked): self.send()
        self.assertEqual(self.transport.calls,[])
    def test_config_requires_human_current_resource_and_preserves_intent(self):
        self.actor='SERVICE'
        with self.assertRaises(AlertBlocked): self.outbox.configure(self.destination)
        self.actor='HUMAN'
        changed=AlertDestination('destination://ops','recipient://different','transport://fixture','secret://transport-config','fixture-policy:1')
        with self.assertRaises(AlertBlocked): self.outbox.configure(changed)
        self.outbox.configure(self.destination)
        self.assertEqual(self.store.db.execute('select count(*) from gateway_alert_config_audit').fetchone()[0],1)
    def test_five_thousand_equivalent_reports_create_one_delivery(self):
        first=self.add()
        for _ in range(4999): self.add()
        pending=self.prepare()
        self.assertTrue(pending['ownerTransitionsPending'])
        self.assertEqual(self.store.get(first.incident_id).occurrence_count,5000)
        self.assertEqual(self.store.db.execute('select count(*) from gateway_alert_delivery').fetchone()[0],1)
        for _ in range(4): self.prepare()
        self.assertEqual(self.store.db.execute('select count(*) from gateway_alert_delivery').fetchone()[0],1)
    def test_accepted_is_not_human_read_ack_or_incident_resolution(self):
        first=self.add();self.prepare();result=self.send()
        self.assertEqual(result['status'],'ACCEPTED');self.assertTrue(result['providerAccepted'])
        self.assertFalse(result['humanReadProven']);self.assertFalse(result['incidentResolved'])
        self.assertEqual(self.store.get(first.incident_id).lifecycle_state,'OPEN')
        self.assertEqual(self.send()['providerCalls'],0)
    def test_payload_has_no_recipient_secret_or_raw_evidence_and_transport_is_bound(self):
        self.add();self.prepare()
        self.transport.transport_ref='wrong'
        with self.assertRaises(AlertBlocked): self.send()
        self.transport.transport_ref='transport://fixture';self.send()
        payload,recipient,secret,key,timeout=self.transport.calls[0]
        self.assertNotIn('recipient',json.dumps(payload));self.assertNotIn('secret',json.dumps(payload));self.assertEqual(timeout,5)
        self.assertEqual(recipient,'recipient://platform-operators');self.assertEqual(secret,'secret://transport-config')
    def test_incremental_backoff_retry_after_and_no_wait_under_lock(self):
        self.add();self.prepare();self.transport.outcome=AlertOutcome('TRANSIENT_NOT_ACCEPTED')
        for delay in [5,15,60,300,900,900]:
            result=self.send();self.assertEqual(result['status'],'PENDING')
            self.assertEqual(self.delivery()['next_due'],self.now.timestamp()+delay)
            self.assertEqual(self.send()['providerCalls'],0)
            self.advance(delay)
        self.transport.outcome=AlertOutcome('TRANSIENT_NOT_ACCEPTED',retry_after_seconds=1200)
        self.send();self.assertEqual(self.delivery()['next_due'],self.now.timestamp()+1200)
        keys={call[3] for call in self.transport.calls};self.assertEqual(len(keys),1)
    def test_restart_keeps_attempts_deadline_and_stable_delivery_key(self):
        self.add();self.prepare();self.transport.outcome=AlertOutcome('TRANSIENT_NOT_ACCEPTED');self.send();before=dict(self.delivery())
        self.store.close();self.store=SQLiteOperationalIncidentStore(self.path,clock=lambda:self.now)
        self.outbox=AlertOutbox(self.store,self.authorize,jitter=lambda:1.0)
        self.assertEqual(dict(self.delivery()),before)
        self.assertEqual(self.send()['providerCalls'],0)
        self.advance(5);self.send()
        self.assertEqual(self.delivery()['total_attempts'],2)
        self.assertEqual({x[3] for x in self.transport.calls},{before['delivery_id']})
    def test_twenty_four_hours_first_limit_stops_automatic_retry(self):
        self.add();self.prepare();self.transport.outcome=AlertOutcome('TRANSIENT_NOT_ACCEPTED')
        for _ in range(200):
            result=self.send()
            if result['status']=='EXHAUSTED': break
            self.now=datetime.fromtimestamp(self.delivery()['next_due'],timezone.utc)
        self.assertEqual(result['status'],'EXHAUSTED')
        self.assertLess(self.delivery()['total_attempts'],128)
        count=len(self.transport.calls);self.advance(86400)
        self.assertEqual(self.send()['providerCalls'],0);self.assertEqual(len(self.transport.calls),count)
    def test_human_renewal_after_exhaustion_has_new_finite_budget_and_old_history(self):
        self.add();self.prepare();self.advance(86401);self.send();old=dict(self.delivery())
        self.assertEqual(old['state'],'EXHAUSTED')
        grant=self.outbox.renew_exhausted_budget(old['delivery_id'],old['version'],'Operator confirmed recovery and requested another delivery attempt.')
        self.assertEqual(grant['maxAttempts'],128);self.assertTrue(grant['oldBudgetHistoryRetained'])
        self.assertNotEqual(self.delivery()['active_session'],old['active_session'])
        self.assertEqual(self.store.db.execute('select count(*) from gateway_alert_budget_session').fetchone()[0],2)
        with self.assertRaises(AlertBlocked): self.outbox.renew_exhausted_budget(old['delivery_id'],old['version'],'Concurrent stale operator')
        self.assertEqual(self.send()['status'],'ACCEPTED')
    def test_nonhuman_or_revoked_renewal_cannot_reset_exhaustion(self):
        self.add();self.prepare();self.advance(86401);self.send();row=self.delivery();self.actor='SERVICE'
        with self.assertRaises(AlertBlocked): self.outbox.renew_exhausted_budget(row['delivery_id'],row['version'],'Retry')
        self.actor='HUMAN';self.grants=False
        with self.assertRaises(AlertBlocked): self.outbox.renew_exhausted_budget(row['delivery_id'],row['version'],'Retry')
        self.assertEqual(self.delivery()['state'],'EXHAUSTED')
    def test_unknown_result_never_blind_retries_or_human_budget_bypasses(self):
        self.add();self.prepare();self.transport.outcome=AlertOutcome('UNKNOWN');self.send();row=self.delivery()
        self.assertEqual(row['state'],'UNKNOWN');self.advance(1000)
        self.assertEqual(self.send()['providerCalls'],0)
        with self.assertRaises(AlertBlocked): self.outbox.renew_exhausted_budget(row['delivery_id'],row['version'],'Retry anyway')
    def test_authoritative_reconciliation_resolves_ambiguity_before_retry(self):
        self.add();self.prepare();self.transport.outcome=AlertOutcome('UNKNOWN');self.send();row=self.delivery()
        result=self.outbox.reconcile_ambiguous_delivery(row['delivery_id'],row['version'],self.transport)
        self.assertEqual(result['status'],'UNKNOWN')
        self.transport.query_outcome=AlertOutcome('TRANSIENT_NOT_ACCEPTED')
        result=self.outbox.reconcile_ambiguous_delivery(row['delivery_id'],row['version'],self.transport)
        self.assertEqual(result['status'],'PENDING');self.assertFalse(result['deliveryAttempted'])
        self.transport.outcome=AlertOutcome('ACCEPTED','provider://receipt');self.send()
        self.assertEqual(self.delivery()['total_attempts'],2)
    def test_lost_worker_fence_rejects_late_outcome_and_leaves_unknown(self):
        self.add();self.prepare()
        parent=self
        def slow(payload,recipient,secret,key,timeout):
            parent.assertFalse(parent.store.db.in_transaction);parent.advance(11)
            return AlertOutcome('ACCEPTED','provider://late')
        self.transport.send=slow
        with self.assertRaises(AlertBlocked): self.send()
        self.assertEqual(self.send()['providerCalls'],0)
        self.assertEqual(self.delivery()['state'],'UNKNOWN')
    def test_critical_escalation_and_recovery_are_separate_deduplicated_deliveries(self):
        self.add();self.prepare();self.send()
        self.add(severity='CRITICAL');self.prepare();self.send()
        self.store.resolve_incident('cause','Recovered.');self.prepare();self.send()
        self.assertEqual([x[0]['phase'] for x in self.transport.calls],['PROBLEM','CRITICAL','RECOVERY'])
        self.prepare();self.assertEqual(self.send()['providerCalls'],0)
    def test_quota_pressure_rolls_back_receipts_and_does_not_stop_owner_incidents(self):
        for i in range(128): self.add(str(i))
        self.prepare();self.prepare()
        self.add('independent')
        count=self.store.db.execute('select count(*) from gateway_alert_transition_receipt').fetchone()[0]
        with self.assertRaises(AlertBlocked): self.prepare()
        self.assertEqual(self.store.db.execute('select count(*) from gateway_alert_transition_receipt').fetchone()[0],count)
        self.assertEqual(len(self.store.list_incidents(limit=200)),129)
    def test_budget_deadline_from_retry_after_and_permanent_error_pause(self):
        self.add();self.prepare();self.transport.outcome=AlertOutcome('TRANSIENT_NOT_ACCEPTED',retry_after_seconds=86400)
        self.assertEqual(self.send()['status'],'EXHAUSTED')
        self.add('permanent');self.prepare();self.transport.outcome=AlertOutcome('PERMANENT')
        self.assertEqual(self.send()['status'],'PAUSED')
        self.assertEqual(self.send()['providerCalls'],0)

    def test_attempt_cap_is_preserved_even_with_old_resumed_attempt_counters(self):
        self.add();self.prepare();row=self.delivery()
        self.store.db.execute('update gateway_alert_budget_session set attempts=127 where session_id=?',(row['active_session'],))
        self.store.db.execute('update gateway_alert_delivery set total_attempts=127 where delivery_id=?',(row['delivery_id'],));self.store.db.commit()
        self.transport.outcome=AlertOutcome('TRANSIENT_NOT_ACCEPTED')
        self.assertEqual(self.send()['status'],'EXHAUSTED')
        self.assertEqual(self.delivery()['total_attempts'],128)
        self.assertEqual(self.send()['providerCalls'],0)

    def test_ambiguous_control_queries_are_finite_and_do_not_create_delivery_budget(self):
        self.add();self.prepare();self.transport.outcome=AlertOutcome('UNKNOWN');self.send();row=self.delivery()
        for _ in range(8):
            self.assertEqual(self.outbox.reconcile_ambiguous_delivery(row['delivery_id'],row['version'],self.transport)['status'],'UNKNOWN')
        with self.assertRaises(AlertBlocked): self.outbox.reconcile_ambiguous_delivery(row['delivery_id'],row['version'],self.transport)
        self.assertEqual(self.delivery()['total_attempts'],1)
        self.assertEqual(self.store.db.execute('select count(*) from gateway_alert_budget_session').fetchone()[0],1)

    def test_changed_tenant_and_current_delivery_resource_denial_stop_before_transport(self):
        self.add();self.prepare()
        def wrong_tenant(action,resource):
            grant=self.authorize(action,resource);grant['tenant']='different';return grant
        self.outbox.authorize=wrong_tenant
        with self.assertRaises(AlertBlocked): self.send()
        def resource_deny(action,resource):
            grant=self.authorize(action,resource)
            if resource['deliveryRef']: grant['allowed']=False
            return grant
        self.outbox.authorize=resource_deny
        with self.assertRaises(AlertBlocked): self.send()
        self.assertEqual(self.transport.calls,[])
        self.assertEqual(self.delivery()['total_attempts'],0)

    def test_acceptance_without_authoritative_receipt_and_malformed_outcomes_stay_unknown(self):
        for index,outcome in enumerate([AlertOutcome('ACCEPTED'),AlertOutcome('TRANSIENT_NOT_ACCEPTED',retry_after_seconds=True),{'kind':'ACCEPTED'},AlertOutcome('UNRECOGNIZED')]):
            self.add('malformed'+str(index));self.prepare();self.transport.outcome=outcome
            self.assertEqual(self.send()['status'],'UNKNOWN')
        self.assertEqual(len(self.transport.calls),4)


if __name__=='__main__': unittest.main()
