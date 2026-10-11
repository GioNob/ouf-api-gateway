import copy
import json
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

from tools.gateway_operational_api import GatewayOperationalOwnerAPI
from tools.operational_incidents import SQLiteOperationalIncidentStore
from owner_authorization_fixture import fixture_owner_authorize


class OwnerCursorReferenceTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name)/'owner.sqlite'
        self.now = datetime(2026, 10, 11, 8, 0, tzinfo=timezone.utc)
        self.store = SQLiteOperationalIncidentStore(self.path, clock=lambda:self.now)
        self.headers = {'X-OUF-Gateway-Verified':'true','X-OUF-Principal-ID':'operator',
                        'X-OUF-Tenant-ID':'tenant','X-OUF-Authorization-Decision-Ref':'coarse'}
        self.api = GatewayOperationalOwnerAPI(self.store, fixture_owner_authorize)

    def tearDown(self):
        self.store.close()
        self.directory.cleanup()

    def add(self, key, severity='ERROR'):
        return self.store.open_incident(dedup_key=key,event_type='DEPENDENCY_UNAVAILABLE',severity=severity,
                                       error_code='TIMEOUT',impact_summary='Work paused.')

    def page(self, query, api=None, headers=None):
        return (api or self.api).handle(self.api.INCIDENTS_PATH, headers or self.headers, json.dumps(query))

    def test_pages_remain_stable_after_updates_and_store_restart(self):
        old = [self.add(str(i)).incident_id for i in range(5)]
        status, first = self.page({'snapshot':True,'limit':2})
        self.assertEqual(status,200)
        retry = self.page({'cursor':first['cursor']})[1]
        self.assertEqual(first,retry)
        self.assertFalse(first['consultationRecorded'])
        for i in range(5): self.store.resolve_incident(str(i),'Recovered.')
        self.add('new','CRITICAL')
        self.store.close()
        self.store = SQLiteOperationalIncidentStore(self.path, clock=lambda:self.now)
        self.api = GatewayOperationalOwnerAPI(self.store,fixture_owner_authorize)
        ids = [i['incident_id'] for i in first['items']]
        while first.get('nextCursor'):
            status, first = self.page({'cursor':first['nextCursor']})
            self.assertEqual(status,200)
            self.assertEqual(first['snapshotRef'],retry['snapshotRef'])
            ids.extend(i['incident_id'] for i in first['items'])
            self.assertTrue(all(i['lifecycle_state']=='OPEN' for i in first['items']))
        self.assertEqual(set(ids),set(old))
        self.assertEqual(len(ids),len(set(ids)))

    def test_concurrent_same_cause_has_one_identity_and_exact_occurrences(self):
        self.add('shared')
        def writer(index):
            store = SQLiteOperationalIncidentStore(self.path)
            try:
                return store.open_incident(dedup_key='shared',event_type='DEPENDENCY_UNAVAILABLE',severity='ERROR',
                                          error_code='TIMEOUT',impact_summary='Work paused.').incident_id
            finally: store.close()
        with ThreadPoolExecutor(max_workers=4) as pool:
            ids = list(pool.map(writer,range(32)))
        self.assertEqual(len(set(ids)),1)
        self.assertEqual(self.store.get(ids[0]).occurrence_count,33)
        self.assertEqual(self.store.db.execute('select count(*) from gateway_incident_transition').fetchone()[0],33)

    def test_rollbacks_capture_no_history_and_history_is_immutable(self):
        first = self.add('one')
        before=self.store.db.execute('select count(*) from gateway_incident_transition').fetchone()[0]
        self.store.db.execute("update gateway_operational_incident set severity='CRITICAL' where incident_id=?",(first.incident_id,))
        self.store.db.rollback()
        self.assertEqual(self.store.db.execute('select count(*) from gateway_incident_transition').fetchone()[0],before)
        for sql in ['update gateway_incident_transition set body=body','delete from gateway_incident_transition']:
            with self.assertRaises(sqlite3.IntegrityError): self.store.db.execute(sql)
            self.store.db.rollback()

    def test_current_revocation_is_checked_before_saved_page_read(self):
        first=self.add('one')
        status,page=self.page({'snapshot':True})
        def revoked(headers,capability,resource): return {'allowed':False}
        api=GatewayOperationalOwnerAPI(self.store,revoked)
        status,body=self.page({'cursor':page['cursor']},api=api)
        self.assertEqual(status,403)
        self.assertNotIn(first.incident_id,json.dumps(body))

    def test_resource_revocation_redacts_and_changes_page_digest(self):
        first=self.add('one')
        _,page=self.page({'snapshot':True})
        def row_deny(headers,capability,resource):
            if resource['id']==first.incident_id: return {'allowed':False}
            return fixture_owner_authorize(headers,capability,resource)
        _,redacted=self.page({'cursor':page['cursor']},api=GatewayOperationalOwnerAPI(self.store,row_deny))
        self.assertEqual(redacted['items'],[])
        self.assertTrue(redacted['partial'])
        self.assertNotEqual(redacted['itemsDigest'],page['itemsDigest'])

    def test_wrong_identity_tenant_context_policy_and_token_fail_closed(self):
        self.add('one')
        _,page=self.page({'snapshot':True})
        for key in ['X-OUF-Principal-ID','X-OUF-Tenant-ID']:
            headers=dict(self.headers); headers[key]='different'
            self.assertEqual(self.page({'cursor':page['cursor']},headers=headers)[0],404)
        def changed(headers,capability,resource):
            decision=fixture_owner_authorize(headers,capability,resource);decision['policyRef']='policy:2';return decision
        self.assertEqual(self.page({'cursor':page['cursor']},api=GatewayOperationalOwnerAPI(self.store,changed))[0],409)
        self.assertEqual(self.page({'cursor':'00000000-0000-0000-0000-000000000000'})[0],404)
        self.assertEqual(self.page({'cursor':page['cursor'],'limit':1})[0],400)
        def changed_context(headers,capability,resource):
            decision=fixture_owner_authorize(headers,capability,resource);decision['identity']['authenticationContextRef']='another';return decision
        self.assertEqual(self.page({'cursor':page['cursor']},api=GatewayOperationalOwnerAPI(self.store,changed_context))[0],404)

    def test_missing_local_policy_or_wrong_resource_detail_cannot_read(self):
        self.add('secret-identity')
        self.assertEqual(self.page({},api=GatewayOperationalOwnerAPI(self.store))[0],503)
        for field in ['resource','permittedDetailLevel','identity']:
            def wrong(headers,capability,resource,field=field):
                decision=fixture_owner_authorize(headers,capability,resource);decision[field]={} if field!='permittedDetailLevel' else 'TENANT';return decision
            status,body=self.page({},api=GatewayOperationalOwnerAPI(self.store,wrong))
            self.assertEqual(status,403)
            self.assertNotIn('secret-identity',json.dumps(body))

    def test_expiry_and_capacity_do_not_stop_incident_persistence(self):
        self.add('one')
        _,page=self.page({'snapshot':True})
        for _ in range(15): self.assertEqual(self.page({'snapshot':True})[0],200)
        self.assertEqual(self.page({'snapshot':True})[0],503)
        self.add('independent')
        self.now+=timedelta(minutes=31)
        self.assertEqual(self.page({'cursor':page['cursor']})[0],410)
        self.assertEqual(self.page({'snapshot':True})[0],200)

    def test_malformed_queries_are_rejected_without_disclosure(self):
        for body in ['null','[]','{"limit":true}','{"limit":1,"limit":2}','{"unknown":1}','{"state":[]}',
                     '{"since":null}','{"snapshot":1}','{"cursor":null}','{"snapshot":true,"sourceId":"a"}',b'\xff', ' '*65537]:
            status,result=self.api.handle(self.api.INCIDENTS_PATH,self.headers,body)
            self.assertEqual(status,400,repr(body)[:80])
        self.assertEqual(self.api.handle(self.api.SUMMARY_PATH,self.headers,'{"snapshot":true}')[0],400)

    def test_priority_before_page_and_explicit_baseline_gap(self):
        critical=self.add('critical','CRITICAL')
        for i in range(5):
            self.add('resolved'+str(i),'CRITICAL');self.store.resolve_incident('resolved'+str(i),'Recovered.')
        status,page=self.page({'snapshot':True,'limit':1,'since':'2026-10-11T07:00:00Z'})
        self.assertEqual(status,200)
        self.assertEqual(page['items'][0]['incident_id'],critical.incident_id)
        self.assertTrue(page['coverage']['historyGap'])
        self.assertTrue(page['partial'])
        self.assertTrue(page['truncated'])

    def test_platform_store_rejects_tenant_relabeling(self):
        with self.assertRaises(ValueError):
            self.store.open_incident(dedup_key='bad',event_type='FAILURE',severity='ERROR',error_code='FAIL',
                                     impact_summary='Failure.',visibility_class='TENANT_OPERATIONAL')

    def test_no_future_column_leaks_and_legacy_rows_have_honest_baseline(self):
        self.add('one')
        self.store.db.execute('alter table gateway_operational_incident add column secret_material text')
        self.store.db.execute("update gateway_operational_incident set secret_material='NEVER_EXPORT'")
        self.store.db.commit()
        status,page=self.page({'snapshot':True})
        self.assertEqual(status,200)
        self.assertNotIn('NEVER_EXPORT',json.dumps(page))
        self.assertNotIn('secret_material',json.dumps(page))

    def test_recovery_keeps_monotonic_observation_when_clock_moves_back(self):
        first=self.add('one')
        self.now-=timedelta(hours=1)
        repeated=self.add('one')
        self.assertEqual(repeated.last_seen_at,first.last_seen_at)
        resolved=self.store.resolve_incident('one','Recovered.')
        self.assertGreaterEqual(resolved.resolved_at,first.last_seen_at)
        recovering=self.store.recovering('one','Checking recovery.')
        self.assertIsNone(recovering.resolved_at)
        self.assertGreaterEqual(recovering.last_seen_at,first.last_seen_at)

    def test_summary_does_not_disclose_counts_or_claim_healthy_when_hidden(self):
        self.add('one')
        self.add('two')
        status,body=self.api.handle(self.api.SUMMARY_PATH,self.headers,'{"limit":1}')
        self.assertEqual(status,200)
        self.assertEqual(body['status'],'UNKNOWN')
        self.assertTrue(body['partial'])
        self.assertNotIn('openIncidents',body)


if __name__=='__main__': unittest.main()
