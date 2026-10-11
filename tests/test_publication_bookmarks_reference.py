import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tools.operational_incidents import SQLiteOperationalIncidentStore
from tools.operational_bookmarks import PublicationBookmarks
from tools.operational_cursor import CursorRejected


class PublicationBookmarkReferenceTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / 'bookmark.sqlite'
        self.now = datetime(2026, 10, 11, 8, tzinfo=timezone.utc)
        self.store = SQLiteOperationalIncidentStore(self.path, clock=lambda: self.now)
        self.identity = {'principal':'operator','tenant':'tenant','actor':'HUMAN','authenticationContextRef':'login-one'}
        self.allowed = True
        self.bookmarks = PublicationBookmarks(self.store, lambda identity, policy: self.allowed)
        self.visible = lambda item: True

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def add(self, cause):
        return self.store.open_incident(dedup_key=cause,event_type='FAILURE',severity='ERROR',
                                       error_code='TIMEOUT',impact_summary='Paused.')

    def start(self, query=None):
        return self.bookmarks.start(query or {}, self.identity, 'policy:1', self.visible)

    def resume(self, bookmark, **kwargs):
        return self.bookmarks.resume(bookmark, self.identity, 'policy:1', self.visible, **kwargs)

    def rejected(self, status, fn):
        with self.assertRaises(CursorRejected) as caught:
            fn()
        self.assertEqual(caught.exception.status, status)

    def test_resume_old_time_publication_after_page_expiry_restart_and_new_login(self):
        first = self.add('first')
        initial = self.start()
        bookmark = initial['publicationBookmark']
        self.assertFalse(initial['consultationRecorded'])
        self.now -= timedelta(hours=1)  # old observation time does not hide a later commit
        later = self.add('late')
        self.store.resolve_incident('first','Recovered.')
        self.now += timedelta(days=31)
        self.store.close()
        self.store = SQLiteOperationalIncidentStore(self.path, clock=lambda:self.now)
        self.bookmarks = PublicationBookmarks(self.store, lambda identity,policy:True)
        self.identity['authenticationContextRef'] = 'new-login'
        result = self.resume(bookmark)
        self.assertEqual({i['incident_id'] for i in result['items']}, {first.incident_id,later.incident_id})
        self.assertEqual(result['coverage']['parentBookmark'],bookmark)
        self.assertFalse(result['consultationRecorded'])
        self.assertNotEqual(result['publicationBookmark'],bookmark)
        empty = self.resume(result['publicationBookmark'])
        self.assertEqual(empty['items'],[])
        self.assertFalse(empty['partial'])

    def test_bookmark_requires_all_unredacted_pages_and_is_stable_on_replay(self):
        for index in range(3): self.add(str(index))
        page = self.start({'limit':1})
        first = page['cursor']
        self.assertNotIn('publicationBookmark',page)
        self.visible = lambda item: False
        page = self.bookmarks.page(page['nextCursor'],self.identity,'policy:1',self.visible)
        self.assertTrue(page['partial'])
        hidden_token = page['cursor']
        page = self.bookmarks.page(page['nextCursor'],self.identity,'policy:1',lambda item:True)
        self.assertNotIn('publicationBookmark',page)
        final_token = page['cursor']
        self.bookmarks.page(hidden_token,self.identity,'policy:1',lambda item:True)
        page = self.bookmarks.page(final_token,self.identity,'policy:1',lambda item:True)
        bookmark = page['publicationBookmark']
        retry = self.bookmarks.page(final_token,self.identity,'policy:1',lambda item:True)
        self.assertEqual(retry['publicationBookmark'],bookmark)
        self.assertEqual(self.store.db.execute('select count(*) from gateway_publication_bookmark').fetchone()[0],1)
        self.assertFalse(self.bookmarks.page(first,self.identity,'policy:1',lambda item:True)['consultationRecorded'])

    def test_revocation_scope_policy_and_missing_sdk_fail_before_resume_capture(self):
        self.add('one')
        bookmark = self.start()['publicationBookmark']
        count = self.store.db.execute('select count(*) from gateway_incident_session').fetchone()[0]
        self.allowed = False
        self.rejected(403,lambda:self.resume(bookmark))
        self.allowed = True
        for key in ('principal','tenant','actor'):
            identity = dict(self.identity, **{key:'SERVICE' if key=='actor' else 'other'})
            self.rejected(404,lambda:self.bookmarks.resume(bookmark,identity,'policy:1',self.visible))
        self.rejected(409,lambda:self.bookmarks.resume(bookmark,self.identity,'policy:2',self.visible))
        self.rejected(503,lambda:PublicationBookmarks(self.store).resume(bookmark,self.identity,'policy:1',self.visible))
        self.assertEqual(self.store.db.execute('select count(*) from gateway_incident_session').fetchone()[0],count)

    def test_expired_or_compacted_boundary_reports_gap_not_empty_health(self):
        self.add('one')
        bookmark = self.start()['publicationBookmark']
        self.now += timedelta(days=91)
        self.rejected(410,lambda:self.resume(bookmark))
        self.now -= timedelta(days=91)
        with self.store.db: self.store.db.execute('update gateway_publication_history_floor set revision=999')
        self.rejected(410,lambda:self.resume(bookmark))

    def test_filters_are_immutable_and_since_or_caller_revisions_are_rejected(self):
        self.add('one')
        bookmark = self.start({'state':'OPEN'})['publicationBookmark']
        self.store.resolve_incident('one','Recovered.')
        self.assertEqual(self.resume(bookmark)['items'],[])
        for query in ({'since':'2026-01-01T00:00:00Z'},{'revision':1},{'state':[]},{'limit':True},{'limit':0}):
            self.rejected(400,lambda:self.start(query))
        self.rejected(400,lambda:self.resume(bookmark,limit=True))
        self.rejected(400,lambda:self.resume('00000000-0000-0000-0000-000000000000'.upper()+'x'))

    def test_bookmark_metadata_is_immutable_and_contains_no_payload(self):
        incident=self.add('one')
        bookmark=self.start()['publicationBookmark']
        row=dict(self.store.db.execute('select * from gateway_publication_bookmark where token=?',(bookmark,)).fetchone())
        self.assertNotIn(incident.incident_id,json.dumps(row))
        self.assertNotIn('impact_summary',row)
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.db.execute('update gateway_publication_bookmark set watermark=watermark+1')
        self.store.db.rollback()

    def test_finite_persistent_capacity_preserves_existing_bookmarks_and_incident_writes(self):
        import uuid
        self.add('first')
        page = self.start()
        original = page['publicationBookmark']
        values = list(self.store.db.execute('select * from gateway_publication_bookmark').fetchone())
        with self.store.db:
            for _ in range(511):
                values[0], values[1] = str(uuid.uuid4()), str(uuid.uuid4())
                self.store.db.execute('insert into gateway_publication_bookmark values(?,?,?,?,?,?,?,?,?,?,?)', values)
        self.add('independent')
        self.rejected(503, lambda:self.start())
        self.assertEqual(self.bookmarks.page(page['cursor'],self.identity,'policy:1',self.visible)['publicationBookmark'], original)
        self.store.close()
        self.store = SQLiteOperationalIncidentStore(self.path, clock=lambda:self.now)
        self.bookmarks = PublicationBookmarks(self.store, lambda identity,policy:True)
        self.rejected(503, lambda:self.start())
        self.assertEqual(self.store.db.execute('select count(*) from gateway_publication_bookmark').fetchone()[0],512)
        self.now += timedelta(days=91)
        self.assertIn('publicationBookmark',self.start())

    def test_live_bookmarks_cannot_be_deleted_and_history_floor_cannot_rewind(self):
        self.add('first')
        self.start()
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.db.execute('delete from gateway_publication_bookmark')
        self.store.db.rollback()
        with self.store.db: self.store.db.execute('update gateway_publication_history_floor set revision=10')
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.db.execute('update gateway_publication_history_floor set revision=0')
        self.store.db.rollback()

    def test_unknown_row_authorization_cannot_be_treated_as_truthy_permission(self):
        self.add('one')
        self.visible = lambda item: {'allowed':False}
        self.rejected(503, lambda:self.start())
        self.assertEqual(self.store.db.execute('select count(*) from gateway_publication_bookmark').fetchone()[0],0)

if __name__ == '__main__': unittest.main()

