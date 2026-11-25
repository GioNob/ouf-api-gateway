"""Offline D-087 examples. The local installation owns the APISIX IDs."""
import copy
import unittest

from tools.plan_semantic_search import EXECUTE_PATH, changed_paths, restore_plan, search_plan


def fixture(mode):
    batch = mode == 'search-batch'
    cap = 'ouf.semantic.search.batch' if batch else 'ouf.semantic.search'
    return {
        'id': 'mcp-semantic-' + mode,
        'uri': EXECUTE_PATH + '/semantic/' + ('consultation/' if batch else '') + mode,
        'methods': ['POST'],
        'labels': {'ouf-installation': 'fixture', 'ouf-installation-revision': '2'},
        'plugins': {'proxy-rewrite': {'uri': '/api/internal/v1/semantic/consultation/' + mode},
                    'request-validation': {'body_schema': {'properties': {'CapabilityID': {'const': cap}}}}},
    }


def inventory(routes):
    return {'total': len(routes), 'list': [{'key': '/apisix/routes/' + row['id'], 'value': row} for row in routes]}


class SearchPlanTest(unittest.TestCase):
    def setUp(self):
        self.desired = [fixture('search'), fixture('search-batch')]
        self.old = copy.deepcopy(self.desired[0])
        self.old['id'] = 'fixture-installed-id'
        self.old['labels']['ouf-installation-revision'] = '1'

    def test_adopt_then_replan_and_restore_with_original_ids(self):
        """GW-51M-05. Replay and restore against the installation-owned route ID."""
        live = {self.old['id']: self.old}
        before = copy.deepcopy(live)
        plan = search_plan(self.desired, inventory(live.values()), '1')
        self.assertEqual([(c.action, c.target_id) for c in plan],
                         [('update', self.old['id']), ('create', self.desired[1]['id'])])
        self.assertEqual(list(changed_paths(plan[0].before, plan[0].after)), ['/labels/ouf-installation-revision'])
        for c in plan:
            live[c.target_id] = c.after
        self.assertEqual(len({r['uri'] for r in live.values()}), 2)
        self.assertEqual([c.action for c in search_plan(self.desired, inventory(live.values()), '2')],
                         ['unchanged', 'unchanged'])
        with self.assertRaisesRegex(ValueError, 'restore readback drift'):
            restore_plan(plan, inventory([dict(r, priority=10) for r in live.values()]))
        for c in restore_plan(plan, inventory(live.values())):
            if c.after is None:
                del live[c.target_id]
            else:
                live[c.target_id] = c.after
        self.assertEqual(live, before)

    def test_only_identified_duplicates_can_be_retired_and_restored(self):
        canonical = dict(self.old, id=self.desired[0]['id'])
        change, retire, create = search_plan(self.desired, inventory([self.old, canonical]), '1')
        self.assertEqual((change.action, retire.action, create.action), ('update', 'retire', 'create'))
        self.assertEqual((retire.target_id, retire.before, retire.after), (self.old['id'], self.old, None))
        restored = restore_plan([change, retire, create], inventory([change.after, create.after]))
        self.assertEqual({c.target_id: c.after for c in restored if c.after}, {r['id']: r for r in [canonical, self.old]})
        with self.assertRaisesRegex(ValueError, 'ambiguous'):
            search_plan(self.desired, inventory([self.old, dict(self.old, id='another')]), '1')

    def test_retired_duplicate_with_uris_selector_restores(self):
        """GW-55C-04. Restore derives the selector of a retired duplicate declared with `uris`."""
        old = {k: v for k, v in self.old.items() if k != 'uri'}
        old['uris'] = [self.old['uri']]
        canonical = dict(self.old, id=self.desired[0]['id'])
        unrelated = dict(self.old, id='unrelated', uri='/unrelated')
        change, retire, create = search_plan(self.desired, inventory([old, canonical, unrelated]), '1')
        self.assertEqual((retire.action, retire.before), ('retire', old))
        restored = restore_plan([change, retire, create], inventory([change.after, create.after, unrelated]))
        self.assertEqual({c.target_id: c.after for c in restored if c.after}, {r['id']: r for r in [canonical, old]})

    def test_refuse_partial_inventory_revision_drift_and_selector_collision(self):
        with self.assertRaisesRegex(ValueError, 'complete'):
            search_plan(self.desired, dict(inventory([self.old]), total=2), '1')
        for route in (dict(self.old, host='fixture.invalid'), dict(self.old, uri=EXECUTE_PATH + '/*'),
                      dict(self.old, labels={'ouf-installation': 'other', 'ouf-installation-revision': '1'}),
                      dict(self.old, labels=self.desired[0]['labels']),
                      dict(self.old, id=self.desired[0]['id'], uri='/unrelated')):
            with self.subTest(route=route), self.assertRaises(ValueError):
                search_plan(self.desired, inventory([route]), '1')

    def test_use_admin_key_and_reject_inconsistent_embedded_id(self):
        snapshot = inventory([copy.deepcopy(self.old)])
        value = snapshot['list'][0]['value']
        del value['id']
        self.assertEqual(search_plan(self.desired, snapshot, '1')[0].target_id, self.old['id'])
        value['id'] = 'unrelated'
        with self.assertRaisesRegex(ValueError, 'key and route ID disagree'):
            search_plan(self.desired, snapshot, '1')
