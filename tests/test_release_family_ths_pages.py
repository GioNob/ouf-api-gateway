"""Offline D-087 qualification of the F5a APISIX bodies, selectors and return."""
import copy
import json
import sys

import pytest

from ops.apisix import deploy_internal_m2m_routes as bulk, deploy_managed_file_ths
from ops.apisix import deploy_trusted_human_authorization as admin_api
from ops.apisix import deploy_trusted_human_onboarding as onboarding, repair_managed_file_picker_login
from tests.release_bundle_fixture import (
    BASELINE_3D69CB4_IDS, THS_PAGES_IDS, canonical_json, ci_profile, load_release_routes, sha256,
)
from tests.test_execute_delegation import Denied, Engine, human, workload
from tools.gateway_release_bundle import ROOT, generate
from tools.plan_semantic_search import Change, changed_paths, inventory_routes

ADMIN_NAMESPACE = '/api/trusted-human/v1/authorization/*'
ADMIN_WRITE_IDS = ('trusted-human-authorization-put', 'trusted-human-authorization-delete')


@pytest.fixture(scope='module')
def artifact(tmp_path_factory):
    destination = tmp_path_factory.mktemp('ths-pages')
    generate(destination, '1' * 40, '.github/workflows/ci.yml', '60')
    return destination


def resolved(artifact, profile):
    return load_release_routes(artifact, '1' * 40, '.github/workflows/ci.yml', '60', profile)


def fixture_profile():
    return ci_profile(dict(installationId='demo', revision=7, issuerUrl='https://issuer.invalid',
                           gatewayAudience='demo-audience', mcpServiceIdentity='demo-mcp'), 18181)


def by_id(routes):
    return inventory_routes({'total': len(routes), 'list': [{'value': row} for row in routes]})


def selectors_overlap(a, b):
    # ouf-deploy 51h: literal URI (including '*'), all methods/hosts when absent.
    def values(route, single, many):
        result = set(route.get(many, []))
        if single in route:
            result.add(route[single])
        return result

    def intersects(left, right):
        return not left or not right or not left.isdisjoint(right)

    return (not values(a, 'uri', 'uris').isdisjoint(values(b, 'uri', 'uris'))
            and intersects(set(a.get('methods', [])), set(b.get('methods', [])))
            and intersects(values(a, 'host', 'hosts'), values(b, 'host', 'hosts')))


def check_conflicts(desired, live, retired):
    removals = set()
    for entry in retired:
        route_id = entry['id']
        if route_id in live and entry['supersededBy'] is None:
            # v3 obsolete entry: deleted by the release; its selector never collides with a governed one.
            assert all(live[route_id].get(key) == value for key, value in entry['match'].items()), route_id
            assert not any(selectors_overlap(route, live[route_id]) for route in desired.values()), route_id
            removals.add(route_id)
        elif route_id in live:
            assert selectors_overlap(live[route_id], desired[entry['supersededBy']]), route_id
            assert live[route_id].get('vars') == entry['vars'], route_id
            removals.add(route_id)
    for route_id, route in desired.items():
        foreign = live.keys() - removals - desired.keys()
        if route_id in THS_PAGES_IDS:
            # Also check all other managed IDs, both deployed and proposed selectors.
            foreign = live.keys() - removals - {route_id}
            for key in desired.keys() - {route_id}:
                assert not selectors_overlap(route, desired[key]), (route_id, key)
        for key in foreign:
            assert not selectors_overlap(route, live[key]), (route_id, key)


def adoption(desired, live, ids):
    changes = []
    for key in ids:
        before = live.get(key)
        after = desired[key]
        if before is not None:
            assert all(before.get(k) == after.get(k) for k in (
                'uri', 'uris', 'methods', 'host', 'hosts', 'vars', 'remote_addr', 'remote_addrs', 'filter_func'
            )), key
        changes.append(Change(key, key, before, after))
    return changes


def return_plan(changes, readback):
    result = []
    for change in reversed(changes):
        assert not list(changed_paths(change.after, readback.get(change.target_id))), change.target_id
        result.append(Change(change.logical_id, change.target_id, change.after, change.before))
    return result


def test_baseline(artifact):
    """GW-60f-01. Canonical 3d69cb4 subset, even when further families are added."""
    resources = json.loads((artifact / 'bundle.json').read_bytes())['resources']
    baseline = [r for r in resources if r['id'] in BASELINE_3D69CB4_IDS]
    assert len(baseline) == len(BASELINE_3D69CB4_IDS) == 31
    assert sha256(canonical_json(baseline)) == '672d41ca6bd2439c0d1b05e6509a37a58e24a406afc37207da0867168199e9b6'


def test_portable_family_contract(artifact):
    """GW-60f-02. Freeze every compiled family field independent of installation and other families."""
    resources = json.loads((artifact / 'bundle.json').read_bytes())['resources']
    family = [r for r in resources if r['id'] in THS_PAGES_IDS]
    assert [r['id'] for r in family] == sorted(THS_PAGES_IDS)
    # The ten 60f bodies keep their digest; 60f-b only adds the two admin write routes.
    first = [r for r in family if r['id'] not in ADMIN_WRITE_IDS]
    assert sha256(canonical_json(first)) == '1262543e68a5e866b18cd81b3b228059918787f81c109652ece842a9d4d7a33d'
    routes = by_id(resolved(artifact, fixture_profile()))
    check_conflicts(routes, routes, [])
    assert set(ADMIN_WRITE_IDS) <= routes.keys()


def test_literal_collision_in_any_uri_or_governed_route(artifact):
    """GW-60f-03. Rehearse 51h for multiple URIs, wildcard literals and optional selectors."""
    routes = by_id(resolved(artifact, fixture_profile()))
    for key in ('authorization-ths-login', 'authorization-ths-page', 'authorization-ths-api',
                'trusted-human-onboarding-review', 'trusted-human-resolution-review'):
        source = routes[key]
        for path in source.get('uris', [source.get('uri')]):
            with pytest.raises(AssertionError):
                check_conflicts(routes, {'foreign-id': {'uri': path}}, [])
    page = dict(routes['authorization-ths-page'], hosts=['demo.invalid'])
    assert selectors_overlap(page, {'uri': page['uris'][1], 'host': 'demo.invalid'})
    assert not selectors_overlap(page, {'uri': page['uris'][1], 'methods': ['PUT']})
    assert not selectors_overlap(page, {'uri': page['uris'][1], 'host': 'other.invalid'})
    with pytest.raises(AssertionError):
        check_conflicts(routes, {'semantic-human-terms': page}, [])
    with pytest.raises(AssertionError):
        check_conflicts(routes, {'old': page}, [dict(id='old', supersededBy=page['id'], vars=[['x', '==', 'y']])])


def exercise_return(desired, before, ids=THS_PAGES_IDS):
    changes = adoption(desired, before, ids)
    assert [c.action for c in changes] == ['update'] * len(ids)
    live = copy.deepcopy(before)
    for c in changes:
        live[c.target_id] = copy.deepcopy(c.after)
    reread = by_id(json.loads(canonical_json(list(live.values()))))
    assert all(c.action == 'unchanged' for c in adoption(desired, reread, ids))
    stale = dict(reread, **{changes[0].target_id: dict(changes[0].after, status=0)})
    with pytest.raises(AssertionError):
        return_plan(changes, stale)
    for c in return_plan(changes, reread):
        live[c.target_id] = copy.deepcopy(c.after)
    assert canonical_json(by_id(json.loads(canonical_json(list(live.values()))))) == canonical_json(before)


def test_exact_return_and_replay(artifact):
    """GW-60f-04. Reapply and fenced return of full synthetic (unredacted) bodies."""
    desired = by_id(resolved(artifact, fixture_profile()))
    before = {key: dict(body, desc='previous route body') for key, body in desired.items()}
    exercise_return(desired, before)


@pytest.mark.parametrize('ids,family_export', [
    pytest.param(tuple(key for key in THS_PAGES_IDS if key not in ADMIN_WRITE_IDS), 'live-routes-60f.json', id='60f'),
    pytest.param(ADMIN_WRITE_IDS, None, id='60f-b'),
])
def test_export_parity_plan_and_exact_return(artifact, ids, family_export):
    """GW-60f-05 / GW-60f-b-02. Recursive parity, collisions, replay and return on the full export."""
    inputs = ROOT / '.codex-input'
    inventory_file = inputs / 'live-routes-all-98.json'
    if not inventory_file.exists():
        pytest.skip('supply the sanitized 98-route export to replay the installation')
    full_rows = json.loads(inventory_file.read_bytes())
    assert len(full_rows) == 98
    live = by_id(full_rows)
    if family_export:
        family_file = inputs / family_export
        if not family_file.exists():
            pytest.skip('supply the sanitized family export for the historical 60f comparison')
        family = by_id(json.loads(family_file.read_bytes()))
        for key in ids:
            assert list(changed_paths(family[key], live[key])) == [], key
    profile = fixture_profile()
    approvals = live['trusted-human-onboarding-approvals-get']
    admin = live['trusted-human-authorization-get']
    address, = approvals['upstream']['nodes']
    host, port = address.rsplit(':', 1)
    profile.update({
        'services.bindings.ouf-onboarding': host, 'services.ports.ouf-onboarding': int(port),
        'installationId': approvals['labels']['ouf-installation'],
        'revision': approvals['labels']['ouf-installation-revision'],
        'gateway.requiredAudience': approvals['plugins']['openid-connect']['client_id'],
        'caddy.oidcDiscoveryUrl': approvals['plugins']['openid-connect']['discovery'],
    })
    for group, reference in [('thsApprovals', approvals), ('thsAuthorization', admin)]:
        limits = reference['plugins']['limit-count']
        profile['gateway.rateLimits.' + group + '.count'] = limits['count']
        profile['gateway.rateLimits.' + group + '.timeWindowSeconds'] = limits['time_window']
    desired = by_id(resolved(artifact, profile))
    governed_oidc = desired['semantic-human-terms']['plugins']['openid-connect']
    retired = json.loads((artifact / 'bundle.json').read_bytes())['retired']
    check_conflicts(desired, live, retired)
    for key in ids:
        expected = copy.deepcopy(live[key])
        nodes = expected['upstream']['nodes']
        expected['upstream']['nodes'] = [{'host': host, 'port': int(port), 'weight': nodes[address]}]
        assert len(nodes) == 1
        oidc = expected['plugins'].get('openid-connect')
        if oidc:
            for field in ('client_secret', 'set_access_token_header', 'set_id_token_header'):
                assert oidc[field] == '<redatto>'
                oidc[field] = governed_oidc[field]
            expected['labels']['ouf-installation-revision'] = profile['revision']
        assert list(changed_paths(expected, desired[key])) == [], key
    exercise_return(desired, live, ids)


@pytest.mark.parametrize('command', [deploy_managed_file_ths, repair_managed_file_picker_login])
def test_picker_legacy_entrypoints_closed(command):
    """GW-60f-06. The repair launcher cannot load an earlier deployer."""
    with pytest.raises((SystemExit, ValueError), match='governed Gateway release'):
        command.main()


def test_mixed_legacy_deploy_and_old_snapshot_skip_governed_ids(tmp_path):
    """GW-60f-07. Simulate apply, snapshot and return through the former mixed writers."""
    class MemoryAdmin:
        work = tmp_path

        def __init__(self):
            self.routes = {}

        def route(self, method, key, data=None):
            assert key not in onboarding.RELEASE_IDS, key
            if method == 'GET':
                return (200, self.routes[key]) if key in self.routes else (404, {})
            if method == 'PUT':
                self.routes[key] = data
                return 200, {}
            assert method == 'DELETE'
            self.routes.pop(key, None)
            return 204, {}

        def curl(self, path, *args, **kwargs):
            return (200 if path.startswith('/apisix/admin/plugins/') else 401), {}

    ids = onboarding.ROUTE_IDS
    routes = [{'id': key, 'plugins': {'proxy-control': {'request_buffering': False}}} for key in ids]
    backend = MemoryAdmin()
    onboarding.apply(routes, backend)
    assert backend.routes.keys() == ids - onboarding.RELEASE_IDS
    onboarding.restore(dict.fromkeys(ids), backend)
    assert backend.routes == {}



def test_bulk_installer_cannot_apply_or_restore_family():
    """GW-60f-06. Older bulk backups cannot overwrite an adopted ID."""
    for key in THS_PAGES_IDS:
        with pytest.raises(ValueError, match='governed Gateway release'):
            bulk.restore({key: None}, None)
        with pytest.raises(ValueError, match='governed Gateway release'):
            bulk.apply([{'id': key}], None)


@pytest.mark.parametrize('key', THS_PAGES_IDS)
def test_forwarded_session_and_human_headers(artifact, key):
    """GW-60f-08. Execute the released Lua at the browser and bearer boundaries."""
    route = by_id(resolved(artifact, fixture_profile()))[key]
    plugins = route['plugins']
    browser = 'openid-connect' not in plugins
    headers = {'Cookie': 'session=demo', 'X-CSRF-TOKEN': 'demo', 'If-Match': '"7"',
               'X-OUF-Principal-ID': 'untrusted'}
    engine = Engine(human(), headers, {'expectedVersion': 7})
    original = engine.body
    pre, = plugins['serverless-pre-function']['functions']
    engine.lua.execute(pre.encode())(None, None)
    assert engine.body == original and 'proxy-rewrite' not in plugins
    assert b'x-ouf-principal-id' not in engine.headers
    assert (b'authorization' not in engine.headers) == browser
    for header in ('Cookie', 'X-CSRF-TOKEN', 'If-Match'):
        assert engine.headers[header.lower().encode()] == headers[header].encode()
    if 'serverless-post-function' in plugins:
        post, = plugins['serverless-post-function']['functions']
        engine.lua.execute(post.encode())(None, None)
        service = Engine(workload())
        with pytest.raises(Denied, match='403'):
            service.lua.execute(post.encode())(None, None)


def test_admin_write_routes_follow_sibling_bodies(artifact):
    """GW-60f-b-01. PUT and DELETE come from the GET/POST materializer: only the method differs."""
    bodies = {r['id']: r['body'] for r in json.loads((artifact / 'bundle.json').read_bytes())['resources']}
    template = bodies['trusted-human-authorization-get']
    for key, method in zip(ADMIN_WRITE_IDS, ('PUT', 'DELETE')):
        assert bodies[key] == dict(template, methods=[method]), key
        assert bodies[key]['uri'] == ADMIN_NAMESPACE and 'proxy-rewrite' not in bodies[key]['plugins']
        limits = bodies[key]['plugins']['limit-count']
        assert (limits['count'], limits['time_window']) == (
            {'$installation': 'gateway.rateLimits.thsAuthorization.count'},
            {'$installation': 'gateway.rateLimits.thsAuthorization.timeWindowSeconds'})
    routes = by_id(resolved(artifact, fixture_profile()))
    for method in ('PUT', 'DELETE'):
        with pytest.raises(AssertionError):
            check_conflicts(routes, {'foreign-id': {'uri': ADMIN_NAMESPACE, 'methods': [method]}}, [])
    check_conflicts(routes, {'foreign-id': {'uri': ADMIN_NAMESPACE, 'methods': ['PATCH']}}, [])


@pytest.mark.parametrize('ids', [
    ADMIN_WRITE_IDS[:1], ADMIN_WRITE_IDS[1:], admin_api.LEGACY_IDS | set(ADMIN_WRITE_IDS), admin_api.MANAGED_IDS,
])
def test_legacy_admin_refuses_governed_ids_before_writes(ids):
    """GW-60f-b-03. Reject single IDs and mixed snapshots from both earlier generations."""
    with pytest.raises(ValueError, match='governed Gateway release'):
        admin_api.apply(({'id': key} for key in ids), None)
    for saved in (None, {'status': 1}):
        with pytest.raises(ValueError, match='governed Gateway release'):
            admin_api.restore(dict.fromkeys(ids, saved), None)


def test_legacy_admin_entrypoints(tmp_path, monkeypatch):
    """GW-60f-b-03. The CLI rejects governed input and can still restore a complete legacy-only snapshot."""
    calls = []

    class MemoryAdmin:
        def __init__(self, args):
            pass

        def route(self, method, key, data=None):
            calls.append((method, key, data))
            return 204, {}

        def close(self):
            pass

    monkeypatch.setattr(admin_api, 'Admin', MemoryAdmin)
    monkeypatch.setattr(admin_api.os, 'umask', lambda mask: 0)
    source = tmp_path / 'input.json'

    def run(option):
        monkeypatch.setattr(sys, 'argv', ['deploy', option, str(source), '--admin-key', str(tmp_path / 'unused')])
        admin_api.main()

    with pytest.raises(ValueError, match='governed Gateway release'):
        run('--materialization')
    for ids in (admin_api.LEGACY_IDS | set(ADMIN_WRITE_IDS), admin_api.MANAGED_IDS):
        source.write_text(json.dumps(dict.fromkeys(ids)))
        with pytest.raises(ValueError, match='governed Gateway release'):
            run('--restore')
    retained, absent = sorted(admin_api.LEGACY_IDS)
    for invalid in ({absent: None}, {absent: None, retained: None, 'foreign-id': None}):
        source.write_text(json.dumps(invalid))
        with pytest.raises(ValueError, match='full managed route set'):
            run('--restore')
    assert calls == []
    saved = {'status': 1}
    source.write_text(json.dumps({retained: saved, absent: None}))
    run('--restore')
    assert calls == [('PUT', retained, saved), ('DELETE', absent, None)]
