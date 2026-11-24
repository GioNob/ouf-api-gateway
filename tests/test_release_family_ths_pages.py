"""Offline D-087 qualification of the F5a APISIX bodies, selectors and return."""
import copy
import json

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
        if route_id in live:
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


def adoption(desired, live):
    changes = []
    for key in THS_PAGES_IDS:
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
    assert sha256(canonical_json(family)) == '1262543e68a5e866b18cd81b3b228059918787f81c109652ece842a9d4d7a33d'
    routes = by_id(resolved(artifact, fixture_profile()))
    check_conflicts(routes, routes, [])
    assert not {'trusted-human-authorization-put', 'trusted-human-authorization-delete'} & routes.keys()


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


def exercise_return(desired, before):
    changes = adoption(desired, before)
    assert [c.action for c in changes] == ['update'] * len(THS_PAGES_IDS)
    live = copy.deepcopy(before)
    for c in changes:
        live[c.target_id] = copy.deepcopy(c.after)
    reread = by_id(json.loads(canonical_json(list(live.values()))))
    assert all(c.action == 'unchanged' for c in adoption(desired, reread))
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


def test_export_parity_plan_and_exact_return(artifact):
    """GW-60f-05. Private offline evidence supplied for qualification; never required for the build."""
    inputs = ROOT / '.codex-input'
    family_file = inputs / 'live-routes-60f.json'
    inventory_file = inputs / 'live-routes-all-98.json'
    if not family_file.exists() and not inventory_file.exists():
        pytest.skip('supply both sanitized task-60f exports to replay the installation')
    full_rows = json.loads(inventory_file.read_bytes())
    assert len(full_rows) == 98
    live = by_id(full_rows)
    family = by_id(json.loads(family_file.read_bytes()))
    profile = fixture_profile()
    approvals = family['trusted-human-onboarding-approvals-get']
    admin = family['trusted-human-authorization-get']
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
    for key in THS_PAGES_IDS:
        assert list(changed_paths(family[key], live[key])) == [], key
        expected = copy.deepcopy(family[key])
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
    exercise_return(desired, live)


@pytest.mark.parametrize('command', [deploy_managed_file_ths, repair_managed_file_picker_login])
def test_picker_legacy_entrypoints_closed(command):
    """GW-60f-06. The repair launcher cannot load an earlier deployer."""
    with pytest.raises((SystemExit, ValueError), match='governed Gateway release'):
        command.main()


@pytest.mark.parametrize('module', [onboarding, admin_api])
def test_mixed_legacy_deploy_and_old_snapshot_skip_governed_ids(tmp_path, module):
    """GW-60f-07. Simulate apply, snapshot and return through the former mixed writers."""
    class MemoryAdmin:
        work = tmp_path

        def __init__(self):
            self.routes = {}

        def route(self, method, key, data=None):
            assert key not in module.RELEASE_IDS, key
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

    ids = onboarding.ROUTE_IDS if module is onboarding else admin_api.CURRENT_IDS
    routes = [{'id': key, 'plugins': {'proxy-control': {'request_buffering': False}}} for key in ids]
    backend = MemoryAdmin()
    module.apply(routes, backend)
    assert backend.routes.keys() == ids - module.RELEASE_IDS
    old_ids = ids if module is onboarding else admin_api.MANAGED_IDS
    module.restore(dict.fromkeys(old_ids), backend)
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
