"""Offline adoption on the sanitized APISIX exports and probes for the HTTP gate."""
import copy
import json
import subprocess
import sys

import pytest

from ops.apisix.deploy_internal_m2m_routes import apply, restore
from ops.apisix.deploy_semantic_human import ROUTES, install, validate_snapshot
from ops.apisix.deploy_status_execute import apply_routes
from tests.test_execute_delegation import Denied, Engine
from tests.release_bundle_fixture import (
    BASE_3D69CB4_IDS, THS_OWNER_IDS, THS_RECOVERY_IDS, canonical_json, ci_profile, load_release_routes, sha256,
)
from tools.gateway_release_bundle import ROOT, generate
from tools.plan_semantic_search import Change, changed_paths


CHALLENGE = '/api/trusted-human/v1/semantic-approval-challenges/11111111-1111-4111-8111-111111111111'
READINESS = '/api/trusted-human/v1/ingestion/onboarding-readiness'
PREFLIGHT = '/api/udp/v1/governance/identity/preflight'
QUARANTINE_ITEM = '/api/trusted-human/v1/ingestion/quarantine/A1111111-b111-4111-8111-111111111111'
MATERIALIZATION_JOB = '/api/udp/v1/governance/materialization/jobs/A1111111-b111-4111-8111-111111111111'
RECOVERY_HTTP_CASES = {
    ('GET', QUARANTINE_ITEM): 'ingestion.quarantine.read',
    ('POST', QUARANTINE_ITEM + '/retry'): 'ouf.ingestion.quarantine.retry',
    ('GET', MATERIALIZATION_JOB): 'udp.materialization.retry',
    ('POST', MATERIALIZATION_JOB + '/retry'): 'udp.materialization.retry',
}
HTTP_CASES = {
    ('GET', CHALLENGE): 'ouf.semantic.review',
    ('POST', CHALLENGE + '/decision'): 'ouf.semantic.approve',
    ('POST', CHALLENGE + '/publish'): 'ouf.semantic.publish',
    ('POST', READINESS): 'ouf.onboarding.configuration.write',
    ('GET', PREFLIGHT): 'urban.identity.preflight',
    ('POST', PREFLIGHT): 'urban.identity.preflight',
    **RECOVERY_HTTP_CASES,
}


def check_owner_http(request, token):
    """GW-60h-05. Observe path, bearer and body at the HTTP owner (exact bytes, decoded JSON for the preflight)."""
    for (method, path), scope in HTTP_CASES.items():
        body = b'{ "sourceId":"test", "configurationHash":"test", "configuration":{} }' if method == 'POST' else None
        assert request(method, path, body, token('SERVICE', scope=scope))[0] == 403
        status, response = request(method, path, body, token(scope=scope))
        assert status == 200, (method, path, status)
        seen_method, seen_path, seen_body, bearer = json.loads(response)
        assert [seen_method, seen_path, bearer] == [method, path, True]
        if (method, path) == ('POST', PREFLIGHT):
            # The installed preflight route validates and re-encodes the JSON body (key order not stable),
            # exactly like the live route it adopts: compare the decoded document.
            assert json.loads(seen_body) == json.loads(body)
        else:
            assert seen_body == (body or b'').decode()
        if (method, path) in RECOVERY_HTTP_CASES:
            assert request(method, path, body, token('HUMAN_USER', scope=scope))[0] == 200
            assert request(method, path, body, token(scope='unrelated'))[0] == 403
    assert request('POST', PREFLIGHT, {}, token(scope='urban.identity.preflight'))[0] == 400


@pytest.fixture(scope='module')
def release(tmp_path_factory):
    directory = tmp_path_factory.mktemp('ths-release')
    generate(directory, '1' * 40, '.github/workflows/ci.yml', '60')
    return directory


def test_predecessor_and_adopted_ids(release):
    """GW-60h-01 / GW-60h-08. Freeze both explicit predecessors independently of other families."""
    resources = json.loads((release / 'bundle.json').read_bytes())['resources']
    old = [r for r in resources if r['id'] in BASE_3D69CB4_IDS]
    assert sha256(canonical_json(old)) == '672d41ca6bd2439c0d1b05e6509a37a58e24a406afc37207da0867168199e9b6'
    first_pass = BASE_3D69CB4_IDS.union(THS_OWNER_IDS)
    previous = [r for r in resources if r['id'] in first_pass]
    assert sha256(canonical_json(previous)) == '5624e6ecf02ec80c4bd09f2e2581019b434112439b48478d55c27bace4d6119e'
    ids = {r['id'] for r in resources}
    assert first_pass.union(THS_RECOVERY_IDS) <= ids


def test_verified_public_route_bodies(release):
    """GW-60h-02 / GW-60h-06. Retain the verified field and placeholder shapes in export-free CI."""
    expected = {
        'semantic-human-card': '5ed7f48339cf0edf7d6ee75e97da4c0b413ad221fcfbe478315c674cd02d550f',
        'semantic-human-decision': 'f67af7ff7349c3f9656b65cd3eaaf93c562546ca13711752d33099cae95b1473',
        'semantic-human-publish': 'af829a21c1eb347bacadcb00b0a9eaa3b4bfa6243de9921a450d68adb82a3ced',
        'trusted-human-ingestion-onboarding-readiness': '5e73b850914144185fd950496a331d76cf6c3754a07ea7c7ed3b3d8da3a91a81',
        'ths-identity-preflight-read': '239f1d0681afdcdcd5966474af1d680abde866af43f5c5bd83b49327f722bb6f',
        'ths-identity-preflight-create': '36071d474df859be4ee2bfca2cc5e64df79c24198290e8143e40dc8d1721355d',
        'r4a-ingestion-human-quarantine-read': '46e9a35fd3b98777ab9025cf2df8b47b191536f68a32ce976db862d8f6bbf9c9',
        'r4a-ingestion-human-quarantine-retry': 'ecf2b476685fd11c9e548dc9c4ac7e892e178fdb6cd921677edf6bcfb39f0f26',
        'r4a-udp-human-materialization-review': 'a4ca9c5dbcb871006942bed451d23f2b02c9e62e68ce41092b332fcd2b6c42ec',
        'r4a-udp-human-materialization-retry': '956630d291b48929b6197ce555b3d6f6fa5c5d6d5ea5ff367c3d239cb8cf5177',
    }
    resources = json.loads((release / 'bundle.json').read_bytes())['resources']
    assert {r['id']: sha256(canonical_json(r['body'])) for r in resources if r['id'] in expected} == expected


def test_recovery_lua_preserves_owner_request(release):
    """GW-60h-10. Execute the published rewrite and access functions with synthetic claims."""
    resources = json.loads((release / 'bundle.json').read_bytes())['resources']
    for route in resources:
        if route['id'] not in THS_RECOVERY_IDS:
            continue
        plugins = route['body']['plugins']
        rewrite, = plugins['serverless-pre-function']['functions']
        access, = plugins['serverless-post-function']['functions']
        for actor in ('HUMAN', 'HUMAN_USER', 'SERVICE'):
            engine = Engine({'ouf_actor_type': actor}, {'X-OUF-Role': 'forged', 'Idempotency-Key': 'request-1'})
            original = engine.body, engine.headers[b'authorization']
            engine.lua.execute(rewrite.encode())(None, None)
            assert b'x-ouf-role' not in engine.headers
            if actor == 'SERVICE':
                with pytest.raises(Denied, match='403'):
                    engine.lua.execute(access.encode())(None, None)
            else:
                engine.lua.execute(access.encode())(None, None)
                assert (engine.body, engine.headers[b'authorization']) == original
                assert engine.headers[b'idempotency-key'] == b'request-1'


def test_legacy_snapshot_and_bulk_writes():
    """GW-60h-04 / GW-60h-09. Historical snapshots and bulk writes respect release ownership."""
    for ids in (set(ROUTES), set(ROUTES) - {'semantic-human-terms'}):
        with pytest.raises(ValueError, match='governed Gateway release'):
            validate_snapshot(dict.fromkeys(ids))
    for route_id in THS_OWNER_IDS + THS_RECOVERY_IDS:
        with pytest.raises(ValueError, match='governed Gateway release'):
            apply([{'id': route_id}], None)
        with pytest.raises(ValueError, match='governed Gateway release'):
            restore({route_id: None}, None)
    with pytest.raises(ValueError, match='governed Gateway release'):
        install([{'id': key} for key in ROUTES], None)


@pytest.mark.parametrize('route_id', THS_RECOVERY_IDS)
def test_legacy_status_batch_and_restore_reject_recovery_ids(tmp_path, route_id):
    """GW-60h-09. A mixed status snapshot must fail before opening the Admin client."""
    snapshot = dict.fromkeys(('first', route_id, 'last'))
    with pytest.raises(ValueError, match='governed Gateway release'):
        apply_routes([{'id': key} for key in snapshot], None)
    path = tmp_path / 'previous.json'
    path.write_text(json.dumps(snapshot))
    result = subprocess.run([sys.executable, str(ROOT / 'ops/apisix/deploy_status_execute.py'),
                             '--restore', str(path), '--admin-key', str(tmp_path / 'absent')],
                            capture_output=True, text=True)
    assert result.returncode != 0 and 'governed Gateway release' in result.stderr


def export(name):
    path = ROOT / '.codex-input' / name
    if not path.exists():
        pytest.skip('supply the read-only sanitized export ' + name)
    rows = json.loads(path.read_bytes())
    indexed = {row['id']: row for row in rows}
    assert len(rows) == len(indexed)
    return indexed


def export_profile(live):
    terms = live['semantic-human-terms']
    oidc = terms['plugins']['openid-connect']
    profile = ci_profile({'installationId': terms['labels']['ouf-installation'],
                          'revision': live['semantic-human-card']['labels']['ouf-installation-revision'],
                          'gatewayAudience': oidc['client_id'], 'issuerUrl': oidc['discovery'].rsplit('/.well-known/', 1)[0],
                          'mcpServiceIdentity': 'test-mcp'}, 18080)
    profile['caddy.oidcDiscoveryUrl'] = oidc['discovery']
    profile['gateway.publicApiHost'] = live['r4a-udp-human-materialization-review']['host']
    for service, ref in [('ouf-semantic-registry', 'semantic-human-terms'),
                         ('ouf-udp-object-resolution', 'ths-resolution-package-read')]:
        node, = live[ref]['upstream']['nodes']
        profile['services.bindings.' + service] = node['host']
        profile['services.ports.' + service] = node['port']
    address, = live['trusted-human-ingestion-onboarding-readiness']['upstream']['nodes']
    host, port = address.rsplit(':', 1)
    profile['services.bindings.ouf-ingestion-runtime'] = host
    profile['services.ports.ouf-ingestion-runtime'] = int(port)
    for group, ref in [('thsSemantic', 'semantic-human-card'),
                       ('thsIngestionReadiness', 'trusted-human-ingestion-onboarding-readiness'),
                       ('thsIdentityPreflight', 'ths-identity-preflight-read')]:
        limit = live[ref]['plugins']['limit-count']
        profile[f'gateway.rateLimits.{group}.count'] = limit['count']
        profile[f'gateway.rateLimits.{group}.timeWindowSeconds'] = limit['time_window']
    return profile


def selectors_overlap(left, right):
    def selectors(route, singular, plural):
        result = set(route.get(plural, []))
        if singular in route:
            result.add(route[singular])
        return result

    uris = selectors(left, 'uri', 'uris') & selectors(right, 'uri', 'uris')
    methods, other_methods = set(left.get('methods', [])), set(right.get('methods', []))
    hosts, other_hosts = selectors(left, 'host', 'hosts'), selectors(right, 'host', 'hosts')
    return bool(uris and (not methods or not other_methods or methods & other_methods)
                and (not hosts or not other_hosts or hosts & other_hosts))


@pytest.mark.parametrize(('filename', 'ids', 'oidc_fields'), [
    ('live-routes-60h.json', THS_OWNER_IDS, ('client_secret', 'set_access_token_header', 'set_id_token_header')),
    ('live-routes-60h-b.json', THS_RECOVERY_IDS, ('client_secret',)),
])
def test_export_plan_readback_restore(release, filename, ids, oidc_fields):
    """GW-60h-02 / GW-60h-06. Check every field, retain before-images and verify reverse readback."""
    live = export(filename)
    profile = export_profile(export('live-routes-60h.json') | live)
    resolved = load_release_routes(release, '1' * 40, '.github/workflows/ci.yml', '60', profile)
    desired = {r['id']: r for r in resolved}
    # APISIX timestamps are server-owned. Keep the installed nodes in their original map form.
    before = {key: {k: v for k, v in row.items() if k not in ('create_time', 'update_time')}
              for key, row in live.items()}
    state = copy.deepcopy(before)
    plan = []
    for key in ids:
        target = desired[key]
        installed = state[key]
        oidc = installed['plugins']['openid-connect']
        if key in THS_RECOVERY_IDS:
            ref = 'ths-identity-preflight-read'
            assert live[ref]['plugins']['openid-connect']['client_secret'] == '<redatto>'
        else:
            ref = 'ths-resolution-package-read' if key.startswith('ths-identity-') else 'semantic-human-terms'
        for field in oidc_fields:
            assert oidc[field] == '<redatto>'
            oidc[field] = desired[ref]['plugins']['openid-connect'][field]
        assert list(changed_paths(installed, target)) == ['/upstream/nodes'], key
        address, = installed['upstream']['nodes']
        host, port = address.rsplit(':', 1)
        assert target['upstream']['nodes'] == [{'host': host, 'port': int(port),
                                                'weight': installed['upstream']['nodes'][address]}]
        plan.append(Change(key, key, installed, target))
    assert [c.action for c in plan] == ['update'] * len(ids)
    for c in plan:
        state[c.target_id] = json.loads(canonical_json(c.after))
        assert Change(c.logical_id, c.target_id, state[c.target_id], desired[c.logical_id]).action == 'unchanged'
    for c in reversed(plan):
        assert state[c.target_id] == c.after
        state[c.target_id] = json.loads(canonical_json(c.before))
        assert not list(changed_paths(c.before, state[c.target_id]))
        # Reapply only the exporter's redactions before comparing with its original bytes.
        for field in oidc_fields:
            state[c.target_id]['plugins']['openid-connect'][field] = '<redatto>'
    assert canonical_json(state) == canonical_json(before)


def test_full_export_selector_conflicts(release):
    """GW-60h-03 / GW-60h-07. Apply 51h to every desired route and every foreign inventory ID."""
    live = export('live-routes-all-98.json')
    assert len(live) == 98
    profile = export_profile(export('live-routes-60h.json') | export('live-routes-60h-b.json'))
    bundle = json.loads((release / 'bundle.json').read_bytes())
    desired = {r['id']: r for r in load_release_routes(
        release, '1' * 40, '.github/workflows/ci.yml', '60', profile)}
    foreign = live.keys() - desired.keys()
    for entry in bundle['retired']:
        key = entry['id']
        if key in live and entry['supersededBy'] is None:
            # v3 obsolete entry: deleted by the release; its selector never collides with a governed one.
            assert all(live[key].get(field) == value for field, value in entry['match'].items())
            assert not any(selectors_overlap(route, live[key]) for route in desired.values())
            foreign.remove(key)
        elif key in live:
            assert live[key].get('vars') == entry['vars']
            assert selectors_overlap(live[key], desired[entry['supersededBy']])
            foreign.remove(key)
    assert [(key, other) for key, route in desired.items() for other in foreign
            if selectors_overlap(route, live[other])] == []
    decision = desired['semantic-human-decision']
    assert selectors_overlap(decision, dict(desired['semantic-human-publish'], id='foreign'))
    assert not selectors_overlap(decision, desired['semantic-human-card'])
