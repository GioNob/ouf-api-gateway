"""Offline adoption on the sanitized APISIX exports and probes for the HTTP gate."""
import copy
import json

import pytest

from ops.apisix.deploy_internal_m2m_routes import apply, restore
from ops.apisix.deploy_semantic_human import LEGACY_IDS, ROUTES, install, validate_snapshot
from tests.release_bundle_fixture import (
    BASE_3D69CB4_IDS, THS_OWNER_IDS, canonical_json, ci_profile, load_release_routes, sha256,
)
from tools.gateway_release_bundle import ROOT, generate
from tools.plan_semantic_search import Change, changed_paths


CHALLENGE = '/api/trusted-human/v1/semantic-approval-challenges/11111111-1111-4111-8111-111111111111'
READINESS = '/api/trusted-human/v1/ingestion/onboarding-readiness'
PREFLIGHT = '/api/udp/v1/governance/identity/preflight'
HTTP_CASES = {
    ('GET', CHALLENGE): 'ouf.semantic.review',
    ('POST', CHALLENGE + '/decision'): 'ouf.semantic.approve',
    ('POST', CHALLENGE + '/publish'): 'ouf.semantic.publish',
    ('POST', READINESS): 'ouf.onboarding.configuration.write',
    ('GET', PREFLIGHT): 'urban.identity.preflight',
    ('POST', PREFLIGHT): 'urban.identity.preflight',
}


def check_owner_http(request, token):
    """GW-60h-05. Observe path, bearer and exact body bytes at the HTTP owner."""
    for (method, path), scope in HTTP_CASES.items():
        body = b'{ "sourceId":"test", "configurationHash":"test", "configuration":{} }' if method == 'POST' else None
        assert request(method, path, body, token('SERVICE', scope=scope))[0] == 403
        status, response = request(method, path, body, token(scope=scope))
        assert status == 200, (method, path, status)
        assert json.loads(response) == [method, path, (body or b'').decode(), True]
    assert request('POST', PREFLIGHT, {}, token(scope='urban.identity.preflight'))[0] == 400


@pytest.fixture(scope='module')
def release(tmp_path_factory):
    directory = tmp_path_factory.mktemp('ths-release')
    generate(directory, '1' * 40, '.github/workflows/ci.yml', '60')
    return directory


def test_predecessor_and_adopted_ids(release):
    """GW-60h-01. Freeze the explicit predecessor, independently of other families."""
    resources = json.loads((release / 'bundle.json').read_bytes())['resources']
    old = [r for r in resources if r['id'] in BASE_3D69CB4_IDS]
    assert sha256(canonical_json(old)) == '672d41ca6bd2439c0d1b05e6509a37a58e24a406afc37207da0867168199e9b6'
    ids = {r['id'] for r in resources}
    assert set(THS_OWNER_IDS) <= ids


def test_verified_public_route_bodies(release):
    """GW-60h-02. Retain the verified field and placeholder shapes in export-free CI."""
    expected = {
        'semantic-human-card': '5ed7f48339cf0edf7d6ee75e97da4c0b413ad221fcfbe478315c674cd02d550f',
        'semantic-human-decision': 'f67af7ff7349c3f9656b65cd3eaaf93c562546ca13711752d33099cae95b1473',
        'semantic-human-publish': 'af829a21c1eb347bacadcb00b0a9eaa3b4bfa6243de9921a450d68adb82a3ced',
        'trusted-human-ingestion-onboarding-readiness': '5e73b850914144185fd950496a331d76cf6c3754a07ea7c7ed3b3d8da3a91a81',
        'ths-identity-preflight-read': '239f1d0681afdcdcd5966474af1d680abde866af43f5c5bd83b49327f722bb6f',
        'ths-identity-preflight-create': '36071d474df859be4ee2bfca2cc5e64df79c24198290e8143e40dc8d1721355d',
    }
    resources = json.loads((release / 'bundle.json').read_bytes())['resources']
    assert {r['id']: sha256(canonical_json(r['body'])) for r in resources if r['id'] in THS_OWNER_IDS} == expected


def test_legacy_snapshot_and_bulk_writes(monkeypatch):
    """GW-60h-04. Historical snapshots and bulk writes respect release ownership."""
    for ids in (set(ROUTES), set(ROUTES) - {'semantic-human-terms'}, LEGACY_IDS):
        assert set(validate_snapshot(dict.fromkeys(ids))) == LEGACY_IDS
    for route_id in THS_OWNER_IDS:
        with pytest.raises(ValueError, match='governed Gateway release'):
            apply([{'id': route_id}], None)
        with pytest.raises(ValueError, match='governed Gateway release'):
            restore({route_id: None}, None)
    writes = {}

    class Admin:
        def route(self, method, key, body=None):
            assert key in LEGACY_IDS
            if method == 'PUT':
                writes[key] = body
            return 200, writes[key]

        def curl(self, path, method):
            return 401, {}

    monkeypatch.setattr('ops.apisix.deploy_semantic_human.snapshot', lambda ids, admin: dict.fromkeys(ids))
    install([{'id': key, 'methods': [method], 'uri': uri} for key, (method, uri, _) in ROUTES.items()], Admin())
    assert writes.keys() == LEGACY_IDS


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


def test_export_plan_readback_restore(release):
    """GW-60h-02. Check every field, retain raw before-images and verify reverse readback."""
    live = export('live-routes-60h.json')
    resolved = load_release_routes(release, '1' * 40, '.github/workflows/ci.yml', '60', export_profile(live))
    desired = {r['id']: r for r in resolved}
    # APISIX timestamps are server-owned. Keep the installed nodes in their original map form.
    before = {key: {k: v for k, v in row.items() if k not in ('create_time', 'update_time')}
              for key, row in live.items()}
    state = copy.deepcopy(before)
    plan = []
    for key in THS_OWNER_IDS:
        target = desired[key]
        installed = state[key]
        oidc = installed['plugins']['openid-connect']
        ref = 'ths-resolution-package-read' if key.startswith('ths-identity-') else 'semantic-human-terms'
        for field in ('client_secret', 'set_access_token_header', 'set_id_token_header'):
            assert oidc[field] == '<redatto>'
            oidc[field] = desired[ref]['plugins']['openid-connect'][field]
        assert list(changed_paths(installed, target)) == ['/upstream/nodes'], key
        address, = installed['upstream']['nodes']
        host, port = address.rsplit(':', 1)
        assert target['upstream']['nodes'] == [{'host': host, 'port': int(port),
                                                'weight': installed['upstream']['nodes'][address]}]
        plan.append(Change(key, key, installed, target))
    assert [c.action for c in plan] == ['update'] * len(THS_OWNER_IDS)
    for c in plan:
        state[c.target_id] = json.loads(canonical_json(c.after))
        assert Change(c.logical_id, c.target_id, state[c.target_id], desired[c.logical_id]).action == 'unchanged'
    for c in reversed(plan):
        assert state[c.target_id] == c.after
        state[c.target_id] = json.loads(canonical_json(c.before))
        assert not list(changed_paths(c.before, state[c.target_id]))
        # Reapply only the exporter's redactions before comparing with its original bytes.
        for field in ('client_secret', 'set_access_token_header', 'set_id_token_header'):
            state[c.target_id]['plugins']['openid-connect'][field] = '<redatto>'
    assert canonical_json(state) == canonical_json(before)


def test_full_export_selector_conflicts(release):
    """GW-60h-03. Apply 51h to every desired route and every foreign inventory ID."""
    live = export('live-routes-all-98.json')
    assert len(live) == 98
    live.update(export('live-routes-60h.json'))
    bundle = json.loads((release / 'bundle.json').read_bytes())
    desired = {r['id']: r for r in load_release_routes(
        release, '1' * 40, '.github/workflows/ci.yml', '60', export_profile(live))}
    foreign = live.keys() - desired.keys()
    for entry in bundle['retired']:
        key = entry['id']
        if key in live:
            assert live[key].get('vars') == entry['vars']
            assert selectors_overlap(live[key], desired[entry['supersededBy']])
            foreign.remove(key)
    assert [(key, other) for key, route in desired.items() for other in foreign
            if selectors_overlap(route, live[other])] == []
    decision = desired['semantic-human-decision']
    assert selectors_overlap(decision, dict(desired['semantic-human-publish'], id='foreign'))
    assert not selectors_overlap(decision, desired['semantic-human-card'])
