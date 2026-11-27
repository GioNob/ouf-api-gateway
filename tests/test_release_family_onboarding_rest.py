"""Qualificazione offline delle rotte REST HUMAN di Onboarding."""
import copy
import json
import subprocess
import sys

import pytest

from ops.apisix import deploy_internal_m2m_routes as bulk
from ops.apisix import deploy_trusted_human_installation as legacy_installation
from tests.release_bundle_fixture import (
    BASE_3D69CB4, BASE_5ED88C8, ONBOARDING_IDS, ONBOARDING_REST_IDS, READ_OPERATIONS_IDS, SEMANTIC_MCP_IDS,
    THS_OWNER_IDS, THS_PAGES_IDS, THS_RECOVERY_IDS, canonical_json, sha256,
)
from tests.test_execute_delegation import Denied, Engine
from tests.test_release_family_ths_pages import (
    by_id, check_conflicts, fixture_profile, resolved, return_plan, selectors_overlap,
)
from tools.gateway_release_bundle import ROOT, generate
from tools.plan_semantic_search import Change, changed_paths


@pytest.fixture(scope='module')
def artifact(tmp_path_factory):
    path = tmp_path_factory.mktemp('onboarding-rest')
    generate(path, '1' * 40, '.github/workflows/ci.yml', '60')
    return path


def test_portable_bodies_and_predecessors(artifact):
    """GW-60g-01. Digest dei soli sottoinsiemi chiusi, anche dopo altre adozioni."""
    resources = json.loads((artifact / 'bundle.json').read_bytes())['resources']
    base_60u = BASE_5ED88C8
    for ids, expected_size, expected_digest in (
        (BASE_3D69CB4, 31, 'fd8252656d638689551ccecedc1d91a2fe46e3013b9ac12da931781b2f977cdc'),
        (base_60u, 74, 'a2988606696bb0e556105bf3dcacfd3814f9f9884076cfb42fec5e7eb631a1e5'),
        (ONBOARDING_REST_IDS, 10, '6965ddabd5f19a5517d36e1db6eb0d96c08903c5333cb76f1c93c79a4430511a'),
    ):
        subset = [route for route in resources if route['id'] in ids]
        assert len(subset) == len(ids) == expected_size
        assert sha256(canonical_json(subset)) == expected_digest


def check_family_selectors(desired, inventory):
    for key in ONBOARDING_REST_IDS:
        for other, route in inventory.items():
            if other != key:
                assert not selectors_overlap(desired[key], route), (key, other)


def test_collision_with_foreign_or_governed_id(artifact):
    """GW-60g-02. Un altro ID con la stessa URI e metodi compatibili blocca il plan."""
    desired = by_id(resolved(artifact, fixture_profile()))
    check_family_selectors(desired, desired)
    key = 'trusted-human-managed-file-actions-post'
    for other in ('foreign-id', 'trusted-human-managed-file-picker'):
        with pytest.raises(AssertionError):
            check_family_selectors(desired, {other: {'uris': ['/unused', desired[key]['uri']]}})


def export_profile(live):
    profile = fixture_profile()
    approval = live['trusted-human-onboarding-approvals-get']
    oidc = approval['plugins']['openid-connect']
    address, = approval['upstream']['nodes']
    host, port = address.rsplit(':', 1)
    profile.update({
        'services.bindings.ouf-onboarding': host, 'services.ports.ouf-onboarding': int(port),
        'installationId': approval['labels']['ouf-installation'],
        'revision': approval['labels']['ouf-installation-revision'],
        'gateway.requiredAudience': oidc['client_id'], 'caddy.oidcDiscoveryUrl': oidc['discovery'],
    })
    for group, reference in [('thsOnboardingRest', live['trusted-human-onboarding-sources-get']),
                             ('thsInstallation', live['trusted-human-installation-get'])]:
        limits = reference['plugins']['limit-count']
        profile[f'gateway.rateLimits.{group}.count'] = limits['count']
        profile[f'gateway.rateLimits.{group}.timeWindowSeconds'] = limits['time_window']
    return profile


def test_export_parity_plan_and_return(artifact):
    """GW-60g-03. Parità ricorsiva, plan e ritorno sulle 98 rotte, inclusi gli ID governati."""
    path = ROOT / '.codex-input/live-routes-all-98.json'
    if not path.exists():
        pytest.skip('export sanificato richiesto per la qualifica privata')
    live = by_id(json.loads(path.read_bytes()))
    assert len(live) == 98
    profile = export_profile(live)
    desired = by_id(resolved(artifact, profile))
    retired = json.loads((artifact / 'bundle.json').read_bytes())['retired']
    check_conflicts(desired, live, retired)
    check_family_selectors(desired, live)
    check_family_selectors(desired, desired)
    governed_oidc = desired['semantic-human-terms']['plugins']['openid-connect']
    for key in ONBOARDING_REST_IDS:
        expected = copy.deepcopy(live[key])
        nodes = expected['upstream']['nodes']
        address, = nodes
        host, port = address.rsplit(':', 1)
        expected['upstream']['nodes'] = [{'host': host, 'port': int(port), 'weight': nodes[address]}]
        if key.startswith('trusted-human-installation-'):
            expected['labels']['ouf-installation-revision'] = profile['revision']
        for field in ('client_secret', 'set_access_token_header', 'set_id_token_header'):
            masked = expected['plugins']['openid-connect'][field] == '<redatto>'
            assert masked, (key, field)
            expected['plugins']['openid-connect'][field] = governed_oidc[field]
        assert list(changed_paths(expected, desired[key])) == [], key
    check_round_trip(desired, live)


def check_round_trip(desired, live):
    changes = [Change(key, key, live.get(key), desired[key]) for key in ONBOARDING_REST_IDS]
    assert [change.action for change in changes] == ['update'] * 10
    state = copy.deepcopy(live)
    for change in changes:
        state[change.target_id] = json.loads(canonical_json(change.after))
    assert all(Change(c.logical_id, c.target_id, state[c.target_id], c.after).action == 'unchanged' for c in changes)
    stale = dict(state)
    stale[changes[0].target_id] = dict(changes[0].after, status=0)
    with pytest.raises(AssertionError):
        return_plan(changes, stale)
    for change in return_plan(changes, state):
        state[change.target_id] = json.loads(canonical_json(change.after))
    assert sha256(canonical_json(state)) == sha256(canonical_json(live))


def test_unredacted_return_without_private_export(artifact):
    """GW-60g-06. Ritorno integrale e rifiuto del readback obsoleto anche nella CI pubblica."""
    desired = by_id(resolved(artifact, fixture_profile()))
    live = copy.deepcopy(desired)
    for key in ONBOARDING_REST_IDS:
        live[key]['plugins']['openid-connect']['client_secret'] = '$ENV://PREVIOUS_OIDC_REFERENCE'
    check_round_trip(desired, live)


def test_upload_streaming_and_human_boundary(artifact):
    """GW-60g-04. Il rewrite e il controllo HUMAN preservano bearer e corpo senza leggerlo."""
    routes = by_id(resolved(artifact, fixture_profile()))
    upload = routes['trusted-human-managed-file-upload']
    assert upload['plugins']['proxy-control'] == {'request_buffering': False}
    assert upload['plugins']['client-control'] == {'max_body_size': 10 * 1024 * 1024}
    assert upload['plugins']['proxy-rewrite'] == {'uri': upload['uri']}
    assert 'request-validation' not in upload['plugins']
    for key in ONBOARDING_REST_IDS:
        plugins = routes[key]['plugins']
        for actor in ('HUMAN', 'SERVICE'):
            headers = {'X-OUF-Gateway-Verified': 'forged', 'Idempotency-Key': 'test',
                       'Cookie': 'session=fixture', 'If-Match': '"test"'}
            engine = Engine({'ouf_actor_type': actor}, headers)
            engine.body = b'\x00\xff,\r\n'
            bearer = engine.headers[b'authorization']
            engine.lua.execute(b'ngx.req.read_body = error; ngx.req.get_body_data = error')
            engine.lua.execute(plugins['serverless-pre-function']['functions'][0].encode())(None, None)
            guard = engine.lua.execute(plugins['serverless-post-function']['functions'][0].encode())
            if actor == 'HUMAN':
                guard(None, None)
            else:
                with pytest.raises(Denied, match='403'):
                    guard(None, None)
            assert b'x-ouf-gateway-verified' not in engine.headers
            assert engine.headers[b'authorization'] == bearer
            assert engine.headers[b'idempotency-key'] == b'test'
            assert engine.headers[b'cookie'] == b'session=fixture'
            assert engine.headers[b'if-match'] == b'"test"'
            assert engine.body == b'\x00\xff,\r\n'


def test_legacy_writers_and_snapshots(tmp_path):
    """GW-60g-05. Vecchi apply e restore non possono scrivere alcun ID adottato."""
    for key in ONBOARDING_REST_IDS:
        with pytest.raises(ValueError, match='governed Gateway release'):
            bulk.apply([{'id': key}], None)
        with pytest.raises(ValueError, match='governed Gateway release'):
            bulk.restore({'unrelated': None, key: None}, None)
    with pytest.raises(ValueError, match='governed Gateway release'):
        legacy_installation.restore(dict.fromkeys(legacy_installation.CURRENT_IDS), None)
    with pytest.raises(ValueError, match='governed Gateway release'):
        legacy_installation.apply([{'id': key} for key in legacy_installation.CURRENT_IDS], None)
    for script in ('deploy_trusted_human_installation.py', 'deploy_trusted_human_onboarding.py'):
        for mode in ('--materialization', '--restore'):
            absent = str(tmp_path / 'absent')
            result = subprocess.run([sys.executable, str(ROOT / 'ops/apisix' / script), mode, absent,
                                     '--admin-key', absent], capture_output=True, text=True)
            assert result.returncode and 'governed Gateway release' in result.stderr
