import json
import re
from urllib.parse import urlsplit

import pytest

from tests.release_bundle_fixture import RATE_CLASSES, RELEASE_ROUTE_IDS, ci_profile, load_release_routes
from tools import gateway_release_bundle
from tools.gateway_release_bundle import generate
from tools.mcp_dispatch_contract import THS_LINK_ROUTE_KEYS
from tools import mcp_dispatch_contract


def test_published_terms_release(tmp_path):
    workflow = '.github/workflows/ci.yml'
    commit = '1' * 40
    generate(tmp_path, commit, workflow, '33')
    profile = ci_profile({'installationId': 'fixture', 'revision': 3, 'gatewayAudience': 'reviewer',
                          'issuerUrl': 'https://issuer.invalid', 'mcpServiceIdentity': 'test-mcp',
                          'ingestionServiceIdentity': 'test-ingestion', 'udpServiceIdentity': 'test-udp'}, 18080)
    routes = load_release_routes(tmp_path, commit, workflow, '33', profile)
    required_routes = [route['id'] for route in routes if route['id'] not in THS_LINK_ROUTE_KEYS]
    assert required_routes == RELEASE_ROUTE_IDS
    route, = (r for r in routes if r['id'] == 'semantic-human-terms')
    assert route['id'] == 'semantic-human-terms'
    assert route['labels']['ouf-surface'] == 'TRUSTED_HUMAN_SEMANTIC'
    oidc = route['plugins']['openid-connect']
    assert (oidc['client_id'], oidc['client_secret'], oidc['discovery']) == (
        profile['gateway.requiredAudience'], profile['gateway.oidcClientSecretRef'], profile['caddy.oidcDiscoveryUrl'])
    assert oidc['required_scopes'] == ['ouf.semantic.review']
    assert route['upstream']['nodes'] == [{'host': '127.0.0.1', 'port': 18080, 'weight': 1}]
    assert route['upstream']['timeout'] == {'connect': 10, 'send': 10, 'read': 10}
    assert route['plugins']['client-control']['max_body_size'] == 65536
    path = '/api/trusted-human/v1/semantic-published-terms'
    assert route['uri'] == route['plugins']['proxy-rewrite']['uri'] == path
    assert route['methods'] == ['GET']
    assert route['vars'] == [['uri', '~~', '^' + path + '$']]
    for method, target, expected in [
        ('GET', path, True), ('GET', path + '?revisionIds=r1,r2', True),
        ('GET', path + '/', False), ('GET', path + '/extra', False), ('POST', path, False),
    ]:
        uri = urlsplit(target).path
        assert bool(re.search(route['vars'][0][2], uri)) == (uri == path)
        assert (method in route['methods'] and uri == route['uri']) == expected

    bundle = json.loads((tmp_path / 'bundle.json').read_bytes())
    assert {p['name']: p['type'] for p in bundle['placeholders']} == {
        'iam.workloadClients.mcpServer': 'string', 'gateway.issuerUrl': 'url',
        'iam.workloadClients.ingestion': 'string', 'iam.workloadClients.udp': 'string',
        **{f'gateway.rateLimits.{group}.{field}': kind for group in RATE_CLASSES
           for field, kind in [('count', 'integer'), ('timeWindowSeconds', 'integer'), ('key', 'string')]},
        'gateway.sourceRevisionOwnerKeyEnv': 'secret', 'gateway.managedUploadMediaTypes': 'string',
        'gateway.semanticReadOwnerKeyEnv': 'secret',
        'gateway.semanticDiscoveryOwnerKeyEnv': 'secret', 'gateway.semanticProposalOwnerKeyEnv': 'secret', 'gateway.delegationKeyEnv': 'secret',
        'installationId': 'string', 'revision': 'string', 'gateway.requiredAudience': 'string',
        'caddy.oidcDiscoveryUrl': 'url', 'gateway.oidcClientSecretRef': 'secret',
        'services.bindings.ouf-semantic-registry': 'string', 'services.ports.ouf-semantic-registry': 'integer',
        'services.bindings.ouf-onboarding': 'string', 'services.ports.ouf-onboarding': 'integer',
        'services.bindings.ouf-ingestion-runtime': 'string', 'services.ports.ouf-ingestion-runtime': 'integer',
        'services.bindings.ouf-udp-object-resolution': 'string', 'services.ports.ouf-udp-object-resolution': 'integer',
    }


def test_missing_picker_issue_stops_release(tmp_path, monkeypatch):
    """GW-51I-MANIFEST. A predecessor manifest must never publish an incomplete release."""
    manifest = tmp_path / 'picker.json'
    rows = json.loads(mcp_dispatch_contract.PICKER_MANIFEST.read_bytes())
    manifest.write_text(json.dumps([r for r in rows if r['capabilityId'] != mcp_dispatch_contract.PICKER_ISSUE]))
    monkeypatch.setattr(mcp_dispatch_contract, 'PICKER_MANIFEST', manifest)
    output = tmp_path / 'release'
    with pytest.raises(ValueError, match=r'mcp-managed-file-handoff-issue: missing or ambiguous MCP declaration'):
        generate(output, '1' * 40, '.github/workflows/ci.yml', '51')
    assert not output.exists()


RETIREMENT = {'kind': 'routes', 'id': 'legacy', 'supersededBy': 'replacement',
              'vars': [['uri', '~~', '^/legacy$']], 'reason': 'Duplicate route'}


@pytest.mark.parametrize('entries, error', [
    pytest.param({}, 'expected a list', id='list'),
    pytest.param([{}], 'expected kind, id, supersededBy, vars and reason', id='fields'),
    pytest.param([RETIREMENT | {'vars': []}], 'vars must be a non-empty list', id='empty-vars'),
    pytest.param([RETIREMENT | {'vars': 'uri'}], 'vars must be a non-empty list', id='non-list-vars'),
    pytest.param([RETIREMENT | {'vars': [['uri', 1]]}], 'vars must be a non-empty list', id='non-string-condition'),
    pytest.param([RETIREMENT, RETIREMENT | {'id': 'earlier'}], 'sorted by ID', id='order'),
    pytest.param([RETIREMENT, RETIREMENT], 'duplicate retired route ID', id='duplicate'),
    pytest.param([RETIREMENT | {'kind': 'services'}], 'kind must be routes', id='kind'),
    pytest.param([RETIREMENT | {'id': 'bad/id'}], 'invalid retired route ID', id='invalid-id'),
    pytest.param([RETIREMENT | {'id': 123}], 'invalid retired route ID', id='non-string-id'),
    pytest.param([RETIREMENT | {'id': 'replacement'}], 'already in resources', id='existing-route-id'),
    pytest.param([RETIREMENT | {'id': 'service'}], 'already in resources', id='existing-service-id'),
    pytest.param([RETIREMENT | {'supersededBy': 'absent'}], 'supersededBy must identify', id='missing-replacement'),
    pytest.param([RETIREMENT | {'supersededBy': 'service'}], 'supersededBy must identify', id='non-route-replacement'),
    pytest.param([RETIREMENT | {'supersededBy': []}], 'supersededBy must identify', id='non-string-replacement'),
    pytest.param([RETIREMENT | {'reason': ' '}], 'reason must be a non-empty string', id='empty-reason'),
])
def test_invalid_retirements_stop_bundle_generation(tmp_path, monkeypatch, entries, error):
    """GW-51D3-RETIRED-VALIDATION."""
    config = tmp_path / 'retired-routes.json'
    config.write_text(json.dumps(entries), encoding='utf-8')
    monkeypatch.setattr(gateway_release_bundle, 'RETIRED_ROUTES_PATH', config)
    monkeypatch.setattr(gateway_release_bundle, 'release_resources', lambda: [
        {'kind': 'routes', 'id': 'replacement', 'body': {}},
        {'kind': 'services', 'id': 'service', 'body': {}},
    ])

    output = tmp_path / 'release'
    with pytest.raises(ValueError, match=error) as raised:
        generate(output, '1' * 40, '.github/workflows/ci.yml', '33')
    assert config.name in str(raised.value)
    assert not output.exists()
