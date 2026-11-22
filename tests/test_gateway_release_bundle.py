import json
import re
from urllib.parse import urlsplit

from tests.release_bundle_fixture import RELEASE_ROUTE_IDS, ci_profile, load_release_routes
from tools.gateway_release_bundle import generate


def test_published_terms_release(tmp_path):
    workflow = '.github/workflows/ci.yml'
    commit = '1' * 40
    generate(tmp_path, commit, workflow, '33')
    profile = ci_profile({'installationId': 'fixture', 'revision': 3, 'gatewayAudience': 'reviewer',
                          'issuerUrl': 'https://issuer.invalid', 'mcpServiceIdentity': 'test-mcp'}, 18080)
    routes = load_release_routes(tmp_path, commit, workflow, '33', profile)
    assert [route['id'] for route in routes] == RELEASE_ROUTE_IDS
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
        'gateway.sourceRevisionOwnerKeyEnv': 'secret',
        'gateway.semanticProposalOwnerKeyEnv': 'secret', 'gateway.delegationKeyEnv': 'secret',
        'installationId': 'string', 'revision': 'string', 'gateway.requiredAudience': 'string',
        'caddy.oidcDiscoveryUrl': 'url', 'gateway.oidcClientSecretRef': 'secret',
        'services.bindings.ouf-semantic-registry': 'string', 'services.ports.ouf-semantic-registry': 'integer',
        'services.bindings.ouf-onboarding': 'string', 'services.ports.ouf-onboarding': 'integer',
        'services.bindings.ouf-udp-object-resolution': 'string', 'services.ports.ouf-udp-object-resolution': 'integer',
    }
