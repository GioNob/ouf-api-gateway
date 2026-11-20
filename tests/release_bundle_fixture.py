"""Independent consumer of the on-disk artifact in the APISIX CI gate."""
import hashlib
import json


def load_release_routes(directory, commit, profile):
    payload = (directory / 'bundle.json').read_bytes()
    manifest = json.loads((directory / 'manifest.json').read_bytes())
    assert manifest['schema'] == 'ouf.gateway-release-manifest.v1'
    assert manifest['files'] == {'bundle.json': hashlib.sha256(payload).hexdigest()}
    bundle = json.loads(payload)
    assert bundle['schema'] == 'ouf.gateway-release-bundle.v1'
    assert bundle['sourceCommit'] == manifest['sourceCommit'] == commit
    resources = bundle['resources']
    encoded = json.dumps(resources, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()
    assert bundle['resourcesSha256'] == hashlib.sha256(encoded).hexdigest()
    used = set()

    def resolve(value):
        if isinstance(value, list):
            return [resolve(item) for item in value]
        if isinstance(value, dict):
            if '$installation' in value:
                assert set(value) == {'$installation'}
                name = value['$installation']
                used.add(name)
                return profile[name]
            return {key: resolve(item) for key, item in value.items()}
        return value

    routes = []
    for item in resources:
        assert set(item) == {'kind', 'id', 'body'} and item['kind'] == 'routes'
        assert 'id' not in item['body']
        routes.append(dict(resolve(item['body']), id=item['id']))
    assert [r['id'] for r in routes] == sorted({r['id'] for r in routes})
    assert manifest['installationPlaceholders'] == sorted(used) == sorted(profile)
    return routes


def ci_profile(installation, port):
    return {
        'installationId': installation['installationId'], 'revision': str(installation['revision']),
        'gateway.requiredAudience': installation['gatewayAudience'],
        'gateway.issuerUrl': installation['issuerUrl'],
        'iam.workloadClients.mcpServer': installation['mcpServiceIdentity'],
        'caddy.oidcDiscoveryUrl': f'http://127.0.0.1:{port}/discovery',
        'gateway.oidcClientSecretRef': '$ENV://OIDC_SECRET',
        'gateway.delegationKeyEnv': 'DELEGATION_KEY',
        'gateway.sourceRevisionOwnerKeyEnv': 'REVISION_KEY',
        'gateway.semanticProposalOwnerKeyEnv': 'SEMANTIC_KEY',
        'services.bindings.ouf-onboarding': '127.0.0.1', 'services.ports.ouf-onboarding': port,
        'services.bindings.ouf-semantic-registry': '127.0.0.1', 'services.ports.ouf-semantic-registry': port,
    }
