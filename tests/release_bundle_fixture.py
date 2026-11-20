"""Independent consumer of the on-disk artifact in the APISIX CI gate."""
import hashlib
import json
import re


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False).encode('utf-8')


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def load_release_routes(directory, commit, workflow_path, run_id, profile):
    assert {p.name for p in directory.iterdir()} == {'bundle.json', 'manifest.json', 'SHA256SUMS'}
    payload = (directory / 'bundle.json').read_bytes()
    manifest_payload = (directory / 'manifest.json').read_bytes()
    assert (directory / 'SHA256SUMS').read_bytes() == (
        f'{sha256(payload)}  bundle.json\n{sha256(manifest_payload)}  manifest.json\n'.encode('ascii')
    )
    manifest = json.loads(manifest_payload)
    bundle = json.loads(payload)
    assert manifest_payload == canonical_json(manifest)
    assert payload == canonical_json(bundle)
    assert set(manifest) == {'schema', 'sourceRepository', 'sourceCommit', 'workflowPath', 'runId',
                             'bundleSha256', 'resourcesSha256', 'placeholders'}
    assert set(bundle) == {'schema', 'sourceRepository', 'sourceCommit', 'resources',
                           'placeholders', 'resourcesSha256'}
    assert manifest['schema'] == 'ouf.gateway-release-manifest.v1'
    assert bundle['schema'] == 'ouf.gateway-release-bundle.v1'
    assert bundle['sourceRepository'] == manifest['sourceRepository'] == 'GioNob/ouf-api-gateway'
    assert re.fullmatch(r'[0-9a-f]{40}', commit)
    assert bundle['sourceCommit'] == manifest['sourceCommit'] == commit
    assert manifest['workflowPath'] == workflow_path
    assert re.fullmatch(r'\.github/workflows/[^/]+\.yml', workflow_path)
    assert manifest['runId'] == run_id
    assert re.fullmatch(r'[0-9]+', run_id)
    assert manifest['bundleSha256'] == sha256(payload)
    resources = bundle['resources']
    assert isinstance(resources, list)
    assert bundle['resourcesSha256'] == manifest['resourcesSha256'] == sha256(canonical_json(resources))
    assert isinstance(bundle['placeholders'], list)
    for entry in bundle['placeholders']:
        assert set(entry) == {'name', 'type'}
        assert re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{0,127}', entry['name'])
        assert entry['type'] in {'string', 'url', 'secret'}
    used = set()

    def resolve(value):
        if isinstance(value, list):
            return [resolve(item) for item in value]
        if isinstance(value, dict):
            if '$installation' in value:
                assert set(value) == {'$installation'}
                name = value['$installation']
                assert re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{0,127}', name)
                used.add(name)
                return profile[name]
            return {key: resolve(item) for key, item in value.items()}
        return value

    routes = []
    for item in resources:
        assert set(item) == {'kind', 'id', 'body'} and item['kind'] == 'routes'
        assert re.fullmatch(r'[A-Za-z0-9._-]{1,64}', item['id'])
        assert isinstance(item['body'], dict) and not {'id', 'create_time', 'update_time'} & item['body'].keys()
        routes.append(dict(resolve(item['body']), id=item['id']))
    assert [r['id'] for r in routes] == sorted({r['id'] for r in routes})
    assert [entry['name'] for entry in bundle['placeholders']] == manifest['placeholders'] == sorted(used) == sorted(profile)
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
