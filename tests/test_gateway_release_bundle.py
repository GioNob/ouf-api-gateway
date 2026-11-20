import json
import subprocess
import sys

import pytest

from tests.release_bundle_fixture import ci_profile, load_release_routes
from tests.test_execute_delegation import Engine, INSTALL, human, proof, workload
from tests.test_semantic_proposals import request as proposal_request
from tests.test_source_revision import request as revision_request
from tools import gateway_release_bundle as producer

WORKFLOW_PATH = '.github/workflows/ci.yml'
RUN_ID = '123456789'


def test_release_artifact(tmp_path, monkeypatch):
    # The CLI must not sample the runner's installed endpoints or key material.
    canary = 'private-test-value-never-distribute'
    for name in ('OIDC_SECRET', 'DELEGATION_KEY', 'OWNER_KEY', 'SEMANTIC_KEY', 'OUF_OIDC_DISCOVERY_URL'):
        monkeypatch.setenv(name, canary)
    directories = [tmp_path / 'first', tmp_path / 'second']
    for seed, directory in enumerate(directories):
        monkeypatch.setenv('PYTHONHASHSEED', str(seed))
        subprocess.run([sys.executable, '-m', 'tools.gateway_release_bundle', '--output', str(directory),
                        '--workflow-path', WORKFLOW_PATH, '--run-id', RUN_ID], check=True)
    first, second = directories
    assert {p.name for p in first.iterdir()} == {p.name for p in second.iterdir()} == {
        'manifest.json', 'bundle.json', 'SHA256SUMS'}
    for file in first.iterdir():
        data = file.read_bytes()
        assert data == (second / file.name).read_bytes()
        for forbidden in (canary, 'BEGIN PRIVATE KEY', 'ouf-lab', '$ENV://', '$secret://', 'installation://',
                          'BUNDLE_INPUT_', 'bundle-input-', '127.0.0.1', 'fixture-only'):
            assert forbidden.encode() not in data

    bundle_file = first / 'bundle.json'
    bundle = json.loads(bundle_file.read_bytes())
    assert {entry['name']: entry['type'] for entry in bundle['placeholders']} == {
        'caddy.oidcDiscoveryUrl': 'url',
        'gateway.delegationKeyEnv': 'secret',
        'gateway.issuerUrl': 'url',
        'gateway.oidcClientSecretRef': 'secret',
        'gateway.requiredAudience': 'string',
        'gateway.semanticProposalOwnerKeyEnv': 'secret',
        'gateway.sourceRevisionOwnerKeyEnv': 'secret',
        'iam.workloadClients.mcpServer': 'string',
        'installationId': 'string',
        'revision': 'string',
        'services.bindings.ouf-onboarding': 'string',
        'services.bindings.ouf-semantic-registry': 'string',
        'services.ports.ouf-onboarding': 'string',
        'services.ports.ouf-semantic-registry': 'string',
    }
    for item in bundle['resources']:
        route = item['body']
        oidc = route['plugins']['openid-connect']
        assert oidc['client_secret'] == {'$installation': 'gateway.oidcClientSecretRef'}
        assert oidc['client_id'] == {'$installation': 'gateway.requiredAudience'}
        assert oidc['discovery'] == {'$installation': 'caddy.oidcDiscoveryUrl'}
        assert route['labels']['ouf-delegation-key-env'] == {'$installation': 'gateway.delegationKeyEnv'}
        assert set(route['labels']['ouf-owner-key-env']) == {'$installation'}
        node, = route['upstream']['nodes']
        assert set(node['host']) == set(node['port']) == {'$installation'}

    profile = ci_profile(dict(INSTALL, installationId='portable', revision=2), 18888)
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    routes = load_release_routes(first, commit, WORKFLOW_PATH, RUN_ID, profile)
    expected = {
        'mcp-source-revision-read': 'source.revision/read', 'mcp-source-revision-prepare': 'source.revision/prepare',
        'mcp-semantic-discovery-adopt': 'semantic/discovery/adopt',
        **{'semantic-proposal-' + mode: 'semantic/' + mode for mode in ('create', 'validate', 'review', 'read')},
    }
    assert {r['id']: r['uri'] for r in routes} == {
        key: '/internal/capabilities/v1/execute/' + path for key, path in expected.items()}
    for route in routes:
        assert route['methods'] == ['POST'] and route['upstream']['retries'] == 0
        assert route['upstream']['nodes'] == [{'host': '127.0.0.1', 'port': 18888, 'weight': 1}]
        exercise_release_function(route)

    with pytest.raises(AssertionError):
        load_release_routes(first, '0' * 40, WORKFLOW_PATH, RUN_ID, profile)
    with pytest.raises(AssertionError):
        load_release_routes(first, commit, WORKFLOW_PATH, '0', profile)
    with pytest.raises(KeyError):
        load_release_routes(first, commit, WORKFLOW_PATH, RUN_ID, {})
    manifest_file = first / 'manifest.json'
    manifest_file.write_bytes(manifest_file.read_bytes() + b' ')
    with pytest.raises(AssertionError):
        load_release_routes(first, commit, WORKFLOW_PATH, RUN_ID, profile)


def test_canonical_bytes():
    assert producer.canonical({'z': '\u00e8', 'a': [1, True]}) == b'{"a":[1,true],"z":"\\u00e8"}'
    with pytest.raises(ValueError):
        producer.canonical([float('nan')])


def test_resource_order_and_identity():
    kinds = ('upstreams', 'services', 'plugin_configs', 'plugin_metadata', 'global_rules', 'routes')
    resources = [{'kind': kind, 'id': name, 'body': {}} for kind in kinds for name in ('a', 'z')]
    assert producer.ordered_resources(resources[::-1]) == resources
    with pytest.raises(ValueError, match='duplicate release resource ID'):
        producer.ordered_resources([resources[0], resources[0]])
    with pytest.raises(ValueError, match='unsupported release resource kind'):
        producer.ordered_resources([dict(resources[0], kind='consumers')])
    with pytest.raises(ValueError, match='invalid release resource ID'):
        producer.ordered_resources([dict(resources[0], id='bad/id')])


def test_unsupported_materialized_collection(monkeypatch):
    materialize = producer.semantic_proposals

    def with_ssls(*args, **kwargs):
        return dict(materialize(*args, **kwargs), ssls=[])

    monkeypatch.setattr(producer, 'semantic_proposals', with_ssls)
    with pytest.raises(ValueError, match='unsupported release collections: ssls'):
        producer.release_routes()


@pytest.mark.parametrize('name', ['', '9gateway.issuerUrl', 'gateway/issuer', 'A' * 129])
def test_invalid_placeholder_names(name):
    with pytest.raises(ValueError, match='invalid installation placeholder'):
        list(producer.placeholder_names({'$installation': name}))


def exercise_release_function(route):
    plugins = route['plugins']
    capability = plugins['request-validation']['body_schema']['properties']['CapabilityID']['const']
    if capability.startswith('ouf.onboarding.revision.'):
        dispatch = revision_request(route['uri'].rsplit('/', 1)[1])
        receipt = b'x-ouf-source-revision-receipt'
    else:
        dispatch = proposal_request(capability)
        receipt = b'x-ouf-semantic-proposal-receipt'
    scope = 'ouf.semantic.discovery' if capability == 'ouf.semantic.discovery.adopt' else capability
    headers = {'X-OUF-Delegation': proof(dict(human(), scope='mcp.connect ' + scope)),
               'X-Correlation-ID': dispatch['CorrelationID'], 'Idempotency-Key': dispatch['IdempotencyKey'],
               'X-Tool-Attempt-ID': dispatch['AttemptID']}
    engine = Engine(workload(), headers, dispatch, uri=route['uri'])
    ctx = engine.modules[b'cjson.safe'][b'decode'](json.dumps({'matched_route': {'value': route}}).encode())
    # Task-25d: semantic routes capture the original envelope in the rewrite phase.
    for capture in plugins.get('serverless-pre-function', {}).get('functions', []):
        if 'ouf_semantic_envelope' in capture:
            engine.lua.execute(capture.encode())(None, ctx)
    source, = plugins['serverless-post-function']['functions']
    engine.lua.execute(source.encode())(None, ctx)
    assert engine.headers[receipt] and b'authorization' not in engine.headers
