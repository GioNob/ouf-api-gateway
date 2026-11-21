import json
import copy
import subprocess
import sys

import pytest

from tests.release_bundle_fixture import ci_profile, load_release_routes
from tests.test_execute_delegation import Engine, INSTALL, human, proof, workload
from tests.test_semantic_proposals import request as proposal_request
from tests.test_source_revision import request as revision_request
from tests.test_managed_file_mcp import request as file_request
from tests.test_onboarding_review import request as review_request
from tests.test_schema_notices import notice_request, check_notice_execution
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
    check_sprint02_bytes(bundle['resources'])
    placeholder_types = {entry['name']: entry['type'] for entry in bundle['placeholders']}
    assert placeholder_types == {
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
        'services.ports.ouf-onboarding': 'integer',
        'services.ports.ouf-semantic-registry': 'integer',
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
        assert [name for name in producer.placeholder_names(route) if placeholder_types[name] == 'integer'] == [
            node['port']['$installation'],
        ]

    profile = ci_profile(dict(INSTALL, installationId='portable', revision=2), 18888)
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    routes = load_release_routes(first, commit, WORKFLOW_PATH, RUN_ID, profile)
    expected = {
        'mcp-source-revision-read': 'source.revision/read', 'mcp-source-revision-prepare': 'source.revision/prepare',
        'mcp-semantic-discovery-adopt': 'semantic/discovery/adopt',
        'mcp-onboarding-schema-notices-read': 'ouf.onboarding.schema-notices.read',
        **{'mcp-managed-file-' + mode: 'managed.file/' + mode
           for mode in ('profile', 'preview', 'create', 'review-prepare')},
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
    for name, invalid, expected_type in (
        ('services.ports.ouf-onboarding', '18888', 'integer'),
        ('services.ports.ouf-semantic-registry', True, 'integer'),
        ('services.ports.ouf-onboarding', 18888.0, 'integer'),
        ('revision', 2, 'string'),
        ('gateway.issuerUrl', 42, 'string'),
        ('gateway.oidcClientSecretRef', False, 'string'),
    ):
        with pytest.raises(AssertionError) as error:
            load_release_routes(first, commit, WORKFLOW_PATH, RUN_ID, {**profile, name: invalid})
        assert str(error.value) == f'{name}: expected {expected_type}'
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


def check_sprint02_bytes(resources):
    # SHA-256 of the seven canonical resources produced by 80aaea4. Undo only
    # the four allowed changes inside revision.prepare's Arguments schema.
    previous = copy.deepcopy([r for r in resources if not r['id'].startswith('mcp-managed-file-')
                              and r['id'] != 'mcp-onboarding-schema-notices-read'])
    assert len(previous) == 7
    prepare, = [r for r in previous if r['id'] == 'mcp-source-revision-prepare']
    args = prepare['body']['plugins']['request-validation']['body_schema']['properties']['Arguments']
    del args['properties']['unitProfileRef']
    args['if'] = {'required': ['assetRef']}
    args['then'] = {'not': {'required': ['changes']}}
    args['else'] = {'required': ['changes'], 'not': {'required': ['newColumns']}}
    assert producer.digest(producer.canonical(previous)) == '2b40501280d57f34819cf05bdcc398009925b6ad21857f5ebd432a71412c28dd'


def release_request(route):
    mode = route['uri'].rsplit('/', 1)[1]
    if route['id'] == 'mcp-onboarding-schema-notices-read':
        return notice_request(), b'x-ouf-schema-notices-receipt'
    if route['id'].startswith('mcp-source-revision-'):
        return revision_request(mode), b'x-ouf-source-revision-receipt'
    if route['id'].startswith('mcp-managed-file-'):
        dispatch = review_request() if mode == 'review-prepare' else file_request(mode)
        return dispatch, b'x-ouf-managed-file-receipt'
    schema = route['plugins']['request-validation']['body_schema']
    return proposal_request(schema['properties']['CapabilityID']['const']), b'x-ouf-semantic-proposal-receipt'


def exercise_release_function(route):
    plugins = route['plugins']
    dispatch, receipt = release_request(route)
    capability = dispatch['CapabilityID']
    if capability == 'ouf.onboarding.schema-notices.read':
        check_notice_execution(route)
        return
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
