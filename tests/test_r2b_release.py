"""Offline expectations for the governed R2B release and read-only plan."""
import copy
import json
from collections import defaultdict

import pytest
import yaml

from tests.release_bundle_fixture import canonical_json, sha256
from tools.gateway_release_bundle import ROOT, canonical, digest, generate, ordered_resources
from tools.r2b_limits import limit_count
from tools.materialize_apisix_internal_m2m_routes import MaterializationError, materialize
from tools.apply_installation_projection import apply_projection
from tools.compile_config import compile_config


ADOPTED_ROUTE_IDS = {
    'r2b-lake-write': 'r4a-udp-runtime-lake-write',
    'r2b-handoff-write': 'r4a-udp-runtime-handoff-write',
    'r2b-publication-feed': 'r4a-onboarding-runtime-publications-list',
}
# resourcesSha256 emitted by the unmodified 6ae4886 release generator.
BASELINE_RESOURCES_SHA256 = 'e7d669a1552f87c10cbefae3ed5013eb3a368e693fe14963795081760ed7cf30'
# Digests of the canonical arrays emitted by the unmodified 9064a5f release generator.
TASK_51D2_RESOURCES_SHA256 = 'ecb8a08122854dbc54dd7d592ea1ceca33e97a481bb2ab3ffa8cc9e6380cb550'
TASK_51D2_PLACEHOLDERS_SHA256 = '90a9dbc7f6d05d7f26f79a799cd24eac6e38ba50a7e51168db367617d68c5695'

# Frozen reconstruction, not a snapshot of the installation. Keep the hashes
# independent of the materializer, including selectors, plugins, Lua and nodes.
ASSUMED_SHAPES = {
    'r4a-udp-runtime-lake-write': '69bd8bb3beaaac6aff413384e751934022a122fdcf02acda0c0433214e3e3699',
    'r4a-udp-runtime-handoff-write': 'fa3ff49ac7f3157e655adea09dd11aac65a924908ce0aa33f18cb690ad1e6c0c',
    'r2b-semantic-reference': 'c71f82fd6e33dc16d51c84953e1da869a7648f87ba417e92d70d5c57501ddcaf',
    'r4a-onboarding-runtime-publications-list': '42e4680d627154d32fb480f4ae2bc485e4ebb9b5c02c018b01df3c89c023c2bd',
    'r2b-publication-resolution': 'bb8688c9a362dfd88a7bd2c4b6f2b93a482235ada386d5a2956aa37cdc0f8e65',
}
EXPECTED_UPDATE_PATHS = (
    'labels.ouf-installation', 'labels.ouf-installation-revision',
    'plugins.limit-count.count', 'plugins.limit-count.key',
    'plugins.limit-count.show_limit_quota_header', 'plugins.limit-count.time_window',
)


@pytest.fixture(scope='module')
def bundle(tmp_path_factory):
    output = tmp_path_factory.mktemp('r2b-release')
    generate(output, '1' * 40, '.github/workflows/ci.yml', '1')
    return json.loads((output / 'bundle.json').read_bytes())


@pytest.fixture(scope='module')
def resources(bundle):
    return {item['id']: item['body'] for item in bundle['resources']}


def test_release_resources_and_placeholders_match_9064a5f(bundle):
    """GW-51D3-BASELINE-PARITY."""
    assert bundle['resourcesSha256'] == sha256(canonical_json(bundle['resources'])) == TASK_51D2_RESOURCES_SHA256
    assert sha256(canonical_json(bundle['placeholders'])) == TASK_51D2_PLACEHOLDERS_SHA256


def test_retired_routes_are_declared_as_v2_metadata(bundle, resources):
    """GW-51D3-RETIRED-METADATA."""
    legacy_run = '^/api/trusted-human/v1/ingestion/runs/' + '-'.join(
        '[0-9A-Fa-f]{%d}' % size for size in (8, 4, 4, 4, 12))
    assert bundle['retired'] == [
        {'kind': 'routes', 'id': 'r4a-ingestion-human-run-read',
         'supersededBy': 'trusted-human-ingestion-run-read',
         'vars': [['uri', '~~', legacy_run + '$']]},
        {'kind': 'routes', 'id': 'r4a-ingestion-human-run-resume',
         'supersededBy': 'trusted-human-ingestion-run-resume',
         'vars': [['uri', '~~', legacy_run + '/resume$']]},
    ]
    assert {entry['id'] for entry in bundle['retired']}.isdisjoint(resources)
    assert {entry['supersededBy'] for entry in bundle['retired']} <= resources.keys()


def test_adopted_route_ids_and_unique_selectors(resources):
    """GW-51D2-ADOPTION."""
    assert set(ADOPTED_ROUTE_IDS.values()) <= resources.keys()
    assert ADOPTED_ROUTE_IDS.keys().isdisjoint(resources)

    run_root = '/api/trusted-human/v1/ingestion/runs/'
    run_actions = {f'trusted-human-ingestion-run-{action}': action for action in ('abort', 'resume')}
    run_id_pattern = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
    selectors = defaultdict(list)
    for route_id, body in resources.items():
        methods = set(body.get('methods', []))
        hosts = {host.lower() for host in body.get('hosts', [])}
        if 'host' in body:
            hosts.add(body['host'].lower())
        uris = body['uris'] if 'uris' in body else [body['uri']]
        for uri in sorted(set(uris)):
            for other_id, other_methods, other_hosts in selectors[uri]:
                if methods and other_methods and methods.isdisjoint(other_methods):
                    continue
                if hosts and other_hosts and hosts.isdisjoint(other_hosts):
                    continue
                # These THS routes share a wildcard namespace and match distinct action paths.
                assert uri == run_root + '*' and {route_id, other_id} == run_actions.keys(), (
                    f'Overlapping method, URI and host selectors for {route_id} and {other_id}: {uri}')
                for action_id, action in run_actions.items():
                    assert resources[action_id]['vars'] == [['uri', '~~', f'^{run_root}{run_id_pattern}/{action}$']]
            selectors[uri].append((route_id, methods, hosts))


def test_release_resources_match_6ae4886_with_original_ids(bundle):
    """GW-51D2-RESOURCE-PARITY."""
    original_ids = {adopted: original for original, adopted in ADOPTED_ROUTE_IDS.items()}
    restored = [dict(item, id=original_ids.get(item['id'], item['id'])) for item in bundle['resources']]
    assert digest(canonical(ordered_resources(restored))) == BASELINE_RESOURCES_SHA256


@pytest.mark.parametrize('route_id', ASSUMED_SHAPES)
def test_expected_update_paths(resources, route_id):
    shape = copy.deepcopy(resources[route_id])
    for path in EXPECTED_UPDATE_PATHS:
        *parents, leaf = path.split('.')
        node = shape
        for parent in parents:
            node = node[parent]
        value = node.pop(leaf)
        if leaf == 'show_limit_quota_header':
            assert value is True
        else:
            assert set(value) == {'$installation'}
    assert digest(canonical(shape)) == ASSUMED_SHAPES[route_id], (route_id, EXPECTED_UPDATE_PATHS)
    print(json.dumps({'id': route_id, 'action': 'update', 'paths': EXPECTED_UPDATE_PATHS}))


def test_batch_is_one_create_with_same_oidc_and_workload_boundary(resources):
    assert {name for name in resources if name.startswith('r2b-') or name in ADOPTED_ROUTE_IDS.values()} == (
        ASSUMED_SHAPES.keys() | {'r2b-semantic-reference-batch'})
    get = resources['r2b-semantic-reference']
    batch = resources['r2b-semantic-reference-batch']
    assert get['methods'] == ['GET'] and batch['methods'] == ['POST']
    assert get['uri'] + '-batch' == batch['uri'] == batch['plugins']['proxy-rewrite']['uri']
    assert get['labels'] == batch['labels'] and get['upstream'] == batch['upstream']
    for plugin in ('openid-connect', 'serverless-pre-function', 'serverless-post-function'):
        assert get['plugins'][plugin] == batch['plugins'][plugin]
    assert batch['plugins']['openid-connect']['required_scopes'] == ['ouf.semantic.read']
    assert batch['plugins']['client-control'] == {'max_body_size': 256 * 1024}
    print(json.dumps({'id': 'r2b-semantic-reference-batch', 'action': 'create'}))


def test_direct_materialization_requires_explicit_installation_limits():
    profile = json.loads((ROOT / 'tests/fixtures/installation-projection-lab.json').read_bytes())
    runtime = apply_projection(compile_config(ROOT / 'ouf-config'), profile)
    with pytest.raises(MaterializationError, match='project gateway.rateLimits'):
        materialize(runtime, ['r2b-semantic-reference'], '$ENV://TEST')


def test_catalog_and_dev_overlay_cover_every_release_rate_field(resources):
    entries = yaml.safe_load((ROOT / 'config/runtime-catalog-v1.yaml').read_text())['entries']
    dev = yaml.safe_load((ROOT / 'config/development/r2b-rate-limits.yaml').read_text())['gateway']['rateLimits']
    fields = {}
    for route_id in ASSUMED_SHAPES.keys() | {'r2b-semantic-reference-batch'}:
        limits = resources[route_id]['plugins']['limit-count']
        assert limits == limit_count(route_id)
        for field, kind in [('count', 'integer'), ('time_window', 'integer'), ('key', 'string')]:
            name = limits[field]['$installation']
            fields[name] = kind
            assert entries[name]['type'] == kind and entries[name]['default'] is None
        assert limit_count(route_id, dev)['key'] == 'remote_addr'
    assert len(fields) == 15


@pytest.mark.parametrize('field,value', [('count', True), ('count', 0), ('timeWindowSeconds', '60'), ('key', '')])
def test_invalid_projection_limits_fail_closed(field, value):
    settings = {'count': 1, 'timeWindowSeconds': 1, 'key': 'remote_addr', field: value}
    with pytest.raises(ValueError, match='gateway.rateLimits'):
        limit_count('r4a-udp-runtime-lake-write', {'r2bLakeWrite': settings})
