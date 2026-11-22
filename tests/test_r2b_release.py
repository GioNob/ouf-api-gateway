"""GW-51D-PLAN. Offline expectations for the governed read-only plan."""
import copy
import json

import pytest
import yaml

from tools.gateway_release_bundle import ROOT, canonical, digest, release_resources
from tools.r2b_limits import limit_count
from tools.materialize_apisix_internal_m2m_routes import MaterializationError, materialize
from tools.apply_installation_projection import apply_projection
from tools.compile_config import compile_config


# Frozen reconstruction, not a snapshot of the installation. Keep the hashes
# independent of the materializer, including selectors, plugins, Lua and nodes.
ASSUMED_SHAPES = {
    'r2b-lake-write': '69bd8bb3beaaac6aff413384e751934022a122fdcf02acda0c0433214e3e3699',
    'r2b-handoff-write': 'fa3ff49ac7f3157e655adea09dd11aac65a924908ce0aa33f18cb690ad1e6c0c',
    'r2b-semantic-reference': 'c71f82fd6e33dc16d51c84953e1da869a7648f87ba417e92d70d5c57501ddcaf',
    'r2b-publication-feed': '42e4680d627154d32fb480f4ae2bc485e4ebb9b5c02c018b01df3c89c023c2bd',
    'r2b-publication-resolution': 'bb8688c9a362dfd88a7bd2c4b6f2b93a482235ada386d5a2956aa37cdc0f8e65',
}
EXPECTED_UPDATE_PATHS = (
    'labels.ouf-installation', 'labels.ouf-installation-revision',
    'plugins.limit-count.count', 'plugins.limit-count.key',
    'plugins.limit-count.show_limit_quota_header', 'plugins.limit-count.time_window',
)


@pytest.fixture(scope='module')
def resources():
    return {item['id']: item['body'] for item in release_resources()}


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
    assert {name for name in resources if name.startswith('r2b-')} == (
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
        limit_count('r2b-lake-write', {'r2bLakeWrite': settings})
