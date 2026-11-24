"""Offline expectations for the governed R2B release and read-only plan."""
import copy
import json
from collections import defaultdict

import pytest
import yaml

from tests.release_bundle_fixture import BASE_3D69CB4, BASELINE_3D69CB4_IDS, BASELINE_51M_IDS, DISCOVERY_REVIEW_IDS, SEARCH_IDS, canonical_json, sha256
from tools.gateway_release_bundle import ROOT, canonical, digest, generate, ordered_resources, placeholder_names
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
PICKER_IDS = {'mcp-managed-file-handoff', 'mcp-managed-file-handoff-issue'}
TASK_51I_RESOURCES_SHA256 = 'c0beb3b5e2bc2282b7205f30ef586e302cfcfbafe6ef4f1755ed859ed1acaac4'

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


def test_release_additions_preserve_predecessor_resources_and_placeholders(bundle):
    """GW-51J-PARITY / GW-51I-BUNDLE-PARITY / GW-51D3-BASELINE-PARITY."""
    task_51j = [row for row in bundle['resources'] if row['id'] in BASELINE_3D69CB4_IDS - set(SEARCH_IDS)]
    assert len(task_51j) == 29 and sha256(canonical_json(task_51j)) == (
        '9cb3f58933b92bece3c2ed8074f6b04ef21bb4520868a5d4009a2eca4cdba12e')
    predecessor = [row for row in task_51j if row['id'] not in DISCOVERY_REVIEW_IDS]
    assert len(predecessor) == 24 and sha256(canonical_json(predecessor)) == TASK_51I_RESOURCES_SHA256
    retained = [item for item in predecessor if item['id'] not in PICKER_IDS]
    assert sha256(canonical_json(retained)) == TASK_51D2_RESOURCES_SHA256
    retained_names = set(placeholder_names(retained))
    assert sha256(canonical_json([p for p in bundle['placeholders']
                                  if p['name'] in retained_names])) == TASK_51D2_PLACEHOLDERS_SHA256


def test_v3_preserves_baseline_resources_and_placeholders(bundle):
    """GW-60J-01. Pin the 3d69cb4 projection independently of subsequent route families."""
    baseline = [row for row in bundle['resources'] if row['id'] in BASELINE_3D69CB4_IDS]
    assert {row['id'] for row in baseline} == BASELINE_3D69CB4_IDS
    assert sha256(canonical_json(baseline)) == '672d41ca6bd2439c0d1b05e6509a37a58e24a406afc37207da0867168199e9b6'
    assert bundle['resourcesSha256'] == sha256(canonical_json(bundle['resources']))
    names = set(placeholder_names(baseline))
    placeholders = [p for p in bundle['placeholders'] if p['name'] in names]
    assert sha256(canonical_json(placeholders)) == '7970011c8370f3286cabcbf07b87de750391be60c8760c708b7de9e9946b214c'


def test_retired_routes_are_declared_as_v2_metadata(bundle, resources):
    """GW-51D3-RETIRED-METADATA / GW-60J-02. Replacements retain the v2 wire format."""
    legacy_run = '^/api/trusted-human/v1/ingestion/runs/' + '-'.join(
        '[0-9A-Fa-f]{%d}' % size for size in (8, 4, 4, 4, 12))
    replacements = [entry for entry in bundle['retired'] if entry['supersededBy'] is not None]
    assert replacements == [
        {'kind': 'routes', 'id': 'r4a-ingestion-human-run-read',
         'supersededBy': 'trusted-human-ingestion-run-read',
         'vars': [['uri', '~~', legacy_run + '$']]},
        {'kind': 'routes', 'id': 'r4a-ingestion-human-run-resume',
         'supersededBy': 'trusted-human-ingestion-run-resume',
         'vars': [['uri', '~~', legacy_run + '/resume$']]},
    ]
    assert {entry['id'] for entry in bundle['retired']}.isdisjoint(resources)
    assert {entry['supersededBy'] for entry in replacements} <= resources.keys()


def test_obsolete_routes_pin_the_sanitized_export(bundle):
    """GW-60J-03. Each historical ID has its own provenance and exact public match."""
    obsolete = [entry for entry in bundle['retired'] if entry['supersededBy'] is None]
    revisions = {
        'ouf-5708b3900d0f-001': '5708b3900d0f43d89801926d3f9554e110f4481f2a1cb08897cd2ec613dfa570',
        'ouf-6f5155e48422-001': '6f5155e484228d958fd36b2c21b3538608cddc4d8ad2bb16fcacab860f86b01b',
    }
    assert [e['id'] for e in obsolete] == list(revisions)
    assert [e['id'] for e in bundle['retired']] == sorted({e['id'] for e in bundle['retired']})
    for entry in obsolete:
        expected = {
            'kind': 'routes', 'id': entry['id'], 'supersededBy': None,
            'reason': 'Rotta disattivata, duplicata e senza consumatori. Il MCP non chiama questa URI.',
            'match': {
                'uri': '/internal/capabilities/v1/execute/urban.object.related_search', 'methods': ['POST'],
                'uris': None, 'host': None, 'hosts': None, 'vars': None, 'priority': None,
                'remote_addrs': None, 'filter_func': None, 'status': 0,
                'labels': {'ouf_index': '001', 'ouf_managed': 'true', 'ouf_revision': revisions[entry['id']]},
            },
        }
        assert canonical_json(entry) == canonical_json(expected)
    assert bundle['retiredSha256'] == sha256(canonical_json(bundle['retired']))


def test_adopted_route_ids_and_unique_selectors(resources):
    """GW-51D2-ADOPTION."""
    assert set(ADOPTED_ROUTE_IDS.values()) <= resources.keys()
    assert ADOPTED_ROUTE_IDS.keys().isdisjoint(resources)
    for route_id in PICKER_IDS:
        mode = route_id.removeprefix('mcp-managed-file-')
        uri = '/internal/capabilities/v1/execute/managed.file/' + mode
        assert [key for key, body in resources.items() if uri in body.get('uris', [body.get('uri')])] == [route_id]
        assert resources[route_id]['methods'] == ['POST'] and 'vars' not in resources[route_id]

    run_root = '/api/trusted-human/v1/ingestion/runs/'
    run_actions = {f'trusted-human-ingestion-run-{action}': action for action in ('abort', 'resume')}
    run_id_pattern = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
    selectors = defaultdict(list)
    for route_id, body in resources.items():
        methods = set(body.get('methods', []))
        hosts = {host.lower() for host in body.get('hosts', [])}
        # A template host may resolve to any literal host in this static check.
        if isinstance(body.get('host'), str):
            hosts.add(body['host'].lower())
        uris = body['uris'] if 'uris' in body else [body['uri']]
        for uri in sorted(set(uris)):
            for other_id, other_methods, other_hosts in selectors[uri]:
                if methods and other_methods and methods.isdisjoint(other_methods):
                    continue
                if hosts and other_hosts and hosts.isdisjoint(other_hosts):
                    continue
                # These THS routes share a wildcard namespace and match distinct action paths.
                if {route_id, other_id} == {'semantic-human-decision', 'semantic-human-publish'}:
                    assert uri == '/api/trusted-human/v1/semantic-approval-challenges/*'
                    for action in ('decision', 'publish'):
                        assert resources['semantic-human-' + action]['vars'] == [
                            ['uri', '~~', '^' + uri[:-1] + '[0-9a-fA-F-]{36}/' + action + '$']]
                    continue
                assert uri == run_root + '*' and {route_id, other_id} == run_actions.keys(), (
                    f'Overlapping method, URI and host selectors for {route_id} and {other_id}: {uri}')
                for action_id, action in run_actions.items():
                    assert resources[action_id]['vars'] == [['uri', '~~', f'^{run_root}{run_id_pattern}/{action}$']]
            selectors[uri].append((route_id, methods, hosts))


def test_release_resources_match_6ae4886_with_original_ids(bundle):
    """GW-51D2-RESOURCE-PARITY."""
    original_ids = {adopted: original for original, adopted in ADOPTED_ROUTE_IDS.items()}
    retained_ids = BASELINE_3D69CB4_IDS.difference(PICKER_IDS, DISCOVERY_REVIEW_IDS, SEARCH_IDS)
    restored = [dict(item, id=original_ids.get(item['id'], item['id']))
                for item in bundle['resources'] if item['id'] in BASELINE_3D69CB4_IDS
                and item['id'] not in PICKER_IDS | set(DISCOVERY_REVIEW_IDS) | set(SEARCH_IDS)]
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
