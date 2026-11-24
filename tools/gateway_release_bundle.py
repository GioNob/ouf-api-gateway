"""Generate the D-081 APISIX release from public inputs. Run as a module."""
import argparse
import copy
import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path

from ops.apisix.deploy_semantic_human import validate
from tools.apply_installation_projection import apply_projection
from tools.compile_config import compile_config
from tools.delegation_functions import INSTALLATION_LABELS
from tools.materialize_apisix_internal_m2m_routes import materialize_route as internal_m2m
from tools.r2b_limits import ROUTE_CLASSES
from tools.materialize_managed_file_mcp import materialize as managed_file
from tools.materialize_onboarding_review import RECOVERY_PAGE_ID, RUN_ROUTES, materialize as onboarding_review
from tools.materialize_semantic_discovery import materialize_governed as discovery_routes
from tools.materialize_semantic_read import materialize_governed as search_routes
from tools.materialize_semantic_proposals import add_to_existing as semantic_proposals
from tools.materialize_source_revision import materialize as revision_prepare
from tools.materialize_resolution_ths import UDP, materialize as resolution
from tools.materialize_semantic_human_runtime import materialize
from tools.release_family_ths_owner_api import owner_routes
from tools.apisix_request_schema import verify_dispatch_arguments
from tools.mcp_dispatch_contract import SEARCH_BINDINGS, THS_LINK_ROUTE_KEYS

ROOT = Path(__file__).resolve().parents[1]
BUNDLE_SCHEMA = 'ouf.gateway-release-bundle.v2'
MANIFEST_SCHEMA = 'ouf.gateway-release-manifest.v2'
SOURCE_REPOSITORY = 'GioNob/ouf-api-gateway'
RETIRED_ROUTES_PATH = ROOT / 'ouf-config/release/retired-routes.json'
RESOURCE_KINDS = ('upstreams', 'services', 'plugin_configs', 'plugin_metadata', 'global_rules', 'routes')
RESOURCE_ID = re.compile(r'[A-Za-z0-9._-]{1,64}')
PLACEHOLDER_NAME = re.compile(r'[A-Za-z][A-Za-z0-9_.-]{0,127}')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False).encode('utf-8')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def installation(name):
    return {'$installation': name}


def placeholder_names(value):
    if isinstance(value, dict):
        if '$installation' in value:
            name = value['$installation']
            if set(value) != {'$installation'} or not isinstance(name, str) or not PLACEHOLDER_NAME.fullmatch(name):
                raise ValueError('invalid installation placeholder')
            yield name
        else:
            for child in value.values():
                yield from placeholder_names(child)
    elif isinstance(value, list):
        for child in value:
            yield from placeholder_names(child)


def placeholder_type(name):
    if (name.startswith('services.ports.') or
            name.startswith('gateway.rateLimits.') and name.endswith(('.count', '.timeWindowSeconds'))):
        return 'integer'
    # References and environment bindings for signing keys are sensitive too.
    if 'Secret' in name or 'Key' in name:
        return 'secret'
    if name.endswith('Url'):
        return 'url'
    return 'string'


def release_resources():
    # Exercise the same D-058 projection and materializer guards as a private
    # installation. These build-only inputs must never be distributed.
    clients = {key: 'bundle-input-' + key for key in ('mcpServer', 'semantic', 'ingestion', 'udp')}
    projection = {
        'installationId': 'bundle-input-installation', 'revision': 'bundle-input-revision',
        'checksum': 'bundle-input-checksum', 'iam': {'workloadClients': clients},
        'mcp': {'environment': {'MCP_OIDC_CLIENT_ID': clients['mcpServer']}},
        'gateway': {'issuerUrl': 'https://bundle-input-issuer.invalid',
                    'publicApiBaseUrl': 'https://bundle-input-api.invalid',
                    'requiredAudience': 'bundle-input-audience'},
    }
    runtime = apply_projection(compile_config(ROOT / 'ouf-config'), projection)
    secret_ref = '$ENV://BUNDLE_INPUT_OIDC'
    routes = validate(materialize(runtime, secret_ref))
    terms, = (r for r in routes if r['id'] == 'semantic-human-terms')
    resources = [route_resource(terms, 'ouf-semantic-registry')]
    bindings = {route['id']: route for route in runtime['routes']}
    for route_id in ROUTE_CLASSES:
        binding = bindings[route_id]
        route = internal_m2m(binding, runtime['x-ouf-installation'], secret_ref, release_template=True)
        for role in ('ingestion', 'udp'):
            label = f'ouf-{role}-workload'
            if label in route['labels']:
                route['labels'][label] = installation(f'iam.workloadClients.{role}')
        route['plugins']['openid-connect']['claim_validator']['issuer'] = {
            'valid_issuers': [installation('gateway.issuerUrl')]}
        resources.append(route_resource(route, binding['x-ouf-backend-binding']['service']))
    for route in resolution(runtime, secret_ref):
        service = 'ouf-onboarding' if route['id'] == 'trusted-human-resolution-review' else UDP
        resources.append(route_resource(route, service))
    delegation = 'BUNDLE_INPUT_DELEGATION'
    onboarding = 'BUNDLE_INPUT_ONBOARDING'
    managed = managed_file(runtime, secret_ref, delegation, onboarding, use_route_labels=True)
    reviewed = onboarding_review(managed, runtime, delegation, onboarding, use_route_labels=True)
    for route, service in owner_routes(runtime, secret_ref, routes, reviewed['routes']):
        resources.append(route_resource(route, service))
    for route in reviewed['routes']:
        if route['id'] == RECOVERY_PAGE_ID:
            resources.append(route_resource(route, 'ouf-onboarding'))
        elif route['id'] in RUN_ROUTES:
            resources.append(route_resource(route, 'ouf-ingestion-runtime'))
    revisions = revision_prepare(reviewed, runtime, delegation, onboarding, use_route_labels=True)
    mediated = semantic_proposals(revisions, runtime, delegation, 'BUNDLE_INPUT_SEMANTIC', use_route_labels=True)
    discovery = discovery_routes(mediated, runtime, delegation, 'BUNDLE_INPUT_DISCOVERY', 'BUNDLE_INPUT_SEMANTIC')
    mediated['routes'].extend(discovery)
    mediated['routes'].extend(search_routes(mediated, runtime, delegation, 'BUNDLE_INPUT_READ'))
    dispatch_bindings = {
        **{key: ('ouf-semantic-registry', 'gateway.semanticReadOwnerKeyEnv') for key in SEARCH_BINDINGS},
        'mcp-semantic-discovery-request': ('ouf-semantic-registry', 'gateway.semanticDiscoveryOwnerKeyEnv'),
        'mcp-semantic-discovery-status': ('ouf-semantic-registry', 'gateway.semanticDiscoveryOwnerKeyEnv'),
        'mcp-semantic-discovery-candidates': ('ouf-semantic-registry', 'gateway.semanticDiscoveryOwnerKeyEnv'),
        'mcp-semantic-discovery-adopt': ('ouf-semantic-registry', 'gateway.semanticProposalOwnerKeyEnv'),
        'mcp-managed-file-review-prepare': ('ouf-onboarding', 'gateway.sourceRevisionOwnerKeyEnv'),
        'semantic-proposal-create': ('ouf-semantic-registry', 'gateway.semanticProposalOwnerKeyEnv'),
        'semantic-proposal-read': ('ouf-semantic-registry', 'gateway.semanticProposalOwnerKeyEnv'),
        'mcp-managed-file-create': ('ouf-onboarding', 'gateway.sourceRevisionOwnerKeyEnv'),
        'mcp-managed-file-handoff': ('ouf-onboarding', 'gateway.sourceRevisionOwnerKeyEnv'),
        'mcp-managed-file-handoff-issue': ('ouf-onboarding', 'gateway.sourceRevisionOwnerKeyEnv'),
        'mcp-managed-file-preview': ('ouf-onboarding', 'gateway.sourceRevisionOwnerKeyEnv'),
        'mcp-managed-file-review-read': ('ouf-onboarding', 'gateway.sourceRevisionOwnerKeyEnv'),
        'mcp-source-revision-prepare': ('ouf-onboarding', 'gateway.sourceRevisionOwnerKeyEnv'),
    }
    dispatch_bindings.update({route['id']: ('ouf-onboarding', 'gateway.sourceRevisionOwnerKeyEnv')
                              for route in mediated['routes'] if route['id'] in THS_LINK_ROUTE_KEYS})
    for route_id, (service, owner_env) in dispatch_bindings.items():
        route, = (r for r in mediated['routes'] if r.get('id') == route_id)
        # A full HTTPS issuer contains ":" and cannot be stored in an APISIX label.
        # Bind OIDC and the delegated request check to the same projected issuer.
        route['plugins']['openid-connect']['claim_validator']['issuer'] = {
            'valid_issuers': [installation('gateway.issuerUrl')],
        }
        settings = {'AUDIENCE': 'gateway.requiredAudience',
                    'MCP_WORKLOAD': 'iam.workloadClients.mcpServer',
                    'DELEGATION_KEY_ENV': 'gateway.delegationKeyEnv', 'OWNER_KEY_ENV': owner_env}
        route['labels'].update({label: installation(settings[key]) for key, label in INSTALLATION_LABELS.items()})
        resources.append(route_resource(route, service))
    return resources


def route_resource(route, service):
    route = copy.deepcopy(route)
    route_id = route.pop('id')
    nodes = route['upstream']['nodes']
    # Keep APISIX's weight and the binding checked by the materializer. Array
    # notation makes host and port separately substitutable JSON values.
    address, = nodes
    host, _, port = address.rpartition(':')
    if host != service or not port.isdigit():
        raise ValueError('unexpected materialized backend for ' + route_id)
    route['upstream']['nodes'] = [{'host': installation('services.bindings.' + service),
                                  'port': installation('services.ports.' + service), 'weight': nodes[address]}]
    if 'openid-connect' in route['plugins']:
        route['plugins']['openid-connect'].update(client_id=installation('gateway.requiredAudience'),
                                                  client_secret=installation('gateway.oidcClientSecretRef'),
                                                  discovery=installation('caddy.oidcDiscoveryUrl'))
    labels = route['labels']
    labels['ouf-installation'] = installation('installationId')
    if 'ouf-installation-revision' in labels:
        labels['ouf-installation-revision'] = installation('revision')
    return {'kind': 'routes', 'id': route_id, 'body': route}


def ordered_resources(resources):
    seen = set()
    for item in resources:
        kind, resource_id = item['kind'], item['id']
        if kind not in RESOURCE_KINDS:
            raise ValueError('unsupported release resource kind: ' + kind)
        if not isinstance(resource_id, str) or not RESOURCE_ID.fullmatch(resource_id):
            raise ValueError('invalid release resource ID')
        if (kind, resource_id) in seen:
            raise ValueError('duplicate release resource ID: ' + kind + '/' + resource_id)
        seen.add((kind, resource_id))
    return sorted(resources, key=lambda item: (RESOURCE_KINDS.index(item['kind']), item['id']))


def load_retired_routes(path, resources):
    try:
        entries = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f'{path}: cannot read retired routes: {exc}') from exc
    if not isinstance(entries, list):
        raise ValueError(f'{path}: expected a list of retired routes')

    resource_ids = {item['id'] for item in resources}
    route_ids = {item['id'] for item in resources if item['kind'] == 'routes'}
    retired = []
    seen = set()
    for index, entry in enumerate(entries):
        location = f'{path}: retired[{index}]'
        if not isinstance(entry, dict) or set(entry) != {'kind', 'id', 'supersededBy', 'vars', 'reason'}:
            raise ValueError(f'{location}: expected kind, id, supersededBy, vars and reason')
        if entry['kind'] != 'routes':
            raise ValueError(f'{location}: kind must be routes')
        resource_id = entry['id']
        if not isinstance(resource_id, str) or not RESOURCE_ID.fullmatch(resource_id):
            raise ValueError(f'{location}: invalid retired route ID')
        if resource_id in seen:
            raise ValueError(f'{location}: duplicate retired route ID: {resource_id}')
        if retired and resource_id < retired[-1]['id']:
            raise ValueError(f'{location}: retired routes must be sorted by ID')
        if resource_id in resource_ids:
            raise ValueError(f'{location}: retired route ID already in resources: {resource_id}')
        replacement = entry['supersededBy']
        if not isinstance(replacement, str) or replacement not in route_ids:
            raise ValueError(f'{location}: supersededBy must identify a routes resource in the bundle')
        if not isinstance(entry['reason'], str) or not entry['reason'].strip():
            raise ValueError(f'{location}: reason must be a non-empty string')
        route_vars = entry['vars']
        # The executor deletes only a live route whose vars equal these literal APISIX conditions.
        if (not isinstance(route_vars, list) or not route_vars
                or not all(isinstance(c, list) and c and all(isinstance(x, str) for x in c) for c in route_vars)):
            raise ValueError(f'{location}: vars must be a non-empty list of APISIX string conditions')
        seen.add(resource_id)
        retired.append({'kind': 'routes', 'id': resource_id, 'supersededBy': replacement, 'vars': route_vars})
    return retired


def generate(output, source_commit, workflow_path, run_id):
    if not re.fullmatch(r'[0-9a-f]{40}', source_commit):
        raise ValueError('expected full Git commit SHA')
    if not re.fullmatch(r'\.github/workflows/[^/\\\r\n]+\.yml', workflow_path):
        raise ValueError('expected workflow path .github/workflows/<file>.yml')
    if not re.fullmatch(r'[0-9]+', run_id):
        raise ValueError('expected numeric workflow run ID')
    resources = ordered_resources(release_resources())
    verify_dispatch_arguments(resources)
    encoded = canonical(resources)
    if b'bundle-input-' in encoded or b'BUNDLE_INPUT_' in encoded or b'installation://' in encoded:
        raise ValueError('unconverted installation input')
    names = sorted(set(placeholder_names(resources)))
    resources_sha256 = digest(encoded)
    retired = load_retired_routes(RETIRED_ROUTES_PATH, resources)
    retired_sha256 = digest(canonical(retired))
    source = {'sourceRepository': SOURCE_REPOSITORY, 'sourceCommit': source_commit}
    bundle = {'schema': BUNDLE_SCHEMA, **source, 'resources': resources, 'resourcesSha256': resources_sha256,
              'retired': retired, 'retiredSha256': retired_sha256,
              'placeholders': [{'name': name, 'type': placeholder_type(name)} for name in names]}
    payload = canonical(bundle)
    manifest = {'schema': MANIFEST_SCHEMA, **source, 'workflowPath': workflow_path, 'runId': run_id,
                'bundleSha256': digest(payload), 'resourcesSha256': resources_sha256, 'retiredSha256': retired_sha256,
                'placeholders': names}
    manifest_payload = canonical(manifest)
    sums = (f"{manifest['bundleSha256']}  bundle.json\n"
            f"{digest(manifest_payload)}  manifest.json\n").encode('ascii')
    # Install the checksums last so validation detects an interrupted replacement.
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=output) as staging:
        for name, content in [('bundle.json', payload), ('manifest.json', manifest_payload), ('SHA256SUMS', sums)]:
            staged = Path(staging) / name
            staged.write_bytes(content)
            staged.replace(output / name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--workflow-path', required=True)
    parser.add_argument('--run-id', required=True)
    args = parser.parse_args()
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    generate(args.output, commit, args.workflow_path, args.run_id)


if __name__ == '__main__':
    main()
