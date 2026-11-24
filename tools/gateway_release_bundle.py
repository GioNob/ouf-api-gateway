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
from tools.materialize_managed_file_mcp import materialize as managed_file
from tools.materialize_onboarding_review import RECOVERY_PAGE_ID, RUN_ROUTES, materialize as onboarding_review
from tools.materialize_semantic_proposals import add_to_existing as semantic_proposals
from tools.materialize_source_revision import materialize as revision_prepare
from tools.materialize_resolution_ths import UDP, materialize as resolution
from tools.materialize_semantic_human_runtime import materialize
from tools.mcp_dispatch_contract import THS_LINK_ROUTE_KEYS

ROOT = Path(__file__).resolve().parents[1]
BUNDLE_SCHEMA = 'ouf.gateway-release-bundle.v1'
MANIFEST_SCHEMA = 'ouf.gateway-release-manifest.v1'
SOURCE_REPOSITORY = 'GioNob/ouf-api-gateway'
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
    if name.startswith('services.ports.'):
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
    for route in resolution(runtime, secret_ref):
        service = 'ouf-onboarding' if route['id'] == 'trusted-human-resolution-review' else UDP
        resources.append(route_resource(route, service))
    delegation = 'BUNDLE_INPUT_DELEGATION'
    onboarding = 'BUNDLE_INPUT_ONBOARDING'
    managed = managed_file(runtime, secret_ref, delegation, onboarding, use_route_labels=True)
    reviewed = onboarding_review(managed, runtime, delegation, onboarding, use_route_labels=True)
    for route in reviewed['routes']:
        if route['id'] == RECOVERY_PAGE_ID:
            resources.append(route_resource(route, 'ouf-onboarding'))
        elif route['id'] in RUN_ROUTES:
            resources.append(route_resource(route, 'ouf-ingestion-runtime'))
    revisions = revision_prepare(reviewed, runtime, delegation, onboarding, use_route_labels=True)
    mediated = semantic_proposals(revisions, runtime, delegation, 'BUNDLE_INPUT_SEMANTIC', use_route_labels=True)
    dispatch_bindings = {
        'semantic-proposal-create': ('ouf-semantic-registry', 'gateway.semanticProposalOwnerKeyEnv'),
        'semantic-proposal-read': ('ouf-semantic-registry', 'gateway.semanticProposalOwnerKeyEnv'),
        'mcp-managed-file-create': ('ouf-onboarding', 'gateway.sourceRevisionOwnerKeyEnv'),
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


def generate(output, source_commit, workflow_path, run_id):
    if not re.fullmatch(r'[0-9a-f]{40}', source_commit):
        raise ValueError('expected full Git commit SHA')
    if not re.fullmatch(r'\.github/workflows/[^/\\\r\n]+\.yml', workflow_path):
        raise ValueError('expected workflow path .github/workflows/<file>.yml')
    if not re.fullmatch(r'[0-9]+', run_id):
        raise ValueError('expected numeric workflow run ID')
    resources = ordered_resources(release_resources())
    encoded = canonical(resources)
    if b'bundle-input-' in encoded or b'BUNDLE_INPUT_' in encoded or b'installation://' in encoded:
        raise ValueError('unconverted installation input')
    names = sorted(set(placeholder_names(resources)))
    resources_sha256 = digest(encoded)
    source = {'sourceRepository': SOURCE_REPOSITORY, 'sourceCommit': source_commit}
    bundle = {'schema': BUNDLE_SCHEMA, **source, 'resources': resources, 'resourcesSha256': resources_sha256,
              'placeholders': [{'name': name, 'type': placeholder_type(name)} for name in names]}
    payload = canonical(bundle)
    manifest = {'schema': MANIFEST_SCHEMA, **source, 'workflowPath': workflow_path, 'runId': run_id,
                'bundleSha256': digest(payload), 'resourcesSha256': resources_sha256, 'placeholders': names}
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
