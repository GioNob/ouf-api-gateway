"""Independent consumer of the on-disk artifact in the APISIX CI gate."""
import hashlib
import json
import re

from tests.public_mcp_fixture import public_mcp_profile


# Closed inventory of release 3d69cb4, independent of future families.
BASE_3D69CB4 = frozenset({
    'mcp-ingestion-run-recovery-link',
    'mcp-managed-file-create',
    'mcp-managed-file-handoff',
    'mcp-managed-file-handoff-issue',
    'mcp-managed-file-preview',
    'mcp-managed-file-review-prepare',
    'mcp-managed-file-review-read',
    'mcp-semantic-discovery-adopt',
    'mcp-semantic-discovery-candidates',
    'mcp-semantic-discovery-request',
    'mcp-semantic-discovery-status',
    'mcp-semantic-review-link',
    'mcp-semantic-search',
    'mcp-semantic-search-batch',
    'mcp-source-revision-prepare',
    'r2b-publication-resolution',
    'r2b-semantic-reference',
    'r2b-semantic-reference-batch',
    'r4a-onboarding-runtime-publications-list',
    'r4a-udp-runtime-handoff-write',
    'r4a-udp-runtime-lake-write',
    'semantic-human-terms',
    'semantic-proposal-create',
    'semantic-proposal-read',
    'ths-resolution-package-confirm',
    'ths-resolution-package-read',
    'trusted-human-ingestion-run-abort',
    'trusted-human-ingestion-run-read',
    'trusted-human-ingestion-run-recovery',
    'trusted-human-ingestion-run-resume',
    'trusted-human-resolution-review',
})

R2B_ROUTE_IDS = (
    'r2b-publication-resolution', 'r2b-semantic-reference', 'r2b-semantic-reference-batch',
    'r4a-onboarding-runtime-publications-list', 'r4a-udp-runtime-handoff-write', 'r4a-udp-runtime-lake-write',
)

DISCOVERY_REVIEW_IDS = [
    'mcp-managed-file-review-prepare', 'mcp-semantic-discovery-adopt', 'mcp-semantic-discovery-candidates',
    'mcp-semantic-discovery-request', 'mcp-semantic-discovery-status',
]

SEARCH_IDS = ('mcp-semantic-search', 'mcp-semantic-search-batch')
SEMANTIC_MCP_IDS = ('mcp-semantic-get', 'semantic-proposal-validate', 'semantic-proposal-review')

BASELINE_3D69CB4_IDS = BASE_3D69CB4  # alias kept for the 60b family tests

ONBOARDING_IDS = ('mcp-managed-file-upload', 'mcp-managed-file-profile', 'mcp-source-revision-read',
                  'mcp-permissions-read', 'mcp-permissions-propose', 'mcp-permissions-status',
                  'mcp-authorization-policy-bundle-read')

BASELINE_51M_IDS = BASE_3D69CB4  # alias kept for the 60d family tests

READ_OPERATIONS_IDS = (
    'mcp-generic-execution', 'mcp-ingestion-status', 'execute-ouf-ingestion-acquisition-read',
    'execute-urban-acquisition-read', 'execute-urban-object-search', 'execute-ouf.operations.incidents',
    'execute-ouf.operations.summary', 'execute-ouf.gateway.operations.incidents', 'execute-ouf.gateway.operations.summary',
    'execute-ouf.ingestion.operations.incidents', 'execute-ouf.ingestion.operations.summary',
)
READ_BACKENDS = ('ingestion-acquisition-reader', 'udp-acquisition-reader', 'ouf-mcp-server',
                 'mcp-operational-aggregate', 'ouf-gateway-control-plane')
READ_KEYS = {'gateway.ingestionReadOwnerKeyEnv': 'OWNER_KEY', 'gateway.udpReadOwnerKeyEnv': 'UDP_KEY',
             'gateway.gatewayOperationalOwnerKeyEnv': 'GATEWAY_SUMMARY_RECEIPT_KEY',
             'gateway.ingestionOperationalOwnerKeyEnv': 'INGESTION_SUMMARY_RECEIPT_KEY'}

THS_PAGES_IDS = (
    'trusted-human-onboarding-review', 'trusted-human-semantic-review', 'trusted-human-managed-file-picker',
    'trusted-human-onboarding-approvals-get', 'trusted-human-onboarding-approvals-post',
    'authorization-ths-login', 'authorization-ths-page', 'authorization-ths-api',
    'trusted-human-authorization-get', 'trusted-human-authorization-post',
    'trusted-human-authorization-put', 'trusted-human-authorization-delete',
)

RELEASE_ROUTE_IDS = sorted([
    *ONBOARDING_IDS,
    'mcp-managed-file-create', 'mcp-managed-file-handoff', 'mcp-managed-file-handoff-issue',
    'mcp-managed-file-preview', 'mcp-managed-file-review-read',
    'mcp-source-revision-prepare',
    'public-mcp-endpoint', 'public-mcp-oauth-protected-resource',
    *R2B_ROUTE_IDS, 'semantic-human-terms', 'semantic-proposal-create',
    'semantic-proposal-read', 'ths-resolution-package-confirm', 'ths-resolution-package-read',
    'trusted-human-ingestion-run-abort', 'trusted-human-ingestion-run-read',
    'trusted-human-ingestion-run-recovery', 'trusted-human-ingestion-run-resume',
    'trusted-human-resolution-review', *DISCOVERY_REVIEW_IDS, *SEARCH_IDS, *SEMANTIC_MCP_IDS, *READ_OPERATIONS_IDS,
    *THS_PAGES_IDS,
])
THS_RATE_CLASSES = ('thsApprovals', 'thsAuthorization')

BASE_3D69CB4_IDS = BASE_3D69CB4  # alias kept for the 60h family tests

THS_OWNER_IDS = ('semantic-human-card', 'semantic-human-decision', 'semantic-human-publish',
                 'trusted-human-ingestion-onboarding-readiness', 'ths-identity-preflight-read',
                 'ths-identity-preflight-create')
THS_RECOVERY_IDS = ('r4a-ingestion-human-quarantine-read', 'r4a-ingestion-human-quarantine-retry',
                    'r4a-udp-human-materialization-review', 'r4a-udp-human-materialization-retry')
RELEASE_ROUTE_IDS = sorted({*RELEASE_ROUTE_IDS, *THS_OWNER_IDS, *THS_RECOVERY_IDS})
THS_QUOTAS = ('thsSemantic', 'thsIngestionReadiness', 'thsIdentityPreflight')

RATE_CLASSES = ('r2bLakeWrite', 'r2bHandoffWrite', 'r2bSemanticGet', 'r2bSemanticBatch', 'r2bPublication',
                'semanticSearch', 'semanticSearchBatch')

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
                             'bundleSha256', 'resourcesSha256', 'retiredSha256', 'placeholders'}
    assert set(bundle) == {'schema', 'sourceRepository', 'sourceCommit', 'resources',
                           'placeholders', 'resourcesSha256', 'retired', 'retiredSha256'}
    assert manifest['schema'] == 'ouf.gateway-release-manifest.v3'
    assert bundle['schema'] == 'ouf.gateway-release-bundle.v3'
    assert bundle['sourceRepository'] == manifest['sourceRepository'] == 'GioNob/ouf-api-gateway'
    assert re.fullmatch(r'[0-9a-f]{40}', commit)
    assert bundle['sourceCommit'] == manifest['sourceCommit'] == commit
    assert manifest['workflowPath'] == workflow_path
    assert re.fullmatch(r'\.github/workflows/[^/]+\.yml', workflow_path)
    assert manifest['runId'] == run_id
    assert re.fullmatch(r'[0-9]+', run_id)
    assert manifest['bundleSha256'] == sha256(payload)
    assert isinstance(bundle['retired'], list)
    assert bundle['retiredSha256'] == manifest['retiredSha256'] == sha256(canonical_json(bundle['retired']))
    resources = bundle['resources']
    assert isinstance(resources, list)
    assert {e['id'] for e in bundle['retired']}.isdisjoint(item['id'] for item in resources)
    assert bundle['resourcesSha256'] == manifest['resourcesSha256'] == sha256(canonical_json(resources))
    assert isinstance(bundle['placeholders'], list)
    placeholder_types = {}
    for entry in bundle['placeholders']:
        assert set(entry) == {'name', 'type'}
        assert re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{0,127}', entry['name'])
        assert entry['type'] in {'string', 'url', 'secret', 'integer'}
        placeholder_types[entry['name']] = entry['type']
    used = set()

    def resolve(value):
        if isinstance(value, list):
            return [resolve(item) for item in value]
        if isinstance(value, dict):
            if '$installation' in value:
                assert set(value) == {'$installation'}
                name = value['$installation']
                assert re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{0,127}', name)
                expected_type = placeholder_types[name]
                replacement = profile[name]
                if expected_type == 'integer':
                    assert type(replacement) is int, f'{name}: expected integer'
                else:
                    assert isinstance(replacement, str), f'{name}: expected string'
                used.add(name)
                return replacement
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
        'gateway.rateLimits.semanticMcp.count': 12, 'gateway.rateLimits.semanticMcp.timeWindowSeconds': 60,
        **READ_KEYS, **{'services.bindings.' + name: '127.0.0.1' for name in READ_BACKENDS},
        **{'services.ports.' + name: port for name in READ_BACKENDS},
        'gateway.rateLimits.readOperationsMcp.count': 60, 'gateway.rateLimits.readOperationsMcp.timeWindowSeconds': 60,
        **public_mcp_profile(installation, port),
        'installationId': installation['installationId'], 'revision': str(installation['revision']),
        'iam.workloadClients.semantic': installation.get('semanticServiceIdentity', 'test-semantic'),
        **{f'gateway.rateLimits.{group}.{field}': value for group in ('onboardingMcp', 'authorizationPolicyRead')
           for field, value in [('count', 60), ('timeWindowSeconds', 60)]},
        'gateway.requiredAudience': installation['gatewayAudience'],
        'gateway.publicApiHost': '127.0.0.1',
        'gateway.issuerUrl': installation['issuerUrl'],
        'iam.workloadClients.mcpServer': installation['mcpServiceIdentity'],
        'iam.workloadClients.ingestion': installation.get('ingestionServiceIdentity', 'test-ingestion'),
        'iam.workloadClients.udp': installation.get('udpServiceIdentity', 'test-udp'),
        **{f'gateway.rateLimits.{group}.{field}': value for group in THS_RATE_CLASSES
           for field, value in [('count', 12), ('timeWindowSeconds', 60)]},
        **{f'gateway.rateLimits.{group}.{field}': value for group in RATE_CLASSES
           for field, value in [('count', 12), ('timeWindowSeconds', 60), ('key', 'remote_addr')]},
        **{f'gateway.rateLimits.{group}.{field}': value for group in THS_QUOTAS
           for field, value in [('count', 12), ('timeWindowSeconds', 60)]},
        'gateway.delegationKeyEnv': 'DELEGATION_KEY', 'gateway.sourceRevisionOwnerKeyEnv': 'OWNER_KEY',
        'gateway.semanticProposalOwnerKeyEnv': 'OWNER_KEY', 'gateway.semanticDiscoveryOwnerKeyEnv': 'DISCOVERY_KEY',
        'gateway.semanticReadOwnerKeyEnv': 'READ_KEY',
        'caddy.oidcDiscoveryUrl': f'http://127.0.0.1:{port}/discovery',
        'gateway.oidcClientSecretRef': '$ENV://OIDC_SECRET',
        'services.bindings.ouf-semantic-registry': '127.0.0.1', 'services.ports.ouf-semantic-registry': port,
        'services.bindings.ouf-onboarding': '127.0.0.1', 'services.ports.ouf-onboarding': port,
        'services.bindings.ouf-ingestion-runtime': '127.0.0.1', 'services.ports.ouf-ingestion-runtime': port,
        'services.bindings.ouf-udp-object-resolution': '127.0.0.1', 'services.ports.ouf-udp-object-resolution': port,
    }
