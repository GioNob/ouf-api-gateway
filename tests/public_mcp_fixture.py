"""Synthetic profile for the public protocol and frozen predecessor inventory."""
import json
from pathlib import Path

import yaml

from tools.release_family_public_mcp import oauth_profile_values


LEGACY_METADATA_PROBE = '/fixture/legacy-oauth-document'

BASELINE_3D69CB4_IDS = frozenset({
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


def public_mcp_profile(installation, port):
    settings = {'publicApiBaseUrl': 'https://public.invalid', **installation}
    source = Path(__file__).resolve().parents[1] / 'ouf-config/protocol/mcp-endpoint.yaml'
    binding = yaml.safe_load(source.read_bytes())
    return {
        **oauth_profile_values(settings, binding['spec']['policy']),
        'services.bindings.ouf-mcp-server': '127.0.0.1',
        'services.ports.ouf-mcp-server': port,
        'gateway.rateLimits.publicMcp.count': 60,
        'gateway.rateLimits.publicMcp.timeWindowSeconds': 60,
        'gateway.rateLimits.publicMcpMetadata.count': 120,
        'gateway.rateLimits.publicMcpMetadata.timeWindowSeconds': 60,
    }


def check_public_mcp_http(request, token, installation):
    """GW-60e-06. Observe the resolved artifact on a real APISIX 3.18 data plane."""
    path = '/.well-known/oauth-protected-resource'
    origin = installation['publicApiBaseUrl'].rstrip('/')
    expected = {'authorization_servers': [installation['issuerUrl'].rstrip('/')],
                'bearer_methods_supported': ['header'], 'resource': origin + '/mcp',
                'resource_name': 'OUF MCP Server', 'scopes_supported': ['mcp.connect']}
    status, raw, headers = request('GET', path, with_headers=True)
    legacy_status, legacy_raw = request('GET', LEGACY_METADATA_PROBE)
    assert status == legacy_status == 200 and raw == legacy_raw
    assert json.loads(raw) == expected
    assert headers['Cache-Control'] == 'public, max-age=300' and headers['X-Content-Type-Options'] == 'nosniff'
    status, _, headers = request('POST', '/mcp', {}, with_headers=True)
    assert status == 401 and headers['WWW-Authenticate'] == f'Bearer resource_metadata="{origin}{path}", scope="mcp.connect"'
    call = {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list'}
    assert request('POST', '/mcp', call, token(scope='other.scope'))[0] == 403
    assert request('POST', '/mcp', b'"scalar"', token())[0] == 400
    for body in (call, [call]):
        status, raw, headers = request('POST', '/mcp', body, token(), 'forged', with_headers=True)
        assert status == 200 and headers['X-Correlation-ID'] == 'corr'
        forwarded = json.loads(raw)
        assert forwarded['request'] == body and forwarded['principal'] == 'human-a'
        assert forwarded['proof'] and forwarded['proof'] != 'forged'
        assert forwarded['roles'] is None and forwarded['tokenHeaders'] == []
