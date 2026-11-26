"""D-087 public MCP ingress and RFC 9728 metadata, using the execute ingress chain."""
import copy

from tools.delegation_functions import INSTALLATION_LABELS, function
from tools.materialize_apisix_runtime import PROTECTED_RESOURCE_ROUTE_ID, oauth_response_values, require_text


ENDPOINT_ID = 'public-mcp-endpoint'
PUBLIC_IDS = (ENDPOINT_ID, PROTECTED_RESOURCE_ROUTE_ID)
CHALLENGE = 'gateway.publicMcpChallenge'
METADATA = 'gateway.publicMcpMetadataJson'


def oauth_profile_values(settings, policy):
    """Derive both complete v2 string values from the projected URLs and MCP binding policy."""
    challenge, metadata = oauth_response_values(settings, require_text(policy, 'requiredScope'))
    return {CHALLENGE: challenge, METADATA: metadata}


def public_mcp_resources(materialized, settings, installation, route_resource):
    ingress, = (r for r in materialized['routes'] if r['id'] == ENDPOINT_ID)
    metadata, = (r for r in materialized['routes'] if r['id'] == PROTECTED_RESOURCE_ROUTE_ID)
    endpoint = route_resource(ingress, 'ouf-mcp-server')
    body = endpoint['body']
    plugins = body['plugins']
    plugins['openid-connect']['claim_validator']['issuer'] = {'valid_issuers': [installation('gateway.issuerUrl')]}
    plugins['response-rewrite']['headers']['set']['WWW-Authenticate'] = installation(CHALLENGE)
    access = plugins['serverless-post-function']
    key_env = materialized['delegationKeyEnv']
    if access['phase'] != 'access' or access['functions'][:1] != [function('issue_delegation', settings, key_env)]:
        raise ValueError('public MCP delegation must precede identity projection in access')
    access['functions'][0] = function('issue_delegation', settings, key_env, use_route_labels=True)
    body['labels'].update({
        INSTALLATION_LABELS['AUDIENCE']: installation('gateway.requiredAudience'),
        INSTALLATION_LABELS['MCP_WORKLOAD']: installation('iam.workloadClients.mcpServer'),
        INSTALLATION_LABELS['DELEGATION_KEY_ENV']: installation('gateway.delegationKeyEnv'),
    })

    metadata = copy.deepcopy(metadata)
    metadata_id = metadata.pop('id')
    metadata['labels'].update({'ouf-installation': installation('installationId'),
                               'ouf-installation-revision': installation('revision')})
    metadata['plugins']['mocking']['response_example'] = installation(METADATA)
    for route, group in ((body, 'publicMcp'), (metadata, 'publicMcpMetadata')):
        route.update(priority=0, status=1)
        route['labels']['ouf-exposure'] = 'public'
        limits = route['plugins']['limit-count']
        limits['count'] = installation(f'gateway.rateLimits.{group}.count')
        limits['time_window'] = installation(f'gateway.rateLimits.{group}.timeWindowSeconds')
    return [endpoint, {'kind': 'routes', 'id': metadata_id, 'body': metadata}]
