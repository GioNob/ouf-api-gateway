"""Materialize the delegated HUMAN schema notice read on the same Onboarding backend."""
import copy
import json
from pathlib import Path

from tools.delegation_functions import function
from tools.materialize_operational_execute import operational_host

CAPABILITY = 'ouf.onboarding.schema-notices.read'
ROUTE_ID = 'mcp-onboarding-schema-notices-read'
PATH = '/api/onboarding/v1/schema-notices'
SCHEMA = Path(__file__).resolve().parents[1] / 'schemas/mcp-gateway-schema-notices-read-dispatch-v1.json'


def materialize(runtime, revision_read, delegation_key_env, owner_key_env):
    installation = runtime['x-ouf-installation']
    binding, = [r for r in runtime['routes'] if r['id'] == ROUTE_ID]
    uri = '/internal/capabilities/v1/execute/' + CAPABILITY
    capability, policy = binding['x-ouf-capability'], binding['x-ouf-policy']
    host = operational_host(installation, binding, 'ouf-onboarding')
    backend = binding['x-ouf-backend-binding']
    port = backend['port']
    if (binding['uri'] != uri or binding['methods'] != ['POST']
            or binding['service_id'] != 'ouf-onboarding' or backend['path'] != PATH
            or binding['plugins']['proxy-rewrite']['uri'] != PATH
            or type(port) is not int or not 1 <= port <= 65535
            or revision_read['id'] != 'mcp-source-revision-read'
            or revision_read['upstream']['nodes'] != {f'{host}:{port}': 1}
            or capability['capabilityId'] != CAPABILITY or capability['owner'] != 'onboarding'
            or capability['operationType'] != 'READ' or not capability['toolEligible'] or capability['humanRequired']
            or policy['identity'] != 'M2M' or policy['requiredScope'] != CAPABILITY
            or policy['allowedActorTypes'] != ['HUMAN']
            or policy['allowedServiceIdentities'] != [installation['mcpServiceIdentity']]
            or policy['maxRequestBytes'] != 65536 or policy['timeoutSeconds'] != 3):
        raise ValueError('schema notice binding mismatch')
    route = copy.deepcopy(revision_read)
    route.update(id=ROUTE_ID, uri=uri)
    route['labels']['ouf-mediation'] = 'schema-notices-v1'
    plugins = route['plugins']
    plugins['request-validation']['body_schema'] = json.loads(SCHEMA.read_text())
    # The access function issues the bounded GET itself and only releases a complete page.
    del plugins['proxy-rewrite']
    plugins['serverless-post-function']['functions'] = [
        function('execute_schema_notices', installation, delegation_key_env, owner_key_env, use_route_labels=True)]
    return route
