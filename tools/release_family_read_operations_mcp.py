"""Adopt the installed read selectors and their owner-specific mediation."""
import copy
import json

from tools.delegation_functions import ROOT as LUA, operational_source
from tools.materialize_operational_execute import CAPABILITIES, dispatch_schema
from tools.mcp_dispatch_contract import EXECUTE_PATH, capability_contracts, envelope_refs

SNAPSHOT = LUA.parents[1] / 'contracts/mcp-read_operations_mcp-capabilities.json'
STATUS = 'ouf.system.status'
INGESTION = 'ouf.ingestion.status'
HISTORY = 'ouf.ingestion.history'
SEARCH = 'urban.object.search'
ACQUISITIONS = {
    'ouf.ingestion.acquisition.read': ('ingestion', 'afterLineageId', 'ingestion.contract.read ingestion.lineage.read ingestion.run.read',
                                       'ingestion-read-owner', 'X-OUF-Ingestion-Read-Receipt'),
    'urban.acquisition.read': ('udp', 'afterHandoffId', 'lineage.object.read lineage.property.read urban.object.read',
                               'udp-acquisition-owner', 'X-OUF-UDP-Acquisition-Receipt'),
}
ROUTES = {
    'mcp-generic-execution': STATUS,
    'mcp-ingestion-status': INGESTION,
    # DN-L3-3: adopted from the MCP manifest aligned to the owner limit (100).
    'mcp-ingestion-history': HISTORY,
    'execute-urban-object-search': SEARCH,
    'execute-ouf-ingestion-acquisition-read': 'ouf.ingestion.acquisition.read',
    'execute-urban-acquisition-read': 'urban.acquisition.read',
    **{'execute-' + cap: cap for cap in (
        'ouf.operations.summary', 'ouf.operations.incidents', 'ouf.ingestion.operations.summary',
        'ouf.ingestion.operations.incidents', 'ouf.gateway.operations.summary', 'ouf.gateway.operations.incidents',
    )},
}
PRODUCERS = {cap for cap, spec in CAPABILITIES.items() if spec[0] != 'mcp'}
NONZERO_UUID = r'^(?!00000000-0000-0000-0000-000000000000$)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'


def declarations():
    rows = json.loads(SNAPSHOT.read_bytes())['capabilities']
    result = {row['capabilityId']: row for row in rows}
    expected = set(ROUTES.values()) - PRODUCERS | {'ouf.ingestion.history', 'ouf.operations.explain', 'urban.object.related_search'}
    if len(result) != len(rows) or result.keys() != expected:
        raise ValueError('incomplete read operations MCP snapshot')
    return result


def arguments(capability):
    if capability in PRODUCERS:
        if capability in capability_contracts():
            raise ValueError('producer acquired a tool declaration; review the owner contract: ' + capability)
        return dispatch_schema(capability)['properties']['Arguments']
    schema = declarations()[capability]['inputSchema']
    fields = schema['properties']
    if capability in ACQUISITIONS:
        for value in fields.values():
            if value.get('format') == 'uuid':
                value['pattern'] = NONZERO_UUID
    elif capability == SEARCH:
        fields['type']['pattern'] = r'^[^*%\x00-\x1f]+$'
    elif capability in ('ouf.operations.summary', HISTORY):
        # Same bounded timestamp accepted by the deployed producer facade and the installed history route.
        fields['since'].update(pattern=r'^.+T.+(Z|[+-][0-9]{2}:[0-9]{2})$', maxLength=100)
    return envelope_refs(schema)


def mediation(cap, owner, path, scope):
    constants = {}
    owner_key = None
    if cap in CAPABILITIES:
        profile = 'summary-execute-v1'
        constants.update(CAPABILITY=cap, OWNER=owner, REQUIRED_SCOPE=scope)
        if cap in PRODUCERS:
            owner_key = f'gateway.{owner}OperationalOwnerKeyEnv'
        source = operational_source(cap in PRODUCERS)
    elif cap in ACQUISITIONS:
        profile = 'acquisition-evidence-read-v1'
        _, cursor, scopes, purpose, header = ACQUISITIONS[cap]
        constants.update(CAPABILITY=cap, OWNER=owner, OWNER_PATH=path, REQUIRED_SCOPES=scopes,
                         CURSOR_FIELD=cursor, RECEIPT_PURPOSE=purpose,
                         RECEIPT_DOMAIN=f'ouf-{purpose}-v1.', RECEIPT_HEADER=header)
        owner_key = f'gateway.{owner}ReadOwnerKeyEnv'
        source = (LUA / 'execute_acquisition_read.lua').read_text()
    elif cap in (INGESTION, HISTORY):
        profile = 'ingestion-read-owner-receipt-v1'
        owner_key = 'gateway.ingestionReadOwnerKeyEnv'
        constants.update(CAPABILITY=cap, OWNER=owner, REQUIRED_SCOPE=scope)
        source = (LUA / 'execute_ingestion_read.lua').read_text()
    elif cap == SEARCH:
        profile = 'udp-search-execute-v1'
        owner_key = 'gateway.udpReadOwnerKeyEnv'
        source = (LUA / 'execute_object_search.lua').read_text()
    else:
        profile = 'status-execute-v1'
        source = (LUA / 'execute_status.lua').read_text()
    lines = ['return function(conf, ctx)', 'local route = ctx.matched_route.value',
             'local labels = route.labels',
             "local issuers = route.plugins['openid-connect'].claim_validator.issuer.valid_issuers",
             'local ISSUER = issuers and #issuers == 1 and issuers[1]',
             "local DELEGATION_KEY_ENV = labels['ouf-delegation-key-env']",
             "local AUDIENCE = labels['ouf-audience']", "local MCP_WORKLOAD = labels['ouf-mcp-workload']",
             'if not ISSUER or not AUDIENCE or not MCP_WORKLOAD or not DELEGATION_KEY_ENV then return ngx.exit(503) end']
    if owner_key:
        key = 'RECEIPT_KEY_ENV' if cap in PRODUCERS else 'OWNER_KEY_ENV'
        lines += [f"local {key} = labels['ouf-owner-key-env']",
                  f'if not {key} or {key} == DELEGATION_KEY_ENV then return ngx.exit(503) end']
    lines.extend(f'local {key} = {json.dumps(value)}' for key, value in constants.items())
    lines.extend([(LUA / 'delegation.lua').read_text(), source, 'end'])
    return profile, owner_key, '\n'.join(lines)


def materialize(runtime, generic, route_resource, installation):
    from tools.apisix_request_schema import dispatch_validation

    resources = []
    manifest = declarations()
    for route_id, cap in ROUTES.items():
        uri = EXECUTE_PATH if cap == STATUS else EXECUTE_PATH + '/' + cap
        binding, = (r for r in runtime['routes'] if r.get('labels', {}).get('exposure') == 'internal'
                    and (r.get('x-ouf-capability') or {}).get('capabilityId') == cap)
        contract, policy = binding['x-ouf-capability'], binding['x-ouf-policy']
        owner, operation = contract['owner'], contract['operationType']
        service = binding['service_id']
        path = binding['plugins']['proxy-rewrite']['uri']
        scope, timeout = policy['requiredScope'], policy['timeoutSeconds']
        if cap in CAPABILITIES:
            expected_owner, expected_service, _, expected_path, expected_scope, expected_timeout = CAPABILITIES[cap]
        elif cap in ACQUISITIONS:
            expected_owner = ACQUISITIONS[cap][0]
            expected_service = expected_owner + '-acquisition-reader'
            expected_path = ('/api/udp/v1/operations/acquisition' if expected_owner == 'udp'
                             else '/api/internal/v1/ingestion/operations/acquisition')
            expected_scope, expected_timeout = manifest[cap]['requiredAuthorizationCapability'], 12
        else:
            expected_owner, expected_service, expected_path = {
                STATUS: ('mcp', 'ouf-mcp-server', '/api/internal/v1/mcp/operations/status'),
                INGESTION: ('ingestion', 'ouf-ingestion-runtime', '/api/internal/v1/ingestion/operations/status'),
                HISTORY: ('ingestion', 'ouf-ingestion-runtime', '/api/internal/v1/ingestion/operations/history'),
                SEARCH: ('udp', 'ouf-udp-object-resolution', '/api/udp/v1/objects/search'),
            }[cap]
            expected_scope, expected_timeout = manifest[cap]['requiredAuthorizationCapability'], 3
        actors = (['HUMAN', 'HUMAN_USER', 'MCP_SERVER'] if cap == STATUS else
                  ['MCP_SERVER'] if cap in PRODUCERS else ['HUMAN_USER', 'MCP_SERVER']
                  if cap in CAPABILITIES or cap in (INGESTION, HISTORY) else ['HUMAN'])
        if ((owner, service, path, scope, timeout) !=
                (expected_owner, expected_service, expected_path, expected_scope, expected_timeout)
                or binding['methods'] != ['POST'] or binding.get('vars')
                or (cap != STATUS and binding['uri'] != uri) or generic['uri'] != EXECUTE_PATH
                or policy['identity'] != 'M2M' or policy['maxRequestBytes'] != 65536
                or policy['allowedServiceIdentities'] != [runtime['x-ouf-installation']['mcpServiceIdentity']]
                or policy['allowedActorTypes'] != actors or contract['humanRequired']
                or contract['toolEligible'] != (cap not in PRODUCERS)
                or operation != ('SEARCH' if cap == SEARCH else 'READ')):
            raise ValueError('read operation binding drift: ' + cap)

        route = copy.deepcopy(generic)
        route.update(id=route_id, uri=uri)
        if cap not in CAPABILITIES:
            route.update(priority=0, status=1)
        plugins = route['plugins']
        schema = plugins['request-validation']['body_schema']
        fields = schema['properties']
        if cap != STATUS:
            fields.update(CapabilityID={'const': cap}, GatewayBindingRef={'const': 'capability://' + cap},
                          Owner={'const': owner})
            if cap == SEARCH:
                fields['OperationClass'] = {'const': operation}
        if cap in CAPABILITIES or cap in (INGESTION, HISTORY):
            fields['MaxResultBytes']['maximum'] = 524288
        fields['Arguments'] = arguments(cap)
        plugins['request-validation'] = dispatch_validation(schema, policy['maxRequestBytes'])
        plugins['request-id'] = binding['plugins']['request-id']
        plugins['proxy-rewrite']['uri'] = path
        plugins['openid-connect']['claim_validator']['issuer'] = {'valid_issuers': [installation('gateway.issuerUrl')]}
        quota = 'gateway.rateLimits.readOperationsMcp.'
        plugins['limit-count'].update(count=installation(quota + 'count'), time_window=installation(quota + 'timeWindowSeconds'))
        profile, owner_key, post = mediation(cap, owner, path, scope)
        plugins['serverless-post-function']['functions'] = [post]
        route['labels'].update({'ouf-exposure': 'internal', 'ouf-mediation': profile,
                                'ouf-audience': installation('gateway.requiredAudience'),
                                'ouf-mcp-workload': installation('iam.workloadClients.mcpServer'),
                                'ouf-delegation-key-env': installation('gateway.delegationKeyEnv')})
        if owner_key:
            route['labels']['ouf-owner-key-env'] = installation(owner_key)
        # Status and the aggregate are separately bound upstreams in the inventory.
        backend = 'mcp-operational-aggregate' if cap in CAPABILITIES and owner == 'mcp' else service
        port = binding['x-ouf-backend-binding']['port']
        route['upstream'].update(nodes={f'{backend}:{port}': 1},
                                 timeout={'connect': 3 if cap in ACQUISITIONS else timeout, 'send': timeout, 'read': timeout})
        resources.append(route_resource(route, backend))
    return resources
