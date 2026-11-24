"""Embed reviewed Lua source in APISIX functions; no credentials in artifacts."""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent / 'lua'

# Release routes carry installation settings as structured APISIX values.
# A profile value never becomes executable Lua source.
INSTALLATION_LABELS = {
    'AUDIENCE': 'ouf-audience', 'MCP_WORKLOAD': 'ouf-mcp-workload',
    'DELEGATION_KEY_ENV': 'ouf-delegation-key-env', 'OWNER_KEY_ENV': 'ouf-owner-key-env',
}


def capture_original_body(ceiling, *, reject_empty=True):
    """Preserve the bounded envelope before APISIX request-validation re-encodes it."""
    empty_check = '#body == 0 or ' if reject_empty else ''
    return f"""return function(conf, ctx)
    local body = require('apisix.core').request.get_body({ceiling})
    if not body or {empty_check}#body > {ceiling} then return ngx.exit(413) end
    ctx.ouf_original_body = body
end"""


def operational_source(with_receipt):
    source = (ROOT / 'execute_operational.lua').read_text()
    before, optional = source.split('-- BEGIN PRODUCER RECEIPT\n', 1)
    receipt, after = optional.split('-- END PRODUCER RECEIPT\n', 1)
    return before + (receipt if with_receipt else 'ngx.req.set_body_data(cjson.encode(e.Arguments))\n') + after


def function(kind, installation, key_env, owner_key_env=None, operational_binding=None, *,
             use_route_labels=False, ths_link=None, issue_handoff=False, discovery_mode=None, read_mode=None):
    if use_route_labels and kind not in ('execute_semantic_proposals', 'execute_source_revision', 'execute_managed_file',
                                         'execute_managed_file_retained', 'execute_semantic_discovery', 'execute_discovery_adopt',
                                         'execute_semantic_read', 'execute_managed_upload', 'execute_permissions',
                                         'execute_managed_profile', 'execute_revision_read'):
        raise ValueError('unsupported installation-bound function')
    if not re.fullmatch(r'[A-Z][A-Z0-9_]{0,127}', key_env):
        raise ValueError('invalid delegation key environment name')
    values = {'DELEGATION_KEY_ENV': key_env, 'ISSUER': installation['issuerUrl'].rstrip('/'),
              'AUDIENCE': installation['gatewayAudience'], 'MCP_WORKLOAD': installation['mcpServiceIdentity']}
    if any(not isinstance(v, str) or not v.strip() or v.startswith('installation://') for v in values.values()):
        raise ValueError('resolved delegation settings required')
    if kind in ('execute_permissions', 'execute_semantic_proposals', 'execute_object_search', 'execute_managed_file', 'execute_managed_file_retained', 'execute_managed_upload', 'execute_semantic_read', 'execute_source_revision', 'execute_semantic_discovery', 'execute_discovery_adopt', 'execute_managed_profile', 'execute_revision_read'):
        if not isinstance(owner_key_env,str) or not re.fullmatch(r'[A-Z][A-Z0-9_]{0,127}',owner_key_env):
            raise ValueError('owner receipt key environment required')
        values['OWNER_KEY_ENV'] = owner_key_env
    if kind == 'execute_discovery_adopt':
        cap = 'ouf.semantic.discovery.adopt'
        values.update(CAPABILITY=cap, REQUIRED_SCOPE='ouf.semantic.discovery',
                      OPERATION='COMMAND', OWNER_PATH='/api/semantic/v1/proposal-commands/adopt')
    if kind == 'execute_semantic_read' and use_route_labels:
        if read_mode not in ('search', 'search-batch', 'get'):
            raise ValueError('expected a fixed semantic search binding')
        values['READ_MODE'] = read_mode
    if kind == 'execute_semantic_proposals':
        from tools.materialize_semantic_proposals import CAPABILITIES
        if not isinstance(operational_binding, dict) or set(operational_binding) != {'capability','owner','scope'}:
            raise ValueError('closed semantic binding required')
        cap = operational_binding['capability']
        expected = CAPABILITIES.get(cap)
        if expected is None or operational_binding['owner'] != 'semantic' or operational_binding['scope'] != expected[2]:
            raise ValueError('semantic binding is not approved')
        values.update(CAPABILITY=cap,REQUIRED_SCOPE=expected[2],OPERATION=expected[1],OWNER_PATH='/api/semantic/v1/proposal-commands/'+expected[0])
    if kind == 'execute_operational':
        if not isinstance(operational_binding, dict) or set(operational_binding) != {'capability','owner','scope'}:
            raise ValueError('closed operational binding required')
        from tools.materialize_operational_execute import CAPABILITIES
        cap = operational_binding['capability']
        expected = CAPABILITIES.get(cap)
        if expected is None or operational_binding['owner'] != expected[0] or operational_binding['scope'] != expected[4]:
            raise ValueError('operational binding is not approved')
        values.update(CAPABILITY=cap,OWNER=expected[0],REQUIRED_SCOPE=expected[4])
        if owner_key_env is not None:
            if (expected[0] not in ('ingestion', 'gateway') or not isinstance(owner_key_env, str)
                or not re.fullmatch(r'[A-Z][A-Z0-9_]{0,127}', owner_key_env)):
                raise ValueError('invalid producer receipt key environment name or owner')
            if owner_key_env == key_env:
                raise ValueError('producer receipt key environment must differ from delegation key')
            # Append after REQUIRED_SCOPE; preserve the order of all existing constants.
            values['RECEIPT_KEY_ENV'] = owner_key_env
        source = operational_source(owner_key_env is not None)
        constants = '\n'.join(f'local {k} = {json.dumps(v)}' for k, v in values.items())
        return ('return function(conf, ctx)\n' + constants + '\n' +
                (ROOT / 'delegation.lua').read_text() + '\n' + source + '\nend')
    if use_route_labels:
        lines = [
            'local route = ctx.matched_route.value',
            'local labels = route.labels',
            "local oidc = route.plugins['openid-connect']",
            'local issuer = oidc and oidc.claim_validator and oidc.claim_validator.issuer',
            'local issuers = issuer and issuer.valid_issuers',
            'local ISSUER = issuers and #issuers == 1 and issuers[1]',
        ]
        for key, value in values.items():
            if key == 'ISSUER':
                continue
            expression = (f'labels[{json.dumps(INSTALLATION_LABELS[key])}]'
                          if key in INSTALLATION_LABELS else json.dumps(value))
            lines.append(f'local {key} = {expression}')
        lines.append('if not ISSUER or not AUDIENCE or not MCP_WORKLOAD or not OWNER_KEY_ENV '
                     'or not DELEGATION_KEY_ENV or OWNER_KEY_ENV == DELEGATION_KEY_ENV then return ngx.exit(503) end')
        constants = '\n'.join(lines)
    else:
        constants = '\n'.join(f'local {k} = {json.dumps(v)}' for k, v in values.items())
        if kind == 'execute_semantic_read':
            constants += '\nlocal READ_MODE = nil'
    if kind not in ('issue_delegation', 'execute_status', 'execute_permissions', 'execute_operational', 'execute_semantic_proposals', 'execute_object_search', 'execute_managed_file', 'execute_managed_file_retained', 'execute_managed_upload', 'execute_semantic_read', 'execute_source_revision', 'execute_semantic_discovery', 'execute_discovery_adopt', 'execute_managed_profile', 'execute_revision_read'):
        raise ValueError('invalid function')
    template = 'execute_semantic_proposals' if kind == 'execute_discovery_adopt' else kind
    source = (ROOT / (template + '.lua')).read_text()
    if kind == 'execute_semantic_read':
        from tools.mcp_dispatch_contract import SEARCH_SCOPE, capability_contracts
        source = source.replace('USE_CAPTURED_READ_BODY', 'false' if read_mode == 'get' else 'READ_MODE')
        kinds = capability_contracts()[SEARCH_SCOPE]['inputSchema']['properties']['type']['enum']
        source = source.replace('-- MATERIALIZE SEARCH TYPES',
                                'local kinds = {' + ','.join(f'[{json.dumps(k)}]=true' for k in kinds) + '}')
    if kind == 'execute_semantic_discovery':
        from tools.mcp_dispatch_contract import DISCOVERY_SCOPE, capability_contracts, dispatch_input_schema
        original = ''
        if discovery_mode == 'candidates':
            original = ("body = ctx.ouf_original_body\n"
                        "if type(body) ~= 'string' or #body > 65536 then return fail(413) end")
        source = source.replace('-- MATERIALIZE DISCOVERY ORIGINAL BODY', original)
        modes = []
        for mode in ('request', 'status', 'candidates'):
            capability = DISCOVERY_SCOPE if mode == 'request' else DISCOVERY_SCOPE + '.' + mode
            schema = dispatch_input_schema(capability, capability_contracts()[capability]['inputSchema'])
            keys = ','.join(f'[{json.dumps(k)}]=true' for k in sorted(schema['properties']))
            modes.append(f'{mode}={{{keys}}}')
        source = source.replace('-- MATERIALIZE DISCOVERY KEYS', 'local keys = {' + ','.join(modes) + '}')

    if kind == 'execute_managed_file':
        file_binding = 'local binding = ths_link'
        receipt_capability = 'e.CapabilityID'
        if issue_handoff:
            from tools.mcp_dispatch_contract import picker_contract
            contract = picker_contract('mcp-managed-file-handoff-issue')
            path = '/api/internal/v1/onboarding/managed-file-mcp/handoff-issue'
            uri = '/internal/capabilities/v1/execute/managed.file/handoff-issue'
            settings = {'capability': contract['capabilityId'], 'binding': contract['gatewayBindingRef'],
                        'operation': contract['operationClass'], 'scope': contract['requiredAuthorizationCapability'],
                        'path': path}
            file_binding = '\n'.join((
                f'if ngx.var.uri ~= "{uri}" and ngx.var.uri ~= "{path}" then return fail(403) end',
                "if type(e.Arguments) ~= 'table' or e.Arguments.commandKey ~= e.IdempotencyKey then return fail(409) end",
                'local binding = {' + ', '.join(f'{k}={json.dumps(v)}' for k, v in settings.items()) + '}',
            ))
            # Onboarding verifies the delegated upload authority, exact issue path and envelope hash.
            receipt_capability = 'binding.scope'
        source = source.replace('-- MATERIALIZE FILE BINDING', file_binding)
        source = source.replace('OWNER_RECEIPT_CAPABILITY', receipt_capability)
        if ths_link is None:
            binding = 'nil'
        else:
            settings = [f'{key}={json.dumps(ths_link[key])}'
                        for key in ('capability', 'binding', 'operation', 'scope', 'path')]
            fields = [f'{{name={json.dumps(name)},type={json.dumps(field_type)}}}'
                      for name, field_type in sorted(ths_link['fields'].items())]
            binding = '{' + ', '.join(settings + ['fields={' + ', '.join(fields) + '}']) + '}'
        source = source.replace('-- MATERIALIZE THS LINK', 'local ths_link = ' + binding)
    if template == 'execute_semantic_proposals':
        adopt = kind == 'execute_discovery_adopt'
        human_only = 'true' if adopt else "CAPABILITY == 'ouf.semantic.proposal.read'"
        source = source.replace('HUMAN_ONLY', human_only)
        source = source.replace('RECEIPT_CAPABILITY', 'CAPABILITY' if adopt else 'REQUIRED_SCOPE')
        from tools.materialize_semantic_proposals import PROPOSAL_REQUEST_BYTES, VALUE_MAP_REQUEST_BYTES
        ceiling = VALUE_MAP_REQUEST_BYTES if cap == 'ouf.semantic.propose' else PROPOSAL_REQUEST_BYTES
        reader = 'ngx.req.read_body()\nlocal body = ngx.req.get_body_data()'
        if adopt or cap == 'ouf.semantic.propose' or (use_route_labels and cap in ('ouf.semantic.review.prepare', 'ouf.semantic.approval.request')):
            reader = "local body = ctx.ouf_original_body\nif type(body) ~= 'string' then return fail(503) end"
        source = source.replace('-- MATERIALIZE SEMANTIC REQUEST BODY', reader)
        source = source.replace('BODY_CEILING', str(ceiling)).replace('LEGACY_CEILING', str(PROPOSAL_REQUEST_BYTES))
    return 'return function(conf, ctx)\n' + constants + '\n' + (ROOT/'delegation.lua').read_text() + '\n' + source + '\nend'

