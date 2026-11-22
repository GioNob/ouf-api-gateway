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


def capture_original_body(ceiling):
    """Preserve the bounded envelope before APISIX request-validation re-encodes it."""
    return f"""return function(conf, ctx)
    local body = require('apisix.core').request.get_body({ceiling})
    if not body or #body == 0 or #body > {ceiling} then return ngx.exit(413) end
    ctx.ouf_original_body = body
end"""


def function(kind, installation, key_env, owner_key_env=None, operational_binding=None, *, use_route_labels=False):
    if use_route_labels and kind not in ('execute_semantic_proposals', 'execute_source_revision', 'execute_managed_file'):
        raise ValueError('unsupported installation-bound function')
    if not re.fullmatch(r'[A-Z][A-Z0-9_]{0,127}', key_env):
        raise ValueError('invalid delegation key environment name')
    values = {'DELEGATION_KEY_ENV': key_env, 'ISSUER': installation['issuerUrl'].rstrip('/'),
              'AUDIENCE': installation['gatewayAudience'], 'MCP_WORKLOAD': installation['mcpServiceIdentity']}
    if any(not isinstance(v, str) or not v.strip() or v.startswith('installation://') for v in values.values()):
        raise ValueError('resolved delegation settings required')
    if kind in ('execute_permissions', 'execute_semantic_proposals', 'execute_object_search', 'execute_managed_file', 'execute_managed_upload', 'execute_semantic_read', 'execute_source_revision'):
        if not isinstance(owner_key_env,str) or not re.fullmatch(r'[A-Z][A-Z0-9_]{0,127}',owner_key_env):
            raise ValueError('owner receipt key environment required')
        values['OWNER_KEY_ENV'] = owner_key_env
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
        source = (ROOT / 'execute_operational.lua').read_text()
        before, optional = source.split('-- BEGIN PRODUCER RECEIPT\n', 1)
        receipt, after = optional.split('-- END PRODUCER RECEIPT\n', 1)
        # Omitted opt-in must preserve even the original generated Lua bytes.
        source = before + (receipt if owner_key_env is not None else
                           'ngx.req.set_body_data(cjson.encode(e.Arguments))\n') + after
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
    if kind not in ('issue_delegation', 'execute_status', 'execute_permissions', 'execute_operational', 'execute_semantic_proposals', 'execute_object_search', 'execute_managed_file', 'execute_managed_upload', 'execute_semantic_read', 'execute_source_revision'):
        raise ValueError('invalid function')
    source = (ROOT / (kind + '.lua')).read_text()
    if kind == 'execute_semantic_proposals':
        from tools.materialize_semantic_proposals import PROPOSAL_REQUEST_BYTES, VALUE_MAP_REQUEST_BYTES
        ceiling = PROPOSAL_REQUEST_BYTES
        reader = 'ngx.req.read_body()\nlocal body = ngx.req.get_body_data()'
        if cap == 'ouf.semantic.propose':
            ceiling = VALUE_MAP_REQUEST_BYTES
            reader = "local body = ctx.ouf_original_body\nif type(body) ~= 'string' then return fail(503) end"
        source = source.replace('-- MATERIALIZE SEMANTIC REQUEST BODY', reader)
        source = source.replace('BODY_CEILING', str(ceiling)).replace('LEGACY_CEILING', str(PROPOSAL_REQUEST_BYTES))
    return 'return function(conf, ctx)\n' + constants + '\n' + (ROOT/'delegation.lua').read_text() + '\n' + source + '\nend'

