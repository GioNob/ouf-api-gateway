"""Render the owner functions shared by the retained and November 8 route profiles."""
import json
from pathlib import Path
import re

from tools.delegation_functions import function


def owner_function(source, installation, delegation_key_env, owner_key_env):
    if source == 'execute_semantic_discovery':
        return function(source, installation, delegation_key_env, owner_key_env)
    if source != 'execute_managed_file_retained':
        raise ValueError('unknown owner function')
    if any(not isinstance(key, str) or not re.fullmatch(r'[A-Z][A-Z0-9_]{0,127}', key)
           for key in (delegation_key_env, owner_key_env)):
        raise ValueError('owner and delegation key environment names required')
    values = {'DELEGATION_KEY_ENV': delegation_key_env, 'ISSUER': installation['issuerUrl'].rstrip('/'),
              'AUDIENCE': installation['gatewayAudience'], 'MCP_WORKLOAD': installation['mcpServiceIdentity'],
              'OWNER_KEY_ENV': owner_key_env}
    if any(not isinstance(v, str) or not v.strip() or v.startswith('installation://') for v in values.values()):
        raise ValueError('resolved delegation settings required')
    constants = '\n'.join(f'local {k} = {json.dumps(v)}' for k, v in values.items())
    lua = Path(__file__).resolve().parent / 'lua'
    return ('return function(conf, ctx)\n' + constants + '\n' + (lua / 'delegation.lua').read_text()
            + '\n' + (lua / (source + '.lua')).read_text() + '\nend')
