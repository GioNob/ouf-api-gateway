"""Embed reviewed Lua source in APISIX functions; no credentials in artifacts."""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent / 'lua'

def function(kind, installation, key_env):
    if not re.fullmatch(r'[A-Z][A-Z0-9_]{0,127}', key_env):
        raise ValueError('invalid delegation key environment name')
    values = {'DELEGATION_KEY_ENV': key_env, 'ISSUER': installation['issuerUrl'].rstrip('/'),
              'AUDIENCE': installation['gatewayAudience'], 'MCP_WORKLOAD': installation['mcpServiceIdentity']}
    if any(not isinstance(v, str) or not v.strip() or v.startswith('installation://') for v in values.values()):
        raise ValueError('resolved delegation settings required')
    constants = '\n'.join(f'local {k} = {json.dumps(v)}' for k, v in values.items())
    if kind not in ('issue_delegation', 'execute_status'):
        raise ValueError('invalid function')
    return 'return function(conf, ctx)\n' + constants + '\n' + (ROOT/'delegation.lua').read_text() + '\n' + (ROOT/(kind+'.lua')).read_text() + '\nend'
