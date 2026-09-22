"""Embed reviewed Lua source in APISIX functions; no credentials in artifacts."""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent / 'lua'

def function(kind, installation, key_env, owner_key_env=None):
    if not re.fullmatch(r'[A-Z][A-Z0-9_]{0,127}', key_env):
        raise ValueError('invalid delegation key environment name')
    values = {'DELEGATION_KEY_ENV': key_env, 'ISSUER': installation['issuerUrl'].rstrip('/'),
              'AUDIENCE': installation['gatewayAudience'], 'MCP_WORKLOAD': installation['mcpServiceIdentity']}
    if any(not isinstance(v, str) or not v.strip() or v.startswith('installation://') for v in values.values()):
        raise ValueError('resolved delegation settings required')
    if kind in ('execute_summary', 'execute_incidents'):
        values['INGESTION_RECEIPT_KEY_ENV'] = 'INGESTION_SUMMARY_RECEIPT_KEY'
        values['GATEWAY_RECEIPT_KEY_ENV'] = 'GATEWAY_SUMMARY_RECEIPT_KEY'
    if kind == 'execute_permissions':
        if not isinstance(owner_key_env,str) or not re.fullmatch(r'[A-Z][A-Z0-9_]{0,127}',owner_key_env):
            raise ValueError('owner receipt key environment required')
        values['OWNER_KEY_ENV'] = owner_key_env
    constants = '\n'.join(f'local {k} = {json.dumps(v)}' for k, v in values.items())
    if kind not in ('issue_delegation', 'execute_status', 'execute_permissions', 'execute_summary', 'execute_incidents'):
        raise ValueError('invalid function')
    return 'return function(conf, ctx)\n' + constants + '\n' + (ROOT/'delegation.lua').read_text() + '\n' + (ROOT/(kind+'.lua')).read_text() + '\nend'
