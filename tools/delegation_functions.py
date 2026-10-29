"""Embed reviewed Lua source in APISIX functions; no credentials in artifacts."""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent / 'lua'

def function(kind, installation, key_env, owner_key_env=None, operational_binding=None):
    if not re.fullmatch(r'[A-Z][A-Z0-9_]{0,127}', key_env):
        raise ValueError('invalid delegation key environment name')
    values = {'DELEGATION_KEY_ENV': key_env, 'ISSUER': installation['issuerUrl'].rstrip('/'),
              'AUDIENCE': installation['gatewayAudience'], 'MCP_WORKLOAD': installation['mcpServiceIdentity']}
    if any(not isinstance(v, str) or not v.strip() or v.startswith('installation://') for v in values.values()):
        raise ValueError('resolved delegation settings required')
    if kind in ('execute_permissions', 'execute_semantic_proposals', 'execute_object_search', 'execute_managed_file', 'execute_managed_upload', 'execute_semantic_read', 'execute_semantic_discovery', 'execute_source_revision', 'execute_ingestion_read'):
        if not isinstance(owner_key_env,str) or not re.fullmatch(r'[A-Z][A-Z0-9_]{0,127}',owner_key_env):
            raise ValueError('owner receipt key environment required')
        values['OWNER_KEY_ENV'] = owner_key_env
        if kind == 'execute_ingestion_read' and owner_key_env == key_env:
            raise ValueError('distinct ingestion owner receipt key reference required')
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
    if kind == 'execute_ingestion_read':
        if (not isinstance(operational_binding, dict) or set(operational_binding) != {'capability','owner','scope'}
            or operational_binding['capability'] not in ('ouf.ingestion.status','ouf.ingestion.history') or operational_binding['owner'] != 'ingestion'
            or operational_binding['scope'] != 'ingestion.operations.read'):
            raise ValueError('closed ingestion READ binding required')
        values.update(CAPABILITY=operational_binding['capability'],OWNER='ingestion',REQUIRED_SCOPE='ingestion.operations.read')
    constants = '\n'.join(f'local {k} = {json.dumps(v)}' for k, v in values.items())
    if kind not in ('issue_delegation', 'execute_status', 'execute_permissions', 'execute_operational', 'execute_semantic_proposals', 'execute_object_search', 'execute_managed_file', 'execute_managed_upload', 'execute_semantic_read', 'execute_source_revision', 'execute_ingestion_read'):
        raise ValueError('invalid function')
    return 'return function(conf, ctx)\n' + constants + '\n' + (ROOT/'delegation.lua').read_text() + '\n' + (ROOT/(kind+'.lua')).read_text() + '\nend'




