#!/usr/bin/env python3
"""Deployable execute profile, deliberately closed to public system status."""
import argparse
import copy
import json
import re
from pathlib import Path

from tools.apisix_request_schema import dispatch_validation
from tools.delegation_functions import function
from tools.materialize_apisix_runtime import materialize as materialize_ingress, require_https_url, require_text

ROOT = Path(__file__).resolve().parents[1]

def enable_analysis_batch_start(ingress, installation, start_key_env, delegation_key_env):
    if (not re.fullmatch(r'[A-Z][A-Z0-9_]{0,127}', start_key_env) or start_key_env == delegation_key_env
            or ingress.get('uri') != '/mcp' or ingress.get('methods') != ['POST']):
        raise ValueError('the BATCH_V1 start proof requires its own key on authenticated MCP ingress')
    plugins = ingress['plugins']
    access = plugins['serverless-post-function']
    oidc = plugins['openid-connect']
    if (access['phase'] != 'access' or oidc.get('use_jwks') is not True or oidc.get('bearer_only') is not True
            or access['functions'][:1] != [function('issue_delegation', installation, delegation_key_env)]):
        raise ValueError('the governed MCP access chain is required')
    values = {
        'INSTALLATION': require_text(installation, 'installationId'),
        'ISSUER': require_https_url(installation, 'issuerUrl'),
        'AUDIENCE': require_text(installation, 'gatewayAudience'),
        'MCP_WORKLOAD': require_text(installation, 'mcpServiceIdentity'),
        'START_KEY_ENV': start_key_env,
    }
    if not all(re.fullmatch(r'[!-~]{1,512}', value) for value in values.values()):
        raise ValueError('resolved installation values required')
    constants = '\n'.join(f'local {name} = {json.dumps(value)}' for name, value in values.items())
    lua = ROOT / 'tools' / 'lua'
    plugins['serverless-pre-function']['functions'].append(
        "return function(conf, ctx) ngx.req.clear_header('X-OUF-Analysis-Batch-Start') end")
    access['functions'].insert(1, '\n'.join((
        'return function(conf, ctx)', constants, (lua / 'delegation.lua').read_text(encoding='utf-8'),
        (lua / 'issue_analysis_batch_start.lua').read_text(encoding='utf-8'), 'end',
    )))


def materialize(runtime, oidc_secret_ref, delegation_key_env, *, analysis_start_key_env=None):
    installation = runtime['x-ouf-installation']
    issuer = require_https_url(installation, 'issuerUrl')
    audience = require_text(installation, 'gatewayAudience')
    workload = require_text(installation, 'mcpServiceIdentity')
    mediation = [r for r in runtime['routes'] if r.get('uri') == '/internal/capabilities/v1/execute']
    if len(mediation) != 1 or mediation[0].get('methods') != ['POST']:
        raise ValueError('exactly one POST execute binding required')
    m = mediation[0]
    if m['x-ouf-policy']['identity'] != 'M2M' or m['x-ouf-mediation']['serviceIdentity'] != workload:
        raise ValueError('execute workload binding is unresolved or invalid')
    routes = [r for r in runtime['routes'] if (r.get('x-ouf-capability') or {}).get('capabilityId') == 'ouf.system.status' and r.get('labels', {}).get('exposure') == 'internal']
    if len(routes) != 1:
        raise ValueError('exactly one internal system status binding required')
    status = routes[0]
    cap, policy = status['x-ouf-capability'], status['x-ouf-policy']
    if cap['owner'] != 'mcp' or cap['operationType'] != 'READ' or cap.get('humanRequired') or not cap.get('toolEligible'):
        raise ValueError('status capability is not delegable READ')
    if policy['identity'] != 'M2M' or workload not in policy['allowedServiceIdentities'] or policy['requiredScope'] != 'operations.status.read' or 'HUMAN' not in policy['allowedActorTypes']:
        raise ValueError('status service/scope/actor policy mismatch')
    if policy.get('maxRequestBytes') != 65536 or policy.get('timeoutSeconds') != 3:
        raise ValueError('status profile limits changed; review materialization')
    if status['service_id'] != 'ouf-mcp-server' or status['plugins']['proxy-rewrite']['uri'] != '/api/internal/v1/mcp/operations/status':
        raise ValueError('unexpected status owner binding')
    result = materialize_ingress(runtime, oidc_secret_ref)
    ingress = next(r for r in result['routes'] if r['uri'] == '/mcp')
    plugins = ingress['plugins']
    plugins['openid-connect'].update(set_access_token_header=False, set_id_token_header=False, set_userinfo_header=False)
    plugins['serverless-pre-function']['functions'].append("return function(conf, ctx) ngx.req.clear_header('X-OUF-Delegation') end")
    plugins['serverless-post-function']['functions'].insert(0, function('issue_delegation', installation, delegation_key_env))
    if analysis_start_key_env is not None:
        enable_analysis_batch_start(ingress, installation, analysis_start_key_env, delegation_key_env)
    oidc = copy.deepcopy(plugins['openid-connect'])
    # Workload auth and signed delegated coarse scope are separate checks.
    oidc.pop('required_scopes', None)
    oidc.update(set_access_token_header=False, set_id_token_header=False, set_userinfo_header=False)
    schema = json.loads((ROOT/'schemas/mcp-gateway-status-dispatch-v1.json').read_text())
    result['routes'].append({
        'id': m['id'], 'uri': m['uri'], 'methods': ['POST'],
        'labels': {**ingress['labels'], 'ouf-mediation': 'status-execute-v1'},
        'plugins': {
            'openid-connect': oidc,
            'limit-count': copy.deepcopy(plugins['limit-count']),
            'request-validation': dispatch_validation(schema, 65536),
            'serverless-pre-function': {'phase':'rewrite', 'functions': ["return function(conf, ctx) for name,_ in pairs(ngx.req.get_headers(0)) do if name:lower():sub(1,6)=='x-ouf-' and name:lower()~='x-ouf-delegation' then ngx.req.clear_header(name) end end end"]},
            'serverless-post-function': {'phase':'access', 'functions':[function('execute_status',installation,delegation_key_env)]},
            'proxy-rewrite': {'uri':'/api/internal/v1/mcp/operations/status'},
        },
        'upstream': {'type':'roundrobin','scheme':'http','nodes':{'ouf-mcp-server:8080':1},
                     'retries':0,'timeout':{'connect':3,'send':3,'read':3}},
    })
    result['delegationKeyEnv'] = delegation_key_env
    return result

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--runtime', type=Path, required=True)
    parser.add_argument('--oidc-client-secret-ref', required=True)
    parser.add_argument('--delegation-key-env', required=True)
    parser.add_argument('--analysis-start-key-env')
    parser.add_argument('--output', type=Path, required=True)
    args=parser.parse_args()
    result=materialize(json.loads(args.runtime.read_text()), args.oidc_client_secret_ref, args.delegation_key_env,
                       analysis_start_key_env=args.analysis_start_key_env)
    args.output.write_text(json.dumps(result,indent=2)+'\n')

if __name__=='__main__': main()
