#!/usr/bin/env python3
"""Install exactly three delegated managed-file MCP routes with rollback."""
import argparse
import json
import os
from pathlib import Path

from ops.apisix.deploy_internal_m2m_routes import Admin, apply, restore, validate_routes

IDS={'mcp-managed-file-profile','mcp-managed-file-preview','mcp-managed-file-create'}
PROBE_ID='00000000-0000-4000-8000-000000000001'

def anonymous_probe(route):
    """Valid envelope without credentials: exercise authentication, not JSON parsing.

    An empty POST can return 400 from request-validation before OIDC runs.
    These synthetic identifiers cannot address a real asset or grant authority.
    """
    mode=route['id'].removeprefix('mcp-managed-file-')
    cap={'profile':'ouf.managed-source.file.profile',
         'preview':'ouf.managed-source.preview',
         'create':'ouf.managed-source.onboarding.create'}[mode]
    args={'assetId':PROBE_ID}
    if mode=='preview':
        args['profileId']=PROBE_ID
    elif mode=='create':
        args.update(profileId=PROBE_ID,sourceId='probe-source',name='Probe',
                    owner='Probe',targetClassIri='https://example.org/Probe',
                    semanticRefs=['probe@1'],sourceObjectKeyFields=[],
                    fields=[{'fieldName':'probe','extractionDecision':'INCLUDE',
                             'dataAccessLabel':'OPEN',
                             'targetPropertyIri':'https://example.org/probe'}])
    return {'GatewayBindingRef':'capability://'+cap,'CapabilityID':cap,
            'Owner':'onboarding','OperationClass':'READ' if mode=='preview' else 'COMMAND',
            'Arguments':args,'Identity':{'ServicePrincipalID':'anonymous-probe',
            'PrincipalID':'anonymous-probe','TenantID':'anonymous-probe',
            'ActorType':'HUMAN','AuthenticationContextRef':'probe'},
            'AuthorizationDecisionRef':'anonymous-probe',
            'CorrelationID':'anonymous-probe','IdempotencyKey':'anonymous-probe',
            'AttemptID':PROBE_ID,'RequestHash':'0'*64,'MaxResultBytes':4096}

def select(doc):
    routes=doc.get('routes')
    if not isinstance(routes,list):
        raise ValueError('missing routes')
    selected=[r for r in routes if isinstance(r,dict) and r.get('id') in IDS]
    if validate_routes(selected)!=IDS:
        raise ValueError('exact managed-file route trio required')
    for route in selected:
        mode=route['id'].removeprefix('mcp-managed-file-')
        if (route['uri']!='/internal/capabilities/v1/execute/managed.file/'+mode
            or route['methods']!=['POST']
            or route['plugins'].get('proxy-rewrite',{}).get('uri')!='/api/internal/v1/onboarding/managed-file-mcp/'+mode
            or route['upstream'].get('nodes')!={'ouf-onboarding:8080':1}
            or route['upstream'].get('retries')!=0
            or route['labels'].get('ouf-mediation')!='managed-file-delegation-v1'
            or 'request-validation' not in route['plugins']):
            raise ValueError('managed-file route contract mismatch: '+mode)
    return selected

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    choice=parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--materialization',type=Path)
    choice.add_argument('--restore',type=Path)
    parser.add_argument('--admin-key',type=Path,required=True)
    parser.add_argument('--container',default='ouf-apisix')
    parser.add_argument('--curl-image',default='curlimages/curl:8.16.0')
    parser.add_argument('--backup-dir',type=Path,default=Path('/opt/ouf/backup'))
    args=parser.parse_args()
    os.umask(0o077)
    previous=None
    if args.restore:
        previous=json.loads(args.restore.read_text())
        if not isinstance(previous,dict) or set(previous)!=IDS:
            raise ValueError('snapshot must contain the exact managed-file route trio')
    else:
        routes=select(json.loads(args.materialization.read_text()))
    admin=Admin(args,'managed-file-mcp-')
    try:
        if previous is not None:
            restore(previous,admin)
            print('MANAGED_FILE_MCP_RESTORED')
        else:
            apply(routes,admin,anonymous_probe=anonymous_probe)
            print('MANAGED_FILE_MCP_ACTIVE')
    finally:
        admin.close()

if __name__=='__main__':
    main()
