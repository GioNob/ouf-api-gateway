"""Add two minimized owner READs, preserving every retained route and binding."""
import copy
import json
import re
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
CAPABILITIES={
    'ouf.ingestion.acquisition.read': ('ingestion','ouf-ingestion-evidence-read','/api/internal/v1/ingestion/operations/acquisition',
        ('ingestion.run.read','ingestion.contract.read','ingestion.lineage.read'),'ingestion.lineage.read','afterLineageId'),
    'urban.acquisition.read': ('udp','ouf-udp-evidence-read','/api/udp/v1/operations/acquisition',
        ('urban.object.read','lineage.object.read','lineage.property.read'),'lineage.object.read','afterHandoffId'),
}

def dispatch_schema(capability):
    if capability not in CAPABILITIES: raise ValueError('closed acquisition binding required')
    owner,_,_,_,_,cursor=CAPABILITIES[capability]
    schema=json.loads((ROOT/'schemas/mcp-gateway-status-dispatch-v1.json').read_text())
    fields=schema['properties'];fields['CapabilityID']={'const':capability};fields['GatewayBindingRef']={'const':'capability://'+capability};fields['Owner']={'const':owner}
    fields['MaxResultBytes']['maximum']=1048576
    uuid={'type':'string','pattern':r'^(?!00000000-0000-0000-0000-000000000000$)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'}
    properties={'sourceId':{'type':'string','minLength':1,'maxLength':200},'runId':uuid,'limit':{'type':'integer','minimum':1,'maximum':100},
        cursor:uuid if owner=='ingestion' else {'type':'string','minLength':1,'maxLength':200}}
    fields['Arguments']={'type':'object','additionalProperties':False,'required':['sourceId','runId'],'properties':properties}
    return schema

def materialize(existing,runtime,delegation_key_env,ingestion_key_env,udp_key_env):
    keys=(delegation_key_env,ingestion_key_env,udp_key_env)
    if len(set(keys))!=3 or any(not isinstance(k,str) or not re.fullmatch(r'[A-Z][A-Z0-9_]{0,127}',k)for k in keys):
        raise ValueError('three distinct named signing keys required')
    result=copy.deepcopy(existing);installation=runtime['x-ouf-installation']
    templates=[r for r in result['routes']if r.get('uri')=='/internal/capabilities/v1/execute']
    if len(templates)!=1:raise ValueError('one retained execute template required')
    template=templates[0];plugins=template.get('plugins',{});oidc=plugins.get('openid-connect',{})
    if(template.get('methods')!=['POST']or any(k not in plugins for k in('openid-connect','limit-count','request-validation','serverless-pre-function','serverless-post-function'))
        or oidc.get('bearer_only')is not True or oidc.get('ssl_verify')is not True or oidc.get('use_jwks')is not True
        or oidc.get('unauth_action')!='deny' or 'required_scopes'in oidc):raise ValueError('retained authenticated execute template required')
    from tools.delegation_functions import function
    for capability,(owner,logical,path,scopes,scope,_)in CAPABILITIES.items():
        uri='/internal/capabilities/v1/execute/'+capability
        bindings=[r for r in runtime['routes']if r.get('uri')==uri]
        if len(bindings)!=1:raise ValueError('one reviewed acquisition binding required')
        b=bindings[0];cap=b['x-ouf-capability'];policy=b['x-ouf-policy'];backend=b['x-ouf-backend-binding']
        service=installation.get('serviceBindings',{}).get(logical,logical);port=backend.get('port')
        if(b.get('methods')!=['POST']or cap.get('capabilityId')!=capability or cap.get('owner')!=owner
            or cap.get('operationType')!='READ' or cap.get('toolEligible')is not True or cap.get('humanRequired')is not False
            or policy.get('identity')!='M2M' or policy.get('requiredScope')!=scope
            or policy.get('allowedServiceIdentities')!=[installation['mcpServiceIdentity']]or policy.get('allowedActorTypes')!=['HUMAN']
            or policy.get('maxRequestBytes')!=65536 or policy.get('timeoutSeconds')!=12
            or backend.get('service')!=service or not isinstance(service,str)or not re.fullmatch(r'[A-Za-z0-9._-]{1,253}',service)
            or type(port)is not int or not 1<=port<=65535 or backend.get('path')!=path
            or b.get('plugins',{}).get('proxy-rewrite',{}).get('uri')!=path):raise ValueError('acquisition binding drift')
        rid='execute-'+capability.replace('.','-')
        if any(r.get('id')==rid or uri in [r.get('uri')]+list(r.get('uris')or[])for r in result['routes']):raise ValueError('acquisition route already selected; reconcile')
        route=copy.deepcopy(template);route.update(id=rid,uri=uri,methods=['POST'],status=1,priority=0)
        route.setdefault('labels',{})['ouf-mediation']='acquisition-evidence-read-v1'
        route['plugins']['request-validation']={'max_req_body_size':65536,'body_schema':dispatch_schema(capability)}
        route['plugins']['serverless-post-function']={'phase':'access','functions':[function('execute_acquisition_read',installation,delegation_key_env,
            owner_key_env=ingestion_key_env if owner=='ingestion'else udp_key_env,operational_binding={'capability':capability,'owner':owner,'scope':scope})]}
        route['plugins']['proxy-rewrite']={'uri':path}
        route['upstream']={'type':'roundrobin','scheme':'http','nodes':{f'{service}:{port}':1},'retries':0,'timeout':{'connect':3,'send':12,'read':12}}
        result['routes'].append(route)
    return result
