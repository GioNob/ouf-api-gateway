import base64
import copy
import hashlib
import hmac
import json
from pathlib import Path

import pytest
from jsonschema import Draft7Validator, FormatChecker
from lupa import LuaRuntime

from tools.delegation_functions import function
from tools.materialize_apisix_execute_runtime import materialize
from tools.compile_config import compile_config
from tools.apply_installation_projection import apply_projection

ROOT=Path(__file__).resolve().parents[1]
KEY='ab'*32
INSTALL={'issuerUrl':'https://auth.test/realms/ouf','gatewayAudience':'gateway','mcpServiceIdentity':'workload'}

def runtime():
    return apply_projection(compile_config(ROOT/'ouf-config'),json.loads((ROOT/'tests/fixtures/installation-projection-lab.json').read_text()))

def human():
    return dict(iss=INSTALL['issuerUrl'],aud='gateway',exp=1300,sub='human-a',tenant_id='tenant-a',acr='1',azp='chatgpt',scope='mcp.connect operations.status.read',ouf_actor_type='HUMAN')

def workload():
    return dict(iss=INSTALL['issuerUrl'],aud='gateway',exp=1300,sub='service',tenant_id='tenant-a',azp='workload',ouf_actor_type='SERVICE')

def envelope():
    return dict(GatewayBindingRef='capability://ouf.system.status',CapabilityID='ouf.system.status',Owner='mcp',OperationClass='READ',Arguments={},Identity=dict(ServicePrincipalID='chatgpt',PrincipalID='human-a',TenantID='tenant-a',ActorType='HUMAN',AuthenticationContextRef='1'),AuthorizationDecisionRef='bundle:6:ouf.system.status',CorrelationID='corr',IdempotencyKey='idem',AttemptID='11111111-1111-4111-8111-111111111111',RequestHash=hashlib.sha256(b'{}').hexdigest(),MaxResultBytes=262144)

class Denied(Exception): pass

class Engine:
    """Execute actual generated Lua; Python supplies ngx and crypto/OpenSSL equivalents.

    OIDC signature enforcement is covered separately by the APISIX container gate.
    """
    def __init__(self,claims,headers=None,body=None,now=1000,key=KEY):
        self.lua=LuaRuntime(encoding=None,unpack_returned_tuples=True)
        self.headers={k.lower().encode():v.encode() for k,v in (headers or {}).items()}
        raw=base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b'=')
        self.headers[b'authorization']=b'Bearer e30.'+raw+b'.test'
        self.body=json.dumps(body if body is not None else envelope()).encode()
        self.modules={}
        def primitive(v):
            if isinstance(v,bytes): return v.decode()
            if hasattr(v,'items'): return {primitive(k):primitive(val) for k,val in v.items()}
            return v
        def lua_value(v):
            if isinstance(v,str):return v.encode()
            if isinstance(v,dict):return self.lua.table_from({lua_value(k):lua_value(val) for k,val in v.items()})
            if isinstance(v,list):return self.lua.table_from([lua_value(val) for val in v])
            return v
        self.modules[b'cjson.safe']=self.lua.table_from({b'encode':lambda v:json.dumps(primitive(v),separators=(',',':')).encode(),b'decode':lambda v:lua_value(json.loads(v))})
        def new(key,algorithm):
            return self.lua.table_from({b'final':lambda _,data:hmac.new(key,data,hashlib.sha256).digest()})
        self.modules[b'resty.openssl.hmac']=self.lua.table_from({b'new':new})
        self.modules[b'bit']=self.lua.eval(b'{bor=function(a,b) return a|b end,bxor=function(a,b) return a~b end}')
        self.lua.globals()[b'require']=lambda name:self.modules[name]
        self.lua.execute(b'os.getenv=function(name) return TEST_KEY end')
        self.lua.globals()[b'TEST_KEY']=key.encode() if key else None
        def denied(code): raise Denied(code)
        def set_header(name,value): self.headers[name.lower()]=value
        def clear_header(name): self.headers.pop(name.lower(),None)
        self.lua.globals()[b'ngx']=self.lua.table_from({b'exit':denied,b'time':lambda:now,b'encode_base64':base64.b64encode,b'decode_base64':lambda v:base64.b64decode(v),b'var':self.lua.table_from({b'http_authorization':self.headers[b'authorization']}),b'req':self.lua.table_from({b'get_headers':lambda *args:self.lua.table_from(self.headers),b'set_header':set_header,b'clear_header':clear_header,b'read_body':lambda:None,b'get_body_data':lambda:self.body,b'set_body_data':lambda v:setattr(self,'body',v)})})
    def run(self,kind): self.lua.execute(function(kind,INSTALL,'TEST_KEY').encode())(None,None)

def proof(claims=None):
    engine=Engine(claims or human());engine.run('issue_delegation')
    return engine.headers[b'x-ouf-delegation'].decode()

def execute(proof_value=None,body=None,claims=None,**kwargs):
    e=body if body is not None else envelope()
    headers={'X-OUF-Delegation':proof_value or proof(),'X-Correlation-ID':e['CorrelationID'],'Idempotency-Key':e['IdempotencyKey'],'X-Tool-Attempt-ID':e['AttemptID'],'X-OUF-Principal-ID':'forged','Cookie':'secret'}
    engine=Engine(claims or workload(),headers,e,**kwargs);engine.run('execute_status');return engine

def test_signed_context_roundtrip_and_owner_headers():
    e=execute()
    assert e.body==b'{}'
    assert e.headers[b'x-ouf-principal-id']==b'human-a'
    assert e.headers[b'x-ouf-service-principal']==b'workload'
    assert e.headers[b'x-ouf-granted-scopes']==b'mcp.connect operations.status.read'
    assert all(k not in e.headers for k in [b'authorization',b'cookie',b'x-ouf-delegation'])

@pytest.mark.parametrize('kind',['signature','tenant','principal','client','actor','acr','workload','scope','audience','issuer','expired','future','key'])
def test_invalid_context_never_reaches_owner(kind):
    p=proof();body=envelope();claims=workload();kwargs={}
    if kind=='signature': p=p[:-2]+('aa' if p[-2:]!='aa' else 'bb')
    elif kind in ['tenant','principal','client','actor','acr']:
        field={'tenant':'TenantID','principal':'PrincipalID','client':'ServicePrincipalID','actor':'ActorType','acr':'AuthenticationContextRef'}[kind];body['Identity'][field]='forged'
    elif kind=='workload': claims['azp']='other'
    elif kind=='scope': c=human();c['scope']='mcp.connect';p=proof(c)
    elif kind=='audience': claims['aud']='wrong'
    elif kind=='issuer': claims['iss']='https://wrong'
    elif kind=='expired': kwargs['now']=1061
    elif kind=='future': kwargs['now']=999
    elif kind=='key': kwargs['key']='cd'*32
    with pytest.raises(Denied): execute(p,body,claims,**kwargs)

def test_missing_signing_key_and_missing_human_claim_fail_closed():
    with pytest.raises(Denied): Engine(human(),key=None).run('issue_delegation')
    c=human();del c['tenant_id']
    with pytest.raises(Denied): Engine(c).run('issue_delegation')

def test_closed_materialization_and_schema():
    result=materialize(runtime(),'$ENV://OIDC_SECRET','DELEGATION_KEY')
    r=next(r for r in result['routes'] if r['uri'].endswith('/execute'))
    schema=r['plugins']['request-validation']['body_schema']
    validator=Draft7Validator(schema,format_checker=FormatChecker())
    validator.validate(envelope())
    for key,value in [('Arguments',{'url':'https://attacker'}),('CapabilityID','other'),('Identity',{'PrincipalID':'forged'})]:
        e=envelope();e[key]=value;assert list(validator.iter_errors(e))
    assert r['upstream']['retries']==0
    assert r['plugins']['openid-connect']['ssl_verify'] is True
    assert 'required_scopes' not in r['plugins']['openid-connect']
    assert KEY not in json.dumps(result)
    for field in ['serviceIdentity','serviceIdentityRef']:
        rtime=runtime();m=next(r for r in rtime['routes'] if r['uri'].endswith('/execute'))
        if field=='serviceIdentity':
            m['x-ouf-mediation'][field]='wrong'
            with pytest.raises(ValueError):materialize(rtime,'$ENV://OIDC','KEY')
