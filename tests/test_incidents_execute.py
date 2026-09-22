import json
import pytest
from tests.test_execute_delegation import Engine,Denied,envelope,human,workload,proof,runtime
from tools.materialize_incidents import materialize

def execute(owner='mcp',arguments=None,scope=True):
    cap='ouf.operations.incidents' if owner=='mcp' else 'ouf.'+owner+'.operations.incidents'
    e=envelope();e.update(CapabilityID=cap,Owner=owner,GatewayBindingRef='capability://'+cap,Arguments=arguments or {'limit':1},AuthorizationDecisionRef='bundle:6:'+cap,MaxResultBytes=524288)
    c=human();c['externalRoleRefs']=['ouf:viewer']
    if scope:c['scope']+=' operations.incident.read'
    engine=Engine(workload(),{'X-OUF-Delegation':proof(c),'X-Correlation-ID':'corr','Idempotency-Key':'idem','X-Tool-Attempt-ID':e['AttemptID']},e)
    engine.lua.globals()[b'ngx'][b'var'][b'request_uri']=('/internal/capabilities/v1/execute/'+cap).encode()
    engine.run('execute_incidents');return engine

def test_closed_routes_and_scope():
    doc=materialize(runtime(),'$ENV://OIDC','DELEGATION_KEY','OWNER_KEY')
    routes=[r for r in doc['routes'] if r.get('labels',{}).get('ouf-mediation')=='incidents-execute-v1']
    assert len(routes)==3
    for owner in ['mcp','gateway','ingestion']:
        result=execute(owner,{'limit':2,'state':'RECOVERING','until':'2026-09-22T00:00:00Z'})
        assert json.loads(result.body)['state']=='RECOVERING'
        assert (b'x-ouf-delegation' in result.headers)==(owner=='mcp')
        assert (b'x-ouf-operational-receipt' in result.headers)==(owner!='mcp')
    with pytest.raises(Denied):execute(scope=False)

@pytest.mark.parametrize('args',[{'limit':101},{'url':'https://attacker'},{'cursor':'x'*8193},{'state':'HEALTHY'},{'severity':'DEBUG'}])
def test_rejects_unbounded_or_unknown_input(args):
    with pytest.raises(Denied):execute(arguments=args)

@pytest.mark.parametrize('severity',['INFO','WARNING','ERROR','CRITICAL'])
def test_all_normative_severities_cross_schema_and_lua(severity):
    import jsonschema
    doc=materialize(runtime(),'$ENV://OIDC','DELEGATION_KEY','OWNER_KEY')
    for owner in ['mcp','gateway','ingestion']:
        result=execute(owner,{'severity':severity})
        assert json.loads(result.body)['severity']==severity
    for route in doc['routes']:
        if route.get('labels',{}).get('ouf-mediation')=='incidents-execute-v1':
            args=route['plugins']['request-validation']['body_schema']['properties']['Arguments']
            jsonschema.validate({'severity':severity},args)
