import copy
import json
import pytest
from jsonschema import Draft7Validator, FormatChecker
from tests.test_execute_delegation import Engine, Denied, envelope, human, workload, proof, runtime
from tools.materialize_summary import materialize

CAP='ouf.operations.summary'
def summary_envelope(cap=CAP,owner='mcp'):
    e=envelope();e.update(CapabilityID=cap,Owner=owner,GatewayBindingRef='capability://'+cap,Arguments={'limit':5},MaxResultBytes=524288,AuthorizationDecisionRef='bundle:6:'+cap)
    return e

def run(e=None,p=None,**kwargs):
    e=e or summary_envelope()
    engine=Engine(workload(),{'X-OUF-Delegation':p or proof(),'X-Correlation-ID':'corr','Idempotency-Key':'idem','X-Tool-Attempt-ID':e['AttemptID'],'Cookie':'secret'},e,**kwargs)
    engine.lua.globals()[b'ngx'][b'var'][b'request_uri']=('/internal/capabilities/v1/execute/'+e['CapabilityID']).encode()
    engine.lua.globals()[b'ngx'][b'var'][b'uri']=('/api/internal/v1/'+e['Owner']+'/operations/summary').encode()
    engine.run('execute_summary')
    return engine

def test_summary_preserves_verified_delegation_only_on_mcp_owner_hop():
    signed=proof();result=run(p=signed)
    assert result.headers[b'x-ouf-delegation']==signed.encode()
    assert result.headers[b'x-ouf-service-principal']==b'chatgpt'
    assert b'authorization' not in result.headers and b'cookie' not in result.headers
    assert json.loads(result.body)=={'limit':5}
    for owner in ('ingestion','gateway'):
        result=run(summary_envelope('ouf.'+owner+'.operations.summary',owner))
        assert b'x-ouf-delegation' not in result.headers

@pytest.mark.parametrize('field,value',[('Owner','udp'),('CapabilityID','urban.merge.confirm'),('GatewayBindingRef','capability://other'),('Arguments',{'url':'https://attacker'}),('Arguments',{'limit':101}),('Arguments',{'limit':0})])
def test_summary_rejects_unbound_input(field,value):
    e=summary_envelope();e[field]=value
    with pytest.raises(Denied):run(e)

def test_summary_rejects_revoked_scope_expiry_and_tampering():
    c=human();c['scope']='mcp.connect'
    for p in [proof(c),proof()[:-4]+'abcd']:
        with pytest.raises(Denied):run(p=p)
    with pytest.raises(Denied):run(now=1061)

def test_materialized_summary_has_closed_fixed_routes_and_preserves_existing_routes():
    doc=materialize(runtime(),'$ENV://OIDC','DELEGATION_KEY','OWNER_KEY')
    routes=[r for r in doc['routes'] if r.get('labels',{}).get('ouf-mediation')=='summary-execute-v1']
    assert len(routes)==3
    assert any(r.get('uri')=='/internal/capabilities/v1/execute' for r in doc['routes'])
    assert any(r.get('uri','').endswith('/authorization/propose') for r in doc['routes'])
    for r in routes:
        assert r['upstream']['retries']==0
        assert r['plugins']['proxy-rewrite']['uri']!='/mcp'
        cap=r['uri'].split('/')[-1];owner=cap.split('.')[1] if cap!=CAP else 'mcp'
        validator=Draft7Validator(r['plugins']['request-validation']['body_schema'],format_checker=FormatChecker())
        e=summary_envelope(cap,owner);validator.validate(e)
        e['Arguments']['since']='not-a-date';assert list(validator.iter_errors(e))
        e=summary_envelope(cap,owner);e['Arguments']['limit']=True;assert list(validator.iter_errors(e))

@pytest.mark.parametrize('field,value',[('service_id','attacker'),('owner','udp'),('requiredScope','admin'),('allowedActorTypes',['SERVICE'])])
def test_materialization_rejects_configuration_drift(field,value):
    rt=runtime();r=next(r for r in rt['routes'] if r.get('labels',{}).get('exposure')=='internal' and (r.get('x-ouf-capability')or{}).get('capabilityId')==CAP)
    if field=='service_id':r[field]=value
    elif field=='owner':r['x-ouf-capability'][field]=value
    else:r['x-ouf-policy'][field]=value
    with pytest.raises(ValueError):materialize(rt,'$ENV://OIDC','KEY','OWNER_KEY')

def test_gateway_owner_fails_closed_without_local_policy_and_tenant(tmp_path):
    from tools.gateway_operational_api import GatewayOperationalOwnerAPI
    from tools.operational_incidents import SQLiteOperationalIncidentStore
    store=SQLiteOperationalIncidentStore(tmp_path/'incidents.db')
    headers={'X-OUF-Gateway-Verified':'true','X-OUF-Principal-ID':'reader','X-OUF-Authorization-Decision-Ref':'bundle:1','X-OUF-Tenant-ID':'tenant-a'}
    api=GatewayOperationalOwnerAPI(store)
    assert api.handle(api.SUMMARY_PATH,headers)[0]==503
    api=GatewayOperationalOwnerAPI(store,summary_authorizer=lambda *args:False,tenant_id='tenant-a')
    assert api.handle(api.SUMMARY_PATH,headers)[0]==403
    api=GatewayOperationalOwnerAPI(store,summary_authorizer=lambda *args:True,tenant_id='tenant-b')
    assert api.handle(api.SUMMARY_PATH,headers)[0]==403
    api=GatewayOperationalOwnerAPI(store,summary_authorizer=lambda *args:True,tenant_id='tenant-a')
    assert api.handle(api.SUMMARY_PATH,headers)[0]==200
    store.close()

def test_old_open_incident_is_not_hidden_by_recent_small_page(tmp_path):
    from datetime import datetime,timedelta,timezone
    from tools.operational_incidents import SQLiteOperationalIncidentStore
    now=datetime(2026,9,20,tzinfo=timezone.utc)
    clock=[now-timedelta(days=2)]
    store=SQLiteOperationalIncidentStore(tmp_path/'incidents.db',clock=lambda:clock[0])
    store.open_incident(dedup_key='old',event_type='FAILURE',severity='ERROR',error_code='FAIL',impact_summary='Unavailable',visibility_class='TENANT_OPERATIONAL')
    clock[0]=now
    store.open_incident(dedup_key='new',event_type='FAILURE',severity='ERROR',error_code='FAIL',impact_summary='Unavailable',visibility_class='TENANT_OPERATIONAL')
    store.resolve_incident('new','Recovered')
    result=store.summary(limit=1)
    assert result['status']=='DEGRADED' and result['openIncidents']==1
    assert result['items'][0]['lifecycle_state']=='RESOLVED'
    store.close()
