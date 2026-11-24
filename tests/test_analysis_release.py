"""Exercise the mandate entry point through the same execute Lua released for interactive requests."""
import base64
import hashlib
import hmac
import json

import pytest
from jsonschema import Draft7Validator, FormatChecker

from tests.release_bundle_fixture import MANDATE_IDS
from tests import test_analysis_mandate as fixtures
from tests.test_analysis_mandate import KEY, OP, PROFILE
from tests.test_execute_delegation import Denied, Engine, workload
from tests.test_value_type_schemas import matched_route_context, routes, run_dispatch_rewrite
from tools.analysis_protocol import BINDINGS, SEARCH_BATCH, Catalog, parse, wire
from tools.analysis_protocol import delegation
from tools.analysis_mandate import new_ref
from tools.mcp_dispatch_contract import capability_contracts
from tools.plan_semantic_search import restore_plan, search_plan


@pytest.mark.parametrize('operation,route_id', [(OP, 'mcp-semantic-discovery-request'),
                                               (SEARCH_BATCH, 'mcp-semantic-search-batch')])
def test_receipt_at_owner_and_expiry(routes, operation, route_id):
    """GW-51N-09. Time, actual bytes and owner path checked against the materialized owner MAC."""
    pet = fixtures.MandatePET()
    pet.setUp()
    try:
        route = routes[route_id]
        # Match the fixture installation to the synthetic tokens generated in this PET.
        route = dict(route, labels={**route['labels'], 'ouf-audience':'gateway', 'ouf-mcp-workload':'worker'})
        route['plugins'] = {**route['plugins'], 'openid-connect': {
            **route['plugins']['openid-connect'], 'claim_validator': {'issuer':{'valid_issuers':[pet.iam.issuer]}}}}
        cap = BINDINGS[operation][0]
        snap = dict(capability_contracts()[cap], publicationState='ACTIVE', toolName=operation)
        catalog = Catalog(wire({'capabilities':[snap]}))
        pet.api.catalog = catalog
        scope = 'ouf.semantic.search' if operation == SEARCH_BATCH else 'ouf.semantic.discovery'
        proof = delegation(dict(v=1, purpose='mcp-execute', iss=pet.iam.issuer, aud='gateway', workload='worker',
                                actor='HUMAN', tenant='tenant', principal='human', iat=1000, exp=1060,
                                acr='interactive', client='human-client', scope=scope), KEY)
        issue = dict(pet.issue, analysisId='e'*64, manifestChecksum=catalog.checksum, commandKey=new_ref())
        status, mandate, _ = pet.send('issue', issue, proof)
        assert status == 200
        b = dict(pet.b, analysisId=issue['analysisId'], mandateId=mandate['mandateId'], operation=operation)
        if operation == SEARCH_BATCH:
            b['arguments'] = dict(contract='ouf.semantic.published-batch.v1', limitPerIntent=3,
                                  intents=[dict(intentId='g', intent='città', preferredLanguages=['it'],
                                                requestedArtifactType='CLASS', context={})])
        pet.server.reserve(b)
        check = pet.server.evidence
        pet.server.evidence = lambda *args: dict(check(*args), manifestChecksum=catalog.checksum)
        verified = []
        def execute(body, headers, limit, suffix):
            assert suffix == route['uri']
            obj = parse(body)
            Draft7Validator(route['plugins']['request-validation']['body_schema'], format_checker=FormatChecker()).validate(obj)
            claims = dict(workload(), iss=pet.iam.issuer, azp='worker', tenant_id='tenant')
            eng = Engine(claims, headers, obj, now=pet.now, uri=suffix)
            eng.body = body
            eng.lua.globals()[b'os'][b'getenv'] = {
                b'DELEGATION_KEY': KEY, b'READ_KEY': b'56'*32, b'DISCOVERY_KEY': b'56'*32}.get
            ctx = matched_route_context(eng, route)
            run_dispatch_rewrite(eng, route, ctx)
            post, = route['plugins']['serverless-post-function']['functions']
            eng.lua.execute(post.encode())(None, ctx)
            kind = 'read' if operation == SEARCH_BATCH else 'discovery'
            token = eng.headers[f'x-ouf-semantic-{kind}-receipt'.encode()]
            encoded, mac = token.split(b'.')
            assert hmac.compare_digest(hmac.digest(b'56'*32, f'ouf-semantic-{kind}-owner-v1.'.encode()+encoded, 'sha256'),
                                       base64.urlsafe_b64decode(mac+b'=='))
            receipt = json.loads(base64.urlsafe_b64decode(encoded+b'==='))
            owner_path = route['plugins']['proxy-rewrite']['uri']
            def accepts(raw, path, now):
                return (receipt['iat'] <= now < receipt['exp'] and receipt['method'] == 'POST' and receipt['path'] == path
                        and receipt['capability'] == cap and receipt['bodyHash'] == hashlib.sha256(raw).hexdigest())
            assert accepts(eng.body, owner_path, 1029)
            assert not accepts(eng.body, owner_path, 1030)
            assert not accepts(eng.body+b' ', owner_path, 1000)
            assert not accepts(eng.body, owner_path+'/other', 1000)
            assert b'x-ouf-delegation' not in eng.headers and b'authorization' not in eng.headers
            verified.append(token)
            return 200, wire({'requestId':PROFILE['assetId']}), None
        pet.owner.post.side_effect = execute
        for _ in range(2):
            b['attemptId'] = new_ref()
            pet.server.reserve(b)
            status, _, metadata = pet.send('dispatch', b, 'untrusted-caller-proof')
            assert status == 200 and metadata['X-Correlation-ID'] == metadata['X-OUF-Analysis-Decision']
        assert len(set(verified)) == 2
    finally:
        pet.doCleanups()


def test_second_plan_unchanged(routes):
    """GW-51N-10. Exact route resources round-trip through the governed installation plan."""
    targets = [routes[k] for k in MANDATE_IDS]
    revision = targets[0]['labels']['ouf-installation-revision']
    # GW-51P-09. Upgrade a task-51n inventory with one create and no updates.
    old = [r for r in routes.values() if r['id'] != 'mcp-analysis-mandate-status']
    upgraded = search_plan(targets, {'total': len(old), 'list': [{'value': r} for r in old]}, revision, mandates=True)
    assert {c.logical_id: c.action for c in upgraded} == {
        route_id: 'create' if route_id == 'mcp-analysis-mandate-status' else 'unchanged' for route_id in MANDATE_IDS}
    plan = search_plan(targets, {'total':0, 'list':[]}, revision, mandates=True)
    assert [c.action for c in plan] == ['create'] * 4
    readback = {'total':4, 'list':[{'value': c.after} for c in plan]}
    assert [c.action for c in search_plan(targets, readback, revision, mandates=True)] == ['unchanged'] * 4
    assert all(c.after is None for c in restore_plan(plan, readback))


@pytest.mark.parametrize('route_id', [*MANDATE_IDS, 'mcp-analysis-mandate-renewal-check',
                                     'onboarding-analysis-renewal-read', 'onboarding-analysis-renewal-decide'])
def test_private_route_forwards_only_selected_headers(routes, route_id):
    """GW-51N-11 / GW-55C-03. Execute the released private HTTPS relay with a synthetic upstream."""
    route = routes[route_id]
    engine = Engine(workload(), {'X-OUF-Delegation':'fixture-delegation', 'X-OUF-Principal-ID':'untrusted',
                                 'X-OUF-Semantic-Read-Receipt':'untrusted', 'Cookie':'untrusted'})
    engine.modules[b'resty.http'] = engine.lua.eval(b"""{
        new=function() return {
            set_timeout=function() end,
            connect=function(_,cfg) peer=cfg return true end,
            request=function(_,req)
                outgoing=req
                return {status=200,headers={},body_reader=function() return nil end}
            end,
            close=function() end
        } end
    }""")
    engine.lua.globals()[b'ngx'][b'print'] = lambda *_: None
    post, = route['plugins']['serverless-post-function']['functions']
    with pytest.raises(Denied, match='200'):
        engine.lua.execute(post.encode())(None, matched_route_context(engine, route))
    peer = engine.lua.globals()[b'peer']
    assert peer[b'ssl_verify'] and peer[b'scheme'] == b'https'
    assert peer[b'ssl_server_name'] == route['upstream']['nodes'][0]['host'].encode()
    req = engine.lua.globals()[b'outgoing']
    assert req[b'body'] == engine.body and req[b'path'] == route['uri'].encode()
    allowed = {b'Authorization', b'Content-Type'}
    if route_id in ('mcp-analysis-mandate-issue', 'mcp-analysis-mandate-revoke', 'mcp-analysis-mandate-renewal-check'):
        allowed.add(b'X-OUF-Delegation')
    assert set(req[b'headers'].keys()) == allowed


def test_status_relay_caps_upstream_response(routes):
    """GW-51P-10. The released Lua enforces the byte limit even across response chunks."""
    route = routes['mcp-analysis-mandate-status']
    engine = Engine(workload(), {})
    engine.modules[b'resty.http'] = engine.lua.eval(b"""{
        new=function() return {
            set_timeout=function() end, connect=function() return true end, close=function() end,
            request=function()
                local chunks = {string.rep('x', 1024), 'x'}
                return {status=200, headers={}, body_reader=function() return table.remove(chunks, 1) end}
            end
        } end
    }""")
    post, = route['plugins']['serverless-post-function']['functions']
    with pytest.raises(Denied, match='503'):
        engine.lua.execute(post.encode())(None, matched_route_context(engine, route))
