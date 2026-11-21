import base64
import hashlib
import hmac
import json
from urllib.parse import parse_qsl, quote_from_bytes, urlsplit

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from tests.test_execute_delegation import Denied, Engine, INSTALL, envelope, human, proof, workload
from tests.test_source_revision import OWNER_KEY
from tools.materialize_schema_notices import CAPABILITY, PATH, SCHEMA

CURSOR = 'a&limit=999 +/%?#\u00e8'


def notice_request():
    return dict(envelope(), CapabilityID=CAPABILITY, GatewayBindingRef='capability://' + CAPABILITY,
                OperationClass='READ', Owner='onboarding', MaxResultBytes=65536,
                Arguments={'state': 'OPEN', 'limit': 20, 'after': CURSOR})


@pytest.mark.parametrize('args,valid', [
    ({'state': 'OPEN', 'limit': 1}, True), ({'state': 'OPEN', 'limit': 100, 'after': 'x'*1024}, True),
    ({'state': 'OPEN', 'limit': 100, 'after': '\u00e8'*1024}, True),
    ({'state': 'OPEN'}, False), ({'limit': 1}, False), ({'state': 'RESOLVED', 'limit': 1}, False),
    *[({'state': 'OPEN', 'limit': n}, False) for n in (0, 101, 1.5, True, '20')],
    *[({'state': 'OPEN', 'limit': 1, 'after': s}, False) for s in ('', None, 'x'*1025)],
    ({'state': 'OPEN', 'limit': 1, 'tenant': 'another'}, False),
])
def test_notice_schema(args, valid):
    validator = Draft202012Validator(json.loads(SCHEMA.read_text()), format_checker=FormatChecker())
    assert validator.is_valid(dict(notice_request(), Arguments=args)) == valid
    assert not validator.is_valid(dict(notice_request(), MaxResultBytes=65537))


def check_notice_execution(route, *, size=65536, declared=False, expected=200, scope=CAPABILITY,
                           claims=None, status=200, elapsed=0, timeout=False, after=CURSOR, maximum=65536):
    dispatch = notice_request()
    dispatch['MaxResultBytes'] = maximum
    if after is None:
        del dispatch['Arguments']['after']
    headers = {'X-OUF-Delegation': proof(dict(human(), scope=scope)), 'X-Correlation-ID': dispatch['CorrelationID'],
               'Idempotency-Key': dispatch['IdempotencyKey'], 'X-Tool-Attempt-ID': dispatch['AttemptID'],
               'Cookie': 'session', 'X-OUF-Schema-Notices-Receipt': 'forged'}
    engine = Engine(claims or workload(), headers, dispatch, uri=route['uri'])
    lua = engine.lua
    g = lua.globals()
    g[b'OWNER_KEY'] = OWNER_KEY
    g[b'OWNER_ENV'] = route['labels']['ouf-owner-key-env'].encode()
    g[b'ngx'][b'escape_uri'] = lambda value: quote_from_bytes(value, safe='').encode()
    g[b'size'], g[b'declared'], g[b'status'], g[b'elapsed'] = size, declared, status, elapsed
    g[b'timeout'] = timeout
    lua.execute(b"""
        os.getenv = function(name) if name == OWNER_ENV then return OWNER_KEY end return TEST_KEY end
        ngx.header = {}
        ngx.now = function() return 1000 + elapsed end
        ngx.req.start_time = function() return 1000 end
        ngx.print = function(s) output=s end
        ngx.sleep = function(t) assert(t == 3-elapsed) end
        ngx.thread = {spawn=function(f) return f end, wait=function(timer,reader)
                          if timeout then return true,timer() end
                          return pcall(reader)
                      end, kill=function() end}
        client = {set_timeout=function(_,t) assert(t==3000) end,
                  connect=function(_,host,port)
                      assert(type(host)=='string' and type(port)=='number', 'expected TCP host and port')
                      dest={host=host,port=port}; return true
                  end, close=function() closed=true end,
                  request=function(_,r)
                      request=r
                      return {status=status, headers={['Content-Length']=declared and tostring(size) or nil},
                              body_reader=function(n)
                                  if size==0 then return nil end
                                  n=math.min(size,n); size=size-n; return string.rep('x',n)
                              end}
                  end}
    """)
    engine.modules[b'resty.http'] = lua.eval(b'{new=function() return client end}')
    ctx = engine.modules[b'cjson.safe'][b'decode'](json.dumps({'matched_route': {'value': route}}).encode())
    source, = route['plugins']['serverless-post-function']['functions']
    with pytest.raises(Denied) as result:
        lua.execute(source.encode())(None, ctx)
    assert result.value.args == (expected,)
    assert g[b'output'] == (b'x'*size if expected == 200 else None)
    if expected in (403, 504) and status == 200:
        assert g[b'request'] is None
        return
    assert g[b'closed']
    node, = route['upstream']['nodes']
    assert (g[b'dest'][b'host'].decode(), g[b'dest'][b'port']) == (node['host'], node['port'])
    request = g[b'request']
    target = request[b'path'].decode()
    parts = urlsplit(target)
    assert request[b'method'] == b'GET' and parts.path == PATH and not parts.fragment
    pairs = [('state', 'OPEN'), ('limit', '20')]
    if after is not None:
        pairs.append(('after', after))
    assert parse_qsl(parts.query) == pairs
    outgoing = dict(request[b'headers'].items())
    assert set(outgoing) == {b'Accept', b'X-Correlation-ID', b'X-OUF-Schema-Notices-Receipt'}
    encoded, signature = outgoing[b'X-OUF-Schema-Notices-Receipt'].split(b'.')
    decode = lambda value: base64.urlsafe_b64decode(value + b'=' * (-len(value) % 4))
    assert hmac.compare_digest(decode(signature), hmac.digest(OWNER_KEY, b'ouf-schema-notices-owner-v1.' + encoded, hashlib.sha256))
    receipt = json.loads(decode(encoded))
    assert (receipt['method'], receipt['path'], receipt['subject'], receipt['tenant'], receipt['capability']) == (
        'GET', target, 'human-a', 'tenant-a', CAPABILITY)


@pytest.fixture(scope='module')
def notice_route(tmp_path_factory):
    from tests.release_bundle_fixture import ci_profile, load_release_routes
    from tools.gateway_release_bundle import generate
    output = tmp_path_factory.mktemp('notice-release')
    source = ('0'*40, '.github/workflows/ci.yml', '1')
    generate(output, *source)
    profile = ci_profile(dict(INSTALL, installationId='portable', revision=2), 18888)
    return next(r for r in load_release_routes(output, *source, profile) if r['id'] == 'mcp-onboarding-schema-notices-read')


@pytest.mark.parametrize('case', [
    {'after': None}, {'size': 65537, 'expected': 502}, {'size': 65537, 'declared': True, 'expected': 502},
    {'maximum': 2, 'size': 3, 'expected': 502}, {'scope': 'mcp.connect', 'expected': 403},
    {'claims': dict(workload(), azp='another'), 'expected': 403},
    {'claims': dict(workload(), tenant_id='another'), 'expected': 403},
    {'status': 503, 'expected': 503}, {'status': 403, 'expected': 403},
    {'elapsed': 3, 'expected': 504}, {'elapsed': 1, 'timeout': True, 'expected': 504},
])
def test_notice_dispatch(notice_route, case):
    check_notice_execution(notice_route, **case)
