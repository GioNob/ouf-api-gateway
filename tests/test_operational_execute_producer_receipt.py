"""Real Lua execution and an independent verifier of the historical owner contract."""
import base64
import copy
import hashlib
import hmac
import json
import re
import subprocess
import sys

import pytest

from tools.delegation_functions import ROOT as LUA_ROOT, function
from tools.materialize_operational_execute import CAPABILITIES, materialize, producer_receipt_keys
from tests.test_execute_delegation import Denied, Engine, INSTALL, KEY, human, proof, workload
from tests.test_operational_execute_delegation import dispatch
from tests import test_operational_execute_upstream_bindings as bindings


# Synthetic names and values: no installation settings or real keys.
RECEIPT_ENV = 'TEST_PRODUCER_RECEIPT_KEY'
RECEIPT_KEY = 'Cd12' * 16
PRODUCERS = [cap for cap, binding in CAPABILITIES.items() if binding[0] != 'mcp']


def serialized(value):
    return json.dumps(value, separators=(',', ':')).encode()


def baseline_function(kind, installation, key_env, operational_binding):
    """Frozen main@98d01f4 renderer, using the original Lua snapshot below.

    Do not read Git history at test time: CI may have a shallow checkout.
    The unchanged delegation helper is shared; operational source is frozen.
    """
    assert kind == 'execute_operational'
    constants = dict(DELEGATION_KEY_ENV=key_env, ISSUER=installation['issuerUrl'].rstrip('/'),
                     AUDIENCE=installation['gatewayAudience'], MCP_WORKLOAD=installation['mcpServiceIdentity'],
                     CAPABILITY=operational_binding['capability'], OWNER=operational_binding['owner'],
                     REQUIRED_SCOPE=operational_binding['scope'])
    header = '\n'.join(f'local {key} = {json.dumps(value)}' for key, value in constants.items())
    return ('return function(conf, ctx)\n' + header + '\n' +
            (LUA_ROOT / 'delegation.lua').read_text() + '\n' + BASELINE_OPERATIONAL_LUA + '\nend')


@pytest.fixture(scope='module')
def rt():
    return bindings.runtime(bindings.IDENTITY)


@pytest.mark.parametrize('settings', [None, {}])
def test_no_receipts_preserves_all_six_main_routes_byte_for_byte(rt, monkeypatch, settings):
    # The existing reference reconstructs every original field/plugin/schema.
    # Freeze its renderer too, so a changed Lua body cannot self-validate.
    monkeypatch.setattr(bindings, 'function', baseline_function)
    baseline = bindings.operational_routes(bindings.before_change_identity_output(rt))
    current = bindings.operational_routes(materialize(
        rt, '$ENV://OIDC', 'DELEGATION_KEY', producer_receipt_key_envs=settings))
    assert len(current) == len(baseline) == 6
    for uri in baseline:
        assert serialized(current[uri]) == serialized(baseline[uri])


def test_gateway_optin_changes_only_its_two_lua_functions(rt):
    original = copy.deepcopy(rt)
    baseline = materialize(rt, '$ENV://OIDC', 'DELEGATION_KEY')
    enabled = materialize(rt, '$ENV://OIDC', 'DELEGATION_KEY',
                          producer_receipt_key_envs={'gateway': RECEIPT_ENV})
    routes = bindings.operational_routes(enabled)
    assert len(routes) == 6
    for capability, (owner, *_) in CAPABILITIES.items():
        route = routes['/internal/capabilities/v1/execute/' + capability]
        source = route['plugins']['serverless-post-function']['functions'][0]
        if owner == 'gateway':
            assert source.count('local RECEIPT_KEY_ENV = ') == 1
            assert f'local RECEIPT_KEY_ENV = "{RECEIPT_ENV}"' in source
            assert (f'local REQUIRED_SCOPE = "{CAPABILITIES[capability][4]}"\n'
                    f'local RECEIPT_KEY_ENV = "{RECEIPT_ENV}"\n') in source
            assert 'ouf-operational-owner-v1.' in source
            assert '-- BEGIN PRODUCER RECEIPT' not in source
            previous = next(r for r in baseline['routes'] if r['id'] == route['id'])
            route['plugins']['serverless-post-function']['functions'] = copy.deepcopy(
                previous['plugins']['serverless-post-function']['functions'])
        else:
            assert 'RECEIPT_KEY_ENV' not in source
    # Includes the other four complete routes and every non-Lua gateway field.
    assert serialized(enabled) == serialized(baseline)
    assert rt == original


def execute_receipt(capability, key=RECEIPT_KEY, now=1000, roles=None, enabled=True):
    context = human()
    context['scope'] += ' operations.incident.read'
    if roles is not None:
        context['externalRoleRefs'] = roles
    body = dispatch(capability, {'limit': 7, 'since': '2026-10-11T00:00:00Z'}, nested=True)
    headers = {'X-OUF-Delegation': proof(context), 'X-Correlation-ID': body['CorrelationID'],
               'Idempotency-Key': body['IdempotencyKey'], 'X-Tool-Attempt-ID': body['AttemptID'],
               'X-OUF-Operational-Receipt': 'client-forged-receipt',
               'X-OUF-Principal-ID': 'forged-subject', 'X-OUF-External-Role-Refs': 'forged-admin'}
    engine = Engine(workload(), headers, body, now=now)
    # Distinct environment names and keys prove the signing key is selected,
    # rather than accidentally using the delegation key or decoding hex bytes.
    env = {b'TEST_KEY': KEY.encode()}
    if key is not None:
        env[RECEIPT_ENV.encode()] = key.encode()
    engine.lua.globals()[b'os'][b'getenv'] = lambda name: env.get(name)
    owner, _, _, _, scope, _ = CAPABILITIES[capability]
    source = function('execute_operational', INSTALL, 'TEST_KEY',
                      owner_key_env=RECEIPT_ENV if enabled else None,
                      operational_binding={'capability': capability, 'owner': owner, 'scope': scope})
    engine.lua.execute(source.encode())(None, None)
    return engine, body, context


def verify_owner_receipt(signed, forwarded_body, capability, now):
    """Python port of owner checks, independent of the Lua signer/harness crypto.

    Summary: 81fdf7a SummaryReceiptFilter; incidents: its 24eba09 extension.
    Deliberately hardcode protocol paths/scopes here, without CAPABILITIES.
    """
    assert re.fullmatch(rb'[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', signed)
    payload, signature = signed.split(b'.')
    decode = lambda value: base64.urlsafe_b64decode(value + b'=' * (-len(value) % 4))
    expected = hmac.digest(RECEIPT_KEY.encode('ascii'), b'ouf-operational-owner-v1.' + payload, 'sha256')
    assert hmac.compare_digest(expected, decode(signature))
    receipt = json.loads(decode(payload))
    owner, operation = capability.split('.')[1], capability.split('.')[-1]
    assert receipt['v'] == 1 and type(receipt['v']) is int
    assert type(receipt['iat']) is int and type(receipt['exp']) is int
    assert receipt['iat'] <= now < receipt['exp']
    assert 0 < receipt['exp'] - receipt['iat'] <= 30
    assert receipt['purpose'] == 'operational-summary-owner'
    assert receipt['method'] == 'POST'
    assert receipt['path'] == f'/api/internal/v1/{owner}/operations/{operation}'
    assert receipt['capability'] == capability
    assert receipt['bodyHash'] == hashlib.sha256(forwarded_body).hexdigest()
    required_scope = 'operations.incident.read' if operation == 'incidents' else 'operations.status.read'
    assert required_scope in receipt['scope'].split(' ')
    assert len(receipt['roles'].split()) <= 32
    return receipt


@pytest.mark.parametrize('capability', PRODUCERS)
@pytest.mark.parametrize('roles', [None, ['ouf:viewer', 'ouf:reader']])
@pytest.mark.parametrize('now,expires', [(1000, 1030), (1045, 1060)])
def test_signed_receipt_matches_independent_owner_contract(capability, roles, now, expires):
    engine, body, context = execute_receipt(capability, now=now, roles=roles)
    receipt = verify_owner_receipt(engine.headers[b'x-ouf-operational-receipt'], engine.body, capability, now)
    assert receipt == dict(v=1, purpose='operational-summary-owner', method='POST',
        path=f"/api/internal/v1/{body['Owner']}/operations/{capability.split('.')[-1]}",
        capability=capability, tenant=context['tenant_id'], issuer=context['iss'], audience=context['aud'],
        workload=INSTALL['mcpServiceIdentity'], bodyHash=hashlib.sha256(engine.body).hexdigest(),
        subject=context['sub'], client=context['azp'], acr=context['acr'],
        roles=' '.join(sorted(roles or [])), scope=context['scope'],
        decisionRef=body['AuthorizationDecisionRef'], iat=now, exp=expires)
    assert json.loads(engine.body) == body['Arguments']
    assert engine.body != serialized(body)  # Receipt binds the forwarded query, not the envelope.
    assert b'x-ouf-delegation' not in engine.headers
    assert b'x-ouf-delegation-verified' not in engine.headers
    assert b'authorization' not in engine.headers


@pytest.mark.parametrize('capability', PRODUCERS)
@pytest.mark.parametrize('key', [None, '', 'a' * 63, 'a' * 65, 'g' * 64, 'a' * 63 + '\n'])
def test_missing_or_malformed_receipt_key_fails_503(capability, key):
    with pytest.raises(Denied) as denied:
        execute_receipt(capability, key=key)
    assert denied.value.args == (503,)


@pytest.mark.parametrize('capability', CAPABILITIES)
def test_client_receipt_is_removed_without_optin(capability):
    engine, _, _ = execute_receipt(capability, enabled=False)
    assert b'x-ouf-operational-receipt' not in engine.headers
    if CAPABILITIES[capability][0] == 'mcp':
        assert engine.headers[b'x-ouf-delegation-verified'] == b'mcp-operational-aggregate-v1'


@pytest.mark.parametrize('settings,error', [
    ({'mcp': RECEIPT_ENV}, 'invalid producer receipt owner'),
    ({'other': RECEIPT_ENV}, 'invalid producer receipt owner'),
    ({'gateway': 'DELEGATION_KEY'}, 'must differ from delegation'),
    ([('gateway', RECEIPT_ENV), ('gateway', 'TEST_OTHER')], 'duplicate producer receipt owner'),
    ('gateway=TEST_KEY', 'must be an owner/environment map'),
    ([('gateway',)], 'requires owner/environment pair'),
])
def test_invalid_receipt_settings_are_explicit(rt, settings, error):
    with pytest.raises(ValueError, match=error):
        materialize(rt, '$ENV://OIDC', 'DELEGATION_KEY', producer_receipt_key_envs=settings)


@pytest.mark.parametrize('name', ['', 'a', '_TEST', '1TEST', 'TEST-KEY', 'A' * 129,
                                 'TEST\n', ' TEST', None, 42])
def test_invalid_environment_names_rejected(rt, name):
    with pytest.raises(ValueError, match='invalid producer receipt key environment name'):
        materialize(rt, '$ENV://OIDC', 'DELEGATION_KEY', producer_receipt_key_envs={'gateway': name})


@pytest.mark.parametrize('name', ['A', 'A9_', 'Z' + '9_' * 63 + '9'])
def test_valid_environment_name_boundaries(name):
    assert producer_receipt_keys({'gateway': name}, 'TEST_DELEGATION') == {'gateway': name}


@pytest.mark.parametrize('owner,name', [('mcp', RECEIPT_ENV), ('gateway', 'TEST_KEY'),
                                       ('gateway', 'invalid-key')])
def test_renderer_also_validates_optional_receipt(owner, name):
    capability = 'ouf.operations.summary' if owner == 'mcp' else 'ouf.gateway.operations.summary'
    with pytest.raises(ValueError, match='producer receipt key environment'):
        function('execute_operational', INSTALL, 'TEST_KEY', owner_key_env=name,
                 operational_binding={'capability': capability, 'owner': owner, 'scope': 'operations.status.read'})


@pytest.mark.parametrize('settings', [[], ['gateway=' + RECEIPT_ENV],
                                   ['ingestion=TEST_INGESTION_RECEIPT', 'gateway=' + RECEIPT_ENV]])
def test_cli_receipt_configuration(rt, tmp_path, settings):
    source, target = tmp_path / 'runtime.json', tmp_path / 'routes.json'
    source.write_text(json.dumps(rt))
    command = [sys.executable, '-m', 'tools.materialize_operational_execute', '--runtime', str(source),
               '--oidc-client-secret-ref', '$ENV://OIDC', '--delegation-key-env', 'DELEGATION_KEY',
               '--output', str(target)]
    for setting in settings:
        command += ['--producer-receipt-key-env', setting]
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    assert json.loads(target.read_text()) == materialize(rt, '$ENV://OIDC', 'DELEGATION_KEY',
        producer_receipt_key_envs=dict(setting.split('=') for setting in settings))


@pytest.mark.parametrize('settings,error', [
    (['gateway=TEST_A', 'gateway=TEST_B'], 'duplicate producer receipt owner'),
    (['mcp=TEST_A'], 'invalid producer receipt owner'),
    (['unknown=TEST_A'], 'invalid producer receipt owner'),
    (['gateway=bad-key'], 'invalid producer receipt key environment name'),
    (['gateway=DELEGATION_KEY'], 'must differ from delegation'),
    (['gateway'], 'requires owner/environment pair'),
])
def test_cli_rejects_invalid_receipt_settings_before_output(tmp_path, settings, error):
    target = tmp_path / 'routes.json'
    command = [sys.executable, '-m', 'tools.materialize_operational_execute', '--runtime', 'unused.json',
               '--oidc-client-secret-ref', '$ENV://OIDC', '--delegation-key-env', 'DELEGATION_KEY',
               '--output', str(target)]
    for setting in settings:
        command += ['--producer-receipt-key-env', setting]
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    assert result.returncode == 2
    assert error in result.stderr
    assert not target.exists()


# Snapshot from main@98d01f4, kept inline within the authorized test scope.
BASELINE_OPERATIONAL_LUA = r"""local claims = jwt_claims()
if type(claims) ~= 'table' or claims.iss ~= ISSUER or not audience_has(claims.aud, AUDIENCE)
    or claims.ouf_actor_type ~= 'SERVICE' or (claims.azp or claims.client_id) ~= MCP_WORKLOAD
    or type(claims.exp) ~= 'number' or claims.exp <= ngx.time() then return fail(403) end
local proof = ngx.req.get_headers()['x-ouf-delegation']
if type(proof) ~= 'string' or #proof > 16384 then return fail(403) end
local payload, signature = proof:match('^([%w_-]+)%.([%w_-]+)$')
if not payload or not signature then return fail(403) end
local expected = sign(payload)
if not expected then return fail(503) end
if not same(expected, decode64(signature)) then return fail(403) end
local raw = decode64(payload)
local p = raw and cjson.decode(raw)
local now = ngx.time()
if type(p) ~= 'table' or p.v ~= 1 or p.purpose ~= 'mcp-execute' or p.iss ~= ISSUER
    or p.aud ~= AUDIENCE or p.workload ~= MCP_WORKLOAD or p.actor ~= 'HUMAN'
    or type(p.iat) ~= 'number' or type(p.exp) ~= 'number' or p.iat > now or p.exp <= now
    or p.exp-p.iat > 60 or p.tenant ~= claims.tenant_id
    or not scope_has(p.scope, REQUIRED_SCOPE) then return fail(403) end
for _, key in ipairs({'principal','tenant','acr','client','scope'}) do
    if not text(p[key]) then return fail(403) end
end
local roles = role_header(p.roles)
if roles == nil then return fail(403) end
ngx.req.read_body()
local body = ngx.req.get_body_data()
if not body or #body > 65536 then return fail(413) end
local e = cjson.decode(body)
if type(e) ~= 'table' or type(e.Identity) ~= 'table' or type(e.Arguments) ~= 'table' then return fail(400) end
local i = e.Identity
if i.PrincipalID ~= p.principal or i.TenantID ~= p.tenant or i.ActorType ~= p.actor
    or i.AuthenticationContextRef ~= p.acr
    or (i.ServicePrincipalID ~= p.client and i.ServicePrincipalID ~= MCP_WORKLOAD) then return fail(403) end
if e.CapabilityID ~= CAPABILITY or e.GatewayBindingRef ~= 'capability://'..CAPABILITY
    or e.Owner ~= OWNER or e.OperationClass ~= 'READ' then return fail(403) end
local headers = ngx.req.get_headers()
if headers['x-correlation-id'] ~= e.CorrelationID or headers['idempotency-key'] ~= e.IdempotencyKey
    or headers['x-tool-attempt-id'] ~= e.AttemptID then return fail(409) end
local all, err = ngx.req.get_headers(0)
if err then return fail(400) end
for name, _ in pairs(all) do
    local lower = name:lower()
    if lower:sub(1,6) == 'x-ouf-' or lower == 'authorization' or lower == 'cookie'
        or lower == 'x-access-token' or lower == 'x-id-token' or lower == 'x-userinfo' then ngx.req.clear_header(name) end
end
local downstream = {
    ['X-OUF-Gateway-Verified']='true', ['X-OUF-Service-Principal']=MCP_WORKLOAD,
    ['X-OUF-Principal-ID']=p.principal, ['X-OUF-Tenant-ID']=p.tenant,
    ['X-OUF-Actor-Type']=p.actor, ['X-OUF-Authentication-Context-Ref']=p.acr,
    ['X-OUF-Token-Issuer']=p.iss, ['X-OUF-Token-Audience']=p.aud,
    ['X-OUF-Granted-Scopes']=p.scope, ['X-OUF-Capability-ID']=CAPABILITY,
    ['X-OUF-Authorization-Decision-Ref']=e.AuthorizationDecisionRef
}
for name, value in pairs(downstream) do ngx.req.set_header(name, value) end
if roles ~= '' then ngx.req.set_header('X-OUF-External-Role-Refs', roles) end
-- Only the aggregate MCP owner needs another governed hop. Producers and
-- public status must not receive the delegation proof or workload bearer.
if OWNER == 'mcp' then
    ngx.req.set_header('X-OUF-Delegation', proof)
    ngx.req.set_header('X-OUF-Delegation-Verified', 'mcp-operational-aggregate-v1')
end
ngx.req.set_body_data(cjson.encode(e.Arguments))
ngx.req.set_header('Content-Type','application/json')
"""
