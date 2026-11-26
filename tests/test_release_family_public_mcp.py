"""GW-60e adoption evidence against the published bundle and the installed route images."""
import copy
import json
import re
from pathlib import Path

import pytest
from jsonschema import Draft7Validator

from ops.apisix import deploy_internal_m2m_routes, deploy_status_execute
from tests.public_mcp_fixture import BASELINE_3D69CB4_IDS
from tests.test_execute_delegation import Denied, Engine, INSTALL, execute, human
from tests.test_value_type_schemas import matched_route_context
from tests.release_bundle_fixture import canonical_json, ci_profile, load_release_routes, sha256
from tools.gateway_release_bundle import generate
from tools.plan_semantic_search import Change, changed_paths
from tools.release_family_public_mcp import ENDPOINT_ID, PROTECTED_RESOURCE_ROUTE_ID, PUBLIC_IDS, oauth_profile_values


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'tests/fixtures/public-mcp-before.json'
EXPORT = ROOT / '.codex-input/live-routes-60e.json'
INVENTORY = ROOT / '.codex-input/live-routes-all-98.json'
WORKFLOW = '.github/workflows/ci.yml'
COMMIT = '6' * 40


@pytest.fixture(scope='module')
def artifact(tmp_path_factory):
    directory = tmp_path_factory.mktemp('public-mcp')
    generate(directory, COMMIT, WORKFLOW, '60')
    return directory


def test_frozen_predecessor(artifact):
    """GW-60e-01. Only the explicit resource IDs of 3d69cb4 contribute to its digest."""
    resources = json.loads((artifact / 'bundle.json').read_bytes())['resources']
    retained = [item for item in resources if item['id'] in BASELINE_3D69CB4_IDS]
    assert len(retained) == 31
    assert sha256(canonical_json(retained)) == 'fd8252656d638689551ccecedc1d91a2fe46e3013b9ac12da931781b2f977cdc'


def check_delegation_lua(installed, released):
    marker = '-- This code runs only after'
    prefix, split, logic = released.partition(marker)
    assert prefix.splitlines() == [
        'return function(conf, ctx)', 'local route = ctx.matched_route.value',
        'local labels = route.labels', "local oidc = route.plugins['openid-connect']",
        'local issuer = oidc and oidc.claim_validator and oidc.claim_validator.issuer',
        'local issuers = issuer and issuer.valid_issuers',
        'local ISSUER = issuers and #issuers == 1 and issuers[1]',
        'local DELEGATION_KEY_ENV = labels["ouf-delegation-key-env"]',
        'local AUDIENCE = labels["ouf-audience"]', 'local MCP_WORKLOAD = labels["ouf-mcp-workload"]',
        'if not ISSUER or not AUDIENCE or not MCP_WORKLOAD or not DELEGATION_KEY_ENV then return ngx.exit(503) end',
    ]
    # The shared fail() gained the dispatch diagnostic. This issuing function
    # calls fail only for identity/authorization failures and missing key material.
    diagnostic = '''    if status == 400 then
        ngx.status = status
        ngx.header.content_type = 'application/problem+json'
        ngx.say('{"type":"urn:ouf:problem:invalid_tool_arguments","code":"INVALID_TOOL_ARGUMENTS","status":400}')
    end
'''
    old_prefix, old_split, old_logic = installed.partition(marker)
    assert old_prefix.splitlines()[0] == 'return function(conf, ctx)'
    assert [line.split(' = ')[0] for line in old_prefix.splitlines()[1:]] == [
        'local DELEGATION_KEY_ENV', 'local ISSUER', 'local AUDIENCE', 'local MCP_WORKLOAD']
    assert old_split == split == marker and 'fail(400)' not in old_logic
    assert logic == old_logic.replace('local function fail(status)\n', 'local function fail(status)\n' + diagnostic)


def installed_profile(before):
    route = before[ENDPOINT_ID]
    public = json.loads(before[PROTECTED_RESOURCE_ROUTE_ID]['plugins']['mocking']['response_example'])
    issuer, = public['authorization_servers']
    oidc = route['plugins']['openid-connect']
    lua = route['plugins']['serverless-post-function']['functions'][0]
    constants = dict(re.findall(r'^local (\w+) = "([^"]+)"$', lua, re.M))
    assert constants['ISSUER'] == issuer and constants['AUDIENCE'] == oidc['client_id']
    address, = route['upstream']['nodes']
    host, port = address.rsplit(':', 1)
    profile = ci_profile({'installationId': route['labels']['ouf-installation'],
                          'revision': route['labels']['ouf-installation-revision'],
                          'gatewayAudience': oidc['client_id'], 'issuerUrl': issuer,
                          'publicApiBaseUrl': public['resource'].removesuffix('/mcp'),
                          'mcpServiceIdentity': constants['MCP_WORKLOAD']}, int(port))
    profile.update({'gateway.delegationKeyEnv': constants['DELEGATION_KEY_ENV'],
                    'services.bindings.ouf-mcp-server': host,
                    'caddy.oidcDiscoveryUrl': oidc['discovery']})
    return profile


def selectors(route):
    return (set(route.get('uris', [])) | ({route['uri']} if 'uri' in route else set()),
            set(route.get('methods', [])),
            set(route.get('hosts', [])) | ({route['host']} if 'host' in route else set()))


def overlap(left, right):
    paths, methods, hosts = selectors(left)
    paths2, methods2, hosts2 = selectors(right)
    return bool(paths & paths2 and (not methods or not methods2 or methods & methods2)
                and (not hosts or not hosts2 or hosts & hosts2))


def conflicts(routes, inventory, retired):
    managed = {route['id']: route for route in routes}
    exemptions = set()
    for row in retired:
        old = inventory.get(row['id'])
        if old and row['supersededBy'] is None:
            # v3 obsolete entry: deleted by the release; its selector never collides with a governed one.
            assert all(old.get(key) == value for key, value in row['match'].items())
            assert not any(overlap(route, old) for route in routes)
            exemptions.add(row['id'])
        elif old:
            assert old.get('vars') == row['vars'] and overlap(old, managed[row['supersededBy']])
            exemptions.add(row['id'])
    return [(route['id'], old_id) for old_id, old in inventory.items()
            if old_id not in managed and old_id not in exemptions
            for route in routes if overlap(route, old)]


def test_selector_collision_controls():
    route = {'id': ENDPOINT_ID, 'uri': '/mcp', 'methods': ['POST'], 'host': 'public.invalid'}
    foreign = {'uris': ['/mcp'], 'hosts': ['public.invalid']}
    assert conflicts([route], {'foreign': foreign}, []) == [(ENDPOINT_ID, 'foreign')]
    for difference in ({'methods': ['GET']}, {'hosts': ['separate.invalid']}, {'uris': ['/other']}):
        assert conflicts([route], {'foreign': foreign | difference}, []) == []


@pytest.mark.parametrize('source', [FIXTURE] + ([EXPORT] if EXPORT.is_file() else []), ids=lambda p: p.stem)
def test_adoption_and_return(artifact, source):
    """GW-60e-02, GW-60e-03, GW-60e-04. Recursive parity, OAuth bytes and D-087 plan/readback/return."""
    exported = json.loads(source.read_bytes())
    before = {row['id']: row for row in exported}
    profile = installed_profile(before)
    routes = load_release_routes(artifact, COMMIT, WORKFLOW, '60', profile)
    desired = {row['id']: row for row in routes}
    retired = json.loads((artifact / 'bundle.json').read_bytes())['retired']
    inventory = dict(before)
    if source == EXPORT and INVENTORY.is_file():
        inventory = {row['id']: row for row in json.loads(INVENTORY.read_bytes())} | before
    assert conflicts(routes, inventory, retired) == []

    store = copy.deepcopy(before)
    plan = []
    for route_id in PUBLIC_IDS:
        old = {k: v for k, v in store[route_id].items() if k not in ('create_time', 'update_time')}
        new = desired[route_id]
        plan.append(Change(route_id, route_id, old, new))
        comparable = copy.deepcopy(old)
        paths = {'/labels/ouf-exposure'}
        assert new['labels']['ouf-exposure'] == 'public'
        if route_id == ENDPOINT_ID:
            oidc = comparable['plugins']['openid-connect']
            governed = desired['mcp-managed-file-preview']['plugins']['openid-connect']
            for field in ('client_secret', 'set_access_token_header', 'set_id_token_header'):
                assert oidc[field] == '<redatto>'
                oidc[field] = governed[field]
            assert oidc['set_access_token_header'] is False and oidc['set_id_token_header'] is False
            assert oidc['client_secret'] == profile['gateway.oidcClientSecretRef']
            issuer = new['plugins']['openid-connect']['claim_validator']['issuer']
            assert issuer == {'valid_issuers': [profile['gateway.issuerUrl']]}
            for label, name in [('ouf-audience', 'gateway.requiredAudience'),
                                ('ouf-mcp-workload', 'iam.workloadClients.mcpServer'),
                                ('ouf-delegation-key-env', 'gateway.delegationKeyEnv')]:
                paths.add('/labels/' + label)
                assert new['labels'][label] == profile[name]
            node, = new['upstream']['nodes']
            assert {f"{node['host']}:{node['port']}": node['weight']} == old['upstream']['nodes']
            code = 'serverless-post-function'
            old_lua = old['plugins'][code]['functions'][0]
            new_lua = new['plugins'][code]['functions'][0]
            check_delegation_lua(old_lua, new_lua)
            paths.update(('/plugins/openid-connect/claim_validator/issuer', '/upstream/nodes',
                          '/plugins/serverless-post-function/functions/0'))
        else:
            actual = new['plugins']['mocking']['response_example'].encode()
            assert actual == old['plugins']['mocking']['response_example'].encode()
        assert set(changed_paths(comparable, new)) == paths
    assert [c.action for c in plan] == ['update', 'update']
    # Keep Admin-owned timestamps outside PUT bodies, as in the executor.

    def put(route_id, body):
        admin = {k: v for k, v in store[route_id].items() if k in ('create_time', 'update_time')}
        store[route_id] = json.loads(json.dumps(body)) | admin

    for change in plan:
        put(change.target_id, change.after)
    for change in reversed(plan):
        actual = {k: v for k, v in store[change.target_id].items() if k not in ('create_time', 'update_time')}
        assert Change(change.logical_id, change.target_id, actual, change.after).action == 'unchanged'
        put(change.target_id, change.before)
    assert canonical_json(store) == canonical_json(before)


def test_oauth_profile_follows_binding_scope():
    """GW-60e-03. One policy and two HTTPS projections determine the two published strings."""
    settings = {'issuerUrl': 'https://issuer.invalid/tenant/', 'publicApiBaseUrl': 'https://edge.invalid/'}
    values = oauth_profile_values(settings, {'requiredScope': 'fixture.scope'})
    assert values == {
        'gateway.publicMcpChallenge': 'Bearer resource_metadata="https://edge.invalid/.well-known/oauth-protected-resource", scope="fixture.scope"',
        'gateway.publicMcpMetadataJson': '{"authorization_servers":["https://issuer.invalid/tenant"],'
                                        '"bearer_methods_supported":["header"],"resource":"https://edge.invalid/mcp",'
                                        '"resource_name":"OUF MCP Server","scopes_supported":["fixture.scope"]}',
    }


def test_json_rpc_validation(artifact):
    """GW-60e-02. The installed protocol boundary accepts objects and arrays up to 4 MiB."""
    resources = json.loads((artifact / 'bundle.json').read_bytes())['resources']
    plugins = next(r['body']['plugins'] for r in resources if r['id'] == ENDPOINT_ID)
    schema = {'anyOf': [{'type': 'object'}, {'type': 'array'}]}
    assert plugins['request-validation'] == {'body_schema': schema, 'max_req_body_size': 4194304}
    assert plugins['client-control'] == {'max_body_size': 4194304}
    validate = Draft7Validator(plugins['request-validation']['body_schema']).is_valid
    assert all(validate(body) for body in ({}, [], {'method': 'initialize'}, [{'jsonrpc': '2.0'}]))
    assert not any(validate(body) for body in (None, True, 1, 'rpc'))


def test_public_ingress_headers_and_signed_proof(artifact):
    """GW-60e-02. Execute both released Lua phases and verify the proof at its consumer."""
    profile = ci_profile(dict(INSTALL, installationId='fixture', revision=1), 18081)
    routes = load_release_routes(artifact, COMMIT, WORKFLOW, '60', profile)
    endpoint, = (r for r in routes if r['id'] == ENDPOINT_ID)

    def ingress(claims, **settings):
        forged = {'X-OUF-Delegation': 'untrusted', 'X-OUF-Principal-ID': 'untrusted',
                  'X-OUF-External-Role-Refs': 'untrusted'}
        engine = Engine(claims, forged, **settings)
        ctx = matched_route_context(engine, endpoint)
        for phase in ('serverless-pre-function', 'serverless-post-function'):
            for lua in endpoint['plugins'][phase]['functions']:
                engine.lua.execute(lua.encode())(None, ctx)
        return engine.headers

    headers = ingress(human() | {'externalRoleRefs': ['viewer']})
    assert b'authorization' not in headers
    assert headers[b'x-ouf-gateway-verified'] == b'true' and headers[b'x-ouf-principal-id'] == b'human-a'
    assert headers[b'x-ouf-external-role-refs'] == b'viewer'
    assert execute(headers[b'x-ouf-delegation'].decode()).headers[b'x-ouf-external-role-refs'] == b'viewer'
    with pytest.raises(Denied, match='401'):
        ingress(human() | {'iss': 'https://other.invalid'})
    with pytest.raises(Denied, match='403'):
        ingress(human() | {'ouf_actor_type': 'unknown'})
    with pytest.raises(Denied, match='503'):
        ingress(human(), key=None)


def test_legacy_writers():
    """GW-60e-05. Public IDs are excluded from legacy installation and saved restores."""
    for route_id in PUBLIC_IDS:
        with pytest.raises(ValueError, match='governed'):
            deploy_internal_m2m_routes.restore({route_id: None}, None)
        with pytest.raises(ValueError, match='governed'):
            deploy_internal_m2m_routes.validate_routes([{'id': route_id}])
        with pytest.raises(ValueError, match='governed'):
            deploy_status_execute.apply_routes([{'id': route_id}], None)
    old = dict.fromkeys((*PUBLIC_IDS, deploy_status_execute.STATUS_ID))
    assert deploy_status_execute.status_snapshot(old) == {deploy_status_execute.STATUS_ID: None}
