"""GW-51M release regressions, from a resolved bundle to the Semantic receipt."""
import base64
import copy
import hashlib
import hmac
import json

import pytest
from jsonschema import Draft7Validator, FormatChecker

from tests.release_bundle_fixture import SEARCH_IDS, ci_profile, load_release_routes
from tests.test_dispatch_schema_contract import dispatch_body, wave2_dispatch_cases
from tests.test_execute_delegation import Denied, Engine, INSTALL, KEY, human, proof, workload
from tests.test_value_type_schemas import matched_route_context, routes, run_dispatch_rewrite
from tools.apisix_request_schema import verify_dispatch_arguments
from tools.gateway_release_bundle import generate
from tools.mcp_dispatch_contract import SEARCH_BATCH, SEARCH_SCOPE, capability_contracts, dispatch_input_schema


def wire_case(route):
    schema = route['plugins']['request-validation']['body_schema']
    owner, accepted, _ = wave2_dispatch_cases([route])[route['uri']]
    return owner, dispatch_body(schema, accepted[0])


@pytest.mark.parametrize('route_id', SEARCH_IDS)
def test_signed_bytes_at_semantic(routes, route_id):
    """GW-51M-03. Exercise delegation, exact forwarding and the signed receipt."""
    route = routes[route_id]
    owner, body = wire_case(route)
    Draft7Validator(route['plugins']['request-validation']['body_schema'], format_checker=FormatChecker()).validate(body)
    engine = send(route, body)
    assert engine.body == json.dumps(body, indent=2, ensure_ascii=False).encode()
    encoded, mac = engine.headers[b'x-ouf-semantic-read-receipt'].split(b'.')
    expected = hmac.digest(b'56' * 32, b'ouf-semantic-read-owner-v1.' + encoded, 'sha256')
    assert hmac.compare_digest(mac, base64.urlsafe_b64encode(expected).rstrip(b'='))
    receipt = json.loads(base64.urlsafe_b64decode(encoded + b'=' * (-len(encoded) % 4)))
    assert receipt['path'] == route['plugins']['proxy-rewrite']['uri'] == owner
    assert receipt['capability'] == body['CapabilityID']
    assert receipt['bodyHash'] == hashlib.sha256(engine.body).hexdigest()
    assert not {b'authorization', b'x-ouf-delegation', b'cookie'} & engine.headers.keys()
    assert route['upstream']['retries'] == 0
    for invalid in ({'scope': SEARCH_BATCH}, {'actor': 'AI_AGENT'}, {'client': 'other-workload'}):
        with pytest.raises(Denied, match='403'):
            send(route, body, **invalid)


def test_search_uses_installation_bindings(tmp_path):
    """GW-51M-04. Both routes can reach a separate Semantic host with installation-specific quotas."""
    commit, workflow = '1' * 40, '.github/workflows/ci.yml'
    generate(tmp_path, commit, workflow, '51')
    profile = ci_profile({**INSTALL, 'installationId': 'fixture', 'revision': 2}, 18080)
    profile.update({'services.bindings.ouf-semantic-registry': 'semantic-owner.invalid',
                    'services.ports.ouf-semantic-registry': 18081,
                    'gateway.rateLimits.semanticSearch.count': 13,
                    'gateway.rateLimits.semanticSearchBatch.count': 7})
    resolved = {r['id']: r for r in load_release_routes(tmp_path, commit, workflow, '51', profile)}
    for route_id, count in zip(SEARCH_IDS, [13, 7]):
        route = resolved[route_id]
        assert route['upstream']['nodes'] == [{'host': 'semantic-owner.invalid', 'port': 18081, 'weight': 1}]
        assert route['plugins']['limit-count']['count'] == count
        assert route['labels']['ouf-owner-key-env'] == profile['gateway.semanticReadOwnerKeyEnv']


def send(route, body, *, scope=SEARCH_SCOPE, actor='HUMAN', client=None):
    headers = {'X-OUF-Delegation': proof(dict(human(), scope=scope, ouf_actor_type=actor)),
               'X-Correlation-ID': body['CorrelationID'], 'Idempotency-Key': body['IdempotencyKey'],
               'X-Tool-Attempt-ID': body['AttemptID'], 'Cookie': 'fixture',
               'X-OUF-Semantic-Read-Receipt': 'untrusted'}
    claims = workload()
    if client:
        claims['azp'] = client
    engine = Engine(claims, headers, body, uri=route['uri'])
    engine.lua.globals()[b'os'][b'getenv'] = {b'DELEGATION_KEY': KEY.encode(), b'READ_KEY': b'56' * 32}.get
    ctx = matched_route_context(engine, route)
    engine.body = json.dumps(body, indent=2, ensure_ascii=False).encode()
    run_dispatch_rewrite(engine, route, ctx)
    engine.body = json.dumps(body, separators=(',', ':')).encode()
    post, = route['plugins']['serverless-post-function']['functions']
    engine.lua.execute(post.encode())(None, ctx)
    return engine


def test_batch_rejects_duplicate_intent_ids_and_case_equivalent_languages(routes):
    route = routes['mcp-semantic-search-batch']
    _, body = wire_case(route)
    intent, = body['Arguments']['intents']
    for intents in ([intent, dict(intent, intent='other')], [dict(intent, preferredLanguages=['it', 'IT'])]):
        body['Arguments']['intents'] = intents
        with pytest.raises(Denied, match='400'):
            send(route, body)


def test_batch_protocol_limits_and_closed_objects(routes):
    route = routes['mcp-semantic-search-batch']
    _, body = wire_case(route)
    check = Draft7Validator(route['plugins']['request-validation']['body_schema'])
    args = body['Arguments']
    item, = args['intents']
    def accepts(candidate):
        return check.is_valid(dict(body, Arguments=candidate))
    assert accepts(dict(args, intents=[dict(item, intentId=f'i{i}') for i in range(64)], limitPerIntent=8))
    for field in args:
        assert not accepts({k: v for k, v in args.items() if k != field})
    for field in item:
        assert not accepts(dict(args, intents=[{k: v for k, v in item.items() if k != field}]))
    for patch in ({'intents': []}, {'intents': [item] * 65}, {'limitPerIntent': 0}, {'limitPerIntent': '3'},
                  {'contract': 'v2'}, {'analysisId': 'x'}):
        assert not accepts(dict(args, **patch))
    for patch in ({'context': {'other': 'x'}}, {'context': {'domain': 'd' * 2049}},
                  {'intent': ''}, {'intent': 'x' * 257}, {'intentId': 'x y'}, {'preferredLanguages': []},
                  {'preferredLanguages': ['it_IT']}, {'preferredLanguages': ['en'] * 6},
                  {'requestedArtifactType': 'VOCABULARY'}, {'other': True}):
        assert not accepts(dict(args, intents=[dict(item, **patch)]))


def test_only_optional_local_search_context_is_projected():
    args = copy.deepcopy(capability_contracts()[SEARCH_SCOPE]['inputSchema'])
    fields = dict(args['properties'], analysisId={'type': 'string'})
    with_local = dict(args, properties=fields)
    assert dispatch_input_schema(SEARCH_SCOPE, with_local) == args
    with pytest.raises(ValueError, match='optional'):
        dispatch_input_schema(SEARCH_SCOPE, dict(with_local, required=['q', 'analysisId']))


def test_missing_datatype_stops_release(routes):
    """GW-51M-01. Reproduce the 23 November release drift."""
    route = copy.deepcopy(routes['mcp-semantic-search'])
    item = {'kind': 'routes', 'id': route['id'], 'body': route}
    verify_dispatch_arguments([item])
    args = route['plugins']['request-validation']['body_schema']['properties']['Arguments']
    args['properties']['type']['enum'].remove('DATATYPE')
    with pytest.raises(ValueError, match='mcp-semantic-search: Arguments differ'):
        verify_dispatch_arguments([item])


@pytest.mark.parametrize(('path', 'value'), [
    (('required',), ['contract']), (('properties', 'limitPerIntent', 'type'), 'number'),
    (('properties', 'intents', 'maxItems'), 63), (('properties', 'intents', 'items', 'additionalProperties'), True),
    (('properties', 'intents', 'items', 'properties', 'intentId', 'pattern'), '.*'),
    (('properties', 'intents', 'items', 'properties', 'context', 'properties'), {}),
])
def test_nested_schema_drift_stops_release(routes, path, value):
    """GW-51M-02. Reject a mismatch at any schema depth."""
    route = copy.deepcopy(routes['mcp-semantic-search-batch'])
    node = route['plugins']['request-validation']['body_schema']['properties']['Arguments']
    for field in path[:-1]:
        node = node[field]
    node[path[-1]] = value
    with pytest.raises(ValueError, match='mcp-semantic-search-batch: Arguments differ'):
        verify_dispatch_arguments([{'kind': 'routes', 'id': route['id'], 'body': route}])
