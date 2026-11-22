import base64
import hashlib
import hmac
import json
import re
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft7Validator, Draft202012Validator, FormatChecker

from tests.test_execute_delegation import Denied, Engine, INSTALL, KEY, human, proof, workload
from tests.release_bundle_fixture import ci_profile, load_release_routes
from tools.gateway_release_bundle import generate
from tools.sync_value_type_schemas import ROUTES as CATALOG_SCHEMAS


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contracts" / "ouf-value-types-v1.json"


def test_value_types_contract_digest():
    assert hashlib.sha256(CONTRACT.read_bytes()).hexdigest() == (
        "3b85052e253b985f1082527eb595d2f02e5336047203deb3503a9766c1324295"
    )


def test_value_maps_contract_digest():
    contract = ROOT / 'contracts' / 'ouf-value-maps-v1.json'
    assert hashlib.sha256(contract.read_bytes()).hexdigest() == (
        '40b247ad3422e09245a8314fdcc59ffe0b039e25733a2ca8f31aa6ba03ff2d2e'
    )


ROUTES = {
    "semantic.propose": ("semantic-proposal-create", 1048576),
    "source.onboarding.create": ("mcp-managed-file-create", 3145728),
    "source.onboarding.revision.prepare": ("mcp-source-revision-prepare", 65536),
}
MAPPINGS = ("source.onboarding.create", "source.onboarding.revision.prepare")


def dispatch(name):
    return json.loads((ROOT / "tests/fixtures/value-types" / (name + ".json")).read_bytes())


def value_map_dispatch():
    body = dispatch('semantic.propose')
    body['Arguments'].update(
        artifactType='VALUE_MAP',
        definition={
            'targetVocabulary': 'urn:example:vocabulary@00000000-0000-4000-8000-000000000012',
            'entries': [
                {'code': 'B', 'concept': 'urn:example:concept:b'},
                {'code': 'a', 'concept': 'urn:example:concept:a'},
                {'code': 'A', 'concept': 'urn:example:concept:a'},
            ],
            'labels': {'it': 'Codici', 'en': 'Codes'},
        },
    )
    return body


def compact_json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')


def value_map_at_definition_limit():
    body = value_map_dispatch()
    args = body['Arguments']
    args['rationale'] = {'sourceColumn': {'fieldName': 'field', 'sourceId': 'source'}}
    definition = args['definition']
    entries = definition['entries'] = [
        {'code': f'{index:04d}' + 'c' * 124, 'concept': 'urn:example:concept:x'}
        for index in range(2000)
    ]
    # Maximizing both fields in every entry would exceed even the HTTP ceiling.
    entries[0]['concept'] = entries[0]['concept'].ljust(512, 'x')
    remaining = 786432 - len(compact_json(definition))
    extra, remainder = divmod(remaining, len(entries) - 1)
    for index, entry in enumerate(entries[1:]):
        entry['concept'] += 'x' * (extra + (index < remainder))
    assert len(compact_json(definition)) == 786432
    return body


@pytest.fixture(scope="module")
def routes(tmp_path_factory):
    directory = tmp_path_factory.mktemp("release")
    workflow = ".github/workflows/ci.yml"
    commit = "1" * 40
    generate(directory, commit, workflow, "46")
    profile = ci_profile({**INSTALL, "installationId": "fixture", "revision": 1}, 18080)
    return {r["id"]: r for r in load_release_routes(directory, commit, workflow, "46", profile)}


def validator(routes, name):
    body = routes[ROUTES[name][0]]["plugins"]["request-validation"]["body_schema"]
    return Draft202012Validator(body, format_checker=FormatChecker())


@pytest.mark.parametrize("name", ROUTES)
def test_mcp_dispatch_in_release(routes, name):
    route_id, limit = ROUTES[name]
    body = dispatch(name)
    route = yaml.safe_load(yaml.safe_dump(routes[route_id]))
    assert all(re.fullmatch(r'[A-Za-z0-9_./-]{1,64}', value) for value in route["labels"].values())
    assert route["plugins"]["openid-connect"]["claim_validator"]["issuer"]["valid_issuers"] == [
        INSTALL["issuerUrl"],
    ]
    validation = route["plugins"]["request-validation"]
    schema = validation["body_schema"]
    catalog = json.loads((ROOT / "schemas" / f"mcp-gateway-{CATALOG_SCHEMAS[name]}-v1.json").read_bytes())
    branch, = (item for item in catalog.get("oneOf", [catalog])
               if item["properties"]["CapabilityID"]["const"] == body["CapabilityID"])
    assert branch["$id"] == f"urn:ouf:gateway:dispatch:{name}"
    assert schema == {key: value for key, value in branch.items() if key != "$id"}
    Draft202012Validator.check_schema(schema)
    validators = (
        Draft202012Validator(catalog, format_checker=FormatChecker()),
        Draft202012Validator(schema, format_checker=FormatChecker()),
        Draft7Validator(schema, format_checker=FormatChecker()),
    )
    invalid = dispatch(name)
    arguments = invalid["Arguments"]
    if name == "semantic.propose":
        arguments["definition"]["components"][0]["type"] = "unknown"
    elif name == "source.onboarding.create":
        arguments["fields"][-1]["transform"] = "unknown"
    else:
        arguments["newColumns"][0]["mapping"]["transform"] = "unknown"
    for check in validators:
        check.validate(body)
        assert not check.is_valid(invalid)
    assert validation["max_req_body_size"] == route["plugins"]["client-control"]["max_body_size"] == limit
    assert validation["rejected_msg"] == "INVALID_TOOL_ARGUMENTS"
    assert route["upstream"]["retries"] == 0
    body["Owner"] = "unexpected"
    assert all(not check.is_valid(body) for check in validators)


@pytest.mark.parametrize('name', ('semantic.propose', 'source.onboarding.revision.prepare'))
def test_dispatch_preserves_original_body(routes, name):
    route_id, limit = ROUTES[name]
    plugins = routes[route_id]['plugins']
    pre = plugins['serverless-pre-function']
    assert pre['phase'] == 'rewrite'
    strip, capture = pre['functions']
    assert 'ngx.req.clear_header(name)' in strip
    assert f"require('apisix.core').request.get_body({limit})" in capture
    assert f'if not body or #body == 0 or #body > {limit} then return ngx.exit(413) end' in capture
    assert 'ctx.ouf_original_body = body' in capture

    post = plugins['serverless-post-function']
    assert post['phase'] == 'access'
    execute, = post['functions']
    assert 'local body = ctx.ouf_original_body' in execute
    assert "if type(body) ~= 'string' then return fail(503) end" in execute
    assert 'get_body' not in execute and 'ngx.req.read_body' not in execute
    assert 'digest:final(body)' in execute
    assert 'ngx.req.set_body_data(body)' in execute


def test_value_map_definition_and_limits(routes):
    check = validator(routes, 'semantic.propose')
    body = value_map_dispatch()
    args = body['Arguments']
    definition = args['definition']
    check.validate(body)
    for changes in (
        {'targetVocabulary': None}, {'targetVocabulary': 'urn:example:vocabulary'},
        {'targetVocabulary': 'relative@00000000-0000-4000-8000-000000000012'},
        {'targetVocabulary': 'urn:example:vocabulary@bad-set'},
        {'targetVocabulary': definition['targetVocabulary'] + '\n'},
        {'targetVocabulary': 'urn:a%xx@00000000-0000-4000-8000-000000000012'},
        {'entries': []}, {'entries': {}}, {'entries': [None]},
        {'entries': [{'code': 'B'}]}, {'entries': [{'concept': 'urn:example:concept'}]},
        {'entries': [{'code': 'x', 'concept': 'relative'}]},
        {'entries': [{'code': 'x', 'concept': 'urn:bad%xx'}]},
        {'entries': [{'code': 'x', 'concept': 'urn:' + 'x' * 509}]},
        {'entries': [dict(definition['entries'][0], extra=True)]},
        {'labels': {'de': 'Codes'}}, {'labels': {'it': 'x' * 4001}},
        {'extra': True}, {'components': []},
    ):
        args['definition'] = dict(definition, **changes)
        assert not check.is_valid(body), changes.keys()
    for field in ('targetVocabulary', 'entries'):
        args['definition'] = {key: value for key, value in definition.items() if key != field}
        assert not check.is_valid(body), field
    args['definition'] = {'targetVocabulary': definition['targetVocabulary'], 'entries': [
        {'code': f'{i:03x}', 'concept': 'x:c'} for i in range(2000)
    ]}
    check.validate(body)
    assert len(json.dumps(body, separators=(',', ':')).encode()) <= ROUTES['semantic.propose'][1]
    args['definition']['entries'].append({'code': 'another', 'concept': 'urn:x'})
    assert not check.is_valid(body)
    args['definition'] = definition
    for artifact_type in ('DATATYPE', 'CLASS', 'ONTOLOGY'):
        args['artifactType'] = artifact_type
        assert not check.is_valid(body), artifact_type
    args['artifactType'] = 'VALUE_MAP'
    args['semanticId'] = 'relative'
    assert not check.is_valid(body)
    args['semanticId'] = 'urn:example:container'
    args['definition'] = dispatch('semantic.propose')['Arguments']['definition']
    assert not check.is_valid(body)
    del args['definition']
    assert not check.is_valid(body)


def test_value_map_rationale_is_optional_and_closed(routes):
    check = validator(routes, 'semantic.propose')
    body = value_map_dispatch()
    args = body['Arguments']
    check.validate(body)
    args['rationale'] = {'sourceColumn': {'fieldName': 'x' * 256}}
    check.validate(body)
    args['rationale']['sourceColumn']['sourceId'] = 'reference'
    check.validate(body)
    for rationale in (
        {}, {'sourceColumn': {}}, {'sourceColumn': {'fieldName': ''}},
        {'sourceColumn': {'fieldName': 'x' * 257}},
        {'sourceColumn': {'fieldName': 'x', 'sourceId': 123}},
        {'sourceColumn': {'fieldName': 'x', 'values': ['source-value']}},
        {'sourceColumn': {'fieldName': 'x'}, 'values': []},
    ):
        args['rationale'] = rationale
        assert not check.is_valid(body)
    legacy = dispatch('semantic.propose')
    legacy['Arguments']['rationale'] = {'sourceColumn': {'fieldName': 'field'}}
    assert not check.is_valid(legacy)


@pytest.mark.parametrize('code,valid', [
    ('x', True), ('\u00e9' * 128, True), ('a b\u2003c', True),
    ('', False), ('x' * 129, False), ('\u00e9' * 129, False),
    (' x', False), ('x ', False), ('x\n', False), ('x\u00a0', False), ('\u2003x', False),
    ('a\0b', False), ('a\x1fb', False), ('a\x7fb', False),
    ('a\ufeff', True), ('\u200bcode', True), ('a\u0100b', True), ('\U0001f30d' * 128, True),
])
def test_value_map_code_syntax(routes, code, valid):
    body = value_map_dispatch()
    body['Arguments']['definition']['entries'][0]['code'] = code
    assert validator(routes, 'semantic.propose').is_valid(body) is valid


def test_value_map_code_white_space_and_controls(routes):
    body = value_map_dispatch()
    entry = body['Arguments']['definition']['entries'][0]
    check = validator(routes, 'semantic.propose')
    spaces = (*range(0x09, 0x0E), 0x20, 0x85, 0xA0, 0x1680,
              *range(0x2000, 0x200B), 0x2028, 0x2029, 0x202F, 0x205F, 0x3000)
    for char in map(chr, spaces):
        for code in (char + 'x', 'x' + char):
            entry['code'] = code
            assert not check.is_valid(body), hex(ord(char))
    for code_point in (*range(0x20), *range(0x7F, 0xA0)):
        entry['code'] = 'x' + chr(code_point) + 'y'
        assert not check.is_valid(body), hex(code_point)


@pytest.mark.parametrize('same_concept', [False, True])
def test_value_map_duplicate_code_is_rejected_before_receipt(routes, same_concept):
    body = value_map_dispatch()
    entries = body['Arguments']['definition']['entries']
    entries[0]['code'] = entries[1]['code'] = 'private-source-value'
    if same_concept:
        entries[1]['concept'] = entries[0]['concept']
    # Lua checks uniqueness by code irrespective of the concept.
    validator(routes, 'semantic.propose').validate(body)
    identity = body['Identity']
    claims = dict(human(), sub=identity['PrincipalID'], tenant_id=identity['TenantID'],
                  acr=identity['AuthenticationContextRef'], azp=identity['ServicePrincipalID'],
                  scope='mcp.connect ' + body['CapabilityID'])
    engine = Engine(dict(workload(), tenant_id=identity['TenantID']), {
        'X-OUF-Delegation': proof(claims), 'Idempotency-Key': body['IdempotencyKey'],
        'X-Correlation-ID': body['CorrelationID'], 'X-Tool-Attempt-ID': body['AttemptID'],
    }, body)
    response = engine.lua.eval(b'{exit=function(status, body) return status, body.message end}')
    engine.modules[b'apisix.core'][b'response'] = response
    route = routes['semantic-proposal-create']
    lua, = route['plugins']['serverless-post-function']['functions']
    ctx = matched_route_context(engine, route)
    forward = engine.lua.execute(lua.encode())
    run_dispatch_rewrite(engine, route, ctx)
    assert forward(None, ctx) == (400, b'INVALID_TOOL_ARGUMENTS')
    receipt = b'x-ouf-semantic-proposal-receipt'
    assert receipt not in engine.headers
    entries[0]['code'] = 'A'
    entries[2]['code'] = 'B'
    engine.body = json.dumps(body).encode()
    run_dispatch_rewrite(engine, route, ctx)
    forward(None, ctx)
    assert receipt in engine.headers
    assert json.loads(engine.body) == body


def matched_route_context(engine, route):
    decode = engine.modules[b'cjson.safe'][b'decode']
    return decode(json.dumps({'matched_route': {'value': route}}).encode())


def run_dispatch_rewrite(engine, route, ctx):
    for lua in route['plugins']['serverless-pre-function']['functions']:
        engine.lua.execute(lua.encode())(None, ctx)


def test_closed_vocabularies_match_contract(routes):
    contract = json.loads(CONTRACT.read_bytes())
    def ids(key):
        return [item["id"] for item in contract[key]]
    proposal = validator(routes, "semantic.propose").schema["properties"]["Arguments"]["$defs"]
    component_type = proposal["datatypeComponents"]["items"]["properties"]["type"]
    assert component_type["oneOf"][0]["enum"] == ids("baseTypes")
    for name in MAPPINGS:
        defs = validator(routes, name).schema["properties"]["Arguments"]["$defs"]
        assert defs["reader"]["enum"] == ids("readers")
        assert defs["constructor"]["properties"]["constructorId"]["enum"] == ids("constructors")


def test_datatype_constraints(routes):
    name = "semantic.propose"
    body = dispatch(name)
    args = body["Arguments"]
    check = validator(routes, name)
    component = {"name": "reading", "required": True, "cardinality": "ONE"}
    for kind, constraints, valid in [
        ("decimal", {"minInclusive": "-0.1"}, True), ("decimal", {"minInclusive": "-0.10"}, False),
        ("integer", {"maxInclusive": "9007199254740993"}, True), ("integer", {"maxInclusive": 42}, False),
        ("date", {"minInclusive": "2026-13-01"}, False), ("datetime", {"minInclusive": "2026-01-01"}, False),
        ("concept", {"vocabularyRef": "urn:example:vocab"}, True), ("concept", {"vocabularyRef": "relative"}, False),
        ("string", {"maxLength": 12}, True), ("string", {"maxLength": "12"}, False),
        ("geometry", {"maxLength": 1}, False), ("unknown", {}, False),
    ]:
        args["definition"] = {"components": [dict(component, type=kind, constraints=constraints)]}
        assert check.is_valid(body) == valid, (kind, constraints)
    args["definition"] = {"components": [dict(component, type="string", name=f"v{i}") for i in range(32)]}
    check.validate(body)
    args["definition"]["components"].append(dict(component, type="string"))
    assert not check.is_valid(body)
    args["artifactType"] = "CLASS"
    args["definition"]["components"] = [dict(component, type="string")]
    assert not check.is_valid(body)


@pytest.mark.parametrize("name", MAPPINGS)
def test_compositions_and_item_readers(routes, name):
    body = dispatch(name)
    args = body["Arguments"]
    check = validator(routes, name)
    contract = json.loads(CONTRACT.read_bytes())
    point, structured = contract["mappingShape"]["example"]["compositions"]
    args["compositions"] = [point, structured]
    check.validate(body)
    point["inputs"][1]["role"] = "lat"
    assert not check.is_valid(body)
    leaf = {"fieldName": "via", "reader": "IDENTITY"}
    structured["components"] = [{"component": "lines", "items": [leaf]}]
    args["compositions"] = [structured]
    check.validate(body)
    structured["components"][0]["items"] = []
    check.validate(body)
    structured["components"][0]["items"] = [leaf]
    leaf["reader"] = "UNKNOWN"
    assert not check.is_valid(body)
    leaf["reader"] = "IDENTITY"
    structured["components"][0]["items"] = [{"items": [leaf]}]
    assert not check.is_valid(body)
    for depth in range(1, 6):
        inner = leaf
        for _ in range(depth - 1):
            inner = {"structured": {"typeRef": structured["typeRef"], "components": [
                {"component": "nested", "items": [inner]}]}}
        structured["components"] = [{"component": "address", "items": [inner]}]
        assert check.is_valid(body) == (depth <= 4)
    split = dict(point, constructorId="LIST_SPLIT_V1", inputs=[dict(leaf, role="value")])
    args["compositions"] = [split]
    for reader, params in [("VALUE_MAP_V1", {"valueMapRef": structured["typeRef"]}),
                           ("WKT_V1", {"crs": "EPSG:4326"})]:
        split["params"] = {"separator": ",", "itemReader": reader}
        assert not check.is_valid(body)
        split["params"]["itemReaderParams"] = params
        check.validate(body)
        split["params"]["itemReaderParams"] = {"other": "private-source-value"}
        assert not check.is_valid(body)


@pytest.mark.parametrize("name", MAPPINGS)
def test_legacy_field_readers(routes, name):
    body = dispatch(name)
    args = body["Arguments"]
    del args["compositions"]
    field = (args["fields"][-1] if "fields" in args else args["newColumns"][0]["mapping"])
    field.pop("transformParams", None)
    for reader in ("IDENTITY", "DECIMAL_DOT_V1", "DECIMAL_COMMA_V1", "DATE_ISO_V1", "DATE_DMY_V1"):
        field["transform"] = reader
        validator(routes, name).validate(body)


def test_composition_only_revision(routes):
    name = "source.onboarding.revision.prepare"
    body = dispatch(name)
    args = body["Arguments"]
    del args["assetRef"], args["newColumns"], args["compositions"]
    assert not validator(routes, name).is_valid(body)
    args["compositions"] = []
    validator(routes, name).validate(body)


@pytest.mark.parametrize("name,body_limit,receipt_header,domain", [
    ("semantic.propose", 65536, "x-ouf-semantic-proposal-receipt", "ouf-semantic-proposal-owner-v1."),
    ("semantic.propose", 1048576, "x-ouf-semantic-proposal-receipt", "ouf-semantic-proposal-owner-v1."),
    ("source.onboarding.create", 3145728, "x-ouf-managed-file-receipt", "ouf-managed-file-owner-v1."),
    ("source.onboarding.revision.prepare", 65536, "x-ouf-source-revision-receipt", "ouf-source-revision-owner-v1."),
])
def test_released_lua_signs_exact_dispatch_at_limit(routes, name, body_limit, receipt_header, domain):
    body = value_map_at_definition_limit() if body_limit == 1048576 else dispatch(name)
    validator(routes, name).validate(body)
    identity = body["Identity"]
    claims = dict(human(), sub=identity["PrincipalID"], tenant_id=identity["TenantID"],
                  acr=identity["AuthenticationContextRef"], azp=identity["ServicePrincipalID"],
                  scope="mcp.connect " + body["CapabilityID"])
    headers = {"X-OUF-Delegation": proof(claims), "Idempotency-Key": body["IdempotencyKey"],
               "X-Correlation-ID": body["CorrelationID"], "X-Tool-Attempt-ID": body["AttemptID"]}
    route = routes[ROUTES[name][0]]
    engine = Engine(dict(workload(), tenant_id=identity["TenantID"]), headers, body, uri=route["uri"])
    ctx = matched_route_context(engine, route)
    lua, = route["plugins"]["serverless-post-function"]["functions"]
    forward = engine.lua.execute(lua.encode())
    issuer_config = ctx[b'matched_route'][b'value'][b'plugins'][b'openid-connect'][b'claim_validator'][b'issuer']
    issuers = issuer_config[b'valid_issuers']
    issuer_config[b'valid_issuers'] = None
    with pytest.raises(Denied, match="503"):
        forward(None, ctx)
    issuer_config[b'valid_issuers'] = engine.lua.table_from([b'https://other-issuer.invalid'])
    with pytest.raises(Denied, match="403"):
        forward(None, ctx)
    assert receipt_header.encode() not in engine.headers
    issuer_config[b'valid_issuers'] = issuers

    # Whitespace pads the original JSON to the exact HTTP envelope limit.
    engine.lua.execute(b"ngx.req.get_body_data=function() return nil end")
    raw = compact_json(body).ljust(body_limit)
    preserves_body = name in ('semantic.propose', 'source.onboarding.revision.prepare')
    if preserves_body:
        with pytest.raises(Denied, match="503"):
            forward(None, ctx)
        engine.body = b''
        with pytest.raises(Denied, match="413"):
            run_dispatch_rewrite(engine, route, ctx)
    engine.body = raw + b" "
    with pytest.raises(Denied, match="413"):
        if preserves_body:
            run_dispatch_rewrite(engine, route, ctx)
        forward(None, ctx)
    assert receipt_header.encode() not in engine.headers
    engine.body = raw
    if preserves_body:
        run_dispatch_rewrite(engine, route, ctx)
        # Simulate request-validation replacing the body after rewrite capture.
        engine.body = compact_json(body)
    forward(None, ctx)
    assert engine.body == raw
    encoded, signature = engine.headers[receipt_header.encode()].split(b".")
    assert hmac.compare_digest(base64.urlsafe_b64decode(signature + b"=="),
                               hmac.digest(KEY.encode(), domain.encode() + encoded, "sha256"))
    receipt = json.loads(base64.urlsafe_b64decode(encoded + b"=="))
    assert receipt["bodyHash"] == hashlib.sha256(raw).hexdigest()
    assert receipt["path"] == route["plugins"]["proxy-rewrite"]["uri"]
    if name == "source.onboarding.revision.prepare":
        assert engine.headers[b"if-match"] == f'W/"ov:{body["Arguments"]["expectedVersion"]}"'.encode()
