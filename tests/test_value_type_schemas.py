import base64
import hashlib
import hmac
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from tests.test_execute_delegation import Denied, Engine, INSTALL, KEY, human, proof, workload
from tests.release_bundle_fixture import ci_profile, load_release_routes
from tools.gateway_release_bundle import generate


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contracts" / "ouf-value-types-v1.json"


def test_value_types_contract_digest():
    assert hashlib.sha256(CONTRACT.read_bytes()).hexdigest() == (
        "4b90e85ecd1573404612ef0a0ee627feffaa9c189fe4363e82079bd07824c333"
    )


ROUTES = {
    "semantic.propose": ("semantic-proposal-create", 65536),
    "source.onboarding.create": ("mcp-managed-file-create", 3145728),
    "source.onboarding.revision.prepare": ("mcp-source-revision-prepare", 65536),
}
MAPPINGS = ("source.onboarding.create", "source.onboarding.revision.prepare")


def dispatch(name):
    return json.loads((ROOT / "tests/fixtures/value-types" / (name + ".json")).read_bytes())


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
    route = routes[route_id]
    validation = route["plugins"]["request-validation"]
    Draft202012Validator.check_schema(validation["body_schema"])
    validator(routes, name).validate(body)
    assert validation["max_req_body_size"] == limit
    assert validation["rejected_msg"] == "INVALID_TOOL_ARGUMENTS"
    assert route["upstream"]["retries"] == 0
    body["Owner"] = "unexpected"
    assert not validator(routes, name).is_valid(body)


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


@pytest.mark.parametrize("name,receipt_header,domain", [
    ("semantic.propose", "x-ouf-semantic-proposal-receipt", "ouf-semantic-proposal-owner-v1."),
    ("source.onboarding.create", "x-ouf-managed-file-receipt", "ouf-managed-file-owner-v1."),
    ("source.onboarding.revision.prepare", "x-ouf-source-revision-receipt", "ouf-source-revision-owner-v1."),
])
def test_released_lua_signs_exact_dispatch_at_limit(routes, name, receipt_header, domain):
    body = dispatch(name)
    identity = body["Identity"]
    claims = dict(human(), sub=identity["PrincipalID"], tenant_id=identity["TenantID"],
                  acr=identity["AuthenticationContextRef"], azp=identity["ServicePrincipalID"],
                  scope="mcp.connect " + body["CapabilityID"])
    headers = {"X-OUF-Delegation": proof(claims), "Idempotency-Key": body["IdempotencyKey"],
               "X-Correlation-ID": body["CorrelationID"], "X-Tool-Attempt-ID": body["AttemptID"]}
    route_id, limit = ROUTES[name]
    route = routes[route_id]
    engine = Engine(dict(workload(), tenant_id=identity["TenantID"]), headers, body, uri=route["uri"])
    labels = {key.encode(): value.encode() for key, value in route["labels"].items()}
    ctx = engine.lua.table_from({b"matched_route": {b"value": {b"labels": labels}}}, recursive=True)
    lua, = route["plugins"]["serverless-post-function"]["functions"]
    forward = engine.lua.execute(lua.encode())
    # Whitespace pads the original JSON to the exact HTTP envelope limit.
    engine.lua.execute(b"ngx.req.get_body_data=function() return nil end")
    raw = engine.body.ljust(limit)
    engine.body = raw + b" "
    with pytest.raises(Denied, match="413"):
        forward(None, ctx)
    engine.body = raw
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
