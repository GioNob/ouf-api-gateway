"""GW-59J. Review batch schemas on the compiled and materialized dispatch routes."""
import copy
import hashlib
import json

import pytest
from jsonschema import Draft7Validator, FormatChecker

from tests.dispatch_schema_parity import predecessor_arguments, review_predecessor_schemas
from tests.test_dispatch_schema_contract import dispatch_body, dispatch_profiles, semantic_review_batch_cases
from tools.compile_config import ROOT, compile_config
from tools.gateway_release_bundle import canonical, digest
from tools.mcp_dispatch_contract import (
    INVALID_TOOL_ARGUMENTS, REVIEW_BATCH_MANIFEST, bound_capability, capability_contracts,
    dispatch_input_schema, envelope_refs,
)

ROUTES = {
    'ouf.semantic.approval.request': ('semantic-proposal-review', 'semantic-proposal-review'),
    'ouf.semantic.proposal.read': ('mcp-semantic-read', 'semantic-proposal-read'),
}


@pytest.fixture(scope='module')
def routes():
    compiled, materialized = dispatch_profiles()
    return [{r['id']: r for r in rows} for rows in (compiled['routes'], materialized)]


def test_snapshot():
    """GW-59J-MANIFEST. Pin the canonical two-row extraction from MCP 1.19.0."""
    snapshot = REVIEW_BATCH_MANIFEST.read_text(encoding='ascii')
    assert hashlib.sha256(snapshot.encode('ascii')).hexdigest() == (
        '16f689a6e53edd809867b58a24f01b9d11a7778b96075f793caa7bdf06c5e903')
    assert json.loads(snapshot) == [capability_contracts()[cap] for cap in ROUTES]


@pytest.mark.parametrize('cap', ROUTES)
@pytest.mark.parametrize('declared', [True, False])
def test_projection_in_every_branch(cap, declared):
    """GW-59J-LOCAL. Local context can never be required on the dispatch boundary."""
    source = capability_contracts()[cap]['inputSchema']
    projected = dispatch_input_schema(cap, source)
    for i, branch in enumerate([source, *source['oneOf']]):
        wire = projected if i == 0 else projected['oneOf'][i - 1]
        assert 'analysisId' in branch['properties']
        assert 'analysisId' not in wire['properties'] and 'analysisId' not in wire.get('required', [])
        invalid = copy.deepcopy(source)
        target = invalid if i == 0 else invalid['oneOf'][i - 1]
        target.setdefault('required', []).append('analysisId')
        for field in ('reviewContextRef', 'expectedVersion'):
            if field in branch['properties']:
                assert wire['properties'][field]['maxLength'] == 64
        if not declared:
            del target['properties']['analysisId']
        with pytest.raises(ValueError, match='analysisId must remain optional MCP context'):
            dispatch_input_schema(cap, invalid)


def test_required_local_context_in_branch_without_properties():
    schema = {'oneOf': [{'required': ['commandKey']}]}
    with pytest.raises(ValueError, match='commandKey must remain optional MCP context'):
        dispatch_input_schema('ouf.managed-source.file.profile', schema)


@pytest.mark.parametrize('cap', ROUTES)
def test_wire_schema_and_verdicts(routes, cap):
    """GW-59J-SCHEMA / GW-59J-FORMS. Exercise both actual dispatch producers."""
    expected = envelope_refs(dispatch_input_schema(cap, capability_contracts()[cap]['inputSchema']))
    accepted, rejected = semantic_review_batch_cases()[cap]
    catalog = json.loads((ROOT / 'schemas/mcp-gateway-semantic-proposals-v1.json').read_bytes())
    entry, = (row for row in catalog['oneOf'] if bound_capability(row) == cap)
    assert entry['properties']['Arguments'] == expected
    for profile, route_id in zip(routes, ROUTES[cap], strict=True):
        validation = profile[route_id]['plugins']['request-validation']
        schema = validation['body_schema']
        assert bound_capability(schema) == cap
        assert schema['properties']['Arguments'] == expected
        assert validation['max_req_body_size'] == 65536
        assert validation['rejected_msg'] == INVALID_TOOL_ARGUMENTS
        validator = Draft7Validator(schema, format_checker=FormatChecker())
        for valid, examples in ((True, accepted), (False, rejected)):
            for args in examples:
                assert validator.is_valid(dispatch_body(schema, args)) == valid, (route_id, args)


def test_predecessor_schemas():
    """GW-59J-PREDECESSOR. MCP 16c5228 (1.19.0-next-discovery-v1), identical at cefa37c."""
    # SHA-256 of the canonical inputSchema from the in-service MCP, before projection.
    pins = {
        'ouf.semantic.approval.request': 'd4bf3b8a69fca654daafd5fcbeb102ad12b3f418c5eac6b4543846d8508f4063',
        'ouf.semantic.proposal.read': 'd69bce836f3a97fc6430214cb6a998ec194da5a00ea923764f4b9efbbdd6fd42',
    }
    schemas = review_predecessor_schemas()
    assert schemas.keys() == pins.keys()
    for cap, old in schemas.items():
        assert digest(canonical(old)) == pins[cap]
        assert old == capability_contracts()[cap]['inputSchema']['oneOf'][0]


def test_predecessor_compiled_config():
    """GW-59J-BUNDLE. Restore just the two old Arguments to reproduce the ead98dd digest."""
    compiled = compile_config(ROOT / 'ouf-config')
    routes = {r['id']: r for r in compiled['routes']}
    for cap, arguments in predecessor_arguments().items():
        route_id, _ = ROUTES[cap]
        fields = routes[route_id]['plugins']['request-validation']['body_schema']['properties']
        fields['Arguments'] = arguments
    del compiled['configurationSha256']
    assert digest(canonical(compiled)) == '813b75a6d7bbabb54382df28a0dee4575ebbc785685ab0276a01ec6d62cff001'
