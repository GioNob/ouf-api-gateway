"""GW-59J. Review batch schemas on the compiled and materialized dispatch routes."""
import copy
import hashlib
import json

import pytest
from jsonschema import Draft7Validator, FormatChecker

from tests.test_dispatch_schema_contract import dispatch_body, dispatch_profiles, semantic_review_batch_cases
from tools.compile_config import ROOT, compile_config
from tools.gateway_release_bundle import canonical, digest
from tools.mcp_dispatch_contract import (
    INVALID_TOOL_ARGUMENTS, MANIFEST, REVIEW_BATCH_MANIFEST, bound_capability, capability_contracts,
    dispatch_input_schema, envelope_refs,
)

ROUTES = {
    'ouf.semantic.approval.request': ('mcp-semantic-review', 'semantic-proposal-review'),
    'ouf.semantic.proposal.read': ('mcp-semantic-read', 'semantic-proposal-read'),
}


@pytest.fixture(scope='module')
def routes():
    compiled, materialized = dispatch_profiles()
    return {r['id']: r for r in compiled['routes'] + materialized}


def test_snapshot():
    """GW-59J-MANIFEST. Pin the canonical two-row extraction from MCP 1.19.0."""
    snapshot = REVIEW_BATCH_MANIFEST.read_text(encoding='ascii')
    assert hashlib.sha256(snapshot.encode('ascii')).hexdigest() == (
        '16f689a6e53edd809867b58a24f01b9d11a7778b96075f793caa7bdf06c5e903')
    assert json.loads(snapshot) == [capability_contracts()[cap] for cap in ROUTES]


@pytest.mark.parametrize('cap', ROUTES)
def test_projection_in_every_branch(cap):
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
        with pytest.raises(ValueError, match='analysisId must remain optional MCP context'):
            dispatch_input_schema(cap, invalid)


@pytest.mark.parametrize('cap', ROUTES)
def test_wire_schema_and_verdicts(routes, cap):
    """GW-59J-SCHEMA / GW-59J-FORMS. Exercise both actual dispatch producers."""
    expected = envelope_refs(dispatch_input_schema(cap, capability_contracts()[cap]['inputSchema']))
    accepted, rejected = semantic_review_batch_cases()[cap]
    for route_id in ROUTES[cap]:
        validation = routes[route_id]['plugins']['request-validation']
        schema = validation['body_schema']
        assert bound_capability(schema) == cap
        assert schema['properties']['Arguments'] == expected
        assert validation['max_req_body_size'] == 65536
        assert validation['rejected_msg'] == INVALID_TOOL_ARGUMENTS
        validator = Draft7Validator(schema, format_checker=FormatChecker())
        for valid, examples in ((True, accepted), (False, rejected)):
            for args in examples:
                assert validator.is_valid(dispatch_body(schema, args)) == valid, (route_id, args)


def test_predecessor_and_compiled_config():
    """GW-59J-PREDECESSOR / GW-59J-BUNDLE. Restore the two old argument schemas only."""
    compiled = compile_config(ROOT / 'ouf-config')
    routes = {r['id']: r for r in compiled['routes']}
    old_rows = json.loads(MANIFEST.read_bytes())['capabilities']
    for cap, (route_id, _) in ROUTES.items():
        old, = (row['inputSchema'] for row in old_rows if row['capabilityId'] == cap)
        fields = routes[route_id]['plugins']['request-validation']['body_schema']['properties']
        # The pre-batch wire form (after the MCP consumes analysisId) survives intact.
        assert envelope_refs(dispatch_input_schema(cap, old)) in fields['Arguments']['oneOf']
        fields['Arguments'] = envelope_refs(old)
    del compiled['configurationSha256']
    # Generated before the batch overlay at da4c8bf.
    assert digest(canonical(compiled)) == '473e80d0c51b18e7d3c3f795af62552f9cad23ed98dec18d8d1148398998a406'
