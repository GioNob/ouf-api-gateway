"""Offline guard: dispatch schemas stay in APISIX's Lua dialect and keep the MCP verdict."""
import hashlib

import pytest
from jsonschema import Draft7Validator

from tests.dispatch_schema_parity import (
    PREDECESSOR_MANIFEST, PREDECESSOR_SHA256, WIRE_FORMATS, cases, dispatch_routes,
)
from tools.apisix_request_schema import apisix_dialect


@pytest.fixture(scope='module')
def routes(tmp_path_factory):
    return dispatch_routes(tmp_path_factory.mktemp('release'))


def test_predecessor_manifest_is_the_service_snapshot():
    assert hashlib.sha256(PREDECESSOR_MANIFEST.read_bytes()).hexdigest() == PREDECESSOR_SHA256


def test_every_dispatch_schema_is_in_the_apisix_dialect(routes):
    assert len(routes) >= 20
    for uri, route in routes.items():
        schema = route['plugins']['request-validation']['body_schema']
        assert schema == apisix_dialect(schema), uri


def test_empty_array_keywords_are_normalized_or_rejected():
    assert apisix_dialect({'type': 'object', 'required': []}) == {'type': 'object'}
    with pytest.raises(ValueError):
        apisix_dialect({'type': 'object', 'properties': {'a': {'enum': []}}})
    # A property literally named "required" is a schema, not the keyword.
    named = {'type': 'object', 'properties': {'required': {'type': 'string'}}, 'required': ['required']}
    assert apisix_dialect(named) == named


def test_projection_keeps_the_mcp_verdict_and_the_predecessor_requests(routes):
    validators = {}
    mismatches = []
    counts = {'current': 0, 'predecessor': 0}
    covered = set()
    for uri, body, expected, kind in cases(routes):
        if uri not in validators:
            validators[uri] = Draft7Validator(routes[uri]['plugins']['request-validation']['body_schema'],
                                              format_checker=WIRE_FORMATS)
        counts[kind] += 1
        if expected:
            covered.add(uri)
        if validators[uri].is_valid(body) != expected:
            mismatches.append((uri, kind, expected, body['Arguments']))
    assert not mismatches, mismatches[:5]
    assert counts['predecessor'] > 0
    uncovered = set(validators) - covered
    assert not uncovered, f'no accepted case for {sorted(uncovered)}'
