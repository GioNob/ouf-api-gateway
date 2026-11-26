"""GW-59F. Onboarding derives acquisition limits; the agent may omit or only tighten them.

MCP task-59c (cefa37c, manifest 1.18.0) made executionProposal.limits optional. The
released review.prepare route must accept the proposal without limits, with a subset
of them and with all three as the MCP in service sends today, and keep the bounds.
"""
import copy

import pytest
from jsonschema import Draft7Validator, FormatChecker

from tests.test_discovery_review_release import dispatch
from tests.test_onboarding_review import request as review_request
from tests.test_value_type_schemas import routes  # noqa: F401  (module fixture)
from tools.mcp_dispatch_contract import DISCOVERY_REVIEW_MANIFEST, INVALID_TOOL_ARGUMENTS, dispatch_input_schema

ROUTE = 'mcp-managed-file-review-prepare'
PUBLICATION = '00000000-0000-4000-8000-000000000002'
IRI = 'https://schema.org/name'


def proposal(limits):
    policy = {'ref': 'identity-policy', 'version': '1', 'tenantId': 'tenant-a',
              'canonicalClass': 'https://schema.org/PerformingArtsTheater', 'sourceId': 'teatri',
              'maxCandidates': 10, 'allowAutoNew': True,
              'signals': [{'id': 'name', 'semanticRef': IRI + '@' + PUBLICATION, 'comparator': 'TEXT_V1',
                           'excludesOnDisagreement': False, 'uniqueWithinScope': False,
                           'assertionRef': 'reviewed-assertion'}],
              'sufficientRules': [{'id': 'name-rule', 'signalIds': ['name'], 'assertionRef': 'reviewed-rule'}]}
    result = {'semanticBindings': [{'semanticId': 'urn:fixture:ontology', 'semanticVersion': '1',
                                    'revisionId': '00000000-0000-4000-8000-000000000001',
                                    'publicationSetId': PUBLICATION}],
              'semanticPublicationSetRef': PUBLICATION,
              'udp': {'resolution': {'strategyId': 'GOVERNED_IDENTITY', 'strategyVersion': '1',
                                     'policyRef': 'identity-policy', 'governedIdentity': policy},
                      'materialization': {'policyRef': 'authority-policy',
                                          'properties': [{'sourceField': 'nome', 'propertyIri': IRI,
                                                          'datatype': 'http://www.w3.org/2001/XMLSchema#string',
                                                          'accessLabel': 'OPEN', 'authorityOrder': ['teatri']}],
                                          'bitemporalProperties': [], 'checkpointInterval': 1}}}
    if limits is not None:
        result['limits'] = limits
    return result


def body(limits):
    envelope = review_request()
    envelope['Arguments']['executionProposal'] = proposal(limits)
    return envelope


def released(routes):
    schema = routes[ROUTE]['plugins']['request-validation']['body_schema']
    return Draft7Validator(schema, format_checker=FormatChecker())


@pytest.mark.parametrize('limits', [
    None,
    {'maxRows': 100},
    {'maxColumns': 20, 'maxCellChars': 1000},
    {'maxRows': 100, 'maxColumns': 20, 'maxCellChars': 1000},
    {},
], ids=['absent', 'rows-only', 'two-limits', 'predecessor-three-limits', 'empty-object'])
def test_release_accepts_owner_derived_limits(routes, limits):
    """GW-59F-ACCEPT. Absent, partial and complete limits reach the owner unchanged."""
    released(routes).validate(body(limits))
    arguments = {'executionProposal': proposal(limits)}
    dispatch(routes, 'review-prepare', arguments=arguments)


@pytest.mark.parametrize('limits', [
    {'maxRows': -1},
    {'maxRows': '100'},
    {'maxRows': 1000001},
    {'maxColumns': 1.5},
    {'maxRows': 100, 'other': 1},
], ids=['negative', 'string', 'above-maximum', 'not-integer', 'unknown-field'])
def test_release_keeps_limit_bounds(routes, limits):
    """GW-59F-BOUNDS. Types, bounds and the closed object are unchanged."""
    assert routes[ROUTE]['plugins']['request-validation']['rejected_msg'] == INVALID_TOOL_ARGUMENTS
    assert not released(routes).is_valid(body(limits))


def test_mcp_local_context_is_not_part_of_the_owner_command():
    """GW-59F-LOCAL. draftAssetRef guides the MCP and never reaches Onboarding."""
    import json
    rows = json.loads(DISCOVERY_REVIEW_MANIFEST.read_bytes())
    row, = (r for r in rows if r['capabilityId'] == 'ouf.managed-source.onboarding.review.prepare')
    assert 'draftAssetRef' in row['inputSchema']['properties']
    wire = dispatch_input_schema(row['capabilityId'], row['inputSchema'])
    assert 'draftAssetRef' not in wire['properties'] and 'analysisId' not in wire['properties']
    required = copy.deepcopy(row['inputSchema'])
    required['required'] = required.get('required', []) + ['draftAssetRef']
    with pytest.raises(ValueError, match='optional MCP context'):
        dispatch_input_schema(row['capabilityId'], required)


def test_release_rejects_mcp_local_context_on_the_wire(routes):
    """GW-59F-WIRE. The MCP strips draftAssetRef before dispatch; the route stays closed."""
    candidate = body(None)
    candidate['Arguments']['draftAssetRef'] = {'assetId': '00000000-0000-4000-8000-000000000003',
                                               'profileId': '00000000-0000-4000-8000-000000000004'}
    assert not released(routes).is_valid(candidate)
