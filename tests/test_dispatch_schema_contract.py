"""Contract coverage for the compiled declarations and APISIX execute profiles."""
import hashlib
import json

from jsonschema import Draft7Validator, FormatChecker

from tests.test_execute_delegation import envelope
from tests.test_file_loop_coherence import retained_installation
from tests.test_onboarding_review import request as review_request
from tools.apisix_request_schema import inline_dispatch_schema
from tools.materialize_managed_upload import URI as UPLOAD_URI
from tools.materialize_onboarding_review import materialize as onboarding_review
from tools.materialize_operational_execute import CAPABILITIES as OPERATIONAL_CAPABILITIES
from tools.materialize_semantic_discovery import materialize as semantic_discovery
from tools.materialize_semantic_proposals import add_to_existing as semantic_proposals
from tools.materialize_source_revision import materialize as source_revision
from tools.mcp_dispatch_contract import (
    EXECUTE_PATH, INVALID_TOOL_ARGUMENTS, MANIFEST, NEXT_RESULT_HEADROOM_BYTES,
    bound_capability, capability_contracts, envelope_refs,
)

HANDOFF_URI = EXECUTE_PATH + '/managed.file/handoff'
REVIEW_READ_URI = EXECUTE_PATH + '/managed.file/review-read'
MANIFEST_SHA256 = '198487a5182e51abdfaacbf4f109ddc9532a3deee7d5f0921a3bd9aea77dfedd'


def dispatch_profiles():
    runtime, existing = retained_installation()
    doc = onboarding_review(existing, runtime, 'DELEGATION_KEY', 'OWNER_KEY')
    doc = source_revision(doc, runtime, 'DELEGATION_KEY', 'OWNER_KEY')
    doc = semantic_proposals(doc, runtime, 'DELEGATION_KEY', 'OWNER_KEY')
    doc = semantic_discovery(
        doc, runtime['x-ouf-installation'], 'DELEGATION_KEY', 'OWNER_KEY',
        {'scheme': 'http', 'nodes': {'ouf-semantic-registry:8080': 1}},
        {name: 'mcp-semantic-discovery-' + name for name in ('request', 'status', 'candidates')},
    )
    return runtime, [route for route in doc['routes'] if is_dispatch(route)]


def is_dispatch(route):
    path = route.get('uri', '')
    return path == EXECUTE_PATH or path.startswith(EXECUTE_PATH + '/')


def dispatch_body(schema, arguments):
    body = envelope()
    fields = schema['properties']
    for field in ('CapabilityID', 'GatewayBindingRef', 'Owner', 'OperationClass'):
        field_schema = fields[field]
        body[field] = field_schema['const'] if 'const' in field_schema else field_schema['enum'][0]
    body['Arguments'] = arguments
    return body


def test_manifest_is_exact_snapshot():
    assert hashlib.sha256(MANIFEST.read_bytes()).hexdigest() == MANIFEST_SHA256


def test_dispatch_profiles_match_pinned_manifest():
    runtime, profiles = dispatch_profiles()
    assert len({route['uri'] for route in profiles}) == len(profiles)
    contracts = capability_contracts()
    materialized = set()
    declared = set()
    internal_producers = OPERATIONAL_CAPABILITIES.keys() - contracts.keys()
    for route in profiles + [route for route in runtime['routes'] if is_dispatch(route)]:
        uri = route['uri']
        if uri == UPLOAD_URI:
            assert 'request-validation' not in route['plugins']
            continue
        if 'x-ouf-mediation' in route:
            # The compiler's generic execute binding is materialized as system.status.
            assert uri == EXECUTE_PATH
            continue
        compiled = 'x-ouf-capability' in route
        if compiled and route['x-ouf-capability']['capabilityId'] in internal_producers:
            continue

        validation = route['plugins']['request-validation']
        assert validation['rejected_msg'] == INVALID_TOOL_ARGUMENTS, uri
        schema = validation['body_schema']
        assert schema == inline_dispatch_schema(schema), uri
        validator = Draft7Validator(schema, format_checker=FormatChecker())
        validator.check_schema(schema)
        assert not validator.is_valid(dispatch_body(schema, ['private-source-value'])), uri
        capability = bound_capability(schema)
        fields = schema['properties']
        if uri == HANDOFF_URI:
            assert capability == 'ouf.managed-source.file.upload'
            assert fields['Arguments'] == {
                'type': 'object', 'additionalProperties': False, 'required': ['handoffId'],
                'properties': {'handoffId': {'type': 'string', 'format': 'uuid'}},
            }
            continue
        if capability in internal_producers:
            continue
        contract = contracts[capability]
        projected = envelope_refs(contract['inputSchema'])
        expected = inline_dispatch_schema({'properties': {'Arguments': projected}})
        assert fields['Arguments'] == expected['properties']['Arguments'], (uri, capability)
        budget = max(contract.get('operationalLimits', {}).get('maxResultBytes', 0),
                     contract['baseCostEnvelope']['hardMaxResultBytes'])
        assert fields['MaxResultBytes']['maximum'] >= budget + NEXT_RESULT_HEADROOM_BYTES, uri
        (declared if compiled else materialized).add(capability)

    # These bindings have no APISIX execute profile in this checkout.
    assert declared - materialized == {
        'urban.object.related_search', 'ouf.ingestion.status', 'ouf.ingestion.history',
        'ouf.operations.explain',
    }


def test_review_read_forms_in_manifest_and_inline():
    _, profiles = dispatch_profiles()
    route, = (route for route in profiles if route['uri'] == REVIEW_READ_URI)
    body_schema = route['plugins']['request-validation']['body_schema']
    manifest_schema = capability_contracts()['ouf.managed-source.onboarding.read']['inputSchema']
    gateway = Draft7Validator(body_schema, format_checker=FormatChecker())
    tool = Draft7Validator(manifest_schema, format_checker=FormatChecker())
    body = review_request('review-read')
    exact = body['Arguments']
    latest = {'sourceId': exact['sourceId'], 'view': 'LATEST'}
    for args, allowed in [
        (exact, True), (latest, True), (dict(exact, view='LATEST'), False),
        ({'sourceId': exact['sourceId']}, False), (dict(latest, view='LATEST_APPROVED'), False),
        (dict(latest, approvedBy='agent'), False), (dict(exact, onboardingVersionId='bad'), False),
    ]:
        assert gateway.is_valid(dict(body, Arguments=args)) == tool.is_valid(args) == allowed
