"""Every JSON dispatch route, its pinned MCP contract and a differential corpus.

Shared by the offline dialect test and by the gate that runs the corpus through
the Lua validator of the APISIX image used in production.
"""
import copy
import json
import re
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from tests.release_bundle_fixture import ci_profile, load_release_routes
from tests.schema_corpus import corpus
from tests.test_dispatch_schema_contract import dispatch_body, dispatch_profiles
from tests.test_execute_delegation import runtime
from tests.test_onboarding_review import request as review_request
from tests.test_permission_role_contract import cases as permission_cases
from tools.gateway_release_bundle import generate
from tools.materialize_object_search import materialize as object_search
from tools.materialize_permission_proposals import materialize as permission_proposals
from tools.mcp_dispatch_contract import (
    DATE_TIME_WIRE_PATTERN, UUID_WIRE_PATTERN, bound_capability, capability_contracts,
)

ROOT = Path(__file__).resolve().parents[1]
# The MCP manifest of the release in service when this Gateway is released
# (D-086 train: the Gateway goes first, the MCP follows). Its requests must
# keep passing until the MCP is replaced.
PREDECESSOR_MANIFEST = ROOT / 'contracts/mcp-capabilities-predecessor.json'
PREDECESSOR_COMMIT = '843d22059e03bcd58569fff9960bb46ae552b2b2'
PREDECESSOR_SHA256 = 'e21634af3c7e087f753665be1e4babeb470541730383847e443ec4faa597efb6'
VALUE_TYPE_FIXTURES = {
    'ouf.semantic.propose': 'semantic.propose',
    'ouf.managed-source.onboarding.create': 'source.onboarding.create',
    'ouf.onboarding.revision.prepare': 'source.onboarding.revision.prepare',
}
# The managed-file create contract accepted by the Gateway in service.
PREDECESSOR_CREATE = {
    'assetId': '00000000-0000-4000-8000-000000000001', 'profileId': '00000000-0000-4000-8000-000000000002',
    'sourceId': 'cinema', 'name': 'Cinema', 'owner': 'Comune', 'targetClassIri': 'https://example.org/Cinema',
    'semanticRefs': ['core@1'], 'sourceObjectKeyFields': [],
    'fields': [{'fieldName': 'cinema', 'extractionDecision': 'INCLUDE', 'dataAccessLabel': 'OPEN',
                'targetPropertyIri': 'https://example.org/name'}],
}


def dispatch_routes(tmp_dir):
    """Unique JSON dispatch routes with request validation, keyed by URI."""
    routes = []
    routes += object_search(runtime(), '$ENV://OIDC_SECRET', 'DELEGATION_KEY', 'OWNER_KEY', 'UDP_KEY')['routes']
    routes += permission_proposals(runtime(), '$ENV://OIDC_SECRET', 'DELEGATION_KEY', 'OWNER_KEY')['routes']
    compiled, profiles = dispatch_profiles()
    routes += profiles + compiled['routes']
    commit, workflow = '1' * 40, '.github/workflows/ci.yml'
    generate(tmp_dir, commit, workflow, '50')
    profile = ci_profile({'installationId': 'fixture', 'revision': 1, **_install()}, 18080)
    routes += load_release_routes(tmp_dir, commit, workflow, '50', profile)
    unique = {}
    for route in routes:
        validation = route.get('plugins', {}).get('request-validation')
        if not validation or 'CapabilityID' not in validation['body_schema'].get('properties', {}):
            continue
        unique.setdefault(route['uri'], route)
    return unique


def _install():
    from tests.test_value_type_schemas import INSTALL
    return INSTALL


def fixtures(capability):
    extra = []
    if capability in VALUE_TYPE_FIXTURES:
        path = ROOT / 'tests/fixtures/value-types' / (VALUE_TYPE_FIXTURES[capability] + '.json')
        extra.append(json.loads(path.read_bytes())['Arguments'])
    if capability == 'ouf.managed-source.onboarding.create':
        extra.append(PREDECESSOR_CREATE)
    for cap, arguments, _ in permission_cases():
        if cap == capability:
            extra.append(arguments)
    if capability == 'ouf.managed-source.onboarding.read':
        args = review_request('review-read')['Arguments']
        extra += [args, {'sourceId': args['sourceId'], 'view': 'LATEST'}]
    return extra


# The Gateway boundary asserts formats: APISIX's Lua validator checks uuid,
# date, date-time and uri with its own expressions, and envelope_refs adds the
# RFC 3339 and UUID wire patterns. The reference verdict asserts the same
# forms (ASCII classes, as PCRE without UCP). APISIX rejects the RFC 3339 leap
# second ":60"; no MCP producer emits it. iri stays an annotation in both.
ASCII_SPACE = re.escape(''.join(map(chr, (32, 9, 10, 11, 12, 13))))
WIRE_FORMAT_PATTERNS = {
    'uuid': UUID_WIRE_PATTERN,
    'date': r'^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$',
    'date-time': (r'^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])[Tt]([01][0-9]|2[0-3]):[0-5][0-9]:'
                  r'[0-5][0-9](\.[0-9]+)?([Zz]|[+-]([01][0-9]|2[0-3]):[0-5][0-9])$'),
    'uri': r'^[A-Za-z][A-Za-z0-9+.-]*:[^' + ASCII_SPACE + r']*$',
}
WIRE_FORMATS = FormatChecker([])


def _wire_check(pattern):
    return lambda value: not isinstance(value, str) or re.search(pattern, value) is not None


for _name, _pattern in WIRE_FORMAT_PATTERNS.items():
    WIRE_FORMATS.checks(_name)(_wire_check(_pattern))


def predecessor_contracts():
    rows = json.loads(PREDECESSOR_MANIFEST.read_bytes())['capabilities']
    return {row['capabilityId']: row for row in rows}


def cases(routes):
    """(uri, body, expected, kind): expected is the verdict of the pinned MCP schema."""
    contracts, previous = capability_contracts(), predecessor_contracts()
    result = []
    for uri, route in sorted(routes.items()):
        schema = route['plugins']['request-validation']['body_schema']
        capability = bound_capability(schema)
        if capability not in contracts:
            continue
        source = contracts[capability]['inputSchema']
        check = Draft202012Validator(source, format_checker=WIRE_FORMATS)
        for arguments in corpus(source, fixtures(capability)):
            result.append((uri, dispatch_body(schema, copy.deepcopy(arguments)), check.is_valid(arguments), 'current'))
        if capability in previous:
            old = previous[capability]['inputSchema']
            old_check = Draft202012Validator(old, format_checker=WIRE_FORMATS)
            for arguments in corpus(old, fixtures(capability)):
                if old_check.is_valid(arguments):
                    result.append((uri, dispatch_body(schema, copy.deepcopy(arguments)), True, 'predecessor'))
    return result
