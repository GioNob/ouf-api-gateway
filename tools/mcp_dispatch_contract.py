"""Pinned MCP input and result contracts for Gateway JSON dispatch."""
import json
import re
from functools import cache
from pathlib import Path


MANIFEST = Path(__file__).resolve().parents[1] / 'contracts/mcp-capabilities.json'
DISCOVERY_REVIEW_MANIFEST = MANIFEST.with_name('mcp-discovery-review-capabilities.json')
SEARCH_SCOPE = 'ouf.semantic.search'
SEARCH_BATCH = SEARCH_SCOPE + '.batch'
SEARCH_BINDINGS = {
    'mcp-semantic-search': (SEARCH_SCOPE, '/semantic/search', 'search'),
    'mcp-semantic-search-batch': (SEARCH_BATCH, '/semantic/consultation/search-batch', 'search-batch'),
}
SEARCH_BATCH_CONTRACT = MANIFEST.with_name('semantic-search-batch-v1.json')
DISCOVERY_SCOPE = 'ouf.semantic.discovery'
DISCOVERY_MODES = ('request', 'status', 'candidates', 'adopt')
DISCOVERY_REVIEW_SCHEMAS = {
    DISCOVERY_SCOPE + ('' if mode == 'request' else '.' + mode): 'semantic-discovery-' + mode
    for mode in DISCOVERY_MODES
}
DISCOVERY_REVIEW_SCHEMAS['ouf.managed-source.onboarding.review.prepare'] = 'onboarding-review-prepare'
# Arguments that guide the MCP decision and never reach the owner.
MCP_LOCAL_CONTEXT = {'ouf.managed-source.onboarding.review.prepare': ('draftAssetRef', 'revisionAssetRef')}
PICKER_CAPABILITY = 'ouf.managed-source.file.upload'
PICKER_ISSUE = 'ouf.managed-source.file.handoff-issue'
PICKER_MANIFEST = MANIFEST.with_name('mcp-picker-capabilities.json')
PICKER_ROUTES = {
    'mcp-managed-file-handoff': (PICKER_CAPABILITY, 'handoffInputSchema', 'handoffId'),
    'mcp-managed-file-handoff-issue': (PICKER_ISSUE, 'inputSchema', 'commandKey'),
}
INVALID_TOOL_ARGUMENTS = 'INVALID_TOOL_ARGUMENTS'
NEXT_RESULT_HEADROOM_BYTES = 2048
EXECUTE_PATH = '/internal/capabilities/v1/execute'
THS_LINK_PATH_PREFIX = '/api/internal/v1/onboarding/ths-links/'
THS_LINKS = {
    'ingestion-run-recovery': {'sourceId': 'string', 'runId': 'string', 'expectedVersion': 'integer'},
    'semantic-review': {'challengeId': 'string'},
}
THS_LINK_ROUTE_KEYS = {f'mcp-{key}-link': key for key in THS_LINKS}
MAX_SAFE_INTEGER = 2**53 - 1


def ths_link_schema_matches(schema, fields):
    properties = schema.get('properties', {})
    return (schema.get('type') == 'object' and schema.get('additionalProperties') is False
            and properties.keys() == fields.keys() and set(schema.get('required', [])) == fields.keys()
            and all(properties[name].get('type') == kind
                    and (kind != 'integer' or
                         0 <= properties[name].get('minimum', -1)
                         <= properties[name].get('maximum', MAX_SAFE_INTEGER + 1) <= MAX_SAFE_INTEGER)
                    for name, kind in fields.items()))


def manifest_execute_uri(binding_ref):
    """Resolve the canonical dispatch URI of a logical capability binding."""
    prefix = 'capability://'
    if not binding_ref.startswith(prefix):
        raise ValueError('expected a logical MCP capability binding')
    name = binding_ref.removeprefix(prefix)
    if not re.fullmatch(r'[a-z0-9][a-z0-9._-]*', name):
        raise ValueError('invalid MCP capability binding name')
    return f'{EXECUTE_PATH}/{name}'


@cache
def capability_contracts():
    rows = json.loads(MANIFEST.read_bytes())['capabilities']
    by_id = {row['capabilityId']: row for row in rows}
    if len(by_id) != len(rows):
        raise ValueError('duplicate capability ID in MCP manifest')
    subset = json.loads(DISCOVERY_REVIEW_MANIFEST.read_bytes())
    updated = {row['capabilityId']: row for row in subset}
    if len(updated) != len(subset) or updated.keys() != DISCOVERY_REVIEW_SCHEMAS.keys():
        raise ValueError('expected the five distinct discovery and review MCP declarations')
    by_id.update(updated)
    if SEARCH_BATCH not in by_id:
        batch = json.loads(SEARCH_BATCH_CONTRACT.read_bytes())
        if batch['capabilityId'] != SEARCH_BATCH or batch['provenance']['kind'] != 'contract-derived':
            raise ValueError('invalid provisional semantic batch declaration')
        by_id[SEARCH_BATCH] = batch
    return by_id


def dispatch_input_schema(capability, schema):
    """The MCP kernel consumes optional local context before dispatch for these tools.

    analysisId accompanies search, discovery and review commands. The draft and
    revision asset references guide the MCP decision for review.prepare and are
    removed from the owner command (MCP orchestration, withoutDraftContext).
    """
    local = set()
    if capability == SEARCH_SCOPE or capability in DISCOVERY_REVIEW_SCHEMAS:
        local.add('analysisId')
    local.update(MCP_LOCAL_CONTEXT.get(capability, ()))
    present = local & schema.get('properties', {}).keys()
    if not present:
        return schema
    for field in sorted(present):
        if field in schema.get('required', []):
            raise ValueError(f'{capability}: {field} must remain optional MCP context')
    return {**schema, 'properties': {k: v for k, v in schema['properties'].items() if k not in present}}


def picker_contract(route_id):
    capability, schema_key, field = PICKER_ROUTES[route_id]
    rows = json.loads(PICKER_MANIFEST.read_bytes())
    matches = [row for row in rows if row['capabilityId'] == capability]
    if len(matches) != 1 or schema_key not in matches[0]:
        raise ValueError(f'{route_id}: missing or ambiguous MCP declaration {capability}.{schema_key}; '
                         'synchronize the task-50n2 picker manifest')
    contract, = matches
    if (contract.get('publicationState') != 'ACTIVE' or contract.get('owner') != 'onboarding'
            or contract.get('operationClass') != 'COMMAND'
            or contract.get('requiredAuthorizationCapability') != PICKER_CAPABILITY
            or contract.get('gatewayBindingRef') != 'capability://' + capability
            or (capability == PICKER_ISSUE and contract.get('allowedActors') != ['HUMAN'])
            or contract.get('toolEligible') is not (capability == PICKER_CAPABILITY)):
        raise ValueError(f'{route_id}: inconsistent MCP contract for {capability}')
    schema = contract[schema_key]
    if (schema.get('type') != 'object' or schema.get('additionalProperties') is not False
            or schema.get('required') != [field] or set(schema.get('properties', {})) != {field}
            or schema['properties'][field].get('type') != 'string'
            or schema['properties'][field].get('format') != 'uuid'):
        raise ValueError(f'{route_id}: expected closed MCP dispatch schema with UUID {field}')
    return contract


def result_ceiling(capability, current):
    contract = capability_contracts().get(capability)
    if contract is None:
        return current
    limits = contract.get('operationalLimits', {})
    budget = max(limits.get('maxResultBytes', 0),
                 contract['baseCostEnvelope']['hardMaxResultBytes'])
    return max(current, budget + NEXT_RESULT_HEADROOM_BYTES)


def bound_capability(schema):
    field = schema['properties']['CapabilityID']
    if 'const' in field:
        return field['const']
    capability, = field['enum']
    return capability


# APISIX matches in PCRE byte mode. Expand classes above ASCII into
# alternatives that each match one complete UTF-8 character.
VALUE_MAP_SPACE_CLASS = '[\t-\r \u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]'
VALUE_MAP_SPACE_ALTERNATIVES = r'(?:[\x09-\x0D ]|' + '|'.join(
    '\u0085\u00a0\u1680' + ''.join(chr(code) for code in range(0x2000, 0x200B))
    + '\u2028\u2029\u202f\u205f\u3000'
) + ')'
VALUE_MAP_CONTROL_CLASS = r'[\x00-\x1F\x7F-\x9F]'
VALUE_MAP_CONTROL_ALTERNATIVES = r'(?:[\x00-\x1F\x7F]|' + '|'.join(
    chr(code) for code in range(0x80, 0xA0)
) + ')'


# Assert the RFC 3339 wire form even when a validator treats format as annotation.
UUID_WIRE_PATTERN = (
    r'^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}(?![\s\S])'
)
DATE_TIME_WIRE_PATTERN = (
    r'^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])[Tt]'
    r'([01][0-9]|2[0-3]):[0-5][0-9]:([0-5][0-9]|60)(\.[0-9]+)?'
    r'([Zz]|[+-]([01][0-9]|2[0-3]):[0-5][0-9])$'
)


def envelope_refs(node):
    """The root seen by APISIX is the HTTP envelope, one level above Arguments."""
    if isinstance(node, list):
        return [envelope_refs(child) for child in node]
    if isinstance(node, dict):
        if '$ref' in node:
            ref = node['$ref']
            if not ref.startswith('#/'):
                raise ValueError('expected a local MCP schema reference')
            projected = {'$ref': '#/properties/Arguments/' + ref[2:]}
            siblings = {key: value for key, value in node.items() if key != '$ref'}
            if not siblings:
                return projected
            # Draft 7 validators ignore siblings of $ref.
            result = envelope_refs(siblings)
            if ref == '#/$defs/valueMapIri' and set(siblings) == {'maxLength'}:
                result['type'] = 'string'
            result.setdefault('allOf', []).append(projected)
            return result
        result = {key: envelope_refs(value) for key, value in node.items()}
        if result.get('format') == 'date-time' and 'pattern' not in result:
            result['pattern'] = DATE_TIME_WIRE_PATTERN
        if result.get('format') == 'uuid' and 'pattern' not in result:
            result['pattern'] = UUID_WIRE_PATTERN
        if isinstance(result.get('pattern'), str):
            result['pattern'] = (result['pattern']
                                 .replace(VALUE_MAP_SPACE_CLASS, VALUE_MAP_SPACE_ALTERNATIVES)
                                 .replace(VALUE_MAP_CONTROL_CLASS, VALUE_MAP_CONTROL_ALTERNATIVES))
        # The installation's Lua validator handles boolean propertyNames only.
        # Express MCP's closed name lists using its supported object keywords.
        if 'propertyNames' in result:
            names = result.pop('propertyNames')
            properties = result.get('properties', {})
            if (set(names) != {'enum'} or set(properties) - set(names['enum'])
                    or 'patternProperties' in result
                    or result.get('additionalProperties', True) is not True):
                raise ValueError('unsupported propertyNames projection')
            result['properties'] = {key: properties.get(key, {}) for key in names['enum']}
            result['additionalProperties'] = False
        # APISIX's Lua validator reads an empty `required` table as "the object
        # must be empty". An empty `required` constrains nothing, so dropping it
        # is exact. A property named `required` maps to a schema, never to [].
        if result.get('required') == []:
            del result['required']
        return result
    return node

