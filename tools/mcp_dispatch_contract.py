"""Pinned MCP input and result contracts for Gateway JSON dispatch."""
import json
from functools import cache
from pathlib import Path


MANIFEST = Path(__file__).resolve().parents[1] / 'contracts/mcp-capabilities.json'
INVALID_TOOL_ARGUMENTS = 'INVALID_TOOL_ARGUMENTS'
NEXT_RESULT_HEADROOM_BYTES = 2048
EXECUTE_PATH = '/internal/capabilities/v1/execute'


@cache
def capability_contracts():
    rows = json.loads(MANIFEST.read_bytes())['capabilities']
    by_id = {row['capabilityId']: row for row in rows}
    if len(by_id) != len(rows):
        raise ValueError('duplicate capability ID in MCP manifest')
    return by_id


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
        return result
    return node

