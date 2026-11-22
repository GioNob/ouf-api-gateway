"""Deterministic JSON instances for differential schema tests.

The corpus is derived from a source JSON Schema: candidate instances are
generated from its keywords, then each mutation is kept with its verdict under
the source schema. Tests compare that verdict with another validator.
"""
import copy
import re

UUID = '3f1c2d4e-5a6b-4c7d-8e9f-0a1b2c3d4e5f'
STRING_CANDIDATES = (
    'a', 'A', 'ab', 'abc', 'x1', 'v1', '1', 'human-a', 'ente:staff', 'viewer', 'GRANTS',
    'edicole-trieste', 'TS-001', 'a.b', 'a_b', 'A_B', 'AB', 'it', 'it-IT', '1.0.0',
    UUID, 'sha256:' + '0' * 64, '0' * 64, 'object://ouf/a', 'capability://ouf.system.status',
    'urn:ouf:x', 'https://example.org/ouf/a', 'https://example.org/ouf/a#b', 'lake://' + UUID,
    'text/turtle', 'text/csv', 'application/json', 'POINT (13.7 45.6)', 'Place', 'place',
    '2026-11-22', '2026-11-22T10:00:00Z',
)
FORMATS = {
    'uuid': UUID,
    'date-time': '2026-11-22T10:00:00Z',
    'date': '2026-11-22',
    'uri': 'https://example.org/ouf/a',
    'iri': 'https://example.org/ouf/a',
    'uri-reference': 'https://example.org/ouf/a',
    'email': 'a@example.org',
}
MAX_VARIANTS = 8


def resolve(root, ref):
    if not ref.startswith('#/'):
        raise ValueError('only local references are supported')
    node = root
    for part in ref[2:].split('/'):
        node = node[part.replace('~1', '/').replace('~0', '~')]
    return node


def merge(base, extra):
    result = copy.deepcopy(base)
    for key, value in extra.items():
        if key == 'properties':
            props = result.setdefault('properties', {})
            for name, schema in value.items():
                props[name] = merge(props[name], schema) if name in props else copy.deepcopy(schema)
        elif key == 'required':
            result['required'] = list(dict.fromkeys(result.get('required', []) + value))
        elif key in ('allOf', 'oneOf', 'anyOf') and key in result:
            result.setdefault('allOf', []).append({key: value})
        else:
            result[key] = copy.deepcopy(value)
    return result


def flatten(schema, root, depth=0):
    """Expand $ref and allOf into a list of plain alternative schemas."""
    if depth > 12 or not isinstance(schema, dict):
        return [schema]
    if '$ref' in schema:
        siblings = {k: v for k, v in schema.items() if k != '$ref'}
        return flatten(merge(resolve(root, schema['$ref']), siblings), root, depth + 1)
    if 'allOf' in schema:
        base = {k: v for k, v in schema.items() if k != 'allOf'}
        variants = [base]
        for part in schema['allOf']:
            variants = [merge(v, alt) for v in variants for alt in flatten(part, root, depth + 1)][:MAX_VARIANTS]
        return [alt for v in variants for alt in flatten(v, root, depth + 1)][:MAX_VARIANTS]
    for key in ('oneOf', 'anyOf'):
        if key in schema:
            base = {k: v for k, v in schema.items() if k != key}
            return [alt for branch in schema[key] for alt in flatten(merge(base, branch), root, depth + 1)][:MAX_VARIANTS]
    return [schema]


def string_value(schema):
    if 'format' in schema and schema['format'] in FORMATS and 'pattern' not in schema:
        return FORMATS[schema['format']]
    low, high = schema.get('minLength', 0), schema.get('maxLength', 10 ** 6)
    candidates = list(STRING_CANDIDATES)
    if schema.get('format') in FORMATS:
        candidates.insert(0, FORMATS[schema['format']])
    pattern = schema.get('pattern')
    for value in candidates:
        if low <= len(value) <= high and (pattern is None or re.search(pattern, value)):
            return value
    if pattern is None:
        return ('a' * max(low, 1))[:high]
    return None


def instances(schema, root, depth=0):
    """Candidate instances (not guaranteed valid) for a schema."""
    out = []
    for alt in flatten(schema, root):
        if not isinstance(alt, dict):
            continue
        if 'const' in alt:
            out.append(copy.deepcopy(alt['const']))
            continue
        if 'enum' in alt:
            out.extend(copy.deepcopy(v) for v in alt['enum'][:4])
            continue
        kind = alt.get('type')
        if isinstance(kind, list):
            kind = next((k for k in kind if k != 'null'), 'null')
        if kind is None:
            kind = 'object' if 'properties' in alt or 'required' in alt else (
                'array' if 'items' in alt else 'string')
        if depth > 8:
            continue
        if kind == 'object':
            props = alt.get('properties', {})
            required = alt.get('required', [])
            for names in (required, list(props)):
                value = {}
                for name in names:
                    candidates = instances(props.get(name, {}), root, depth + 1)
                    if not candidates:
                        value = None
                        break
                    value[name] = candidates[0]
                if value is not None and value not in out:
                    out.append(value)
            # Explore each property's alternatives once, on the minimal object.
            base = out[-1] if out else {}
            for name in props:
                for candidate in instances(props[name], root, depth + 1)[1:3]:
                    variant = copy.deepcopy(base)
                    variant[name] = candidate
                    out.append(variant)
        elif kind == 'array':
            items = alt.get('items', {})
            count = max(alt.get('minItems', 0), 1)
            if isinstance(items, dict):
                candidates = instances(items, root, depth + 1)
                if candidates:
                    out.append([copy.deepcopy(candidates[i % len(candidates)]) for i in range(count)])
                if alt.get('minItems', 0) == 0:
                    out.append([])
        elif kind == 'string':
            value = string_value(alt)
            if value is not None:
                out.append(value)
        elif kind in ('integer', 'number'):
            low = alt.get('minimum', alt.get('exclusiveMinimum', 0) + (1 if 'exclusiveMinimum' in alt else 0))
            out.append(max(int(low), 1) if 'maximum' not in alt or alt['maximum'] >= 1 else int(low))
        elif kind == 'boolean':
            out.extend([True, False])
        elif kind == 'null':
            out.append(None)
    return out[:4 * MAX_VARIANTS]


def mutations(value):
    """Valid-looking and invalid neighbours of an object instance."""
    yield copy.deepcopy(value)
    if not isinstance(value, dict):
        return
    unexpected = copy.deepcopy(value)
    unexpected['__unexpected__'] = 1
    yield unexpected
    for name in value:
        dropped = copy.deepcopy(value)
        del dropped[name]
        yield dropped
        wrong = copy.deepcopy(value)
        wrong[name] = 12345 if not isinstance(value[name], int) or isinstance(value[name], bool) else 'not-a-number'
        yield wrong
        if isinstance(value[name], str):
            other = copy.deepcopy(value)
            other[name] = 'NOT_AN_ALLOWED_VALUE\n'
            yield other
    yield {}
    yield ['not-an-object']


def corpus(schema, extra=()):
    """Unique instances: generated candidates, their mutations and given fixtures."""
    seen, result = set(), []
    for base in list(instances(schema, schema)) + list(extra):
        for value in mutations(base):
            key = repr(value)
            if key not in seen:
                seen.add(key)
                result.append(value)
    return result
