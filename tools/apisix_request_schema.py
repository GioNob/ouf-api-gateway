"""Project self-contained dispatch schemas into APISIX request-validation."""

from tools.mcp_dispatch_contract import INVALID_TOOL_ARGUMENTS


def dispatch_validation(schema, request_limit):
    return {
        'max_req_body_size': request_limit,
        'body_schema': inline_dispatch_schema(schema),
        'rejected_msg': INVALID_TOOL_ARGUMENTS,
    }


def inline_dispatch_schema(schema):
    # The catalog gives each embedded branch its own reference root. Once a
    # branch becomes an independent body_schema, local JSON Pointers still
    # resolve from that root without an absolute $id, which APISIX 3.18 rejects.
    projected = {key: value for key, value in schema.items() if key != '$id'}
    pending = [projected]
    nested_ids = []
    has_refs = False
    while pending:
        node = pending.pop()
        if isinstance(node, list):
            pending.extend(node)
        elif isinstance(node, dict):
            if {'$dynamicRef', '$recursiveRef'} & node.keys():
                raise ValueError('dispatch body schema must use a single reference root')
            if '$id' in node:
                nested_ids.append(node)
            if '$ref' in node:
                has_refs = True
                if not node['$ref'].startswith('#/'):
                    raise ValueError('dispatch body schema requires local JSON Pointer references')
            pending.extend(node.values())
    if nested_ids:
        if has_refs:
            raise ValueError('dispatch body schema must use a single reference root')
        # Without references, these identifiers have no validation effect.
        return apisix_dialect(without_schema_ids(projected))
    return apisix_dialect(projected)


# Keywords whose values are schemas, maps of schemas or lists of schemas.
SCHEMA_MAPS = ('properties', 'patternProperties', '$defs', 'definitions', 'dependentSchemas')
SCHEMA_VALUES = ('items', 'additionalProperties', 'additionalItems', 'not', 'if', 'then', 'else',
                 'contains', 'propertyNames', 'unevaluatedProperties', 'unevaluatedItems')
SCHEMA_LISTS = ('allOf', 'anyOf', 'oneOf', 'prefixItems')
# The Lua validator receives YAML/JSON arrays as Lua tables: an empty array is
# indistinguishable from an empty object and is evaluated as such.
ARRAY_KEYWORDS = ('required', 'enum', 'type') + SCHEMA_LISTS


def apisix_dialect(schema):
    """Exact rewrite into the forms APISIX 3.18's Lua validator evaluates like JSON Schema.

    An empty `required` constrains nothing and is dropped. Any other empty
    array keyword has no exact equivalent for that validator and is rejected.
    """
    def walk(node):
        if not isinstance(node, dict):
            return node
        result = {}
        for key, value in node.items():
            if key in SCHEMA_MAPS and isinstance(value, dict):
                result[key] = {name: walk(child) for name, child in value.items()}
            elif key in SCHEMA_LISTS and isinstance(value, list):
                result[key] = [walk(child) for child in value]
            elif key in SCHEMA_VALUES:
                result[key] = [walk(child) for child in value] if isinstance(value, list) else walk(value)
            else:
                result[key] = value
        if result.get('required') == []:
            del result['required']
        for key in ARRAY_KEYWORDS:
            if result.get(key) == []:
                raise ValueError(f'APISIX Lua validator misreads an empty {key!r} array')
        return result
    return walk(schema)


def without_schema_ids(node):
    if isinstance(node, dict):
        return {key: without_schema_ids(value) for key, value in node.items() if key != '$id'}
    if isinstance(node, list):
        return [without_schema_ids(value) for value in node]
    return node
