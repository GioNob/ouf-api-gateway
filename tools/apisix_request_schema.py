"""Project self-contained dispatch schemas into APISIX request-validation."""

import json

from tools.mcp_dispatch_contract import (
    EXECUTE_PATH, INVALID_TOOL_ARGUMENTS, PICKER_ROUTES, bound_capability, capability_contracts,
    dispatch_input_schema, envelope_refs, picker_contract, ONBOARDING_DISPATCH, UPLOAD_ID,
)


def verify_dispatch_arguments(resources):
    """Check every released execute route against its declaration, including nested constraints."""
    from tools.release_family_read_operations_mcp import ROUTES, arguments as read_arguments
    for item in resources:
        route = item['body']
        uri = route.get('uri', '')
        if item['kind'] != 'routes':
            continue
        route_id = item['id']
        if route_id == UPLOAD_ID:
            if (uri != EXECUTE_PATH + '/managed.file/upload' or route['methods'] != ['POST']
                    or 'request-validation' in route['plugins']
                    or route['plugins'].get('proxy-control') != {'request_buffering': False}
                    or route['plugins'].get('client-control') != {'max_body_size': 10485760}):
                raise ValueError(f'{route_id}: expected bounded streaming dispatch')
            continue
        if uri != EXECUTE_PATH and not uri.startswith(EXECUTE_PATH + '/'):
            if route_id in ONBOARDING_DISPATCH:
                raise ValueError(f'{route_id}: expected Onboarding dispatch URI')
            continue
        schema = route['plugins']['request-validation']['body_schema']
        capability = bound_capability(schema)
        if route_id in ONBOARDING_DISPATCH and capability != ONBOARDING_DISPATCH[route_id]:
            raise ValueError(f'{route_id}: unexpected Onboarding dispatch capability')
        if route_id in ROUTES:
            expected = apisix_dialect(read_arguments(ROUTES[route_id]))
            if capability != ROUTES[route_id] or json.dumps(schema['properties']['Arguments'], sort_keys=True) != json.dumps(expected, sort_keys=True):
                raise ValueError(f'{route_id}: read operation differs from its dispatch contract')
            continue
        if route_id in PICKER_ROUTES:
            target, field, _ = PICKER_ROUTES[route_id]
            if capability != target:
                raise ValueError(f'{route_id}: unexpected picker capability')
            arguments = picker_contract(route_id)[field]
        else:
            arguments = dispatch_input_schema(capability, capability_contracts()[capability]['inputSchema'])
        expected = inline_dispatch_schema({'properties': {'Arguments': envelope_refs(arguments)}})
        actual = schema['properties']['Arguments']
        if json.dumps(actual, sort_keys=True) != json.dumps(expected['properties']['Arguments'], sort_keys=True):
            raise ValueError(f'{route_id}: Arguments differ from {capability} contract')


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
