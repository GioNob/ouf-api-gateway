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
        return without_schema_ids(projected)
    return projected


def without_schema_ids(node):
    if isinstance(node, dict):
        return {key: without_schema_ids(value) for key, value in node.items() if key != '$id'}
    if isinstance(node, list):
        return [without_schema_ids(value) for value in node]
    return node
