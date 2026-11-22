"""Project self-contained dispatch schemas into APISIX request-validation."""


def inline_dispatch_schema(schema):
    # The catalog gives each embedded branch its own reference root. Once a
    # branch becomes an independent body_schema, local JSON Pointers still
    # resolve from that root without an absolute $id, which APISIX 3.18 rejects.
    projected = {key: value for key, value in schema.items() if key != '$id'}
    pending = [projected]
    while pending:
        node = pending.pop()
        if isinstance(node, list):
            pending.extend(node)
        elif isinstance(node, dict):
            if {'$id', '$dynamicRef', '$recursiveRef'} & node.keys():
                raise ValueError('dispatch body schema must use a single reference root')
            if '$ref' in node and not node['$ref'].startswith('#/'):
                raise ValueError('dispatch body schema requires local JSON Pointer references')
            pending.extend(node.values())
    return projected
