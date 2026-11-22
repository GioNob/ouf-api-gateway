"""Import the three MCP input schemas into their Gateway dispatch envelopes offline."""
import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ROUTES = {
    'semantic.propose': 'semantic-proposals',
    'source.onboarding.create': 'managed-file-dispatch',
    'source.onboarding.revision.prepare': 'source-revision-prepare-dispatch',
}


def envelope_refs(node):
    """The root seen by APISIX is the HTTP envelope, one level above Arguments."""
    if isinstance(node, list):
        return [envelope_refs(child) for child in node]
    if isinstance(node, dict):
        if '$ref' in node:
            ref = node['$ref']
            if not ref.startswith('#/'):
                raise ValueError('expected a local MCP schema reference')
            return {**node, '$ref': '#/properties/Arguments/' + ref[2:]}
        result = {key: envelope_refs(value) for key, value in node.items()}
        # The installation's Lua validator handles boolean propertyNames only.
        # Express MCP's closed name lists using its supported object keywords.
        if 'propertyNames' in result:
            names = result.pop('propertyNames')
            properties = result.get('properties', {})
            if set(names) != {'enum'} or set(properties) - set(names['enum']):
                raise ValueError('unsupported propertyNames projection')
            result['properties'] = {key: properties.get(key, {}) for key in names['enum']}
            result['additionalProperties'] = False
        return result
    return node


def sync(checkout, check):
    contract = 'contracts/ouf-value-types-v1.json'
    if (checkout / contract).read_bytes() != (ROOT / contract).read_bytes():
        raise ValueError('VALUE_TYPES_CONTRACT_MISMATCH')
    manifest = json.loads((checkout / 'internal/manifest/capabilities.json').read_bytes())
    capabilities = {row['toolName']: row for row in manifest['capabilities']}
    for name, stem in ROUTES.items():
        capability = capabilities[name]
        path = ROOT / f'schemas/mcp-gateway-{stem}-v1.json'
        document = json.loads(path.read_bytes())
        branches = document.get('oneOf', [document])
        branch, = (s for s in branches
                   if s['properties']['CapabilityID']['const'] == capability['capabilityId'])
        # These schemas are validated both in the catalog and as a standalone
        # APISIX body_schema. The embedded resource has its own reference root.
        branch['$id'] = 'urn:ouf:gateway:dispatch:' + name
        branch['properties']['Arguments'] = envelope_refs(capability['inputSchema'])
        fixture = Path('internal/kernel/testdata/value-types') / (name + '.json')
        target = ROOT / 'tests/fixtures/value-types' / fixture.name
        source = (checkout / fixture).read_bytes()
        if check:
            if document != json.loads(path.read_bytes()) or json.loads(target.read_bytes()) != json.loads(source):
                raise ValueError('VALUE_TYPES_DISPATCH_DRIFT: ' + name)
        else:
            path.write_text(json.dumps(document, ensure_ascii=True, indent=2) + '\n', encoding='utf-8')
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mcp_checkout', type=Path)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    sync(args.mcp_checkout, args.check)
