"""Import the three MCP input schemas into their Gateway dispatch envelopes offline."""
import argparse
import json
from pathlib import Path

if __package__:
    from tools.mcp_dispatch_contract import MANIFEST, envelope_refs
else:
    from mcp_dispatch_contract import MANIFEST, envelope_refs

ROOT = Path(__file__).resolve().parents[1]
ROUTES = {
    'semantic.propose': 'semantic-proposals',
    'source.onboarding.create': 'managed-file-dispatch',
    'source.onboarding.revision.prepare': 'source-revision-prepare-dispatch',
}

def sync(checkout, check):
    for contract, error in (
        ('ouf-value-types-v1.json', 'VALUE_TYPES_CONTRACT_MISMATCH'),
        ('ouf-value-maps-v1.json', 'VALUE_MAPS_CONTRACT_MISMATCH'),
    ):
        source = checkout / 'contracts' / contract
        if not source.is_file() or source.read_bytes() != (ROOT / 'contracts' / contract).read_bytes():
            raise ValueError(error)
    source_manifest = (checkout / 'internal/manifest/capabilities.json').read_bytes()
    if source_manifest != MANIFEST.read_bytes():
        raise ValueError('MCP_DISPATCH_MANIFEST_MISMATCH')
    manifest = json.loads(source_manifest)
    capabilities = {row['toolName']: row for row in manifest['capabilities']}
    proposal = capabilities['semantic.propose']['inputSchema']
    if 'VALUE_MAP' not in proposal['properties']['artifactType']['enum']:
        raise ValueError('VALUE_MAP_SCHEMA_MISSING')
    if 'valueMapRationale' not in proposal['$defs']:
        raise ValueError('VALUE_MAP_SCHEMA_REVISION_2_MISSING')
    for name, stem in ROUTES.items():
        capability = capabilities[name]
        path = ROOT / f'schemas/mcp-gateway-{stem}-v1.json'
        document = json.loads(path.read_bytes())
        branches = document.get('oneOf', [document])
        branch, = (s for s in branches
                   if s['properties']['CapabilityID']['const'] == capability['capabilityId'])
        # The catalog branch has its own reference root. The APISIX
        # materializer drops this identifier when it extracts the branch.
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
