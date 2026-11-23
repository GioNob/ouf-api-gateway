"""Pin the two MCP manifest rows used by the internal file picker, offline."""
import argparse
import json
from pathlib import Path

from tools.mcp_dispatch_contract import PICKER_MANIFEST, PICKER_ROUTES


def sync(checkout, check):
    source = checkout / 'internal/manifest/capabilities.json'
    rows = json.loads(source.read_bytes())['capabilities']
    selected = []
    for capability, field, _ in sorted(PICKER_ROUTES.values()):
        matches = [row for row in rows if row['capabilityId'] == capability]
        if len(matches) != 1 or field not in matches[0]:
            raise ValueError(f'{source}: expected one MCP declaration for {capability}.{field}')
        selected.extend(matches)
    data = (json.dumps(selected, ensure_ascii=True, indent=2) + '\n').encode('utf-8')
    if check:
        if PICKER_MANIFEST.read_bytes() != data:
            raise ValueError('MCP picker manifest differs from the pinned snapshot')
    else:
        PICKER_MANIFEST.write_bytes(data)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mcp_checkout', type=Path)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    sync(args.mcp_checkout, args.check)
