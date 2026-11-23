"""Read-only D-087 search preflight on resolved release routes and a complete APISIX routes list."""
import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path

from tools.mcp_dispatch_contract import EXECUTE_PATH, SEARCH_BINDINGS, bound_capability
from tools.analysis_protocol import BASE as MANDATE_PATH


@dataclass(frozen=True)
class Change:
    logical_id: str
    target_id: str
    before: dict | None
    after: dict | None

    @property
    def action(self):
        if self.before is None:
            return 'create'
        if self.after is None:
            return 'retire'
        return 'unchanged' if next(changed_paths(self.before, self.after), None) is None else 'update'


def overlaps(route, uri):
    if route.get('methods') and 'POST' not in route['methods']:
        return False
    for path in route.get('uris', [route.get('uri')]):
        if not isinstance(path, str):
            raise ValueError('incomplete route selector in inventory')
        # An overlapping wildcard or parameterized selector requires reconciliation.
        pattern = '/'.join('[^/]+' if part.startswith(':') else re.escape(part).replace(r'\*', '.*')
                           for part in path.split('/'))
        if re.fullmatch(pattern, uri):
            return True
    return False


def inventory_routes(inventory):
    rows = inventory['list']
    if len(rows) != inventory['total']:
        raise ValueError('complete APISIX routes inventory required')
    live = {}
    for row in rows:
        route = row['value']
        route_id = route.get('id')
        if 'key' in row:
            match = re.fullmatch(r'(?:/[^/]+)*/routes/([A-Za-z0-9._-]{1,64})', row['key'])
            if not match or (route_id is not None and str(route_id) != match[1]):
                raise ValueError('APISIX key and route ID disagree')
            route_id = match[1]
        if not isinstance(route_id, str) or not re.fullmatch(r'[A-Za-z0-9._-]{1,64}', route_id):
            raise ValueError('missing or invalid APISIX route ID')
        if route_id in live:
            raise ValueError('duplicate ID in APISIX inventory')
        live[route_id] = {**{k: v for k, v in route.items() if k not in ('create_time', 'update_time')}, 'id': route_id}
    return live


def search_plan(desired, inventory, current_revision, *, mandates=False):
    live = inventory_routes(inventory)
    bindings = ({'mcp-analysis-mandate-' + action: (None, MANDATE_PATH + action, None)
                 for action in ('issue', 'dispatch', 'revoke')} if mandates else SEARCH_BINDINGS)
    targets = [r for r in desired if r['id'] in bindings]
    installations = {(r['labels']['ouf-installation'], r['labels']['ouf-installation-revision']) for r in targets}
    if len(installations) != 1 or not all(isinstance(v, str) and v for v in next(iter(installations))):
        raise ValueError('resolved search routes must have one installation and revision')
    changes = []
    for logical_id, (cap, suffix, owner_op) in bindings.items():
        target, = (r for r in targets if r['id'] == logical_id)
        uri = suffix if mandates else EXECUTE_PATH + suffix
        if target['uri'] != uri or target['methods'] != ['POST']:
            raise ValueError(f'{logical_id}: unexpected release selector')
        owner_path = None if mandates else '/api/internal/v1/semantic/consultation/' + owner_op
        matches = [key for key, r in live.items() if overlaps(r, uri)]
        if logical_id in live and logical_id not in matches:
            raise ValueError(f'{logical_id}: ID occupied by another route')
        for key in matches:
            r = live[key]
            labels = r.get('labels', {})
            plugins = r.get('plugins', {})
            if (r.get('uris', [r.get('uri')]) != [uri] or r.get('methods') != ['POST']
                    or any(r.get(k) for k in ('vars', 'host', 'hosts', 'remote_addr', 'remote_addrs', 'filter_func'))
                    or labels.get('ouf-installation') != target['labels']['ouf-installation']
                    or labels.get('ouf-installation-revision') != current_revision
                    or plugins.get('proxy-rewrite', {}).get('uri') != owner_path):
                raise ValueError(f'{logical_id}: selector, owner or installation drift at {key}')
            if mandates:
                if labels.get('ouf-mediation') != 'analysis-mandate-v1':
                    raise ValueError(f'{logical_id}: installed mandate binding drift at {key}')
            elif bound_capability(plugins['request-validation']['body_schema']) != cap:
                raise ValueError(f'{logical_id}: installed capability drift at {key}')
        if len(matches) > 1 and logical_id not in matches:
            raise ValueError(f'{logical_id}: ambiguous installed IDs')
        key = logical_id if logical_id in matches or not matches else matches[0]
        changes.append(Change(logical_id, key, live.get(key), dict(target, id=key)))
        for duplicate in sorted(set(matches) - {key}):
            changes.append(Change(logical_id, duplicate, live[duplicate], None))
    return changes


def restore_plan(plan, readback):
    """Reverse only an acknowledged change set whose full after-images still match."""
    live = inventory_routes(readback)
    affected = {c.target_id for c in plan}
    for c in plan:
        uri = ((c.after or c.before)['uri'] if c.logical_id.startswith('mcp-analysis-mandate-')
               else EXECUTE_PATH + SEARCH_BINDINGS[c.logical_id][1])
        if any(overlaps(r, uri) for key, r in live.items() if key not in affected):
            raise ValueError('unexpected search selector at restore')
        if next(changed_paths(c.after, live.get(c.target_id)), None) is not None:
            raise ValueError(f'{c.logical_id}: restore readback drift at {c.target_id}')
    return [Change(c.logical_id, c.target_id, c.after, c.before) for c in reversed(plan)]


def changed_paths(before, after, path=''):
    if isinstance(before, dict) and isinstance(after, dict):
        for key in sorted(before.keys() | after.keys()):
            child = path + '/' + key.replace('~', '~0').replace('/', '~1')
            if key in before and key in after:
                yield from changed_paths(before[key], after[key], child)
            else:
                yield child
    elif isinstance(before, list) and isinstance(after, list) and len(before) == len(after):
        for index, (old, new) in enumerate(zip(before, after)):
            yield from changed_paths(old, new, f'{path}/{index}')
    elif type(before) != type(after) or before != after:
        yield path


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--resolved-routes', required=True, type=Path, help='resolved APISIX routes array')
    parser.add_argument('--inventory', required=True, type=Path, help='complete APISIX routes list response')
    parser.add_argument('--current-revision', required=True)
    parser.add_argument('--family', choices=('semantic-search', 'analysis-mandate'), default='semantic-search')
    parser.add_argument('--restore-inventory', type=Path, help='post-apply readback for a restore plan')
    args = parser.parse_args()
    plan = search_plan(json.loads(args.resolved_routes.read_bytes()), json.loads(args.inventory.read_bytes()),
                       args.current_revision, mandates=args.family == 'analysis-mandate')
    if args.restore_inventory:
        plan = restore_plan(plan, json.loads(args.restore_inventory.read_bytes()))
    print(json.dumps([{'logicalId': c.logical_id, 'id': c.target_id, 'action': c.action,
                       'changedPaths': list(changed_paths(c.before, c.after))} for c in plan]))
