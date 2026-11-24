"""Offline 51h selector check, real-ID adoption and guarded restore."""
import argparse
import json
from pathlib import Path

from tools.plan_semantic_search import Change, changed_paths, inventory_routes
from tools.release_family_read_operations_mcp import ROUTES


def selectors_overlap(left, right):
    def values(route, singular, plural):
        return set(route.get(plural, ())) | ({route[singular]} if singular in route else set())

    def intersects(a, b):
        return not a or not b or not set(a).isdisjoint(b)

    return (bool(values(left, 'uri', 'uris') & values(right, 'uri', 'uris'))
            and intersects(left.get('methods'), right.get('methods'))
            and intersects({h.lower() for h in values(left, 'host', 'hosts')},
                           {h.lower() for h in values(right, 'host', 'hosts')}))


def checked_inventory(desired, inventory):
    live = inventory_routes(inventory)
    managed = {r['id'] for r in desired}
    for key, installed in live.items():
        if key not in managed and any(selectors_overlap(route, installed) for route in desired):
            raise ValueError('unmanaged selector conflict: ' + key)
    return live


def adoption_plan(desired, inventory):
    live = checked_inventory(desired, inventory)
    targets = {r['id']: r for r in desired if r['id'] in ROUTES}
    if targets.keys() != ROUTES.keys():
        raise ValueError('incomplete family in release')
    changes = []
    for key, target in targets.items():
        old = live.get(key)
        if not old or any(old.get(field) != target.get(field) for field in ('uri', 'methods', 'host', 'hosts', 'vars')):
            raise ValueError('missing installed ID or selector drift: ' + key)
        if old['labels']['ouf-installation'] != target['labels']['ouf-installation']:
            raise ValueError('installation drift: ' + key)
        old_fields = old['plugins']['request-validation']['body_schema']['properties']
        new_fields = target['plugins']['request-validation']['body_schema']['properties']
        if any(old_fields[k] != new_fields[k] for k in ('Owner', 'CapabilityID', 'GatewayBindingRef', 'OperationClass')):
            raise ValueError('dispatch identity drift: ' + key)
        if (old['plugins']['proxy-rewrite'] != target['plugins']['proxy-rewrite']
                or old['labels']['ouf-mediation'] != target['labels']['ouf-mediation']):
            raise ValueError('owner binding drift: ' + key)
        changes.append(Change(key, key, old, target))
    return changes


def restore_plan(changes, desired, readback):
    live = checked_inventory(desired, readback)
    for change in changes:
        if next(changed_paths(change.after, live.get(change.target_id)), None) is not None:
            raise ValueError('restore readback drift: ' + change.target_id)
    return [Change(c.logical_id, c.target_id, c.after, c.before) for c in reversed(changes)]


def read_inventory(path):
    doc = json.loads(path.read_bytes())
    if isinstance(doc, list):
        return {'total': len(doc), 'list': [{'value': row} for row in doc]}
    return doc


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--resolved-routes', type=Path, required=True)
    parser.add_argument('--inventory', type=Path, required=True)
    parser.add_argument('--restore-inventory', type=Path)
    args = parser.parse_args()
    desired = json.loads(args.resolved_routes.read_bytes())
    changes = adoption_plan(desired, read_inventory(args.inventory))
    if args.restore_inventory:
        changes = restore_plan(changes, desired, read_inventory(args.restore_inventory))
    print(json.dumps([{'id': c.target_id, 'action': c.action, 'changedPaths': list(changed_paths(c.before, c.after))}
                      for c in changes]))
