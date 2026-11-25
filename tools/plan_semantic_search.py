"""Read-only D-087 search preflight on resolved release routes and a complete APISIX routes list."""
import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path

from tools.mcp_dispatch_contract import EXECUTE_PATH, SEARCH_BINDINGS, bound_capability
from tools.analysis_protocol import ACTIONS, BASE as MANDATE_PATH, RENEWAL_SELECTORS
from tools.materialize_semantic_provider import materialize as provider_routes, _materialize
from tools.semantic_provider_quota import provider_quota


# Exact public selectors in the approved task-55c bundle (daa7351).
_OLD_REVIEW_SEGMENT = '[A-Za-z0-9_~-][A-Za-z0-9._~-]*'
_OLD_REVIEW_PAGE = '^/trusted-human/analysis-renewal/' + _OLD_REVIEW_SEGMENT
_OLD_RENEWAL_REGEX = {
    'trusted-human-analysis-renewal-read': (_OLD_REVIEW_PAGE + '(?:/(?:' + _OLD_REVIEW_SEGMENT
                                           + '/)*' + _OLD_REVIEW_SEGMENT + r'\.(?:js|css))?$'),
    'trusted-human-analysis-renewal-decide': _OLD_REVIEW_PAGE + '/decision$',
}


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


def overlaps(route, uri, method='POST'):
    if route.get('methods') and method not in route['methods']:
        return False
    for path in route.get('uris', [route.get('uri')]):
        if not isinstance(path, str):
            raise ValueError('incomplete route selector in inventory')
        # An overlapping wildcard or parameterized selector requires reconciliation.
        pattern = '/'.join('[^/]+' if part.startswith(':') else re.escape(part).replace(r'\*', '.*')
                           for part in path.split('/'))
        if re.fullmatch(pattern, uri):
            return True
        if uri.endswith('/*'):
            # Conservatively reconcile a concrete child or parameterized subtree of this prefix.
            prefix = uri[:-1]
            fixed = re.split(r'\*|(?<=/):', path, maxsplit=1)[0]
            if fixed.startswith(prefix) or (fixed != path and prefix.startswith(fixed)):
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


def search_plan(desired, inventory, current_revision, *, mandates=False, renewals=False):
    live = inventory_routes(inventory)
    bindings = ({'mcp-analysis-mandate-' + action: (None, MANDATE_PATH + action, None)
                 for action in ACTIONS if action != 'renewal-check'} if mandates else SEARCH_BINDINGS)
    if renewals:
        bindings = {key: (None, uri, None) for key, (_, uri, _) in RENEWAL_SELECTORS.items()}
    targets = [r for r in desired if r['id'] in bindings]
    installations = {(r['labels']['ouf-installation'], r['labels']['ouf-installation-revision']) for r in targets}
    if len(installations) != 1 or not all(isinstance(v, str) and v for v in next(iter(installations))):
        raise ValueError('resolved search routes must have one installation and revision')
    changes = []
    for logical_id, (cap, suffix, owner_op) in bindings.items():
        target, = (r for r in targets if r['id'] == logical_id)
        uri = suffix if mandates or renewals else EXECUTE_PATH + suffix
        method, _, regex = RENEWAL_SELECTORS[logical_id] if renewals else ('POST', uri, None)
        selector = [['uri', '~~', regex]] if regex else None
        if target['uri'] != uri or target['methods'] != [method] or target.get('vars') != selector:
            raise ValueError(f'{logical_id}: unexpected release selector')
        owner_path = None if mandates or renewals else '/api/internal/v1/semantic/consultation/' + owner_op
        matches = [key for key, r in live.items() if overlaps(r, uri, method)]
        if logical_id in live and logical_id not in matches:
            raise ValueError(f'{logical_id}: ID occupied by another route')
        for key in matches:
            r = live[key]
            labels = r.get('labels', {})
            plugins = r.get('plugins', {})
            allowed_selectors = [selector]
            if renewals and key == logical_id and key in _OLD_RENEWAL_REGEX:
                old_selector = [['uri', '~~', _OLD_RENEWAL_REGEX[key]]]
                old_labels = {**target['labels'], 'ouf-installation-revision': current_revision}
                if r == {**target, 'vars': old_selector, 'labels': old_labels}:
                    allowed_selectors.append(old_selector)
            if (r.get('uris', [r.get('uri')]) != [uri] or r.get('methods') != [method]
                    or (r.get('vars') or None) not in allowed_selectors
                    or any(r.get(k) for k in ('host', 'hosts', 'remote_addr', 'remote_addrs', 'filter_func'))
                    or labels.get('ouf-installation') != target['labels']['ouf-installation']
                    or labels.get('ouf-installation-revision') != current_revision
                    or plugins.get('proxy-rewrite', {}).get('uri') != owner_path):
                raise ValueError(f'{logical_id}: selector, owner or installation drift at {key}')
            if renewals:
                if key != logical_id or labels.get('ouf-capability') != target['labels']['ouf-capability']:
                    raise ValueError(f'{logical_id}: conflicting installed renewal binding at {key}')
            elif mandates:
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
        # The plan admits retired duplicates only with exactly one selector URI and method.
        target = c.after or c.before
        uri, = target.get('uris', [target.get('uri')])
        if any(overlaps(r, uri, target['methods'][0]) for key, r in live.items() if key not in affected):
            raise ValueError('unexpected search selector at restore')
        if next(changed_paths(c.after, live.get(c.target_id)), None) is not None:
            raise ValueError(f'{c.logical_id}: restore readback drift at {c.target_id}')
    return [Change(c.logical_id, c.target_id, c.after, c.before) for c in reversed(plan)]


def provider_plan(desired, inventory, binding, previous=None):
    """Check the two resolved private routes and recognize only exact before-images."""
    resolved = provider_routes({'routes': []}, binding)
    old = {}
    if previous is not None:
        if previous['installation'] != binding['installation']:
            raise ValueError('provider installation drift')
        prior = _materialize({'routes': []}, previous, predecessor='quotaInventory' not in previous)
        old = {r['id']: r for r in prior['routes']}
        if old.keys() != {r['id'] for r in resolved['routes']}:
            raise ValueError('provider route identity drift')
    live = inventory_routes(inventory)
    changes = []
    for target in resolved['routes']:
        key = target['id']
        candidates = [r for r in desired if r['id'] == key]
        if len(candidates) != 1 or next(changed_paths(candidates[0], target), None) is not None:
            raise ValueError(f'{key}: resolved provider route drift')
        uri, method = target['uri'], target['methods'][0]
        if key in old and (old[key]['uri'] != uri or old[key]['methods'] != [method]):
            raise ValueError(f'{key}: provider selector drift')
        if any(overlaps(r, uri, method) for r in desired if r['id'] != key):
            raise ValueError(f'{key}: overlapping release selector')
        if any(overlaps(r, uri, method) for k, r in live.items() if k != key):
            raise ValueError(f'{key}: overlapping installed selector')
        before = live.get(key)
        if before is not None and all(next(changed_paths(before, image), None) is not None
                                      for image in (target, old.get(key))):
            raise ValueError(f'{key}: provider predecessor drift')
        changes.append(Change(key, key, before, target))
    return changes, resolved['providerQuotaPlan']


def provider_restore_plan(changes, readback, binding):
    restored = restore_plan(changes, readback)
    by_id = {c.target_id: c for c in restored}
    routes = {name: by_id[binding[name + 'RouteId']] for name in ('search', 'fetch')}
    # A removed route admits zero traffic. Its checked forward limit is a
    # conservative placeholder while validating the two-slot inventory.
    limits = {name: (c.after or c.before)['plugins']['limit-count'] for name, c in routes.items()}
    quota = provider_quota(binding['quotaInventory'], limits)
    return restored, {name: quota[name] for name, c in routes.items() if c.after is not None}


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
    parser.add_argument('--current-revision')
    parser.add_argument('--family', choices=('semantic-search', 'analysis-mandate', 'analysis-renewal', 'semantic-provider'), default='semantic-search')
    parser.add_argument('--provider-binding', type=Path, help='provider route configuration including quotaInventory')
    parser.add_argument('--previous-provider-binding', type=Path, help='exact prior configuration for governed adoption')
    parser.add_argument('--restore-inventory', type=Path, help='post-apply readback for a restore plan')
    args = parser.parse_args()
    desired = json.loads(args.resolved_routes.read_bytes())
    inventory = json.loads(args.inventory.read_bytes())
    if args.family == 'semantic-provider':
        if not args.provider_binding:
            parser.error('--provider-binding is required for semantic-provider')
        previous = json.loads(args.previous_provider_binding.read_bytes()) if args.previous_provider_binding else None
        binding = json.loads(args.provider_binding.read_bytes())
        plan, quota = provider_plan(desired, inventory, binding, previous)
    else:
        if not args.current_revision or args.provider_binding or args.previous_provider_binding:
            parser.error('expected --current-revision and no provider binding')
        plan = search_plan(desired, inventory, args.current_revision, mandates=args.family == 'analysis-mandate',
                           renewals=args.family == 'analysis-renewal')
    if args.restore_inventory:
        readback = json.loads(args.restore_inventory.read_bytes())
        if args.family == 'semantic-provider':
            plan, quota = provider_restore_plan(plan, readback, binding)
        else:
            plan = restore_plan(plan, readback)
    rows = [{'logicalId': c.logical_id, 'id': c.target_id, 'action': c.action,
             'changedPaths': list(changed_paths(c.before, c.after))} for c in plan]
    print(json.dumps({'providerQuotaPlan': quota, 'changes': rows} if args.family == 'semantic-provider' else rows))
