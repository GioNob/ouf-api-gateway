"""Release bindings and pinned MCP declarations for the three installed Semantic tools."""
import copy
import json
from pathlib import Path

from tools.delegation_functions import function


GET = 'mcp-semantic-get'
CAPABILITIES = {
    GET: 'ouf.semantic.consultation.read',
    'semantic-proposal-validate': 'ouf.semantic.review.prepare',
    'semantic-proposal-review': 'ouf.semantic.approval.request',
}
SERVICE = 'ouf-semantic-registry'
DISPATCH_BINDINGS = {
    route_id: (SERVICE, 'gateway.semanticReadOwnerKeyEnv' if route_id == GET else 'gateway.semanticProposalOwnerKeyEnv')
    for route_id in CAPABILITIES
}
SNAPSHOT = Path(__file__).resolve().parents[1] / 'contracts/mcp-semantic_mcp-capabilities.json'


def declarations():
    rows = json.loads(SNAPSHOT.read_bytes())['capabilities']
    result = {row['capabilityId']: row for row in rows}
    if len(rows) != len(result) or result.keys() != set(CAPABILITIES.values()):
        raise ValueError('expected the three distinct Semantic MCP declarations')
    return result


def materialize(mediated, runtime, delegation_env, read_env):
    """Complete the two existing proposal mediations and bind the installed get endpoint."""
    from tools.mcp_dispatch_contract import EXECUTE_PATH, capability_contracts

    routes = {r['id']: r for r in mediated['routes']}
    template, = (r for r in routes.values() if r.get('uri') == EXECUTE_PATH)
    installation = runtime['x-ouf-installation']
    for route_id, capability in CAPABILITIES.items():
        mode = route_id.rsplit('-', 1)[1]
        read = route_id == GET
        binding, = (r for r in runtime['routes'] if r['id'] == route_id)
        backend = binding['x-ouf-backend-binding']
        path = ('/api/internal/v1/semantic/consultation/' if read else '/api/semantic/v1/proposal-commands/') + mode
        policy, cap = binding['x-ouf-policy'], binding['x-ouf-capability']
        contract = capability_contracts()[capability]
        if (binding['uri'] != EXECUTE_PATH + '/semantic/' + mode or binding['methods'] != ['POST']
                or binding.get('vars') or binding['labels']['exposure'] != 'internal'
                or backend['service'] != SERVICE or backend['path'] != path
                or cap['capabilityId'] != capability or cap['owner'] != contract['owner'] or cap['owner'] != 'semantic'
                or cap['operationType'] != contract['operationClass'] or cap['operationType'] != ('READ' if read else 'COMMAND')
                or cap['humanRequired'] != read or not cap['toolEligible'] or not contract['toolEligible']
                or contract['publicationState'] != 'ACTIVE' or contract['gatewayBindingRef'] != 'capability://' + capability
                or contract['requiredAuthorizationCapability'] != capability
                or policy['identity'] != 'M2M' or policy['allowedServiceIdentities'] != [installation['mcpServiceIdentity']]
                or policy['requiredScope'] != ('ouf.semantic.read' if read else capability)
                or policy['allowedActorTypes'] != (['HUMAN'] if read else ['HUMAN', 'AI_AGENT', 'SERVICE'])
                or policy['maxRequestBytes'] != 65536 or policy['timeoutSeconds'] != 3):
            raise ValueError(f'{route_id}: installed Semantic binding mismatch')
        if read:
            if delegation_env == read_env or any(r['id'] == GET or r.get('uri') == binding['uri'] for r in routes.values()):
                raise ValueError('expected a distinct Semantic read key and unoccupied get binding')
            route = copy.deepcopy(template)
            route.update(id=GET, uri=binding['uri'])
            route['labels']['ouf-mediation'] = 'semantic-read-v1'
            plugins = route['plugins']
            plugins['request-validation'] = copy.deepcopy(binding['plugins']['request-validation'])
            plugins['serverless-post-function']['functions'] = [
                function('execute_semantic_read', installation, delegation_env, read_env,
                         use_route_labels=True, read_mode='get')]
            plugins['proxy-rewrite']['uri'] = path
            mediated['routes'].append(route)
        else:
            route = routes[route_id]  # add_to_existing owns the command envelope and receipt.
        route.update(priority=0, status=1)
        route['labels']['ouf-exposure'] = 'internal'
        route['plugins']['request-id'] = copy.deepcopy(binding['plugins']['request-id'])
        quota = route['plugins']['limit-count']
        quota.update(count={'$installation': 'gateway.rateLimits.semanticMcp.count'},
                     time_window={'$installation': 'gateway.rateLimits.semanticMcp.timeWindowSeconds'})
        timeout = policy['timeoutSeconds']
        route['upstream'] = {'type': 'roundrobin', 'scheme': 'http', 'retries': 0,
                             'timeout': dict(connect=timeout, send=timeout, read=timeout),
                             'nodes': {f"{SERVICE}:{backend['port']}": 1}}


def _selectors_overlap(left, right):
    def host_set(route):
        return {h.lower() for h in route.get('hosts', []) + ([route['host']] if 'host' in route else [])}

    left_hosts, right_hosts = host_set(left), host_set(right)
    left_methods, right_methods = set(left.get('methods', [])), set(right.get('methods', []))
    return (bool(set(left.get('uris', [left.get('uri')])).intersection(right.get('uris', [right.get('uri')])))
            and not (left_hosts and right_hosts and left_hosts.isdisjoint(right_hosts))
            and not (left_methods and right_methods and left_methods.isdisjoint(right_methods)))


def adoption_plan(desired, inventory):
    """Offline plan for the installed family. Check foreign selectors against the entire release."""
    from tools.plan_semantic_search import Change, inventory_routes

    live = inventory_routes(inventory)
    targets = {r['id']: r for r in desired}
    if len(targets) != len(desired):
        raise ValueError('duplicate release route ID')
    for key in live.keys() - targets.keys():
        if any(_selectors_overlap(live[key], route) for route in targets.values()):
            raise ValueError(f'foreign selector conflict: {key}')
    changes = []
    for key, capability in CAPABILITIES.items():
        route, before = targets[key], live.get(key)
        if (before is None or before.get('uri') != route['uri'] or before.get('methods') != ['POST']
                or any(before.get(field) for field in ('uris', 'host', 'hosts', 'vars', 'remote_addr', 'remote_addrs', 'filter_func'))
                or before['labels']['ouf-installation'] != route['labels']['ouf-installation']
                or before['plugins']['proxy-rewrite'] != route['plugins']['proxy-rewrite']
                or before['plugins']['request-validation']['body_schema']['properties']['CapabilityID'] != {'const': capability}):
            raise ValueError(f'{key}: expected installed Semantic binding')
        changes.append(Change(key, key, before, route))
    return changes


def restore_plan(plan, desired, readback):
    """Reconcile the readback and selectors before returning the original bodies."""
    from tools.plan_semantic_search import Change, changed_paths

    current = adoption_plan(desired, readback)
    by_id = {c.target_id: c.before for c in current}
    for change in plan:
        if next(changed_paths(change.after, by_id[change.target_id]), None) is not None:
            raise ValueError(f'{change.target_id}: restore readback drift')
    return [Change(c.logical_id, c.target_id, c.after, c.before) for c in reversed(plan)]
