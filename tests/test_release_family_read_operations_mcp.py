"""GW-60d qualification. The private export is consumed in memory only."""
import base64
import copy
import hashlib
import hmac
import json
import re
from collections import Counter

import pytest
from jsonschema import Draft7Validator

from tests.release_bundle_fixture import BASELINE_51M_IDS, READ_OPERATIONS_IDS, ci_profile, load_release_routes
from tools.apisix_request_schema import verify_dispatch_arguments
from tools.gateway_release_bundle import ROOT, canonical, digest, generate
from tools.plan_read_operations_mcp import adoption_plan, restore_plan, selectors_overlap
from tools.plan_semantic_search import changed_paths
from tools.release_family_read_operations_mcp import ACQUISITIONS, PRODUCERS, ROUTES, declarations

EXPORT = ROOT / '.codex-input/live-routes-60d.json'
# DN-L3-3: the snapshot follows the MCP manifest with ouf.ingestion.history aligned to the owner (task-60d-b).
MANIFEST = ROOT / '.codex-input/mcp-manifest-60d-b.json'
GENERIC = 'mcp-generic-execution'
PREVIEW = 'mcp-managed-file-preview'
INCIDENTS = 'execute-ouf.operations.incidents'
UUID = '12345678-1234-4234-8234-123456789abc'


@pytest.fixture(scope='module')
def artifact(tmp_path_factory):
    directory = tmp_path_factory.mktemp('read-operations')
    generate(directory, '1' * 40, '.github/workflows/ci.yml', '60')
    return directory


def resources(artifact):
    return json.loads((artifact / 'bundle.json').read_bytes())['resources']


def resolved(artifact, profile):
    return load_release_routes(artifact, '1' * 40, '.github/workflows/ci.yml', '60', profile)


def synthetic_profile():
    return ci_profile({'installationId': 'fixture', 'revision': 1, 'issuerUrl': 'https://issuer.invalid',
                       'gatewayAudience': 'gateway', 'mcpServiceIdentity': 'workload'}, 18080)


def test_predecessor_and_adopted_ids(artifact):
    """GW-60d-01. Pin the explicit predecessor independently of future families."""
    rows = resources(artifact)
    baseline = [r for r in rows if r['id'] in BASELINE_51M_IDS]
    assert digest(canonical(baseline)) == 'fd8252656d638689551ccecedc1d91a2fe46e3013b9ac12da931781b2f977cdc'
    assert {r['id'] for r in rows}.issuperset(READ_OPERATIONS_IDS)
    assert set(READ_OPERATIONS_IDS) == ROUTES.keys()
    # GW-60d-c-01. DN-L3-3: one contract, the owner limit, adopted on the live ID.
    assert 'mcp-ingestion-history' in {r['id'] for r in rows}
    history = declarations()['ouf.ingestion.history']
    assert history['inputSchema']['properties']['limit']['maximum'] == 100
    assert history['operationalLimits']['maxLimit'] == 100


@pytest.mark.skipif(not MANIFEST.exists(), reason='private handoff manifest required')
def test_snapshot_matches_deployed_manifest():
    from tools.release_family_read_operations_mcp import SNAPSHOT
    snapshot = json.loads(SNAPSHOT.read_bytes())
    source = json.loads(MANIFEST.read_bytes())
    provenance = snapshot['provenance']
    assert provenance['version'] == source['version']
    assert provenance['sha256'] == hashlib.sha256(MANIFEST.read_bytes()).hexdigest()
    assert declarations() == {c['capabilityId']: c for c in source['capabilities'] if c['capabilityId'] in declarations()}


@pytest.mark.parametrize('key', READ_OPERATIONS_IDS)
def test_recursive_schema_drift(artifact, key):
    """GW-60d-02. Mutate the installed wire constraints, including non-manifest producer queries."""
    row, = (r for r in resources(artifact) if r['id'] == key)
    args = row['body']['plugins']['request-validation']['body_schema']['properties']['Arguments']
    if key == INCIDENTS:
        assert set(args['properties']) == {'limit', 'sourceId', 'since', 'state', 'coverage', 'snapshot', 'cursor', 'resumeFrom'}
        assert len(args['oneOf']) == 6
        del args['oneOf'][4]['properties']['cursor']['not']
    elif key == 'mcp-ingestion-status':
        assert 'since' not in args['properties']
        args['properties']['since'] = {'type': 'string'}
    elif key == 'execute-ouf.operations.summary':
        assert args['properties']['since']['maxLength'] == 100
        del args['properties']['since']['pattern']
    elif ROUTES[key] in ACQUISITIONS:
        assert args['properties']['runId']['format'] == 'uuid'
        assert not Draft7Validator(args).is_valid({'sourceId': 's', 'runId': '00000000-0000-0000-0000-000000000000'})
        del args['properties']['runId']['pattern']
    elif key == 'execute-urban-object-search':
        assert not Draft7Validator(args).is_valid({'type': '*'})
        del args['properties']['type']['pattern']
    elif key == GENERIC:
        schema = row['body']['plugins']['request-validation']['body_schema']
        assert schema['properties']['CapabilityID']['enum'] == ['ouf.system.status']
        assert Draft7Validator(args).is_valid({}) and not Draft7Validator(args).is_valid({'incidentId': UUID})
        schema['properties']['CapabilityID'] = {'const': 'urban.object.related_search'}
    elif key.endswith('.incidents'):
        assert len(args['oneOf']) == 5
        del args['oneOf'][-1]['properties']['resumeFrom']['pattern']
    else:
        args['properties']['limit']['maximum'] += 1
    with pytest.raises(ValueError, match='dispatch contract'):
        verify_dispatch_arguments([row])


def inventory(rows):
    return {'total': len(rows), 'list': [{'value': r} for r in rows]}


def generic_requests():
    related = json.loads((ROOT / 'tests/fixtures/mcp-related-search-dispatch.json').read_bytes())
    related['Identity']['ActorType'] = 'HUMAN'
    for cap, owner, operation, args in [
        ('ouf.system.status', 'mcp', 'READ', {}),
        ('ouf.operations.explain', 'mcp', 'READ', {'incidentId': UUID}),
        ('urban.object.related_search', 'udp', 'SEARCH', related['Arguments']),
    ]:
        yield dict(related, CapabilityID=cap, GatewayBindingRef='capability://' + cap,
                   OperationClass=operation, Owner=owner, Arguments=args, RequestHash=digest(canonical(args)))


def test_generic_dispatch_preserves_status_only(artifact):
    row, = (r for r in resources(artifact) if r['id'] == GENERIC)
    check = Draft7Validator(row['body']['plugins']['request-validation']['body_schema'])
    for request in generic_requests():
        cap = request['CapabilityID']
        assert Draft7Validator(declarations()[cap]['inputSchema']).is_valid(request['Arguments'])
        assert check.is_valid(request) == (cap == 'ouf.system.status')


def test_plan_fences_and_selector_intersection(artifact):
    desired = resolved(artifact, synthetic_profile())
    installed = [copy.deepcopy(r) for r in desired if r['id'] in ROUTES]
    assert all(c.action == 'unchanged' for c in adoption_plan(desired, inventory(installed)))
    with pytest.raises(ValueError, match='missing installed ID'):
        adoption_plan(desired, inventory(installed[1:]))
    other = dict(installed[0], id='unmanaged', hosts=['a.invalid'])
    with pytest.raises(ValueError, match='selector conflict'):
        adoption_plan(desired, inventory(installed + [other]))
    assert not selectors_overlap(other, dict(installed[0], host='b.invalid'))
    assert selectors_overlap(other, dict(installed[0], host='A.INVALID'))
    assert not selectors_overlap(other, dict(installed[0], methods=['GET']))
    changes = adoption_plan(desired, inventory(installed))
    installed[0]['upstream']['retries'] = 7
    with pytest.raises(ValueError, match='readback drift'):
        restore_plan(changes, desired, inventory(installed))


def export_profile(rows):
    """Read independent profile values from their owning route, never from a proposed replacement."""
    live = {r['id']: r for r in rows}
    profile = synthetic_profile()
    control = live[PREVIEW]
    labels = control['labels']
    oidc = control['plugins']['openid-connect']
    profile.update({'installationId': labels['ouf-installation'], 'revision': labels['ouf-installation-revision'],
                    'gateway.requiredAudience': oidc['client_id'], 'caddy.oidcDiscoveryUrl': oidc['discovery'],
                    'gateway.issuerUrl': oidc['claim_validator']['issuer']['valid_issuers'][0],
                    'iam.workloadClients.mcpServer': labels['ouf-mcp-workload'],
                    'gateway.delegationKeyEnv': labels['ouf-delegation-key-env'],
                    'gateway.sourceRevisionOwnerKeyEnv': labels['ouf-owner-key-env']})
    count = live[GENERIC]['plugins']['limit-count']
    profile['gateway.rateLimits.readOperationsMcp.count'] = count['count']
    profile['gateway.rateLimits.readOperationsMcp.timeWindowSeconds'] = count['time_window']
    owners = {'ouf-mcp-server': GENERIC, 'mcp-operational-aggregate': 'execute-ouf.operations.summary',
              'ouf-gateway-control-plane': 'execute-ouf.gateway.operations.summary',
              'ouf-ingestion-runtime': 'mcp-ingestion-status', 'ouf-udp-object-resolution': 'execute-urban-object-search',
              'ingestion-acquisition-reader': 'execute-ouf-ingestion-acquisition-read',
              'udp-acquisition-reader': 'execute-urban-acquisition-read', 'ouf-onboarding': PREVIEW}
    for service, key in owners.items():
        nodes = live[key]['upstream']['nodes']
        if isinstance(nodes, list):
            node, = nodes
            host, port = node['host'], node['port']
        else:
            address, = nodes
            host, port = address.rsplit(':', 1)
        profile['services.bindings.' + service] = host
        profile['services.ports.' + service] = int(port)
    for role, key in [('ingestionRead', 'mcp-ingestion-status'), ('udpRead', 'execute-urban-object-search'),
                      ('gatewayOperational', 'execute-ouf.gateway.operations.summary'),
                      ('ingestionOperational', 'execute-ouf.ingestion.operations.summary')]:
        post, = live[key]['plugins']['serverless-post-function']['functions']
        name, = re.findall(r'^local (?:OWNER|RECEIPT)_KEY_ENV = "([^"]+)"$', post, re.M)
        profile['gateway.' + role + 'OwnerKeyEnv'] = name
    return profile


def normalize_export(route, profile):
    # Three sanitized fields have no comparable value. Use the governed OIDC profile for both sides.
    copy_route = copy.deepcopy(route)
    oidc = copy_route['plugins']['openid-connect']
    for key, value in [('client_secret', profile['gateway.oidcClientSecretRef']),
                       ('set_id_token_header', False), ('set_access_token_header', False)]:
        assert oidc[key] == '<redatto>'
        oidc[key] = value
    return copy_route


def review_change(change):
    old, new = change.before, change.after
    key = change.target_id
    expected = copy.deepcopy(old)
    plugins = expected['plugins']
    schema = plugins['request-validation']['body_schema']
    cap = ROUTES[key]
    before_args = schema['properties']['Arguments']
    after_args = new['plugins']['request-validation']['body_schema']['properties']['Arguments']
    if cap not in PRODUCERS:
        additions = {
            GENERIC: ['/properties'], 'mcp-ingestion-status': ['/properties/since'],
            'execute-ouf-ingestion-acquisition-read': ['/properties/afterLineageId/format', '/properties/runId/format'],
            'execute-urban-acquisition-read': ['/properties/runId/format'],
            INCIDENTS: ['/additionalProperties', '/oneOf', '/properties', '/type'],
        }
        assert list(changed_paths(before_args, after_args)) == ['/$schema', *additions.get(key, [])]
        schema['properties']['Arguments'] = after_args
    labels = expected['labels']
    labels['ouf-exposure'] = 'internal'
    labels['ouf-installation-revision'] = new['labels']['ouf-installation-revision']
    plugins['request-id'] = {'algorithm': 'uuid', 'header_name': 'X-Correlation-ID', 'include_in_response': True}
    plugins['request-validation']['rejected_msg'] = 'INVALID_TOOL_ARGUMENTS'
    old_post, = plugins['serverless-post-function']['functions']
    new_post, = new['plugins']['serverless-post-function']['functions']
    prefix, code = old_post.split('-- This code', 1)
    new_prefix, new_code = new_post.split('-- This code', 1)
    constants = dict(re.findall(r'^local ([A-Z_]+) = "([^"]*)"$', prefix, re.M))
    issuer = constants.pop('ISSUER')
    plugins['openid-connect']['claim_validator']['issuer'] = {'valid_issuers': [issuer]}
    for var, label in [('AUDIENCE', 'ouf-audience'), ('MCP_WORKLOAD', 'ouf-mcp-workload'),
                       ('DELEGATION_KEY_ENV', 'ouf-delegation-key-env'), ('OWNER_KEY_ENV', 'ouf-owner-key-env'),
                       ('RECEIPT_KEY_ENV', 'ouf-owner-key-env')]:
        if var in constants:
            labels[label] = constants.pop(var)
            assert f"local {var} = labels['{label}']" in new_prefix
    assert dict(re.findall(r'^local ([A-Z_]+) = "([^"]*)"$', new_prefix, re.M)) == constants
    diagnostic = re.compile(r"    if status == 400 then\n.*?\n    end\n", re.S)
    assert diagnostic.sub('', new_code, count=1) == code
    plugins['serverless-post-function']['functions'] = [new_post]
    address, = old['upstream']['nodes']
    host, port = address.rsplit(':', 1)
    expected['upstream']['nodes'] = [{'host': host, 'port': int(port), 'weight': old['upstream']['nodes'][address]}]
    # A failure reports paths only, never installation data.
    assert list(changed_paths(expected, new)) == [], key


@pytest.mark.skipif(not EXPORT.exists(), reason='private sanitized APISIX handoff required')
def test_export_plan_recursive_review_and_exact_restore(artifact):
    """GW-60d-03. Use actual before-images and independently bound installation values."""
    raw = json.loads(EXPORT.read_bytes())
    profile = export_profile(raw)
    desired = resolved(artifact, profile)
    rows = [normalize_export(r, profile) for r in raw]
    changes = adoption_plan(desired, inventory(rows))
    assert Counter(c.action for c in changes) == {'update': 12}
    for change in changes:
        review_change(change)
    state = {r['id']: copy.deepcopy(r) for r in rows}
    def apply(plan):
        for c in plan:
            # Admin timestamps are outside the writable resource body.
            times = {k: v for k, v in state[c.target_id].items() if k in ('create_time', 'update_time')}
            state[c.target_id] = dict(copy.deepcopy(c.after), **times)
    preview, = (r for r in desired if r['id'] == PREVIEW)
    assert not list(changed_paths(preview, {k: v for k, v in state[PREVIEW].items() if k not in ('create_time', 'update_time')}))
    apply(changes)
    assert all(c.action == 'unchanged' for c in adoption_plan(desired, inventory(list(state.values()))))
    apply(restore_plan(changes, desired, inventory(list(state.values()))))
    assert not list(changed_paths(rows, list(state.values())))
    # Read back through the same export redaction as the supplied inventory.
    for route in state.values():
        for field in ('client_secret', 'set_id_token_header', 'set_access_token_header'):
            route['plugins']['openid-connect'][field] = '<redatto>'
    assert not list(changed_paths(raw, list(state.values())))


def check_read_owner_http(reads, post, token, dispatch_body):
    """GW-60d-04. Verify the bytes captured by the HTTP owner after APISIX mediation."""
    by_id = {r['id']: r for r in reads}
    for key, scopes, args, header, domain, secret in [
        ('mcp-ingestion-status', 'ingestion.operations.read', {'limit': 7}, 'x-ouf-ingestion-read-receipt',
         'ouf-ingestion-read-owner-v1.', 'cd'),
        ('mcp-ingestion-history', 'ingestion.operations.read', {'sourceId': 'source-a', 'limit': 7},
         'x-ouf-ingestion-read-receipt', 'ouf-ingestion-read-owner-v1.', 'cd'),
        ('execute-ouf-ingestion-acquisition-read', 'ingestion.contract.read ingestion.lineage.read ingestion.run.read',
         {'sourceId': 'source-a', 'runId': UUID, 'afterLineageId': UUID}, 'x-ouf-ingestion-read-receipt',
         'ouf-ingestion-read-owner-v1.', 'cd'),
        ('execute-urban-acquisition-read', 'lineage.object.read lineage.property.read urban.object.read',
         {'sourceId': 'source-a', 'runId': UUID, 'afterHandoffId': 'next'}, 'x-ouf-udp-acquisition-receipt',
         'ouf-udp-acquisition-owner-v1.', '34'),
    ]:
        route = by_id[key]
        code, raw = post('/mcp', {}, token(scope='mcp.connect ' + scopes))
        assert code == 200
        delegated = json.loads(raw)['proof']
        schema = route['plugins']['request-validation']['body_schema']
        body = dispatch_body(schema, args)
        body['RequestHash'] = hashlib.sha256(canonical(args)).hexdigest()
        code, raw = post(route['uri'], body, token('SERVICE'), delegated)
        assert code == 200, (key, code)
        response = json.loads(raw)
        assert json.loads(response['wire']) == args
        headers = response['headers']
        assert not {'authorization', 'cookie', 'x-ouf-delegation'} & headers.keys()
        encoded, mac = headers[header].encode().split(b'.')
        expected = hmac.digest((secret * 32).encode(), domain.encode() + encoded, 'sha256')
        assert hmac.compare_digest(expected, base64.urlsafe_b64decode(mac + b'=='))
        receipt = json.loads(base64.urlsafe_b64decode(encoded + b'=='))
        assert receipt['bodyHash'] == hashlib.sha256(response['wire'].encode()).hexdigest()
        assert receipt['path'] == route['plugins']['proxy-rewrite']['uri']
        assert receipt['capability'] == body['CapabilityID']
    route = by_id[GENERIC]
    schema = route['plugins']['request-validation']['body_schema']
    for request in list(generic_requests())[1:]:
        body = dispatch_body(schema, request['Arguments'])
        body.update({key: request[key] for key in ('CapabilityID', 'GatewayBindingRef', 'Owner', 'OperationClass', 'RequestHash')})
        code, _ = post(route['uri'], body, token('SERVICE'), delegated)
        assert code == 400


def test_legacy_guards():
    """GW-60d-05. Neither direction of the bulk writer may touch an adopted ID."""
    from ops.apisix import deploy_internal_m2m_routes as bulk, deploy_object_search as search
    for key in READ_OPERATIONS_IDS:
        with pytest.raises(ValueError, match='governed Gateway release'):
            bulk.apply([{'id': key}], None)
        with pytest.raises(ValueError, match='governed Gateway release'):
            bulk.restore({key: None}, None)
    alias = {'id': 'mcp-operations-incidents', 'uri': '/internal/capabilities/v1/execute/ouf.operations.incidents'}
    with pytest.raises(ValueError, match='governed Gateway release'):
        bulk.restore({alias['id']: alias}, None)
    with pytest.raises(ValueError, match='governed Gateway release'):
        bulk.apply([alias], None)
    with pytest.raises(SystemExit, match='governed Gateway release'):
        search.main()
