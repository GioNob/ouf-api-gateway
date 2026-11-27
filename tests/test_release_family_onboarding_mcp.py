"""GW-60b offline adoption and owner dispatch on the generated bundle."""
import base64
import copy
import hmac
import json
import re
from pathlib import Path

import pytest

from tests.release_bundle_fixture import (
    BASELINE_3D69CB4_IDS, ONBOARDING_IDS, canonical_json, ci_profile, load_release_routes, sha256,
)
from tools.apisix_request_schema import inline_dispatch_schema, verify_dispatch_arguments
from tools.gateway_release_bundle import generate
from tools.mcp_dispatch_contract import ONBOARDING_DISPATCH, ONBOARDING_MANIFEST, POLICY_BUNDLE_ID, UPLOAD_ID, envelope_refs
from tools.plan_semantic_search import changed_paths
from tools.release_family_onboarding_mcp import adoption_plan, restore_adoption

ROOT = Path(__file__).resolve().parents[1]
EXPORT = ROOT / '.codex-input/live-routes-60b.json'
PREVIEW = 'mcp-managed-file-preview'
WORKFLOW = '.github/workflows/ci.yml'
COMMIT = '1' * 40
PROFILE_ID = 'mcp-managed-file-profile'
REVISION_ID = 'mcp-source-revision-read'


@pytest.fixture(scope='module')
def artifact(tmp_path_factory):
    directory = tmp_path_factory.mktemp('onboarding-release')
    generate(directory, COMMIT, WORKFLOW, '60')
    return directory


def fixture_profile():
    return ci_profile({'installationId': 'fixture', 'revision': 2, 'issuerUrl': 'https://iam.invalid',
                       'gatewayAudience': 'gateway', 'mcpServiceIdentity': 'workload'}, 18080)


def test_baseline_and_snapshot(artifact):
    """GW-60b-01. Pin the previous 31 resources and the public six-capability extraction."""
    resources = json.loads((artifact / 'bundle.json').read_bytes())['resources']
    baseline = [r for r in resources if r['id'] in BASELINE_3D69CB4_IDS]
    assert {r['id'] for r in baseline} == BASELINE_3D69CB4_IDS
    assert sha256(canonical_json(baseline)) == '100e003c9aefeb9f943b4e056ec43ce69289262c8a81b9d2e6d6abe337055359'
    snapshot = json.loads(ONBOARDING_MANIFEST.read_bytes())
    assert sha256(canonical_json(snapshot['capabilities'])) == '79b0639a09acd77deca7e463842d040b1447aeecfc22d61b55a2d3c4a8e4e0d6'
    assert snapshot['provenance']['commit'] == '4b395686ab1dccb80e37e63d26a8228b472d05ac'
    assert snapshot['provenance']['version'] == '1.17.0-published-batch-v1'
    assert snapshot['provenance']['sha256'] == 'ec67c43add39551d561a1ffa142dbaf1d6437b584d85b3892f07c29e0aff3acc'


def inventory(rows):
    return {'total': len(rows), 'list': [{'key': '/apisix/routes/' + r['id'], 'value': r} for r in rows]}


def export_profile(installed):
    preview = installed[PREVIEW]
    labels = preview['labels']
    oidc = preview['plugins']['openid-connect']
    node, = preview['upstream']['nodes']
    profile = fixture_profile()
    profile.update({'installationId': labels['ouf-installation'], 'revision': labels['ouf-installation-revision'],
                    'gateway.issuerUrl': oidc['claim_validator']['issuer']['valid_issuers'][0],
                    'gateway.requiredAudience': oidc['client_id'], 'caddy.oidcDiscoveryUrl': oidc['discovery'],
                    'iam.workloadClients.mcpServer': labels['ouf-mcp-workload'],
                    'gateway.delegationKeyEnv': labels['ouf-delegation-key-env'],
                    'gateway.sourceRevisionOwnerKeyEnv': labels['ouf-owner-key-env'],
                    'services.bindings.ouf-onboarding': node['host'], 'services.ports.ouf-onboarding': node['port']})
    guard, = installed[POLICY_BUNDLE_ID]['plugins']['serverless-post-function']['functions']
    names = re.search(r'local allowed_services=\{([^}]*)\}', guard)[1]
    services = re.findall(r'\[("[^"]+")\]=true', names)
    assert len(services) == 4 and json.loads(services[0]) == labels['ouf-mcp-workload']
    for role, service in zip(('mcpServer', 'ingestion', 'udp', 'semantic'), services, strict=True):
        profile['iam.workloadClients.' + role] = json.loads(service)
    for group, route_id in [('authorizationPolicyRead', POLICY_BUNDLE_ID), ('onboardingMcp', PROFILE_ID)]:
        quota = installed[route_id]['plugins']['limit-count']
        profile[f'gateway.rateLimits.{group}.count'] = quota['count']
        profile[f'gateway.rateLimits.{group}.timeWindowSeconds'] = quota['time_window']
    return profile


def expected_wire(capability):
    rows = json.loads(ONBOARDING_MANIFEST.read_bytes())['capabilities']
    args, = (c['inputSchema'] for c in rows if c['capabilityId'] == capability)
    if capability == ONBOARDING_DISPATCH[PROFILE_ID]:
        del args['properties']['commandKey']
    return inline_dispatch_schema(envelope_refs(args))


def assert_reviewed_changes(old, target, reference):
    # Construct the expected after-image independently from the installed configuration.
    expected = copy.deepcopy(old)
    route_id = old['id']
    labels = expected['labels']
    labels.update({'ouf-exposure': 'internal', 'ouf-installation-revision': reference['labels']['ouf-installation-revision']})
    plugins = expected['plugins']
    oidc = plugins['openid-connect']
    oidc['claim_validator']['issuer'] = reference['plugins']['openid-connect']['claim_validator']['issuer']
    nodes = expected['upstream']['nodes']
    if isinstance(nodes, dict):
        address, = nodes
        host, port = address.rsplit(':', 1)
        expected['upstream']['nodes'] = [{'host': host, 'port': int(port), 'weight': nodes[address]}]
    key = 'serverless-post-function'
    old_access, = plugins[key]['functions']
    if route_id == POLICY_BUNDLE_ID:
        roles = ('mcp', 'ingestion', 'udp', 'semantic')
        match = re.search(r'local allowed_services=\{([^}]*)\}', old_access)
        names = re.findall(r'\[("[^"]+")\]=true', match[1])
        for role, value in zip(roles, names, strict=True):
            labels[f'ouf-{role}-workload'] = json.loads(value)
        table = ','.join(f'[ctx.matched_route.value.labels["ouf-{role}-workload"]]=true' for role in roles)
        plugins[key]['functions'] = [old_access[:match.start(1)] + table + old_access[match.end(1):]]
    else:
        if route_id == REVISION_ID:
            assert labels.pop('ouf-issuer') == oidc['claim_validator']['issuer']['valid_issuers'][0]
        else:
            constants = {k: json.loads(v) for k, v in re.findall(r'^local (\w+) = ("[^"]+")$', old_access, re.M)}
            assert constants == {
                'ISSUER': oidc['claim_validator']['issuer']['valid_issuers'][0],
                'MCP_WORKLOAD': reference['labels']['ouf-mcp-workload'], 'AUDIENCE': oidc['client_id'],
                'DELEGATION_KEY_ENV': reference['labels']['ouf-delegation-key-env'],
                'OWNER_KEY_ENV': reference['labels']['ouf-owner-key-env'],
            }
        for name in ('ouf-audience', 'ouf-mcp-workload', 'ouf-delegation-key-env', 'ouf-owner-key-env'):
            labels[name] = reference['labels'][name]
        plugins['request-id'] = reference['plugins']['request-id']
        # Same executable access checks, except the released 400 diagnostic and binding preamble.
        start = '-- This code runs only after openid-connect'
        prefix, diagnostic = reference['plugins'][key]['functions'][0].split(start)
        fail = re.search(r'local function fail\(status\).*?\nend', diagnostic, re.S)[0]
        suffix = old_access.split(start)[1].replace('local function fail(status)\n    return ngx.exit(status)\nend', fail)
        plugins[key]['functions'] = [prefix + start + suffix]
        if route_id in ONBOARDING_DISPATCH:
            validation = plugins['request-validation']
            validation['rejected_msg'] = 'INVALID_TOOL_ARGUMENTS'
            validation['body_schema']['properties']['Arguments'] = expected_wire(ONBOARDING_DISPATCH[route_id])
    # On failure show paths only, including inside schema branches. Never print private bodies.
    assert list(changed_paths(expected, target)) == []


def exercise_export(directory, rows):
    original = copy.deepcopy(rows)
    installed = {r['id']: r for r in rows}
    profile = export_profile(installed)
    desired = load_release_routes(directory, COMMIT, WORKFLOW, '60', profile)
    reference, = (r for r in desired if r['id'] == PREVIEW)
    # Keep raw redactions for restore. Compare the three opaque OIDC fields with
    # their governed counterparts only in the in-memory comparison copy.
    after = {r['id']: copy.deepcopy(r) for r in rows}
    changes = adoption_plan(desired, inventory(rows))
    assert len(changes) == 7 and all(c.action == 'update' for c in changes)
    for route_id, old in installed.items():
        clean = {k: copy.deepcopy(v) for k, v in old.items() if k not in ('create_time', 'update_time')}
        oidc = clean['plugins']['openid-connect']
        for field in ('client_secret', 'set_access_token_header', 'set_id_token_header'):
            if field in oidc:
                assert oidc[field] == '<redatto>'
                oidc[field] = reference['plugins']['openid-connect'][field]
        if route_id == PREVIEW:
            assert list(changed_paths(clean, reference)) == []
        else:
            change, = (c for c in changes if c.target_id == route_id)
            assert next(changed_paths(clean, change.after), None) is not None
            assert_reviewed_changes(clean, change.after, reference)
            after[route_id] = change.after
    assert all(c.action == 'unchanged' for c in adoption_plan(desired, inventory(after.values())))
    for change in restore_adoption(changes, desired, inventory(after.values())):
        # Admin timestamps belong to the simulated store, outside the writable route body.
        meta = {k: v for k, v in installed[change.target_id].items() if k in ('create_time', 'update_time')}
        after[change.target_id] = dict(change.after, **meta)
    assert canonical_json(list(after.values())) == canonical_json(original)


@pytest.mark.skipif(not EXPORT.exists(), reason='requires the private sanitized task-60b export')
def test_export_plan_readback_restore(artifact):
    """GW-60b-02. Recursive diff, seven updates, preview unchanged, exact before-images."""
    exercise_export(artifact, json.loads(EXPORT.read_bytes()))


def test_conflict_and_concurrent_readback(artifact):
    """GW-60b-03. Fail closed on missing IDs, foreign selectors and a later write."""
    desired = load_release_routes(artifact, COMMIT, WORKFLOW, '60', fixture_profile())
    installed = [r for r in desired if r['id'] in ONBOARDING_IDS]
    before = [dict(r, labels={**r['labels'], 'ouf-installation-revision': 'previous'}) for r in installed]
    plan = adoption_plan(desired, inventory(before))
    assert [c.action for c in plan] == ['update'] * 7
    assert {c.target_id: c.after for c in restore_adoption(plan, desired, inventory(installed))} == {
        r['id']: r for r in before}
    assert all(c.action == 'unchanged' for c in adoption_plan(desired, inventory(installed)))
    with pytest.raises(ValueError, match='missing'):
        adoption_plan(desired, inventory(installed[1:]))
    for r in desired:
        with pytest.raises(ValueError, match='conflict'):
            adoption_plan(desired, inventory(installed + [dict(r, id='foreign')]))
    target = dict(installed[0], host='owner.invalid', methods=['GET'])
    foreign = dict(target, id='foreign', host='*.invalid', methods=['POST'])
    from tools.release_family_onboarding_mcp import check_selectors
    check_selectors([target], [foreign, dict(foreign, host='elsewhere.invalid', methods=['GET'])])
    with pytest.raises(ValueError, match='conflict'):
        check_selectors([target], [dict(foreign, methods=['GET'])])
    with pytest.raises(ValueError, match='readback drift'):
        restore_adoption(plan, desired, inventory([dict(r, priority=19) for r in installed]))


@pytest.mark.parametrize('route_id,path', [
    ('mcp-permissions-read', ('properties', 'view', 'enum')),
    ('mcp-permissions-read', ('oneOf',)), ('mcp-permissions-propose', ('oneOf',)),
    ('mcp-permissions-propose', ('properties', 'roleCatalogue', 'properties', 'assignments', 'items', 'oneOf')),
    (REVISION_ID, ('properties', 'sourceId', 'pattern')), (PROFILE_ID, ('properties',)),
    ('mcp-permissions-status', ('required',)),
])
def test_reintroduced_schema_drift_stops_generation(artifact, route_id, path):
    """GW-60b-04. Reintroduce one drift at a time, including the local profile key."""
    resources = json.loads((artifact / 'bundle.json').read_bytes())['resources']
    route, = (r for r in resources if r['id'] == route_id)
    args = route['body']['plugins']['request-validation']['body_schema']['properties']['Arguments']
    assert args == expected_wire(ONBOARDING_DISPATCH[route_id])
    node = args
    for key in path:
        node = node[key]
    if path[-1] == 'enum':
        node.remove('CAPABILITIES')
    elif route_id == PROFILE_ID:
        node['commandKey'] = {'type': 'string'}
    else:
        parent = args
        for key in path[:-1]:
            parent = parent[key]
        del parent[path[-1]]
    with pytest.raises(ValueError, match='Arguments differ'):
        verify_dispatch_arguments(resources)


@pytest.mark.parametrize('route_id', ONBOARDING_IDS)
def test_legacy_apply_and_restore_refused(route_id):
    """GW-60b-05. Block both legacy mutations before the first Admin call."""
    from ops.apisix.deploy_internal_m2m_routes import apply, restore
    from ops.apisix.deploy_status_execute import apply_routes
    with pytest.raises(ValueError, match='governed Gateway release'):
        apply([{'id': route_id}], None)
    with pytest.raises(ValueError, match='governed Gateway release'):
        restore({route_id: None}, None)
    with pytest.raises(ValueError, match='governed Gateway release'):
        apply_routes([{'id': route_id}], None)


def test_release_upload_never_reads_stream(artifact):
    """GW-60b-06. Execute both published Lua phases with every body reader disabled."""
    from tests.test_execute_delegation import Engine, INSTALL, human, proof, workload
    from tests.test_managed_upload import CSV
    from tests.test_value_type_schemas import matched_route_context, run_dispatch_rewrite
    profile = ci_profile({**INSTALL, 'installationId': 'fixture', 'revision': 2}, 18080)
    route, = (r for r in load_release_routes(artifact, COMMIT, WORKFLOW, '60', profile) if r['id'] == UPLOAD_ID)
    headers = {'Content-Type': 'text/csv', 'Content-Length': str(len(CSV)), 'Idempotency-Key': 'upload',
               'X-OUF-File-ID': 'file_fixture', 'X-Content-SHA256': 'sha256:' + sha256(CSV),
               'X-OUF-Delegation': proof(dict(human(), scope='ouf.managed-source.file.upload'))}
    engine = Engine(workload(), headers, uri=route['uri'])
    engine.body = CSV

    def forbidden(*_):
        pytest.fail('streaming access attempted to read or rewrite the file')

    req = engine.lua.globals()[b'ngx'][b'req']
    req[b'read_body'] = req[b'get_body_data'] = req[b'set_body_data'] = forbidden
    engine.modules[b'apisix.core'][b'request'][b'get_body'] = forbidden
    ctx = matched_route_context(engine, route)
    run_dispatch_rewrite(engine, route, ctx)
    engine.lua.execute(route['plugins']['serverless-post-function']['functions'][0].encode())(None, ctx)
    assert engine.body == CSV and b'x-ouf-file-id' not in engine.headers
    assert 'request-validation' not in route['plugins']
    assert route['plugins']['proxy-control'] == {'request_buffering': False}
    item = {'kind': 'routes', 'id': UPLOAD_ID, 'body': route}
    route['plugins']['request-validation'] = {}
    with pytest.raises(ValueError, match='bounded streaming'):
        verify_dispatch_arguments([item])


# The real HTTP gate calls these two helpers from its existing synthetic owner and issuer.
WIRE_CASES = {
    PROFILE_ID: ('managed-file', {'assetId': '00000000-0000-4000-8000-000000000001'}),
    REVISION_ID: ('source-revision', {'sourceId': 'fixture', 'onboardingVersionId': '00000000-0000-4000-8000-000000000001'}),
    'mcp-permissions-read': ('authorization', {'view': 'CAPABILITIES'}),
    'mcp-permissions-propose': ('authorization', {'operation': 'REVOKE', 'grantId': 'fixture', 'reason': 'review'}),
    'mcp-permissions-status': ('authorization', {'proposalId': '00000000-0000-4000-8000-000000000001'}),
}


def reply_onboarding_owner(handler, body):
    if not handler.headers.get('X-Test-Onboarding'):
        return False
    handler.reply({'path': handler.path, 'body': base64.b64encode(body).decode(),
                   'headers': {k.lower(): v for k, v in handler.headers.items()}})
    return True


def check_onboarding_http(release, request, token, installation):
    """GW-60b-07. Verify actual owner bytes, receipt MACs, headers and SERVICE authorization."""
    from tests.test_dispatch_schema_contract import dispatch_body
    from tests.test_managed_upload import CSV
    routes = {r['id']: r for r in release}
    scopes = ' '.join([*ONBOARDING_DISPATCH.values(), 'ouf.managed-source.file.upload'])
    code, raw = request('POST', '/mcp', {}, token(scope='mcp.connect ' + scopes))
    assert code == 200
    delegation = json.loads(raw)['proof']
    for route_id in (*WIRE_CASES, UPLOAD_ID):
        route = routes[route_id]
        cap = ONBOARDING_DISPATCH.get(route_id, 'ouf.managed-source.file.upload')
        headers = {'X-Test-Onboarding': '1'}
        if route_id == UPLOAD_ID:
            body = CSV
            kind = 'managed-file'
            prefix = 'ouf-managed-file-upload-v1.'
            headers.update({'Content-Type': 'text/csv', 'X-OUF-File-ID': 'file_fixture',
                            'X-Content-SHA256': 'sha256:' + sha256(CSV)})
        else:
            kind, args = WIRE_CASES[route_id]
            prefix = 'ouf-' + kind + '-owner-v1.'
            body = dispatch_body(route['plugins']['request-validation']['body_schema'], args)
        status, raw = request('POST', route['uri'], body, token('SERVICE'), delegation, extra_headers=headers)
        assert status == 200, (route_id, status)
        result = json.loads(raw)
        assert result['path'] == route['plugins']['proxy-rewrite']['uri']
        received = base64.b64decode(result['body'])
        forwarded = result['headers']
        assert not {'authorization', 'x-ouf-delegation', 'x-ouf-unknown', 'x-ouf-file-id'} & forwarded.keys()
        encoded, mac = forwarded['x-ouf-' + kind + '-receipt'].split('.')
        assert hmac.compare_digest(base64.urlsafe_b64decode(mac + '=='),
                                   hmac.digest(b'cd' * 32, (prefix + encoded).encode(), 'sha256'))
        receipt = json.loads(base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4)))
        assert receipt['path'] == result['path'] and receipt['capability'] == cap
        if route_id == UPLOAD_ID:
            assert received == CSV and receipt['fileId'] == 'file_fixture'
            assert receipt['expectedLength'] == len(CSV) and receipt['expectedHash'] == 'sha256:' + sha256(CSV)
            for field, bad in [('Content-Type', 'multipart/form-data'), ('X-Content-SHA256', 'bad')]:
                assert request('POST', route['uri'], body, token('SERVICE'), delegation,
                               extra_headers={**headers, field: bad})[0] == 400
        else:
            assert json.loads(received) == body and receipt['bodyHash'] == sha256(received)

    route = routes[POLICY_BUNDLE_ID]
    headers = {'X-Test-Onboarding': '1', 'X-OUF-Gateway-Verified': 'forged'}
    for role in ('mcp', 'semantic', 'udp', 'ingestion'):
        bearer = token('SERVICE', azp=installation[role + 'ServiceIdentity'])
        code, raw = request('GET', route['uri'], bearer=bearer, extra_headers=headers)
        assert code == 200
        observed = json.loads(raw)
        assert observed['path'] == route['plugins']['proxy-rewrite']['uri']
        assert observed['headers']['authorization'] == 'Bearer ' + bearer
        assert 'x-ouf-gateway-verified' not in observed['headers'] and observed['body'] == ''
    assert request('GET', route['uri'], bearer=token('SERVICE', scope='mcp.connect'), extra_headers=headers)[0] in (401, 403)
    for bearer in (token('SERVICE', azp='unlisted'), token(scope='authorization.bundle.read')):
        assert request('GET', route['uri'], bearer=bearer, extra_headers=headers)[0] == 403
