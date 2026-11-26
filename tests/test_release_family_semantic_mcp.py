"""GW-60c. Qualify the release artifact, installed selectors, wire contract and reverse plan."""
import base64
import copy
import hashlib
import hmac
import json
import re
import tempfile
import unittest
from pathlib import Path

from ops.apisix.deploy_internal_m2m_routes import restore, validate_routes
from tests.release_bundle_fixture import BASE_3D69CB4, SEMANTIC_MCP_IDS, canonical_json, ci_profile, load_release_routes
from tools.apisix_request_schema import verify_dispatch_arguments
from tools.gateway_release_bundle import generate
from tools.plan_semantic_search import changed_paths, inventory_routes
from tools.release_family_semantic_mcp import CAPABILITIES, GET, SNAPSHOT, adoption_plan, restore_plan


INPUT = Path(__file__).resolve().parents[1] / '.codex-input'
EXPORT = INPUT / 'live-routes-60c.json'
MANIFEST = INPUT / 'mcp-manifest-4b39568.json'
CREATE = 'semantic-proposal-create'
COMMIT, WORKFLOW = '1' * 40, '.github/workflows/ci.yml'


def dispatch_case(route_id):
    pin = '11111111-1111-4111-8111-111111111111'
    if route_id == GET:
        args = {'semanticId': 'example:term', 'revisionId': pin, 'publicationSetId': pin}
        owner = '/api/internal/v1/semantic/consultation/get'
    else:
        mode = route_id.rsplit('-', 1)[1]
        args = {'revisionId': pin, 'expectedRowVersion': 0, 'commandKey': 'idem'}
        if mode == 'review':
            args['validationRunId'] = pin
        owner = '/api/semantic/v1/proposal-commands/' + mode
    return owner, [args], [dict(args, analysisId='a' * 64), dict(args, revisionId='bad')]


def check_owner_receipt(route_id, value, wire, body):
    """GW-60c-03. Called by the HTTP owner gate with the bytes it actually received."""
    read = route_id == GET
    purpose = 'semantic-read-owner' if read else 'semantic-proposal-owner'
    key = (b'56' if read else b'cd') * 32
    encoded, mac = value.encode().split(b'.')
    expected = hmac.digest(key, b'ouf-' + purpose.encode() + b'-v1.' + encoded, 'sha256')
    assert hmac.compare_digest(expected, base64.urlsafe_b64decode(mac + b'=='))
    receipt = json.loads(base64.urlsafe_b64decode(encoded + b'=='))
    assert receipt['purpose'] == purpose and receipt['method'] == 'POST'
    assert receipt['capability'] == CAPABILITIES[route_id] and receipt['path'] == dispatch_case(route_id)[0]
    assert receipt['bodyHash'] == hashlib.sha256(wire).hexdigest()
    assert json.loads(wire) == body
    if not read:
        assert wire == json.dumps(body).encode()
        assert receipt['idempotencyKey'] == body['IdempotencyKey'] == body['Arguments']['commandKey']


def check_denied_dispatch(route_id, uri, body, post, token, delegation):
    """Invalid authority or command identity must fail before the HTTP owner sees a request."""
    if route_id == GET:
        # The MCP authorization capability alone does not grant the delegated owner read scope.
        status, response = post('/mcp', {}, token(scope='mcp.connect ' + CAPABILITIES[GET]))
        assert status == 200
        wrong_proof = json.loads(response)['proof']
        status, _ = post(uri, body, token('SERVICE'), wrong_proof)
        assert status == 403
    else:
        wrong_key = dict(body, Arguments=dict(body['Arguments'], commandKey='another-intent'))
        status, _ = post(uri, wrong_key, token('SERVICE'), delegation)
        assert status == 409


def inventory(routes):
    return {'total': len(routes), 'list': [{'value': route} for route in routes]}


def replay(changes, images):
    for change in changes:
        assert not list(changed_paths(images[change.target_id], change.before))
        images[change.target_id] = json.loads(json.dumps(change.after))
        assert not list(changed_paths(images[change.target_id], change.after))


def export_profile(profile, routes):
    sibling = routes[CREATE]
    labels = sibling['labels']
    plugins = sibling['plugins']
    oidc = plugins['openid-connect']
    node, = sibling['upstream']['nodes']
    function, = routes[GET]['plugins']['serverless-post-function']['functions']
    owner_env = re.search(r'^local OWNER_KEY_ENV = ("[^"]+")$', function, re.MULTILINE)
    return {**profile, 'revision': labels['ouf-installation-revision'], 'installationId': labels['ouf-installation'],
            'gateway.requiredAudience': oidc['client_id'], 'gateway.issuerUrl': oidc['claim_validator']['issuer']['valid_issuers'][0],
            'caddy.oidcDiscoveryUrl': oidc['discovery'], 'iam.workloadClients.mcpServer': labels['ouf-mcp-workload'],
            'gateway.delegationKeyEnv': labels['ouf-delegation-key-env'], 'gateway.semanticProposalOwnerKeyEnv': labels['ouf-owner-key-env'],
            'gateway.semanticReadOwnerKeyEnv': json.loads(owner_env[1]), 'services.bindings.ouf-semantic-registry': node['host'],
            'services.ports.ouf-semantic-registry': node['port'], 'gateway.rateLimits.semanticMcp.count': plugins['limit-count']['count'],
            'gateway.rateLimits.semanticMcp.timeWindowSeconds': plugins['limit-count']['time_window']}


class ReleaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temp.cleanup)
        cls.directory = Path(temp.name)
        generate(cls.directory, COMMIT, WORKFLOW, '60')
        cls.bundle = json.loads((cls.directory / 'bundle.json').read_bytes())
        cls.profile = ci_profile({'installationId': 'fixture', 'revision': 1, 'gatewayAudience': 'test-audience',
                                  'issuerUrl': 'https://issuer.invalid', 'mcpServiceIdentity': 'test-mcp'}, 18080)
        cls.desired = load_release_routes(cls.directory, COMMIT, WORKFLOW, '60', cls.profile)

    def test_retained_release(self):
        """GW-60c-01. Only the explicit predecessor inventory contributes to this digest."""
        rows = [r for r in self.bundle['resources'] if r['id'] in BASE_3D69CB4]
        self.assertEqual({r['id'] for r in rows}, BASE_3D69CB4)
        self.assertEqual(hashlib.sha256(canonical_json(rows)).hexdigest(),
                         'fd8252656d638689551ccecedc1d91a2fe46e3013b9ac12da931781b2f977cdc')

    @unittest.skipUnless(MANIFEST.is_file(), 'private source manifest unavailable')
    def test_snapshot_source(self):
        raw = MANIFEST.read_bytes()
        source = json.loads(raw)
        snapshot = json.loads(SNAPSHOT.read_bytes())
        self.assertEqual(snapshot['provenance'], {
            'repository': 'GioNob/ouf-mcp-server', 'commit': '4b395686ab1dccb80e37e63d26a8228b472d05ac',
            'version': source['version'], 'sha256': hashlib.sha256(raw).hexdigest()})
        self.assertEqual(snapshot['capabilities'], [r for r in source['capabilities'] if r['capabilityId'] in CAPABILITIES.values()])

    def test_manifest_arguments(self):
        """GW-60c-02. A regression in any projected field blocks publication."""
        for key in SEMANTIC_MCP_IDS:
            item, = (r for r in self.bundle['resources'] if r['id'] == key)
            for path, wrong in [(('required',), []), (('additionalProperties',), True),
                                (('properties', 'revisionId', 'pattern'), '.*'),
                                (('properties', 'analysisId'), {'type': 'string'})] + (
                                    [(('properties', 'semanticId', 'maxLength'), 2049)] if key == GET else
                                    [(('properties', 'expectedRowVersion', 'maximum'), 2**53),
                                     (('properties', 'commandKey', 'pattern'), '.*')]):
                with self.subTest(route=key, path=path):
                    drift = copy.deepcopy(item)
                    args = drift['body']['plugins']['request-validation']['body_schema']['properties']['Arguments']
                    self.assertNotIn('analysisId', args['properties'])
                    node = args
                    for field in path[:-1]:
                        node = node[field]
                    node[path[-1]] = wrong
                    with self.assertRaisesRegex(ValueError, 'Arguments differ'):
                        verify_dispatch_arguments([drift])

    def test_owner_binding_and_limits(self):
        """GW-60c-03. Resolve a remote owner, independent key references and installed envelope limits."""
        profile = dict(self.profile)
        profile.update({'services.bindings.ouf-semantic-registry': 'semantic.invalid',
                        'services.ports.ouf-semantic-registry': 18181,
                        'gateway.rateLimits.semanticMcp.count': 17, 'gateway.rateLimits.semanticMcp.timeWindowSeconds': 29})
        resolved = load_release_routes(self.directory, COMMIT, WORKFLOW, '60', profile)
        for route in resolved:
            key = route['id']
            if key not in SEMANTIC_MCP_IDS:
                continue
            with self.subTest(route=key):
                read = key == GET
                plugins = route['plugins']
                self.assertEqual(route['methods'], ['POST'])
                self.assertEqual(route['upstream'], {'type': 'roundrobin', 'scheme': 'http', 'retries': 0,
                    'timeout': dict(connect=3, send=3, read=3), 'nodes': [{'host': 'semantic.invalid', 'port': 18181, 'weight': 1}]})
                self.assertEqual(plugins['proxy-rewrite']['uri'], dispatch_case(key)[0])
                self.assertEqual(plugins['limit-count'], {'count': 17, 'time_window': 29, 'rejected_code': 429})
                self.assertEqual(plugins['request-validation']['max_req_body_size'], 65536)
                fields = plugins['request-validation']['body_schema']['properties']
                self.assertEqual(fields['CapabilityID'], {'const': CAPABILITIES[key]})
                self.assertEqual(fields['Identity']['properties']['ActorType']['enum'],
                                 ['HUMAN'] if read else ['HUMAN', 'AI_AGENT', 'SERVICE'])
                self.assertEqual(fields['MaxResultBytes']['maximum'], 262144 if read else 1048576)
                owner_key = 'gateway.semanticReadOwnerKeyEnv' if read else 'gateway.semanticProposalOwnerKeyEnv'
                self.assertEqual(route['labels']['ouf-owner-key-env'], profile[owner_key])

    def test_selector_conflicts_and_restore_fencing(self):
        """GW-60c-04. Detect a foreign ID on any bundle selector, including a previously governed sibling."""
        live = [copy.deepcopy(r) for r in self.desired if r['id'] in CAPABILITIES]
        earlier = next(r for r in self.desired if r['id'] == CREATE)
        foreign = dict(id='foreign', uris=[earlier['uri']], hosts=['test.invalid'])
        with self.assertRaisesRegex(ValueError, 'foreign selector'):
            adoption_plan(self.desired, inventory(live + [foreign]))
        changes = adoption_plan(self.desired, inventory(live + [dict(foreign, methods=['GET'])]))
        self.assertEqual([c.action for c in changes], ['unchanged'] * 3)
        live[0]['priority'] += 1
        with self.assertRaisesRegex(ValueError, 'restore readback drift'):
            restore_plan(changes, self.desired, inventory(live))
        with self.assertRaisesRegex(ValueError, 'expected installed'):
            adoption_plan(self.desired, inventory(live[1:]))

    def test_update_and_restore_without_private_export(self):
        images = {r['id']: copy.deepcopy(r) for r in self.desired if r['id'] in CAPABILITIES}
        for route in images.values():
            del route['plugins']['request-id']
        original = canonical_json(images)
        changes = adoption_plan(self.desired, inventory(list(images.values())))
        self.assertEqual({c.target_id: c.action for c in changes}, dict.fromkeys(SEMANTIC_MCP_IDS, 'update'))
        replay(changes, images)
        replay(restore_plan(changes, self.desired, inventory(list(images.values()))), images)
        self.assertEqual(canonical_json(images), original)

    @unittest.skipUnless(EXPORT.is_file(), 'private route export unavailable')
    def test_installed_plan_and_exact_return(self):
        """GW-60c-05. Recursive field audit and serialized PUT/readback of every before-image."""
        raw = json.loads(EXPORT.read_bytes())
        installed = inventory_routes(inventory(copy.deepcopy(raw)))
        profile = export_profile(self.profile, installed)
        desired = load_release_routes(self.directory, COMMIT, WORKFLOW, '60', profile)
        reference = next(r for r in desired if r['id'] == CREATE)
        redacted = ('client_secret', 'set_access_token_header', 'set_id_token_header')
        for key in (*SEMANTIC_MCP_IDS, CREATE):
            oidc = installed[key]['plugins']['openid-connect']
            for field in redacted:
                self.assertEqual(oidc[field], '<redatto>')
                oidc[field] = reference['plugins']['openid-connect'][field]
        self.assertEqual(list(changed_paths(installed[CREATE], reference)), [])
        changes = adoption_plan(desired, inventory(list(installed.values())))
        self.assertEqual({c.target_id: c.action for c in changes}, dict.fromkeys(SEMANTIC_MCP_IDS, 'update'))
        arg = '/plugins/request-validation/body_schema/properties/Arguments/properties/'
        common = {'/labels/ouf-exposure', '/plugins/request-id', '/plugins/openid-connect/claim_validator/issuer',
                  '/plugins/request-validation/rejected_msg', '/plugins/serverless-post-function/functions/0',
                  arg + 'revisionId/pattern'}
        for change in changes:
            key = change.target_id
            labels = change.after['labels']
            issuer, = change.after['plugins']['openid-connect']['claim_validator']['issuer']['valid_issuers']
            if key == GET:
                post, = change.before['plugins']['serverless-post-function']['functions']
                settings = dict((name, json.loads(value)) for name, value in re.findall(
                    r'^local (ISSUER|AUDIENCE|MCP_WORKLOAD|OWNER_KEY_ENV|DELEGATION_KEY_ENV) = ("[^"]+")$', post, re.MULTILINE))
                self.assertEqual(settings, {'ISSUER': issuer, 'AUDIENCE': labels['ouf-audience'],
                                            'MCP_WORKLOAD': labels['ouf-mcp-workload'], 'OWNER_KEY_ENV': labels['ouf-owner-key-env'],
                                            'DELEGATION_KEY_ENV': labels['ouf-delegation-key-env']})
                node, = change.after['upstream']['nodes']
                self.assertEqual(change.before['upstream']['nodes'], {f"{node['host']}:{node['port']}": node['weight']})
                self.assertEqual(change.after['upstream']['type'], 'roundrobin')
                extra = {'/labels/ouf-' + k for k in ('audience', 'delegation-key-env', 'installation-revision',
                                                      'mcp-workload', 'owner-key-env')}
                extra.update(('/upstream/type', '/upstream/nodes', arg + 'publicationSetId/pattern'))
            else:
                self.assertEqual(change.before['labels']['ouf-issuer'], issuer)
                extra = {'/labels/ouf-issuer', '/plugins/serverless-pre-function/functions/1'}
                if key == 'semantic-proposal-review':
                    extra.add(arg + 'validationRunId/pattern')
            self.assertEqual(set(changed_paths(change.before, change.after)), common | extra, key)
        images = copy.deepcopy(installed)
        replay(changes, images)
        readback = inventory(list(images.values()))
        self.assertEqual([c.action for c in adoption_plan(desired, readback)], ['unchanged'] * 3)
        replay(restore_plan(changes, desired, readback), images)
        self.assertEqual(canonical_json(images), canonical_json(installed))
        # Compare again with the untouched input, in its sanitized representation.
        for key in (*SEMANTIC_MCP_IDS, CREATE):
            images[key]['plugins']['openid-connect'].update(dict.fromkeys(redacted, '<redatto>'))
        self.assertEqual(canonical_json(images), canonical_json(inventory_routes(inventory(raw))))

    def test_legacy_install_and_restore_blocked(self):
        """GW-60c-06. Reject legacy writes before Admin access."""
        for route in self.desired:
            if route['id'] in SEMANTIC_MCP_IDS:
                with self.assertRaisesRegex(ValueError, 'governed Gateway release'):
                    validate_routes([route])
                with self.assertRaisesRegex(ValueError, 'governed Gateway release'):
                    restore({route['id']: route}, None)
