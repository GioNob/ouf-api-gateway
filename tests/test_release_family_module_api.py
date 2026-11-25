"""PET di adozione F7. L'export privato viene confrontato solo in memoria."""
import copy
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ops.apisix.deploy_internal_m2m_routes import apply, restore
from tests.release_bundle_fixture import (
    BASE_3D69CB4, MODULE_API_IDS, ONBOARDING_IDS, READ_OPERATIONS_IDS, SEMANTIC_MCP_IDS,
    THS_OWNER_IDS, THS_PAGES_IDS, THS_RECOVERY_IDS, canonical_json, ci_profile, load_release_routes, sha256,
)
from tools.gateway_release_bundle import ROOT, generate
from tools.plan_semantic_search import Change, changed_paths
from tools.release_family_onboarding_mcp import check_selectors

COMMIT = '1' * 40
WORKFLOW = '.github/workflows/ci.yml'
FILE = 'onboarding-managed-file-read'
PREFLIGHT = 'onboarding-identity-preflight-read'
POST = 'serverless-post-function'
REFS = {
    'ouf-onboarding': FILE,
    'ouf-udp-object-resolution': PREFLIGHT,
    'ouf-semantic-registry': 'semantic-human-card',
}
RATE_REFS = {
    'moduleApiOnboarding': 'r4a-onboarding-ingestion-compatibility',
    'semanticRestApi': 'semantic-artifact-search',
    'moduleApiPreflight': PREFLIGHT,
}


def live_profile(live):
    reference = live[FILE]
    oidc = reference['plugins']['openid-connect']
    profile = ci_profile({
        'installationId': reference['labels']['ouf-installation'],
        'revision': reference['labels']['ouf-installation-revision'],
        'issuerUrl': oidc['discovery'].rsplit('/.well-known/', 1)[0],
        'gatewayAudience': oidc['client_id'], 'mcpServiceIdentity': 'test-mcp',
    }, 18080)
    profile['caddy.oidcDiscoveryUrl'] = oidc['discovery']
    for service, key in REFS.items():
        address, = live[key]['upstream']['nodes']
        host, port = address.rsplit(':', 1)
        profile['services.bindings.' + service] = host
        profile['services.ports.' + service] = int(port)
    for group, key in RATE_REFS.items():
        limit = live[key]['plugins']['limit-count']
        profile[f'gateway.rateLimits.{group}.count'] = limit['count']
        profile[f'gateway.rateLimits.{group}.timeWindowSeconds'] = limit['time_window']

    file_guard = reference['plugins'][POST]['functions'][0]
    allowed = re.search(r'local allowed_services=\{([^}]+)\}', file_guard)[1]
    onboarding, ingestion = re.findall(r'\["([^"]+)"\]=true', allowed)
    preflight_guard = live[PREFLIGHT]['plugins'][POST]['functions'][0]
    source = re.search(r"claims\['client_id'\]~='([^']+)' and claims\['azp'\]~='\1'", preflight_guard)[1]
    if len({onboarding, ingestion, source}) != 3:
        raise ValueError('unexpected installed workload identity overlap')
    for role, value in [('onboarding', onboarding), ('ingestion', ingestion), ('sourceOnboarding', source)]:
        profile['iam.workloadClients.' + role] = value
    return profile


def expected_route(current, desired, profile):
    """Converti soltanto i campi ammessi. Tutto il resto deve coincidere ricorsivamente."""
    route = copy.deepcopy(current)
    key = route['id']
    address, = route['upstream']['nodes']
    host, port = address.rsplit(':', 1)
    route['upstream']['nodes'] = [{'host': host, 'port': int(port), 'weight': route['upstream']['nodes'][address]}]

    oidc = route['plugins']['openid-connect']
    ref = 'ths-identity-preflight-read' if key == PREFLIGHT else 'semantic-human-terms'
    fields = ['client_secret']
    if key == PREFLIGHT or key.startswith('semantic-'):
        fields += ['set_access_token_header', 'set_id_token_header']
    for field in fields:
        if oidc[field] != '<redatto>':
            raise ValueError('unexpected OIDC export redaction: ' + field)
        oidc[field] = desired[ref]['plugins']['openid-connect'][field]

    guard = route['plugins'][POST]['functions'][0]
    if key == PREFLIGHT:
        service = profile['iam.workloadClients.sourceOnboarding']
        label = 'ouf-source-onboarding-workload'
        route['labels'][label] = service
        guard = guard.replace('return function() ', 'return function(conf, ctx) ', 1).replace(
            f"if claims['client_id']~='{service}' and claims['azp']~='{service}' then",
            f'local service=ctx.matched_route.value.labels["{label}"]; '
            "if type(service)~='string' or service=='' or "
            "(claims['client_id']~=service and claims['azp']~=service) then")
    elif not key.startswith('semantic-'):
        for role in (('onboarding', 'ingestion') if key == FILE else ('ingestion',)):
            label = 'ouf-' + role + '-workload'
            service = profile['iam.workloadClients.' + role]
            route['labels'][label] = service
            guard = guard.replace('[' + json.dumps(service) + ']=true',
                                  f'[ctx.matched_route.value.labels["{label}"]]=true')
    route['plugins'][POST]['functions'] = [guard]
    return route


class ModuleApiRelease(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(tmp.cleanup)
        cls.release = Path(tmp.name)
        generate(cls.release, COMMIT, WORKFLOW, '60')
        cls.resources = json.loads((cls.release / 'bundle.json').read_bytes())['resources']

    def test_predecessors_and_service_bindings(self):
        """GW-60i-01. Identita dei due predecessori e binding Semantic per nome anche senza export."""
        base = BASE_3D69CB4.union(ONBOARDING_IDS, SEMANTIC_MCP_IDS, READ_OPERATIONS_IDS, THS_PAGES_IDS,
                                  THS_OWNER_IDS, THS_RECOVERY_IDS, {'public-mcp-endpoint', 'public-mcp-oauth-protected-resource'})
        for ids, digest in [(BASE_3D69CB4, '672d41ca6bd2439c0d1b05e6509a37a58e24a406afc37207da0867168199e9b6'),
                            (base, 'c1f2c25d8f43c4e8028330f9f98444d0339d44e4c73337ee3b897b5ac4576d22')]:
            self.assertEqual(sha256(canonical_json([r for r in self.resources if r['id'] in ids])), digest)
        adopted = [r for r in self.resources if r['id'] in MODULE_API_IDS]
        self.assertEqual(sha256(canonical_json(adopted)), '6e0d76b9c9c6a8d113b285c0cc237b1358e1f92ed51e6a15264c215c0ba8bb2b')
        family = {r['id']: r['body'] for r in adopted}
        self.assertEqual(set(family), set(MODULE_API_IDS))
        for key, route in family.items():
            service = 'ouf-semantic-registry' if key.startswith('semantic-') else (
                'ouf-udp-object-resolution' if key == PREFLIGHT else 'ouf-onboarding')
            self.assertEqual(route['upstream']['nodes'], [{'host': {'$installation': 'services.bindings.' + service},
                                                           'port': {'$installation': 'services.ports.' + service}, 'weight': 1}])

    def test_export_adoption_readback_and_return(self):
        """GW-60i-02/03. Confronto di tutti i campi, selettori 51h, plan, rilettura e ritorno."""
        path = ROOT / '.codex-input/live-routes-all-98.json'
        if not path.is_file():
            self.skipTest('richiede export sanificato privato')
        rows = json.loads(path.read_bytes())
        live = {r['id']: {k: v for k, v in r.items() if k not in ('create_time', 'update_time')} for r in rows}
        self.assertEqual(len(live), len(rows))
        profile = live_profile(live)
        desired = {r['id']: r for r in load_release_routes(self.release, COMMIT, WORKFLOW, '60', profile)}
        targets = [desired[key] for key in MODULE_API_IDS]
        check_selectors(targets, live.values())
        state = copy.deepcopy(live)
        changes = [Change(r['id'], r['id'], live.get(r['id']), r) for r in targets]
        self.assertEqual([c.action for c in changes], ['update'] * len(MODULE_API_IDS))
        for change in changes:
            key = change.target_id
            expected = expected_route(change.before, desired, profile)
            self.assertFalse(list(changed_paths(expected, change.after)), key)
            state[key] = json.loads(canonical_json(change.after))
            self.assertEqual(Change(key, key, state[key], desired[key]).action, 'unchanged')
        for change in reversed(changes):
            state[change.target_id] = json.loads(canonical_json(change.before))
        self.assertTrue(canonical_json(state) == canonical_json(live), 'rollback differs from original export')

    def test_legacy_writes(self):
        """GW-60i-04. I dieci ID bloccano anche un ripristino misto prima del primo accesso Admin."""
        for key in MODULE_API_IDS:
            with self.assertRaisesRegex(ValueError, 'governed Gateway release'):
                apply([{'id': key}], None)
            with self.assertRaisesRegex(ValueError, 'governed Gateway release'):
                restore({'unrelated': None, key: None}, None)
        for mode in ('--materialization', '--restore'):
            result = subprocess.run([sys.executable, str(ROOT / 'ops/apisix/deploy_semantic_human.py'),
                                     mode, 'absent.json', '--admin-key', 'absent.key'],
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('governed Gateway release', result.stderr)

    def test_m2m_claims_and_forwarded_request(self):
        """GW-60i-05. Esegui Lua con identita sintetiche, inclusi client_id e azp discordi."""
        from tests.test_execute_delegation import Denied, Engine
        for item in self.resources:
            key = item['id']
            if key not in MODULE_API_IDS or key.startswith('semantic-'):
                continue
            route = item['body']
            labels = {k.encode(): v['$installation'].split('.')[-1].encode() for k, v in route['labels'].items()
                      if k.endswith('-workload')}
            allowed = {v.decode() for v in labels.values()}
            wanted = {'sourceOnboarding'} if key == PREFLIGHT else ({'ingestion', 'onboarding'} if key == FILE else {'ingestion'})
            self.assertEqual(allowed, wanted, key)
            for service in wanted:
                for client, azp, actor, status in [
                        (service, 'other', 'SERVICE', 200), (None, service, 'SERVICE', 200),
                        ('other', service, 'SERVICE', 200 if key == PREFLIGHT else 403),
                        ('other', 'other', 'SERVICE', 403), (service, service, 'HUMAN', 403)]:
                    claims = dict(azp=azp, ouf_actor_type=actor, sub='test', tenant_id='test',
                                  acr='test', iss='test', scope='test', aud='test')
                    if client is not None:
                        claims['client_id'] = client
                    engine = Engine(claims, {'X-OUF-Gateway-Verified': 'forged', 'Idempotency-Key': 'request'})
                    ctx = engine.lua.table_from({b'matched_route': {b'value': {b'labels': labels}}}, recursive=True)
                    body, bearer = engine.body, engine.headers[b'authorization']
                    plugins = route['plugins']
                    engine.lua.execute(plugins['serverless-pre-function']['functions'][0].encode())(None, ctx)
                    self.assertNotIn(b'x-ouf-gateway-verified', engine.headers)
                    access = engine.lua.execute(plugins[POST]['functions'][0].encode())
                    if status == 403:
                        with self.assertRaisesRegex(Denied, '403'):
                            access(None, ctx)
                    else:
                        access(None, ctx)
                        self.assertEqual((engine.body, engine.headers[b'authorization'], engine.headers[b'idempotency-key']),
                                         (body, bearer, b'request'))
