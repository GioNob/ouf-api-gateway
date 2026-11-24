import ast
import hashlib
import io
import json
import os
from pathlib import Path
from zipfile import ZipFile

import pytest

from tests.fixtures import resolution_plan_reference as reference
from tests.release_bundle_fixture import ci_profile, load_release_routes
from tools.apply_installation_projection import apply_projection
from tools.compile_config import compile_config
from tools.gateway_release_bundle import generate
from tools.materialize_onboarding_review import materialize as onboarding
from tools.materialize_permission_proposals import materialize as permissions
from tools.materialize_r4a_identity_preflight import materialize as preflight
from tools.materialize_resolution_ths import materialize

ROOT = Path(__file__).resolve().parents[1]
SECRET_REF = '$ENV://OIDC_SECRET'
WORKFLOW = '.github/workflows/ci.yml'
COMMIT = '1' * 40


@pytest.fixture(scope='module')
def runtime():
    projection = json.loads((ROOT / 'tests/fixtures/installation-projection-lab.json').read_bytes())
    projection['services']['bindings']['ouf-udp-object-resolution'] = 'udp-fixture'
    return apply_projection(compile_config(ROOT / 'ouf-config'), projection)


def test_resolution_matches_installation_plan(runtime, tmp_path):
    existing = permissions(runtime, SECRET_REF, 'DELEGATION_KEY', 'AUTHORIZATION_OWNER_KEY')
    workflows = onboarding(existing, runtime, 'DELEGATION_KEY', 'ONBOARDING_OWNER_KEY')
    udp = preflight(runtime, SECRET_REF, 'udp-fixture')
    before = {r['id']: r for r in workflows['routes'] + udp['routes']}
    expected = reference.compile_routes(before)
    assert {r['id']: r for r in materialize(runtime, SECRET_REF)} == expected

    # Compare the serialized release after resolving a distinct upstream per owner.
    generate(tmp_path, COMMIT, WORKFLOW, '36')
    installation = runtime['x-ouf-installation']
    profile = ci_profile(installation, 18080)
    profile['caddy.oidcDiscoveryUrl'] = installation['issuerUrl'] + '/.well-known/openid-configuration'
    profile.update({'services.bindings.ouf-onboarding': 'ouf-onboarding', 'services.ports.ouf-onboarding': 18081,
                    'services.bindings.ouf-udp-object-resolution': 'udp-fixture', 'services.ports.ouf-udp-object-resolution': 18082})
    released = {r['id']: r for r in load_release_routes(tmp_path, COMMIT, WORKFLOW, '36', profile)}
    for route in expected.values():
        (address, weight), = route['upstream']['nodes'].items()
        host, port = address.rsplit(':', 1)
        assert port == '8080'
        port = {'ouf-onboarding': 18081, 'udp-fixture': 18082}[host]
        route['upstream']['nodes'] = [{'host': host, 'port': port, 'weight': weight}]
    assert {key: released[key] for key in expected} == expected


@pytest.fixture
def deploy_checkout():
    checkout = os.environ.get('OUF_DEPLOY_CHECKOUT')
    if not checkout:
        pytest.skip('Set OUF_DEPLOY_CHECKOUT to compare with the original installer')
    return Path(checkout)


def test_reference_matches_deploy_source(deploy_checkout):
    # Compare the transformation and its constants without importing Linux installation code.
    def definitions(path):
        result = {}
        for node in ast.parse(path.read_bytes()).body:
            if isinstance(node, ast.FunctionDef) and node.name == 'compile_routes':
                result[node.name] = ast.dump(node)
            if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
                name = node.targets[0].id
                if name in ('PAGE', 'PACKAGE', 'ROUTES', 'UUID_PATTERN', 'CONFIRM_SCHEMA'):
                    result[name] = ast.dump(node)
        return result

    assert definitions(Path(reference.__file__)) == definitions(deploy_checkout / 'tools/resolution_ths_update/plan.py')


def test_release_passes_executor_verifier(deploy_checkout, monkeypatch, runtime, tmp_path):
    monkeypatch.syspath_prepend(str(deploy_checkout / 'tools'))
    monkeypatch.syspath_prepend(str(deploy_checkout / 'tools/privileged_executor'))
    from gateway_bundle import verify

    generate(tmp_path, COMMIT, WORKFLOW, '36')
    archive = io.BytesIO()
    with ZipFile(archive, 'w') as output:
        for path in tmp_path.iterdir():
            output.write(path, path.name)
    raw = archive.getvalue()
    ci = {'repository': 'GioNob/ouf-api-gateway', 'workflow': 'ci.yml', 'runId': 36,
          'sourceCommit': COMMIT, 'zipSha256': hashlib.sha256(raw).hexdigest()}
    profile = ci_profile(runtime['x-ouf-installation'], 18080)
    verified = verify(raw, ci, profile)
    assert verified['retired'] == json.loads((tmp_path / 'bundle.json').read_bytes())['retired']
    routes = [dict(r['body'], id=r['id']) for r in verified['resources']]
    assert routes == load_release_routes(tmp_path, COMMIT, WORKFLOW, '36', profile)
