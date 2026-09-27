import json
from pathlib import Path
import re

import pytest

from tools.apply_installation_projection import apply_projection
from tools.compile_config import compile_config
from tools.materialize_semantic_human_runtime import REGEX, ROUTES, materialize
from ops.apisix.deploy_semantic_human import validate, install, sample_uri

ROOT = Path(__file__).resolve().parents[1]


def compiled():
    projection = json.loads((ROOT / 'tests/fixtures/installation-projection-lab.json').read_text())
    return apply_projection(compile_config(ROOT / 'ouf-config'), projection)


def routes():
    return validate(materialize(compiled(), '$ENV://OUF_GATEWAY_OIDC_CLIENT_SECRET'))


def test_exact_scopes_and_bounded_suffixes():
    selected = routes()
    assert len(selected) == 8
    for route in selected:
        route_id = route['id']
        assert route['upstream']['nodes'] == {'ouf-semantic:8080': 1}
        assert route['plugins']['openid-connect']['required_scopes'] == [ROUTES[route_id][2]]
        assert route['plugins']['openid-connect']['set_access_token_header'] is False
        assert route['plugins']['client-control']['max_body_size'] == (
            8388608 if route_id == 'semantic-rdf-import' else 65536)
        if route_id in REGEX:
            assert re.fullmatch(route['vars'][0][2], sample_uri(route))
        else:
            assert 'vars' not in route
    by_id = {route['id']: route for route in selected}
    decision = by_id['semantic-human-decision']
    publish = by_id['semantic-human-publish']
    assert decision['uri'] == publish['uri']
    assert not re.fullmatch(decision['vars'][0][2], sample_uri(publish))
    assert not re.fullmatch(publish['vars'][0][2], sample_uri(decision))


def test_scope_or_upstream_drift_fails_before_admin_mutation():
    document = materialize(compiled(), '$ENV://OUF_GATEWAY_OIDC_CLIENT_SECRET')
    document['routes'][0]['plugins']['openid-connect']['required_scopes'] = ['ouf.semantic.publish']
    with pytest.raises(ValueError, match='CONTRACT_CHANGED'):
        validate(document)
    runtime = compiled()
    binding = next(row for row in runtime['routes'] if row['id'] == 'semantic-human-publish')
    binding['x-ouf-backend-binding']['service'] = 'unreviewed-upstream'
    with pytest.raises(ValueError, match='CONTRACT_CHANGED'):
        materialize(runtime, '$ENV://OUF_GATEWAY_OIDC_CLIENT_SECRET')


def test_installer_rejects_existing_route_drift_without_a_write(monkeypatch, tmp_path):
    selected = routes()
    class Admin:
        work = tmp_path
        def route(self, *args):
            raise AssertionError('no writes permitted')
    def snapshot(ids, admin):
        assert ids == set(ROUTES)
        return {key: ({'uri': '/changed'} if key == selected[0]['id'] else None) for key in ids}
    monkeypatch.setattr('ops.apisix.deploy_semantic_human.snapshot', snapshot)
    with pytest.raises(RuntimeError, match='EXISTING_SEMANTIC_ROUTE_DRIFT'):
        install(selected, Admin())
