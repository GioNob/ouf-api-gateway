"""Read-only route preflight must reject existing routes and never write Admin API."""
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from ops.apisix import preflight_r4a_route as subject


@pytest.mark.parametrize('route_status,expected', [(404, True), (200, False)])
def test_admin_preflight_reads_only(monkeypatch, tmp_path, route_status, expected):
    backup = tmp_path / 'backup'
    backup.mkdir(mode=0o700)
    manifest = tmp_path / 'materialization.json'
    manifest.write_text(json.dumps({
        'delegationKeyEnv': 'OUF_GATEWAY_DELEGATION_KEY',
        'udpOwnerKeyEnv': 'OUF_UDP_SEARCH_OWNER_KEY',
        'routes': [{
            'id': subject.ROUTE_ID, 'uri': subject.ROUTE_URI,
            'methods': ['POST'],
            'upstream': {'nodes': {'ouf-udp-object-resolution:8080': 1}, 'retries': 0},
            'plugins': {
                'proxy-rewrite': {'uri': '/api/udp/v1/objects/search'},
                'openid-connect': {'client_secret': '$ENV://OUF_GATEWAY_OIDC_CLIENT_SECRET'},
            },
        }],
    }))
    manifest.chmod(0o600)
    if os.getuid() != 0:
        original_stat = Path.stat
        def root_owned_stat(path, *args, **kwargs):
            stat = original_stat(path, *args, **kwargs)
            if path in (backup, manifest):
                return SimpleNamespace(st_uid=0, st_mode=stat.st_mode)
            return stat
        monkeypatch.setattr(Path, 'stat', root_owned_stat)
    key = tmp_path / 'key'
    key.write_text('test key')
    env = ['OUF_GATEWAY_DELEGATION_KEY=' + 'a' * 64,
           'OUF_UDP_SEARCH_OWNER_KEY=' + 'b' * 64,
           'OUF_GATEWAY_OIDC_CLIENT_SECRET=test']
    def docker(cmd, **kwargs):
        if cmd[1:3] == ['inspect', 'ouf-apisix']:
            return SimpleNamespace(stdout=json.dumps([{'Config': {'Env': env}}]))
        if cmd[1:4] == ['exec', 'ouf-apisix', 'cat']:
            return SimpleNamespace(stdout='env OUF_GATEWAY_DELEGATION_KEY;\nenv OUF_UDP_SEARCH_OWNER_KEY;')
        assert cmd[1:3] == ['image', 'inspect']
        return SimpleNamespace(stdout='')
    monkeypatch.setattr(subject.subprocess, 'run', docker)
    calls = []
    class FakeAdmin:
        def __init__(self, args):
            self.work = backup / 'temporary'
            self.work.mkdir()
        def __call__(self, method, route_id):
            calls.append((method, route_id))
            return route_status, {}
    monkeypatch.setattr(subject, 'Admin', FakeAdmin)
    if expected:
        subject.preflight(manifest, key, backup)
    else:
        with pytest.raises(ValueError, match='already exists'):
            subject.preflight(manifest, key, backup)
    assert calls == [('GET', subject.ROUTE_ID)]
    assert not (backup / 'temporary').exists()


def test_new_route_unauthenticated_probe():
    from ops.apisix.deploy_object_search import SearchAdmin
    admin = object.__new__(SearchAdmin)
    calls = []
    def curl(path, method='GET', data=None, admin=False):
        calls.append((path, method))
        if path == '/.well-known/oauth-protected-resource':
            return 200, {}
        return 401, {}
    admin.curl = curl
    admin.check_public()
    assert calls[-1] == (subject.ROUTE_URI, 'POST')
