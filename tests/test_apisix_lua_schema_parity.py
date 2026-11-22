"""Differential gate: APISIX's Lua validator must give the pinned MCP verdict.

Every JSON dispatch route is evaluated by the request-validation modules of
the APISIX image used in production, on a corpus derived from the pinned MCP
input schemas (current release) and from the MCP in service (mixed window of
the D-086 train, Gateway before MCP).
"""
import json
import os
import subprocess
from pathlib import Path

import pytest
import yaml

from tests.dispatch_schema_parity import cases, dispatch_routes

APISIX_IMAGE = 'apache/apisix:3.18.0-debian'
SCRIPT = Path(__file__).resolve().parent / 'apisix_schema_parity.lua'


@pytest.mark.skipif(os.environ.get('OUF_APISIX_LIVE_TEST') != '1', reason='requires Docker APISIX image')
def test_apisix_lua_validator_keeps_the_mcp_verdict(tmp_path):
    routes = dispatch_routes(tmp_path / 'release')
    corpus = cases(routes)
    work = tmp_path / 'work'
    work.mkdir()
    schemas = {uri: route['plugins']['request-validation']['body_schema'] for uri, route in routes.items()}
    (work / 'schemas.yaml').write_text(yaml.safe_dump(schemas), encoding='utf-8')
    (work / 'cases.json').write_text(json.dumps([[uri, json.dumps(body)] for uri, body, _, _ in corpus]),
                                     encoding='utf-8')
    os.chmod(work, 0o755)
    output = subprocess.run([
        'docker', 'run', '--rm', '-v', f'{work}:/w:ro', '-v', f'{SCRIPT}:/parity.lua:ro',
        '--entrypoint', '/usr/local/openresty/bin/resty', APISIX_IMAGE,
        '-I', '/usr/local/apisix', '-I', '/usr/local/apisix/deps/share/lua/5.1',
        '/parity.lua', '/w/schemas.yaml', '/w/cases.json',
    ], capture_output=True, text=True, timeout=600)
    lines = [line.split('\t') for line in output.stdout.splitlines()]
    assert lines and lines[-1] == ['DONE', str(len(corpus))], output.stderr[-4000:]
    mismatches = []
    kinds = {'current': 0, 'predecessor': 0}
    for (uri, body, expected, kind), (index, verdict, error) in zip(corpus, lines[:-1]):
        kinds[kind] += 1
        if (verdict == '1') != expected:
            mismatches.append({'uri': uri, 'kind': kind, 'expected': expected, 'lua': error,
                               'arguments': body['Arguments']})
    assert not mismatches, json.dumps(mismatches[:5], ensure_ascii=False)[:4000]
    assert kinds['current'] > 0 and kinds['predecessor'] > 0
