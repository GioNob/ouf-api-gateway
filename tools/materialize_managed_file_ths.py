"""Materialize only the first-party HUMAN picker UI route, bound to existing upload."""
import argparse
import json
from pathlib import Path

ROUTE_ID = 'trusted-human-managed-file-picker'
URI = '/trusted-human/managed-files/*'
CAP = 'ouf.managed-source.file.upload'


def materialize(runtime):
    installation = runtime['x-ouf-installation']
    bindings = [r for r in runtime['routes'] if r.get('id') == 'trusted-human-managed-file-upload']
    if len(bindings) != 1:
        raise ValueError('exact managed-file HUMAN binding required')
    binding = bindings[0]
    policy = binding['x-ouf-policy']
    capability = binding['x-ouf-capability']
    backend = binding['x-ouf-backend-binding']
    if (binding.get('uri') != '/api/managed-sources/v1/files'
            or policy['identity'] != 'OIDC' or policy['requiredScope'] != CAP
            or policy['allowedActorTypes'] != ['HUMAN']
            or capability['capabilityId'] != CAP
            or backend['service'] != 'ouf-onboarding' or backend['port'] != 8080
            or backend['path'] != '/api/managed-sources/v1/files'):
        raise ValueError('managed-file HUMAN binding mismatch')
    return {'formatVersion': '1.0', 'installationId': installation['installationId'],
            'installationRevision': installation['revision'], 'routes': [{
                'id': ROUTE_ID, 'uri': URI, 'methods': ['GET', 'POST'],
                'labels': {'ouf-managed': 'true', 'ouf-installation': installation['installationId'],
                           'ouf-capability': CAP, 'ouf-surface': 'TRUSTED_HUMAN_MANAGED_FILE'},
                'plugins': {
                    'client-control': {'max_body_size': 10485760},
                    'proxy-control': {'request_buffering': False},
                    'serverless-pre-function': {'phase': 'rewrite', 'functions': [
                        "return function() for k,_ in pairs(ngx.req.get_headers(0)) do "
                        "local n=k:lower(); if n:sub(1,6)=='x-ouf-' or n=='authorization' "
                        "then ngx.req.clear_header(k) end end end"]},
                },
                'upstream': {'type': 'roundrobin', 'scheme': 'http',
                             'nodes': {'ouf-onboarding:8080': 1}, 'retries': 0,
                             'timeout': {'connect': 10, 'send': 30, 'read': 30}},
            }]}


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--runtime', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    a.output.write_text(json.dumps(materialize(json.loads(a.runtime.read_text())), indent=2) + '\n')
