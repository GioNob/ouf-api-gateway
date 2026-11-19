"""Add two explicitly installed, workload-only provider routes without live writes."""
import copy
import json
from pathlib import Path
import re
from urllib.parse import urlsplit
from tools.semantic_provider_admission import AdmissionBinding


def materialize(existing, config):
    required = {'installation', 'issuer', 'audience', 'workload', 'scope', 'tenants',
                'searchPath', 'fetchPath', 'searchRouteId', 'fetchRouteId',
                'receiptKeyEnvironment', 'oidcSecretRef', 'upstream', 'tlsProfile', 'rateLimit', 'maxRequestBytes'}
    if not isinstance(config, dict) or set(config) != required:
        raise ValueError('explicit provider installation binding required')
    binding = AdmissionBinding(*(config[k] for k in ('installation', 'issuer', 'audience', 'workload', 'scope', 'tenants')))
    binding.validate()
    parsed = urlsplit(binding.issuer)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError('safe issuer required')
    if not isinstance(config['receiptKeyEnvironment'], str) or not re.fullmatch('[A-Z][A-Z0-9_]{1,127}', config['receiptKeyEnvironment']):
        raise ValueError('receipt key environment required')
    if config['receiptKeyEnvironment'] in {'OUF_GATEWAY_DELEGATION_KEY','OUF_SEMANTIC_READ_OWNER_KEY'}:
        raise ValueError('purpose-separated provider receipt key required')
    if not isinstance(config['oidcSecretRef'], str) or not config['oidcSecretRef'].startswith(('$ENV://', '$secret://')):
        raise ValueError('OIDC secret reference required')
    ids = [config['searchRouteId'], config['fetchRouteId']]
    paths = [config['searchPath'], config['fetchPath']]
    if len(set(ids)) != 2 or any(not isinstance(v, str) or not re.fullmatch('[A-Za-z0-9_-]{1,128}', v) for v in ids):
        raise ValueError('distinct route IDs required')
    if len(set(paths)) != 2 or any(not isinstance(v, str) or not re.fullmatch(r'/[A-Za-z0-9_/-]{1,200}', v)
                                  or '//' in v or v.endswith('/') for v in paths):
        raise ValueError('distinct exact paths required')
    max_bytes = config['maxRequestBytes']
    if type(max_bytes) is not int or not 1 <= max_bytes <= 65536:
        raise ValueError('bounded request size required')
    upstream = config['upstream']
    if not isinstance(upstream, dict) or set(upstream) != {'type', 'scheme', 'nodes', 'pass_host', 'upstream_host', 'timeout'} \
            or upstream.get('type') != 'roundrobin' or upstream.get('scheme') != 'https' \
            or not upstream.get('nodes') \
            or upstream.get('pass_host') != 'rewrite' or not upstream.get('upstream_host'):
        raise ValueError('explicit certificate-verified HTTPS adapter binding required')
    if not isinstance(upstream['nodes'], dict) or len(upstream['nodes']) != 1 \
            or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{0,252}', upstream['upstream_host']):
        raise ValueError('exact installed adapter endpoint and trust binding required')
    for node, weight in upstream['nodes'].items():
        endpoint = urlsplit('https://'+node)
        if not endpoint.hostname or endpoint.port is None or endpoint.port < 1 or weight != 1 \
                or endpoint.username or endpoint.password or endpoint.path or endpoint.query or endpoint.fragment:
            raise ValueError('explicit adapter host and port required')
    timeout = upstream['timeout']
    if not isinstance(timeout, dict) or set(timeout) != {'connect', 'send', 'read'} \
            or any(type(v) is not int or not 1 <= v <= 60 for v in timeout.values()):
        raise ValueError('bounded adapter upstream timeouts required')
    # APISIX 3.18's upstream.tls.verify is Kafka-only, not HTTPS enforcement.
    # Require the explicit NGINX verification/trust profile for a separately
    # governed southbound role; a route alone cannot enable this global setting.
    tls = config['tlsProfile']
    if not isinstance(tls, dict) or set(tls) != {'role', 'mode', 'trustedCertificateFile', 'verifyDepth'} \
            or tls['role'] != 'DEDICATED_SOUTHBOUND' or tls['mode'] != 'NGINX_PROXY_SSL_VERIFY' \
            or not isinstance(tls['trustedCertificateFile'], str) \
            or not re.fullmatch(r'/[A-Za-z0-9_./-]{1,255}', tls['trustedCertificateFile']) \
            or '..' in tls['trustedCertificateFile'].split('/') \
            or type(tls['verifyDepth']) is not int or not 1 <= tls['verifyDepth'] <= 5:
        raise ValueError('explicit dedicated southbound NGINX TLS profile required')
    rate = config['rateLimit']
    if not isinstance(rate, dict) or set(rate) != {'count', 'time_window', 'key_type', 'key', 'policy', 'rejected_code'} \
            or type(rate.get('count')) is not int or not 1 <= rate['count'] <= 1000 \
            or type(rate.get('time_window')) is not int or not 1 <= rate['time_window'] <= 3600 \
            or rate.get('key_type') != 'var' or rate.get('key') != 'remote_addr' \
            or rate.get('policy') != 'local' or rate.get('rejected_code') != 429:
        raise ValueError('explicit bounded rate limit required')
    if not isinstance(existing, dict) or not isinstance(existing.get('routes'), list):
        raise ValueError('existing route snapshot required')
    if any(route.get('id') in ids or route.get('uri') in paths for route in existing['routes']):
        raise ValueError('provider binding already exists; reconcile before installation')
    result = copy.deepcopy(existing)
    if 'providerTLSRequirement' in result:
        raise ValueError('provider TLS requirement already exists; reconcile first')
    result['providerTLSRequirement'] = {'role': tls['role'], 'mode': tls['mode'],
        'apisixSSLTrustedCertificate': tls['trustedCertificateFile'],
        'nginxHTTPConfigurationSnippet': 'proxy_ssl_verify on;\nproxy_ssl_verify_depth '+str(tls['verifyDepth'])+';',
        'installed': False}
    template = (Path(__file__).parent/'lua/admit_semantic_provider.lua').read_text()
    constants = {'INSTALLATION': binding.installation, 'ISSUER': binding.issuer, 'AUDIENCE': binding.audience,
                 'WORKLOAD': binding.workload, 'SCOPE': binding.scope, 'RECEIPT_KEY_ENV': config['receiptKeyEnvironment']}
    prefix = '\n'.join('local '+key+'='+json.dumps(value) for key, value in constants.items())
    prefix += '\nlocal TENANTS={'+','.join('['+json.dumps(v)+']=true' for v in binding.tenants)+'}\n'
    strip = "return function(conf,ctx) for name,_ in pairs(ngx.req.get_headers(0)) do if name:lower():sub(1,6)=='x-ouf-' then ngx.req.clear_header(name) end end end"
    for name, method in (('search', 'POST'), ('fetch', 'GET')):
        lua = 'return function(conf,ctx)\n'+prefix+'local METHOD='+json.dumps(method)+'\nlocal PATH='+json.dumps(config[name+'Path'])+'\nlocal MAX_REQUEST_BYTES='+str(max_bytes)+'\n'+template+'\nend'
        result['routes'].append({'id': config[name+'RouteId'], 'uri': config[name+'Path'], 'methods': [method],
            'labels': {'ouf-managed': 'true', 'ouf-installation': binding.installation, 'ouf-mediation': 'semantic-provider-transport-v1'},
            'plugins': {'client-control': {'max_body_size': max_bytes}, 'limit-count': copy.deepcopy(rate),
                'serverless-pre-function': {'phase': 'rewrite', 'functions': [strip]},
                'openid-connect': {'client_id': binding.audience, 'client_secret': config['oidcSecretRef'],
                    'discovery': binding.issuer.rstrip('/')+'/.well-known/openid-configuration',
                    'bearer_only': True, 'unauth_action': 'deny', 'use_jwks': True, 'ssl_verify': True,
                    'required_scopes': [binding.scope],
                    'claim_validator': {'audience': {'required': True, 'match_with_client_id': True}},
                    'set_access_token_header': False, 'set_id_token_header': False, 'set_userinfo_header': False},
                'serverless-post-function': {'phase': 'access', 'functions': [lua]}},
            'upstream': {**copy.deepcopy(upstream), 'retries': 0}})
    return result
