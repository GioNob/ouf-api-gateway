"""WSGI factory for the private Gateway mandate authority, behind an installation TLS listener."""
import http
import os
from pathlib import Path
import sqlite3
import ssl

from tools.analysis_clients import Endpoint, RemoteIAM, Reservations
from tools.analysis_mandate import Mandates
from tools.analysis_protocol import BASE, Catalog, Rejected, exact, matches, parse, require, wire
from tools.analysis_store import MandateStore


def https_endpoint(config, timeout):
    if not exact(config, 'url caFile clientCertFile clientKeyFile'):
        raise ValueError('explicit endpoint and role-specific mTLS trust required')
    ctx = ssl.create_default_context(cafile=config['caFile'])
    ctx.load_cert_chain(config['clientCertFile'], config['clientKeyFile'])
    return Endpoint(config['url'], ctx, timeout)


def application():
    cfg = parse(Path(os.environ['OUF_ANALYSIS_CONFIG']).read_bytes())
    required = ('contract store manifestFile issuer audience workload delegationKeyEnv introspection decisions '
                'reservations execute timeoutSeconds mandateTtlSeconds proofTtlSeconds maxResultBytes')
    if (not (exact(cfg, required) or exact(cfg, required + ' dispatchEnabled'))
            or cfg['contract'] != 'ouf.analysis.installation.v1'
            or not matches(cfg['delegationKeyEnv'], '[A-Z][A-Z0-9_]{0,127}')
            or not all(isinstance(cfg[k], str) and cfg[k] for k in ('issuer', 'audience', 'workload'))):
        raise ValueError('invalid analysis configuration')
    timeout = cfg['timeoutSeconds']
    decisions = https_endpoint(cfg['decisions'], timeout) if cfg['decisions'] is not None else None
    iam = RemoteIAM(https_endpoint(cfg['introspection'], timeout), decisions, cfg['issuer'], cfg['audience'], cfg['workload'])
    execute = https_endpoint(cfg['execute'], timeout)
    if execute.path not in ('', '/'):
        raise ValueError('governed execute HTTPS origin required')
    api = Mandates(MandateStore(cfg['store']), Catalog(Path(cfg['manifestFile']).read_bytes()), iam,
                   Reservations(https_endpoint(cfg['reservations'], timeout)), execute,
                   os.environ[cfg['delegationKeyEnv']].encode('ascii'), enabled=cfg.get('dispatchEnabled', False),
                   ttl=cfg['mandateTtlSeconds'], proof_ttl=cfg['proofTtlSeconds'], max_result=cfg['maxResultBytes'])
    return handler(api)


def handler(api):
    def serve(env, start_response):
        try:
            path = env['PATH_INFO']
            require(path in {BASE + action for action in ('issue', 'dispatch', 'revoke')}
                    and env['REQUEST_METHOD'] == 'POST' and not env.get('QUERY_STRING')
                    and not env.get('HTTP_CONTENT_ENCODING')
                    and env.get('CONTENT_TYPE', '').partition(';')[0] == 'application/json')
            size = env.get('CONTENT_LENGTH', '')
            require(matches(size, '[1-9][0-9]{0,5}') and int(size) <= 131072)
            data = env['wsgi.input'].read(int(size))
            require(len(data) == int(size))
            status, body, headers = api.handle(path[len(BASE):], data, env.get('HTTP_AUTHORIZATION'),
                                               env.get('HTTP_X_OUF_DELEGATION'))
        except Rejected as exc:
            status, body = exc.status, wire({'code': exc.code})
            headers = {'Retry-After': exc.retry_after} if exc.retry_after else {}
        except (sqlite3.Error, OSError):
            status, body, headers = 503, wire({'code': 'ANALYSIS_AUTHORITY_UNAVAILABLE'}), {}
        response_headers = [('Content-Type', 'application/json'), ('Content-Length', str(len(body))),
                            ('Cache-Control', 'no-store'), *headers.items()]
        reason = http.HTTPStatus(status).phrase if status in http.HTTPStatus._value2member_map_ else 'Owner Response'
        start_response(f'{status} {reason}', response_headers)
        return [body]
    return serve
