"""WSGI factory for the private Gateway mandate authority, behind an installation TLS listener."""
from copy import copy
import http
import os
from pathlib import Path
import sqlite3
import ssl
from types import SimpleNamespace

from tools.analysis_capacity import Capacity
from tools.analysis_clients import Endpoint, RemoteIAM, Reservations
from tools.analysis_mandate import Mandates
from tools.analysis_protocol import (
    ACTIONS, BASE, RENEWALS, RENEWAL_REQUEST_MAX, STATUS_MAX_BYTES, Catalog, Rejected, exact, matches, parse, require, wire,
)
from tools.analysis_renewal import Renewals
from tools.analysis_store import MandateStore
from tools.authority_host import credential


def https_endpoint(config, timeout):
    if not exact(config, 'url caFile clientCertFile clientKeyFile'):
        raise ValueError('explicit endpoint and role-specific mTLS trust required')
    ctx = ssl.create_default_context(cafile=config['caFile'])
    ctx.load_cert_chain(config['clientCertFile'], config['clientKeyFile'])
    return Endpoint(config['url'], ctx, timeout)


def application(cfg=None):
    if cfg is None:
        cfg = parse(Path(os.environ['OUF_ANALYSIS_CONFIG']).read_bytes())
    required = ('contract store manifestFile issuer audience workload introspection decisions '
                'reservations execute timeoutSeconds mandateTtlSeconds proofTtlSeconds maxResultBytes')
    if (type(cfg) is not dict or not set(required.split()) <= cfg.keys()
            or cfg.keys() - set(required.split()) - {'dispatchEnabled', 'statusReadsPerMinute', 'renewalChannel', 'capacity',
                                                      'keycloakCurrentRights', 'delegationKeyFile', 'delegationKeyEnv'}
            or cfg['contract'] != 'ouf.analysis.installation.v1'
            or not all(isinstance(cfg[k], str) and cfg[k] for k in ('issuer', 'audience', 'workload'))):
        raise ValueError('invalid analysis configuration')
    capacity = Capacity(cfg.get('capacity', {}))
    key = credential(cfg, 'delegationKeyFile', 'delegationKeyEnv').encode('ascii')
    timeout = cfg['timeoutSeconds']
    decisions = https_endpoint(cfg['decisions'], timeout) if cfg['decisions'] is not None else None
    iam = RemoteIAM(https_endpoint(cfg['introspection'], timeout), decisions, cfg['issuer'], cfg['audience'], cfg['workload'],
                    keycloak=cfg.get('keycloakCurrentRights', False))
    execute = https_endpoint(cfg['execute'], timeout)
    if execute.path not in ('', '/'):
        raise ValueError('governed execute HTTPS origin required')
    api = Mandates(MandateStore(cfg['store']), Catalog(Path(cfg['manifestFile']).read_bytes()), iam,
                   Reservations(https_endpoint(cfg['reservations'], timeout)), execute,
                   key, enabled=cfg.get('dispatchEnabled', False),
                   ttl=cfg['mandateTtlSeconds'], proof_ttl=cfg['proofTtlSeconds'], max_result=cfg['maxResultBytes'],
                   status_reads_per_minute=cfg.get('statusReadsPerMinute', 60))
    channel = None
    if 'renewalChannel' in cfg:
        profile = cfg['renewalChannel']
        if not exact(profile, 'mcp thsClient'):
            raise ValueError('invalid renewal channel profile')
        channel = Renewals(api, https_endpoint(profile['mcp'], timeout), profile['thsClient'])
    return handler(api, channel, capacity)


class RequestStore(MandateStore):
    """Borrow one request-owned connection across the store's short units of work."""
    def __init__(self, db):
        # MandateStore closes each borrow, including on exceptions. Discard any
        # uncommitted work then. The WSGI request owns the physical close.
        self.borrowed = SimpleNamespace(execute=db.execute, commit=db.commit, close=db.rollback)

    def connect(self):
        return self.borrowed


def handler(api, channel=None, capacity=None):
    if capacity is None:
        capacity = Capacity({})
    mandate_paths = {BASE + action: action for action in ACTIONS}
    review_paths = {RENEWALS + action: action for action in ('read', 'decide')}
    traffic = {BASE + action: 'control' for action in ('status', 'revoke', 'renewal-check')}
    traffic.update({BASE + action: 'data' for action in ('dispatch', 'issue')})
    traffic.update(dict.fromkeys(review_paths, 'relay'))

    def serve(env, start_response):
        try:
            path = env['PATH_INFO']
            if path == '/metrics' and env['REQUEST_METHOD'] == 'GET' and not env.get('QUERY_STRING'):
                body = capacity.metrics()
                start_response('200 OK', [('Content-Type', 'text/plain; version=0.0.4; charset=utf-8'),
                                          ('Content-Length', str(len(body))), ('Cache-Control', 'no-store')])
                return [body]
            require(path in traffic and env['REQUEST_METHOD'] == 'POST' and not env.get('QUERY_STRING')
                    and not env.get('HTTP_CONTENT_ENCODING')
                    and env.get('CONTENT_TYPE', '').partition(';')[0] == 'application/json')
            pool = capacity.pools[traffic[path]]
            with pool.admit():
                size = env.get('CONTENT_LENGTH', '')
                limit = STATUS_MAX_BYTES if path == BASE + 'status' else RENEWAL_REQUEST_MAX
                require(matches(size, '[1-9][0-9]{0,5}') and int(size) <= limit)
                data = env['wsgi.input'].read(int(size))
                require(len(data) == int(size))
                bearer = env.get('HTTP_AUTHORIZATION')
                if path in review_paths:
                    require(channel is not None, 503)
                    status, body, headers = channel.forward(review_paths[path], data, bearer)
                else:
                    with pool.connection(api.store) as db:
                        request_api = copy(api)
                        request_api.store = RequestStore(db)
                        status, body, headers = request_api.handle(
                            mandate_paths[path], data, bearer, env.get('HTTP_X_OUF_DELEGATION'))
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
