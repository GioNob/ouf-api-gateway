"""Private HTTPS listener for the Gateway's opt-in D-104 runtime."""
import argparse
import http.client
import logging
import os
import socket
import ssl
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

from tools.analysis_batch_mandate import (
    AUTHORIZATION_INVALID, AUTHORIZATION_TLS, AUTHORIZATION_UNAVAILABLE, DISCOVERY_BINDING_HEADER,
    UNAVAILABLE, BatchMandates, Clock,
)
from tools.analysis_batch_protocol import (
    Denied, MAX_REQUEST, digest, exact, hash_ref, identity_value, parse, require,
    signing_key, token, uuid_ref, wire,
)
from tools.analysis_batch_store import BatchMandateAudit

BASE = '/internal/analysis-batch/v1/'
LOG = logging.getLogger(__name__)
ROUTES = {BASE + action: action for action in ('prepare', 'issue', 'dispatch', 'expire', 'revoke', 'read')}
AUTHORIZATION_PATH = '/api/internal/v1/authorization/analysis-mandates/'
AUTHORIZATION_LIMIT = 16_384
AUTHORIZATION_ERRORS = {
    400: {'INVALID_REQUEST'},
    401: {'GATEWAY_AUTHENTICATION_REQUIRED', 'HUMAN_AUTHENTICATION_REQUIRED'},
    403: {'GATEWAY_WORKLOAD_DENIED', 'MANDATE_BINDING_MISMATCH', 'HUMAN_PROOF_REQUIRED',
          'HUMAN_PROOF_INVALID', 'REAUTHENTICATION_REQUIRED', 'OPERATION_DENIED', 'PRINCIPAL_INACTIVE',
          'CURRENT_RIGHTS_DENIED', 'RIGHTS_CHANGED', 'POLICY_EPOCH_CHANGED', 'POLICY_CHANGED',
          'MANDATE_REVOKED', 'MANDATE_EXPIRED', 'REVOCATION_DENIED'},
    404: {'MANDATE_NOT_FOUND'},
    409: {'ISSUE_KEY_CONFLICT', 'MANDATE_VERSION_CHANGED', 'MANDATE_GENERATION_CHANGED',
          'MANDATE_NOT_RENEWABLE', 'DEADLINE_NOT_REACHED'},
    500: {'REGISTRY_FAILURE'},
    503: {'CURRENT_RIGHTS_UNAVAILABLE', 'RIGHTS_EVIDENCE_INVALID', 'CLOCK_UNVERIFIED', 'REGISTRY_UNAVAILABLE'},
}


class HTTPS:
    def __init__(self, config, timeout, *, origin=False):
        if not exact(config, 'url caFile certFile keyFile') or not all(isinstance(v, str) and v for v in config.values()):
            raise ValueError('explicit HTTPS trust and client certificate required')
        url = urlsplit(config['url'])
        if (url.scheme != 'https' or not url.hostname or url.username is not None or url.password is not None
                or url.query or url.fragment or url.path.startswith('//') or (origin and url.path not in ('', '/'))):
            raise ValueError('invalid configured HTTPS destination')
        self.host, self.port, self.path = url.hostname, url.port, url.path
        self.timeout = timeout
        self.context = tls_context(config, server=False)

    def connection(self):
        return http.client.HTTPSConnection(self.host, self.port, timeout=self.timeout, context=self.context)

    def reachable(self):
        connection = self.connection()
        try:
            connection.connect()
        finally:
            connection.close()

    def post(self, path, body, headers, limit, failure, *, invalid=None, tls_failure=None):
        connection = self.connection()
        started = time.monotonic()
        timer = None
        try:
            connection.connect()
            remaining = self.timeout - (time.monotonic() - started)
            require(remaining > 0, 503, failure)
            peer_socket = connection.sock

            def interrupt():
                try:
                    peer_socket.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

            # Limit the full response as well as each socket read. A peer
            # sending occasional bytes cannot renew the attempt indefinitely.
            timer = threading.Timer(remaining, interrupt)
            timer.daemon = True
            timer.start()
            connection.request('POST', path, body, headers)
            with connection.getresponse() as response:
                data = response.read(limit + 1)
                require(time.monotonic() - started < self.timeout, 503, failure)
                require(len(data) <= limit and response.length in (0, None)
                        and not 300 <= response.status < 400, 502 if invalid else 503, invalid or failure)
                safe = {}
                retry = response.getheader('Retry-After')
                if token(retry, r'(?:[0-9]{1,9}|[A-Za-z0-9, :]{10,40})'):
                    safe['Retry-After'] = retry
                return response.status, data, safe
        except ssl.SSLError as exc:
            raise Denied(502 if tls_failure else 503, tls_failure or failure) from exc
        except (OSError, http.client.HTTPException) as exc:
            raise Denied(503, failure) from exc
        finally:
            if timer is not None:
                timer.cancel()
            connection.close()

    def evidence(self, body):
        headers = {'Content-Type': 'application/json', 'Cache-Control': 'no-store'}
        status, raw, headers = self.post(self.path or '/', body, headers, MAX_REQUEST, UNAVAILABLE)
        if status in (429, 503):
            raise Denied(status, UNAVAILABLE, headers.get('Retry-After'))
        if status in (401, 403):
            raise Denied(403, 'ANALYSIS_EVIDENCE_CHANNEL_DENIED')
        require(status == 200, 503, UNAVAILABLE)
        try:
            return parse(raw)
        except Denied as exc:
            raise Denied(503, UNAVAILABLE) from exc

    def send(self, path, body, headers, limit):
        return self.post(path, body, headers, limit, 'ANALYSIS_OWNER_OUTCOME_UNCERTAIN')


class Authorization(HTTPS):
    def __init__(self, config, timeout):
        super().__init__(config, timeout, origin=True)

    def command(self, action, payload, bearer=None):
        body = wire(payload)
        require(len(body) <= AUTHORIZATION_LIMIT, 413, 'ANALYSIS_AUTHORIZATION_REQUEST_TOO_LARGE')
        headers = {'Content-Type': 'application/json', 'Cache-Control': 'no-store'}
        if action == 'revoke' and bearer is not None:
            headers['Authorization'] = bearer
        status, raw, response_headers = self.post(AUTHORIZATION_PATH + action, body, headers,
                                                  AUTHORIZATION_LIMIT, AUTHORIZATION_UNAVAILABLE,
                                                  invalid=AUTHORIZATION_INVALID, tls_failure=AUTHORIZATION_TLS)
        try:
            view = parse(raw)
        except Denied as exc:
            raise Denied(502, AUTHORIZATION_INVALID) from exc
        if status != 200:
            require(exact(view, 'code') and isinstance(view['code'], str)
                    and view['code'] in AUTHORIZATION_ERRORS.get(status, ()), 502, AUTHORIZATION_INVALID)
            raise Denied(status, view['code'], response_headers.get('Retry-After') if status == 503 else None)
        fields = 'mandateRef generation version state analysisId expiresAtMs'
        if action == 'admit':
            fields += ' receiptContext'
        require(exact(view, fields)
                and uuid_ref(view['mandateRef'], v4=True) and hash_ref(view['analysisId'])
                and type(view['generation']) is int and view['generation'] == payload['generation']
                and type(view['version']) is int and type(view['expiresAtMs']) is int
                and 0 < view['expiresAtMs'] <= 2**63 - 1
                and view['state'] in ('ACTIVE', 'REVOKED', 'EXPIRED')
                and view['version'] == (1 if view['state'] == 'ACTIVE' else 2)
                and all(view[k] == payload[k] for k in ('mandateRef', 'analysisId') if k in payload)
                and (action != 'admit' or (view['state'] == 'ACTIVE' and view['version'] == payload['expectedVersion']))
                and (action != 'revoke' or view['state'] == 'REVOKED')
                and (action != 'expire' or view['state'] in ('REVOKED', 'EXPIRED')),
                502, AUTHORIZATION_INVALID)
        return view


def tls_context(config, *, server):
    if server:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_verify_locations(cafile=config['caFile'])
        # Missing certificates reach the handler solely to produce an audited
        # denial. A supplied certificate must pass CA validation in the handshake.
        context.verify_mode = ssl.CERT_OPTIONAL
    else:
        context = ssl.create_default_context(cafile=config['caFile'])
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(config['certFile'], config['keyFile'])
    return context


class Listener(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, api, tls, pins, timeout, capacity):
        super().__init__(address, Handler)
        self.api, self.tls, self.pins, self.timeout = api, tls, pins, timeout
        self.workers = threading.BoundedSemaphore(capacity + 4)
        self.data = threading.BoundedSemaphore(capacity)
        self.ready_until = 0

    def process_request(self, request, client_address):
        if not self.workers.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.workers.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            request.settimeout(self.timeout)
            try:
                wrapped = self.tls.wrap_socket(request, server_side=True)
            except OSError:
                LOG.info('ANALYSIS_TLS_PEER_REJECTED')
                self.shutdown_request(request)
                return
            super().process_request_thread(wrapped, client_address)
        finally:
            self.workers.release()

    def handle_error(self, request, client_address):
        LOG.error('ANALYSIS_LISTENER_REQUEST_FAILED')


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def reply(self, status, body=b'', headers=None):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        for name in ('Retry-After', DISCOVERY_BINDING_HEADER):
            if headers and name in headers:
                self.send_header(name, headers[name])
        self.end_headers()
        if body:
            self.wfile.write(body)

    def problem(self, error):
        self.reply(error.status, wire({'code': error.code}),
                   {'Retry-After': error.retry_after} if error.retry_after else None)

    def do_GET(self):
        if self.path == '/health/live':
            self.reply(204)
        elif self.path == '/health/ready':
            try:
                clock = self.server.api.clock
                clock.checked()
                ready = clock.monotonic() < self.server.ready_until
            except Denied:
                ready = False
            self.reply(204 if ready else 503)
        else:
            self.reply(404)

    def do_POST(self):
        action = ROUTES.get(self.path)
        if action is None:
            self.reply(404)
            return
        certificate = self.connection.getpeercert(binary_form=True)
        peer = self.server.pins.get(digest(certificate)) if certificate else None
        if peer is None or (peer != 'mcp' and action != 'revoke'):
            self.run_action(action, b'', peer, None)
            return
        slot = self.server.data if action in ('dispatch', 'issue', 'prepare') else None
        if slot and not slot.acquire(blocking=False):
            self.reject(action, Denied(429, 'ANALYSIS_CAPACITY_EXCEEDED', '1'))
            return
        try:
            lengths = self.headers.get_all('Content-Length', [])
            authorizations = self.headers.get_all('Authorization', [])
            require(len(lengths) == 1 and token(lengths[0], r'[1-9][0-9]{0,5}')
                    and int(lengths[0]) <= MAX_REQUEST and not self.headers.get_all('Transfer-Encoding')
                    and not self.headers.get_all('Content-Encoding') and len(authorizations) <= 1
                    and self.headers.get('Content-Type') == 'application/json',
                    400, 'ANALYSIS_REQUEST_ENVELOPE_INVALID')
            try:
                body = self.rfile.read(int(lengths[0]))
            except TimeoutError as exc:
                raise Denied(408, 'ANALYSIS_REQUEST_TIMEOUT') from exc
            require(len(body) == int(lengths[0]), 400, 'ANALYSIS_REQUEST_ENVELOPE_INVALID')
            self.run_action(action, body, peer, authorizations[0] if authorizations else None)
        except Denied as error:
            self.reject(action, error)
        finally:
            if slot:
                slot.release()

    def run_action(self, action, body, peer, bearer):
        try:
            status, result, headers = self.server.api.handle(action, body, peer, bearer)
        except Denied as error:
            self.problem(error)
            return
        self.reply(status, result, headers)

    def reject(self, action, error):
        self.server.api.record_event(dict(action=action, correlationId=str(uuid.uuid4())), 'DENIED', error.code)
        self.problem(error)


def positive_int(config, field, lower, upper):
    value = config[field]
    if type(value) is not int or not lower <= value <= upper:
        raise ValueError(f'invalid {field}')
    return value


def application(config):
    fields = ('contract installationId issuer audience workload startKeyEnv bindingKeyEnv '
              'semanticReadKeyEnv semanticDiscoveryKeyEnv authorization rights mcpState semantic clockSkewMs '
              'timeoutSeconds readinessSeconds maxResultBytes dispatchCapacity listen')
    if not (exact(config, fields) or exact(config, fields + ' store')) or config['contract'] != 'ouf.analysis.batch.installation.v2':
        raise ValueError('closed installation profile required')
    if not all(identity_value(config[k]) for k in ('installationId', 'issuer', 'audience', 'workload')):
        raise ValueError('installation identities required')
    names = [config[k] for k in ('startKeyEnv', 'bindingKeyEnv', 'semanticReadKeyEnv', 'semanticDiscoveryKeyEnv')]
    if not all(token(name, r'[A-Z][A-Z0-9_]{0,127}') for name in names):
        raise ValueError('signing keys must be supplied through installation environment references')
    keys = [signing_key(os.environ[name]) for name in names]
    if len(set(keys)) != len(keys):
        raise ValueError('signing keys must be independent')
    listener = config['listen']
    if (not exact(listener, 'host port caFile certFile keyFile mcpCertSha256 humanRelayCertSha256')
            or not identity_value(listener['host']) or not hash_ref(listener['mcpCertSha256'])
            or not hash_ref(listener['humanRelayCertSha256']) or listener['mcpCertSha256'] == listener['humanRelayCertSha256']):
        raise ValueError('distinct pinned MCP and HUMAN relay certificates required')
    port = positive_int(listener, 'port', 1, 65535)
    timeout = positive_int(config, 'timeoutSeconds', 1, 10)
    capacity = positive_int(config, 'dispatchCapacity', 1, 64)
    settings = SimpleNamespace(installation=config['installationId'],
                               issuer=config['issuer'], audience=config['audience'], workload=config['workload'],
                               start_key=keys[0], binding_key=keys[1],
                               owner_keys={'read': keys[2], 'discovery': keys[3]},
                               max_result_bytes=positive_int(config, 'maxResultBytes', 1, 264192))
    audit = BatchMandateAudit(config['store'], settings.installation) if 'store' in config else None
    api = BatchMandates(settings, audit, Authorization(config['authorization'], timeout),
                        HTTPS(config['rights'], timeout), HTTPS(config['mcpState'], timeout),
                        HTTPS(config['semantic'], timeout, origin=True),
                        Clock(positive_int(config, 'clockSkewMs', 100, 10_000)))
    server = Listener((listener['host'], port), api, tls_context(listener, server=True),
                      {listener['mcpCertSha256']: 'mcp', listener['humanRelayCertSha256']: 'human'}, timeout, capacity)
    return server, positive_int(config, 'readinessSeconds', 1, 300)


def monitor_readiness(server, interval, stop):
    paused = False
    while not stop.is_set():
        try:
            api = server.api
            api.authorization.reachable()
            api.clock.evidence(api.receipt_context, dict(action='clock', installation=api.config.installation))
        except (Denied, OSError):
            if not paused:
                LOG.warning('ANALYSIS_DEPENDENCY_READINESS_UNVERIFIED')
            paused = True
            server.ready_until = 0
        else:
            paused = False
            server.ready_until = api.clock.monotonic() + 2000 * interval
        stop.wait(interval)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', type=Path, required=True)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    server, interval = application(parse(args.profile.read_bytes()))
    stop = threading.Event()
    thread = threading.Thread(target=monitor_readiness, args=(server, interval, stop), daemon=True)
    with server:
        thread.start()
        try:
            server.serve_forever()
        finally:
            stop.set()
            thread.join()


if __name__ == '__main__':
    main()
