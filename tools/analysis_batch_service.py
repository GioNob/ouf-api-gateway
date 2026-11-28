"""Private HTTPS listener for the Gateway's opt-in D-104 runtime."""
import argparse
import http.client
import logging
import os
import socket
import sqlite3
import ssl
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

from tools.analysis_batch_mandate import BatchMandates, Clock, UNAVAILABLE
from tools.analysis_batch_protocol import (
    Denied, MAX_REQUEST, OPERATIONS, digest, exact, hash_ref, identity_value, parse, require,
    signing_key, token, wire,
)
from tools.analysis_batch_store import BatchMandateStore

BASE = '/internal/analysis-batch/v1/'
LOG = logging.getLogger(__name__)
ROUTES = {BASE + action: action for action in ('prepare', 'issue', 'dispatch', 'expire', 'revoke')}


class HTTPS:
    def __init__(self, config, timeout, *, origin=False):
        if not exact(config, 'url caFile certFile keyFile'):
            raise ValueError('explicit HTTPS trust and client certificate required')
        url = urlsplit(config['url'])
        if (url.scheme != 'https' or not url.hostname or url.username is not None or url.password is not None
                or url.query or url.fragment or url.path.startswith('//') or (origin and url.path not in ('', '/'))):
            raise ValueError('invalid configured HTTPS destination')
        self.host, self.port, self.path = url.hostname, url.port, url.path
        self.timeout = timeout
        self.context = tls_context(config, server=False)

    def post(self, path, body, headers, limit, failure):
        connection = http.client.HTTPSConnection(self.host, self.port, timeout=self.timeout, context=self.context)
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
                require(len(data) <= limit and time.monotonic() - started < self.timeout
                        and not 300 <= response.status < 400, 503, failure)
                safe = {}
                retry = response.getheader('Retry-After')
                if token(retry, r'(?:[0-9]{1,9}|[A-Za-z0-9, :]{10,40})'):
                    safe['Retry-After'] = retry
                return response.status, data, safe
        except (OSError, http.client.HTTPException) as exc:
            raise Denied(503, failure) from exc
        finally:
            if timer is not None:
                timer.cancel()
            connection.close()

    def evidence(self, body, bearer=None):
        headers = {'Content-Type': 'application/json', 'Cache-Control': 'no-store'}
        if bearer is not None:
            headers['Authorization'] = bearer
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
        self.sweep_ready_until = 0

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
        if headers and 'Retry-After' in headers:
            self.send_header('Retry-After', headers['Retry-After'])
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
                now = clock.checked()
                ready = clock.monotonic() < self.server.sweep_ready_until and self.server.api.store.check(now)
            except (sqlite3.Error, Denied):
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
        self.server.api.denial(dict(action=action, record=None, actor=None, operation=None,
                                    correlation=str(uuid.uuid4())), error)
        self.problem(error)


def positive_int(config, field, lower, upper):
    value = config[field]
    if type(value) is not int or not lower <= value <= upper:
        raise ValueError(f'invalid {field}')
    return value


def application(config):
    fields = ('contract installationId storageEpoch store issuer audience workload thsClient startKeyEnv '
              'semanticReadKeyEnv semanticDiscoveryKeyEnv rights mcpState semantic clockSkewMs '
              'timeoutSeconds sweepSeconds maxResultBytes dispatchCapacity ratePerMinute listen')
    if not exact(config, fields) or config['contract'] != 'ouf.analysis.batch.installation.v1':
        raise ValueError('closed installation profile required')
    if not all(identity_value(config[k]) for k in ('installationId', 'issuer', 'audience', 'workload', 'thsClient')):
        raise ValueError('installation identities required')
    if not hash_ref(config['storageEpoch']):
        raise ValueError('storage epoch required')
    rates = config['ratePerMinute']
    if (not isinstance(rates, dict) or rates.keys() != OPERATIONS.keys()
            or not all(type(v) is int and 0 < v <= 100_000 for v in rates.values())):
        raise ValueError('an installation rate limit per operation is required')
    names = [config[k] for k in ('startKeyEnv', 'semanticReadKeyEnv', 'semanticDiscoveryKeyEnv')]
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
    settings = SimpleNamespace(installation=config['installationId'], storage_epoch=config['storageEpoch'],
                               issuer=config['issuer'], audience=config['audience'], workload=config['workload'],
                               ths_client=config['thsClient'], start_key=keys[0], rates=rates,
                               owner_keys={'read': keys[1], 'discovery': keys[2]},
                               max_result_bytes=positive_int(config, 'maxResultBytes', 1, 264192))
    store = BatchMandateStore(config['store'], settings.installation, settings.storage_epoch, initialize=False)
    api = BatchMandates(settings, store, HTTPS(config['rights'], timeout), HTTPS(config['mcpState'], timeout),
                        HTTPS(config['semantic'], timeout, origin=True),
                        Clock(positive_int(config, 'clockSkewMs', 100, 10_000)))
    server = Listener((listener['host'], port), api, tls_context(listener, server=True),
                      {listener['mcpCertSha256']: 'mcp', listener['humanRelayCertSha256']: 'human'}, timeout, capacity)
    return server, positive_int(config, 'sweepSeconds', 1, 300)


def sweep(server, interval, stop):
    paused = False
    while not stop.is_set():
        try:
            server.api.sweep()
        except (Denied, sqlite3.Error):
            if not paused:
                LOG.warning('ANALYSIS_EXPIRATION_SWEEP_PAUSED')
            paused = True
            server.sweep_ready_until = 0
        else:
            paused = False
            server.sweep_ready_until = server.api.clock.monotonic() + 2000 * interval
        stop.wait(interval)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', type=Path, required=True)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    server, interval = application(parse(args.profile.read_bytes()))
    stop = threading.Event()
    thread = threading.Thread(target=sweep, args=(server, interval, stop), daemon=True)
    with server:
        thread.start()
        try:
            server.serve_forever()
        finally:
            stop.set()
            thread.join()


if __name__ == '__main__':
    main()
