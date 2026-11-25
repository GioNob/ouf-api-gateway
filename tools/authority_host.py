"""Closed HTTPS host for the two private Gateway WSGI factories."""
from contextlib import closing
import ipaddress
import os
from pathlib import Path
import re
import sqlite3
import ssl
import stat
import sys

from tools.analysis_protocol import CAPACITY_FIELDS, Rejected, capacity_profile, matches, opaque, parse

CONFIG_FILES = {'authority': 'OUF_ANALYSIS_CONFIG', 'iam-adapter': 'OUF_KEYCLOAK_DECISIONS_CONFIG'}
CREDENTIAL_MAX_BYTES = 4096


class HostError(ValueError):
    """Contains only static diagnostics and public configuration field names."""


def credential(cfg, file_key, env_key, *, reference=None):
    if (file_key in cfg) == (env_key in cfg):
        raise ValueError(f'exactly one of {file_key} and {env_key} required')
    key = file_key if file_key in cfg else env_key
    source = cfg[key]
    if reference is not None and isinstance(source, dict):
        source = source.get(reference)
    if key == env_key and matches(source, '[A-Z][A-Z0-9_]{0,127}'):
        return os.environ[source]
    if key == file_key and isinstance(source, str) and source:
        try:
            def nonblocking(path, flags):
                return os.open(path, flags | getattr(os, 'O_NONBLOCK', 0))

            with open(source, 'rb', opener=nonblocking) as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_size > CREDENTIAL_MAX_BYTES:
                    raise ValueError()
                raw = stream.read(CREDENTIAL_MAX_BYTES + 1)
            if len(raw) > CREDENTIAL_MAX_BYTES:
                raise ValueError()
            value = raw.decode('utf-8')
        except (OSError, ValueError):
            raise ValueError(f'invalid {file_key}') from None
        if value.endswith('\n'):
            value = value[:-1].removesuffix('\r')
        if value and not any(c in value for c in '\r\n\x00'):
            return value
    raise ValueError(f'invalid {key}')


def required(env, name):
    value = env.get(name)
    if not value:
        raise HostError(f'{name} required')
    return value


def number(env, name, maximum):
    value = required(env, name)
    if not re.fullmatch('[1-9][0-9]{0,4}', value) or int(value) > maximum:
        raise HostError(f'{name} outside supported range')
    return int(value)


def listener(env):
    address = required(env, 'OUF_HOST_ADDRESS')
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        label = r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
        if len(address) > 253 or not all(re.fullmatch(label, part) for part in address.split('.')):
            raise HostError('OUF_HOST_ADDRESS invalid') from None
    else:
        if '%' in address:
            raise HostError('OUF_HOST_ADDRESS invalid')
        if ip.version == 6:
            address = f'[{address}]'
    port = number(env, 'OUF_HOST_PORT', 65535)
    return f'{address}:{port}'


def hosting(command, env):
    config = Path(required(env, CONFIG_FILES[command]))
    workers = number(env, 'OUF_HOST_PROCESSES', CAPACITY_FIELDS['processes'][2])
    threads = number(env, 'OUF_HOST_THREADS', CAPACITY_FIELDS['threadsPerProcess'][2])
    total = number(env, 'OUF_HOST_CONNECTIONS', CAPACITY_FIELDS['instanceConnections'][2])
    try:
        fields = parse(config.read_bytes())
        if not isinstance(fields, dict):
            raise ValueError()
    except (OSError, ValueError, Rejected):
        fields = None  # Only the unavailable response can be served on this listener.
    probe = env.get('OUF_HOST_PROBE_PRINCIPAL')
    if command == 'iam-adapter' and fields is not None and probe is not None and probe == fields.get('gatewayTlsPrincipal'):
        raise HostError('OUF_HOST_PROBE_PRINCIPAL must differ from gatewayTlsPrincipal')
    if command == 'authority' and fields is not None:
        try:
            capacity = capacity_profile(fields.get('capacity', {}))
        except ValueError:
            raise HostError('AUTHORITY_HOSTING_MISMATCH: invalid capacity') from None
        if (workers, threads, total) != tuple(capacity[k] for k in ('processes', 'threadsPerProcess', 'instanceConnections')):
            raise HostError('AUTHORITY_HOSTING_MISMATCH')
    # Gunicorn applies the same worker_connections limit to each gthread worker.
    if total % workers:
        raise HostError('AUTHORITY_HOSTING_MISMATCH: connections must divide evenly among processes')
    return dict(bind=[listener(env)], workers=workers, threads=threads, worker_connections=total // workers), fields


def tls_settings(command, env):
    cert = required(env, 'OUF_HOST_CERT_FILE')
    key = required(env, 'OUF_HOST_KEY_FILE')
    ca = env.get('OUF_HOST_CLIENT_CA_FILE')
    if command == 'iam-adapter' or ca is not None:
        ca = required(env, 'OUF_HOST_CLIENT_CA_FILE')
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols(['http/1.1'])
    try:
        context.load_cert_chain(cert, key, password=lambda: b'')
    except (OSError, ValueError):
        raise HostError('OUF_HOST_CERT_FILE or OUF_HOST_KEY_FILE invalid') from None
    if ca:
        try:
            context.load_verify_locations(cafile=ca)
        except (OSError, ValueError):
            raise HostError('OUF_HOST_CLIENT_CA_FILE invalid') from None
        context.verify_mode = ssl.CERT_REQUIRED

    def ssl_context(config, default_factory):
        return context

    return dict(certfile=cert, keyfile=key, ca_certs=ca, cert_reqs=context.verify_mode, ssl_context=ssl_context)


def peer_identity(sock, field):
    if not isinstance(sock, ssl.SSLSocket) or not sock.server_side or sock.context.verify_mode != ssl.CERT_REQUIRED:
        return None
    try:
        cert = sock.getpeercert()
    except (OSError, ValueError):
        return None
    if not cert:
        return None
    if field == 'subject-cn':
        names = [v for rdn in cert.get('subject', ()) for k, v in rdn if k == 'commonName']
    else:
        names = [v for k, v in cert.get('subjectAltName', ()) if k == 'URI']
    if len(names) == 1 and opaque(names[0]):
        return names[0]
    return None


def authenticated(app, field):
    def serve(env, start_response):
        for name in ('REMOTE_USER', 'SSL_CLIENT_VERIFY', 'HTTP_REMOTE_USER', 'HTTP_SSL_CLIENT_VERIFY'):
            env.pop(name, None)
        principal = peer_identity(env.get('gunicorn.socket'), field)
        if principal is not None:
            env.update(REMOTE_USER=principal, SSL_CLIENT_VERIFY='SUCCESS')
        return app(env, start_response)
    return serve


def store_ready(command, uri):
    try:
        with closing(sqlite3.connect(uri, uri=True, isolation_level=None, timeout=0)) as db:
            db.execute('begin immediate')
            if command == 'authority':
                db.execute("insert into analysis_mandate_v1 (id,scope,plan,record) values ('readiness','','',X'')")
            else:
                db.execute("insert into keycloak_rate_v1 (kind,until_epoch,used) values ('readiness',0,0)")
            db.execute('rollback')
        return True
    except sqlite3.Error:
        return False


def worker_application(command, fields, *, mtls, probe_principal):
    from tools.analysis_service import application as authority
    from tools.iam_keycloak_decisions import application as adapter

    app = None
    if fields is not None:
        try:
            app = (authority if command == 'authority' else adapter)(fields)
            store_uri = Path(fields['store']).resolve().as_uri() + '?mode=rw'
        except Exception:
            # Factory diagnostics can quote credentials. Keep this worker fail-closed.
            print(f'{CONFIG_FILES[command]}: factory initialization failed', file=sys.stderr)
            app = None

    def serve(env, start_response):
        status = '503 Service Unavailable'
        if env.get('PATH_INFO') == '/health/ready' and env.get('REQUEST_METHOD') == 'GET':
            if env.get('QUERY_STRING'):
                status = '400 Bad Request'
            elif mtls and not opaque(probe_principal):
                pass  # No trusted probe configured for this listener.
            elif mtls and (env.get('SSL_CLIENT_VERIFY') != 'SUCCESS' or env.get('REMOTE_USER') != probe_principal):
                status = '403 Forbidden'
            elif app is not None and store_ready(command, store_uri):
                status = '204 No Content'
        elif app is not None:
            return app(env, start_response)
        start_response(status, [('Cache-Control', 'no-store')])
        return [b'']

    return serve


def run(command, env):
    settings, fields = hosting(command, env)
    settings.update(tls_settings(command, env))
    field = env.get('OUF_HOST_IDENTITY_FIELD', 'subject-cn')
    if field not in ('subject-cn', 'san-uri'):
        raise HostError('OUF_HOST_IDENTITY_FIELD invalid')

    from gunicorn.app.base import BaseApplication
    from gunicorn.glogging import Logger

    class HostLogger(Logger):
        # Parser errors and exception traces may quote raw request material.
        def critical(self, msg, *args, **kwargs):
            super().critical('Gateway HTTPS host failure')

    class Host(BaseApplication):
        def load_config(self):
            options = dict(worker_class='gthread', worker_tmp_dir='/tmp', accesslog=None,
                           loglevel='critical', logger_class=HostLogger, forwarded_allow_ips='',
                           forwarder_headers='', secure_scheme_headers={}, **settings)
            for key, value in options.items():
                self.cfg.set(key, value)

        def load(self):
            # Gunicorn calls load after fork: each process owns its own admission pools.
            app = worker_application(command, fields, mtls=settings['cert_reqs'] == ssl.CERT_REQUIRED,
                                     probe_principal=env.get('OUF_HOST_PROBE_PRINCIPAL'))
            return authenticated(app, field)

    Host().run()


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1 or args[0] not in CONFIG_FILES:
        print('expected one command: authority | iam-adapter', file=sys.stderr)
        return 2
    try:
        run(args[0], os.environ)
    except HostError as exc:
        print(exc, file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
