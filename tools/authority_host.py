"""Closed HTTPS host for the two private Gateway WSGI factories."""
import ipaddress
import os
from pathlib import Path
import re
import ssl
import sys

from tools.analysis_protocol import CAPACITY_FIELDS, Rejected, capacity_profile, opaque, parse

CONFIG_FILES = {'authority': 'OUF_ANALYSIS_CONFIG', 'iam-adapter': 'OUF_KEYCLOAK_DECISIONS_CONFIG'}


class HostError(ValueError):
    """Contains only static diagnostics and public configuration field names."""


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
        raise HostError(f'{CONFIG_FILES[command]} unreadable or invalid') from None
    if command == 'authority':
        try:
            capacity = capacity_profile(fields.get('capacity', {}))
        except ValueError:
            raise HostError('AUTHORITY_HOSTING_MISMATCH: invalid capacity') from None
        if (workers, threads, total) != tuple(capacity[k] for k in ('processes', 'threadsPerProcess', 'instanceConnections')):
            raise HostError('AUTHORITY_HOSTING_MISMATCH')
    # Gunicorn applies the same worker_connections limit to each gthread worker.
    if total % workers:
        raise HostError('AUTHORITY_HOSTING_MISMATCH: connections must divide evenly among processes')
    return dict(bind=[listener(env)], workers=workers, threads=threads, worker_connections=total // workers)


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


def run(command, env):
    settings = hosting(command, env)
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
            try:
                if command == 'authority':
                    from tools.analysis_service import application
                else:
                    from tools.iam_keycloak_decisions import application
                return authenticated(application(), field)
            except Exception:
                print(f'{CONFIG_FILES[command]}: factory initialization failed', file=sys.stderr)
                raise RuntimeError('Gateway factory initialization failed') from None

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
