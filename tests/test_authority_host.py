"""Offline GW-58D hosting qualification. The CI smoke exercises the same boundary on TLS."""
from contextlib import redirect_stderr
from io import StringIO
import json
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from tools import authority_host as host


class AuthorityHostTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.config = Path(tmp.name) / 'config.json'
        self.config.write_text('{}', encoding='utf-8')
        self.env = dict(OUF_HOST_ADDRESS='localhost', OUF_HOST_PORT='8443', OUF_HOST_PROCESSES='1',
                        OUF_HOST_THREADS='8', OUF_HOST_CONNECTIONS='8', OUF_ANALYSIS_CONFIG=str(self.config),
                        OUF_KEYCLOAK_DECISIONS_CONFIG=str(self.config))

    def test_gw_58d_01_required_and_validated_inputs(self):
        """GW-58D-01. Only one bounded TCP listener; errors identify the field."""
        for name in ('OUF_HOST_ADDRESS', 'OUF_HOST_PORT', 'OUF_HOST_PROCESSES', 'OUF_HOST_THREADS',
                     'OUF_HOST_CONNECTIONS', 'OUF_ANALYSIS_CONFIG'):
            with self.subTest(name=name), self.assertRaisesRegex(host.HostError, name):
                host.hosting('authority', {k: v for k, v in self.env.items() if k != name})
        for name, value in [('OUF_HOST_ADDRESS', 'unix:/tmp/socket'), ('OUF_HOST_ADDRESS', 'x,y'),
                            ('OUF_HOST_PORT', '65536'), ('OUF_HOST_PORT', '0'), ('OUF_HOST_THREADS', '-1'),
                            ('OUF_HOST_PROCESSES', '65'), ('OUF_HOST_CONNECTIONS', '32769')]:
            with self.subTest(name=name), self.assertRaisesRegex(host.HostError, name):
                host.hosting('iam-adapter', {**self.env, name: value})
        self.assertEqual(host.listener({**self.env, 'OUF_HOST_ADDRESS': '::1'}), '[::1]:8443')
        self.config.write_text('invalid', encoding='utf-8')
        self.assertIsNone(host.hosting('iam-adapter', self.env)[1])

    def test_gw_58d_02_effective_gthread_capacity(self):
        """GW-58D-02. Match all three limits including defaults and per-worker connections."""
        self.assertEqual(host.hosting('authority', self.env)[0]['worker_connections'], 8)
        profile = dict(processes=2, threadsPerProcess=12, instanceConnections=24)
        self.config.write_text(json.dumps({'capacity': profile}), encoding='utf-8')
        env = {**self.env, 'OUF_HOST_PROCESSES': '2', 'OUF_HOST_THREADS': '12', 'OUF_HOST_CONNECTIONS': '24'}
        self.assertEqual(host.hosting('authority', env)[0],
                         dict(bind=['localhost:8443'], workers=2, threads=12, worker_connections=12))
        for name, wrong in [('OUF_HOST_PROCESSES', '1'), ('OUF_HOST_THREADS', '11'), ('OUF_HOST_CONNECTIONS', '12')]:
            with self.subTest(name=name), self.assertRaisesRegex(host.HostError, 'AUTHORITY_HOSTING_MISMATCH'):
                host.hosting('authority', {**env, name: wrong})
        profile['instanceConnections'] = 25
        self.config.write_text(json.dumps({'capacity': profile}), encoding='utf-8')
        with self.assertRaisesRegex(host.HostError, 'AUTHORITY_HOSTING_MISMATCH'):
            host.hosting('authority', {**env, 'OUF_HOST_CONNECTIONS': '25'})

    def test_gw_58d_03_tls_policy(self):
        """GW-58D-03. Validate material before bind and require client trust for IAM."""
        paths = dict(OUF_HOST_CERT_FILE='cert', OUF_HOST_KEY_FILE='key')
        with self.assertRaisesRegex(host.HostError, 'OUF_HOST_CLIENT_CA_FILE'):
            host.tls_settings('iam-adapter', paths)
        with self.assertRaisesRegex(host.HostError, 'OUF_HOST_CERT_FILE'):
            host.tls_settings('authority', paths)
        for command, ca, mode in [('authority', {}, ssl.CERT_NONE),
                                  ('authority', {'OUF_HOST_CLIENT_CA_FILE': 'ca'}, ssl.CERT_REQUIRED),
                                  ('iam-adapter', {'OUF_HOST_CLIENT_CA_FILE': 'ca'}, ssl.CERT_REQUIRED)]:
            with patch.object(ssl.SSLContext, 'load_cert_chain'), patch.object(ssl.SSLContext, 'load_verify_locations'):
                options = host.tls_settings(command, {**paths, **ca})
            ctx = options['ssl_context'](None, None)
            self.assertEqual(ctx.minimum_version, ssl.TLSVersion.TLSv1_3)
            self.assertEqual(ctx.verify_mode, mode)
            self.assertEqual(options['cert_reqs'], mode)

    def test_gw_58d_04_peer_identity(self):
        """GW-58D-04. Take a unique verified CN or URI SAN and erase incoming identity."""
        peer = Mock(spec=ssl.SSLSocket)
        peer.server_side = True
        peer.context.verify_mode = ssl.CERT_REQUIRED
        cert = {'subject': ((('commonName', 'gateway'),),), 'subjectAltName': (('URI', 'urn:ouf:gateway'),)}
        peer.getpeercert.return_value = cert

        def result(sock, field='subject-cn'):
            env = dict.fromkeys(('REMOTE_USER', 'SSL_CLIENT_VERIFY', 'HTTP_REMOTE_USER', 'HTTP_SSL_CLIENT_VERIFY'), 'bogus')
            env['gunicorn.socket'] = sock
            host.authenticated(lambda actual, _: actual, field)(env, None)
            self.assertNotIn('HTTP_REMOTE_USER', env)
            self.assertNotIn('HTTP_SSL_CLIENT_VERIFY', env)
            return (env.get('REMOTE_USER'), env.get('SSL_CLIENT_VERIFY'))

        self.assertEqual(result(peer), ('gateway', 'SUCCESS'))
        self.assertEqual(result(peer, 'san-uri'), ('urn:ouf:gateway', 'SUCCESS'))
        self.assertEqual(result(None), (None, None))
        peer.server_side = False
        self.assertEqual(result(peer), (None, None))
        peer.server_side = True
        peer.context.verify_mode = ssl.CERT_NONE
        self.assertEqual(result(peer), (None, None))
        peer.context.verify_mode = ssl.CERT_REQUIRED
        for unproven in ({}, {'subject': cert['subject'] * 2}, {'subjectAltName': cert['subjectAltName']}):
            peer.getpeercert.return_value = unproven
            self.assertEqual(result(peer), (None, None))

    def test_gw_58d_05_closed_entrypoint(self):
        """GW-58D-05. Reject arbitrary commands and extra arguments before reading config."""
        for args in ([], ['unknown'], ['authority', '--help'], ['iam-adapter', 'extra']):
            with redirect_stderr(StringIO()) as errors:
                self.assertEqual(host.main(args), 2)
            self.assertNotIn('unknown', errors.getvalue())
        process = subprocess.run([sys.executable, '-m', 'tools.authority_host', 'unknown'], capture_output=True)
        self.assertEqual(process.returncode, 2)
        self.assertIn(b'expected one command', process.stderr)
