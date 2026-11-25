"""GW-58I offline qualification for the two private installation roles."""
from contextlib import closing, redirect_stderr
import hashlib
import io
import json
from pathlib import Path
import sqlite3
import ssl
import tempfile
import unittest
from unittest.mock import Mock, patch

from deploy.authority.image_manifest import publish
from deploy.authority.smoke_config import generate
from tools.authority_host import credential, worker_application


class InstallableTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)

    def test_gw_58i_01_package(self):
        """GW-58I-01. The generic consumer expects exactly three top-level members."""
        archive = b'synthetic compressed image bytes'
        (self.root / 'image.tar.gz').write_bytes(archive)
        commit, tree, image_id = 'a' * 40, 'b' * 40, 'sha256:' + 'c' * 64
        checksum = hashlib.sha256(archive).hexdigest()
        publish(self.root, repository='fixture/gateway', source_commit=commit, tested_commit=commit,
                tree=tree, run_id='12', attempt='2', image_id=image_id)
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ['SHA256SUMS', 'image.tar.gz', 'manifest.json'])
        self.assertEqual((self.root / 'SHA256SUMS').read_bytes(), f'{checksum}  image.tar.gz\n'.encode())
        self.assertEqual(json.loads((self.root / 'manifest.json').read_bytes()), dict(
            schema='ouf.gateway-authority-tested-image.v1', repository='fixture/gateway',
            reviewedSourceCommit=commit, testedCommit=commit, testedTree=tree, workflowRunId='12',
            workflowRunAttempt='2', imageRevisionLabel=commit, imageTag='gateway-authority:' + commit,
            imageId=image_id, archiveName='image.tar.gz', archiveBytes=len(archive), archiveSha256=checksum))

    def test_gw_58i_02_file_credentials(self):
        """GW-58I-02. Preserve credential bytes apart from the optional line terminator."""
        path = self.root / 'fixture'
        path.write_bytes(b' fixture \r\n')
        for file_key, env_key in [('delegationKeyFile', 'delegationKeyEnv'), ('secretFile', 'secretEnv')]:
            config = {file_key: str(path)}
            self.assertEqual(credential(config, file_key, env_key), ' fixture ')
            for invalid in ({}, {**config, env_key: 'FIXTURE'}, {file_key: ''}, {file_key: str(self.root / 'absent')}):
                with self.assertRaises(ValueError):
                    credential(invalid, file_key, env_key)
        ref = 'fixture/assignment'
        mapped = {'secretFile': {ref: str(path)}}
        self.assertEqual(credential(mapped, 'secretFile', 'secretEnv', reference=ref), ' fixture ')
        with self.assertRaises(ValueError):
            credential(mapped, 'secretFile', 'secretEnv', reference='other')
        for data in (b'', b'\xff', b'two\nlines', b'a\x00b', b'bare\r'):
            path.write_bytes(data)
            with self.assertRaises(ValueError):
                credential(mapped, 'secretFile', 'secretEnv', reference=ref)

    def configurations(self):
        for name in ('config', 'authority-store', 'iam-store'):
            (self.root / name).mkdir()
        generate(self.root)
        cfg = self.root / 'config'
        authority = json.loads((cfg / 'authority.json').read_bytes())
        adapter = json.loads((cfg / 'iam.json').read_bytes())
        key, secret = self.root / 'key', self.root / 'secret'
        key.write_bytes(b'ab' * 32)
        secret.write_bytes(b'fixture-secret')
        authority.update(store=str(self.root / 'authority-store/gateway.db'), delegationKeyFile=str(key),
                         manifestFile='contracts/mcp-capabilities.json')
        adapter.update(store=str(self.root / 'iam-store/iam.db'), secretFile=str(secret), profileFile=str(cfg / 'profile.json'))
        return [('authority', authority, key), ('iam-adapter', adapter, secret)]

    @staticmethod
    def request(app, **extra):
        env = dict(PATH_INFO='/health/ready', REQUEST_METHOD='GET', REMOTE_USER='probe', SSL_CLIENT_VERIFY='SUCCESS')
        response = Mock()
        body = b''.join(app({**env, **extra}, response))
        return response.call_args.args[0], body

    def test_gw_58i_03_readiness(self):
        """GW-58I-03. Probe the live local store and release every write lock."""
        for command, config, secret in self.configurations():
            mtls = command == 'iam-adapter'
            with self.subTest(command=command), patch('tools.analysis_service.https_endpoint', return_value=Mock(path='/')), \
                    patch('tools.analysis_service.Catalog'), \
                    patch('ssl.create_default_context', return_value=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)), \
                    patch('tools.analysis_clients.Endpoint.request', side_effect=AssertionError('peer called')):
                app = worker_application(command, config, mtls=mtls, probe_principal='probe')
                secret.unlink()  # Loaded once for this worker generation.
                self.assertEqual(self.request(app), ('204 No Content', b''))
                if mtls:
                    self.assertEqual(self.request(app, REMOTE_USER='gateway'), ('403 Forbidden', b''))
                    self.assertEqual(self.request(app, SSL_CLIENT_VERIFY='FAILURE'), ('403 Forbidden', b''))
                with closing(sqlite3.connect(config['store'], timeout=0)) as db:
                    db.execute('begin immediate')
                    self.assertEqual(self.request(app), ('503 Service Unavailable', b''))
                    db.rollback()
                    self.assertEqual(self.request(app), ('204 No Content', b''))
                    # A connection may accept BEGIN IMMEDIATE but still prohibit writes.
                    connect = sqlite3.connect

                    def query_only(*args, **kwargs):
                        conn = connect(*args, **kwargs)
                        conn.execute('pragma query_only=on')
                        return conn

                    with patch('sqlite3.connect', side_effect=query_only):
                        self.assertEqual(self.request(app), ('503 Service Unavailable', b''))
                Path(config['store']).unlink()
                self.assertEqual(self.request(app), ('503 Service Unavailable', b''))
                self.assertFalse(Path(config['store']).exists())

    def test_gw_58i_04_invalid_configuration(self):
        """GW-58I-04. A failed factory exposes no business service or private diagnostic."""
        for command, config, secret in self.configurations():
            secret.write_bytes(b'invalid\nprivate-fixture')
            with self.subTest(command=command), redirect_stderr(io.StringIO()) as logs:
                app = worker_application(command, config, mtls=command == 'iam-adapter', probe_principal='probe')
                self.assertEqual(self.request(app), ('503 Service Unavailable', b''))
                self.assertEqual(self.request(app, PATH_INFO='/decisions'), ('503 Service Unavailable', b''))
                self.assertNotIn('private-fixture', logs.getvalue())
                if command == 'iam-adapter':
                    self.assertEqual(self.request(app, REMOTE_USER='other'), ('403 Forbidden', b''))
