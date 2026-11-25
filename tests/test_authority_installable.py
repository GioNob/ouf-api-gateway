"""GW-58I offline qualification for the two private installation roles."""
from contextlib import closing, redirect_stderr
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from deploy.authority.image_manifest import publish
from deploy.authority.smoke_config import generate
from tools import analysis_schema
from tools.analysis_store import MandateStore
from tools.authority_host import credential, main, store_ready, worker_application
from tools.iam_keycloak_decisions import VerifierStore


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

    def test_gw_58ib_01_reversible_insert(self):
        """GW-58IB-01. Both probes must insert a row and roll it back."""
        for command, config, _ in self.configurations():
            if command == 'authority':
                MandateStore(config['store'])
                table = 'analysis_mandate_v1'
                seed = "('existing','scope','plan',X'01')"
            else:
                VerifierStore(config['store'])
                table = 'keycloak_rate_v1'
                seed = "('decisions',9,8)"
            uri = Path(config['store']).as_uri() + '?mode=rw'
            with self.subTest(command=command), closing(sqlite3.connect(config['store'], isolation_level=None)) as db:
                db.execute(f'insert into {table} values {seed}')
                rows = db.execute(f'select * from {table}').fetchall()
                db.execute(f"""create trigger detect_insert after insert on {table}
                               begin select raise(abort, 'probe insert'); end""")
                self.assertFalse(store_ready(command, uri))
                db.execute('drop trigger detect_insert')
                self.assertTrue(store_ready(command, uri))
                self.assertEqual(db.execute(f'select * from {table}').fetchall(), rows)

    @staticmethod
    def boot_worker(command, config):
        with patch('tools.analysis_service.https_endpoint', return_value=Mock(path='/')), \
                patch('tools.analysis_service.Catalog'), \
                patch('ssl.create_default_context', return_value=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)):
            return worker_application(command, config, mtls=command == 'iam-adapter', probe_principal='probe')

    def test_gw_58ie_01_release_during_backoff(self):
        """GW-58IE-01 / GW-58IB-02. A reader blocking schema installation releases before the final attempt."""
        for command, config, _ in self.configurations():
            with self.subTest(command=command), closing(sqlite3.connect(config['store'])) as reader, \
                    patch.dict(os.environ, OUF_SCHEMA_MAX_ATTEMPTS='3', OUF_SCHEMA_INITIAL_DELAY_MS='500'), \
                    patch('tools.analysis_schema.time.sleep') as sleep:
                reader.execute('pragma journal_mode=delete')
                reader.execute('begin')
                reader.execute('select count(*) from sqlite_master').fetchone()

                def release_on_second_wait(seconds):
                    if sleep.call_count == 2:
                        reader.rollback()

                sleep.side_effect = release_on_second_wait
                app = self.boot_worker(command, config)
                self.assertEqual(self.request(app), ('204 No Content', b''))
                self.assertEqual(sleep.call_count, 2)
                for call, base in zip(sleep.call_args_list, (0.5, 1.0)):
                    self.assertGreaterEqual(call.args[0], base)
                    self.assertLessEqual(call.args[0], base * 1.2)
                path = Path(config['store'])
                self.assertEqual(list(path.parent.iterdir()), [path])

    def test_gw_58ie_02_exhaustion_and_restart(self):
        """GW-58IE-02. An exhausted worker serves 503. A replacement gets its own attempts."""
        restart = """from tests.test_authority_installable import InstallableTests as T
from tools import analysis_schema
from unittest.mock import patch
import json, sys
with patch.object(analysis_schema, '_install', wraps=analysis_schema._install) as install:
    print(T.request(T.boot_worker(sys.argv[1], json.loads(sys.argv[2])))[0], install.call_count)
"""
        for command, config, _ in self.configurations():
            with self.subTest(command=command), closing(sqlite3.connect(config['store'])) as writer, \
                    patch.dict(os.environ, OUF_SCHEMA_MAX_ATTEMPTS='4', OUF_SCHEMA_INITIAL_DELAY_MS='1'), \
                    patch.object(analysis_schema, '_install', wraps=analysis_schema._install) as install, \
                    patch('tools.analysis_schema.time.sleep') as sleep, redirect_stderr(io.StringIO()):
                writer.execute('pragma journal_mode=delete')
                writer.execute('begin exclusive')
                exhausted = self.boot_worker(command, config)
                self.assertEqual(self.request(exhausted), ('503 Service Unavailable', b''))
                self.assertEqual(install.call_count, 4)
                self.assertEqual(sleep.call_count, 3)
                process = subprocess.run([sys.executable, '-c', restart, command, json.dumps(config)],
                                         capture_output=True, text=True, timeout=10, check=True)
                self.assertEqual(process.stdout.strip(), '503 Service Unavailable 4')
                # The replacement encounters the same lock and recovers in its own backoff.
                sleep.side_effect = lambda _: writer.rollback()
                fresh = self.boot_worker(command, config)
                self.assertEqual(install.call_count, 6)
                self.assertEqual(self.request(fresh), ('204 No Content', b''))
                self.assertEqual(self.request(exhausted), ('503 Service Unavailable', b''))
                self.assertEqual(self.request(exhausted, PATH_INFO='/decisions'), ('503 Service Unavailable', b''))
                self.assertEqual(install.call_count, 6)

    def test_gw_58ie_03_bounds_and_deadline(self):
        """GW-58IE-03. Invalid parameters fail before SQLite. No new attempt starts after expiry."""
        for command, config, _ in self.configurations():
            with self.subTest(command=command), redirect_stderr(io.StringIO()), \
                    patch.object(analysis_schema, '_install', wraps=analysis_schema._install) as install, \
                    patch('tools.analysis_schema.time') as clock:
                for key, invalid in [('OUF_SCHEMA_MAX_ATTEMPTS', ('', '0', '5', '1.5')),
                                     ('OUF_SCHEMA_INITIAL_DELAY_MS', ('0', '501', '-1', 'nan'))]:
                    for value in invalid:
                        with self.subTest(key=key, value=value), patch.dict(os.environ, {key: value}):
                            self.assertEqual(self.request(self.boot_worker(command, config))[0], '503 Service Unavailable')
                install.assert_not_called()
                clock.sleep.assert_not_called()

                clock.monotonic.return_value = 0
                with closing(sqlite3.connect(config['store'])) as writer:
                    writer.execute('begin exclusive')
                    with patch.dict(os.environ, OUF_SCHEMA_MAX_ATTEMPTS='1'):
                        self.assertEqual(self.request(self.boot_worker(command, config))[0], '503 Service Unavailable')
                    self.assertEqual(install.call_count, 1)
                    clock.sleep.assert_not_called()
                    clock.sleep.side_effect = lambda _: setattr(clock.monotonic, 'return_value', 5)
                    self.assertEqual(self.request(self.boot_worker(command, config))[0], '503 Service Unavailable')
                    self.assertEqual(install.call_count, 2)
                    clock.sleep.assert_called_once()

                # SQLite reports SQLITE_READONLY when the missing schema requires a write.
                connect = sqlite3.connect

                def read_only_connection(*args, **kwargs):
                    db = connect(*args, **kwargs)
                    db.execute('pragma query_only=on')
                    return db

                clock.sleep.reset_mock()
                with patch('sqlite3.connect', side_effect=read_only_connection):
                    self.assertEqual(self.request(self.boot_worker(command, config))[0], '503 Service Unavailable')
                self.assertEqual(install.call_count, 3)
                clock.sleep.assert_not_called()

    def test_gw_58ic_02_initialized_store_with_active_reader(self):
        """GW-58IC-02. A rollback-journal reader coexists with boot and reversible readiness."""
        for command, config, _ in self.configurations():
            store = MandateStore if command == 'authority' else VerifierStore
            store(config['store'])
            with self.subTest(command=command), closing(sqlite3.connect(config['store'])) as reader, \
                    patch('tools.analysis_service.https_endpoint', return_value=Mock(path='/')), \
                    patch('tools.analysis_service.Catalog'), \
                    patch('ssl.create_default_context', return_value=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)), \
                    patch('time.sleep') as backoff:
                self.assertEqual(reader.execute('pragma journal_mode=delete').fetchone(), ('delete',))
                reader.execute('begin')
                reader.execute('select count(*) from sqlite_master').fetchone()
                app = worker_application(command, config, mtls=command == 'iam-adapter', probe_principal='probe')
                self.assertEqual(self.request(app), ('204 No Content', b''))
                backoff.assert_not_called()
                reader.rollback()
                self.assertEqual(self.request(app), ('204 No Content', b''))

    def test_gw_58ic_02_partial_or_incompatible_schema(self):
        """GW-58IC-02. Only a complete compatible schema qualifies for the read-only path."""
        for command, config, _ in self.configurations():
            if command == 'authority':
                store, index = MandateStore, 'analysis_phase_v1'
            else:
                store, index = VerifierStore, 'keycloak_expiry_v1'
            store(config['store'])
            with self.subTest(command=command), closing(sqlite3.connect(config['store'], isolation_level=None)) as db:
                query = 'select sql from sqlite_master where name=?'
                definition, = db.execute(query, (index,)).fetchone()
                db.execute(f'drop index {index}')
                store(config['store'])
                self.assertEqual(db.execute(query, (index,)).fetchone(), (definition,))
                db.execute(f'drop index {index}')
                db.execute(f'create table {index} (unrelated integer)')
                with self.assertRaisesRegex(ValueError, 'incompatible store schema'):
                    store(config['store'])

    def test_gw_58ie_04_index_structure(self):
        """GW-58IE-04 / GW-58ID-02. Only structurally equivalent indexes qualify, also on restart."""
        index = 'keycloak_expiry_v1'
        for unique, indexed in (
            ('unique', 'keycloak_permission_v1(expiry)'),
            ('', 'keycloak_permission_v1(grant_id)'),
            ('', 'keycloak_permission_v1(expiry) where expiry > 0'),
            ('', 'keycloak_rate_v1(used)'),
            ('', 'keycloak_permission_v1(expiry collate nocase)'),
            ('', 'keycloak_permission_v1(expiry desc)'),
        ):
            with self.subTest(unique=unique, indexed=indexed), tempfile.TemporaryDirectory(dir=self.root) as volume:
                target = Path(volume) / 'iam.db'
                target.touch()
                VerifierStore(target)
                with closing(sqlite3.connect(target, isolation_level=None)) as db:
                    db.execute(f'drop index {index}')
                    db.execute(f'CREATE INDEX "{index}" ON keycloak_permission_v1 ("expiry")')
                    VerifierStore(target)
                    db.execute(f'drop index {index}')
                    db.execute(f'create {unique} index "{index}" on {indexed}')
                    with self.assertRaisesRegex(ValueError, 'incompatible store schema'):
                        VerifierStore(target)
                with patch('tools.analysis_schema.time.sleep') as sleep, self.assertRaisesRegex(ValueError, 'incompatible'):
                    VerifierStore(target)
                sleep.assert_not_called()

    def test_gw_58ie_05_restore_main_store(self):
        """GW-58IE-05. D-065 restores application state and writability from a quiescent volume."""
        for command, config, _ in self.configurations():
            path = Path(config['store'])
            with self.subTest(command=command):
                self.assertEqual(self.request(self.boot_worker(command, config))[0], '204 No Content')
                with closing(sqlite3.connect(path)) as db:
                    if command == 'authority':
                        db.execute("insert into analysis_mandate_v1 values ('m','s','p',X'7B7D')")
                        db.execute("insert into analysis_command_v1 values ('actor','cmd','fp',X'7B7D')")
                        db.execute("insert into analysis_attempt_v1 values ('m','a','i','op',3,'ADMITTED',0,X'7B7D')")
                    else:
                        db.execute("insert into keycloak_rate_v1 values ('decisions',60,2)")
                        db.execute("insert into keycloak_permission_v1 values ('binding',60,'grant',X'5B5D')")
                    db.commit()
                    expected = list(db.iterdump())

                restored = self.root / ('restored-' + command)
                shutil.copytree(path.parent, restored)
                restored_path = restored / path.name
                app = self.boot_worker(command, {**config, 'store': str(restored_path)})
                self.assertEqual(self.request(app), ('204 No Content', b''))
                with closing(sqlite3.connect(restored_path)) as db:
                    self.assertEqual(db.execute('pragma integrity_check').fetchone(), ('ok',))
                    self.assertEqual(list(db.iterdump()), expected)

    def test_gw_58ib_03_reject_probe_as_gateway_before_bind(self):
        """GW-58IB-03. The entrypoint rejects equal identities before loading TLS or binding."""
        _, config, _ = self.configurations()[1]
        path = self.root / 'config/iam.json'
        path.write_text(json.dumps(config), encoding='utf-8')
        env = dict(OUF_KEYCLOAK_DECISIONS_CONFIG=str(path), OUF_HOST_PROBE_PRINCIPAL=config['gatewayTlsPrincipal'],
                   OUF_HOST_ADDRESS='localhost', OUF_HOST_PORT='8443', OUF_HOST_PROCESSES='1', OUF_HOST_THREADS='8',
                   OUF_HOST_CONNECTIONS='8')
        with patch.dict(os.environ, env), patch('tools.authority_host.tls_settings') as tls, redirect_stderr(io.StringIO()) as log:
            self.assertEqual(main(['iam-adapter']), 2)
            tls.assert_not_called()
        self.assertIn('OUF_HOST_PROBE_PRINCIPAL', log.getvalue())
        self.assertNotIn(config['gatewayTlsPrincipal'], log.getvalue())

    def test_gw_58ib_04_regular_bounded_credentials(self):
        """GW-58IB-04. Count raw bytes, including CRLF, even if the opened file grows."""
        path = self.root / 'credential'
        config = {'secretFile': str(path)}
        path.write_bytes(b'a' * 4094 + b'\r\n')
        self.assertEqual(credential(config, 'secretFile', 'secretEnv'), 'a' * 4094)
        with patch('tools.authority_host.os.fstat', return_value=os.stat(os.devnull)), self.assertRaises(ValueError):
            credential(config, 'secretFile', 'secretEnv')
        prior = path.stat()
        path.write_bytes(b'a' * 4095 + b'\r\n')
        with self.assertRaisesRegex(ValueError, '^invalid secretFile$'):
            credential(config, 'secretFile', 'secretEnv')
        with patch('tools.authority_host.os.fstat', return_value=prior) as descriptor, self.assertRaises(ValueError):
            credential(config, 'secretFile', 'secretEnv')
        self.assertIsInstance(descriptor.call_args.args[0], int)
        with self.assertRaisesRegex(ValueError, '^invalid secretFile$'):
            credential({'secretFile': os.devnull}, 'secretFile', 'secretEnv')

    @unittest.skipUnless(hasattr(os, 'mkfifo'), 'requires POSIX FIFO')
    def test_gw_58ib_04_fifo_without_writer(self):
        """GW-58IB-04. A FIFO without a writer cannot hang worker boot."""
        fifo = self.root / 'fifo'
        os.mkfifo(fifo)
        code = """from tools.authority_host import credential
import sys
try:
    credential({'secretFile': sys.argv[1]}, 'secretFile', 'secretEnv')
except ValueError as exc:
    sys.exit(0 if str(exc) == 'invalid secretFile' else 1)
sys.exit(1)
"""
        subprocess.run([sys.executable, '-c', code, str(fifo)], timeout=5, check=True)
