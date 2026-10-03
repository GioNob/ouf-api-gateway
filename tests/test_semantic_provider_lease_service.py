import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time
import unittest
import uuid

from scripts.run_semantic_provider_lease_owner import supervise, read_configuration, lock
from tools import semantic_provider_dns as dns
from tools.materialize_semantic_lease_service import compile_service
from tools.materialize_southbound_kernel import materialize
from tools.semantic_provider_lease_nft import NftBackend, structure_hash
from tests.test_southbound_kernel import configuration


class LifecycleTest(unittest.TestCase):
    def test_stop_revoke_and_config_drift_revoke(self):
        stop = threading.Event(); events = []
        class Owner:
            def revoke(self): events.append('revoke')
            def refresh(self): events.append('fresh'); stop.set()
        supervise(Owner(), lambda: events.append('check'), 1, stop, log=lambda *a, **k: None)
        self.assertEqual(events, ['revoke', 'check', 'fresh', 'revoke'])
        stop.clear(); events.clear()
        def changed(): raise RuntimeError('changed')
        with self.assertRaises(RuntimeError): supervise(Owner(), changed, 1, stop, log=lambda *a, **k: None)
        self.assertEqual(events, ['revoke', 'revoke'])
    def test_unit_injection_and_unsealed_binding_rejected(self):
        value = dict(unitName='fixture', pythonPath='/usr/bin/python3', sourceRoot='/etc/fixture/source',
            configurationFile='/etc/fixture/config.json', configurationHash='a'*64,
            runtimeDirectory='fixture', restartSeconds=2, stopSeconds=60, dependencyUnits=['docker.service'])
        self.assertFalse(compile_service(value)['started'])
        for key, bad in (('sourceRoot', '/etc/a\nExecStart=/bin/sh'), ('configurationHash', 'x'),
                         ('dependencyUnits', ['x.service\nExecStart=/bin/sh']), ('runtimeDirectory', '../other')):
            modified = copy.deepcopy(value); modified[key] = bad
            with self.assertRaises(ValueError): compile_service(modified)


@unittest.skipUnless(os.environ.get('OUF_LEASE_SYSTEMD_TEST') == '1', 'real root systemd/nft gate is opt-in')
class SystemdTest(unittest.TestCase):
    def test_actual_service_dns_refresh_stop_revocation_and_fresh_restart(self):
        self.assertEqual(os.geteuid(), 0)
        self.assertEqual(Path('/proc/1/comm').read_text().strip(), 'systemd')
        suffix = uuid.uuid4().hex[:8]; unit_name = 'ouf-lease-fixture-'+suffix
        unit_file = Path('/run/systemd/system')/(unit_name+'.service')
        root = Path(tempfile.mkdtemp(prefix=unit_name+'-', dir='/etc')); os.chmod(root, 0o700)
        table = 'ouf_lease_'+suffix; cfg = configuration(); cfg['tableName'] = table
        cfg['guardedInterfaces'] = ['olf-'+suffix]; cfg['existingInterfaces'] = []
        cfg['providerFlows'][0]['leaseSeconds'] = 5
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); udp.bind(('127.0.0.1', 0)); udp.settimeout(0.25)
        dns_stop = threading.Event(); queries = []; errors = []
        def peer():
            while not dns_stop.is_set():
                try: raw, source = udp.recvfrom(512)
                except socket.timeout: continue
                except OSError: return
                try:
                    ident = struct.unpack('!H', raw[:2])[0]; kind = struct.unpack('!H', raw[-4:-2])[0]
                    if kind == 1:
                        payload = socket.inet_aton('10.90.0.2'); header = struct.pack('!6H', ident, 0x8180, 1, 1, 0, 0)
                        record = b'\xc0\x0c'+struct.pack('!HHIH', 1, 1, 30, len(payload))+payload
                    else:
                        payload = dns.wire_name('ns.repository.example')+dns.wire_name('hostmaster.repository.example')+struct.pack('!5I',1,30,30,30,30)
                        header = struct.pack('!6H', ident, 0x8180, 1, 0, 1, 0)
                        record = b'\xc0\x0c'+struct.pack('!HHIH', 6, 1, 30, len(payload))+payload
                    udp.sendto(header+raw[12:]+record, source); queries.append(kind)
                except Exception as error: errors.append(type(error).__name__)
        thread = threading.Thread(target=peer, daemon=True); thread.start()
        def run(*command, raw=None):
            return subprocess.run(command, input=raw, text=True, capture_output=True, timeout=30, check=True).stdout
        backend = None; created = False
        def wait_for(predicate):
            deadline = time.monotonic()+15
            while not predicate():
                if time.monotonic() >= deadline:
                    logs = run('journalctl', '-u', unit_name+'.service', '--no-pager', '-n', '30')
                    self.fail('isolated service condition timed out: '+logs)
                time.sleep(0.1)
        try:
            run('nft', '-f', '-', raw=materialize(cfg)['nftRules']); created = True
            source = root/'source'; source.mkdir(mode=0o700)
            for directory in ('scripts', 'tools'): (source/directory).mkdir(mode=0o700)
            repo = Path(__file__).resolve().parents[1]
            paths = ('scripts/run_semantic_provider_lease_owner.py', 'scripts/prepare_semantic_provider_trust.py',
                'tools/materialize_southbound_kernel.py', 'tools/materialize_southbound_lease_refresh.py',
                'tools/semantic_provider_dns.py', 'tools/semantic_provider_lease_owner.py', 'tools/semantic_provider_lease_nft.py')
            for path in paths:
                (source/path).write_bytes((repo/path).read_bytes()); os.chmod(source/path, 0o600)
            tables = {f: json.loads(run('nft','-j','list','table',f,table)) for f in ('inet','bridge')}
            expected = structure_hash(tables)
            backend = NftBackend([shutil.which('nft')], cfg, expected, 2)
            value = {'schema': 'ouf.semantic-lease-owner-runtime.v1', 'kernel': cfg,
                'dns': {'resolvers': ['127.0.0.1'], 'resolverPort': udp.getsockname()[1], 'timeoutSeconds': 2,
                        'maxLeaseSeconds': 5, 'applyBudgetSeconds': 1},
                'expectedStructureHash': expected, 'nftPath': shutil.which('nft'), 'readBudgetSeconds': 2, 'pollSeconds': 1}
            raw = json.dumps(value).encode(); config = root/'config.json'; config.write_bytes(raw); os.chmod(config, 0o600)
            hash_value = hashlib.sha256(raw).hexdigest()
            self.assertEqual(read_configuration(config, hash_value), value)
            config.write_bytes(raw+b' ')
            with self.assertRaises(Exception): read_configuration(config, hash_value)
            config.write_bytes(raw)
            descriptor = lock(root/'owner.lock')
            with self.assertRaises(Exception): lock(root/'owner.lock')
            os.close(descriptor)
            compiled = compile_service(dict(unitName=unit_name, pythonPath=shutil.which('python3'),
                sourceRoot=str(source), configurationFile=str(config), configurationHash=hash_value,
                runtimeDirectory=unit_name, restartSeconds=1, stopSeconds=30, dependencyUnits=['docker.service']))
            unit_file.write_text(compiled['unit']); os.chmod(unit_file, 0o600)
            run('systemd-analyze','verify',str(unit_file)); run('systemctl','daemon-reload')
            run('systemctl','start',unit_name+'.service')
            wait_for(lambda: len(queries) >= 2 and all(backend.read_sets(cfg).values()))
            count = len(queries); self.assertGreaterEqual(count, 2)
            run('systemctl','stop',unit_name+'.service')
            self.assertFalse(any(backend.read_sets(cfg).values()))
            run('systemctl','start',unit_name+'.service')
            wait_for(lambda: len(queries) >= count+2 and all(backend.read_sets(cfg).values()))
            dns_stop.set(); udp.close(); thread.join(2)
            wait_for(lambda: not any(backend.read_sets(cfg).values()))
            run('systemctl','stop',unit_name+'.service')
            self.assertFalse(any(backend.read_sets(cfg).values())); self.assertEqual(errors, [])
            logs = run('journalctl','-u',unit_name+'.service','--no-pager')
            self.assertIn('SEMANTIC_LEASE_STOP=PASS', logs)
            print('SEMANTIC_LEASE_SYSTEMD_CI=PASS REAL_SYSTEMD_NFT_DNS=true STARTUP_REVOKE=true'
                  ' STOP_REVOKE=true RESTART_FRESH_DNS=true DNS_FAILURE_DENIED=true'
                  ' SEALED_CONFIG_AND_LOCK_VERIFIED=true PROVIDER_CALLS=0 NOT_RELEASE_ACCEPTANCE=true')
        finally:
            subprocess.run(['systemctl','stop',unit_name+'.service'], capture_output=True, timeout=40)
            if unit_file.exists(): unit_file.unlink(); run('systemctl','daemon-reload')
            if created:
                run('nft','-f','-',raw='delete table inet '+table+'\ndelete table bridge '+table+'\n')
            dns_stop.set(); udp.close(); thread.join(2); shutil.rmtree(root)
            print('SEMANTIC_LEASE_SYSTEMD_CLEANUP=PASS OWNED_SERVICE_TABLES_AND_FILES_REMOVED=true')
