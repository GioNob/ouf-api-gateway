"""Real runc createRuntime gate, owned nft tables and sealed private package.

Synthetic authority in an isolated CI network namespace. No Docker registration
or target startup/admission acceptance. The fixture runs only a static shell.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

from scripts.semantic_provider_preexec_hook import MODULES, SELF
from tests.test_semantic_preexec import profile as initial_profile
from tests.test_semantic_shared_coordination_native import NativeTest
from tools.materialize_southbound_kernel import materialize
from tools.semantic_provider_lease_nft import structure_hash
from tools.semantic_provider_preexec import digest, rules
from tools.semantic_provider_preexec_native import NativeBackend


@unittest.skipUnless(os.environ.get('OUF_PREEXEC_OCI_NATIVE_TEST') == '1', 'isolated real runc fixture opt-in')
class OciTest(unittest.TestCase):
    setUp = NativeTest.setUp
    command = NativeTest.command
    cleanup = NativeTest.cleanup
    peer = NativeTest.peer
    kernel = NativeTest.kernel

    def test_real_runc_denials_prevent_application_and_valid_create_precedes_start(self):
        self.assertIsNotNone(shutil.which('runc')); self.assertIsNotNone(shutil.which('busybox'))
        bridge = 'broci'; self.command('ip', 'link', 'add', bridge, 'type', 'bridge'); self.links.append(bridge)
        self.command('ip', 'link', 'set', bridge, 'up')
        ns, host, index = self.peer('oci', '10.77.0.2/24', '02:00:00:00:00:02', bridge)
        _, _, peer_index = self.peer('peer', '10.77.0.3/24', '02:00:00:00:00:03', bridge)
        child = json.loads(self.command('ip', '-n', ns, '-j', 'addr', 'show', 'eth0'))[0]
        cfg = self.kernel(); self.command('nft', '-f', '-', raw=materialize(cfg, empty_provider_sets=True)['nftRules'])
        self.tables += [(f, 'lease_owned') for f in ('inet', 'bridge')]
        lease_hash = structure_hash({f: json.loads(self.command('nft', '-j', 'list', 'table', f, 'lease_owned'))
                                     for f in ('inet', 'bridge')})
        commands = {name: str(Path(shutil.which(name)).resolve()) for name in ('nft', 'ip', 'nsenter')}
        tmp = self.enterContext(tempfile.TemporaryDirectory(prefix='ouf-oci-', dir='/etc'))
        root = Path(tmp); root.chmod(0o700); bundle = root/'bundle'; bundle.mkdir(mode=0o700)
        source = root/'source'; source.mkdir(mode=0o700)
        repository = Path(__file__).resolve().parents[1]; hashes = {}
        for relative in [SELF, *('tools/'+name+'.py' for name in MODULES)]:
            path = source/relative; path.parent.mkdir(mode=0o700, exist_ok=True)
            raw = (repository/relative).read_bytes(); path.write_bytes(raw); path.chmod(0o600)
            hashes[relative] = hashlib.sha256(raw).hexdigest()
        lock = root/'guard.lock'; lock.touch(mode=0o600)
        def private(path, value): path.write_text(json.dumps(value)); path.chmod(0o600)
        profile = initial_profile(); profile['containerId'] = 'ouf-oci-'+self.suffix
        profile['bundlePath'] = str(bundle); profile['namespacePath'] = '/run/netns/'+ns
        profile['namespaceInode'] = os.stat(profile['namespacePath']).st_ino
        profile['namespaceLinks'] = [{'interface': 'eth0', 'ifindex': child['ifindex'], 'hostIfindex': index}]
        profile['policy']['tableName'] = 'oci_owned'
        profile['policy']['attachments'][0].update(interface=host, ifindex=index, bridge=bridge)
        profile['policy']['flows'][0]['peerIngress']['ifindex'] = peer_index
        profile['applicationStartAuthorized'] = True  # explicit synthetic fixture authority
        filesystem = bundle/'rootfs'; (filesystem/'bin').mkdir(parents=True)
        (filesystem/'proof').mkdir(); (filesystem/'proc').mkdir()
        shutil.copyfile(shutil.which('busybox'), filesystem/'bin/busybox'); (filesystem/'bin/busybox').chmod(0o755)
        (filesystem/'bin/sh').symlink_to('busybox'); marker = filesystem/'proof/app-started'
        driver_path = root/'driver.json'
        hook = {'path': sys.executable, 'args': [sys.executable, '-I', '-B', str(source/SELF),
            '--configuration', str(driver_path), '--mode', 'hook'], 'timeout': 10}
        oci = {'ociVersion': '1.0.2', 'root': {'path': str(filesystem), 'readonly': False},
            'process': {'terminal': False, 'user': {'uid': 0, 'gid': 0}, 'cwd': '/',
                'args': ['/bin/sh', '-c', 'echo APP > /proof/app-started'], 'env': ['PATH=/bin'],
                'noNewPrivileges': True, 'capabilities': {k: [] for k in
                    ('bounding', 'effective', 'inheritable', 'permitted', 'ambient')}},
            'mounts': [{'destination': '/proc', 'type': 'proc', 'source': 'proc', 'options': ['nosuid', 'noexec', 'nodev']}],
            'linux': {'cgroupsPath': '/'+profile['containerId'], 'namespaces': [
                {'type': 'mount'}, {'type': 'pid'}, {'type': 'ipc'}, {'type': 'uts'},
                {'type': 'network', 'path': profile['namespacePath']}]}, 'hooks': {'createRuntime': [hook]}}
        private(bundle/'config.json', oci); profile['bundleHash'] = digest(oci)
        backend = NativeBackend(profile, commands, 5)
        backend.create(rules(profile)); profile['expectedFootprint'] = backend.footprint(backend.tables()); backend.remove()
        self.tables += [(f, 'oci_owned') for f in ('inet', 'bridge')]
        binding = {'transactionId': 'a'*64, 'configurationHash': digest(cfg), 'leaseStructureHash': lease_hash}
        coordination_path, preexec_path = root/'coordination.json', root/'preexec.json'
        coordination = {'schema': 'ouf.semantic-lease-coordination.v1', **binding, 'state': 'QUIESCED',
            'leaseAuthorized': False, 'startAuthorized': False, 'leaseAddresses': [[]]}
        private(coordination_path, coordination)
        private(preexec_path, {'schema': 'ouf.semantic-preexec-journal.v1', 'transactionId': 'a'*64,
            'configurationHash': digest(profile), 'state': 'STAGED', 'sharedStructureHash': None, 'containerGeneration': None})
        driver = {'schema': 'ouf.semantic-preexec-driver.v1', 'sourceRoot': str(source), 'sourceHashes': hashes,
            'profile': profile, 'kernel': cfg, 'dns': {'resolvers': ['127.0.0.1'], 'resolverPort': 53,
                'timeoutSeconds': 2, 'maxLeaseSeconds': 30, 'applyBudgetSeconds': 1},
            'coordinationBinding': binding, 'coordinationJournal': str(coordination_path),
            'preexecJournal': str(preexec_path), 'lockFile': str(lock), 'commands': commands, 'budgetSeconds': 5}
        private(driver_path, driver)
        def call(mode):
            return subprocess.run([sys.executable, '-I', '-B', str(source/SELF), '--configuration', str(driver_path),
                '--mode', mode], capture_output=True, text=True, timeout=20)
        for mode in ('plan', 'apply', 'verify'):
            result = call(mode); self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        owned = json.loads(preexec_path.read_text())
        runtime = root/'runtime'; runc = [shutil.which('runc'), '--root', str(runtime)]
        container = profile['containerId']
        def delete(): subprocess.run([*runc, 'delete', '--force', container], capture_output=True, timeout=10)
        self.addCleanup(delete)
        def create():
            return subprocess.run([*runc, 'create', '--bundle', str(bundle), container],
                                  capture_output=True, text=True, timeout=20)
        def denied(reason):
            result = create(); self.assertNotEqual(result.returncode, 0)
            self.assertIn(reason, result.stderr+result.stdout)
            self.assertFalse(marker.exists()); delete()
        # Source substitution cannot execute even one application command.
        target = source/'tools/semantic_provider_preexec.py'; original = target.read_bytes()
        target.write_bytes(original+b'\n# foreign\n'); denied('SOURCE_PACKAGE_DRIFT'); target.write_bytes(original)
        profile['applicationStartAuthorized'] = False; private(driver_path, driver)
        denied('APPLICATION_START_NOT_AUTHORIZED')
        profile['applicationStartAuthorized'] = True; private(driver_path, driver)
        private(coordination_path, {**coordination, 'state': 'QUIESCING'}); denied('LEASE_QUIESCENCE_REQUIRED')
        private(coordination_path, coordination)
        self.command('ip', '-n', ns, 'link', 'set', 'eth0', 'address', '02:00:00:00:00:09')
        denied('NAMESPACE_PORT_BINDING_DRIFT')
        self.command('ip', '-n', ns, 'link', 'set', 'eth0', 'address', '02:00:00:00:00:02')
        altered = copy.deepcopy(oci); altered['process']['args'] = ['/bin/sh', '-c', 'echo BAD > /proof/app-started']
        private(bundle/'config.json', altered); denied('OCI_BUNDLE_DRIFT'); private(bundle/'config.json', oci)
        result = create(); self.assertEqual(result.returncode, 0, result.stderr+result.stdout)
        self.assertFalse(marker.exists(), 'create must not execute the application')
        state = json.loads(self.command(*runc, 'state', container)); self.assertEqual(state['status'], 'created')
        self.assertEqual(json.loads(preexec_path.read_text())['containerGeneration']['pid'], state['pid'])
        result = call('rollback'); self.assertNotEqual(result.returncode, 0)
        self.assertIn('LIVE_GENERATION_ROLLBACK_DENIED', result.stdout); self.assertFalse(marker.exists())
        self.command(*runc, 'start', container)
        until = time.monotonic()+5
        while not marker.exists() and time.monotonic() < until: time.sleep(.02)
        self.assertEqual(marker.read_text().strip(), 'APP'); delete(); marker.unlink()
        # Simulate a foreign recreation; preserve its tables and deny new OCI generation.
        fresh = NativeBackend(profile, commands, 5); fresh.remove(); fresh.create(rules(profile))
        denied('SHARED_STRUCTURE_RECONCILIATION_REQUIRED')
        self.assertIsNotNone(fresh.tables())
        print('PREEXEC_OCI_NATIVE=PASS REAL_RUNC_CREATE_RUNTIME=true REAL_NFT_PRIVATE_SOURCE_JOURNAL=true'
              ' SOURCE_AUTHORITY_LEASE_MAC_BUNDLE_DRIFT_NO_APPLICATION=true CREATE_PRECEDES_START=true'
              ' LIVE_GENERATION_ROLLBACK_DENIED=true FOREIGN_HANDLES_PRESERVED=true'
              ' DOCKER_INTEGRATION_PROVEN=false TARGET_START_AUTHORIZED=false NOT_RELEASE_ACCEPTANCE=true')


if __name__ == '__main__': unittest.main()
