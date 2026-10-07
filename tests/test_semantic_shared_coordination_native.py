"""Opt-in real packet/nft/flock proofs, inside an isolated network namespace."""
import copy
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
import uuid

from tools.materialize_semantic_shared_faces import materialize as shared
from tools.materialize_southbound_kernel import materialize
from tools.semantic_provider_lease_coordination import Coordinator, CoordinationDenied, PrivateJournal, hold_common_lock
from tools.semantic_provider_coordinated_supervisor import supervise
from tools.semantic_provider_lease_nft import NftBackend, structure_hash
from tools.semantic_provider_lease_owner import LeaseOwner
from tools import semantic_provider_dns as dns
from tools.semantic_provider_preexec import Preexec, PreexecDenied, digest, rules
from tests.test_semantic_preexec import profile as preexec_profile


@unittest.skipUnless(os.environ.get('OUF_SHARED_COORDINATION_NATIVE_TEST') == '1', 'isolated native fixture opt-in')
class NativeTest(unittest.TestCase):
    def setUp(self):
        self.assertEqual(os.geteuid(), 0)
        self.assertNotEqual(os.stat('/proc/self/ns/net').st_ino, os.stat('/proc/1/ns/net').st_ino,
                            'run this fixture under unshare --net --fork')
        self.ns = []; self.servers = []; self.links = []; self.tables = []
        self.suffix = uuid.uuid4().hex[:8]
        self.addCleanup(self.cleanup)
        self.command('ip', 'link', 'set', 'lo', 'up')

    def command(self, *args, raw=None):
        return subprocess.run(args, input=raw, text=True, capture_output=True, timeout=20, check=True).stdout

    def cleanup(self):
        for server in self.servers:
            server.terminate()
            try: server.communicate(timeout=3)
            except subprocess.TimeoutExpired: server.kill(); server.communicate(timeout=3)
        for family, table in self.tables:
            subprocess.run(['nft', 'delete', 'table', family, table], capture_output=True, timeout=10)
        for ns in self.ns:
            subprocess.run(['ip', 'netns', 'delete', ns], capture_output=True, timeout=10)
        for link in reversed(self.links):
            subprocess.run(['ip', 'link', 'delete', link], capture_output=True, timeout=10)

    def peer(self, tag, address, mac, bridge=None):
        ns = 'ouf-sc-'+self.suffix+'-'+tag; self.command('ip', 'netns', 'add', ns); self.ns.append(ns)
        host, child = 'w'+tag, 'c'+tag
        self.command('ip', 'link', 'add', host, 'type', 'veth', 'peer', 'name', child); self.links.append(host)
        self.command('ip', 'link', 'set', child, 'netns', ns)
        self.command('ip', '-n', ns, 'link', 'set', child, 'name', 'eth0')
        self.command('ip', '-n', ns, 'link', 'set', 'lo', 'up')
        self.command('ip', '-n', ns, 'link', 'set', 'eth0', 'address', mac)
        self.command('ip', '-n', ns, 'addr', 'add', address, 'dev', 'eth0')
        self.command('ip', '-n', ns, 'link', 'set', 'eth0', 'up')
        if bridge: self.command('ip', 'link', 'set', host, 'master', bridge)
        self.command('ip', 'link', 'set', host, 'up')
        index = json.loads(self.command('ip', '-j', 'link', 'show', host))[0]['ifindex']
        return ns, host, index

    def serve(self, ns=None):
        code = """import selectors,socket
s=selectors.DefaultSelector()
for family,host in ((socket.AF_INET,'0.0.0.0'),(socket.AF_INET6,'::')):
 for port in (9443,9444):
  sock=socket.socket(family,socket.SOCK_STREAM);sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
  if family==socket.AF_INET6:sock.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
  sock.bind((host,port));sock.listen();s.register(sock,selectors.EVENT_READ)
print('READY',flush=True)
while True:
 for key,_ in s.select():
  conn,_=key.fileobj.accept();conn.settimeout(1)
  try:conn.recv(1);conn.sendall(b'K')
  except OSError:pass
  finally:conn.close()
"""
        cmd = (['ip', 'netns', 'exec', ns] if ns else [])+[sys.executable, '-u', '-c', code]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.servers.append(proc)
        import select
        self.assertTrue(select.select([proc.stdout], [], [], 5)[0], 'fixture server startup timeout')
        self.assertEqual(proc.stdout.readline().strip(), 'READY')

    def probe(self, ns, address, port=9443, source=None):
        code = """import socket,sys
a=sys.argv[1];s=socket.socket(socket.AF_INET6 if ':' in a else socket.AF_INET,socket.SOCK_STREAM);s.settimeout(.7)
try:
 if sys.argv[3]!='-':s.bind((sys.argv[3],0))
 s.connect((a,int(sys.argv[2])));s.sendall(b'Q');print('PASS' if s.recv(1)==b'K' else 'DENIED')
except OSError:print('DENIED')
finally:s.close()
"""
        return self.command('ip', 'netns', 'exec', ns, sys.executable, '-c', code,
                        address, str(port), source or '-').strip() == 'PASS'

    def test_shared_packets_same_subnet_routed_host_spoof_ipv6_and_other_peers(self):
        bridge = 'shared0'; self.command('ip', 'link', 'add', bridge, 'type', 'bridge'); self.links.append(bridge)
        self.command('ip', 'addr', 'add', '10.77.0.1/24', 'dev', bridge); self.command('ip', 'link', 'set', bridge, 'up')
        a, pa, ia = self.peer('a', '10.77.0.2/24', '02:00:00:00:00:02', bridge)
        b, pb, ib = self.peer('b', '10.77.0.3/24', '02:00:00:00:00:03', bridge)
        c, pc, ic = self.peer('c', '10.77.0.4/24', '02:00:00:00:00:04', bridge)
        d, pd, id_ = self.peer('d', '10.78.0.2/24', '02:00:00:00:00:05')
        self.command('ip', 'addr', 'add', '10.78.0.1/24', 'dev', pd)
        self.command('sysctl', '-w', 'net.ipv4.ip_forward=1')
        for ns in (a, b, c): self.command('ip', '-n', ns, 'route', 'add', 'default', 'via', '10.77.0.1')
        self.command('ip', '-n', d, 'route', 'add', '10.77.0.0/24', 'via', '10.78.0.1')
        for ns, suffix in ((a, '2'), (b, '3'), (c, '4')):
            self.command('ip', '-n', ns, '-6', 'addr', 'add', 'fd77::'+suffix+'/64', 'dev', 'eth0', 'nodad')
        for ns in (a, b, c, d): self.serve(ns)
        self.serve()
        self.assertTrue(self.probe(c, '10.77.0.3')); self.assertTrue(self.probe(c, 'fd77::3'))
        attachments = [{'workloadRef': 'southbound', 'interface': pa, 'ifindex': ia, 'bridge': bridge,
            'mac': '02:00:00:00:00:02', 'ipv4': '10.77.0.2', 'bindingRef': 'fixture-port'}]
        flows = []
        for src, dst, kind, ingress, purpose in (
                ('10.77.0.2', '10.77.0.3', 'BRIDGE_PORT', ib, 'IDENTITY'),
                ('10.77.0.3', '10.77.0.2', 'BRIDGE_PORT', ib, 'WORKLOAD_GATEWAY'),
                ('10.77.0.2', '10.77.0.1', 'HOST', 0, 'IDENTITY'),
                ('10.77.0.2', '10.78.0.2', 'ROUTED', id_, 'IDENTITY')):
            flows.append({'purpose': purpose, 'authorityRef': 'fixture-approved', 'source': src,
                'destination': dst, 'protocol': 'tcp', 'port': 9443,
                'peerIngress': {'kind': kind, 'ifindex': ingress}})
        rules = shared({'schema': 'ouf.semantic-shared-faces.v1', 'tableName': 'shared_owned',
                        'attachments': attachments, 'flows': flows})['nftRules']
        self.command('nft', '-f', '-', raw=rules); self.tables += [(f, 'shared_owned') for f in ('inet', 'bridge')]
        for src, dst in ((a, '10.77.0.3'), (b, '10.77.0.2'), (a, '10.77.0.1'), (a, '10.78.0.2')):
            self.assertTrue(self.probe(src, dst), (src, dst, 'governed flow denied'))
        self.assertFalse(self.probe(a, '10.77.0.3', 9444)); self.assertFalse(self.probe(a, '10.77.0.4'))
        self.assertFalse(self.probe(c, '10.77.0.2')); self.assertFalse(self.probe(a, 'fd77::3'))
        self.assertTrue(self.probe(c, '10.77.0.3')); self.assertTrue(self.probe(c, 'fd77::3'))
        self.command('ip', '-n', a, 'addr', 'add', '10.77.0.99/24', 'dev', 'eth0')
        self.assertFalse(self.probe(a, '10.77.0.3', source='10.77.0.99'))
        self.command('ip', '-n', a, 'link', 'set', 'eth0', 'address', '02:00:00:00:00:99')
        self.assertFalse(self.probe(a, '10.77.0.3'))
        self.command('ip', '-n', a, 'link', 'set', 'eth0', 'address', '02:00:00:00:00:02')
        self.command('ip', '-n', c, 'addr', 'add', '10.77.0.3/24', 'dev', 'eth0')
        self.command('ip', '-n', c, 'link', 'set', 'eth0', 'address', '02:00:00:00:00:03')
        self.assertFalse(self.probe(c, '10.77.0.2', source='10.77.0.3'))
        self.command('ip', '-n', c, 'addr', 'del', '10.77.0.3/24', 'dev', 'eth0')
        self.command('ip', '-n', c, 'link', 'set', 'eth0', 'address', '02:00:00:00:00:04')
        for ns in (a, b): self.command('ip', '-n', ns, 'neigh', 'flush', 'dev', 'eth0')
        self.assertTrue(self.probe(a, '10.77.0.3'))
        self.command('ip', 'link', 'set', pa, 'name', 'renamed_a'); self.links[self.links.index(pa)] = 'renamed_a'
        self.assertTrue(self.probe(a, '10.77.0.3'))
        self.assertFalse(self.probe(a, '10.77.0.4'))  # ifindex binding survives rename
        print('SHARED_FACE_NATIVE=PASS SAME_SUBNET=true ROUTED=true HOST_LOCAL=true'
              ' UNRELATED_PEERS_PRESERVED=true SOURCE_IP_MAC_PEER_PORT_SPOOF_DENIED=true'
              ' IPV6_SELECTED_DENIED=true RENAME_BINDING_PRESERVED=true NOT_RELEASE_ACCEPTANCE=true')

    def test_real_lease_dns_nft_common_lock_quiesce_crash_gate_and_foreign_handles(self):
        self.command('nft', '-f', '-', raw=materialize(self.kernel(), empty_provider_sets=True)['nftRules'])
        self.tables += [(f, 'lease_owned') for f in ('inet', 'bridge')]
        cfg = self.kernel()
        tables = {f: json.loads(self.command('nft', '-j', 'list', 'table', f, 'lease_owned')) for f in ('inet', 'bridge')}
        expected = structure_hash(tables); backend = NftBackend([shutil.which('nft')], cfg, expected, 2)
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); udp.bind(('127.0.0.1', 0)); udp.settimeout(.2)
        self.addCleanup(udp.close); stop = threading.Event(); self.addCleanup(stop.set); queries = []
        def server():
            while not stop.is_set():
                try: raw, peer = udp.recvfrom(512)
                except socket.timeout: continue
                except OSError: return
                ident = struct.unpack('!H', raw[:2])[0]; kind = struct.unpack('!H', raw[-4:-2])[0]
                if kind == 1:
                    payload = socket.inet_aton('10.78.0.2'); counts = (1, 0)
                    record = b'\xc0\x0c'+struct.pack('!HHIH', 1, 1, 30, len(payload))+payload
                else:
                    payload = dns.wire_name('ns.fixture.invalid')+dns.wire_name('hostmaster.fixture.invalid')+struct.pack('!5I', 1, 30, 30, 30, 30)
                    counts = (0, 1); record = b'\xc0\x0c'+struct.pack('!HHIH', 6, 1, 30, len(payload))+payload
                udp.sendto(struct.pack('!6H', ident, 0x8180, 1, *counts, 0)+raw[12:]+record, peer); queries.append(kind)
        thread = threading.Thread(target=server, daemon=True); thread.start()
        self.addCleanup(lambda: (stop.set(), thread.join(2)))
        owner = LeaseOwner(cfg, {'resolvers': ['127.0.0.1'], 'resolverPort': udp.getsockname()[1],
            'timeoutSeconds': 2, 'maxLeaseSeconds': 30, 'applyBudgetSeconds': 1}, backend)
        binding = {'transactionId': 'a'*64, 'configurationHash': 'b'*64, 'leaseStructureHash': expected}
        record = {'schema': 'ouf.semantic-lease-coordination.v1', **binding, 'state': 'LEASE_READY',
                  'leaseAuthorized': True, 'startAuthorized': False, 'leaseAddresses': [[]]}
        with tempfile.TemporaryDirectory(prefix='ouf-coordination-', dir='/etc') as tmp:
            Path(tmp).chmod(0o700)
            lock = Path(tmp)/'common.lock'; lock.touch(mode=0o600)
            journal_path = Path(tmp)/'journal.json'; journal_path.write_text(json.dumps(record)); journal_path.chmod(0o600)
            journal = PrivateJournal(journal_path)
            def hold(): return hold_common_lock(lock)
            coord = Coordinator(owner, binding, hold, journal.read, journal.write)
            coord.refresh(); self.assertEqual(set(queries), {1, 28}); self.assertTrue(any(backend.read_sets(cfg).values()))
            self.assertFalse(coord.guard()['dockerPrestartStructuralGate'])
            with hold():
                with self.assertRaises(BlockingIOError): coord.guard()
                with self.assertRaises(BlockingIOError): coord.refresh()
            coord.quiesce(); self.assertFalse(any(backend.read_sets(cfg).values()))
            count = len(queries)
            with self.assertRaises(CoordinationDenied): coord.refresh()
            self.assertEqual(len(queries), count); self.assertTrue(coord.guard()['dockerPrestartStructuralGate'])
            # Explicit fixture authorization is separate from the protocol; no
            # automatic reactivation or reuse of a cached DNS observation.
            record = journal.read(); journal.write(record, {**record, 'state': 'LEASE_READY', 'leaseAuthorized': True})
            test = self
            class StopAfterFreshCycle:
                def is_set(self): return False
                def wait(self, seconds):
                    test.assertTrue(any(backend.read_sets(cfg).values()))
                    test.assertFalse(coord.guard()['dockerPrestartStructuralGate'])
                    return True
            supervise(coord, lambda: None, 1, StopAfterFreshCycle(), log=lambda *a, **k: None)
            self.assertGreaterEqual(len(queries), count+2)
            self.assertFalse(any(backend.read_sets(cfg).values()))
            self.assertEqual(journal.read()['state'], 'QUIESCED')
            self.assertFalse(journal.read()['leaseAuthorized'])
            self.assertTrue(coord.guard()['dockerPrestartStructuralGate'])
            with self.assertRaises(CoordinationDenied): coord.fresh_start()
            record = journal.read(); journal.write(record, {**record, 'state': 'LEASE_UPDATING'})
            with self.assertRaises(CoordinationDenied): coord.guard()
            with self.assertRaises(CoordinationDenied): coord.refresh()
            coord.quiesce()
            self.command('nft', '-f', '-', raw='delete table inet lease_owned\ndelete table bridge lease_owned\n'+materialize(cfg, empty_provider_sets=True)['nftRules'])
            with self.assertRaises(RuntimeError): coord.guard()
            self.assertFalse(any(backend.read_sets(cfg).values()))
        print('LEASE_COORDINATION_NATIVE=PASS REAL_DNS_NFT_FLOCK=true QUIESCE_REVOKE=true'
              ' RESTART_FRESH_DNS=true COORDINATED_SUPERVISOR_STOP_REVOKE=true REARM_REFUSED=true'
              ' INCOMPLETE_GATE_DENIED=true HANDLE_REBIND_REFUSED=true'
              ' START_AUTHORIZED=false PROVIDER_CALLS=0 NOT_RELEASE_ACCEPTANCE=true')

    def test_real_nft_preexec_owned_install_crash_recovery_and_generation(self):
        cfg = self.kernel()
        self.command('nft', '-f', '-', raw=materialize(cfg, empty_provider_sets=True)['nftRules'])
        self.tables += [(f, 'lease_owned') for f in ('inet', 'bridge')]
        lease_tables = {f: json.loads(self.command('nft', '-j', 'list', 'table', f, 'lease_owned'))
                        for f in ('inet', 'bridge')}
        expected = structure_hash(lease_tables)
        owner = LeaseOwner(cfg, {'resolvers': ['127.0.0.1'], 'resolverPort': 53, 'timeoutSeconds': 2,
            'maxLeaseSeconds': 30, 'applyBudgetSeconds': 1}, NftBackend([shutil.which('nft')], cfg, expected, 2))
        binding = {'transactionId': 'a'*64, 'configurationHash': 'b'*64, 'leaseStructureHash': expected}
        bridge = 'brpre'; self.command('ip', 'link', 'add', bridge, 'type', 'bridge'); self.links.append(bridge)
        self.command('ip', 'link', 'set', bridge, 'up')
        ns, host, index = self.peer('pre', '10.77.0.2/24', '02:00:00:00:00:02', bridge)
        _, _, peer_index = self.peer('next', '10.77.0.3/24', '02:00:00:00:00:03', bridge)
        profile = preexec_profile(); profile['policy']['tableName'] = 'preexec_owned'
        profile['policy']['attachments'][0].update(interface=host, ifindex=index, bridge=bridge)
        profile['policy']['flows'][0]['peerIngress']['ifindex'] = peer_index
        namespace = '/run/netns/'+ns; profile['namespacePath'] = namespace
        profile['namespaceInode'] = os.stat(namespace).st_ino
        child = json.loads(self.command('ip', '-n', ns, '-j', 'addr', 'show', 'eth0'))[0]
        profile['namespaceLinks'] = [{'interface': 'eth0', 'ifindex': child['ifindex'], 'hostIfindex': index}]
        test = self
        def normalized(value):
            if isinstance(value, list): return [normalized(v) for v in value if not (isinstance(v, dict) and 'metainfo' in v)]
            if isinstance(value, dict): return {k: normalized(v) for k, v in value.items()
                                               if k not in ('handle', 'packets', 'bytes')}
            return value
        class Backend:
            crash = False
            def tables(self):
                entries = json.loads(test.command('nft', '-j', '-n', 'list', 'tables'))['nftables']
                present = {v['table']['family'] for v in entries if 'table' in v
                           and v['table']['name'] == 'preexec_owned' and v['table']['family'] in ('inet', 'bridge')}
                if not present: return None
                if present != {'inet', 'bridge'}: raise PreexecDenied('PARTIAL_TABLES')
                return {f: json.loads(test.command('nft', '-j', '-n', 'list', 'table', f, 'preexec_owned')) for f in present}
            def footprint(self, value): return digest(normalized(value))
            def structure_hash(self, value): return structure_hash(value)
            def create(self, raw):
                test.command('nft', '-f', '-', raw='create table inet preexec_owned\ncreate table bridge preexec_owned\n'+raw)
                if self.crash: raise RuntimeError('fixture crash after atomic create')
            def remove(self):
                test.command('nft', '-f', '-', raw='delete table inet preexec_owned\ndelete table bridge preexec_owned\n')
            def bindings(self, value, state):
                if os.stat(value['namespacePath']).st_ino != value['namespaceInode']:
                    raise PreexecDenied('NAMESPACE_CHANGED')
                link = json.loads(test.command('ip', '-j', 'link', 'show', host))[0]
                child_link = json.loads(test.command('ip', '-n', ns, '-j', 'addr', 'show', 'eth0'))[0]
                if link['ifindex'] != index or link.get('master') != bridge \
                        or child_link['ifindex'] != child['ifindex'] or child_link['address'] != child['address'] \
                        or child_link['addr_info'] != child['addr_info']:
                    raise PreexecDenied('PORT_BINDING_CHANGED')
                if state is None: return None
                pid = state['pid']; inode = os.stat('/proc/'+str(pid)+'/ns/net').st_ino
                ticks = int(Path('/proc/'+str(pid)+'/stat').read_text().rsplit(')', 1)[1].split()[19])
                if inode != value['namespaceInode']: raise PreexecDenied('PROCESS_NAMESPACE_CHANGED')
                return {'pid': pid, 'startTicks': ticks, 'namespaceInode': inode}
            def generation_alive(self, generation):
                try:
                    return self.bindings(profile, {'pid': generation['pid']}) == generation
                except (OSError, PreexecDenied): return False
        backend = Backend(); backend.create(rules(profile)); profile['expectedFootprint'] = backend.footprint(backend.tables())
        backend.remove(); self.tables += [(f, 'preexec_owned') for f in ('inet', 'bridge')]
        with tempfile.TemporaryDirectory(prefix='ouf-preexec-', dir='/etc') as tmp:
            root = Path(tmp); root.chmod(0o700)
            lock = root/'guard.lock'; lock.touch(mode=0o600)
            def private(name, value):
                path = root/name; path.write_text(json.dumps(value)); path.chmod(0o600); return PrivateJournal(path)
            journal = private('lease.json', {'schema': 'ouf.semantic-lease-coordination.v1', **binding,
                'state': 'QUIESCED', 'leaseAuthorized': False, 'startAuthorized': False, 'leaseAddresses': [[]]})
            coord = Coordinator(owner, binding, lambda: hold_common_lock(lock), journal.read, journal.write)
            profile['applicationStartAuthorized'] = True  # synthetic fixture authority only
            prejournal = private('preexec.json', {'schema': 'ouf.semantic-preexec-journal.v1', 'transactionId': 'a'*64,
                'configurationHash': digest(profile), 'state': 'STAGED', 'sharedStructureHash': None, 'containerGeneration': None})
            gate = Preexec(profile, backend, coord, prejournal)
            gate.operate('plan'); backend.crash = True
            with self.assertRaises(RuntimeError): gate.operate('apply')
            with self.assertRaises(PreexecDenied): gate.operate('rollback')
            gate.operate('reconcile'); gate.operate('verify'); backend.crash = False
            with coord.hold_lock():
                with self.assertRaises(BlockingIOError): gate.operate('verify')
            process = subprocess.Popen(['ip', 'netns', 'exec', ns, sys.executable, '-c',
                                        'import time; print("READY", flush=True); time.sleep(30)'],
                                       stdout=subprocess.PIPE, text=True)
            self.servers.append(process); self.assertEqual(process.stdout.readline().strip(), 'READY')
            self.assertTrue(gate.before_process({'id': 'fixture', 'bundle': '/sealed/bundle',
                'status': 'creating', 'pid': process.pid})['protectedBeforeProcess'])
            for mode in ('rollback', 'reconcile'):
                with self.assertRaises(PreexecDenied): gate.operate(mode)
            process.terminate(); process.wait(timeout=3); process.stdout.close(); self.servers.remove(process)
            # Replacement by another native structure must be preserved even
            # if it has the same table name and transaction comment.
            backend.remove(); backend.create(rules(profile))
            with self.assertRaises(PreexecDenied): gate.operate('rollback')
            self.assertIsNotNone(backend.tables())
        print('PREEXEC_PROTOCOL_NATIVE=PASS REAL_NFT_PRIVATE_JOURNAL_FLOCK=true CRASH_RECONCILE=true'
              ' LIVE_GENERATION_ROLLBACK_DENIED=true FOREIGN_HANDLES_PRESERVED=true'
              ' OCI_HOOK_INTEGRATION_PROVEN=false START_AUTHORIZED=false NOT_RELEASE_ACCEPTANCE=true')

    def kernel(self):
        return {'tableName': 'lease_owned', 'guardedInterfaces': ['dedicated0'], 'existingInterfaces': [],
            'staticFlows': [], 'providerFlows': [{'endpointRef': 'fixture', 'endpoint': 'https://provider.fixture.invalid/sparql',
                'source': '10.77.0.2', 'addresses': [], 'leaseSeconds': 30,
                'resolutionEvidenceRef': 'fresh-dns', 'allowedPrivateAddresses': ['10.78.0.2']}]}


if __name__ == '__main__': unittest.main()
