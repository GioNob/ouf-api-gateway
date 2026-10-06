"""Opt-in target-host proof: only a new internal bridge/table/test containers.

No image pull, provider/DNS/token request, OUF source job or shared-rule write.
The host table is uniquely named and matches only the newly created bridge.
"""
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import time
import unittest
import uuid
import socket
import struct
import threading
from tools import semantic_provider_dns as dns
from tools.semantic_provider_lease_owner import LeaseOwner, LeaseDenied
from tools.semantic_provider_lease_nft import NftBackend, structure_hash

from tools.materialize_southbound_kernel import materialize
from tools.materialize_southbound_lease_refresh import compile_refresh


def stable_rules(value):
    """Ignore packet counters and remaining lease duration, not rule structure."""
    if isinstance(value, dict):
        return {key: stable_rules(item) for key, item in value.items() if key not in ('packets', 'bytes', 'expires')}
    if isinstance(value, list):
        return [stable_rules(item) for item in value]
    return value


def rule_hash(value):
    return hashlib.sha256(json.dumps(stable_rules(value), sort_keys=True, separators=(',', ':')).encode()).hexdigest()


@unittest.skipUnless(os.environ.get('OUF_SOUTHBOUND_DOCKER_KERNEL_TEST') == '1', 'real root Docker bridge/nft fixture is opt-in')
class DockerKernelPacketTest(unittest.TestCase):
    def test_scoped_bridge_default_deny_exact_flow_bypass_and_expiry(self):
        self.assertEqual(os.geteuid(), 0, 'fixture needs root for its scoped host table')
        image = os.environ['OUF_SOUTHBOUND_DOCKER_KERNEL_IMAGE']
        self.assertRegex(image, r'^[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[0-9a-f]{64}$')
        suffix = uuid.uuid4().hex[:8]
        network = 'ouf-kernel-fixture-' + suffix
        bridge = 'oufk-' + suffix
        table = 'ouf_fixture_' + suffix
        client, server, bypass = ['ouf-kernel-' + role + '-' + suffix for role in ('client', 'server', 'bypass')]
        containers = []; net_created = False; table_created = False; persistent = None
        before_rules = None
        def run(*args, input=None, timeout=30):
            return subprocess.run(args, input=input, text=True, capture_output=True, timeout=timeout, check=True).stdout.strip()
        def tables():
            raw = json.loads(run('nft', '-j', 'list', 'tables'))
            return {(v['table']['family'], v['table']['name']) for v in raw['nftables'] if 'table' in v}
        def delete_owned_tables():
            run('nft', '-f', '-', input='delete table inet '+table+'\ndelete table bridge '+table+'\n')
        def inspect(name):
            return json.loads(run('docker', 'inspect', '--type', 'container', name))[0]
        def address(name):
            raw = inspect(name)['NetworkSettings']['Networks']
            self.assertEqual(set(raw), {network})
            value = raw[network]['IPAddress']
            self.assertEqual(ipaddress.ip_address(value).version, 4)
            return value
        def probe(name, target, port):
            code = ('import socket,json; s=socket.socket();s.settimeout(0.6)\ntry:\n'
                    ' s.connect((' + repr(target) + ',' + str(port) + '));s.sendall(b"probe");print(json.dumps(s.recv(10)==b"probe"))\n'
                    'except OSError:print("false")\nfinally:s.close()')
            return json.loads(run('docker', 'exec', name, 'python3', '-B', '-c', code))
        echo = '''import socket,threading
def serve(port):
 s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(("0.0.0.0",port));s.listen()
 def handle(c):
  try:
   while True:
    b=c.recv(100)
    if not b:break
    c.sendall(b)
  except OSError:pass
  finally:c.close()
 while True:
  c,_=s.accept();threading.Thread(target=handle,args=(c,),daemon=True).start()
threading.Thread(target=serve,args=(15443,),daemon=True).start()
serve(15444)
'''
        try:
            # Require the explicitly selected image locally; fixture never pulls.
            json.loads(run('docker', 'image', 'inspect', image))
            existing_links = json.loads(run('ip', '-json', '-details', 'link', 'show'))
            existing_interfaces = [link['ifname'] for link in existing_links]
            self.assertNotIn(bridge, existing_interfaces)
            self.assertNotIn(('inet', table), tables())
            self.assertNotIn(('bridge', table), tables())
            run('docker', 'network', 'create', '--internal', '--driver', 'bridge',
                '--opt', 'com.docker.network.bridge.name=' + bridge, network)
            net_created = True
            observed = json.loads(run('ip', '-json', '-details', 'link', 'show', bridge))
            self.assertEqual(observed[0]['linkinfo']['info_kind'], 'bridge')
            for name in (client, server, bypass):
                code = echo if name == server else 'import time;time.sleep(240)'
                run('docker', 'run', '-d', '--name', name, '--network', network, '--restart=no',
                    '--user', '10006:10006', '--read-only', '--cap-drop=ALL',
                    '--security-opt', 'no-new-privileges', '--pids-limit', '64',
                    image, 'python3', '-B', '-c', code)
                containers.append(name)
            client_ip, server_ip, bypass_ip = [address(name) for name in (client, server, bypass)]
            deadline = time.monotonic()+8
            while not (probe(client, server_ip, 15443) and probe(client, server_ip, 15444)
                       and probe(bypass, server_ip, 15443)):
                if time.monotonic() >= deadline: self.fail('fixture baseline Docker connectivity missing')
                time.sleep(0.1)
            # Take the shared-rule snapshot after Docker's own fixture setup.
            before_rules = json.loads(run('nft', '-j', 'list', 'ruleset'))
            cfg = {'tableName': table, 'guardedInterfaces': [bridge],
                   'existingInterfaces': existing_interfaces, 'staticFlows': [], 'providerFlows': []}
            # Empty allowed flows: neither peer nor host traffic is admitted.
            run('nft', '-f', '-', input=materialize(cfg)['nftRules']); table_created = True
            self.assertFalse(probe(client, server_ip, 15443), 'DOCKER_BRIDGE_HOOK_NOT_PROVEN')
            self.assertFalse(probe(client, server_ip, 15444), 'DOCKER_BRIDGE_HOOK_NOT_PROVEN')
            deny_readback = json.loads(run('nft', '-j', 'list', 'table', 'bridge', table))
            drops = [expr['counter']['packets'] for item in deny_readback['nftables'] if 'rule' in item
                     for expr in item['rule']['expr'] if 'counter' in expr and any('drop' in e for e in item['rule']['expr'])]
            self.assertGreater(sum(drops), 0, 'scoped table must account for denied actual packets')
            # Replace only this uniquely owned fixture table, never a shared one.
            delete_owned_tables(); table_created = False
            cfg['providerFlows'] = [{'endpointRef': 'fixture-provider', 'endpoint': 'https://fixture.invalid:15443/sparql',
                'source': client_ip, 'addresses': [server_ip], 'allowedPrivateAddresses': [server_ip],
                'leaseSeconds': 8, 'resolutionEvidenceRef': 'fixture-docker-inspect'}]
            run('nft', '-f', '-', input=materialize(cfg)['nftRules']); table_created = True
            self.assertTrue(probe(client, server_ip, 15443))
            self.assertFalse(probe(client, server_ip, 15444))
            self.assertFalse(probe(bypass, server_ip, 15443), 'unregistered workload bypass admitted')
            code = ('import socket,time; s=socket.socket();s.settimeout(0.8);s.connect((' + repr(server_ip) + ',15443));'
                    's.sendall(b"before");assert s.recv(20)==b"before";print("OPEN",flush=True);time.sleep(9)\n'
                    'try:\n s.sendall(b"after");print("LEAK" if s.recv(20)==b"after" else "CLOSED",flush=True)\n'
                    'except OSError:print("BLOCKED",flush=True)\nfinally:s.close()')
            persistent = subprocess.Popen(['docker', 'exec', client, 'python3', '-B', '-c', code],
                                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            out, err = persistent.communicate(timeout=15)
            self.assertEqual(persistent.returncode, 0, err)
            self.assertIn('OPEN', out); self.assertNotIn('LEAK', out)
            self.assertFalse(probe(client, server_ip, 15443))
            now = time.monotonic(); flow = cfg['providerFlows'][0]
            fresh = [dict(endpointRef=flow['endpointRef'], endpoint=flow['endpoint'],
                resolutionEvidenceRef=flow['resolutionEvidenceRef'], addresses=flow['addresses'],
                observedMonotonic=now, expiresMonotonic=now+20, historicalEvidenceOnly=False)]
            update = compile_refresh(cfg, fresh, now, apply_budget_seconds=2)
            run('nft', '-f', '-', input=update['nftTransaction'])
            self.assertLess(time.monotonic(), update['mustApplyByMonotonic'])
            self.assertTrue(probe(client, server_ip, 15443)); self.assertFalse(probe(bypass, server_ip, 15443))
            invalid = update['nftTransaction']+'add element bridge '+table+' missing_set { '+server_ip+' }\n'
            failed = subprocess.run(['nft','-f','-'], input=invalid, text=True, capture_output=True, timeout=20)
            self.assertNotEqual(failed.returncode, 0); self.assertTrue(probe(client, server_ip, 15443))
            denied = compile_refresh(cfg, [], time.monotonic(), apply_budget_seconds=2)
            run('nft', '-f', '-', input=denied['nftTransaction'])
            self.assertFalse(probe(client, server_ip, 15443))
            # Actual fresh UDP DNS -> lifecycle owner -> atomic nft/readback ->
            # real Docker packet gate. DNS peer is local; no external provider.
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp.bind(('127.0.0.1', 0)); udp.settimeout(3)
            dns_failures = []
            def dns_peer():
                try:
                    for _ in range(2):
                        raw, source = udp.recvfrom(512)
                        ident = struct.unpack('!H', raw[:2])[0]
                        kind = struct.unpack('!H', raw[-4:-2])[0]
                        if kind == 1:
                            payload = socket.inet_aton(server_ip)
                            header = struct.pack('!6H', ident, 0x8180, 1, 1, 0, 0)
                            record = b'\xc0\x0c'+struct.pack('!HHIH', 1, 1, 30, len(payload))+payload
                        else:
                            payload = dns.wire_name('ns.fixture.invalid')+dns.wire_name('hostmaster.fixture.invalid')+struct.pack('!5I', 1, 30, 30, 30, 30)
                            header = struct.pack('!6H', ident, 0x8180, 1, 0, 1, 0)
                            record = b'\xc0\x0c'+struct.pack('!HHIH', 6, 1, 30, len(payload))+payload
                        udp.sendto(header+raw[12:]+record, source)
                except Exception as error: dns_failures.append(type(error).__name__)
            thread = threading.Thread(target=dns_peer, daemon=True); thread.start()
            raw_tables = {f: json.loads(run('nft', '-j', 'list', 'table', f, table)) for f in ('inet', 'bridge')}
            backend = NftBackend(['nft'], cfg, structure_hash(raw_tables), 2)
            owner = LeaseOwner(cfg, {'resolvers': ['127.0.0.1'], 'resolverPort': udp.getsockname()[1],
                'timeoutSeconds': 2, 'maxLeaseSeconds': 10, 'applyBudgetSeconds': 2}, backend)
            try:
                self.assertTrue(owner.refresh()['bothFamiliesReadBack'])
                self.assertTrue(probe(client, server_ip, 15443)); self.assertFalse(probe(bypass, server_ip, 15443))
            finally:
                thread.join(4); udp.close()
            self.assertFalse(thread.is_alive()); self.assertEqual(dns_failures, [])
            # The selected DNS peer is now unavailable: revoke rather than cache.
            with self.assertRaisesRegex(LeaseDenied, 'SETS_REVOKED'): owner.refresh()
            self.assertFalse(probe(client, server_ip, 15443))
            print('SOUTHBOUND_LEASE_OWNER_DOCKER_CI=PASS REAL_DOCKER_BRIDGE=true REAL_LOCAL_DNS=true'
                  ' A_AND_AAAA_CHECKED=true BOTH_FAMILIES_READ_BACK=true FAILED_DNS_REVOKED=true'
                  ' PACKET_DENIED_AFTER_REVOCATION=true PROVIDER_CALLS=0 NOT_RELEASE_ACCEPTANCE=true')
            delete_owned_tables(); table_created = False
            self.assertEqual(rule_hash(before_rules), rule_hash(json.loads(run('nft', '-j', 'list', 'ruleset'))),
                             'SHARED_RULE_STRUCTURE_CHANGED')
            self.assertTrue(probe(client, server_ip, 15443))
            self.assertTrue(probe(bypass, server_ip, 15443))
            print('SOUTHBOUND_DOCKER_KERNEL=PASS REAL_DOCKER_BRIDGE=true NATIVE_BRIDGE_HOOK=true SCOPED_HOST_FORWARD_HOOK=true '
                  'DEFAULT_DENY=true UNREGISTERED_WORKLOAD_DENIED=true LEASE_EXPIRY_NEW_AND_ESTABLISHED_DENIED=true '
                  'SHARED_RULE_STRUCTURE_UNCHANGED=true PROVIDER_CALLS=0 NOT_RELEASE_ACCEPTANCE=true')
            print('SOUTHBOUND_DOCKER_LEASE_REFRESH_CI=PASS REAL_DOCKER_BRIDGE=true ATOMIC_INET_BRIDGE_REFRESH=true FAILED_BATCH_ROLLBACK=true MISSING_RESOLUTION_REVOKED=true PROVIDER_CALLS=0 NOT_RELEASE_ACCEPTANCE=true')
        finally:
            if persistent is not None and persistent.poll() is None:
                persistent.terminate()
                try: persistent.wait(timeout=3)
                except subprocess.TimeoutExpired: persistent.kill(); persistent.wait(timeout=3)
            # Remove test workloads before removing their guard on failure.
            cleanup_errors = []
            for name in reversed(containers):
                try: run('docker', 'rm', '-f', name)
                except Exception: cleanup_errors.append('CONTAINER')
            if net_created:
                try: run('docker', 'network', 'rm', network)
                except Exception: cleanup_errors.append('NETWORK')
            if table_created and not cleanup_errors:
                try: delete_owned_tables()
                except Exception: cleanup_errors.append('TABLE')
            elif table_created:
                cleanup_errors.append('TABLE_RETAINED')
            if cleanup_errors:
                print('SOUTHBOUND_DOCKER_KERNEL_CLEANUP=BLOCKED FIXTURE_PREFIX='+suffix+' REMAINING_TYPES='+','.join(cleanup_errors))
                self.fail('fixture cleanup unproven; reconcile the printed prefix')
            print('SOUTHBOUND_DOCKER_KERNEL_CLEANUP=PASS TEST_CONTAINERS_NETWORK_AND_TABLE_REMOVED=true')


if __name__ == '__main__':
    unittest.main()
