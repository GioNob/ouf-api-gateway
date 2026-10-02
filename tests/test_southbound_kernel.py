import json
import os
import socket
import subprocess
import sys
import time
import unittest
import uuid

from tools.materialize_southbound_kernel import materialize


def configuration():
    return {'tableName': 'ouf_test', 'guardedInterfaces': ['guard0'], 'existingInterfaces': ['existing0'],
            'staticFlows': [], 'providerFlows': [{'endpointRef': 'registered-provider',
                'endpoint': 'https://repository.example/sparql', 'source': '10.90.0.1',
                'addresses': ['10.90.0.2'], 'leaseSeconds': 30,
                'resolutionEvidenceRef': 'fixture-resolution', 'allowedPrivateAddresses': ['10.90.0.2']}]}


class KernelPlanTest(unittest.TestCase):
    def test_scoped_bounded_plan_without_install_or_dns_claim(self):
        value = materialize(configuration())
        rules = value['nftRules']
        self.assertFalse(value['installed'])
        self.assertFalse(value['fqdnPolicyProven'])
        self.assertIn('timeout 30s', rules)
        self.assertIn('type filter hook input', rules)
        self.assertIn('type filter hook output', rules)
        self.assertIn('type filter hook forward', rules)
        self.assertIn('table bridge ouf_test', rules)
        self.assertIn('meta ibrname { "guard0" } jump governed_bridge_flows', rules)
        self.assertEqual(value['tableFamilies'], ['inet', 'bridge'])
        self.assertIn('ip daddr @provider_0 tcp dport 443', rules)
        self.assertIn('ip saddr @provider_0 ip daddr 10.90.0.1', rules)
        self.assertNotIn('ct state established,related accept', rules)
        self.assertNotIn('flush ruleset', rules)
        self.assertNotIn('0.0.0.0/0', rules)

    def test_shared_interface_and_injection_rejected(self):
        for interface in ('existing0', 'x";accept', 'lo;flush ruleset', 'a'*16):
            cfg = configuration(); cfg['guardedInterfaces'] = [interface]
            with self.assertRaises(ValueError): materialize(cfg)
        cfg = configuration(); cfg['tableName'] = 'x;flush ruleset'
        with self.assertRaises(ValueError): materialize(cfg)

    def test_lease_and_port_bounds(self):
        for lease in (0, -1, 3601, True, '30'):
            cfg = configuration(); cfg['providerFlows'][0]['leaseSeconds'] = lease
            with self.assertRaises(ValueError): materialize(cfg)
        for endpoint in ('http://host/sparql', 'https://user:password@host/sparql', 'https://host:0', 'https://host?q=arbitrary'):
            cfg = configuration(); cfg['providerFlows'][0]['endpoint'] = endpoint
            with self.assertRaises(ValueError): materialize(cfg)

    def test_address_classes_and_no_cidrs(self):
        for address in ('0.0.0.0/0', '169.254.169.254', '127.0.0.1', '0.0.0.0', '224.0.0.1', '100.64.0.1'):
            cfg = configuration(); cfg['providerFlows'][0]['addresses'] = [address]
            cfg['providerFlows'][0]['allowedPrivateAddresses'] = []
            with self.assertRaises(ValueError): materialize(cfg)

    def test_private_exception_is_exact_and_used(self):
        cfg = configuration(); cfg['providerFlows'][0]['allowedPrivateAddresses'] = []
        with self.assertRaises(ValueError): materialize(cfg)
        cfg['providerFlows'][0]['allowedPrivateAddresses'] = ['10.90.0.3']
        with self.assertRaises(ValueError): materialize(cfg)

    def test_ipv6_uses_same_timed_guard(self):
        cfg = configuration(); flow = cfg['providerFlows'][0]
        flow.update(source='fd90::1', addresses=['fd90::2'], allowedPrivateAddresses=['fd90::2'])
        rules = materialize(cfg)['nftRules']
        self.assertIn('type ipv6_addr', rules)
        self.assertIn('ip6 daddr @provider_0 tcp dport 443', rules)
        flow['addresses'] = ['10.90.0.2']
        with self.assertRaises(ValueError): materialize(cfg)

    def test_infrastructure_pair_and_reply_are_exact(self):
        cfg = configuration(); cfg['staticFlows'] = [{'purpose': 'DNS', 'source': '10.90.0.1',
            'destination': '10.90.0.53', 'protocol': 'udp', 'port': 53}]
        rules = materialize(cfg)['nftRules']
        self.assertIn('ip saddr 10.90.0.53 ip daddr 10.90.0.1 udp sport 53 ct state established', rules)
        cfg['staticFlows'][0]['purpose'] = 'GENERIC_INTERNET'
        with self.assertRaises(ValueError): materialize(cfg)
        cfg['staticFlows'][0]['purpose'] = 'DNS'; cfg['staticFlows'][0]['port'] = 5353
        with self.assertRaises(ValueError): materialize(cfg)

    def test_extra_fields_and_unbounded_lists_rejected(self):
        cfg = configuration(); cfg['allowInternet'] = True
        with self.assertRaises(ValueError): materialize(cfg)
        cfg = configuration(); cfg['providerFlows'] *= 17
        with self.assertRaises(ValueError): materialize(cfg)


@unittest.skipUnless(os.environ.get('OUF_SOUTHBOUND_KERNEL_TEST') == '1', 'isolated root netns/nft fixture is opt-in')
class KernelPacketTest(unittest.TestCase):
    def test_real_kernel_default_deny_and_open_socket_lease_expiry(self):
        self.assertEqual(os.geteuid(), 0, 'CI must run this fixture as root')
        prefix = 'ouf-nft-' + uuid.uuid4().hex[:8]
        client, server = prefix+'-c', prefix+'-s'
        namespaces = []; processes = []
        def run(*args, input=None):
            return subprocess.run(args, input=input, text=True, capture_output=True, timeout=20, check=True).stdout
        echo = '''import socket,threading
def serve(port):
 s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(("10.90.0.2",port));s.listen()
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
threading.Thread(target=serve,args=(443,),daemon=True).start()
serve(8443)
'''
        def probe(port):
            raw = run('ip', 'netns', 'exec', client, sys.executable, '-B', '-c',
                'import socket,json; s=socket.socket();s.settimeout(0.5)\ntry:\n s.connect(("10.90.0.2",'+str(port)+'));s.sendall(b"probe");print(json.dumps(s.recv(10)==b"probe"))\nexcept OSError:print("false")\nfinally:s.close()')
            return json.loads(raw)
        try:
            for ns in (client, server):
                run('ip', 'netns', 'add', ns); namespaces.append(ns)
                run('ip', '-n', ns, 'link', 'set', 'lo', 'up')
            # Create the pair directly in its namespaces, leaving host links alone.
            run('ip', '-n', client, 'link', 'add', 'guard0', 'type', 'veth', 'peer', 'name', 'peer0', 'netns', server)
            for ns, interface, address in ((client, 'guard0', '10.90.0.1/24'), (server, 'peer0', '10.90.0.2/24')):
                run('ip', '-n', ns, 'address', 'add', address, 'dev', interface)
                run('ip', '-n', ns, 'link', 'set', interface, 'up')
            process = subprocess.Popen(['ip', 'netns', 'exec', server, sys.executable, '-B', '-c', echo], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            processes.append(process)
            deadline = time.monotonic()+5
            while not (probe(443) and probe(8443)):
                if time.monotonic() >= deadline: self.fail('fixture baseline connectivity missing')
                time.sleep(0.1)
            # Start with a deny-only table: ordinary new connections are blocked.
            cfg = configuration(); cfg['providerFlows'] = []
            run('ip', 'netns', 'exec', client, 'nft', '-f', '-', input=materialize(cfg)['nftRules'])
            self.assertFalse(probe(443)); self.assertFalse(probe(8443))
            run('ip', 'netns', 'exec', client, 'nft', '-f', '-', input='delete table inet ouf_test\ndelete table bridge ouf_test\n')
            cfg = configuration(); cfg['providerFlows'][0]['leaseSeconds'] = 5
            run('ip', 'netns', 'exec', client, 'nft', '-f', '-', input=materialize(cfg)['nftRules'])
            self.assertTrue(probe(443)); self.assertFalse(probe(8443))
            # Hold one established socket across expiry; a broad conntrack
            # ACCEPT would wrongly allow this exchange after its address lease.
            persistent = subprocess.Popen(['ip', 'netns', 'exec', client, sys.executable, '-B', '-c',
                'import socket,time; s=socket.socket();s.settimeout(0.7);s.connect(("10.90.0.2",443));s.sendall(b"before");assert s.recv(20)==b"before";print("OPEN",flush=True);time.sleep(6)\ntry:\n s.sendall(b"after");print("LEAK" if s.recv(20)==b"after" else "CLOSED",flush=True)\nexcept OSError:print("BLOCKED",flush=True)\nfinally:s.close()'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            processes.append(persistent)
            out, err = persistent.communicate(timeout=10)
            self.assertEqual(persistent.returncode, 0, err)
            self.assertIn('OPEN', out); self.assertNotIn('LEAK', out)
            self.assertFalse(probe(443))
            readback = run('ip', 'netns', 'exec', client, 'nft', '-j', 'list', 'table', 'inet', 'ouf_test')
            self.assertIn('governed_flows', readback)
            print('SOUTHBOUND_KERNEL_CI=PASS REAL_NFT_NETNS=true DEFAULT_DENY=true LEASE_EXPIRY_NEW_AND_ESTABLISHED_DENIED=true DOCKER_HOOK_NOT_PROVEN=true PROVIDER_CALLS=0 NOT_RELEASE_ACCEPTANCE=true')
        finally:
            for process in reversed(processes):
                if process.poll() is None:
                    process.terminate()
                    try: process.wait(timeout=3)
                    except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=3)
            for ns in reversed(namespaces):
                subprocess.run(['ip', 'netns', 'delete', ns], capture_output=True, timeout=10)


if __name__ == '__main__':
    unittest.main()
