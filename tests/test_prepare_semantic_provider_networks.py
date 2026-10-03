"""Cold network preparation: real Docker/nft required in its CI gate."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import shutil
import subprocess
import unittest
import uuid

from scripts import prepare_semantic_provider_networks as prep
from scripts import inventory_semantic_provider_network as inventory


class ValidationTest(unittest.TestCase):
    def test_overlap_rejected_and_counters_ignored(self):
        with self.assertRaisesRegex(prep.trust.Blocked, 'OVERLAP'):
            prep.reject_overlap([ipaddress.ip_network('10.80.0.0/24'), ipaddress.ip_network('10.81.0.0/24')],
                                [ipaddress.ip_network('10.0.0.0/8')])
        prep.reject_overlap([ipaddress.ip_network('10.80.0.0/24'), ipaddress.ip_network('10.81.0.0/24')], [])
        self.assertEqual(prep.fingerprint({'counter': {'packets': 4, 'bytes': 50}}),
                         prep.fingerprint({'counter': {'packets': 8, 'bytes': 100}}))
        self.assertNotEqual(prep.fingerprint({'verdict': 'accept'}), prep.fingerprint({'verdict': 'drop'}))


@unittest.skipUnless(os.environ.get('OUF_COLD_NETWORK_TEST') == '1', 'real root Docker/nft gate is opt-in')
class RealColdNetworkTest(unittest.TestCase):
    def test_plan_apply_verify_collision_guard_tampering_and_cleanup(self):
        self.assertEqual(os.geteuid(), 0)
        image = os.environ['OUF_COLD_NETWORK_IMAGE']
        suffix = uuid.uuid4().hex[:8]
        root = Path('/root')/('ouf-cold-fixture-'+suffix)
        shared = 'ouf-cold-baseline-'+suffix
        roles = ['ouf-cold-'+r+'-'+suffix for r in ('gateway', 'semantic', 'ingestion')]
        internal, egress = 'ouf-cold-internal-'+suffix, 'ouf-cold-egress-'+suffix
        table = 'ouf_cold_'+suffix
        attached = []
        def run(*cmd, raw=None):
            return subprocess.run(cmd, input=raw, capture_output=True, text=True, timeout=30, check=True).stdout.strip()
        def network_exists(n):
            return subprocess.run(['docker', 'network', 'inspect', n], capture_output=True).returncode == 0
        try:
            run('docker', 'image', 'inspect', image)
            run('docker', 'network', 'create', '--internal', shared)
            for role in roles:
                run('docker', 'run', '-d', '--pull=never', '--name', role, '--network', shared,
                    '--user', '10006:10006', '--read-only', '--cap-drop=ALL',
                    '--security-opt', 'no-new-privileges', '--pids-limit', '64',
                    image, 'python3', '-B', '-c', 'import time;time.sleep(240)')
                attached.append(role)
            args = argparse.Namespace(mode='plan', snapshot_root=root, installation_id='ci-'+suffix,
                source_commit='1'*40, expected_snapshot_hash='0'*64, gateway_container=roles[0],
                semantic_container=roles[1], ingestion_container=roles[2],
                expected_gateway_id=json.loads(run('docker', 'inspect', roles[0]))[0]['Id'],
                internal_network=internal, egress_network=egress,
                internal_bridge='ocint-'+suffix, egress_bridge='ocegr-'+suffix,
                table_name=table, ipam='docker-auto-ipv4', docker_path='docker', ip_path='ip', nft_path='nft')
            args.expected_snapshot_hash = inventory.collect(args)['snapshotHash']
            self.assertIsNone(prep.operate(args))
            self.assertFalse(root.exists()); self.assertFalse(network_exists(internal))
            args.mode = 'apply'; receipt = prep.operate(args)
            self.assertTrue(receipt['guardInstalledBeforeNetworkCreation'])
            self.assertTrue(receipt['customGuardSharedRulesPreserved'])
            self.assertEqual(len(receipt['networks']), 2)
            args.mode = 'verify'; self.assertEqual(prep.operate(args), receipt)
            # Controlled local packet negatives verify the newly installed guard,
            # rather than accepting mere table existence as a denial proof.
            server = 'ouf-cold-server-'+suffix
            client = 'ouf-cold-client-'+suffix
            code = 'import socket; s=socket.socket();s.bind(("0.0.0.0",15943));s.listen();\nwhile True:\n c,_=s.accept();c.sendall(b"ok");c.close()'
            for container, command in ((server, code), (client, 'import time;time.sleep(240)')):
                run('docker', 'run', '-d', '--pull=never', '--name', container, '--network', internal,
                    '--user', '10006:10006', '--read-only', '--cap-drop=ALL',
                    '--security-opt', 'no-new-privileges', '--pids-limit', '64',
                    image, 'python3', '-B', '-c', command)
                attached.append(container)
            target = json.loads(run('docker', 'inspect', server))[0]['NetworkSettings']['Networks'][internal]['IPAddress']
            probe = 'import socket; s=socket.socket();s.settimeout(0.5)\ntry:\n s.connect((%s,15943));print(s.recv(2)==b"ok")\nexcept OSError:print(False)\nfinally:s.close()'
            self.assertEqual(run('docker', 'exec', server, 'python3', '-B', '-c', probe % repr('127.0.0.1')), 'True')
            self.assertEqual(run('docker', 'exec', client, 'python3', '-B', '-c', probe % repr(target)), 'False')
            with self.assertRaisesRegex(prep.trust.Blocked, 'OWNED_EMPTY_NETWORK'): prep.operate(args)
            for container in (client, server):
                run('docker', 'rm', '-f', container); attached.remove(container)
            self.assertEqual(prep.operate(args), receipt)
            args.mode = 'apply'
            with self.assertRaisesRegex(prep.trust.Blocked, 'SNAPSHOT_EXISTS'): prep.operate(args)
            args.mode = 'verify'
            # A rule changed by another writer must never pass verification.
            run('nft', 'add', 'rule', 'inet', table, 'governed_flows', 'counter', 'accept')
            with self.assertRaisesRegex(prep.trust.Blocked, 'GUARD_OR_INTENT'): prep.operate(args)
            print('SEMANTIC_PROVIDER_COLD_NETWORK_CI=PASS REAL_DOCKER_NFT=true GUARD_BEFORE_NETWORKS=true'
                  ' EMPTY_NETWORKS_VERIFIED=true SHARED_RULES_PRESERVED_BY_CUSTOM_GUARD=true'
                  ' SAME_BRIDGE_PACKET_DENIED=true UNEXPECTED_ATTACHMENT_DENIED=true'
                  ' TAMPERING_DENIED=true PROVIDER_CALLS=0 NOT_RELEASE_ACCEPTANCE=true')
        finally:
            for container in reversed(attached): run('docker', 'rm', '-f', container)
            # Remove networks before guard; retain guard if any endpoint prevents removal.
            for n in (internal, egress, shared):
                if network_exists(n): run('docker', 'network', 'rm', n)
            for family in ('inet', 'bridge'):
                if (family, table) in prep.tables(argparse.Namespace(nft_path='nft')):
                    run('nft', 'delete', 'table', family, table)
            if root.exists(): shutil.rmtree(root)
            print('SEMANTIC_PROVIDER_COLD_NETWORK_CLEANUP=PASS OWNED_NETWORKS_TABLES_AND_FIXTURES_REMOVED=true')
