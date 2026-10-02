import contextlib
import copy
import io
import json
import os
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid

from scripts import inventory_semantic_provider_network as module


class NetworkInventoryTest(unittest.TestCase):
    def setUp(self):
        self.args = SimpleNamespace(docker_path='docker', ip_path='ip',
                                    gateway_container='gw', expected_gateway_id='a'*64,
                                    semantic_container='sem', ingestion_container='ing')
        self.nid = '1'*64
        self.raw_network = {'Id': self.nid, 'Name': 'arbitrary-install-network',
                            'Driver': 'bridge', 'Internal': True, 'EnableIPv6': False,
                            'Options': {'com.docker.network.bridge.name': 'custom-br'},
                            'IPAM': {'Config': [{'Subnet': '10.77.0.0/24', 'Gateway': '10.77.0.1'}]}}
        self.raw_workloads = {}
        for index, (name, cid) in enumerate([('gw', 'a'), ('sem', 'b'), ('ing', 'c')], 2):
            self.raw_workloads[name] = {'Id': cid*64, 'Image': 'sha256:' + cid*64,
                                       'State': {'Running': True}, 'HostConfig': {'NetworkMode': 'arbitrary-install-network'},
                                       'Config': {'Env': ['SECRET=DO_NOT_EXPOSE']},
                                       'Mounts': [{'Source': '/private/DO_NOT_EXPOSE'}],
                                       'NetworkSettings': {'Networks': {'arbitrary-install-network': {
                                           'NetworkID': self.nid, 'IPAddress': '10.77.0.' + str(index),
                                           'GlobalIPv6Address': ''}}}}
        self.links = [{'ifname': 'custom-br', 'ifindex': 42, 'linkinfo': {'info_kind': 'bridge'}}]
        self.commands = []

    def read(self, command):
        self.commands.append(command)
        if command[0] == 'ip':
            return copy.deepcopy(self.links)
        if command[1:3] == ['network', 'inspect']:
            return [copy.deepcopy(self.raw_network)]
        if command[1:4] == ['inspect', '--type', 'container']:
            return [copy.deepcopy(self.raw_workloads[command[-1]])]
        self.fail('unexpected command')

    def collect(self):
        with patch.object(module, 'read_json', side_effect=self.read):
            return module.collect(self.args)

    def test_selected_read_only_facts_and_redaction(self):
        result = self.collect()
        self.assertTrue(result['bridgeBindingsReady'])
        self.assertFalse(result['egressDefaultDenyProven'])
        self.assertFalse(result['fqdnPolicyProven'])
        self.assertFalse(result['atomicSnapshotProven'])
        self.assertEqual(result['networks'][0]['bridgeIfindex'], 42)
        self.assertNotIn('DO_NOT_EXPOSE', json.dumps(result))
        self.assertEqual(len(self.commands), 10)
        self.assertFalse(any(set(command) & {'exec', 'run', 'create', 'connect', 'iptables', 'nft'} for command in self.commands))

    def test_wrong_gateway_id(self):
        self.args.expected_gateway_id = 'd'*64
        with self.assertRaisesRegex(module.Blocked, 'GATEWAY_ID_MISMATCH'):
            self.collect()

    def test_role_alias_and_option_like_name_rejected_before_read(self):
        for name in ('--help', 'sem'):
            self.args.gateway_container = name
            with self.assertRaises(module.Blocked):
                self.collect()
        self.assertEqual(self.commands, [])

    def test_absent_or_wrong_link_kind_is_not_proof(self):
        for links in ([], [{'ifname': 'custom-br', 'ifindex': 42, 'linkinfo': {'info_kind': 'dummy'}}]):
            self.links = links
            self.assertFalse(self.collect()['bridgeBindingsReady'])

    def test_default_network_does_not_invent_bridge(self):
        self.raw_network.update(Name='bridge', Options={})
        for value in self.raw_workloads.values():
            value['NetworkSettings']['Networks']['bridge'] = value['NetworkSettings']['Networks'].pop('arbitrary-install-network')
        result = self.collect()
        self.assertIsNone(result['networks'][0]['bridgeName'])
        self.assertFalse(result['bridgeBindingsReady'])

    def test_bridge_id_convention_is_observed(self):
        self.raw_network['Options'] = {}
        self.links[0]['ifname'] = 'br-' + self.nid[:12]
        self.assertTrue(self.collect()['bridgeBindingsReady'])

    def test_ipv6_dual_stack(self):
        self.raw_network['EnableIPv6'] = True
        self.raw_network['IPAM']['Config'].append({'Subnet': 'fd77::/64', 'Gateway': 'fd77::1'})
        self.raw_workloads['sem']['NetworkSettings']['Networks']['arbitrary-install-network']['GlobalIPv6Address'] = 'fd77::3'
        self.assertEqual(self.collect()['workloads'][1]['networks'][0]['ipv6'], 'fd77::3')

    def test_network_gateway_and_workload_address_outside_subnet(self):
        self.raw_network['IPAM']['Config'][0]['Gateway'] = '10.88.0.1'
        with self.assertRaisesRegex(module.Blocked, 'NETWORK_GATEWAY_OUTSIDE_SUBNET'):
            self.collect()
        self.raw_network['IPAM']['Config'][0]['Gateway'] = '10.77.0.1'
        self.raw_workloads['sem']['NetworkSettings']['Networks']['arbitrary-install-network']['IPAddress'] = '10.88.0.3'
        with self.assertRaisesRegex(module.Blocked, 'WORKLOAD_ADDRESS_OUTSIDE_SUBNET'):
            self.collect()

    def test_unsupported_mode_driver_stopped_and_name_id_mismatch(self):
        for mode in ('host', 'none', 'container:another'):
            self.raw_workloads['sem']['HostConfig']['NetworkMode'] = mode
            with self.assertRaisesRegex(module.Blocked, 'BRIDGE_WORKLOAD_BINDING_REQUIRED'):
                self.collect()
        self.raw_workloads['sem']['HostConfig']['NetworkMode'] = 'arbitrary-install-network'
        self.raw_network['Driver'] = 'overlay'
        with self.assertRaisesRegex(module.Blocked, 'SELECTED_BRIDGE_NETWORK_UNPROVEN'):
            self.collect()
        self.raw_network['Driver'] = 'bridge'
        self.raw_workloads['sem']['State']['Running'] = False
        with self.assertRaisesRegex(module.Blocked, 'SELECTED_WORKLOAD_NOT_RUNNING'):
            self.collect()
        self.raw_workloads['sem']['State']['Running'] = True
        self.raw_network['Name'] = 'other'
        with self.assertRaisesRegex(module.Blocked, 'NETWORK_NAME_ID_MISMATCH'):
            self.collect()

    def test_changed_topology_blocks(self):
        count = 0
        def changing(command):
            nonlocal count
            value = self.read(command)
            if command[0] == 'ip':
                count += 1
                if count == 2:
                    value[0]['ifindex'] += 1
            return value
        with patch.object(module, 'read_json', side_effect=changing):
            with self.assertRaisesRegex(module.Blocked, 'SELECTED_TOPOLOGY_CHANGED'):
                module.collect(self.args)

    def test_cli_redacts_unexpected_failure(self):
        output = io.StringIO()
        with patch.object(module.os, 'geteuid', return_value=0), patch.object(module, 'collect', side_effect=ValueError('SECRET')):
            with contextlib.redirect_stdout(output):
                status = module.main(['--gateway-container', 'gw', '--expected-gateway-id', 'a'*64,
                                      '--semantic-container', 'sem', '--ingestion-container', 'ing'])
        self.assertEqual(status, 1)
        self.assertIn('INVENTORY_UNPROVEN', output.getvalue())
        self.assertNotIn('SECRET\n', output.getvalue())


@unittest.skipUnless(os.environ.get('OUF_PROVIDER_NETWORK_TEST') == '1', 'real Docker network fixture is opt-in')
class DockerNetworkInventoryTest(unittest.TestCase):
    def test_real_selected_bridge_topology(self):
        image = os.environ['OUF_PROVIDER_NETWORK_TEST_IMAGE']
        self.assertRegex(image, r'@sha256:[0-9a-f]{64}$')
        suffix = uuid.uuid4().hex[:8]
        network_name = 'ouf-network-fixture-' + suffix
        bridge_name = 'ouft-' + suffix
        names = ['ouf-' + role + '-' + suffix for role in ('gw', 'sem', 'ing')]
        def run(*command):
            return subprocess.run(command, capture_output=True, text=True, timeout=90, check=True).stdout.strip()
        created = []
        net_created = False
        try:
            run('docker', 'pull', image)
            run('docker', 'network', 'create', '--internal', '--driver', 'bridge',
                '--opt', 'com.docker.network.bridge.name=' + bridge_name, network_name)
            net_created = True
            for name in names:
                run('docker', 'run', '-d', '--name', name, '--network', network_name,
                    '--read-only', '--cap-drop=ALL', '--security-opt', 'no-new-privileges',
                    image, 'python3', '-B', '-c', 'import time; time.sleep(240)')
                created.append(name)
            gateway_id = run('docker', 'inspect', '--format', '{{.Id}}', names[0])
            args = SimpleNamespace(docker_path='docker', ip_path='ip', gateway_container=names[0],
                                   expected_gateway_id=gateway_id, semantic_container=names[1], ingestion_container=names[2])
            result = module.collect(args)
            self.assertTrue(result['bridgeBindingsReady'])
            self.assertEqual(result['networks'][0]['bridgeName'], bridge_name)
            self.assertTrue(result['networks'][0]['internal'])
            self.assertEqual(len(result['workloads']), 3)
            self.assertFalse(result['egressDefaultDenyProven'])
            self.assertFalse(result['fqdnPolicyProven'])
            print('SEMANTIC_PROVIDER_NETWORK_CI=PASS REAL_DOCKER_BRIDGE=true PROVIDER_CALLS=0 NOT_RELEASE_ACCEPTANCE=true')
        finally:
            for name in reversed(created):
                subprocess.run(['docker', 'rm', '-f', name], capture_output=True, timeout=30)
            if net_created:
                subprocess.run(['docker', 'network', 'rm', network_name], capture_output=True, timeout=30)


if __name__ == '__main__':
    unittest.main()
