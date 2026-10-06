"""Private manifest filesystem and simulated inspect-only Docker/kernel readback."""
import argparse
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from scripts import stage_semantic_provider_candidates as stage

@unittest.skipUnless(os.geteuid()==0,'root-owned private manifest fixtures required')
class StoppedManifestTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=os.environ.get('OUF_MANIFEST_TEST_PARENT',str(Path.cwd())))
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.args=argparse.Namespace(mode='plan',source_commit='a'*40,launch_source_commit='b'*40,validator_source_commit='c'*40,
            snapshot_root=self.root/'prepared',launch_root=self.root/'launch',trust_root=self.root/'trust',tls_root=self.root/'tls',
            runtime_root=self.root/'runtime',network_root=self.root/'cold',docker_path='/usr/bin/docker',nft_path='/usr/sbin/nft',
            backend_network='backend',gateway_container='gateway',adapter_container='adapter-fixture',southbound_container='southbound-fixture',
            adapter_configuration_target='/private/adapter.json',gateway_configuration_target='/gateway/config.yaml',
            gateway_resources_target='/gateway/apisix.yaml',memory_bytes=268435456,pids_limit=128)
        for name in ('launch','trust','tls','runtime','cold'):(self.root/name).mkdir(mode=0o700)
        self.tables={'inet':{'nftables':[{'table':{'family':'inet','name':'guard'}}]},
                     'bridge':{'nftables':[{'table':{'family':'bridge','name':'guard'}}]}}
        def net(name,nid,internal,subnet,bridge=None):
            return {'Name':name,'Id':nid,'Driver':'bridge','Internal':internal,'EnableIPv6':False,
                'IPAM':{'Driver':'default','Config':[{'Subnet':subnet,'Gateway':str(__import__('ipaddress').ip_network(subnet).network_address+1)}]},
                'Containers':{},'Labels':{'ouf.cold-network.owner':'installation-fixture'},
                'Options':{'com.docker.network.bridge.name':bridge}}
        self.networks={'internal':net('internal','1'*64,True,'10.91.0.0/24','bridge-in'),
            'egress':net('egress','2'*64,False,'10.92.0.0/24','bridge-out'),
            'backend':net('backend','3'*64,True,'10.93.0.0/24')}
        self.names=''
        self.trust={'intent':{'installation':'installation-fixture','adapterHostname':'adapter-fixture','southboundHostname':'southbound-fixture',
            'adapterImage':{'id':'sha256:'+'4'*64,'runtimeUser':'10006:10006'},
            'gateway':{'image':'sha256:'+'5'*64,'user':'apisix','uid':636,'gid':636}}}
        binding={'routes':{'installation':'installation-fixture','tlsProfile':{'trustedCertificateFile':'/private/trust.pem'}},
            'adapter':{'tlsCertificateFile':'/private/server.crt','tlsPrivateKeyFile':'/private/server.key','receiptKeyFile':'/private/receipt.key',
                       'provider':{'ca_file':'/private/trust.pem'}},'dns':{'resolvers':['192.0.2.53'],'networkIPVersion':4}}
        cold={'schema':'ouf.semantic-provider-cold-networks.v1','notReleaseAcceptance':True,
            'binding':{'installation_id':'installation-fixture','internal_network':'internal','egress_network':'egress',
                'internal_bridge':'bridge-in','egress_bridge':'bridge-out','table_name':'guard'},
            'networkIds':{'internal':'1'*64,'egress':'2'*64},
            'guardHash':stage.validator.digest(stage.validator.encoded(stage.canonical(self.tables)))}
        for root,name,value in [(self.args.launch_root,'launch-input-receipt.json',{'fixture':'verified'}),
            (self.args.trust_root,'trust-receipt.json',self.trust),(self.args.tls_root,'tls-runtime-receipt.json',{}),
            (self.args.runtime_root,'binding.json',binding),(self.args.network_root,'network-receipt.json',cold)]:
            stage.validator.write(root/name,stage.validator.encoded(value))
        def read(command,**kwargs):
            if command[0]==self.args.nft_path:return json.dumps(self.tables[command[4]])
            if command[1:3]==['network','inspect']:return json.dumps([self.networks[command[3]]])
            if command[1:3]==['image','inspect']:return json.dumps([{'Id':'sha256:'+'5'*64,'Config':{'User':'apisix',
                'Entrypoint':['/entrypoint.sh'],'Cmd':['docker-start'],'WorkingDir':'/gateway','Env':['SECRET=never-serialize-this']}}])
            if command[1]=='inspect':return json.dumps([{'Config':{'Env':['SECRET=never-serialize-this']},
                'NetworkSettings':{'Networks':{'backend':{'NetworkID':'3'*64}}}}])
            if command[1]=='ps':return self.names
            raise AssertionError('unexpected/mutating command '+str(command))
        self.addCleanup(patch.stopall)
        patch.object(stage.inputs,'run',side_effect=read).start()
        patch.object(stage.launch,'operate',return_value={'fixture':'verified'}).start()
    def test_plan_apply_verify_stopped_minimal_manifest(self):
        intent=stage.operate(self.args)
        self.assertFalse(self.args.snapshot_root.exists())
        self.assertFalse(intent['startAuthorized'])
        self.assertNotIn('never-serialize-this',json.dumps(intent))
        self.assertEqual(intent['containers'][1]['networks'][0]['ipv4'],'10.91.0.3')
        self.assertTrue(all(m['readOnly'] for c in intent['containers'] for m in c['mounts']))
        self.assertTrue(all(c['restartPolicy']=='no' and c['publishPorts']==[] for c in intent['containers']))
        self.args.mode='apply';stage.operate(self.args)
        path=self.args.snapshot_root/'stopped-manifest.json';self.assertEqual(path.stat().st_mode & 0o777,0o600)
        self.args.mode='verify';stage.operate(self.args)
        path.write_text('{}')
        with self.assertRaisesRegex(stage.inputs.Blocked,'STOPPED_MANIFEST_DRIFT_NO_OVERWRITE'):stage.operate(self.args)
    def test_occupied_cold_network_or_existing_name_denied(self):
        self.networks['internal']['Containers']={'other':{'IPv4Address':'10.91.0.9/24'}}
        with self.assertRaisesRegex(stage.inputs.Blocked,'OWNED_EMPTY_NETWORK_REQUIRED'):stage.operate(self.args)
        self.networks['internal']['Containers']={};self.names='adapter-fixture\n'
        with self.assertRaisesRegex(stage.inputs.Blocked,'CANDIDATE_NAME_EXISTS_RECONCILE'):stage.operate(self.args)
    def test_guard_and_network_id_changes_denied(self):
        self.tables['inet']['nftables'].append({'rule':{'expr':[{'accept':None}]}})
        with self.assertRaisesRegex(stage.inputs.Blocked,'COLD_DENY_GUARD_CHANGED_RECONCILE'):stage.operate(self.args)
        self.tables['inet']['nftables'].pop();self.networks['internal']['Id']='6'*64
        with self.assertRaisesRegex(stage.inputs.Blocked,'CANDIDATE_NETWORK_BINDING_DRIFT'):stage.operate(self.args)
    def test_no_overwrite_existing_manifest_root(self):
        self.args.snapshot_root.mkdir(mode=0o700)
        self.args.mode='apply'
        with self.assertRaisesRegex(stage.inputs.Blocked,'MANIFEST_ROOT_EXISTS_RECONCILE'):stage.operate(self.args)
    def test_backend_allocation_avoids_gateway_and_existing_endpoints(self):
        self.networks['backend']['Containers']={'existing':{'IPv4Address':'10.93.0.2/24'}}
        manifest=stage.operate(self.args)
        self.assertEqual(manifest['containers'][0]['networks'][0]['ipv4'],'10.93.0.3')

if __name__=='__main__':unittest.main()
