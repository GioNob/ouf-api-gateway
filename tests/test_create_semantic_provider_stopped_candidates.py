"""Real Docker create/connect/inspect/cleanup; synthetic inputs, no container start or provider call."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import uuid
from unittest.mock import patch
from scripts import create_semantic_provider_stopped_candidates as creator
from scripts import inventory_semantic_provider_static_ipam as ipam

@unittest.skipUnless(os.environ.get('OUF_STOPPED_CREATE_DOCKER_TEST')=='1','native Docker fixture is opt-in')
class StoppedCreateDockerTest(unittest.TestCase):
    def setUp(self):
        self.assertEqual(os.geteuid(),0)
        self.tmp=tempfile.TemporaryDirectory(dir=os.environ.get('OUF_STOPPED_CREATE_TEST_PARENT','/root'))
        self.root=Path(self.tmp.name)
        self.suffix=uuid.uuid4().hex[:10]
        self.networks=[];self.names=[]
        self.addCleanup(self.cleanup_fixture)
        image=os.environ['OUF_STOPPED_CREATE_TEST_IMAGE']
        self.assertRegex(image,r'^[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[0-9a-f]{64}$')
        self.image=json.loads(self.docker('image','inspect',image))[0]
        for role in ('backend','internal','egress'):
            name='ouf-stopped-'+role+'-'+self.suffix
            options=['network','create','--label','ouf.fixture='+self.suffix]
            if role!='egress':options+=['--internal']
            # Obtain a daemon-selected free subnet, then explicitly configure it
            # on a new empty fixture network. Static IPs require user-configured IPAM.
            probe=name+'-allocation'
            self.docker(*options,probe)
            allocated=json.loads(self.docker('network','inspect',probe))[0]['IPAM']['Config'][0]
            self.docker('network','rm',probe)
            self.docker(*options,'--subnet',allocated['Subnet'],'--gateway',allocated['Gateway'],name)
            self.networks.append(name)
        netrows=[json.loads(self.docker('network','inspect',name))[0] for name in self.networks]
        ips=[creator.stage.reserve(row,2) for row in netrows]
        config=self.root/'private.json';creator.validator.write(config,b'{"fixture":true}')
        env=self.root/'private.env';creator.validator.write(env,b'FIXTURE_VALIDATOR_SECRET=synthetic-test-only\n')
        specs=[]
        for index,role in enumerate(('southbound','adapter')):
            name='ouf-stopped-'+role+'-'+self.suffix;self.names.append(name)
            selected=range(3) if index==0 else (1,2)
            specs.append({'name':name,'image':self.image['Id'],'user':'10006:10006','restartPolicy':'no','publishPorts':[],
                'readOnlyRoot':index==1,'memoryBytes':134217728,'pidsLimit':64,'dnsServers':['192.0.2.53'],
                'command':[] if index==0 else ['-B','-c','raise SystemExit(99)'],
                'mounts':[{'source':str(config),'target':'/private/fixture.json','readOnly':True}],
                'envFile':str(env) if index==0 else None,
                'networks':[{'name':netrows[i]['Name'],'id':netrows[i]['Id'],'ipv4':ips[i][index]} for i in selected]})
        self.manifest={'schema':'ouf.semantic-provider-stopped-manifest.v1','startAuthorized':False,'containersCreated':0,'containers':specs,
            'sourceHashes':{p.name:creator.validator.digest(p.read_bytes()) for p in (Path(creator.stage.__file__),Path(creator.launch.__file__),Path(creator.inputs.__file__),Path(creator.validator.__file__))}}
        mroot=self.root/'manifest';mroot.mkdir(mode=0o700)
        creator.validator.write(mroot/'stopped-manifest.json',creator.validator.encoded(self.manifest))
        self.args=argparse.Namespace(mode='plan',source_commit='a'*40,creation_root=self.root/'transaction',manifest_root=mroot,docker_path='/usr/bin/docker')
        self.gate=patch.object(creator,'verify_inputs',return_value='0'*64);self.gate.start();self.addCleanup(self.gate.stop)
    def docker(self,*options):
        result=subprocess.run(['/usr/bin/docker',*options],capture_output=True,text=True,timeout=60)
        if result.returncode:raise AssertionError('fixture Docker operation failed: '+str(options[:2]))
        return result.stdout.strip()
    def cleanup_fixture(self):
        # Only this fixture's exact random names. Never starts/kills/removes a running workload.
        for name in reversed(self.names):
            result=subprocess.run(['/usr/bin/docker','inspect','--type','container',name],capture_output=True,text=True)
            if result.returncode==0:
                raw=json.loads(result.stdout)[0]
                self.assertFalse(raw['State']['Running'])
                self.assertTrue(raw['State']['StartedAt'].startswith('0001-01-01T'))
                self.docker('rm',raw['Id'])
        for name in reversed(self.networks):self.docker('network','rm',name)
        self.tmp.cleanup()
    def test_real_create_verify_cleanup_never_started(self):
        planned=creator.operate(self.args);self.assertEqual(planned['state'],'PLANNED')
        self.assertFalse(self.args.creation_root.exists())
        self.args.mode='apply';result=creator.operate(self.args)
        self.assertEqual(result['state'],'CREATED_STOPPED');self.assertEqual(len(result['candidateIds']),2)
        self.args.mode='verify';creator.operate(self.args)
        self.assertEqual((self.args.creation_root/'creation-journal.json').stat().st_mode & 0o777,0o600)
        self.args.mode='cleanup';creator.operate(self.args)
        creator.operate(self.args) # journal-backed idempotent cleanup
        self.assertFalse(self.docker('ps','-a','--filter','label='+creator.OWNER+'='+result['transaction'],'--format','{{.ID}}'))
        print('STOPPED_CREATE_DOCKER=PASS CREATED=2 NEVER_STARTED=true PRIVATE_MOUNTS_RO=true CONNECTED_CONFIG_VERIFIED=true CLEANUP_OWNED_ONLY=true PROVIDER_CALLS=0 NOT_RELEASE_ACCEPTANCE=true')
    def test_interrupted_connection_retained_and_owned_cleanup(self):
        original=creator.command
        def interrupted(args,*options):
            if options[:2]==('network','connect'):raise creator.inputs.Blocked('FIXTURE_INTERRUPTED_CONNECTION')
            return original(args,*options)
        self.args.mode='apply'
        with patch.object(creator,'command',side_effect=interrupted):
            with self.assertRaisesRegex(creator.inputs.Blocked,'FIXTURE_INTERRUPTED_CONNECTION'):creator.operate(self.args)
        journal,_=creator.inputs.private_json(self.args.creation_root/'creation-journal.json')
        self.assertEqual(journal['state'],'CREATING');self.assertEqual(len(journal['candidateIds']),1)
        self.args.mode='verify'
        with self.assertRaisesRegex(creator.inputs.Blocked,'PARTIAL_CREATION_REQUIRES_RECONCILIATION'):creator.operate(self.args)
        self.args.mode='cleanup';creator.operate(self.args)
    def test_host_config_drift_and_foreign_owner_cleanup_denied(self):
        self.args.mode='apply';journal=creator.operate(self.args)
        cid=journal['candidateIds'][self.names[0]]
        self.docker('update','--restart','always',cid)
        self.args.mode='verify'
        with self.assertRaisesRegex(creator.inputs.Blocked,'CANDIDATE_HOST_CONFIG_DRIFT'):creator.operate(self.args)
        # A modified journal transaction must not delete containers belonging to the original transaction.
        altered=dict(journal,transaction='foreign')
        creator.save(self.args.creation_root/'creation-journal.json',altered)
        self.args.mode='cleanup'
        with self.assertRaisesRegex(creator.inputs.Blocked,'OWNERSHIP_OR_NEVER_STARTED_STATE_UNPROVEN'):creator.operate(self.args)
        self.assertEqual(json.loads(self.docker('inspect',cid))[0]['Id'],cid)
        creator.save(self.args.creation_root/'creation-journal.json',journal)
        self.docker('update','--restart','no',cid)
        creator.operate(self.args)
    def test_static_ipam_runtime_discovery_and_explicit_profile_without_start(self):
        name='ouf-stopped-auto-'+self.suffix
        self.docker('network','create','--internal','--label','ouf.fixture='+self.suffix,name)
        self.networks.append(name)
        automatic=json.loads(self.docker('network','inspect',name))[0]
        explicit=json.loads(self.docker('network','inspect',self.networks[0]))[0]
        args=argparse.Namespace(mode='plan',source_commit='b'*40,docker_path='/usr/bin/docker',image_id=self.image['Id'],
            probe_entrypoint='/bin/false',snapshot_root=self.root/'ipam',network=[name+'='+automatic['Id'],explicit['Name']+'='+explicit['Id']])
        ipam.operate(args);self.assertFalse(args.snapshot_root.exists())
        args.mode='apply';result=ipam.operate(args)
        self.assertTrue(result['results'][1]['staticIpSupported'])
        self.assertEqual(result['staticIpReady'],all(r['staticIpSupported'] for r in result['results']))
        self.assertTrue(all(r['probeRemoved'] for r in result['results']))
        args.mode='verify';ipam.operate(args)
        self.assertFalse(self.docker('ps','-a','--filter','name=ouf-ipam-probe-','--format','{{.ID}}'))

if __name__=='__main__':unittest.main()
