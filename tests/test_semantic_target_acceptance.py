import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from scripts import inventory_semantic_target_acceptance as h

@unittest.skipUnless(os.geteuid()==0,'root-owned metadata/private evidence fixtures required')
class TargetAcceptanceTest(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory(dir=os.environ.get('OUF_SHARED_COORDINATION_TEST_PARENT',str(Path.cwd())))
        self.addCleanup(t.cleanup);self.root=Path(t.name);self.root.chmod(0o700)
        self.mount=self.root/'key';self.mount.write_bytes(b'SECRET_DO_NOT_READ');self.mount.chmod(0o600)
        self.image='sha256:'+'c'*64;self.net='e'*64;self.specs=[];self.rows={};self.ids={'one':'a'*64,'two':'b'*64}
        for i,n in enumerate(self.ids):
            spec={'name':n,'image':self.image,'user':'1000:1000','command':['/never-run'],'readOnlyRoot':True,
                'memoryBytes':268435456,'pidsLimit':128,'dnsServers':[],
                'mounts':[{'source':str(self.mount),'target':'/key','readOnly':True}],
                'networks':[{'name':'fixture','id':self.net,'ipv4':'192.0.2.'+str(i+2)}]};self.specs.append(spec)
            self.rows[self.ids[n]]={'id':self.ids[n],'name':'/'+n,'image':self.image,'status':'created','running':False,
                'restarting':False,'pid':0,'started':'0001-01-01T00:00:00Z','runtime':'runc','restart':'no','transaction':'d'*32,
                'manifest':'f'*64,'user':spec['user'],'entrypoint':None,'command':spec['command'],'workdir':'','health':['NONE'],
                'privileged':False,'readOnly':True,'memory':268435456,'swap':268435456,'pids':128,'capDrop':['ALL'],
                'capAdd':None,'devices':[],'deviceRequests':None,'ports':{},'dns':[],'mode':self.net,
                'mounts':[{'Source':str(self.mount),'Destination':'/key','Type':'bind','RW':False,'Propagation':'rprivate'}],
                'networks':{'fixture':{'NetworkID':'','IPAMConfig':{'IPv4Address':spec['networks'][0]['ipv4']},'Aliases':[n],'GlobalIPv6Address':''}}}
        self.m={'installation':'independent-entity','containers':self.specs}
        self.j={'candidateIds':self.ids,'transaction':'d'*32,'manifestHash':'f'*64}
        self.img={'id':self.image,'rootfs':{'Type':'layers','Layers':['sha256:'+'1'*64]},'entrypoint':None,'command':None,'workdir':'','volumes':None}
    def query(self,kind,identity):
        if kind=='container':return copy.deepcopy(self.rows[identity])
        if kind=='image':return copy.deepcopy(self.img)
        return {'id':self.net,'name':'fixture','driver':'bridge','ipv6':False}
    def inventory(self,query=None,metadata=h.mount_metadata):return h.inventory(self.m,self.j,query or self.query,metadata)
    def test_no_mount_contents_or_environment_read_and_no_acceptance(self):
        opened=os.open
        def guarded(path,*a,**kw):
            self.assertNotEqual(Path(path),self.mount);return opened(path,*a,**kw)
        with patch.object(os,'open',side_effect=guarded):v=self.inventory()
        self.assertNotIn('SECRET_DO_NOT_READ',json.dumps(v));self.assertNotIn('.Config.Env',h.CONTAINER+h.IMAGE)
        self.assertTrue(all(not r['fullCreationAcceptanceProven'] and not r['environmentRead'] for r in v['candidates']))
    def test_inert_authority_draft_is_not_runtime_policy(self):
        v=h.authority_plan('installation');self.assertNotEqual(v['schema'],v['policySchema']);self.assertIsNone(v['entityRef'])
        self.assertFalse(v['startAuthorized']);self.assertFalse(v['centralAuthorityRequired'])
        self.assertTrue(all(not r['authorized'] and r['publicKey'] is None for r in v['roles']))
    def test_started_privileged_config_and_mount_drift_denied(self):
        cid='a'*64;original=copy.deepcopy(self.rows[cid])
        for k,bad in [('running',True),('pid',42),('privileged',True),('restart','always'),('command',['/changed']),
            ('image','sha256:'+'9'*64),('capAdd',['NET_ADMIN']),('memory',1),('runtime','bad\n'),('manifest','0'*64)]:
            self.rows[cid]={**original,k:bad}
            with self.subTest(key=k),self.assertRaises(h.Blocked):self.inventory()
        self.rows[cid]=original;self.rows[cid]['mounts'][0]['RW']=True
        with self.assertRaises(h.Blocked):self.inventory()
    def test_network_rebind_and_unplanned_image_volume_denied(self):
        self.rows['a'*64]['networks']['fixture']['IPAMConfig']['IPv4Address']='192.0.2.99'
        with self.assertRaises(h.Blocked):self.inventory()
        self.rows['a'*64]['networks']['fixture']['IPAMConfig']['IPv4Address']='192.0.2.2';self.img['volumes']={'/extra':{}}
        with self.assertRaises(h.Blocked):self.inventory()
    def test_image_or_metadata_drift_between_reads_denied(self):
        count=0
        def query(kind,identity):
            nonlocal count
            count+=1;v=self.query(kind,identity)
            if count>6 and kind=='image':v['rootfs']['Layers']=['sha256:'+'9'*64]
            return v
        with self.assertRaises(h.Blocked):self.inventory(query)
        count=0
        def metadata(path):
            nonlocal count
            count+=1;v=h.mount_metadata(path)
            if count>2:v['attributes'][0]+=1
            return v
        with self.assertRaises(h.Blocked):self.inventory(metadata=metadata)
    def test_symlink_fifo_and_writable_mount_denied(self):
        link=self.root/'link';link.symlink_to(self.mount);fifo=self.root/'fifo';os.mkfifo(fifo,0o600)
        for p in (link,fifo):
            with self.assertRaises(h.Blocked):h.mount_metadata(p)
        self.mount.chmod(0o666)
        with self.assertRaises(h.Blocked):h.mount_metadata(self.mount)
    def test_bounded_json_subprocess_output_deadline_and_failure(self):
        for raw in (b'{"a":1,"a":2}',b'{"a":NaN}',b' '*131073):
            with self.assertRaises(h.Blocked):h.decode(raw)
        for code,seconds in [("print('X'*131073)",2),('import time;time.sleep(2)',0.1),('exit(1)',2)]:
            with self.assertRaises(h.Blocked) as error:h.bounded([sys.executable,'-c',code],time.monotonic()+seconds)
            self.assertIn(str(error.exception),('LOCAL_COMMAND_DEADLINE','LOCAL_COMMAND_OUTPUT_LIMIT','LOCAL_COMMAND_EXIT_NONZERO'))
    def test_durable_publication_no_overwrite_or_receipt_after_fsync_failure(self):
        h.publish(self.root,'evidence.json',b'{"observed":true}')
        self.assertEqual((self.root/'evidence.json').stat().st_mode&0o777,0o600)
        with self.assertRaises(FileExistsError):h.publish(self.root,'evidence.json',b'changed')
        self.assertEqual(h.private(self.root/'evidence.json'),b'{"observed":true}')
        with patch.object(os,'fsync',side_effect=OSError('fail')):
            with self.assertRaises(OSError):h.publish(self.root,'partial.json',b'partial')
        self.assertFalse((self.root/'inventory-receipt.json').exists())



    def test_diagnostic_errors_are_constant_and_do_not_publish(self):
        import contextlib, io
        argv=['inventory','--diagnose','--manifest-root',str(self.root),'--creation-root',str(self.root),
            '--package-root',str(self.root),'--snapshot-root',str(self.root),'--docker-path','/usr/bin/docker',
            '--expected-manifest-hash','a'*64,'--expected-creation-journal-hash','b'*64,
            '--creation-source-commit','1'*40,'--package-source-commit','2'*40,'--source-manifest-sha256','c'*64]
        for error in (ValueError('SECRET_PRIVATE_VALUE'),KeyError('SECRET_PRIVATE_VALUE'),h.Blocked('bad secret path')):
            output=io.StringIO()
            with patch.object(sys,'argv',argv),patch.object(h,'private',side_effect=error),contextlib.redirect_stdout(output):
                self.assertEqual(h.main(),1)
            text=output.getvalue();self.assertIn('DIAGNOSTIC=BLOCKED CHECK=PINNED_CANDIDATE_INPUTS',text)
            self.assertNotIn('SECRET_PRIVATE_VALUE',text);self.assertNotIn('bad secret path',text);self.assertNotIn(str(self.root),text)
            self.assertFalse((self.root/'inventory-receipt.json').exists())

    def test_source_custody_pins_every_file_and_receipt(self):
        root=self.root/'package';root.mkdir(mode=0o700)
        for d in ('source','source/scripts','source/tools'):(root/d).mkdir(mode=0o700)
        hashes={}
        for i in range(26):
            name='tools/source_'+str(i)+'.py';raw=b'# sealed source\n'
            p=root/'source'/name;p.write_bytes(raw);p.chmod(0o600);hashes[name]=h.digest(raw)
        raw=''.join(value+'  '+name+'\n' for name,value in hashes.items()).encode()
        (root/'sources.sha256').write_bytes(raw);(root/'sources.sha256').chmod(0o600)
        receipt={'schema':'ouf.semantic-local-producers-source-package.v8','sourceCommit':'1'*40,
            'sourceManifestHash':h.digest(raw),'sourceHashes':hashes,'sourceCount':26,'sourceCustodyVerified':True}
        receipt.update({k:0 for k in ('keysGenerated','privateKeysRead','signaturesIssued','providerCalls','sourceBodiesExecuted')})
        receipt.update({k:False for k in ('runtimeRegistered','startAuthorized','rulesChanged','unitsChanged','containersChanged')})
        path=root/'source-package-receipt.json';path.write_bytes(h.encoded(receipt));path.chmod(0o600)
        h.package(root,'1'*40,h.digest(raw))
        source=root/'source/tools/source_0.py';source.write_bytes(b'# drift\n')
        with self.assertRaises(h.Blocked):h.package(root,'1'*40,h.digest(raw))
        source.write_bytes(b'# sealed source\n');receipt['startAuthorized']=True;path.write_bytes(h.encoded(receipt))
        with self.assertRaises(h.Blocked):h.package(root,'1'*40,h.digest(raw))


@unittest.skipUnless(os.environ.get('OUF_TARGET_ACCEPTANCE_NATIVE_TEST')=='1','real stopped Docker inventory opt-in')
class DockerTargetAcceptanceTest(unittest.TestCase):
    def test_go_template_handles_docker29_omitted_optional_keys(self):
        import shutil, subprocess
        go=os.environ.get('OUF_TEMPLATE_GO_PATH') or shutil.which('go');self.assertIsNotNone(go,'CI Go toolchain required for real text/template regression')
        legacy=('{{json .Id}}{{json .RootFS}}{{json .Config.User}}{{json .Config.Entrypoint}}'
            '{{json .Config.Cmd}}{{json .Config.WorkingDir}}{{json .Config.Volumes}}')
        fixture=Path(__file__).parent/'fixtures/semantic_image_inspect_template.go'
        with tempfile.TemporaryDirectory(dir='/root') as tmp:
            env={**os.environ,'GO111MODULE':'off','GOTOOLCHAIN':'local','GOPROXY':'off','GOSUMDB':'off','GOCACHE':tmp}
            result=subprocess.run([go,'run',str(fixture)],input=h.encoded({'Current':h.IMAGE,'Legacy':legacy}),
                capture_output=True,timeout=60,env=env)
        self.assertEqual(result.returncode,0,'Go strict image-inspect compatibility regression failed')
        self.assertIn(b'GO_IMAGE_TEMPLATE_COMPATIBILITY=PASS',result.stdout)
        self.assertNotIn(b'never-output',result.stdout+result.stderr)

    def test_cli_on_actual_images_mounts_and_two_never_started_candidates(self):
        import io, shutil, subprocess, tarfile, uuid
        from scripts import stage_semantic_local_producers_package as stage
        self.assertEqual(os.geteuid(),0);docker=shutil.which('docker');self.assertIsNotNone(docker)
        token=uuid.uuid4().hex[:10];created=[];image=net=None
        def run(*args,payload=None):
            r=subprocess.run([docker,*args],input=payload,capture_output=True,timeout=20)
            self.assertEqual(r.returncode,0,'Docker fixture command failed');return r.stdout.decode().strip()
        try:
            archive=io.BytesIO()
            with tarfile.open(fileobj=archive,mode='w') as tar:
                item=tarfile.TarInfo('fixture');item.size=7;tar.addfile(item,io.BytesIO(b'fixture'))
            image=run('image','import','-',payload=archive.getvalue())
            network='ouf-accept-'+token;net=run('network','create','--internal','--subnet','192.0.2.0/24',network)
            with tempfile.TemporaryDirectory(dir='/root') as tmp:
                root=Path(tmp);root.chmod(0o700);mount=root/'key';mount.write_bytes(b'NEVER_READ_SECRET');mount.chmod(0o600)
                specs=[];ids={};tx=uuid.uuid4().hex
                for i in range(2):
                    name='ouf-accept-'+token+'-'+str(i);ip='192.0.2.'+str(i+2)
                    specs.append({'name':name,'image':image,'user':'1000:1000','command':['/never-run'],'readOnlyRoot':True,
                        'memoryBytes':268435456,'pidsLimit':128,'dnsServers':[],
                        'mounts':[{'source':str(mount),'target':'/key','readOnly':True}],
                        'networks':[{'name':network,'id':net,'ipv4':ip}]})
                manifest={'schema':'ouf.semantic-provider-stopped-manifest.v1','startAuthorized':False,'installation':'fixture','containers':specs}
                mr=h.encoded(manifest);mh=h.digest(mr)
                for spec in specs:
                    cid=run('create','--name',spec['name'],'--user',spec['user'],'--restart','no','--read-only','--cap-drop','ALL',
                        '--memory','268435456','--memory-swap','268435456','--pids-limit','128','--no-healthcheck',
                        '--mount','type=bind,source='+str(mount)+',target=/key,readonly','--network',net,'--ip',spec['networks'][0]['ipv4'],
                        '--network-alias',spec['name'],'--label','ouf.semantic.candidate.transaction='+tx,
                        '--label','ouf.semantic.candidate.manifest='+mh,image,'/never-run')
                    created.append(cid);ids[spec['name']]=cid
                journal={'schema':'ouf.semantic-provider-stopped-create.v1','state':'CREATED_STOPPED','startAuthorized':False,
                    'sourceCommit':'1'*40,'manifestHash':mh,'candidateIds':ids,'transaction':tx};jr=h.encoded(journal)
                for n,raw in [('stopped-manifest.json',mr),('creation-journal.json',jr),('inventory.py',Path(h.__file__).read_bytes())]:
                    p=root/n;p.write_bytes(raw);p.chmod(0o600)
                pkg=root/'package';pkg.mkdir(mode=0o700)
                for d in ('source','source/scripts','source/tools'):(pkg/d).mkdir(mode=0o700)
                repo=Path(h.__file__).resolve().parents[1];hashes={}
                for name in stage.NAMES:
                    raw=(repo/name).read_bytes();p=pkg/'source'/name;p.write_bytes(raw);p.chmod(0o600);hashes[name]=h.digest(raw)
                source_raw=''.join(value+'  '+name+'\n' for name,value in hashes.items()).encode()
                (pkg/'sources.sha256').write_bytes(source_raw);(pkg/'sources.sha256').chmod(0o600)
                subprocess.run([sys.executable,'-I','-B',str(pkg/'source'/stage.SELF),'--mode','apply','--package-root',str(pkg),
                    '--source-commit','2'*40,'--source-manifest-sha256',h.digest(source_raw)],check=True,stdout=subprocess.DEVNULL,timeout=10)
                out=root/'evidence';out.mkdir(mode=0o700)
                argv=[sys.executable,'-I','-B',str(root/'inventory.py'),'--manifest-root',str(root),'--creation-root',str(root),
                    '--package-root',str(pkg),'--snapshot-root',str(out),'--docker-path',docker,'--expected-manifest-hash',mh,
                    '--expected-creation-journal-hash',h.digest(jr),'--creation-source-commit','1'*40,'--package-source-commit','2'*40,
                    '--source-manifest-sha256',h.digest(source_raw)]
                diagnostic=subprocess.run(argv+['--diagnose'],capture_output=True,text=True,timeout=40)
                self.assertEqual(diagnostic.returncode,0,diagnostic.stdout)
                self.assertIn('DIAGNOSTIC=PASS',diagnostic.stdout)
                self.assertFalse(any((out/name).exists() for name in ('target-dossier.json','authority-plan.json','inventory-receipt.json')))
                r=subprocess.run(argv,capture_output=True,text=True,timeout=40)
                self.assertEqual(r.returncode,0,r.stdout);self.assertEqual(r.stderr,'')
                v=json.loads(r.stdout.splitlines()[0].split('=',1)[1]);self.assertFalse(v['deploymentAuthorityProven'])
                self.assertEqual(v['candidateCount'],2);self.assertFalse(v['startAuthorized'])
                dossier=h.private(out/'target-dossier.json');self.assertNotIn(b'NEVER_READ_SECRET',dossier)
                self.assertEqual(h.digest(dossier),v['dossierHash'])
                self.assertEqual(h.digest(h.private(out/'authority-plan.json')),v['authorityPlanHash'])
                # Completed evidence cannot be overwritten or replayed.
                again=subprocess.run(argv,capture_output=True,text=True,timeout=40);self.assertEqual(again.returncode,1)
                self.assertEqual(h.private(out/'target-dossier.json'),dossier)
                self.assertTrue(all(json.loads(run('inspect','--format',h.CONTAINER,cid))['status']=='created' for cid in created))
        finally:
            for cid in created:run('rm',cid)
            if net:run('network','rm',net)
            if image:run('image','rm',image)

if __name__=='__main__':unittest.main()
