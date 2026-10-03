import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
import uuid
from scripts import semantic_provider_docker_runtime as adapter
from scripts.semantic_provider_preexec_hook import SELF, MODULES


class AdapterContractTest(unittest.TestCase):
    def test_no_exec_run_restore_or_ambiguous_runtime_arguments(self):
        cid = 'a'*64
        for args in [['--root','/run/test','run',cid], ['--root','/run/test','exec',cid],
                     ['--root','/run/test','restore',cid], ['--root','/run/test','create','--bundle','/b','-b','/c',cid],
                     ['--root','/run/test','create','--bundle','/b','--preserve-fds','1',cid],
                     ['--root','/run/test','start',cid,'foreign']]:
            with self.assertRaises(adapter.Denied): adapter.arguments(args)
        self.assertEqual(adapter.arguments(['--root','/run/test','create','--bundle','/b',cid])[0], 'create')

    def test_duplicate_json_and_candidate_independent_binding(self):
        with self.assertRaises(adapter.Denied): adapter.parse('{"a":1,"a":2}')
        cfg = {'runtimePath':'/runc','candidates':{'a':{'approvalRef':'one'}}}
        original = adapter.binding(cfg, 'a'); cfg['candidates']['b'] = {'approvalRef':'two'}
        self.assertEqual(adapter.binding(cfg, 'a'), original)
        cfg['runtimePath'] = '/foreign'; self.assertNotEqual(adapter.binding(cfg, 'a'), original)


@unittest.skipUnless(os.environ.get('OUF_DOCKER_ADAPTER_NATIVE_TEST') == '1', 'real named Docker adapter opt-in')
class DockerAdapterTest(unittest.TestCase):
    def test_named_docker_runtime_gate_and_default_preserved(self):
        self.assertEqual(os.geteuid(), 0)
        docker = shutil.which('docker'); runc = str(Path(shutil.which('runc')).resolve())
        python = str(Path(sys.executable).resolve()); repository = Path(__file__).resolve().parents[1]
        suffix = uuid.uuid4().hex[:8]; name = 'ouf-gate-'+suffix; bridge = 'dg'+suffix
        daemon_path = Path('/etc/docker/daemon.json'); old = daemon_path.read_bytes() if daemon_path.exists() else None
        def run(*argv, check=True, payload=None):
            result = subprocess.run(argv, input=payload, capture_output=True, timeout=30)
            if check: self.assertEqual(result.returncode, 0, 'CI fixture command failed: '+argv[0])
            return result
        def dock(*argv, **kw): return run(docker, *argv, **kw)
        default = dock('info','--format','{{.DefaultRuntime}}').stdout
        image = None; network = None; cids = []; tables = []; modified = False
        with tempfile.TemporaryDirectory(dir='/root', prefix='ouf-docker-adapter-') as tmp:
            root = Path(tmp); root.chmod(0o700); source = root/'source'; source.mkdir(mode=0o700)
            for relative in [SELF, 'scripts/semantic_provider_docker_runtime.py', *('tools/'+v+'.py' for v in MODULES)]:
                target = source/relative; target.parent.mkdir(mode=0o700, exist_ok=True)
                target.write_bytes((repository/relative).read_bytes()); target.chmod(0o600)
            def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
            broker = root/'admission.py'; broker.write_bytes((repository/'tests/fixtures/semantic_docker_admission_fixture.py').read_bytes()); broker.chmod(0o600)
            registry = root/'registry'; registry.mkdir(mode=0o700)
            admission_path = root/'admission.json'; config_path = root/'adapter.json'
            def private(path, value): path.write_text(json.dumps(value)); path.chmod(0o600)
            commands = {k:str(Path(shutil.which(k)).resolve()) for k in ('nft','ip','nsenter')}
            admission = {'repository':str(repository),'source':str(source),'python':python,'commands':commands,
                         'runc':runc,'runcHash':sha(runc),'approved':{}}
            private(admission_path, admission)
            cfg = {'schema':'ouf.semantic-docker-runtime-adapter.v1','sourceHash':sha(source/'scripts/semantic_provider_docker_runtime.py'),
                'runtimePath':runc,'runtimeSha256':sha(runc),'pythonPath':python,'pythonSha256':sha(python),
                'driverPath':str(source/SELF),'driverSha256':sha(source/SELF),'admissionPath':str(broker),
                'admissionSha256':sha(broker),'admissionConfiguration':str(admission_path),
                'admissionConfigurationHash':sha(admission_path),'registryRoot':str(registry),
                'runtimeStateRoot':'/run','candidates':{}}
            private(config_path, cfg)
            try:
                daemon = json.loads(old) if old else {}; daemon.setdefault('runtimes', {})
                self.assertNotIn(name, daemon['runtimes'])
                daemon['runtimes'][name] = {'path':python,'runtimeArgs':['-I','-B',str(source/'scripts/semantic_provider_docker_runtime.py'),
                                           '--configuration',str(config_path)]}
                daemon_path.parent.mkdir(exist_ok=True); daemon_path.write_text(json.dumps(daemon)); modified = True
                run('systemctl','reload','docker'); self.assertEqual(dock('info','--format','{{.DefaultRuntime}}').stdout, default)
                archive = io.BytesIO()
                with tarfile.open(fileobj=archive, mode='w') as tar:
                    for directory in ('bin','proof'):
                        item = tarfile.TarInfo(directory); item.type = tarfile.DIRTYPE; item.mode = 0o755; tar.addfile(item)
                    busybox = Path(shutil.which('busybox')).read_bytes(); item = tarfile.TarInfo('bin/busybox')
                    item.size = len(busybox); item.mode = 0o755; tar.addfile(item, io.BytesIO(busybox))
                    item = tarfile.TarInfo('bin/sh'); item.type = tarfile.SYMTYPE; item.linkname = 'busybox'; tar.addfile(item)
                image = dock('image','import','-',payload=archive.getvalue()).stdout.decode().strip()
                network = dock('network','create','--internal','--subnet','10.77.0.0/24',
                               '--opt','com.docker.network.bridge.name='+bridge, name).stdout.decode().strip()
                parents = ['/run/containerd/io.containerd.runtime.v2.task/moby',
                           '/run/docker/containerd/daemon/io.containerd.runtime.v2.task/moby']
                for index, (authorized, drift) in enumerate([(False, False),(True, True),(True, False)]):
                    proof = root/('proof'+str(index)); proof.mkdir(); marker = proof/'started'
                    command = ['/bin/sh','-c','echo APP > /proof/started; /bin/busybox sleep 2']
                    cid = dock('create','--runtime',name,'--network',network,'--ip','10.77.0.'+str(index+2),
                        '--cap-drop','ALL','--security-opt','no-new-privileges','--mount','type=bind,source='+str(proof)+',target=/proof',
                        image, *command).stdout.decode().strip(); cids.append(cid)
                    directory = registry/cid; directory.mkdir(mode=0o700); (directory/'operation.lock').touch(mode=0o600)
                    shared, lease = 'ds_'+suffix+str(index), 'dl_'+suffix+str(index); tables.extend([shared,lease])
                    admission['approved'][cid] = {'authority':True,'startAuthorized':authorized,'leaseDrift':drift,
                        'command':command,'proof':str(proof),'ipv4':'10.77.0.'+str(index+2),'bridge':bridge,
                        'sharedTable':shared,'leaseTable':lease}
                    private(admission_path, admission); cfg['admissionConfigurationHash'] = sha(admission_path)
                    cfg['candidates'][cid] = {'approvalRef':sha(admission_path),'bundleParents':parents}
                    private(config_path, cfg)
                    private(directory/'adapter.json', {'schema':'ouf.semantic-docker-runtime-journal.v1','containerId':cid,
                        'configurationHash':adapter.binding(cfg,cid),'state':'STAGED','runtimeRoot':None,'bundleHash':None,'driverHash':None})
                    result = dock('start',cid,check=False)
                    if not authorized or drift:
                        self.assertNotEqual(result.returncode, 0); self.assertFalse(marker.exists())
                        self.assertEqual(dock('inspect','--format','{{.State.Running}}',cid).stdout.strip(), b'false')
                    else:
                        self.assertEqual(result.returncode, 0, result.stderr.decode())
                        until = time.monotonic()+5
                        while not marker.exists() and time.monotonic() < until: time.sleep(.02)
                        self.assertEqual(marker.read_text().strip(), 'APP')
                        value = json.loads((directory/'preexec.json').read_bytes()); self.assertIsNotNone(value['containerGeneration'])
                        dock('wait',cid); self.assertEqual(dock('info','--format','{{.DefaultRuntime}}').stdout, default)
                    dock('rm','--force',cid,check=False); cids.remove(cid)
                    # Teardown only unique fixture tables, including deliberate incomplete cases.
                    for table in (shared,lease):
                        for family in ('inet','bridge'): run(commands['nft'],'delete','table',family,table,check=False)
                print('DOCKER_PREEXEC_ADAPTER_NATIVE=PASS REAL_DOCKER_NAMED_RUNTIME=true REAL_RUNC_NFT_GATE=true'
                      ' AUTHORITY_AND_LEASE_DRIFT_NO_APPLICATION=true GUARDED_START=true DEFAULT_PRESERVED=true'
                      ' TARGET_RUNTIME_REGISTERED=false TARGET_START_AUTHORIZED=false NOT_RELEASE_ACCEPTANCE=true')
            finally:
                for cid in cids: dock('rm','--force',cid,check=False)
                for table in tables:
                    for family in ('inet','bridge'): run(commands['nft'],'delete','table',family,table,check=False)
                if network: dock('network','rm',network,check=False)
                if image: dock('image','rm',image,check=False)
                if modified:
                    if old is None: daemon_path.unlink()
                    else: daemon_path.write_bytes(old)
                    run('systemctl','reload','docker')


if __name__ == '__main__': unittest.main()
