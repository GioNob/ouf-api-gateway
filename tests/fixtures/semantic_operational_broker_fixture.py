"""CI fault injection around the production broker, never a deployment producer."""
import json
from pathlib import Path
import subprocess
import sys
configuration=Path(sys.argv[sys.argv.index('--configuration')+1]);root=configuration.parent
cfg=json.loads(configuration.read_bytes());fault=json.loads((root/'ci-faults.json').read_bytes())
mode=sys.argv[sys.argv.index('--mode')+1]
request_raw=sys.stdin.buffer.read(16385)
if mode=='prepare':
    sys.path.insert(0,fault['repository'])
    from tests.fixtures.semantic_node_acceptance_setup import provision
    provision(root,cfg,json.loads(request_raw))
    if fault['rootfsDrift']:
        state=json.loads(request_raw);oci=json.loads((Path(state['bundle'])/'config.json').read_bytes())
        path=Path(oci['root']['path'])/'bin/busybox';path.write_bytes(path.read_bytes()+b'CI-ROOTFS-DRIFT')
result=subprocess.run([fault['python'],'-I','-B',str(Path(cfg['sourceRoot'])/'scripts/semantic_provider_deployment_broker.py'),
    *sys.argv[1:]],input=request_raw,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=19)
if result.returncode:raise SystemExit(result.returncode)
if mode=='prepare':
    if fault['leaseDrift']:
        path=root/'coordination.json';value=json.loads(path.read_bytes());value['state']='QUIESCING';path.write_text(json.dumps(value));path.chmod(0o600)
    if fault['signatureDrift']:
        path=Path(cfg['signatureDirectory'])/(cfg['intentBinding']['sha256']+'.DEPLOYMENT_INTENT.json')
        value=json.loads(path.read_bytes());value['signature']=('00' if value['signature'][:2]!='00' else '01')+value['signature'][2:]
        path.write_text(json.dumps(value));path.chmod(0o600)
