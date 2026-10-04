"""CI-only complete synthetic image acceptance authority; never target code.

Signs a specific observed OCI/rootfs after independently checking the approved
Busybox command/mount/image. Production attestor must reobserve it independently.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import time
from tools.semantic_provider_node_observation import rootfs_seal
from tools.semantic_provider_deployment_authentication import VerificationBudget
from tools.semantic_provider_deployment_producer import encoded
from tools.semantic_provider_preexec import digest
from tools.semantic_provider_preexec_native import NativeBackend

def provision(root,cfg,state):
    inputs=json.loads((root/'ci-node-acceptance-input.json').read_bytes())
    node=json.loads((root/'attestation-producer.json').read_bytes());intent=json.loads((root/'intent.json').read_bytes())
    bundle=Path(state['bundle']);oci=json.loads((bundle/'config.json').read_bytes())
    assert state['id']==intent['containerId'] and state['status']=='created'
    assert oci['process']['args']==inputs['command']
    assert any(m.get('destination')=='/proof' and m.get('source')==inputs['proof'] for m in oci['mounts'])
    rootfs=Path(oci['root']['path']);rootfs=rootfs if rootfs.is_absolute() else bundle/rootfs
    assert hashlib.sha256((rootfs/'bin/busybox').read_bytes()).hexdigest()==inputs['busyboxHash']
    seal=rootfs_seal(rootfs,node['rootfsLimits'],VerificationBudget(12))
    value={'schema':'ouf.semantic-node-creation-acceptance-mandate.v1','issuerRef':'ci-node-verifier',
        **{k:intent[k] for k in ('installationRef','entityRef','containerId','transactionId','artifactHash',
            'deploymentConstraintsHash','transportHash','runtimeExecutableHash')},'intentHash':cfg['intentBinding']['sha256'],
        'applicationHash':digest(oci),'generation':NativeBackend.generation(None,state['pid']),'rootfsSeal':seal,'issuedAt':int(time.time()),'expiresAt':intent['expiresAt'],
        'state':'ACTIVE','attestationAuthorized':True,'completeCreationAccepted':True}
    payload=encoded(value);path=root/'ci-node-mandate.json';path.write_bytes(payload);path.chmod(0o600)
    header={'schema':'ouf.semantic-deployment-detached-signature.v1','algorithm':'Ed25519','keyRef':'verifier-key',
        'role':'CREATION_ATTESTATION','issuerRef':'ci-node-verifier',
        **{k:intent[k] for k in ('installationRef','entityRef')},'payloadHash':hashlib.sha256(payload).hexdigest()}
    canonical=encoded(header);frame=b'OUF-DEPLOYMENT-EVIDENCE\x00V1\x00'+len(canonical).to_bytes(4,'big')+canonical+len(payload).to_bytes(4,'big')+payload
    path=root/'ci-acceptance-frame';path.write_bytes(frame);path.chmod(0o600)
    signature=subprocess.run([inputs['openssl'],'pkeyutl','-sign','-rawin','-inkey',inputs['key'],'-in',str(path)],
        check=True,capture_output=True,timeout=2).stdout
    path=Path(cfg['signatureDirectory'])/(header['payloadHash']+'.CREATION_ATTESTATION.json')
    path.write_bytes(encoded({**header,'signature':signature.hex()}));path.chmod(0o600)
