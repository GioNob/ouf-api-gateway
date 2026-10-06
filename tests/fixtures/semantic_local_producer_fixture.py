"""CI-only distinct-role signer and approved synthetic Busybox image verifier."""
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

def raw(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')
def sha(value):return hashlib.sha256(value).hexdigest()
configuration=json.loads(Path(sys.argv[2]).read_bytes())
request=json.loads(sys.stdin.buffer.read(4097));role=configuration['role']
assert request['role']==role and request['containerId']==configuration['containerId']
facts={k:request[k] for k in ('containerId','transactionId','applicationHash','transportHash')}
if role=='CREATION_ATTESTATION':
    oci=json.loads((Path(configuration['bundle'])/'config.json').read_bytes())
    assert sha(raw(oci))==request['applicationHash']
    assert oci['process']['args']==configuration['command']
    assert any(m.get('destination')=='/proof' and m.get('source')==configuration['proof'] for m in oci['mounts'])
    assert sha((Path(oci['root']['path'])/'bin/busybox').read_bytes())==configuration['busyboxHash']
    creation={'schema':'ouf.semantic-container-creation-acceptance.v1',**{k:request[k] for k in
        ('containerId','applicationHash','transportHash')},'accepted':True}
    record={'schema':'ouf.semantic-created-candidate-attestation.v1','attestorRef':request['issuerRef'],
        **{k:request[k] for k in ('installationRef','entityRef','intentHash','artifactHash','deploymentConstraintsHash',
            'runtimeExecutableHash','generation')},**facts,'observedAt':int(time.time()),'creationAcceptance':creation}
else:
    attestation=(Path(configuration['bundle']).parent/'attestation.json').read_bytes()
    assert sha(attestation)==request['attestationHash']
    assert sha(raw(json.loads(attestation)['creationAcceptance']))==request['creationAcceptanceHash']
    record={'schema':'ouf.semantic-deployment-admission-approval.v1','issuerRef':request['issuerRef'],
        **{k:request[k] for k in ('installationRef','entityRef','creationAcceptanceHash')},**facts,
        'approvalRef':'ci-final-'+request['containerId'][:8],'issuedAt':int(time.time()),
        'expiresAt':configuration['expiresAt'],'state':'ACTIVE','infrastructureAuthorized':True,'applicationStartAuthorized':True}

def sign(payload):
    header={'schema':'ouf.semantic-deployment-detached-signature.v1','algorithm':'Ed25519','keyRef':configuration['keyRef'],
        **{k:request[k] for k in ('role','issuerRef','installationRef','entityRef')},'payloadHash':sha(payload)}
    canonical=raw(header)
    frame=b'OUF-DEPLOYMENT-EVIDENCE\x00V1\x00'+len(canonical).to_bytes(4,'big')+canonical+len(payload).to_bytes(4,'big')+payload
    path=Path(configuration['frame']);path.write_bytes(frame);path.chmod(0o600)
    result=subprocess.run([configuration['openssl'],'pkeyutl','-sign','-rawin','-inkey',configuration['key'],'-in',str(path)],
        check=True,capture_output=True,timeout=2).stdout
    return {**header,'signature':result.hex()}
payload=raw(record);signature=sign(payload)
binding=raw({'schema':'ouf.semantic-local-producer-binding.v1','requestHash':sha(raw(request)),
    'recordHash':sha(payload),'recordSignatureHash':sha(raw(signature))})
sys.stdout.buffer.write(raw({'schema':'ouf.semantic-local-producer-result.v1','recordBase64':base64.b64encode(payload).decode('ascii'),
    'recordSignature':signature,'bindingSignature':sign(binding)}))
