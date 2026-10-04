"""Ed25519 issuance with a pinned existing private key and explicit public mandate.

No generation, provisioning, registration or start. Caller owns durable issuance
custody and protocol authorization before invoking this signing primitive.
"""
import hashlib
from pathlib import Path
import subprocess
import tempfile

from tools.semantic_provider_deployment_authentication import binding,private_bytes,policy,signing_bytes,DER_PREFIX
from tools.semantic_provider_deployment_protocol import identity
from tools.semantic_provider_deployment_producer import encoded
from tools.semantic_provider_preexec import PreexecDenied


def require(ok,reason):
    if not ok:raise PreexecDenied(reason)


class ExistingEd25519Signer:
    def __init__(self,key_binding,key_ref,verifier,scope):
        self.key=binding(key_binding);require(identity(key_ref),'EXPLICIT_SIGNING_KEY_REF_REQUIRED')
        self.key_ref,self.verifier,self.scope=key_ref,verifier,scope.copy()
        require(set(scope)=={'role','issuerRef','installationRef','entityRef'} and scope['role']=='FINAL_DEPLOYMENT_APPROVAL',
                'INSTALLER_APPROVAL_SIGNING_SCOPE_REQUIRED')

    def key_raw(self):
        raw=private_bytes(Path(self.key['path']),4096)
        require(hashlib.sha256(raw).hexdigest()==self.key['sha256'],'EXISTING_SIGNING_KEY_DRIFT')
        return raw

    def native(self,argv,limit):
        executable=self.verifier.executable()
        with tempfile.TemporaryFile() as output:
            try:
                result=subprocess.run([executable,*argv],stdin=subprocess.DEVNULL,stdout=output,stderr=subprocess.DEVNULL,
                    timeout=self.verifier.timeout(),env={'PATH':'/usr/bin:/bin','LC_ALL':'C','OPENSSL_CONF':'/dev/null'})
            except (OSError,subprocess.TimeoutExpired):raise PreexecDenied('EXISTING_KEY_SIGNING_UNPROVEN') from None
            output.seek(0);raw=output.read(limit+1)
        require(result.returncode==0 and len(raw)<=limit,'EXISTING_KEY_SIGNING_UNPROVEN')
        self.verifier.executable();return raw

    def sign(self,raw):
        started=self.verifier.clock();policy_raw=self.verifier.read_policy();s=self.scope
        configured=policy(policy_raw,s['installationRef'],s['entityRef'],started)
        keys=[k for k in configured['keys'] if k['keyRef']==self.key_ref and k['issuerRef']==s['issuerRef']
            and s['role'] in k['roles'] and k['state']=='ACTIVE' and k['notBefore']<=started<k['expiresAt']]
        require(len(keys)==1,'EXPLICIT_SIGNING_ROLE_MANDATE_REQUIRED')
        key_raw=self.key_raw()
        public=self.native(['pkey','-in',self.key['path'],'-pubout','-outform','DER'],52)
        require(public==DER_PREFIX+bytes.fromhex(keys[0]['publicKey']),'SIGNING_KEY_PUBLIC_MANDATE_DRIFT')
        header={'schema':'ouf.semantic-deployment-detached-signature.v1','algorithm':'Ed25519','keyRef':self.key_ref,
                **s,'payloadHash':hashlib.sha256(raw).hexdigest()}
        frame=signing_bytes(raw,header)
        # Only public evidence is spooled; the private key is never copied,
        # generated or exported to stdout/stderr by this component.
        with tempfile.TemporaryDirectory(prefix='ouf-installer-signature-') as directory:
            path=Path(directory)/'frame.bin';path.write_bytes(frame);path.chmod(0o600)
            sig=self.native(['pkeyutl','-sign','-rawin','-inkey',self.key['path'],'-in',str(path)],64)
        require(len(sig)==64 and self.key_raw()==key_raw,'SIGNING_KEY_CHANGED_DURING_ISSUANCE')
        envelope=encoded({**header,'signature':sig.hex()})
        require(self.verifier.verify_detached(raw,envelope,s['role'],s['issuerRef'],s['installationRef'],s['entityRef']) is True,
                'ISSUED_SIGNATURE_VERIFICATION_REQUIRED')
        finished=self.verifier.clock()
        require(finished>=started and keys[0]['notBefore']<=finished<keys[0]['expiresAt']
                and self.verifier.read_policy()==policy_raw and self.key_raw()==key_raw,'SIGNING_MANDATE_CHANGED_OR_EXPIRED')
        self.verifier.check_budget();return envelope
