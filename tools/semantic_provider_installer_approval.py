"""Real final-approval producer. Existing signatures/mandate/key, one durable attempt."""
import base64
import copy
import hashlib
import os
from pathlib import Path
import stat
import time

from tools.semantic_provider_deployment_authentication import DetachedAuthenticator,VerificationBudget,binding,private_bytes,decode
from tools.semantic_provider_deployment_protocol import context,validate_creation,validate_final,validate_intent,window,identity
from tools.semantic_provider_deployment_producer import LocalEvidenceProducer,encoded
from tools.semantic_provider_deployment_signing import ExistingEd25519Signer
from tools.semantic_provider_preexec import PreexecDenied,digest


def require(ok,reason):
    if not ok:raise PreexecDenied(reason)


def publish_once(path,raw,exists_reason):
    """Publish private evidence durably; partial issuance is never replayed."""
    from tools.semantic_provider_deployment_authentication import ancestors
    path=Path(path);ancestors(path);info=path.parent.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid==info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o700,
            'PRIVATE_INSTALLER_ISSUANCE_DIRECTORY_REQUIRED')
    require(type(raw) is bytes and 0<len(raw)<=131072,'PRIVATE_ISSUANCE_EVIDENCE_UNBOUNDED')
    try:fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    except FileExistsError:raise PreexecDenied(exists_reason) from None
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,'wb',closefd=False) as stream:stream.write(raw);stream.flush();os.fsync(fd)
    finally:os.close(fd)
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
    require(private_bytes(path)==raw,'INSTALLER_ISSUANCE_PUBLICATION_UNPROVEN')


class InstallerApproval:
    def __init__(self,cfg,configuration_raw,configuration_path,producer_binding,clock=time.time):
        fields={'schema','sourceRoot','sourceHashes','pythonBinding','authorities','intentBinding','attestationPath',
            'approvalMandateBinding','policyBinding','signatureDirectory','opensslBinding','signingKeyBinding','keyRef',
            'brokerEmissionJournal','issuanceClaimPath','budgetSeconds'}
        require(set(cfg)==fields and cfg['schema']=='ouf.semantic-installer-approval-producer.v1','EXACT_INSTALLER_PRODUCER_CONFIGURATION_REQUIRED')
        self.cfg=copy.deepcopy(cfg);self.raw=configuration_raw;self.path=Path(configuration_path);self.clock=clock
        require(type(cfg['budgetSeconds']) is int and 1<=cfg['budgetSeconds']<=12,'BOUNDED_INSTALLER_ISSUANCE_REQUIRED')
        self.budget=VerificationBudget(cfg['budgetSeconds']);self.ctx=context(cfg['authorities'])
        self.verifier=DetachedAuthenticator(cfg['policyBinding'],cfg['signatureDirectory'],cfg['opensslBinding'],clock,self.budget)
        self.producer=LocalEvidenceProducer(producer_binding,self.ctx,self.verifier,self.budget)
        self.inputs={};self.signatures={};self.policy_raw=None

    def read(self,item):
        b=binding(item);raw=private_bytes(Path(b['path']))
        require(hashlib.sha256(raw).hexdigest()==b['sha256'],'INSTALLER_EVIDENCE_HASH_DRIFT')
        self.inputs[Path(b['path'])]=raw;return raw

    def authenticate(self,raw,role,issuer,installation,entity):
        path=self.verifier.signature_directory/(hashlib.sha256(raw).hexdigest()+'.'+role+'.json')
        signature=private_bytes(path,4096);self.signatures[path]=signature
        return self.verifier.verify_detached(raw,signature,role,issuer,installation,entity)

    def stable(self):
        self.budget.check();self.producer.pinned()
        require(private_bytes(self.path)==self.raw,'INSTALLER_CONFIGURATION_CHANGED')
        for path,raw in self.inputs.items():require(private_bytes(path)==raw,'INSTALLER_EVIDENCE_CHANGED')
        for path,raw in self.signatures.items():require(private_bytes(path,4096)==raw,'INSTALLER_SIGNATURE_CHANGED')
        require(self.policy_raw is not None and self.verifier.read_policy()==self.policy_raw,'INSTALLER_POLICY_CHANGED')
        for relative,sha in self.cfg['sourceHashes'].items():
            require(hashlib.sha256(private_bytes(Path(self.cfg['sourceRoot'])/relative)).hexdigest()==sha,'INSTALLER_SOURCE_CHANGED')
        self.budget.check()

    def broker_claim(self,request,raw):
        path=Path(self.cfg['brokerEmissionJournal']);value=decode(private_bytes(path),131072)
        keys=('role','installationRef','entityRef','issuerRef','containerId','transactionId')
        expected={'schema':'ouf.semantic-local-producer-emission.v1',**{k:request[k] for k in keys},
            'requestHash':hashlib.sha256(raw).hexdigest(),'producerHash':hashlib.sha256(encoded(self.producer.configured)).hexdigest(),
            'state':'ISSUING','resultHash':None}
        require(encoded(value)==encoded(expected),'BROKER_ISSUING_CLAIM_REQUIRED')
        return path,private_bytes(path)

    def mandate(self,raw,intent):
        value=decode(raw,131072)
        fields={'schema','issuerRef','installationRef','entityRef','intentHash','containerId','transactionId',
            'artifactHash','deploymentConstraintsHash','transportHash','runtimeExecutableHash','approvalRef',
            'issuedAt','expiresAt','state','issuanceAuthorized','applicationStartAuthorized'}
        require(set(value)==fields and value['schema']=='ouf.semantic-final-approval-mandate.v1','EXACT_FINAL_APPROVAL_MANDATE_REQUIRED')
        require(value['issuerRef']==self.ctx['approvalIssuerRef'] and identity(value['approvalRef'])
            and all(value[k]==intent[k] for k in ('installationRef','entityRef','containerId','transactionId','artifactHash',
                'deploymentConstraintsHash','transportHash','runtimeExecutableHash'))
            and value['intentHash']==hashlib.sha256(self.inputs[Path(self.cfg['intentBinding']['path'])]).hexdigest(),
            'INSTALLER_MANDATE_INTENT_SCOPE_DRIFT')
        require(value['state']=='ACTIVE' and value['issuanceAuthorized'] is True and value['applicationStartAuthorized'] is True,
                'EXPLICIT_FINAL_APPROVAL_AUTHORITY_REQUIRED')
        window(value,self.clock())
        require(value['issuedAt']>=intent['issuedAt'] and value['expiresAt']<=intent['expiresAt'],
                'INSTALLER_MANDATE_EXCEEDS_INTENT')
        self.authenticate(raw,'FINAL_DEPLOYMENT_APPROVAL',self.ctx['approvalIssuerRef'],self.ctx['installationRef'],self.ctx['entityRef'])
        return value

    def claim(self,request,request_raw):
        path=Path(self.cfg['issuanceClaimPath']);parent=path.parent
        # Explicit dedicated issuer directory, no symlinks or hardlinks.
        from tools.semantic_provider_deployment_authentication import ancestors
        ancestors(path);info=parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid==info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o700,
                'PRIVATE_INSTALLER_ISSUANCE_DIRECTORY_REQUIRED')
        value={'schema':getattr(self,'CLAIM_SCHEMA','ouf.semantic-installer-issuance-claim.v1'),'configurationHash':hashlib.sha256(self.raw).hexdigest(),
            'requestHash':hashlib.sha256(request_raw).hexdigest(),'state':'ISSUING',
            **{k:request[k] for k in ('role','issuerRef','installationRef','entityRef','containerId','transactionId')}}
        raw=encoded(value)
        publish_once(path,raw,'DO_NOT_REPLAY_INSTALLER_ISSUANCE')
        require(private_bytes(path)==raw,'INSTALLER_ISSUANCE_CLAIM_UNPROVEN')
        return path,raw

    def emit(self,request_raw):
        started=self.clock()
        request=decode(request_raw,4096);role='FINAL_DEPLOYMENT_APPROVAL'
        facts={k:v for k,v in request.items() if k not in {'schema','role','installationRef','entityRef','issuerRef'}}
        expected,canonical=self.producer.request(role,facts)
        require(request==expected and request_raw==canonical,'EXACT_CANONICAL_INSTALLER_REQUEST_REQUIRED')
        self.policy_raw=self.verifier.read_policy();self.producer.pinned()
        broker_path,broker_raw=self.broker_claim(request,request_raw)
        intent_raw=self.read(self.cfg['intentBinding']);intent=validate_intent(intent_raw,self.ctx,self.authenticate,self.clock)
        mandate_raw=self.read(self.cfg['approvalMandateBinding']);mandate=self.mandate(mandate_raw,intent)
        att_path=Path(self.cfg['attestationPath']);att_raw=private_bytes(att_path);self.inputs[att_path]=att_raw
        att=validate_creation(intent_raw,att_raw,self.ctx,self.authenticate,self.clock)
        require(all(request[k]==att[k] for k in ('containerId','transactionId','intentHash','artifactHash',
            'deploymentConstraintsHash','applicationHash','transportHash','runtimeExecutableHash','generation'))
            and request['attestationHash']==hashlib.sha256(att_raw).hexdigest()
            and request['creationAcceptanceHash']==digest(att['creationAcceptance']),'INSTALLER_ATTESTATION_REQUEST_DRIFT')
        now=int(self.clock());approval={'schema':'ouf.semantic-deployment-admission-approval.v1',
            'issuerRef':self.ctx['approvalIssuerRef'],'installationRef':self.ctx['installationRef'],'entityRef':self.ctx['entityRef'],
            'approvalRef':mandate['approvalRef'],**{k:request[k] for k in ('containerId','transactionId','applicationHash','transportHash','creationAcceptanceHash')},
            'issuedAt':now,'expiresAt':min(intent['expiresAt'],mandate['expiresAt']),'state':'ACTIVE',
            'infrastructureAuthorized':True,'applicationStartAuthorized':True}
        raw=encoded(approval)
        # Validate generated approval's protocol before reading any private key.
        validate_final(intent_raw,att_raw,raw,self.ctx,
            lambda payload,*args: True if payload==raw else self.authenticate(payload,*args),self.clock)
        self.stable();require(private_bytes(broker_path)==broker_raw,'BROKER_CLAIM_CHANGED')
        claim_path,claim_raw=self.claim(request,request_raw)
        signer=ExistingEd25519Signer(self.cfg['signingKeyBinding'],self.cfg['keyRef'],self.verifier,
            {k:request[k] for k in ('role','issuerRef','installationRef','entityRef')})
        signature=signer.sign(raw)
        binding_raw=encoded({'schema':'ouf.semantic-local-producer-binding.v1','requestHash':hashlib.sha256(request_raw).hexdigest(),
            'recordHash':hashlib.sha256(raw).hexdigest(),'recordSignatureHash':hashlib.sha256(signature).hexdigest()})
        binding_signature=signer.sign(binding_raw)
        self.stable();window(mandate,self.clock())
        validate_final(intent_raw,att_raw,raw,self.ctx,
            lambda payload,*args: self.verifier.verify_detached(payload,signature,*args) if payload==raw else self.authenticate(payload,*args),self.clock)
        self.stable();require(private_bytes(broker_path)==broker_raw and private_bytes(claim_path)==claim_raw,'INSTALLER_CLAIM_CHANGED')
        require(self.clock()>=started,'INSTALLER_CLOCK_REGRESSED')
        # Claim stays ISSUING: the broker alone publishes confirmed custody and
        # ISSUED after receiving this reply. Never infer receipt of stdout.
        return encoded({'schema':'ouf.semantic-local-producer-result.v1','recordBase64':base64.b64encode(raw).decode('ascii'),
            'recordSignature':decode(signature,4096),'bindingSignature':decode(binding_signature,4096)})
