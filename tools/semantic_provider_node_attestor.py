"""Real node attestor: explicit signed acceptance, observed rootfs/OCI/live links.

InstallerApproval's private IO/custody helpers are reused; its approval emission
is never called. v1 verifies a preexisting mandate. Explicit v2 pins authority
bytes; v3 pins the private signed-authority path before its exact OCI is known.
Both live modes require signed exact-OCI/rootfs acceptance and issuance authority.
"""
import base64
import copy
import hashlib
from pathlib import Path
import time

from tools.semantic_provider_installer_approval import InstallerApproval,require,publish_once
from tools.semantic_provider_deployment_authentication import DetachedAuthenticator,VerificationBudget,private_bytes,decode
from tools.semantic_provider_deployment_protocol import context,validate_intent,validate_creation,window,hashed
from tools.semantic_provider_deployment_producer import LocalEvidenceProducer,encoded
from tools.semantic_provider_deployment_signing import ExistingEd25519Signer
from tools.semantic_provider_node_observation import NodeObservation
from tools.semantic_provider_preexec import digest

class NodeAttestor(InstallerApproval):
    CLAIM_SCHEMA='ouf.semantic-node-attestation-issuance-claim.v1'
    def __init__(self,cfg,configuration_raw,configuration_path,producer_binding,clock=time.time):
        fields={'schema','sourceRoot','sourceHashes','pythonBinding','authorities','intentBinding','acceptanceMandatePath',
            'policyBinding','signatureDirectory','opensslBinding','signingKeyBinding','keyRef','brokerEmissionJournal',
            'brokerStateJournal','issuanceClaimPath','budgetSeconds','runtimeBinding','runtimeRootParents','bundleParents',
            'commands','candidate','rootfsLimits'}
        self.live=cfg.get('schema') in {'ouf.semantic-node-attestor.v2','ouf.semantic-node-attestor.v3','ouf.semantic-node-attestor.v4'}
        self.live_path=cfg.get('schema') in {'ouf.semantic-node-attestor.v3','ouf.semantic-node-attestor.v4'}
        self.fresh_frame=cfg.get('schema')=='ouf.semantic-node-attestor.v4'
        if self.fresh_frame:fields.add('creationFrameObserverBinding')
        if self.live:fields.add('liveAcceptanceAuthorizationPath' if self.live_path else 'liveAcceptanceAuthorizationBinding')
        require(set(cfg)==fields and cfg['schema'] in {'ouf.semantic-node-attestor.v1','ouf.semantic-node-attestor.v2','ouf.semantic-node-attestor.v3','ouf.semantic-node-attestor.v4'},
                'EXACT_NODE_ATTESTOR_CONFIGURATION_REQUIRED')
        if self.live_path:
            path=cfg['liveAcceptanceAuthorizationPath']
            require(type(path) is str and Path(path).is_absolute() and '..' not in Path(path).parts,
                    'EXACT_PRIVATE_LIVE_AUTHORIZATION_PATH_REQUIRED')
        require(type(cfg['budgetSeconds']) is int and 1<=cfg['budgetSeconds']<=12,'BOUNDED_NODE_ATTESTATION_REQUIRED')
        require(set(cfg['commands'])=={'ip','nsenter'} and set(cfg['candidate'])=={'networkBindings','transport','tableName'},
            'EXACT_NODE_OBSERVATION_CONFIGURATION_REQUIRED')
        require(all(type(cfg[k]) is list and 1<=len(cfg[k])<=8 and all(type(p) is str and Path(p).is_absolute()
            and '..' not in Path(p).parts for p in cfg[k]) for k in ('runtimeRootParents','bundleParents')),'EXPLICIT_NODE_PATH_PARENTS_REQUIRED')
        self.cfg=copy.deepcopy(cfg);self.raw=configuration_raw;self.path=Path(configuration_path);self.clock=clock
        self.budget=VerificationBudget(cfg['budgetSeconds']);self.ctx=context(cfg['authorities'])
        self.verifier=DetachedAuthenticator(cfg['policyBinding'],cfg['signatureDirectory'],cfg['opensslBinding'],clock,self.budget)
        self.producer=LocalEvidenceProducer(producer_binding,self.ctx,self.verifier,self.budget)
        self.inputs={};self.signatures={};self.policy_raw=None
        self.observer=NodeObservation(self.cfg,self.budget)
        if self.fresh_frame:
            self.frame_producer=LocalEvidenceProducer(self.cfg['creationFrameObserverBinding'],self.ctx,self.verifier,self.budget)
    def observe(self,request,journal):
        observed=self.observer.observe(request,journal,self.bundle)
        if not self.fresh_frame:return observed
        # The existing signed complete authorization binds artifactHash. v4
        # requires that exact artifact to be the independently reviewed frame
        # policy; unsigned observations cannot replace that authorization.
        require(self.frame_producer.configured['configuration']['sha256']==request['artifactHash'],
            'NODE_CREATION_POLICY_ARTIFACT_DRIFT')
        executable,private=self.frame_producer.pinned()
        for key,raw in private.items():self.inputs[Path(self.frame_producer.configured[key]['path'])]=raw
        require(type(observed['state'].get('pid')) is int and observed['state']['pid']>1
            and observed['state']['pid']==request['generation']['pid'],'NODE_CREATED_FRAME_PID_REQUIRED')
        frame_request=encoded({'pid':observed['state']['pid'],'generation':request['generation'],
            'bundlePath':str(Path(observed['bundle'])/'config.json'),'applicationHash':request['applicationHash'],
            'policyHash':request['artifactHash']})
        require(len(frame_request)<=4096,'NODE_FRAME_REQUEST_UNBOUNDED')
        reply=self.frame_producer.invoke(executable,frame_request);frame=decode(reply,131072)
        fields={'schema','configuredPolicy','sourceMountFrame','policyAuthenticationProven','rootfsSealProven',
            'imagePublisherProvenanceVerified','completeCreationAccepted','acceptanceGranted','signaturesIssued','startAuthorized'}
        require(set(frame)==fields and frame['schema']=='ouf.semantic-configured-created-frame.v1'
            and all(frame[k] is False for k in ('policyAuthenticationProven','rootfsSealProven',
                'imagePublisherProvenanceVerified','completeCreationAccepted','acceptanceGranted','startAuthorized'))
            and type(frame['signaturesIssued']) is int and frame['signaturesIssued']==0
            and frame['configuredPolicy']['configuredPolicyConforms'] is True
            and frame['configuredPolicy']['applicationHash']==request['applicationHash']
            and frame['sourceMountFrame']['sourceByteHashesMatchExpected'] is True
            and frame['sourceMountFrame']['stableAcrossReads'] is True
            and frame['sourceMountFrame']['privateMaterialSpooled'] is False
            and frame['sourceMountFrame']['mountObservation']['effectiveReadOnlyFileBindingsObserved'] is True,
            'NODE_CONFIGURED_SOURCE_MOUNT_FRAME_REQUIRED')
        after_executable,after_private=self.frame_producer.pinned()
        require(after_executable==executable and after_private==private,'NODE_FRAME_OBSERVER_CHANGED')
        return {**observed,'creationFrameHash':digest(frame)}
    def broker_state(self,request):
        path=Path(self.cfg['brokerStateJournal']);raw=private_bytes(path);value=decode(raw,131072);self.inputs[path]=raw
        fields={'schema','installationRef','entityRef','containerId','transactionId','intentHash','configurationHash',
            'state','runtimeRoot','bundleHash','driverHash'}
        require(set(value)==fields and value['schema']=='ouf.semantic-deployment-broker-journal.v1'
            and value['state']=='PREPARING' and value['driverHash'] is None and hashed(value['configurationHash'])
            and all(value[k]==request[k] for k in ('installationRef','entityRef','containerId','transactionId','intentHash')),
            'NODE_BROKER_PREPARING_REQUIRED')
        return value
    def bundle(self,path):
        raw=private_bytes(path);self.inputs[path]=raw;return raw
    def acceptance(self,request,intent):
        path=Path(self.cfg['acceptanceMandatePath']);raw=private_bytes(path);self.inputs[path]=raw;value=decode(raw,131072)
        fields={'schema','issuerRef','installationRef','entityRef','containerId','transactionId','intentHash','artifactHash',
            'deploymentConstraintsHash','applicationHash','transportHash','runtimeExecutableHash','generation','rootfsSeal',
            'issuedAt','expiresAt','state','attestationAuthorized','completeCreationAccepted'}
        require(set(value)==fields and value['schema']=='ouf.semantic-node-creation-acceptance-mandate.v1',
            'EXACT_SIGNED_NODE_ACCEPTANCE_REQUIRED')
        require(all(encoded(value[k])==encoded(request[k]) for k in fields-{'schema','rootfsSeal','issuedAt','expiresAt','state',
            'attestationAuthorized','completeCreationAccepted'}) and value['state']=='ACTIVE'
            and value['attestationAuthorized'] is True and value['completeCreationAccepted'] is True,
            'EXPLICIT_COMPLETE_NODE_ACCEPTANCE_REQUIRED')
        self.rootfs_acceptance(value['rootfsSeal'])
        window(value,self.clock());require(value['issuedAt']>=intent['issuedAt'] and value['expiresAt']<=intent['expiresAt'],
            'NODE_ACCEPTANCE_EXCEEDS_INTENT')
        self.authenticate(raw,'CREATION_ATTESTATION',self.ctx['attestorRef'],self.ctx['installationRef'],self.ctx['entityRef'])
        return value
    def rootfs_acceptance(self,seal):
        require(type(seal) is dict and set(seal)=={'schema','sha256','entries','bytes'}
            and seal['schema']=='ouf.semantic-rootfs-seal.v1' and hashed(seal['sha256'])
            and type(seal['entries']) is int and 1<=seal['entries']<=self.cfg['rootfsLimits']['maxEntries']
            and type(seal['bytes']) is int and 0<=seal['bytes']<=self.cfg['rootfsLimits']['maxBytes'],'EXACT_APPROVED_ROOTFS_SEAL_REQUIRED')
    def live_authorization(self,request,intent):
        if self.live_path:
            path=Path(self.cfg['liveAcceptanceAuthorizationPath'])
            raw=private_bytes(path);self.inputs[path]=raw
        else:raw=self.read(self.cfg['liveAcceptanceAuthorizationBinding'])
        value=decode(raw,131072)
        bound={'issuerRef','installationRef','entityRef','containerId','transactionId','intentHash','artifactHash',
               'deploymentConstraintsHash','applicationHash','transportHash','runtimeExecutableHash'}
        fields=bound|{'schema','rootfsSeal','generationBinding','issuedAt','expiresAt','state',
                      'mandateIssuanceAuthorized','attestationAuthorized','completeCreationAccepted'}
        require(set(value)==fields and value['schema']=='ouf.semantic-node-live-acceptance-authorization.v1',
                'EXACT_SIGNED_LIVE_ACCEPTANCE_AUTHORIZATION_REQUIRED')
        require(all(encoded(value[k])==encoded(request[k]) for k in bound)
                and value['generationBinding']=='OBSERVED_CREATED' and value['state']=='ACTIVE'
                and all(value[k] is True for k in ('mandateIssuanceAuthorized','attestationAuthorized','completeCreationAccepted')),
                'EXPLICIT_LIVE_ACCEPTANCE_AUTHORITY_REQUIRED')
        self.rootfs_acceptance(value['rootfsSeal']);window(value,self.clock())
        require(value['issuedAt']>=intent['issuedAt'] and value['expiresAt']<=intent['expiresAt'],
                'NODE_ACCEPTANCE_EXCEEDS_INTENT')
        self.authenticate(raw,'CREATION_ATTESTATION',self.ctx['attestorRef'],self.ctx['installationRef'],self.ctx['entityRef'])
        path=Path(self.cfg['acceptanceMandatePath'])
        from tools.semantic_provider_deployment_authentication import ancestors
        ancestors(path)
        require(not path.exists() and not path.is_symlink(),'DO_NOT_REPLAY_LIVE_NODE_MANDATE')
        return value
    def issue_live_mandate(self,request,intent,authorization,observed,journal,signer):
        # Exact OCI and rootfs acceptance are signed in advance. Only the live
        # created generation is filled here, after independent observation.
        now=int(self.clock());window(authorization,self.clock());window(intent,self.clock())
        value={'schema':'ouf.semantic-node-creation-acceptance-mandate.v1',
               **{k:request[k] for k in ('issuerRef','installationRef','entityRef','containerId','transactionId',
                   'intentHash','artifactHash','deploymentConstraintsHash','applicationHash','transportHash',
                   'runtimeExecutableHash','generation')},'rootfsSeal':copy.deepcopy(authorization['rootfsSeal']),
               'issuedAt':now,'expiresAt':min(authorization['expiresAt'],intent['expiresAt']),
               'state':'ACTIVE','attestationAuthorized':True,'completeCreationAccepted':True}
        raw=encoded(value);signature=signer.sign(raw)
        require(self.observe(request,journal)==observed,'NODE_OBSERVATION_CHANGED_DURING_MANDATE')
        self.stable();window(value,self.clock());window(authorization,self.clock())
        path=Path(self.cfg['acceptanceMandatePath'])
        sigpath=self.verifier.signature_directory/(hashlib.sha256(raw).hexdigest()+'.CREATION_ATTESTATION.json')
        publish_once(sigpath,signature,'DO_NOT_REPLAY_LIVE_NODE_SIGNATURE')
        publish_once(path,raw,'DO_NOT_REPLAY_LIVE_NODE_MANDATE')
        return self.acceptance(request,intent)
    def emit(self,request_raw):
        started=self.clock();request=decode(request_raw,4096);role='CREATION_ATTESTATION'
        facts={k:v for k,v in request.items() if k not in {'schema','role','installationRef','entityRef','issuerRef'}}
        expected,canonical=self.producer.request(role,facts)
        require(request==expected and request_raw==canonical,'EXACT_CANONICAL_NODE_REQUEST_REQUIRED')
        self.policy_raw=self.verifier.read_policy();self.producer.pinned()
        broker_path,broker_raw=self.broker_claim(request,request_raw)
        intent_raw=self.read(self.cfg['intentBinding']);intent=validate_intent(intent_raw,self.ctx,self.authenticate,self.clock)
        mandate=self.live_authorization(request,intent) if self.live else self.acceptance(request,intent)
        journal=self.broker_state(request)
        require(self.cfg['runtimeBinding']['sha256']==request['runtimeExecutableHash'],'NODE_RUNTIME_INTENT_DRIFT')
        observed=self.observe(request,journal)
        require(observed['applicationHash']==request['applicationHash'] and observed['generation']==request['generation'],
                'NODE_OBSERVED_REQUEST_DRIFT')
        require(observed['rootfsSeal']==mandate['rootfsSeal'],'NODE_APPROVED_ROOTFS_DRIFT')
        self.stable();require(private_bytes(broker_path)==broker_raw,'NODE_BROKER_CLAIM_CHANGED')
        claim_path,claim_raw=self.claim(request,request_raw)
        creation={'schema':'ouf.semantic-container-creation-acceptance.v1',**{k:request[k] for k in
            ('containerId','applicationHash','transportHash')},'accepted':True}
        record={'schema':'ouf.semantic-created-candidate-attestation.v1','attestorRef':self.ctx['attestorRef'],
            **{k:request[k] for k in ('installationRef','entityRef','intentHash','containerId','transactionId','artifactHash',
                'deploymentConstraintsHash','applicationHash','transportHash','runtimeExecutableHash','generation')},
            'observedAt':int(self.clock()),'creationAcceptance':creation}
        raw=encoded(record)
        validate_creation(intent_raw,raw,self.ctx,lambda payload,*args:True if payload==raw else self.authenticate(payload,*args),self.clock)
        signer=ExistingEd25519Signer(self.cfg['signingKeyBinding'],self.cfg['keyRef'],self.verifier,
            {k:request[k] for k in ('role','issuerRef','installationRef','entityRef')})
        if self.live:mandate=self.issue_live_mandate(request,intent,mandate,observed,journal,signer)
        signature=signer.sign(raw)
        binding_raw=encoded({'schema':'ouf.semantic-local-producer-binding.v1','requestHash':hashlib.sha256(request_raw).hexdigest(),
            'recordHash':hashlib.sha256(raw).hexdigest(),'recordSignatureHash':hashlib.sha256(signature).hexdigest()})
        binding_signature=signer.sign(binding_raw)
        require(self.observe(request,journal)==observed,'NODE_OBSERVATION_CHANGED_DURING_SIGNING')
        self.stable();window(mandate,self.clock())
        validate_creation(intent_raw,raw,self.ctx,lambda payload,*args:self.verifier.verify_detached(payload,signature,*args)
            if payload==raw else self.authenticate(payload,*args),self.clock)
        require(private_bytes(broker_path)==broker_raw and private_bytes(claim_path)==claim_raw and self.clock()>=started,
            'NODE_CLAIM_OR_CLOCK_CHANGED')
        return encoded({'schema':'ouf.semantic-local-producer-result.v1','recordBase64':base64.b64encode(raw).decode('ascii'),
            'recordSignature':decode(signature,4096),'bindingSignature':decode(binding_signature,4096)})
