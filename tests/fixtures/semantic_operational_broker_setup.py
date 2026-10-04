"""CI-only provisioning. Keys and approved synthetic image remain outside broker."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
from scripts import semantic_provider_deployment_broker as broker
from tools.materialize_southbound_kernel import materialize
from tools.semantic_provider_lease_nft import structure_hash
from tools.semantic_provider_preexec import digest

def configure(directory,cfg,repository,source,python,run):
    def raw(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')
    def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    def private(path,value):path.write_bytes(raw(value));path.chmod(0o600)
    intent=cfg['intent'];cid=intent['containerId'];crypto=cfg['crypto'];datum=cfg['approved'][cid]
    private(directory/'ci-faults.json',{'python':python,'leaseDrift':datum['leaseDrift'],'signatureDrift':datum['signatureDrift']})
    intent_path=directory/'intent.json';private(intent_path,intent)
    header={'schema':'ouf.semantic-deployment-detached-signature.v1','algorithm':'Ed25519','keyRef':'installer-key',
        'role':'DEPLOYMENT_INTENT','issuerRef':'ci-installer','installationRef':'ci-installation','entityRef':'ci-entity',
        'payloadHash':sha(intent_path)}
    canonical=raw(header);payload=raw(intent)
    frame=b'OUF-DEPLOYMENT-EVIDENCE\x00V1\x00'+len(canonical).to_bytes(4,'big')+canonical+len(payload).to_bytes(4,'big')+payload
    frame_path=directory/'ci-intent-frame';frame_path.write_bytes(frame);frame_path.chmod(0o600)
    signed=run(crypto['opensslBinding']['path'],'pkeyutl','-sign','-rawin','-inkey',crypto['privateKeys']['installer-key'],
        '-in',str(frame_path)).stdout
    private(Path(crypto['signatureDirectory'])/(sha(intent_path)+'.DEPLOYMENT_INTENT.json'),{**header,'signature':signed.hex()})
    # The broker consumes an existing empty lease/guard installation. CI alone
    # materializes its unique tables before provisioning immutable broker input.
    kernel=cfg['kernel'];run(cfg['commands']['nft'],'-f','-',payload=materialize(kernel,empty_provider_sets=True)['nftRules'].encode())
    lease_hash=structure_hash({f:json.loads(run(cfg['commands']['nft'],'-j','list','table',f,kernel['tableName']).stdout) for f in ('inet','bridge')})
    coordination={'transactionId':intent['transactionId'],'configurationHash':digest(kernel),'leaseStructureHash':lease_hash}
    private(directory/'coordination.json',{'schema':'ouf.semantic-lease-coordination.v1',**coordination,
        'state':'QUIESCED','leaseAuthorized':False,'startAuthorized':False,'leaseAddresses':[[]]})
    commands={**cfg['commands'],**cfg['mountCommands']}
    template={'schema':'ouf.semantic-admission-preparer-template.v1','pythonPath':python,'pythonHash':sha(python),
        'commands':commands,'commandHashes':{k:sha(v) for k,v in commands.items()},
        'candidate':{'containerId':cid,'transactionId':intent['transactionId'],'networkBindings':cfg['networkBindings'],
            'transport':cfg['transport'],'tableName':datum['sharedTable'],'runtimeBinding':{'path':cfg['runc'],'sha256':cfg['runcHash']}},
        'kernel':kernel,'dns':{'resolvers':['127.0.0.1'],'resolverPort':53,'timeoutSeconds':2,'maxLeaseSeconds':30,'applyBudgetSeconds':1},
        'coordinationBinding':coordination,'coordinationJournal':str(directory/'coordination.json'),'lockFile':cfg['lock'],
        'budgetSeconds':5,'hostNetworkNamespace':os.stat('/proc/self/ns/net').st_ino}
    template_path=directory/'preparer-template.json';private(template_path,template)
    producer_script=directory/'ci-producer.py';producer_script.write_bytes((repository/'tests/fixtures/semantic_local_producer_fixture.py').read_bytes());producer_script.chmod(0o600)
    producers={}
    for name,role,keyref in [('attestation','CREATION_ATTESTATION','verifier-key')]:
        configuration=directory/(name+'-producer.json')
        private(configuration,{'role':role,'containerId':cid,'bundle':str(directory/'bundle'),'command':datum['command'],
            'proof':datum['proof'],'busyboxHash':cfg['busyboxHash'],'expiresAt':intent['expiresAt'],
            'openssl':crypto['opensslBinding']['path'],'keyRef':keyref,'key':crypto['privateKeys'][keyref],
            'frame':str(directory/(name+'-frame'))})
        producers[name]={k:{'path':str(p),'sha256':sha(p)} for k,p in
            [('python',Path(python)),('source',producer_script),('configuration',configuration)]}
        (directory/(name+'-results')).mkdir(mode=0o700)
    # CI alone provisions a signed mandate and existing installer key.
    # Production CLI emits final approval; node attestor remains a CI fixture.
    from scripts import semantic_provider_installer_approval as issuer
    authorities={'installationRef':'ci-installation','entityRef':'ci-entity','intentIssuerRef':'ci-installer',
        'attestorRef':'ci-node-verifier','approvalIssuerRef':'ci-installer'}
    mandate={'schema':'ouf.semantic-final-approval-mandate.v1','issuerRef':'ci-installer',
        'installationRef':'ci-installation','entityRef':'ci-entity','intentHash':sha(intent_path),
        **{k:intent[k] for k in ('containerId','transactionId','artifactHash','deploymentConstraintsHash','transportHash','runtimeExecutableHash')},
        'approvalRef':'ci-final-'+cid,'issuedAt':intent['issuedAt'],'expiresAt':intent['expiresAt'],
        'state':'ACTIVE','issuanceAuthorized':True,'applicationStartAuthorized':True}
    mandate_path=directory/'ci-final-mandate.json';private(mandate_path,mandate)
    header={**header,'role':'FINAL_DEPLOYMENT_APPROVAL','payloadHash':sha(mandate_path)}
    canonical=raw(header);payload=raw(mandate)
    frame=b'OUF-DEPLOYMENT-EVIDENCE\x00V1\x00'+len(canonical).to_bytes(4,'big')+canonical+len(payload).to_bytes(4,'big')+payload
    frame_path.write_bytes(frame)
    signed=run(crypto['opensslBinding']['path'],'pkeyutl','-sign','-rawin','-inkey',crypto['privateKeys']['installer-key'],'-in',str(frame_path)).stdout
    private(Path(crypto['signatureDirectory'])/(sha(mandate_path)+'.FINAL_DEPLOYMENT_APPROVAL.json'),{**header,'signature':signed.hex()})
    issuer_paths=[issuer.SELF,*('tools/'+m+'.py' for m in issuer.MODULES)]
    configuration=directory/'approval-producer.json';key=Path(crypto['privateKeys']['installer-key'])
    private(configuration,{'schema':'ouf.semantic-installer-approval-producer.v1','sourceRoot':str(source),
        'sourceHashes':{p:sha(source/p) for p in issuer_paths},'pythonBinding':{'path':python,'sha256':sha(python)},
        'authorities':authorities,'intentBinding':{'path':str(intent_path),'sha256':sha(intent_path)},
        'attestationPath':str(directory/'attestation.json'),'approvalMandateBinding':{'path':str(mandate_path),'sha256':sha(mandate_path)},
        **{k:crypto[k] for k in ('policyBinding','signatureDirectory','opensslBinding')},
        'signingKeyBinding':{'path':str(key),'sha256':sha(key)},'keyRef':'installer-key',
        'brokerEmissionJournal':str(directory/'approval-emission.json'),
        'issuanceClaimPath':str(directory/'installer-signing-claim.json'),'budgetSeconds':12})
    producers['approval']={k:{'path':str(p),'sha256':sha(p)} for k,p in
        [('python',Path(python)),('source',source/issuer.SELF),('configuration',configuration)]}
    (directory/'approval-results').mkdir(mode=0o700)
    paths=[broker.SELF,broker.PREPARER,broker.DRIVER,*('tools/'+m+'.py' for m in broker.MODULES)]
    return {'schema':'ouf.semantic-deployment-broker.v1','sourceRoot':str(source),'sourceHashes':{p:sha(source/p) for p in paths},
        'authorities':{'installationRef':'ci-installation','entityRef':'ci-entity','intentIssuerRef':'ci-installer',
            'attestorRef':'ci-node-verifier','approvalIssuerRef':'ci-installer'},
        'intentBinding':{'path':str(intent_path),'sha256':sha(intent_path)},
        **{k:crypto[k] for k in ('policyBinding','signatureDirectory','opensslBinding')},'producers':producers,
        'preparerTemplate':{'path':str(template_path),'sha256':sha(template_path)},'candidateRoot':str(directory),'runtimeRootParent':'/run'}
