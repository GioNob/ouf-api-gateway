"""CI-only producer bridge exercising the real v2 preparer/v4 driver.

Synthetic installer/attestor mandates are confined to this fixture. This is not
a deployable signer, image verifier or source-package component.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

parser=argparse.ArgumentParser()
for key in ('configuration','container-id','bundle','runtime-root','mode'): parser.add_argument('--'+key,required=True)
args=parser.parse_args(); cfg_raw=Path(args.configuration).read_bytes(); cfg=json.loads(cfg_raw)
sys.path.insert(0,cfg['repository'])
from scripts import semantic_provider_admission_preparer as preparer
from tests.test_semantic_shared_coordination_native import NativeTest
from tools.materialize_southbound_kernel import materialize
from tools.semantic_provider_deployment_admission import application_hash,transport_hash
from tools.semantic_provider_deployment_consumption import Consumption
from tools.semantic_provider_preexec import digest
from tools.semantic_provider_preexec_native import NativeBackend
from tools.semantic_provider_lease_coordination import PrivateJournal,hold_common_lock
from tools.semantic_provider_lease_nft import structure_hash

root=Path(args.bundle).parent; cid=args.container_id; approved=cfg['approved'][cid]
def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def raw(value): return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
def private(path,value): path.write_bytes(raw(value)); path.chmod(0o600)
def run(*argv,payload=None):
    return subprocess.run(argv,input=payload,capture_output=True,text=True,timeout=20,check=True).stdout
def failed(kind,value,tb):
    lines=[]
    while tb:
        if tb.tb_frame.f_code.co_filename==__file__: lines.append(tb.tb_lineno)
        tb=tb.tb_next
    private(root/'fixture-failure.json',{'type':kind.__name__,'lines':lines})
sys.excepthook=failed
intent=cfg['intent']; intent_raw=raw(intent)
binding={k:intent[k] for k in ('installationRef','entityRef','containerId','transactionId')}
binding.update(intentHash=hashlib.sha256(intent_raw).hexdigest(),configurationHash=hashlib.sha256(cfg_raw).hexdigest())
lock=Path(cfg['lock']); gate=Consumption(binding,PrivateJournal(root/'deployment.json'),lambda:hold_common_lock(lock))
authorities={'installationRef':'ci-installation','entityRef':'ci-entity','intentIssuerRef':'ci-installer',
             'attestorRef':'ci-node-verifier','approvalIssuerRef':'ci-installer'}
authenticated={}
def trust(payload,role,issuer,installation,entity):
    # CI producer custody: only exact records issued below under their role are
    # authenticated. Real deployments must bind a cryptographic/trusted issuer.
    return authenticated.get((role,payload))==(issuer,installation,entity)
def issue(value,role,issuer):
    payload=raw(value); authenticated[(role,payload)]=(issuer,'ci-installation','ci-entity')
    if cfg.get('crypto'):
        crypto=cfg['crypto'];keyref='verifier-key' if role=='CREATION_ATTESTATION' else 'installer-key'
        header={'schema':'ouf.semantic-deployment-detached-signature.v1','algorithm':'Ed25519','keyRef':keyref,
            'role':role,'issuerRef':issuer,'installationRef':'ci-installation','entityRef':'ci-entity',
            'payloadHash':hashlib.sha256(payload).hexdigest()}
        canonical=json.dumps(header,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')
        frame=b'OUF-DEPLOYMENT-EVIDENCE\x00V1\x00'+len(canonical).to_bytes(4,'big')+canonical+len(payload).to_bytes(4,'big')+payload
        path=root/'ci-frame.bin';path.write_bytes(frame);path.chmod(0o600)
        sig=subprocess.run([crypto['opensslBinding']['path'],'pkeyutl','-sign','-rawin','-inkey',crypto['privateKeys'][keyref],
            '-in',str(path)],check=True,capture_output=True,timeout=3).stdout
        private(Path(crypto['signatureDirectory'])/(header['payloadHash']+'.'+role+'.json'),{**header,'signature':sig.hex()})
        name={'DEPLOYMENT_INTENT':'intent','CREATION_ATTESTATION':'attestation','FINAL_DEPLOYMENT_APPROVAL':'approval'}[role]
        (root/(name+'.json')).write_bytes(payload);(root/(name+'.json')).chmod(0o600)
    return payload
if cfg.get('crypto'):
    from tools.semantic_provider_deployment_authentication import DetachedAuthenticator
    crypto=cfg['crypto'];trust=DetachedAuthenticator(crypto['policyBinding'],crypto['signatureDirectory'],crypto['opensslBinding'])
issue(intent,'DEPLOYMENT_INTENT','ci-installer')
config=root/'preparer.json'; argv=[cfg['python'],'-I','-B',str(Path(cfg['source'])/preparer.SELF),
    '--configuration',str(config),'--container-id',cid,'--bundle',args.bundle,'--runtime-root',args.runtime_root]
if args.mode=='cleanup': run(*argv,'--mode','cleanup'); raise SystemExit(0)
state=json.loads(sys.stdin.buffer.read(16385))
if args.mode=='authorize-create':
    gate.authorize_create(intent_raw,authorities,trust)
    kernel=cfg['kernel']
    run(cfg['commands']['nft'],'-f','-',payload=materialize(kernel,empty_provider_sets=True)['nftRules'])
    lease_hash=structure_hash({f:json.loads(run(cfg['commands']['nft'],'-j','list','table',f,kernel['tableName']))
                              for f in ('inet','bridge')})
    coordination={'transactionId':intent['transactionId'],'configurationHash':digest(kernel),'leaseStructureHash':lease_hash}
    private(root/'coordination.json',{'schema':'ouf.semantic-lease-coordination.v1',**coordination,
        'state':'QUIESCED','leaseAuthorized':False,'startAuthorized':False,'leaseAddresses':[[]]})
    raise SystemExit(0)
assert state['id']==cid and state['bundle']==args.bundle and state['status']=='created'
actual=json.loads(run(cfg['runc'],'--root',args.runtime_root,'state',cid))
assert all(actual[k]==state[k] for k in ('id','bundle','status','pid'))
oci=json.loads((Path(args.bundle)/'config.json').read_bytes())
generation=NativeBackend.generation(None,state['pid'])
if args.mode=='record-created':
    gate.created(application_hash(oci),generation); raise SystemExit(0)
assert args.mode=='prepare'
assert oci['process']['args']==approved['command']
assert any(m.get('destination')=='/proof' and m.get('source')==approved['proof'] for m in oci['mounts'])
assert sha(Path(oci['root']['path'])/'bin/busybox')==cfg['busyboxHash']
candidate={'containerId':cid,'transactionId':intent['transactionId'],'bundlePath':args.bundle,
    'applicationHash':application_hash(oci),'networkBindings':cfg['networkBindings'],'transport':cfg['transport'],
    'tableName':approved['sharedTable'],'runtimeBinding':{'path':cfg['runc'],'sha256':cfg['runcHash'],'root':args.runtime_root}}
assert transport_hash(candidate)==intent['transportHash']
creation={'schema':'ouf.semantic-container-creation-acceptance.v1','containerId':cid,
    'applicationHash':candidate['applicationHash'],'transportHash':intent['transportHash'],'accepted':True}
now=int(time.time())
attestation={'schema':'ouf.semantic-created-candidate-attestation.v1','attestorRef':'ci-node-verifier',
    'installationRef':'ci-installation','entityRef':'ci-entity','intentHash':binding['intentHash'],
    **{k:intent[k] for k in ('containerId','transactionId','artifactHash','deploymentConstraintsHash','transportHash','runtimeExecutableHash')},
    'applicationHash':candidate['applicationHash'],'generation':generation,'observedAt':now,'creationAcceptance':creation}
scope={'issuerRef':'ci-installer','installationRef':'ci-installation','entityRef':'ci-entity','approvalRef':'ci-final-'+cid[:8],
    'containerId':cid,'transactionId':intent['transactionId'],'applicationHash':candidate['applicationHash'],
    'transportHash':intent['transportHash'],'creationAcceptanceHash':digest(creation)}
approval={'schema':'ouf.semantic-deployment-admission-approval.v1',**scope,'issuedAt':now,
    'expiresAt':intent['expiresAt'],'state':'ACTIVE','infrastructureAuthorized':True,'applicationStartAuthorized':True}
evidence=gate.ready(intent_raw,issue(attestation,'CREATION_ATTESTATION','ci-node-verifier'),
                    issue(approval,'FINAL_DEPLOYMENT_APPROVAL','ci-installer'),authorities,trust)
private(root/'creation.json',creation); private(root/'approval.json',approval)
candidate['creationAcceptance']={'path':str(root/'creation.json'),'sha256':sha(root/'creation.json')}
candidate['authorityBinding']={'path':str(root/'approval.json'),'sha256':sha(root/'approval.json'),
                               'issuedAt':now,'expiresAt':intent['expiresAt']}
candidate['authorityScope']=scope
modules=(*preparer.MODULES,'semantic_provider_deployment_protocol','semantic_provider_deployment_consumption')
if cfg.get('crypto'): modules=(*modules,'semantic_provider_deployment_authentication','semantic_provider_deployment_reauthorization')
hashes={p:sha(Path(cfg['source'])/p) for p in [preparer.SELF,preparer.DRIVER,*('tools/'+m+'.py' for m in modules)]}
commands={**cfg['commands'],**cfg['mountCommands']}
coord=json.loads((root/'coordination.json').read_bytes()); coordination={k:coord[k] for k in ('transactionId','configurationHash','leaseStructureHash')}
value={'schema':'ouf.semantic-admission-preparer.v2','sourceRoot':cfg['source'],'sourceHashes':hashes,
    'pythonPath':cfg['python'],'pythonHash':sha(cfg['python']),'commands':commands,'commandHashes':{k:sha(v) for k,v in commands.items()},
    'candidate':candidate,'kernel':cfg['kernel'],'dns':{'resolvers':['127.0.0.1'],'resolverPort':53,'timeoutSeconds':2,
    'maxLeaseSeconds':30,'applyBudgetSeconds':1},'coordinationBinding':coordination,'coordinationJournal':str(root/'coordination.json'),
    'lockFile':str(lock),'budgetSeconds':5,'hostNetworkNamespace':os.stat('/proc/self/ns/net').st_ino,
    'consumptionBinding':{'journalPath':str(root/'deployment.json'),'binding':binding,'evidenceHash':digest(evidence)}}
if cfg.get('crypto'):
    value['schema']='ouf.semantic-admission-preparer.v3'
    value['authenticationBinding']={'records':{name:{'path':str(root/(name+'.json')),'sha256':sha(root/(name+'.json'))}
        for name in ('intent','attestation','approval')},'authorities':authorities,
        **{k:cfg['crypto'][k] for k in ('policyBinding','signatureDirectory','opensslBinding')}}
private(config,value)
private(root/'admission.json',{'schema':'ouf.semantic-admission-journal.v1','transactionId':intent['transactionId'],
    'configurationHash':sha(config),'state':'STAGED','driverHash':None,'namespaceOwned':False,'namespaceInode':None,'containerGeneration':None})
run(*argv,'--mode','prepare',payload=json.dumps(state))
gate.seal_driver(sha(root/'driver.json'))
if approved['leaseDrift']:
    coord['state']='QUIESCING'; private(root/'coordination.json',coord)

if approved.get('signatureDrift'):
    path=Path(cfg['crypto']['signatureDirectory'])/(binding['intentHash']+'.DEPLOYMENT_INTENT.json')
    record=json.loads(path.read_bytes());record['signature']=('00' if record['signature'][:2]!='00' else '01')+record['signature'][2:]
    private(path,record)
