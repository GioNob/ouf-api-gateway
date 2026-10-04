"""Operational local broker: existing mandates, created candidate, one issuance.

No signer, image verifier, runtime registration, implicit create/start or recovery.
The adapter calls the four phases. The installer provisions immutable profiles
and STAGED journals; uncertain phases are preserved, never resumed automatically.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
import types

SELF = 'scripts/semantic_provider_deployment_broker.py'
PREPARER = 'scripts/semantic_provider_admission_preparer.py'
DRIVER = 'scripts/semantic_provider_preexec_hook.py'
MODULES = ('materialize_southbound_kernel','materialize_southbound_lease_refresh','semantic_provider_dns',
    'semantic_provider_lease_nft','semantic_provider_lease_owner','materialize_semantic_shared_faces',
    'semantic_provider_lease_coordination','semantic_provider_preexec','semantic_provider_preexec_native',
    'semantic_provider_deployment_admission','semantic_provider_deployment_protocol',
    'semantic_provider_deployment_consumption','semantic_provider_deployment_authentication',
    'semantic_provider_deployment_reauthorization','semantic_provider_deployment_producer')

def require(ok, reason):
    if not ok: raise RuntimeError(reason)


def signature(value):
    # A successful read may update atime (relatime); that is not content drift.
    return tuple(getattr(value,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink',
                                          'st_size','st_mtime_ns','st_ctime_ns'))


def private(path):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'PRIVATE_PATH_REQUIRED')
    for parent in (path.parent,*path.parent.parents):
        st = parent.lstat()
        require(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022, 'PRIVATE_ANCESTOR_REQUIRED')
    fd = os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
                and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1
                and before.st_size <= 131072, 'PRIVATE_FILE_REQUIRED')
        raw = os.read(fd,131073); after = os.fstat(fd)
        require(len(raw) <= 131072 and signature(before) == signature(after), 'PRIVATE_READ_DRIFT')
        return raw
    finally: os.close(fd)


def parse(raw):
    def unique(pairs):
        out = {}
        for k,v in pairs:
            require(k not in out,'DUPLICATE_JSON_KEY'); out[k] = v
        return out
    return json.loads(raw,object_pairs_hook=unique)


def executable(path, expected):
    p = Path(path); require(p.is_absolute() and '..' not in p.parts,'EXPLICIT_EXECUTABLE_REQUIRED')
    for parent in (p.parent,*p.parent.parents):
        st = parent.lstat()
        require(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022,'TRUSTED_COMMAND_ANCESTOR_REQUIRED')
    fd = os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_mode & 0o111
                and not before.st_mode & 0o022 and before.st_size <= 64000000,'TRUSTED_COMMAND_REQUIRED')
        h = hashlib.sha256(); size = 0
        while True:
            raw = os.read(fd,65536)
            if not raw: break
            size += len(raw); require(size <= 64000000,'COMMAND_SIZE_UNBOUNDED')
            h.update(raw)
        require(h.hexdigest() == expected and signature(os.fstat(fd)) == signature(before),'COMMAND_BINARY_DRIFT')
    finally: os.close(fd)


def create(path,value):
    return create_bytes(path, json.dumps(value,sort_keys=True,separators=(',',':')).encode())


def create_bytes(path,raw):
    require(len(raw) <= 131072,'PRIVATE_RESULT_UNBOUNDED')
    fd = os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,'wb',closefd=False) as f: f.write(raw); f.flush(); os.fsync(fd)
    finally: os.close(fd)
    fd = os.open(Path(path).parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)


def load(path):
    raw = private(path); cfg = parse(raw)
    fields = {'schema','sourceRoot','sourceHashes','authorities','intentBinding','policyBinding',
              'signatureDirectory','opensslBinding','producers','preparerTemplate','candidateRoot','runtimeRootParent'}
    require(set(cfg) == fields and cfg['schema'] == 'ouf.semantic-deployment-broker.v1', 'EXACT_BROKER_CONFIGURATION_REQUIRED')
    root = Path(cfg['sourceRoot'])
    require(stat.S_IMODE(root.lstat().st_mode) == 0o700, 'PRIVATE_SOURCE_ROOT_REQUIRED')
    paths = [SELF,PREPARER,DRIVER,*('tools/'+m+'.py' for m in MODULES)]
    require(Path(__file__).absolute() == root/SELF and set(cfg['sourceHashes']) == set(paths),'EXACT_BROKER_SOURCE_SET_REQUIRED')
    verified = {p:private(root/p) for p in paths}
    for p, content in verified.items():
        require(hashlib.sha256(content).hexdigest() == cfg['sourceHashes'][p],'BROKER_SOURCE_PACKAGE_DRIFT')
    package = types.ModuleType('tools');package.__path__=[];sys.modules['tools']=package
    for name in MODULES:
        full='tools.'+name;module=types.ModuleType(full);module.__package__='tools'
        module.__file__=str(root/'tools'/(name+'.py'));sys.modules[full]=module;setattr(package,name,module)
        exec(compile(verified['tools/'+name+'.py'],module.__file__,'exec'),module.__dict__)
    require(private(path) == raw,'BROKER_CONFIGURATION_DRIFT')
    return cfg,raw


class Broker:
    def __init__(self, cfg, raw, configuration_path, args, clock=time.time):
        from tools.semantic_provider_deployment_authentication import DetachedAuthenticator, VerificationBudget, binding, private_bytes
        from tools.semantic_provider_deployment_protocol import context, decode
        from tools.semantic_provider_deployment_consumption import Consumption
        from tools.semantic_provider_lease_coordination import PrivateJournal, hold_common_lock
        self.cfg,self.raw,self.configuration_path,self.args,self.clock=cfg,raw,configuration_path,args,clock
        self.budget=VerificationBudget(18)
        self.ctx=context(cfg['authorities']); self.root=Path(cfg['candidateRoot'])
        require(stat.S_IMODE(self.root.lstat().st_mode)==0o700,'PRIVATE_CANDIDATE_ROOT_REQUIRED')
        self.intent_raw=self.read_binding(cfg['intentBinding']);self.intent=decode(self.intent_raw)
        self.cid=self.intent.get('containerId');self.txn=self.intent.get('transactionId')
        require(args.container_id==self.cid and args.bundle==str(self.root/'bundle'),'BROKER_CANDIDATE_BINDING_DRIFT')
        runtime=Path(args.runtime_root)
        require(runtime.is_absolute() and '..' not in runtime.parts and runtime==runtime.resolve()
                and runtime.is_relative_to(Path(cfg['runtimeRootParent'])) and runtime!=Path(cfg['runtimeRootParent']),
                'BROKER_RUNTIME_ROOT_DRIFT')
        self.template_raw=self.read_binding(cfg['preparerTemplate']);self.template=decode(self.template_raw)
        fields={'schema','pythonPath','pythonHash','commands','commandHashes','candidate','kernel','dns',
                'coordinationBinding','coordinationJournal','lockFile','budgetSeconds','hostNetworkNamespace'}
        require(set(self.template)==fields and self.template['schema']=='ouf.semantic-admission-preparer-template.v1',
                'EXACT_BROKER_PREPARER_TEMPLATE_REQUIRED')
        candidate=self.template['candidate']
        require(set(candidate)=={'containerId','transactionId','networkBindings','transport','tableName','runtimeBinding'}
                and candidate['containerId']==self.cid and candidate['transactionId']==self.txn
                and set(candidate['runtimeBinding'])=={'path','sha256'},'EXACT_BROKER_CANDIDATE_TEMPLATE_REQUIRED')
        require(candidate['runtimeBinding']['sha256']==self.intent.get('runtimeExecutableHash'),'BROKER_RUNTIME_INTENT_DRIFT')
        require(set(cfg['producers'])=={'attestation','approval'},'EXPLICIT_BROKER_PRODUCERS_REQUIRED')
        self.lock=lambda:hold_common_lock(Path(self.template['lockFile']))
        self.verifier=DetachedAuthenticator(cfg['policyBinding'],cfg['signatureDirectory'],cfg['opensslBinding'],clock,self.budget)
        self.binding={k:self.intent[k] for k in ('installationRef','entityRef','containerId','transactionId')}
        self.binding.update(intentHash=hashlib.sha256(self.intent_raw).hexdigest(),configurationHash=hashlib.sha256(raw).hexdigest())
        self.gate=Consumption(self.binding,PrivateJournal(self.root/'deployment.json'),self.lock)
        self.journal=PrivateJournal(self.root/'broker-state.json')
        self.custodies=[]

    def read_binding(self, value):
        from tools.semantic_provider_deployment_authentication import binding, private_bytes
        record=binding(value);raw=private_bytes(Path(record['path']))
        require(hashlib.sha256(raw).hexdigest()==record['sha256'],'BROKER_BOUND_FILE_DRIFT')
        return raw

    def stable(self):
        self.budget.check()
        require(private(self.configuration_path)==self.raw and self.read_binding(self.cfg['intentBinding'])==self.intent_raw
                and self.read_binding(self.cfg['preparerTemplate'])==self.template_raw,'BROKER_INPUT_CHANGED')
        for path,expected in self.cfg['sourceHashes'].items():
            require(hashlib.sha256(private(Path(self.cfg['sourceRoot'])/path)).hexdigest()==expected,'BROKER_SOURCE_PACKAGE_DRIFT')
        for path,raw in self.custodies:
            from tools.semantic_provider_deployment_authentication import private_bytes
            require(private_bytes(path,262144)==raw,'BROKER_PRODUCER_CUSTODY_DRIFT')

    def record(self):
        value=self.journal.read()
        require(set(value)=={'schema',*self.binding,'state','runtimeRoot','bundleHash','driverHash'}
                and value['schema']=='ouf.semantic-deployment-broker-journal.v1'
                and all(value[k]==v for k,v in self.binding.items())
                and value['state'] in ('STAGED','CREATING','CREATED','PREPARING','PROTECTED','CLEANED'),
                'FOREIGN_BROKER_JOURNAL')
        if value['state']=='STAGED':require(all(value[k] is None for k in ('runtimeRoot','bundleHash','driverHash')),'BROKER_PHASE_DRIFT')
        else:
            require(value['runtimeRoot']==self.args.runtime_root,'BROKER_RUNTIME_ROOT_DRIFT')
            from tools.semantic_provider_deployment_protocol import hashed
            require(hashed(value['bundleHash']) and (hashed(value['driverHash']) if value['state'] in ('PROTECTED','CLEANED')
                    else value['driverHash'] is None),'BROKER_PHASE_DRIFT')
        return value

    def publish(self, old, **extra):
        require(self.record()==old,'BROKER_JOURNAL_CHANGED_UNDER_LOCK')
        value={**old,**extra};self.journal.write(old,value)
        require(self.record()==value,'BROKER_PUBLICATION_UNPROVEN')
        return value

    def runtime(self, state):
        from tools.semantic_provider_preexec_native import NativeBackend
        from tools.semantic_provider_deployment_admission import application_hash
        self.stable();runtime=self.template['candidate']['runtimeBinding'];executable(runtime['path'],runtime['sha256'])
        with tempfile.TemporaryFile() as out:
            p=subprocess.run([runtime['path'],'--root',self.args.runtime_root,'state',self.cid],stdout=out,
                stderr=subprocess.DEVNULL,timeout=self.budget.remaining(2),env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
            out.seek(0);raw=out.read(16385)
        require(p.returncode==0 and len(raw)<=16384,'BROKER_CREATED_RUNTIME_UNPROVEN')
        actual=parse(raw)
        require(actual.get('id')==self.cid and actual.get('bundle')==self.args.bundle and actual.get('status')=='created'
                and type(actual.get('pid')) is int and actual['pid']>1
                and all(actual.get(k)==state.get(k) for k in ('id','bundle','status','pid')),'BROKER_LIVE_CREATED_STATE_DRIFT')
        executable(runtime['path'],runtime['sha256'])
        oci=parse(private(Path(self.args.bundle)/'config.json'))
        return application_hash(oci),NativeBackend.generation(None,actual['pid'])

    def emit(self, name, role, facts):
        from tools.semantic_provider_deployment_producer import LocalEvidenceProducer, ProducerEmission, encoded
        from tools.semantic_provider_lease_coordination import PrivateJournal
        from tools.semantic_provider_deployment_authentication import private_bytes
        producer=LocalEvidenceProducer(self.cfg['producers'][name],self.ctx,self.verifier,self.budget)
        journal=PrivateJournal(self.root/(name+'-emission.json'))
        gate=ProducerEmission(producer,role,facts,journal,self.root/(name+'-results'),self.lock)
        # Only the already claimed PREPARING phase may allocate this first-use
        # claim. O_EXCL and the whole-phase journal prevent implicit recovery.
        create(self.root/(name+'-emission.json'),
               {'schema':'ouf.semantic-local-producer-emission.v1',**gate.binding,'state':'UNUSED','resultHash':None})
        value=gate.emit_locked();custody=value['custody'];raw=private_bytes(Path(custody['path']),262144)
        require(hashlib.sha256(raw).hexdigest()==custody['sha256'],'BROKER_PRODUCER_CUSTODY_DRIFT')
        self.custodies.append((Path(custody['path']),raw))
        self.custodies.append((self.root/(name+'-emission.json'),private(self.root/(name+'-emission.json'))))
        return value['result']

    def publish_result(self,name,role,result):
        from tools.semantic_provider_deployment_producer import encoded
        raw=result['record'];path=self.root/(name+'.json');create_bytes(path,raw)
        require(private(path)==raw,'BROKER_RECORD_PUBLICATION_DRIFT')
        signature=Path(self.cfg['signatureDirectory'])/(hashlib.sha256(raw).hexdigest()+'.'+role+'.json')
        create(signature,parse(result['recordSignature']))
        require(private(signature)==result['recordSignature'],'BROKER_SIGNATURE_PUBLICATION_DRIFT')
        self.custodies.extend([(path,raw),(signature,result['recordSignature'])])
        return {'path':str(path),'sha256':hashlib.sha256(raw).hexdigest()}

    def prepare(self,state):
        from tools.semantic_provider_deployment_protocol import validate_intent,validate_creation,validate_final,decode
        from tools.semantic_provider_deployment_admission import transport_hash
        from tools.semantic_provider_preexec import digest
        with self.lock():
            self.stable();old=self.record();created=self.gate.record()
            require(old['state']=='CREATED' and created['state']=='CREATED','DO_NOT_REPLAY_BROKER_PREPARATION')
            app,generation=self.runtime(state)
            require(app==created['bundleHash']==old['bundleHash'] and generation==created['generation'],'BROKER_CREATED_GENERATION_DRIFT')
            validate_intent(self.intent_raw,self.ctx,self.verifier,self.clock)
            candidate=copy.deepcopy(self.template['candidate']);candidate.update(bundlePath=self.args.bundle,applicationHash=app)
            candidate['runtimeBinding']['root']=self.args.runtime_root
            require(transport_hash(candidate)==self.intent['transportHash'],'BROKER_TRANSPORT_INTENT_DRIFT')
            pending=self.publish(old,state='PREPARING')
            facts={k:self.intent[k] for k in ('containerId','transactionId','artifactHash','deploymentConstraintsHash','transportHash','runtimeExecutableHash')}
            facts.update(intentHash=self.binding['intentHash'],applicationHash=app,generation=generation)
            att=self.emit('attestation','CREATION_ATTESTATION',facts)
            att_binding=self.publish_result('attestation','CREATION_ATTESTATION',att)
            attested=validate_creation(self.intent_raw,att['record'],self.ctx,self.verifier,self.clock)
            # Invalid complete creation claims never reach the approval producer.
            approval_facts={**facts,'attestationHash':hashlib.sha256(att['record']).hexdigest(),
                            'creationAcceptanceHash':digest(attested['creationAcceptance'])}
            approval=self.emit('approval','FINAL_DEPLOYMENT_APPROVAL',approval_facts)
            approval_binding=self.publish_result('approval','FINAL_DEPLOYMENT_APPROVAL',approval)
            self.stable();require(self.runtime(state)==(app,generation),'BROKER_CREATED_GENERATION_DRIFT')
            evidence=self.gate.ready_locked(self.intent_raw,att['record'],approval['record'],self.ctx,self.verifier,self.clock)
            accepted=attested['creationAcceptance'];create(self.root/'creation.json',accepted)
            candidate.update(creationAcceptance={'path':str(self.root/'creation.json'),'sha256':digest(accepted)},
                authorityBinding={**approval_binding,**{k:decode(approval['record'])[k] for k in ('issuedAt','expiresAt')}},authorityScope=evidence['scope'])
            value={**copy.deepcopy(self.template),'schema':'ouf.semantic-admission-preparer.v3','candidate':candidate,
                'sourceRoot':self.cfg['sourceRoot'],'sourceHashes':{p:h for p,h in self.cfg['sourceHashes'].items()
                    if p not in (SELF,'tools/semantic_provider_deployment_producer.py')},
                'consumptionBinding':{'journalPath':str(self.root/'deployment.json'),'binding':self.binding,'evidenceHash':digest(evidence)},
                'authenticationBinding':{'records':{'intent':self.cfg['intentBinding'],'attestation':att_binding,'approval':approval_binding},
                    'authorities':self.ctx,**{k:self.cfg[k] for k in ('policyBinding','signatureDirectory','opensslBinding')}}}
            create(self.root/'preparer.json',value)
            create(self.root/'admission.json',{'schema':'ouf.semantic-admission-journal.v1','transactionId':self.txn,
                'configurationHash':digest(value),'state':'STAGED','driverHash':None,'namespaceOwned':False,
                'namespaceInode':None,'containerGeneration':None})
            self.stable();require(self.record()==pending,'BROKER_JOURNAL_CHANGED_UNDER_LOCK')
        # The preparer acquires the same common lock itself. Never nest flock
        # across processes; its remaining wall-clock time is this phase's budget.
        self.invoke_preparer('prepare',state)
        with self.lock():
            self.stable();require(self.record()==pending,'BROKER_JOURNAL_CHANGED_UNDER_LOCK')
            require(self.runtime(state)==(app,generation),'BROKER_CREATED_GENERATION_DRIFT')
            raw=private(self.root/'driver.json');grant=parse(raw);driver_hash=hashlib.sha256(raw).hexdigest()
            admission=parse(private(self.root/'admission.json'))
            require(grant['schema']=='ouf.semantic-preexec-driver.v5' and grant['consumptionBinding']==value['consumptionBinding']
                    and grant['authenticationBinding']==value['authenticationBinding']
                    and admission['state']=='PROTECTED' and admission['driverHash']==driver_hash,'BROKER_PREPARED_DRIVER_DRIFT')
            validate_final(self.intent_raw,att['record'],approval['record'],self.ctx,self.verifier,self.clock)
            self.gate.seal_driver_locked(driver_hash)
            self.stable();require(self.record()==pending,'BROKER_JOURNAL_CHANGED_UNDER_LOCK')
            require(self.gate.record()['driverHash']==driver_hash,'BROKER_DRIVER_SEAL_UNPROVEN')
            self.publish(pending,state='PROTECTED',driverHash=driver_hash)

    def invoke_preparer(self,mode,state=None):
        executable(self.template['pythonPath'],self.template['pythonHash']);self.stable()
        argv=[self.template['pythonPath'],'-I','-B',str(Path(self.cfg['sourceRoot'])/PREPARER),
            '--configuration',str(self.root/'preparer.json'),'--container-id',self.cid,'--bundle',self.args.bundle,
            '--runtime-root',self.args.runtime_root,'--mode',mode]
        p=subprocess.run(argv,input=None if state is None else json.dumps(state).encode(),stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,timeout=self.budget.remaining(18),env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
        require(p.returncode==0,'BROKER_SEALED_PREPARER_DENIED');self.stable()

    def operate(self,state):
        if self.args.mode=='authorize-create':
            from tools.semantic_provider_deployment_protocol import hashed
            require(set(state)=={'id','bundleHash'} and state['id']==self.cid and hashed(state['bundleHash']),'EXACT_BROKER_CREATE_REQUEST_REQUIRED')
            with self.lock():require(self.record()['state']=='STAGED','DO_NOT_REPLAY_BROKER_CREATE')
            self.gate.authorize_create(self.intent_raw,self.ctx,self.verifier,self.clock)
            with self.lock():
                self.stable();old=self.record();require(old['state']=='STAGED','DO_NOT_REPLAY_BROKER_CREATE')
                self.publish(old,state='CREATING',runtimeRoot=self.args.runtime_root,bundleHash=state['bundleHash'])
        elif self.args.mode=='record-created':
            app,generation=self.runtime(state)
            with self.lock():
                old=self.record();require(old['state']=='CREATING' and old['bundleHash']==app,'BROKER_CREATION_BINDING_DRIFT')
            self.gate.created(app,generation)
            with self.lock():self.publish(old,state='CREATED')
        elif self.args.mode=='prepare':self.prepare(state)
        elif self.args.mode=='cleanup':
            with self.lock():
                old=self.record();require(old['state']=='PROTECTED' and hashlib.sha256(private(self.root/'driver.json')).hexdigest()==old['driverHash'],
                    'OWNED_BROKER_CLEANUP_REQUIRED')
            self.invoke_preparer('cleanup')
            with self.lock():self.publish(old,state='CLEANED')
        else:require(False,'UNKNOWN_BROKER_PHASE')


def main():
    parser=argparse.ArgumentParser()
    for key in ('configuration','container-id','bundle','runtime-root','mode'):parser.add_argument('--'+key,required=True)
    args=parser.parse_args()
    try:
        cfg,raw=load(args.configuration)
        state={} if args.mode=='cleanup' else parse(sys.stdin.buffer.read(16385))
        Broker(cfg,raw,args.configuration,args).operate(state)
        print('SEMANTIC_DEPLOYMENT_BROKER=PASS MODE='+args.mode+' NO_KEYS_GENERATED=true NO_RUNTIME_REGISTERED=true NOT_RELEASE_ACCEPTANCE=true NO_SECRETS_PRINTED=true')
    except Exception:
        print('SEMANTIC_DEPLOYMENT_BROKER=DENIED EXPLICIT_RECOVERY_REQUIRED=true NO_SECRETS_PRINTED=true',file=sys.stderr)
        return 1
    return 0


if __name__=='__main__':raise SystemExit(main())
