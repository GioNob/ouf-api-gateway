"""Bounded transport for explicitly mandated local evidence producers.

No keys, mandate, signature issuance or runtime operation is implemented here.
The optional emission wrapper persists claim/result custody without retry. A configured producer may issue evidence under its own
explicit mandate. Its reply and a separate request binding must both verify.
"""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess

from tools.semantic_provider_deployment_authentication import private_bytes, binding, ancestors, attributes, decode, policy
from tools.semantic_provider_deployment_protocol import context, hashed
from tools.semantic_provider_deployment_consumption import generation
from tools.semantic_provider_preexec import PreexecDenied

OUTPUT_LIMIT = 196608
ROLE_ISSUER = {'CREATION_ATTESTATION':'attestorRef', 'FINAL_DEPLOYMENT_APPROVAL':'approvalIssuerRef'}


def require(ok, reason):
    if not ok: raise PreexecDenied(reason)


def encoded(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')


def program(value, budget):
    value = binding(value); path = Path(value['path']); ancestors(path); budget.check()
    fd = os.open(path, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
                and before.st_mode & 0o111 and not before.st_mode & 0o022 and before.st_size <= 64000000,
                'TRUSTED_PRODUCER_INTERPRETER_REQUIRED')
        digest = hashlib.sha256(); total = 0
        while True:
            budget.check(); raw = os.read(fd,65536)
            if not raw: break
            total += len(raw); require(total <= 64000000, 'PRODUCER_EXECUTABLE_UNBOUNDED'); digest.update(raw)
        require(digest.hexdigest() == value['sha256'] and attributes(before) == attributes(os.fstat(fd)),
                'PRODUCER_INTERPRETER_DRIFT')
    finally: os.close(fd)
    return str(path)


class LocalEvidenceProducer:
    def __init__(self, configured, authorities, verifier, budget):
        require(type(configured) is dict and set(configured) == {'python','source','configuration'},
                'EXACT_LOCAL_PRODUCER_BINDING_REQUIRED')
        self.configured = {key:binding(value) for key,value in configured.items()}
        self.authorities = context(authorities)
        self.verifier, self.budget = verifier, budget
        require(callable(getattr(verifier,'verify_detached',None)) and callable(getattr(budget,'check',None)),
                'EXPLICIT_PRODUCER_VERIFIER_AND_BUDGET_REQUIRED')
        # The verification calls and producer invocation share one deadline.
        require(verifier.budget is budget, 'SHARED_PRODUCER_VERIFICATION_DEADLINE_REQUIRED')

    def pinned(self):
        executable = program(self.configured['python'],self.budget)
        private = {}
        for key in ('source','configuration'):
            item = self.configured[key]; raw = private_bytes(Path(item['path']))
            require(hashlib.sha256(raw).hexdigest() == item['sha256'], 'LOCAL_PRODUCER_SOURCE_OR_CONFIGURATION_DRIFT')
            private[key] = raw
        self.budget.check()
        return executable, private

    def request(self, role, facts):
        require(type(role) is str and role in ROLE_ISSUER, 'TYPED_LOCAL_PRODUCER_ROLE_REQUIRED')
        fields = {'containerId','transactionId','intentHash','artifactHash','deploymentConstraintsHash',
                  'applicationHash','transportHash','runtimeExecutableHash','generation'}
        if role == 'FINAL_DEPLOYMENT_APPROVAL': fields |= {'attestationHash','creationAcceptanceHash'}
        require(type(facts) is dict and set(facts) == fields and all(hashed(facts[k]) for k in fields-{'generation'}),
                'EXACT_LOCAL_PRODUCER_FACTS_REQUIRED')
        value = {'schema':'ouf.semantic-local-producer-request.v1','role':role,
            'installationRef':self.authorities['installationRef'],'entityRef':self.authorities['entityRef'],
            'issuerRef':self.authorities[ROLE_ISSUER[role]],**copy.deepcopy(facts)}
        value['generation'] = generation(value['generation'])
        raw = encoded(value); require(len(raw) <= 4096, 'LOCAL_PRODUCER_REQUEST_UNBOUNDED')
        return value, raw

    def invoke(self, executable, request):
        self.budget.check()
        argv = [executable,'-I','-B',self.configured['source']['path'],'--configuration',self.configured['configuration']['path']]
        child = None; waited = False
        try:
            child = subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                cwd='/',start_new_session=True,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
            # Request is <= PIPE_BUF; output is read incrementally without an
            # unbounded communicate() buffer or disk spool.
            child.stdin.write(request); child.stdin.close()
            chunks = []; size = 0
            with selectors.DefaultSelector() as selector:
                os.set_blocking(child.stdout.fileno(),False); selector.register(child.stdout,selectors.EVENT_READ)
                while True:
                    events = selector.select(self.budget.remaining(5))
                    require(events, 'LOCAL_PRODUCER_DEADLINE_MISSED')
                    chunk = os.read(child.stdout.fileno(), min(65536,OUTPUT_LIMIT+1-size))
                    if not chunk: break
                    size += len(chunk); require(size <= OUTPUT_LIMIT,'LOCAL_PRODUCER_OUTPUT_UNBOUNDED');chunks.append(chunk)
            code = child.wait(timeout=self.budget.remaining(5)); waited = True
            require(code == 0,'LOCAL_PRODUCER_DENIED'); self.budget.check()
            return b''.join(chunks)
        except (OSError,subprocess.TimeoutExpired):
            raise PreexecDenied('LOCAL_PRODUCER_EXECUTION_UNPROVEN') from None
        finally:
            if child is not None:
                if not waited:
                    try: os.killpg(child.pid,signal.SIGKILL)
                    except ProcessLookupError: pass
                    child.wait(timeout=1)
                for stream in (child.stdin, child.stdout):
                    if stream is not None:
                        try: stream.close()
                        except OSError: pass

    def emit(self, role, facts):
        request, request_raw = self.request(role,facts)
        started = self.verifier.clock()
        policy_raw = self.verifier.read_policy()
        configured = policy(policy_raw,request['installationRef'],request['entityRef'],started)
        require(any(key['issuerRef'] == request['issuerRef'] and role in key['roles'] and key['state'] == 'ACTIVE'
                and key['notBefore'] <= started < key['expiresAt'] for key in configured['keys']),
                'EXPLICIT_ACTIVE_LOCAL_PRODUCER_MANDATE_REQUIRED')
        executable, private = self.pinned()
        response_raw = self.invoke(executable,request_raw)
        reply = decode(response_raw,OUTPUT_LIMIT)
        require(set(reply) == {'schema','recordBase64','recordSignature','bindingSignature'}
                and reply['schema'] == 'ouf.semantic-local-producer-result.v1' and type(reply['recordBase64']) is str,
                'EXACT_LOCAL_PRODUCER_RESULT_REQUIRED')
        try: record_raw = base64.b64decode(reply['recordBase64'],validate=True)
        except (ValueError,UnicodeError): raise PreexecDenied('INVALID_LOCAL_PRODUCER_RECORD_ENCODING') from None
        require(0 < len(record_raw) <= 131072 and base64.b64encode(record_raw).decode('ascii') == reply['recordBase64'],
                'BOUNDED_CANONICAL_PRODUCER_RECORD_REQUIRED')
        signature = encoded(reply['recordSignature']); binding_signature = encoded(reply['bindingSignature'])
        binding_raw = encoded({'schema':'ouf.semantic-local-producer-binding.v1',
            'requestHash':hashlib.sha256(request_raw).hexdigest(),'recordHash':hashlib.sha256(record_raw).hexdigest(),
            'recordSignatureHash':hashlib.sha256(signature).hexdigest()})
        args = (role,request['issuerRef'],request['installationRef'],request['entityRef'])
        require(self.verifier.verify_detached(record_raw,signature,*args) is True
                and self.verifier.verify_detached(binding_raw,binding_signature,*args) is True,
                'AUTHENTICATED_PRODUCER_REPLY_REQUIRED')
        result = decode(record_raw,131072)
        expected_schema = 'ouf.semantic-created-candidate-attestation.v1' if role == 'CREATION_ATTESTATION' else 'ouf.semantic-deployment-admission-approval.v1'
        issuer_field = 'attestorRef' if role == 'CREATION_ATTESTATION' else 'issuerRef'
        common = ('installationRef','entityRef','containerId','transactionId','applicationHash','transportHash')
        expected_schemas={expected_schema}
        if role=='CREATION_ATTESTATION':expected_schemas.add('ouf.semantic-created-candidate-attestation.v2')
        require(result.get('schema') in expected_schemas and result.get(issuer_field) == request['issuerRef']
                and all(result.get(k) == request[k] for k in common), 'LOCAL_PRODUCER_RECORD_SCOPE_DRIFT')
        if role == 'CREATION_ATTESTATION':
            require(all(result.get(k) == facts[k] for k in ('intentHash','artifactHash','deploymentConstraintsHash','runtimeExecutableHash','generation')),
                    'LOCAL_ATTESTOR_FACTS_DRIFT')
        else:
            require(result.get('creationAcceptanceHash') == facts['creationAcceptanceHash'], 'LOCAL_APPROVAL_ACCEPTANCE_DRIFT')
        after_executable, after_private = self.pinned()
        require(after_executable == executable and after_private == private, 'LOCAL_PRODUCER_CHANGED_DURING_EXECUTION')
        require(self.verifier.read_policy() == policy_raw, 'LOCAL_PRODUCER_MANDATE_CHANGED')
        finished = self.verifier.clock()
        require(finished >= started, 'LOCAL_PRODUCER_CLOCK_REGRESSED')
        for signature_field in ('recordSignature','bindingSignature'):
            ref = reply[signature_field]['keyRef']
            require(any(key['keyRef'] == ref and key['issuerRef'] == request['issuerRef'] and role in key['roles']
                    and key['state'] == 'ACTIVE' and key['notBefore'] <= finished < key['expiresAt']
                    for key in configured['keys']), 'LOCAL_PRODUCER_MANDATE_EXPIRED')
        self.budget.check()
        # Full protocol validation, durable publication and custody are caller
        # responsibilities. An authenticated reply is never a start instruction.
        return {'record':record_raw,'recordSignature':signature,
                'binding':binding_raw,'bindingSignature':binding_signature}


class ProducerEmission:
    """One durable issuance attempt under the existing guard/lease lock.

    Installer provisions UNUSED and the empty root-private result directory.
    Unknown ISSUING outcomes require explicit recovery; no reset or replay API.
    """
    def __init__(self, producer, role, facts, journal, result_directory, hold_lock):
        request, raw = producer.request(role,facts)
        self.binding = {k:request[k] for k in ('role','installationRef','entityRef','issuerRef','containerId','transactionId')}
        self.binding.update(requestHash=hashlib.sha256(raw).hexdigest(),
                            producerHash=hashlib.sha256(encoded(producer.configured)).hexdigest())
        self.producer, self.role, self.facts = producer, role, copy.deepcopy(facts)
        self.journal, self.hold_lock = journal, hold_lock
        self.directory = Path(result_directory); ancestors(self.directory/'placeholder')
        info = self.directory.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o700,
                'PRIVATE_PRODUCER_RESULT_DIRECTORY_REQUIRED')

    def record(self):
        value = self.journal.read()
        require(type(value) is dict and set(value) == {'schema',*self.binding,'state','resultHash'}
                and value['schema'] == 'ouf.semantic-local-producer-emission.v1'
                and all(value[k] == v for k,v in self.binding.items())
                and value['state'] in ('UNUSED','ISSUING','ISSUED')
                and (hashed(value['resultHash']) if value['state']=='ISSUED' else value['resultHash'] is None),
                'EXACT_PRODUCER_EMISSION_CUSTODY_REQUIRED')
        return copy.deepcopy(value)

    def publish(self, old, state, result_hash=None):
        require(self.record() == old,'PRODUCER_EMISSION_CHANGED_UNDER_LOCK')
        value={**old,'state':state,'resultHash':result_hash};self.journal.write(old,value)
        require(self.record() == value,'PRODUCER_EMISSION_PUBLICATION_UNPROVEN')
        return value

    def emit_once(self):
        with self.hold_lock(): return self.emit_locked()

    def emit_locked(self):
        """Internal composition point: caller already owns the common lock."""
        old = self.record();require(old['state']=='UNUSED','DO_NOT_REPLAY_PRODUCER_EMISSION')
        path=self.directory/(self.binding['requestHash']+'.json')
        require(not path.exists() and not path.is_symlink(),'FOREIGN_PRODUCER_RESULT_PRESERVED')
        self.producer.budget.check()
        pending = self.publish(old,'ISSUING')
        result = self.producer.emit(self.role,self.facts)
        require(self.record() == pending,'PRODUCER_EMISSION_CHANGED_BEFORE_PUBLICATION')
        value={'schema':'ouf.semantic-local-producer-result-custody.v1',**self.binding,
               **{key:base64.b64encode(raw).decode('ascii') for key,raw in result.items()}}
        raw=encoded(value);require(len(raw)<=262144,'PRODUCER_RESULT_CUSTODY_UNBOUNDED')
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        try:
            os.fchmod(fd,0o600)
            with os.fdopen(fd,'wb',closefd=False) as stream:stream.write(raw);stream.flush();os.fsync(fd)
        finally:os.close(fd)
        directory=os.open(self.directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(directory)
        finally:os.close(directory)
        require(private_bytes(path,262144) == raw,'PRODUCER_RESULT_CUSTODY_DRIFT')
        self.producer.budget.check()
        digest=hashlib.sha256(raw).hexdigest();self.publish(pending,'ISSUED',digest)
        return {'result':result,'custody':{'path':str(path),'sha256':digest}}
