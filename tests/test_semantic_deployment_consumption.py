import copy
from contextlib import contextmanager
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import tempfile
import unittest

from tests import test_semantic_deployment_protocol as protocol
from tests import test_semantic_preexec as preexec
from tools.semantic_provider_deployment_consumption import Consumption
from tools.semantic_provider_preexec import PreexecDenied, digest
from tools.semantic_provider_lease_coordination import PrivateJournal, hold_common_lock


class Journal:
    def __init__(self, value): self.value = copy.deepcopy(value)
    def read(self): return copy.deepcopy(self.value)
    def write(self, old, value):
        if old != self.value: raise PreexecDenied('CHANGED')
        self.value = copy.deepcopy(value)


class ConsumptionTest(unittest.TestCase):
    def setUp(self):
        self.auth = protocol.DeploymentProtocolTest(); self.auth.setUp()
        self.raw = self.auth.records()
        self.binding = {'installationRef':'installation-a','entityRef':'entity-a','containerId':'a'*64,
                        'transactionId':'b'*64,'intentHash':hashlib.sha256(self.raw[0]).hexdigest(),
                        'configurationHash':'c'*64}
        self.journal = Journal({'schema':'ouf.semantic-deployment-consumption.v1',**self.binding,
            'state':'STAGED','bundleHash':None,'generation':None,'evidenceHash':None,'approvalHash':None,'driverHash':None})
        self.held = False; self.started = []
        self.gate = Consumption(self.binding,self.journal,self.lock)

    @contextmanager
    def lock(self):
        self.assertFalse(self.held); self.held = True
        try: yield
        finally: self.held = False

    def ready(self):
        self.gate.authorize_create(self.raw[0],self.auth.ctx,self.auth.authenticate,lambda:150)
        self.gate.created('1'*64,self.auth.attestation['generation'])
        evidence = self.gate.ready(*self.raw,self.auth.ctx,self.auth.authenticate,lambda:150)
        self.gate.seal_driver('d'*64)
        return digest(evidence)

    def reauthorize(self): self.assertTrue(self.held)

    def start(self):
        self.assertTrue(self.held)
        self.assertEqual(self.gate.record()['state'],'STARTING')
        self.started.append(1)

    def consume(self, evidence_hash, reauthorize=None, starter=None):
        with self.lock():
            self.gate.consume_locked(evidence_hash,'d'*64,self.auth.attestation['generation'],
                                     reauthorize or self.reauthorize,starter or self.start)

    def test_one_start_attempt_is_durable_before_process_and_replay_is_denied(self):
        evidence_hash = self.ready(); self.consume(evidence_hash)
        self.assertEqual(self.gate.record()['state'],'STARTED'); self.assertEqual(self.started,[1])
        with self.assertRaisesRegex(PreexecDenied,'DO_NOT_REPLAY'): self.consume(evidence_hash)
        self.assertEqual(self.started,[1])

    def test_native_failure_preserves_starting_without_automatic_replay(self):
        evidence_hash = self.ready()
        def failed():
            self.start(); raise RuntimeError('native outcome unknown')
        with self.assertRaises(RuntimeError): self.consume(evidence_hash,starter=failed)
        self.assertEqual(self.gate.record()['state'],'STARTING')
        with self.assertRaises(PreexecDenied): self.consume(evidence_hash)
        self.assertEqual(self.started,[1])

    def test_late_revocation_after_durable_claim_prevents_start_and_replay(self):
        evidence_hash = self.ready(); calls = []
        def revoked():
            self.reauthorize(); calls.append(1)
            if len(calls) == 2: raise PreexecDenied('REVOKED')
        with self.assertRaises(PreexecDenied): self.consume(evidence_hash,reauthorize=revoked)
        self.assertEqual(self.started,[]); self.assertEqual(self.gate.record()['state'],'STARTING')

    def test_early_revocation_does_not_claim_or_invoke_start(self):
        evidence_hash = self.ready()
        def revoked(): raise PreexecDenied('REVOKED')
        with self.assertRaises(PreexecDenied): self.consume(evidence_hash,reauthorize=revoked)
        self.assertEqual(self.gate.record()['state'],'READY'); self.assertEqual(self.started,[])

    def test_other_generation_bundle_or_installation_cannot_be_accepted(self):
        self.gate.authorize_create(self.raw[0],self.auth.ctx,self.auth.authenticate,lambda:150)
        self.gate.created('9'*64,self.auth.attestation['generation'])
        with self.assertRaises(PreexecDenied): self.gate.ready(*self.raw,self.auth.ctx,self.auth.authenticate,lambda:150)
        self.assertEqual(self.gate.record()['state'],'CREATED')
        self.journal.value['installationRef'] = 'other'
        with self.assertRaises(PreexecDenied): self.gate.record()

    def test_wrong_start_generation_or_driver_never_releases_process(self):
        evidence_hash = self.ready()
        for driver,gen,evidence in [('9'*64,self.auth.attestation['generation'],evidence_hash),
                ('d'*64,{**self.auth.attestation['generation'],'startTicks':999},evidence_hash),
                ('d'*64,self.auth.attestation['generation'],'9'*64)]:
            with self.lock(),self.assertRaises(PreexecDenied):
                self.gate.consume_locked(evidence,driver,gen,self.reauthorize,self.start)
        self.assertEqual(self.started,[]); self.assertEqual(self.gate.record()['state'],'READY')

    def test_create_finalization_and_driver_seal_are_not_replayed(self):
        self.ready()
        for operation in (lambda:self.gate.authorize_create(self.raw[0],self.auth.ctx,self.auth.authenticate,lambda:150),
                          lambda:self.gate.ready(*self.raw,self.auth.ctx,self.auth.authenticate,lambda:150),
                          lambda:self.gate.seal_driver('e'*64),
                          lambda:self.gate.created('1'*64,self.auth.attestation['generation'])):
            with self.assertRaises(PreexecDenied): operation()

    def test_journal_phase_corruption_is_denied(self):
        self.journal.value['bundleHash'] = '1'*64
        with self.assertRaises(PreexecDenied): self.gate.record()
        self.journal.value['bundleHash'] = None; self.journal.value['state'] = 'READY'
        with self.assertRaises(PreexecDenied): self.gate.record()

    def test_publication_failure_never_calls_starter(self):
        evidence_hash = self.ready()
        def broken(old,value): raise OSError('fsync failed')
        self.journal.write = broken
        with self.assertRaises(OSError): self.consume(evidence_hash)
        self.assertEqual(self.started,[])

    def test_preexec_consumption_callback_runs_after_live_checks_under_common_lock(self):
        helper = preexec.PreexecTest(); helper.setUp(); helper.enable_fixture_start(); helper.gate.operate('apply')
        helper.state['status'] = 'created'; calls = []
        def consume(gen,starter):
            self.assertTrue(helper.held); calls.append(gen); starter()
        helper.gate.before_process(helper.state,lambda:self.started.append(1),consume=consume)
        self.assertEqual(len(calls),1); self.assertEqual(self.started,[1])

    @unittest.skipUnless(os.geteuid()==0,'root-private real journal and flock')
    def test_two_processes_cannot_consume_one_ready_journal_twice(self):
        evidence_hash = self.ready()
        with tempfile.TemporaryDirectory(dir=os.environ.get('OUF_SHARED_COORDINATION_TEST_PARENT',str(Path.cwd()))) as tmp:
            root = Path(tmp).resolve(); root.chmod(0o700); path=root/'journal.json'; lock=root/'guard.lock'; marker=root/'started'
            path.write_text(json.dumps(self.journal.read())); path.chmod(0o600); lock.touch(mode=0o600)
            ctx = multiprocessing.get_context('fork'); begin=ctx.Event(); output=ctx.Queue()
            def worker():
                gate=Consumption(self.binding,PrivateJournal(path),lambda:hold_common_lock(lock))
                begin.wait(5)
                try:
                    with gate.hold_lock():
                        gate.consume_locked(evidence_hash,'d'*64,self.auth.attestation['generation'],lambda:None,
                            lambda:marker.open('xb').close())
                    output.put('STARTED')
                except (PreexecDenied,BlockingIOError): output.put('DENIED')
            children=[ctx.Process(target=worker) for _ in range(2)]
            for child in children: child.start()
            begin.set()
            for child in children:
                child.join(10)
                if child.is_alive(): child.terminate(); child.join(); self.fail('consumption worker timeout')
                self.assertEqual(child.exitcode,0)
            self.assertCountEqual([output.get(timeout=2),output.get(timeout=2)],['STARTED','DENIED'])
            self.assertTrue(marker.exists()); self.assertEqual(PrivateJournal(path).read()['state'],'STARTED')


if __name__=='__main__': unittest.main()
