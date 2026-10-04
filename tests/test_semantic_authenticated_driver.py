"""Deadline sharing, exact bindings and isolated source closures."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
from tests import test_semantic_deployment_authentication as crypto
from tests import test_semantic_deployment_reauthorization as late_fixture
from tools import semantic_provider_deployment_authentication as auth
from tools.semantic_provider_deployment_reauthorization import sealed_authorizer
from tools.semantic_provider_preexec import PreexecDenied
from scripts import semantic_provider_admission_preparer as preparer

@unittest.skipUnless(os.geteuid()==0,'root-private source and crypto fixtures')
class AuthenticatedDriverTest(unittest.TestCase):
    def setUp(self):
        self.fixture=crypto.AuthenticationTest();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)

    def test_subprocesses_share_remaining_time(self):
        now=[0.0];budget=auth.VerificationBudget(2,monotonic=lambda:now[0]);self.fixture.verifier.budget=budget
        original=auth.subprocess.run;timeouts=[]
        def run(*args,**kwargs):
            timeouts.append(kwargs['timeout']);result=original(*args,**kwargs)
            if len(timeouts)==1:now[0]=1.0
            return result
        with patch.object(auth.subprocess,'run',side_effect=run):self.fixture.verify()
        self.assertEqual(timeouts,[2,1])

    def test_deadline_after_version_prevents_crypto_subprocess(self):
        now=[0.0];self.fixture.verifier.budget=auth.VerificationBudget(2,monotonic=lambda:now[0])
        original=auth.subprocess.run;calls=[]
        def run(*args,**kwargs):
            calls.append(1);result=original(*args,**kwargs);now[0]=2;return result
        with patch.object(auth.subprocess,'run',side_effect=run),self.assertRaisesRegex(PreexecDenied,'AUTHENTICATION_DEADLINE_MISSED'):
            self.fixture.verify()
        self.assertEqual(calls,[1])

    def test_budget_cannot_be_reset_between_durable_claim_and_release(self):
        f=late_fixture.LateEvidenceTest();f.setUp();self.addCleanup(f.doCleanups)
        now=[0.0];f.late.verifier.budget=auth.VerificationBudget(2,monotonic=lambda:now[0])
        original=f.gate.journal.write
        def advance(old,new):
            original(old,new)
            if new['state']=='STARTING':now[0]=2
        f.gate.journal.write=advance
        with self.assertRaisesRegex(PreexecDenied,'AUTHENTICATION_DEADLINE_MISSED'):f.consume()
        self.assertEqual(f.gate.record()['state'],'STARTING');self.assertEqual(f.started,[])

    def test_invalid_or_extended_budget_denied(self):
        for seconds in (0,19,True,2.5):
            with self.subTest(seconds=seconds),self.assertRaises(PreexecDenied):auth.VerificationBudget(seconds)
        for deadline in (0,3,float('nan'),float('inf')):
            with self.subTest(deadline=deadline),self.assertRaises(PreexecDenied):
                auth.VerificationBudget(2,deadline=deadline,monotonic=lambda:0)

    def test_missing_authenticated_binding_never_falls_back(self):
        with self.assertRaisesRegex(PreexecDenied,'EXACT_AUTHENTICATED_DRIVER_BINDING_REQUIRED'):
            sealed_authorizer({}, {}, {}, 'a'*64,auth.VerificationBudget(2))

    def configuration(self,kind):
        root=self.fixture.root/'source';root.mkdir(mode=0o700)
        repository=Path(__file__).resolve().parents[1]
        modules=(*preparer.MODULES,'semantic_provider_deployment_protocol','semantic_provider_deployment_consumption',
            'semantic_provider_deployment_authentication','semantic_provider_deployment_reauthorization')
        paths=[preparer.DRIVER,*('tools/'+m+'.py' for m in modules)]
        if kind=='preparer':paths.insert(0,preparer.SELF)
        hashes={}
        for relative in paths:
            target=root/relative;target.parent.mkdir(mode=0o700,exist_ok=True);target.write_bytes((repository/relative).read_bytes());target.chmod(0o600)
            hashes[relative]=hashlib.sha256(target.read_bytes()).hexdigest()
        config={'schema':'ouf.semantic-preexec-driver.v5','sourceRoot':str(root),'sourceHashes':hashes,
            'profile':{},'kernel':{},'dns':{},'coordinationBinding':{},'coordinationJournal':'unused',
            'preexecJournal':'unused','lockFile':'unused','commands':{},'budgetSeconds':5,'runtimeBinding':{},
            'authorityBinding':{},'authorityScope':{},'consumptionBinding':{},'authenticationBinding':{}}
        if kind=='preparer':
            for field in ('profile','preexecJournal','runtimeBinding','authorityBinding','authorityScope'):config.pop(field)
            python=str(Path('/usr/bin/python3').resolve());command='/usr/bin/true'
            config.update(schema='ouf.semantic-admission-preparer.v3',pythonPath=python,
                pythonHash=hashlib.sha256(Path(python).read_bytes()).hexdigest(),candidate={},
                commands={k:command for k in ('nft','ip','nsenter','unshare','mount','umount')},
                commandHashes={k:hashlib.sha256(Path(command).read_bytes()).hexdigest() for k in ('nft','ip','nsenter','unshare','mount','umount')},
                hostNetworkNamespace=1)  # load validates shape; native CI validates the inode
        path=self.fixture.root/'config.json';path.write_text(json.dumps(config));path.chmod(0o600)
        script=root/(preparer.SELF if kind=='preparer' else preparer.DRIVER)
        return path,script,config

    def load(self,path,script):
        code="import runpy;from pathlib import Path;ns=runpy.run_path(%r);ns['load'](Path(%r))"%(str(script),str(path))
        return subprocess.run([sys.executable,'-I','-B','-c',code],capture_output=True,text=True,timeout=10)

    def test_driver_v5_exact_closure_loads_and_missing_auth_is_denied(self):
        path,script,cfg=self.configuration('driver');self.assertEqual(len(cfg['sourceHashes']),15)
        result=self.load(path,script);self.assertEqual(result.returncode,0,result.stderr)
        cfg.pop('authenticationBinding');path.write_text(json.dumps(cfg))
        result=self.load(path,script);self.assertNotEqual(result.returncode,0);self.assertIn('EXACT_DRIVER_CONFIGURATION_REQUIRED',result.stderr)

    def test_preparer_v3_exact_closure_loads(self):
        path,script,cfg=self.configuration('preparer');self.assertEqual(len(cfg['sourceHashes']),16)
        result=self.load(path,script);self.assertEqual(result.returncode,0,result.stderr)

    def test_substituted_verifier_source_is_denied_before_execution(self):
        path,script,cfg=self.configuration('driver')
        target=Path(cfg['sourceRoot'])/'tools/semantic_provider_deployment_authentication.py'
        target.write_text("raise RuntimeError('BODY_MUST_NOT_EXECUTE')\n")
        result=self.load(path,script);self.assertNotEqual(result.returncode,0)
        self.assertIn('SOURCE_PACKAGE_DRIFT',result.stderr);self.assertNotIn('BODY_MUST_NOT_EXECUTE',result.stderr)

if __name__=='__main__':unittest.main()
