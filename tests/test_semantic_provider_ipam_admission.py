"""Root-private host proof admission: source/image/network/result binding, no Docker mutation."""
import argparse
import copy
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from scripts import create_semantic_provider_stopped_candidates as creator

@unittest.skipUnless(os.geteuid()==0,'real private root fixtures require root')
class StaticIpamAdmissionTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=os.environ.get('OUF_IPAM_ADMISSION_TEST_PARENT',str(Path.cwd())))
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.args=argparse.Namespace(ipam_root=self.root,ipam_source_commit='a'*40)
        self.facts=[{'id':str(i)*64,'name':'network-'+str(i),'internal':i!=3,
            'subnet':'10.'+str(i)+'.0.0/24','gateway':'10.'+str(i)+'.0.1','probeAddress':'10.'+str(i)+'.0.2'} for i in (1,2,3)]
        self.saved={'containers':[{'networks':[{'id':f['id'],'name':f['name']} for f in self.facts]},
            {'image':'sha256:'+'4'*64,'networks':[{'id':f['id'],'name':f['name']} for f in self.facts[1:]]}]}
        self.proof={'schema':'ouf.semantic-provider-static-ipam.v1','sourceCommit':'a'*40,
            'sourceHash':creator.validator.digest(Path(creator.ipam.__file__).read_bytes()),'imageId':self.saved['containers'][1]['image'],
            'staticIpReady':True,'containersStarted':0,'providerCalls':0,'notReleaseAcceptance':True,'networkFacts':self.facts,
            'results':[dict(f,staticIpSupported=True,probeCreated=True,probeRemoved=True) for f in self.facts]}
        self.addCleanup(patch.stopall)
        patch.object(creator.ipam,'network',side_effect=lambda args,name,nid:copy.deepcopy(next(f for f in self.facts if f['id']==nid))).start()
    def save(self):
        path=self.root/'ipam-receipt.json'
        if path.exists():path.unlink()
        creator.validator.write(path,creator.validator.encoded(self.proof))
    def test_positive_target_proof_admitted_without_explicit_subnet_assumption(self):
        self.save();result=creator.verify_ipam(self.args,self.saved)
        self.assertRegex(result,'^[0-9a-f]{64}$')
    def test_false_or_incomplete_results_rejected(self):
        for field,value in [('staticIpReady',False),('containersStarted',1),('providerCalls',1),('sourceHash','0'*64)]:
            original=self.proof[field];self.proof[field]=value;self.save()
            with self.assertRaisesRegex(creator.inputs.Blocked,'TARGET_STATIC_IPAM_PROOF_UNPROVEN'):creator.verify_ipam(self.args,self.saved)
            self.proof[field]=original
        self.proof['results'][0]['probeRemoved']=False;self.save()
        with self.assertRaisesRegex(creator.inputs.Blocked,'TARGET_STATIC_IPAM_NETWORK_PROOF_DRIFT'):creator.verify_ipam(self.args,self.saved)
    def test_other_network_or_changed_current_network_rejected(self):
        self.proof['networkFacts']=copy.deepcopy(self.facts);self.proof['networkFacts'][0]['id']='9'*64;self.save()
        with self.assertRaisesRegex(creator.inputs.Blocked,'TARGET_STATIC_IPAM_NETWORK_PROOF_DRIFT'):creator.verify_ipam(self.args,self.saved)
        self.proof['networkFacts']=self.facts;self.save()
        with patch.object(creator.ipam,'network',return_value=dict(self.facts[0],subnet='10.200.0.0/24')):
            with self.assertRaisesRegex(creator.inputs.Blocked,'TARGET_STATIC_IPAM_CURRENT_NETWORK_DRIFT'):creator.verify_ipam(self.args,self.saved)
    def test_next_free_address_is_not_a_reserved_or_live_endpoint_claim(self):
        self.save()
        with patch.object(creator.ipam,'network',side_effect=lambda args,name,nid:dict(next(f for f in self.facts if f['id']==nid),probeAddress='10.1.0.20')):
            creator.verify_ipam(self.args,self.saved)

if __name__=='__main__':unittest.main()
