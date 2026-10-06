"""Custody admission tests; command readbacks are fixtures, not host acceptance."""
import argparse
import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch
from scripts import inventory_semantic_provider_guard_custody as g

class CustodyTest(unittest.TestCase):
    def setUp(self):
        self.args=argparse.Namespace(manifest_root=Path('/manifest'),creation_root=Path('/creation'),network_root=Path('/cold'),
            boot_stage_root=Path('/boot'),boot_install_root=Path('/installed'),creation_source_commit='a'*40,
            docker_path='/bin/docker',nft_path='/bin/nft',systemctl_path='/bin/systemctl')
        self.files={};self.commands=[]
        def save(path,value):
            raw=g.encoded(value);self.files[path]=raw;return g.digest(raw)
        self.save=save
        self.tables={f:{'nftables':[{'metainfo':{'version':'fixture'}},{'table':{'name':'guard','family':f,'handle':7}}]} for f in ('inet','bridge')}
        cold={'networkIds':{'internal':'i','egress':'e'},'binding':{'table_name':'guard','internal_network':'inside',
            'egress_network':'outside','internal_bridge':'br-in','egress_bridge':'br-out'}}
        ch=save('/cold/network-receipt.json',cold)
        self.specs=[{'name':n,'image':'sha256:fixture'} for n in ('gateway','adapter')]
        manifest={'schema':'ouf.semantic-provider-stopped-manifest.v1','containers':self.specs,'startAuthorized':False,
            'networkReceiptHash':ch,'guardHash':g.digest(g.encoded(g.canonical(self.tables)))}
        mh=save('/manifest/stopped-manifest.json',manifest)
        self.journal={'schema':'ouf.semantic-provider-stopped-create.v1','sourceCommit':'a'*40,'state':'CREATED_STOPPED',
            'manifestHash':mh,'startAuthorized':False,'candidateIds':{'gateway':'id1','adapter':'id2'},'transaction':'nonce'}
        save('/creation/creation-journal.json',self.journal)
        self.rows={s['name']:{'Id':self.journal['candidateIds'][s['name']],'Name':'/'+s['name'],'Image':s['image'],
            'State':{'Status':'created','Running':False,'StartedAt':'0001-01-01T00:00:00Z'},
            'HostConfig':{'RestartPolicy':{'Name':'no'}},'Config':{'Labels':{
                'ouf.semantic.candidate.transaction':'nonce','ouf.semantic.candidate.manifest':mh}}} for s in self.specs}
        self.nets={nid:{'Id':nid,'Name':cold['binding'][role+'_network'],'Driver':'bridge','EnableIPv6':False,
            'Internal':role=='internal','Options':{'com.docker.network.bridge.name':cold['binding'][role+'_bridge']},
            'Containers':{}} for role,nid in cold['networkIds'].items()}
        conf={'schema':'ouf.semantic-deny-boot-guard.v1','tableName':'guard','nftPath':'/bin/nft',
            'expectedFootprint':g.digest(g.encoded(g.canonical(self.tables,True)))}
        artifacts={'boot-configuration.json':g.encoded(conf),'guard.service':b'guard','docker-drop-in.conf':b'drop'}
        for name,raw in artifacts.items(): self.files['/boot/'+name]=raw
        self.files['/boot/source/scripts/restore_semantic_boot_guard.py']=b'restore'
        self.files['/boot/source/scripts/stage_semantic_boot_guard.py']=b'stage'
        stage={'schema':'ouf.semantic-boot-guard-stage.v1','coldReceiptHash':ch,
            'artifactHashes':{n:g.digest(v) for n,v in artifacts.items()},
            'sourceHashes':{'restore_semantic_boot_guard.py':g.digest(b'restore'),'stage_semantic_boot_guard.py':g.digest(b'stage')},
            'profile':{'root':'/boot','guardUnit':'guard','dockerUnit':'docker.service'}}
        sh=save('/boot/boot-stage-receipt.json',stage)
        install={'schema':'ouf.semantic-boot-guard-install.v1','state':'installed','stageReceiptHash':sh,'stageRoot':'/boot',
            'unitRoot':'/units','proof':{'dependentMainPID':'123','dependentExecStartPreFingerprint':g.digest(b'sealed')}}
        save('/installed/install-journal.json',install)
        self.files['/units/guard.service']=b'guard';self.files['/units/docker.service.d/90-guard.conf']=b'drop'
        self.status={'docker.service':{'LoadState':'loaded','ActiveState':'active','SubState':'running','MainPID':'123',
            'NeedDaemonReload':'no','ExecStartPre':'sealed'},'guard.service':{'LoadState':'loaded','ActiveState':'active',
            'SubState':'exited','MainPID':'0','NeedDaemonReload':'no'}}
        self.addCleanup(patch.stopall)
        patch.object(g.os,'geteuid',return_value=0).start()
        patch.object(g,'private',side_effect=lambda path:self.files[str(path)]).start()
        patch.object(g,'run',side_effect=self.command_readback).start()
    def command_readback(self,command):
        self.commands.append(command)
        if command[0]=='/bin/docker':
            if command[1]=='inspect':return json.dumps([self.rows[command[-1]]])
            if command[1:3]==['network','inspect']:return json.dumps([self.nets[command[-1]]])
        if command[0]=='/bin/nft' and command[1:4]==['-j','list','table']:return json.dumps(self.tables[command[4]])
        if command[0]=='/bin/systemctl' and command[1]=='show':return '\n'.join(k+'='+v for k,v in self.status[command[3]].items())
        raise AssertionError('non-read-only command')
    def test_completed_creation_does_not_require_empty_networks_or_iam(self):
        self.nets['i']['Containers']={'id1':{}}
        result=g.operate(self.args)
        self.assertTrue(result['bootTransitionRequiredBeforeRuntimeRules']);self.assertFalse(result['startAuthorized'])
        self.assertFalse(result['kernelLeaseInstalled']);self.assertTrue(self.commands)
    def test_started_or_foreign_candidate_denied(self):
        original=copy.deepcopy(self.rows['adapter'])
        for field,value in [('Status','exited'),('StartedAt','2026-01-01T00:00:00Z'),('Running',True)]:
            self.rows['adapter']=copy.deepcopy(original);self.rows['adapter']['State'][field]=value
            with self.assertRaises(ValueError):g.operate(self.args)
        self.rows['adapter']=original;self.rows['adapter']['Config']['Labels']['ouf.semantic.candidate.transaction']='foreign'
        with self.assertRaises(ValueError):g.operate(self.args)
    def test_partial_journal_denied_before_host_readback(self):
        self.journal['state']='CREATING';self.save('/creation/creation-journal.json',self.journal)
        with self.assertRaises(ValueError):g.operate(self.args)
        self.assertEqual(self.commands,[])
    def test_foreign_network_endpoint_denied(self):
        self.nets['i']['Containers']={'foreign':{}}
        with self.assertRaises(ValueError):g.operate(self.args)
    def test_loaded_drop_in_or_docker_restart_denied(self):
        for key,value in [('MainPID','456'),('ExecStartPre','other'),('NeedDaemonReload','yes')]:
            old=self.status['docker.service'][key];self.status['docker.service'][key]=value
            with self.assertRaises(ValueError):g.operate(self.args)
            self.status['docker.service'][key]=old
    def test_guard_rule_or_installed_file_drift_denied(self):
        self.tables['inet']['nftables'].append({'rule':{'expr':'accept'}})
        with self.assertRaises(ValueError):g.operate(self.args)
        self.tables['inet']['nftables'].pop();self.files['/units/guard.service']=b'foreign'
        with self.assertRaises(ValueError):g.operate(self.args)
    def test_runtime_metrics_are_not_structure_changes(self):
        self.tables['inet']['nftables'][1]['table'].update(packets=17,bytes=900)
        g.operate(self.args)

if __name__=='__main__':unittest.main()
