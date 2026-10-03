"""CI-only admission with explicit synthetic authority; never a VPS preparer."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

parser = argparse.ArgumentParser()
for name in ('configuration','container-id','bundle','runtime-root','mode'): parser.add_argument('--'+name, required=True)
args = parser.parse_args()
cfg = json.loads(Path(args.configuration).read_bytes())
sys.path.insert(0, cfg['repository'])  # explicit trusted CI checkout, not production discovery
from tests.test_semantic_preexec import profile as initial_profile
from tests.test_semantic_shared_coordination_native import NativeTest
from scripts.semantic_provider_preexec_hook import SELF, MODULES
from tools.materialize_southbound_kernel import materialize
from tools.semantic_provider_lease_nft import structure_hash
from tools.semantic_provider_preexec import digest, rules
from tools.semantic_provider_preexec_native import NativeBackend

root = Path(args.bundle).parent; cid = args.container_id; approved = cfg['approved'][cid]
def private(path, value): path.write_text(json.dumps(value)); path.chmod(0o600)
def run(*argv): return subprocess.run(argv, capture_output=True, text=True, timeout=20, check=True).stdout
driver_path = root/'driver.json'
def driver(mode):
    return run(cfg['python'], '-I', '-B', str(Path(cfg['source'])/SELF), '--configuration', str(driver_path), '--mode', mode)
if args.mode == 'rollback': driver('rollback'); raise SystemExit(0)
assert args.mode == 'prepare' and approved['authority'] is True
oci = json.loads((Path(args.bundle)/'config.json').read_bytes())
assert oci['process']['args'] == approved['command']
assert any(m.get('destination') == '/proof' and m.get('source') == approved['proof'] for m in oci['mounts'])
namespace = next(v['path'] for v in oci['linux']['namespaces'] if v['type'] == 'network')
commands = cfg['commands']
children = json.loads(run(commands['nsenter'], '--net='+namespace, commands['ip'], '-j', 'addr', 'show'))
child = next(v for v in children if v['ifname'] != 'lo')
assert [v['local'] for v in child['addr_info'] if v['family'] == 'inet'] == [approved['ipv4']]
hosts = json.loads(run(commands['ip'], '-j', 'link', 'show'))
host = next(v for v in hosts if v['ifindex'] == child['link_index'])
assert host['link_index'] == child['ifindex'] and host['master'] == approved['bridge']
profile = initial_profile(); profile['containerId'] = cid; profile['transactionId'] = hashlib.sha256(cid.encode()).hexdigest()
profile['bundlePath'] = args.bundle; profile['bundleHash'] = digest(oci)
profile['namespacePath'] = namespace; profile['namespaceInode'] = os.stat(namespace).st_ino
profile['namespaceLinks'] = [{'interface': child['ifname'], 'ifindex': child['ifindex'], 'hostIfindex': host['ifindex']}]
profile['policy']['tableName'] = approved['sharedTable']
profile['policy']['attachments'][0].update(interface=host['ifname'], ifindex=host['ifindex'],
    bridge=approved['bridge'], mac=child['address'], ipv4=approved['ipv4'])
profile['policy']['flows'][0].update(source='10.77.0.1', destination=approved['ipv4'], peerIngress={'kind':'HOST','ifindex':0})
profile['applicationStartAuthorized'] = approved['startAuthorized']
cfg_kernel = NativeTest.kernel(None); cfg_kernel['tableName'] = approved['leaseTable']
cfg_kernel['guardedInterfaces'] = [host['ifname']]; cfg_kernel['providerFlows'][0]['source'] = approved['ipv4']
subprocess.run([commands['nft'], '-f', '-'], input=materialize(cfg_kernel, empty_provider_sets=True)['nftRules'],
               text=True, capture_output=True, timeout=10, check=True)
lease_hash = structure_hash({f: json.loads(run(commands['nft'], '-j', 'list', 'table', f, approved['leaseTable'])) for f in ('inet','bridge')})
# Synthetic fixture footprint calibration, never an authority/template compiler.
backend = NativeBackend(profile, commands, 5); backend.create(rules(profile))
profile['expectedFootprint'] = backend.footprint(backend.tables()); backend.remove()
binding = {'transactionId': profile['transactionId'], 'configurationHash': digest(cfg_kernel), 'leaseStructureHash': lease_hash}
lock = root/'guard.lock'; lock.touch(mode=0o600)
private(root/'coordination.json', {'schema':'ouf.semantic-lease-coordination.v1', **binding,
    'state':'QUIESCED', 'leaseAuthorized':False, 'startAuthorized':False, 'leaseAddresses':[[]]})
private(root/'preexec.json', {'schema':'ouf.semantic-preexec-journal.v1', 'transactionId':profile['transactionId'],
    'configurationHash':digest(profile), 'state':'STAGED', 'sharedStructureHash':None, 'containerGeneration':None})
hashes = {name: hashlib.sha256((Path(cfg['source'])/name).read_bytes()).hexdigest()
    for name in [SELF, *('tools/'+v+'.py' for v in MODULES)]}
private(driver_path, {'schema':'ouf.semantic-preexec-driver.v2', 'sourceRoot':cfg['source'], 'sourceHashes':hashes,
    'profile':profile, 'kernel':cfg_kernel, 'dns':{'resolvers':['127.0.0.1'],'resolverPort':53,'timeoutSeconds':2,
    'maxLeaseSeconds':30,'applyBudgetSeconds':1}, 'coordinationBinding':binding,
    'coordinationJournal':str(root/'coordination.json'), 'preexecJournal':str(root/'preexec.json'),
    'lockFile':str(lock),'commands':commands,'budgetSeconds':5,
    'runtimeBinding':{'path':cfg['runc'],'sha256':cfg['runcHash'],'root':args.runtime_root}})
driver('plan'); driver('apply'); driver('verify')
if approved['leaseDrift']:
    value = json.loads((root/'coordination.json').read_bytes()); value['state'] = 'QUIESCING'
    private(root/'coordination.json', value)
