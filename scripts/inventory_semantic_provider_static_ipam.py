#!/usr/bin/env python3
"""Probe Docker static-IP support using never-started disposable containers; no service changes."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import uuid
from scripts import inventory_semantic_provider_candidate_inputs as inputs
from scripts import prepare_semantic_southbound_validator_credentials as validator


def execute(args,*options):
    result=subprocess.run([args.docker_path,*map(str,options)],capture_output=True,text=True,timeout=60)
    if len(result.stdout)>2_000_000:raise inputs.Blocked('DOCKER_READBACK_TOO_LARGE')
    return result


def query(args,*options):
    result=execute(args,*options)
    if result.returncode:raise inputs.Blocked('IPAM_METADATA_QUERY_FAILED')
    return json.loads(result.stdout)


def network(args,name,expected):
    row=query(args,'network','inspect',name)[0]
    if row['Id']!=expected or row['Name']!=name or row['Driver']!='bridge' or row['EnableIPv6'] \
            or row['IPAM']['Driver']!='default' or len(row['IPAM']['Config'])!=1:
        raise inputs.Blocked('IPAM_NETWORK_PROFILE_DRIFT')
    cfg=row['IPAM']['Config'][0];subnet=ipaddress.ip_network(cfg['Subnet'])
    if subnet.version!=4 or cfg.get('IPRange') or cfg.get('AuxiliaryAddresses'):
        raise inputs.Blocked('IPAM_CUSTOM_ALLOCATION_UNSUPPORTED')
    used={ipaddress.ip_address(cfg['Gateway'])}
    used.update(ipaddress.ip_interface(c['IPv4Address']).ip for c in (row.get('Containers') or {}).values() if c.get('IPv4Address'))
    address=next((str(ip) for ip in subnet.hosts() if ip not in used),None)
    if not address:raise inputs.Blocked('IPAM_FREE_TEST_ADDRESS_UNPROVEN')
    return {'name':name,'id':expected,'internal':row['Internal'],'subnet':str(subnet),'gateway':cfg['Gateway'],'probeAddress':address}


def cleanup(args,cid,token,name):
    row=query(args,'inspect','--type','container',cid)[0]
    if row['Id']!=cid or row['Name']!='/'+name or row['Config']['Labels'].get('ouf.ipam.probe')!=token \
            or row['State']['Status']!='created' or row['State']['Running'] \
            or not row['State']['StartedAt'].startswith('0001-01-01T'):
        raise inputs.Blocked('IPAM_PROBE_NEVER_STARTED_OWNERSHIP_UNPROVEN')
    if execute(args,'rm',cid).returncode:raise inputs.Blocked('IPAM_PROBE_PRIVATE_CLEANUP_FAILED')


def probe(args,fact):
    token=uuid.uuid4().hex;name='ouf-ipam-probe-'+token
    validator.write(args.snapshot_root/('probe-'+token+'.json'),validator.encoded({'name':name,'token':token,'imageId':args.image_id}))
    result=execute(args,'create','--name',name,'--label','ouf.ipam.probe='+token,
        '--network',fact['id'],'--ip',fact['probeAddress'],'--restart','no','--cap-drop','ALL',
        '--memory','67108864','--pids-limit','32','--no-healthcheck',
        '--entrypoint',args.probe_entrypoint,args.image_id)
    if result.returncode:
        found=execute(args,'ps','-a','--no-trunc','--filter','label=ouf.ipam.probe='+token,'--format','{{.ID}}')
        if found.returncode:raise inputs.Blocked('IPAM_PROBE_FAILURE_RECONCILIATION_REQUIRED')
        retained=found.stdout.splitlines()
        for cid in retained:cleanup(args,cid,token,name)
        error=(result.stderr+result.stdout).lower()
        if 'user specified ip address' in error or 'user-specified ip address' in error:
            return dict(fact,staticIpSupported=False,reason='DOCKER_REQUIRES_EXPLICIT_SUBNET',probeCreated=bool(retained),probeRemoved=True)
        raise inputs.Blocked('IPAM_PROBE_CREATE_FAILED_NO_OUTPUT_PRINTED')
    cid=result.stdout.strip()
    if not re.fullmatch('[0-9a-f]{64}',cid):raise inputs.Blocked('IPAM_PROBE_ID_INVALID')
    validator.write(args.snapshot_root/('created-'+token+'.json'),validator.encoded({'id':cid,'name':name,'token':token}))
    cleanup(args,cid,token,name)
    return dict(fact,staticIpSupported=True,reason='STATIC_CREATE_ACCEPTED_NOT_PACKET_PROOF',probeCreated=True,probeRemoved=True)


def operate(args):
    if os.geteuid()!=0:raise inputs.Blocked('ROOT_REQUIRED')
    if not re.fullmatch('[0-9a-f]{40}',args.source_commit) or not re.fullmatch('sha256:[0-9a-f]{64}',args.image_id):
        raise inputs.Blocked('IMMUTABLE_SOURCE_IMAGE_REQUIRED')
    for path in (args.docker_path,args.probe_entrypoint):
        if not re.fullmatch('/[A-Za-z0-9_./-]+',path) or '..' in Path(path).parts:raise inputs.Blocked('EXECUTABLE_BINDING_UNSAFE')
    image=query(args,'image','inspect',args.image_id)[0]
    if image['Id']!=args.image_id or image['Config'].get('Volumes'):
        raise inputs.Blocked('PROBE_IMAGE_VOLUME_OR_ID_UNPROVEN')
    facts=[]
    for binding in args.network:
        name,nid=binding.split('=',1)
        if not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',name) or not re.fullmatch('[0-9a-f]{64}',nid):
            raise inputs.Blocked('NETWORK_BINDING_INVALID')
        facts.append(network(args,name,nid))
    if len({f['id'] for f in facts})!=len(facts):raise inputs.Blocked('DUPLICATE_NETWORK_BINDING')
    validator.directory(args.snapshot_root.parent)
    if args.mode=='verify':
        validator.directory(args.snapshot_root)
        saved,_=inputs.private_json(args.snapshot_root/'ipam-receipt.json')
        if saved['sourceCommit']!=args.source_commit or saved['sourceHash']!=validator.digest(Path(__file__).read_bytes()) \
                or saved['imageId']!=args.image_id or saved['networkFacts']!=facts:
            raise inputs.Blocked('IPAM_RECEIPT_BINDING_DRIFT')
        return saved
    if os.path.lexists(args.snapshot_root):raise inputs.Blocked('IPAM_ROOT_EXISTS_RECONCILE')
    if args.mode=='plan':return {'networkFacts':facts,'results':[],'staticIpReady':False}
    args.snapshot_root.mkdir(mode=0o700)
    validator.write(args.snapshot_root/'ipam-intent.json',validator.encoded({'sourceCommit':args.source_commit,'imageId':args.image_id,'networkFacts':facts}))
    results=[probe(args,fact) for fact in facts]
    # Network identity/configuration and the next free address must be unchanged
    # after removing our disposable containers. No daemon image/source is executed.
    current=[network(args,f['name'],f['id']) for f in facts]
    if current!=facts:raise inputs.Blocked('IPAM_NETWORK_CHANGED_DURING_PROBE')
    receipt={'schema':'ouf.semantic-provider-static-ipam.v1','sourceCommit':args.source_commit,
        'sourceHash':validator.digest(Path(__file__).read_bytes()),'imageId':args.image_id,
        'networkFacts':facts,'results':results,'staticIpReady':all(r['staticIpSupported'] for r in results),
        'providerCalls':0,'containersStarted':0,'notReleaseAcceptance':True}
    validator.write(args.snapshot_root/'ipam-receipt.json',validator.encoded(receipt))
    return receipt


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--mode',required=True,choices=('plan','apply','verify'))
    for name in ('source-commit','docker-path','image-id','probe-entrypoint'):p.add_argument('--'+name,required=True)
    p.add_argument('--network',required=True,action='append');p.add_argument('--snapshot-root',required=True,type=Path)
    args=p.parse_args()
    try:
        saved=operate(args)
        for row in saved['results']:
            print('SEMANTIC_PROVIDER_IPAM_NETWORK='+json.dumps({k:row[k] for k in ('name','id','staticIpSupported','reason','probeCreated','probeRemoved')},sort_keys=True))
        print('SEMANTIC_PROVIDER_STATIC_IPAM=PASS MODE='+args.mode+' STATIC_IP_READY='+str(saved['staticIpReady']).lower()+
            ' NEVER_STARTED=true OWNED_PROBES_REMOVED=true NO_SHARED_CONTAINER_OR_NETWORK_CONFIG_CHANGED=true'+
            ' NO_PROVIDER_CALL=true NOT_RELEASE_ACCEPTANCE=true NO_SECRETS_PRINTED=true')
        if args.mode!='plan':print('SEMANTIC_PROVIDER_STATIC_IPAM_RECEIPT='+str(args.snapshot_root/'ipam-receipt.json')+' PRIVATE=true')
    except Exception as error:
        code=str(error) if isinstance(error,inputs.Blocked) else 'IPAM_INVENTORY_FAILED'
        print('SEMANTIC_PROVIDER_STATIC_IPAM=BLOCKED CODE='+code+' DO_NOT_RERUN_BLINDLY=true NO_SECRETS_PRINTED=true')
        raise SystemExit(1) from None

if __name__=='__main__':main()
