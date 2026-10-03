#!/usr/bin/env python3
"""Create only sealed, never-started Docker candidates with a private recovery journal."""
import argparse
import fcntl
import hmac
import json
import os
from pathlib import Path
import re
import subprocess
import uuid
from scripts import inventory_semantic_provider_candidate_inputs as inputs
from scripts import prepare_semantic_southbound_validator_credentials as validator
from scripts import prepare_semantic_provider_launch_inputs as launch
from scripts import stage_semantic_provider_candidates as stage

OWNER='ouf.semantic.candidate.transaction'
MANIFEST='ouf.semantic.candidate.manifest'


def command(args,*options):
    # All callers use fixed Docker verbs and argument arrays; no shell or start.
    value=subprocess.run([args.docker_path,*map(str,options)],capture_output=True,text=True,timeout=60)
    if value.returncode:
        error=(value.stdout+value.stderr).lower()
        if 'user specified ip address' in error or 'user-specified ip address' in error:
            raise inputs.Blocked('DOCKER_EXPLICIT_IPAM_SUBNET_REQUIRED')
        raise inputs.Blocked('DOCKER_CANDIDATE_OPERATION_FAILED')
    if len(value.stdout)>2_000_000:raise inputs.Blocked('DOCKER_READBACK_TOO_LARGE')
    return value.stdout


def inspect(args,name):
    return json.loads(command(args,'inspect','--type','container',name))[0]


def save(path,value):
    tmp=path.with_name(path.name+'.next-'+uuid.uuid4().hex)
    validator.write(tmp,validator.encoded(value))
    os.replace(tmp,path)
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)


def receipt(args):
    saved,raw_hash=inputs.private_json(args.manifest_root/'stopped-manifest.json')
    if saved.get('schema')!='ouf.semantic-provider-stopped-manifest.v1' or saved.get('startAuthorized') is not False \
            or saved.get('containersCreated')!=0 or len(saved.get('containers',[]))!=2:
        raise inputs.Blocked('STOPPED_MANIFEST_REQUIRED')
    modules=(Path(stage.__file__),Path(launch.__file__),Path(inputs.__file__),Path(validator.__file__))
    if saved['sourceHashes']!={p.name:validator.digest(p.read_bytes()) for p in modules}:
        raise inputs.Blocked('SEALED_MANIFEST_SOURCE_COHORT_DRIFT')
    return saved,raw_hash


def verify_inputs(args,saved,initial,journal=None):
    southbound,adapter=saved['containers']
    checked=argparse.Namespace(**vars(args))
    checked.source_commit=args.launch_source_commit;checked.mode='verify';checked.snapshot_root=args.launch_root
    launch.operate(checked)
    _,launch_hash=inputs.private_json(args.launch_root/'launch-input-receipt.json')
    _,network_hash=inputs.private_json(args.network_root/'network-receipt.json')
    if launch_hash!=saved['launchReceiptHash'] or network_hash!=saved['networkReceiptHash']:
        raise inputs.Blocked('SEALED_MANIFEST_RECEIPT_DRIFT')
    if initial:
        checked.source_commit=saved['sourceCommit'];checked.snapshot_root=args.manifest_root
        checked.backend_network=southbound['networks'][0]['name']
        checked.adapter_container=adapter['name'];checked.southbound_container=southbound['name']
        checked.memory_bytes=southbound['memoryBytes'];checked.pids_limit=southbound['pidsLimit']
        checked.adapter_configuration_target=adapter['mounts'][0]['target']
        checked.gateway_configuration_target=southbound['mounts'][0]['target']
        checked.gateway_resources_target=southbound['mounts'][1]['target']
        stage.operate(checked)
    cold,_=inputs.private_json(args.network_root/'network-receipt.json')
    if initial and cold['binding'].get('explicit_subnets') is not True:
        raise inputs.Blocked('COLD_IPAM_PROFILE_NOT_EXPLICIT_NO_CONTAINER_CREATED')
    tables={family:json.loads(inputs.run([args.nft_path,'-j','list','table',family,cold['binding']['table_name']])) for family in ('inet','bridge')}
    if validator.digest(validator.encoded(stage.canonical(tables)))!=saved['guardHash']:
        raise inputs.Blocked('COLD_DENY_GUARD_CHANGED_RECONCILE')
    gateway=inspect(args,args.gateway_container)
    primary=southbound['networks'][0]
    if (gateway['NetworkSettings']['Networks'].get(primary['name']) or {}).get('NetworkID')!=primary['id']:
        raise inputs.Blocked('LIVE_GATEWAY_BACKEND_BINDING_CHANGED')
    allowed_ids=set((journal or {}).get('candidateIds',{}).values())
    for spec in saved['containers']:
        for net in spec['networks']:
            row=json.loads(command(args,'network','inspect',net['id']))[0]
            if row['Id']!=net['id'] or row['Name']!=net['name'] or row['Driver']!='bridge' or row['EnableIPv6']:
                raise inputs.Blocked('CANDIDATE_NETWORK_CHANGED')
            if net['id'] in cold['networkIds'].values():
                if set(row.get('Containers') or {})-allowed_ids:
                    raise inputs.Blocked('FOREIGN_COLD_NETWORK_ENDPOINT')
                role=next(k for k,v in cold['networkIds'].items() if v==net['id'])
                if row['Internal']!=(role=='internal') or (row.get('Options') or {}).get('com.docker.network.bridge.name')!=cold['binding'][role+'_bridge'] \
                        or (row.get('Labels') or {}).get('ouf.cold-network.owner')!=saved['installation']:
                    raise inputs.Blocked('CANDIDATE_NETWORK_CHANGED')
    startup=json.loads(command(args,'image','inspect',southbound['image']))[0]['Config']
    if validator.digest(validator.encoded({k:startup.get(k) for k in ('Entrypoint','Cmd','WorkingDir')}))!=saved['gatewayPackagedStartupFingerprint']:
        raise inputs.Blocked('PACKAGED_STARTUP_DRIFT')


def environment(args,spec):
    image=json.loads(command(args,'image','inspect',spec['image']))[0]
    if image['Id']!=spec['image'] or image['Config'].get('Volumes'):
        raise inputs.Blocked('UNPLANNED_IMAGE_VOLUME_OR_ID')
    result={}
    for item in image['Config'].get('Env') or []:
        key,value=item.split('=',1);result[key]=value
    if spec['envFile']:
        raw=launch.private_read(Path(spec['envFile']),0,0,4096)
        for line in raw.decode('ascii').splitlines():
            key,value=line.split('=',1)
            if key in ('PATH','HOME','LD_PRELOAD','PYTHONPATH'):raise inputs.Blocked('SECRET_ENVIRONMENT_BINDING_INVALID')
            result[key]=value
    return image,result


def create_command(spec,journal):
    primary=spec['networks'][0]
    result=['create','--name',spec['name'],'--user',spec['user'],'--restart','no','--cap-drop','ALL',
        '--memory',str(spec['memoryBytes']),'--memory-swap',str(spec['memoryBytes']),
        '--pids-limit',str(spec['pidsLimit']),'--no-healthcheck',
        '--label',OWNER+'='+journal['transaction'],'--label',MANIFEST+'='+journal['manifestHash'],
        '--network',primary['id'],'--ip',primary['ipv4'],'--network-alias',spec['name']]
    if spec['readOnlyRoot']:result.append('--read-only')
    for dns in spec['dnsServers']:result+=['--dns',dns]
    for m in spec['mounts']:
        result+=['--mount','type=bind,source='+m['source']+',target='+m['target']+',readonly']
    if spec['envFile']:result+=['--env-file',spec['envFile']]
    return result+[spec['image'],*spec['command']]


def owned(raw,spec,journal):
    labels=raw['Config'].get('Labels') or {}
    state=raw['State']
    if labels.get(OWNER)!=journal['transaction'] or labels.get(MANIFEST)!=journal['manifestHash'] \
            or raw['Name']!='/'+spec['name'] or raw['Image']!=spec['image'] \
            or state['Running'] or state.get('Restarting') or state['Status']!='created' \
            or not state['StartedAt'].startswith('0001-01-01T'):
        raise inputs.Blocked('OWNERSHIP_OR_NEVER_STARTED_STATE_UNPROVEN')
    if not re.fullmatch('[0-9a-f]{64}',raw['Id']):raise inputs.Blocked('CANDIDATE_ID_INVALID')
    recorded=journal['candidateIds'].get(spec['name'])
    if recorded and recorded!=raw['Id']:raise inputs.Blocked('CANDIDATE_ID_CHANGED')


def verify_container(args,spec,journal,partial=False):
    raw=inspect(args,spec['name']);owned(raw,spec,journal)
    image,expected_env=environment(args,spec)
    cfg,host=raw['Config'],raw['HostConfig']
    actual_env={}
    for value in cfg.get('Env') or []:
        key,item=value.split('=',1)
        if key in actual_env:raise inputs.Blocked('DUPLICATE_CONTAINER_ENVIRONMENT')
        actual_env[key]=item
    expected_cmd=spec['command'] or image['Config'].get('Cmd')
    if cfg['User']!=spec['user'] or cfg.get('Entrypoint')!=image['Config'].get('Entrypoint') or cfg.get('Cmd')!=expected_cmd \
            or cfg.get('WorkingDir')!=image['Config'].get('WorkingDir') \
            or not hmac.compare_digest(validator.encoded(actual_env),validator.encoded(expected_env)):
        raise inputs.Blocked('CANDIDATE_PACKAGED_CONFIG_DRIFT')
    if host['Privileged'] or host['ReadonlyRootfs']!=spec['readOnlyRoot'] or host['RestartPolicy']['Name']!='no' \
            or host['Memory']!=spec['memoryBytes'] or host['MemorySwap']!=spec['memoryBytes'] \
            or host['PidsLimit']!=spec['pidsLimit'] or set(host.get('CapDrop') or [])!={'ALL'} \
            or host.get('CapAdd') or host.get('PortBindings') or raw['NetworkSettings'].get('Ports') \
            and any(raw['NetworkSettings']['Ports'].values()) or host.get('Devices') or host.get('DeviceRequests') \
            or host.get('Dns')!=spec['dnsServers'] or cfg.get('Healthcheck',{}).get('Test')!=['NONE']:
        raise inputs.Blocked('CANDIDATE_HOST_CONFIG_DRIFT')
    expected_mounts={(m['source'],m['target']) for m in spec['mounts']}
    actual_mounts={(m['Source'],m['Destination']) for m in raw['Mounts']}
    if actual_mounts!=expected_mounts or any(m['Type']!='bind' or m['RW'] for m in raw['Mounts']):
        raise inputs.Blocked('CANDIDATE_PRIVATE_MOUNT_DRIFT')
    expected_networks={n['name']:n for n in spec['networks']}
    actual=raw['NetworkSettings']['Networks']
    if host['NetworkMode'] not in (spec['networks'][0]['id'],spec['networks'][0]['name']):
        raise inputs.Blocked('CANDIDATE_PRIMARY_NETWORK_CONFIG_DRIFT')
    if (set(actual)!=set(expected_networks) if not partial else not set(actual)<=set(expected_networks)):
        raise inputs.Blocked('CANDIDATE_NETWORK_ATTACHMENT_DRIFT')
    for name,row in actual.items():
        intended=expected_networks[name]
        # Created containers can defer NetworkID and endpoint activation until
        # start. Prove the configured network name/current ID separately; do not
        # claim a live namespace, allocated endpoint, packet flow or lease.
        configured=json.loads(command(args,'network','inspect',name))[0]
        if configured['Id']!=intended['id'] or row['NetworkID'] not in ('',None,intended['id']) \
                or (row.get('IPAMConfig') or {}).get('IPv4Address')!=intended['ipv4'] \
                or row.get('GlobalIPv6Address') or spec['name'] not in (row.get('Aliases') or []):
            raise inputs.Blocked('CANDIDATE_STATIC_NETWORK_CONFIG_DRIFT')
    return raw['Id']


def lock(root):
    path=root/'operation.lock'
    fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    inputs.file_metadata(path,0,0,0o600)
    try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd);raise inputs.Blocked('CANDIDATE_OPERATION_BUSY') from None
    return fd


def operate(args):
    if os.geteuid()!=0:raise inputs.Blocked('ROOT_REQUIRED')
    if not re.fullmatch('[0-9a-f]{40}',args.source_commit):raise inputs.Blocked('SOURCE_BINDING_INVALID')
    validator.directory(args.creation_root.parent)
    saved,manifest_hash=receipt(args)
    if args.mode in ('plan','apply'):
        if os.path.lexists(args.creation_root):raise inputs.Blocked('CREATION_ROOT_EXISTS_RECONCILE')
        verify_inputs(args,saved,True)
        for spec in saved['containers']:environment(args,spec)
        if args.mode=='plan':return {'state':'PLANNED','candidateIds':{}}
        args.creation_root.mkdir(mode=0o700)
        journal={'schema':'ouf.semantic-provider-stopped-create.v1','sourceCommit':args.source_commit,
            'sourceHash':validator.digest(Path(__file__).read_bytes()),'manifestHash':manifest_hash,
            'transaction':uuid.uuid4().hex,'state':'PREPARED','candidateIds':{},'startAuthorized':False,
            'liveNetworkNamespaceProven':False,'liveAddressAllocationProven':False,'kernelLeaseInstalled':False}
        validator.write(args.creation_root/'creation-journal.json',validator.encoded(journal))
    validator.directory(args.creation_root)
    if args.creation_root.stat().st_mode & 0o777 != 0o700:raise inputs.Blocked('PRIVATE_ROOT_INVALID')
    fd=lock(args.creation_root)
    try:
        journal,_=inputs.private_json(args.creation_root/'creation-journal.json')
        if journal['sourceCommit']!=args.source_commit or journal['sourceHash']!=validator.digest(Path(__file__).read_bytes()) \
                or journal['manifestHash']!=manifest_hash or journal['startAuthorized'] is not False:
            raise inputs.Blocked('CREATION_JOURNAL_BINDING_DRIFT')
        if args.mode=='cleanup':
            if journal['state']=='CLEANED':return journal
            # Discover only the transaction-labelled IDs, including a create whose
            # process was interrupted before it could record Docker's returned ID.
            ids=command(args,'ps','-a','--no-trunc','--filter','label='+OWNER+'='+journal['transaction'],'--format','{{.ID}}').splitlines()
            existing=set(command(args,'ps','-a','--no-trunc','--format','{{.ID}}').splitlines())
            ids=sorted(set(ids) | (set(journal['candidateIds'].values()) & existing))
            specs={spec['name']:spec for spec in saved['containers']}
            for cid in ids:
                raw=inspect(args,cid);name=raw['Name'].removeprefix('/')
                if name not in specs:raise inputs.Blocked('UNEXPECTED_TRANSACTION_CONTAINER')
                owned(raw,specs[name],journal)
            for cid in ids:command(args,'rm',cid) # Never force/remove running or foreign containers.
            journal['state']='CLEANED';save(args.creation_root/'creation-journal.json',journal)
            return journal
        if args.mode=='apply':
            journal['state']='CREATING';save(args.creation_root/'creation-journal.json',journal)
            for spec in saved['containers']:
                cid=command(args,*create_command(spec,journal)).strip()
                if not re.fullmatch('[0-9a-f]{64}',cid):raise inputs.Blocked('DOCKER_CREATE_ID_INVALID')
                journal['candidateIds'][spec['name']]=cid;save(args.creation_root/'creation-journal.json',journal)
                verify_container(args,spec,journal,partial=True)
                for net in spec['networks'][1:]:
                    command(args,'network','connect','--ip',net['ipv4'],'--alias',spec['name'],net['id'],cid)
                verify_container(args,spec,journal)
            journal['state']='CREATED_STOPPED'
        if journal['state']!='CREATED_STOPPED':raise inputs.Blocked('PARTIAL_CREATION_REQUIRES_RECONCILIATION')
        verify_inputs(args,saved,False,journal)
        for spec in saved['containers']:verify_container(args,spec,journal)
        save(args.creation_root/'creation-journal.json',journal)
        return journal
    finally:os.close(fd)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--mode',required=True,choices=('plan','apply','verify','cleanup'))
    for name in ('manifest-root','creation-root','launch-root','credential-root','tls-root','trust-root','runtime-root','network-root'):
        p.add_argument('--'+name,type=Path,required=True)
    for name in ('source-commit','launch-source-commit','validator-source-commit','docker-path','nft-path','openssl-path',
                 'gateway-container','iam-container','realm','kcadm-path'):
        p.add_argument('--'+name,required=True)
    p.add_argument('--minimum-cert-seconds',type=int,required=True)
    args=p.parse_args()
    try:
        if not 1<=args.minimum_cert_seconds<=86400:raise inputs.Blocked('CERTIFICATE_WINDOW_INVALID')
        result=operate(args)
        print('SEMANTIC_PROVIDER_STOPPED_CREATE=PASS MODE='+args.mode+' STATE='+result['state']+
              ' CONTAINERS='+str(0 if result['state']=='CLEANED' else len(result['candidateIds']))+' NEVER_STARTED=true START_AUTHORIZED=false NETWORK_CONFIGURATION_ONLY=true'+
              ' NO_SHARED_CONTAINER_CHANGED=true NO_RULE_OR_ROUTE_OR_IAM_WRITES=true NO_PROVIDER_CALL=true NOT_RELEASE_ACCEPTANCE=true NO_SECRETS_PRINTED=true')
        if args.mode!='plan':print('SEMANTIC_PROVIDER_STOPPED_CREATE_JOURNAL='+str(args.creation_root/'creation-journal.json')+' PRIVATE=true')
    except Exception as error:
        code=str(error) if isinstance(error,inputs.Blocked) else 'STOPPED_CANDIDATE_CREATION_FAILED'
        print('SEMANTIC_PROVIDER_STOPPED_CREATE=BLOCKED CODE='+code+' DO_NOT_RERUN_BLINDLY=true NO_SECRETS_PRINTED=true')
        raise SystemExit(1) from None

if __name__=='__main__':main()
