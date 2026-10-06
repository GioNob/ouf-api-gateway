#!/usr/bin/env python3
"""Compile a private runtime guard profile using isolated native nft readback."""
import argparse
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
from types import SimpleNamespace


def load(path, expected):
    # The guard is the shared private-file primitive; its source is checked
    # using the original sealed intent reader before execution.
    from importlib.util import spec_from_file_location, module_from_spec
    if not path.is_absolute() or '..' in path.parts: raise ValueError('unsafe source path')
    for parent in (path.parent,*path.parent.parents):
        s=parent.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022: raise ValueError('unsafe source ancestor')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        s=os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_gid!=0 or s.st_nlink!=1 \
                or stat.S_IMODE(s.st_mode)!=0o600 or s.st_size>131072: raise ValueError('unsafe source file')
        raw=os.read(fd,131073)
    finally: os.close(fd)
    import hashlib
    if hashlib.sha256(raw).hexdigest()!=expected: raise ValueError('source hash drift')
    spec=spec_from_file_location('runtime_stage_guard',path)
    module=module_from_spec(spec); exec(compile(raw,str(path),'exec'),module.__dict__)
    if module.private(path)!=raw: raise ValueError('source metadata drift')
    return module


def verify_intent(args, guard):
    record=guard.read(args.intent_root/'transition-intent.json')
    if record.get('schema')!='ouf.semantic-provider-transition-intent.v1' \
            or record.get('state')!='PREFLIGHT_ONLY' or record.get('sourceCommit')!=args.intent_source_commit \
            or record.get('intentSourceHash')!=args.intent_source_sha256 \
            or record.get('roots',{}).get('snapshot_root')!=str(args.intent_root): raise ValueError('intent binding drift')
    source=args.intent_root.parent/'source/scripts/prepare_semantic_provider_transition_intent.py'
    if guard.digest(guard.private(source))!=args.intent_source_sha256: raise ValueError('intent source drift')
    spec=importlib.util.spec_from_file_location('sealed_existing_intent',source)
    old=importlib.util.module_from_spec(spec); spec.loader.exec_module(old)
    roots={k:Path(v) for k,v in record['roots'].items()}
    package=guard.read(roots['lease_package_root']/'source-package-receipt.json')
    creation=guard.read(roots['creation_root']/'creation-journal.json')
    prior=SimpleNamespace(mode='verify',**roots,boot_lock_file=Path(record['bootLockFile']),
        source_commit=record['sourceCommit'],intent_source_sha256=args.intent_source_sha256,
        lease_source_commit=package['sourceCommit'],creation_source_commit=creation['sourceCommit'],
        custody_source_sha256=record['custodySourceHash'],
        expected_manifest_hash=record['custody']['manifestHash'],
        expected_creation_journal_hash=record['custody']['creationJournalHash'],
        expected_boot_install_journal_hash=record['custody']['bootInstallJournalHash'],
        docker_path=args.docker_path,nft_path=args.nft_path,systemctl_path=args.systemctl_path)
    if old.operate(prior)!=record: raise ValueError('intent current readback drift')
    return record


def kernel_profile(record, roots, args, guard):
    manifest=guard.read(roots['manifest_root']/'stopped-manifest.json')
    cold=guard.read(roots['network_root']/'network-receipt.json')
    binding=guard.read(roots['runtime_root']/'binding.json')
    byname={c['name']:c for c in manifest['containers']}
    south=byname[binding['tlsIdentities']['southboundHostname']]
    adapter=byname[binding['tlsIdentities']['adapterHostname']]
    def address(spec,role):
        entries=[n for n in spec['networks'] if n['id']==cold['networkIds'][role]]
        if len(entries)!=1: raise ValueError('manifest role network binding')
        return str(ipaddress.IPv4Address(entries[0]['ipv4']))
    if binding['dns']['networkIPVersion']!=4 or binding['dns']['resolverPort']!=53:
        raise ValueError('selected IPv4 DNS profile required')
    resolvers=[str(ipaddress.ip_address(v)) for v in binding['dns']['resolvers'] if ipaddress.ip_address(v).version==4]
    flows=[{'purpose':'GATEWAY_ADAPTER','source':address(south,'internal'),
        'destination':address(adapter,'internal'),'protocol':'tcp','port':binding['adapter']['listenPort']}]
    for spec in (south,adapter):
        for resolver in resolvers:
            for protocol in ('udp','tcp'):
                flows.append({'purpose':'DNS','source':address(spec,'egress'),'destination':resolver,'protocol':protocol,'port':53})
    private=[]
    for cidr in binding['adapter']['provider']['allowed_cidrs']:
        net=ipaddress.ip_network(cidr)
        if net.prefixlen!=net.max_prefixlen or net.version!=4: raise ValueError('exact IPv4 exception required')
        private.append(str(net.network_address))
    guarded=record['guardedInterfaces']
    existing=[]
    for nid in guard.run([args.docker_path,'network','ls','-q']).split():
        nets=json.loads(guard.run([args.docker_path,'network','inspect',nid]),object_pairs_hook=guard.unique)
        if len(nets)!=1: raise ValueError('network readback')
        net=nets[0]
        if net['Id'] in cold['networkIds'].values(): continue
        if net['Driver']=='bridge':
            bridge=(net.get('Options') or {}).get('com.docker.network.bridge.name')
            if not bridge: bridge='docker0' if net['Name']=='bridge' else 'br-'+net['Id'][:12]
            existing.append(bridge)
    return {'tableName':record['tableName'],'guardedInterfaces':guarded,
        'existingInterfaces':sorted(set(existing)),'staticFlows':flows,
        'providerFlows':[{'endpointRef':args.provider_endpoint_ref,'endpoint':binding['adapter']['provider']['endpoint'],
            'source':address(adapter,'egress'),'addresses':[],'leaseSeconds':args.lease_seconds,
            'resolutionEvidenceRef':args.resolution_evidence_ref,'allowedPrivateAddresses':private}]}


def service(profile, config_path, config_hash, lock_file):
    for k in ('guardUnit','runtimeDirectory'):
        if not re.fullmatch('[A-Za-z][A-Za-z0-9_-]{0,63}',profile[k]): raise ValueError('unsafe unit name')
    if not re.fullmatch('[A-Za-z0-9_-]+\\.service',profile['dockerUnit']): raise ValueError('unsafe Docker unit')
    for k in ('pythonPath','scriptPath','root'):
        if not re.fullmatch('/[A-Za-z0-9_./-]+',profile[k]) or '..' in Path(profile[k]).parts:
            raise ValueError('unsafe unit path')
    command=profile['pythonPath']+' -B '+profile['scriptPath']+' --configuration '+str(config_path)+\
        ' --configuration-sha256 '+config_hash+' --lock-file '+str(lock_file)
    unit='\n'.join(['[Unit]','Description=Sealed Semantic empty-set runtime boot guard','DefaultDependencies=no',
        'After=local-fs.target nftables.service','Before='+profile['dockerUnit'],'RequiresMountsFor='+profile['root'],
        '[Service]','Type=oneshot','RemainAfterExit=yes','User=root','Group=root','UMask=0077',
        'ExecStart='+command,'RuntimeDirectory='+profile['runtimeDirectory'],'RuntimeDirectoryMode=0700',
        'RuntimeDirectoryPreserve=yes','NoNewPrivileges=yes','CapabilityBoundingSet=CAP_NET_ADMIN',
        'AmbientCapabilities=CAP_NET_ADMIN','ProtectSystem=strict','ProtectHome=yes','PrivateTmp=yes',
        'ProtectKernelTunables=yes','ProtectKernelModules=yes','ProtectControlGroups=yes','RestrictNamespaces=yes',
        'RestrictAddressFamilies=AF_NETLINK AF_UNIX','ReadWritePaths=/run/'+profile['runtimeDirectory'],
        '[Install]','WantedBy=multi-user.target',''])
    drop='\n'.join(['[Unit]','Requires='+profile['guardUnit']+'.service','After='+profile['guardUnit']+'.service',
        '[Service]','ExecStartPre='+command,''])
    return unit.encode(),drop.encode()


def write(guard,path,raw):
    guard.directory(path.parent)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,'wb',closefd=False) as stream: stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    finally: os.close(fd)


def operate(args):
    if os.geteuid()!=0: raise ValueError('root required')
    for k in ('source_commit','intent_source_commit'):
        if not re.fullmatch('[0-9a-f]{40}',getattr(args,k)): raise ValueError('source binding')
    for k in ('runtime_guard_sha256','intent_source_sha256'):
        if not re.fullmatch('[0-9a-f]{64}',getattr(args,k)): raise ValueError('source hash binding')
    source=args.snapshot_root.parent/'source/scripts/restore_semantic_runtime_boot_guard.py'
    guard=load(source,args.runtime_guard_sha256)
    for k in ('docker_path','nft_path','systemctl_path','unshare_path','python_path'): guard.safe_path(getattr(args,k))
    guard.directory(args.snapshot_root.parent)
    if args.mode!='verify' and os.path.lexists(args.snapshot_root): raise ValueError('existing snapshot reconcile')
    record=verify_intent(args,guard); roots={k:Path(v) for k,v in record['roots'].items()}
    kernel=kernel_profile(record,roots,args,guard)
    package=guard.read(roots['lease_package_root']/'source-package-receipt.json')
    compiler=roots['lease_package_root']/'source/tools/materialize_southbound_kernel.py'
    compiler_hash=package['sourceHashes']['tools/materialize_southbound_kernel.py']
    native={'nftPath':args.nft_path,'kernel':kernel,'compilerFile':str(compiler),'compilerHash':compiler_hash,
            'parentNetworkNamespace':os.stat('/proc/self/ns/net').st_ino}
    template=json.loads(guard.run([args.unshare_path,'--net','--fork',args.python_path,'-B',str(source),
                                  '--native-template'],guard.encoded(native).decode()),object_pairs_hook=guard.unique)
    old_stage=guard.read(roots['boot_stage_root']/'boot-stage-receipt.json')
    transaction=guard.digest(guard.encoded({'intentHash':guard.digest(guard.private(args.intent_root/'transition-intent.json')),
                                        'sourceCommit':args.source_commit,'root':str(args.snapshot_root),'kernel':kernel}))
    conf={'schema':'ouf.semantic-runtime-boot-guard.v1','nftPath':args.nft_path,'kernel':kernel,
        'compilerFile':str(compiler),'compilerHash':compiler_hash,'expectedFootprint':guard.footprint(template),
        'journalFile':str(args.snapshot_root/'transition-journal.json'),'transactionId':transaction,
        'lockFile':record['bootLockFile']}
    guard.validate(conf)
    raw=guard.encoded(conf); profile={**old_stage['profile'],'root':str(args.snapshot_root),
        'pythonPath':args.python_path,'scriptPath':str(source)}
    if conf['lockFile']!='/run/'+profile['runtimeDirectory']+'/guard.lock': raise ValueError('common lock binding')
    unit,drop=service(profile,args.snapshot_root/'runtime-configuration.json',guard.digest(raw),conf['lockFile'])
    artifacts={'runtime-configuration.json':raw,'native-template.json':guard.encoded(template),
               'guard.service':unit,'docker-drop-in.conf':drop}
    names=('stage_semantic_runtime_transition.py','restore_semantic_runtime_boot_guard.py','transition_semantic_runtime_guard.py')
    hashes={n:guard.digest(guard.private(args.snapshot_root.parent/'source/scripts'/n)) for n in names}
    receipt={'schema':'ouf.semantic-runtime-transition-stage.v1','sourceCommit':args.source_commit,
        'intentRoot':str(args.intent_root),'intentHash':guard.digest(guard.private(args.intent_root/'transition-intent.json')),
        'intentSourceCommit':args.intent_source_commit,'intentSourceHash':args.intent_source_sha256,
        'profile':profile,'sourceHashes':hashes,'artifactHashes':{k:guard.digest(v) for k,v in artifacts.items()},
        'configurationHash':guard.digest(raw),'nativeTemplateIsolated':True,'hostRulesChanged':False,
        'unitInstalled':False,'providerCalls':0,'startAuthorized':False,'liveAddressAllocationProven':False,
        'infrastructureAuthorityComplete':False,'leaseLifecycleActivationReady':False,'notReleaseAcceptance':True,
        'executables':{k:getattr(args,k) for k in ('docker_path','nft_path','systemctl_path','unshare_path','python_path')}}
    # Revalidate the original intent after the native compilation, before publication.
    if verify_intent(args,guard)!=record: raise ValueError('post-template intent drift')
    receipt_path=args.snapshot_root/'runtime-stage-receipt.json'
    if args.mode=='verify':
        for k,v in artifacts.items():
            if guard.private(args.snapshot_root/k)!=v: raise ValueError('artifact drift')
        if guard.read(receipt_path)!=receipt: raise ValueError('stage drift')
    elif args.mode=='apply':
        args.snapshot_root.mkdir(mode=0o700)
        for k,v in artifacts.items(): write(guard,args.snapshot_root/k,v)
        write(guard,receipt_path,guard.encoded(receipt))
    return receipt


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--mode',choices=('plan','apply','verify'),required=True)
    for k in ('intent-root','snapshot-root'): p.add_argument('--'+k,type=Path,required=True)
    for k in ('source-commit','intent-source-commit','intent-source-sha256','runtime-guard-sha256',
              'docker-path','nft-path','systemctl-path','unshare-path','python-path','provider-endpoint-ref','resolution-evidence-ref'):
        p.add_argument('--'+k,required=True)
    p.add_argument('--lease-seconds',type=int,required=True)
    args=p.parse_args(argv)
    try:
        operate(args)
        print('SEMANTIC_RUNTIME_TRANSITION_STAGE=PASS MODE='+args.mode+
              ' ISOLATED_NATIVE_TEMPLATE=true HOST_RULES_UNCHANGED=true UNITS_UNCHANGED=true'
              ' CONTAINERS_UNCHANGED=true EMPTY_PROVIDER_SETS=true START_AUTHORIZED=false PROVIDER_CALLS=0'
              ' NOT_RELEASE_ACCEPTANCE=true NO_SECRETS_PRINTED=true')
        if args.mode!='plan': print('SEMANTIC_RUNTIME_TRANSITION_STAGE_ROOT='+str(args.snapshot_root)+' PRIVATE=true')
        return 0
    except Exception:
        print('SEMANTIC_RUNTIME_TRANSITION_STAGE=BLOCKED PARTIAL_EVIDENCE_RETAINED=true NO_SECRETS_PRINTED=true'); return 1


if __name__=='__main__': raise SystemExit(main())
