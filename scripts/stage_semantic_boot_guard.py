#!/usr/bin/env python3
"""Privately compile boot guard/unit/drop-in; never publish or reload systemd."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys

from scripts.restore_semantic_boot_guard import private, footprint, observed, execute


def digest(raw): return hashlib.sha256(raw).hexdigest()
def encoded(value): return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def legacy(value):
    if isinstance(value, dict): return {k: legacy(v) for k,v in value.items() if k not in ('packets','bytes','expires')}
    if isinstance(value, list): return [legacy(v) for v in value]
    return value


def write(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb', closefd=False) as stream: stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    finally: os.close(fd)


def service(profile, configuration, configuration_hash):
    for k in ('guardUnit', 'runtimeDirectory'):
        if not re.fullmatch('[A-Za-z][A-Za-z0-9_-]{0,63}', profile[k]): raise ValueError('safe unit name required')
    if not re.fullmatch(r'[A-Za-z0-9_-]+\.service', profile['dockerUnit']): raise ValueError('explicit Docker service required')
    for key in ('pythonPath','scriptPath','root'):
        if not re.fullmatch('/[A-Za-z0-9_./-]+', profile[key]) or '..' in Path(profile[key]).parts:
            raise ValueError('safe unit path required')
    command = profile['pythonPath']+' -B '+profile['scriptPath']+' --configuration '+str(configuration)+\
              ' --configuration-sha256 '+configuration_hash+' --lock-file /run/'+profile['runtimeDirectory']+'/guard.lock'
    unit = '\n'.join(['[Unit]', 'Description=Sealed Semantic deny-only boot guard', 'DefaultDependencies=no',
        'After=local-fs.target nftables.service', 'Before='+profile['dockerUnit'], 'RequiresMountsFor='+profile['root'],
        '[Service]', 'Type=oneshot', 'RemainAfterExit=yes', 'User=root', 'Group=root', 'UMask=0077',
        'ExecStart='+command, 'RuntimeDirectory='+profile['runtimeDirectory'], 'RuntimeDirectoryMode=0700',
        'NoNewPrivileges=yes', 'CapabilityBoundingSet=CAP_NET_ADMIN', 'AmbientCapabilities=CAP_NET_ADMIN',
        'ProtectSystem=strict', 'ProtectHome=yes', 'PrivateTmp=yes', 'ProtectKernelTunables=yes',
        'ProtectKernelModules=yes', 'ProtectControlGroups=yes', 'RestrictNamespaces=yes',
        'RestrictAddressFamilies=AF_NETLINK AF_UNIX', 'ReadWritePaths=/run/'+profile['runtimeDirectory'],
        '[Install]', 'WantedBy=multi-user.target', ''])
    drop_in = '\n'.join(['[Unit]', 'Requires='+profile['guardUnit']+'.service',
        'After='+profile['guardUnit']+'.service', '[Service]', 'ExecStartPre='+command, ''])
    return unit, drop_in


def operate(args):
    if os.geteuid() != 0: raise ValueError('root required')
    if not re.fullmatch('[0-9a-f]{40}', args.source_commit): raise ValueError('source binding required')
    cold_raw = private(args.cold_root/'network-receipt.json'); cold = json.loads(cold_raw)
    if cold['schema'] != 'ouf.semantic-provider-cold-networks.v1' or cold['notReleaseAcceptance'] is not True:
        raise ValueError('cold receipt invalid')
    package_raw = private(args.lease_package_root/'source-package-receipt.json'); package = json.loads(package_raw)
    if package['schema'] != 'ouf.semantic-lease-source-package.v1' or package['sourceCommit'] != args.lease_source_commit:
        raise ValueError('lease package invalid')
    expected = {'scripts/stage_semantic_lease_package.py','scripts/run_semantic_provider_lease_owner.py',
        'scripts/prepare_semantic_provider_trust.py','tools/materialize_semantic_lease_service.py',
        'tools/materialize_southbound_kernel.py','tools/materialize_southbound_lease_refresh.py',
        'tools/semantic_provider_dns.py','tools/semantic_provider_lease_owner.py','tools/semantic_provider_lease_nft.py'}
    if set(package['sourceHashes']) != expected: raise ValueError('source cohort invalid')
    for name, expected_hash in package['sourceHashes'].items():
        if digest(private(args.lease_package_root/'source'/name)) != expected_hash: raise ValueError('lease source drift')
    # Import only the root-owned sealed factory; the staged lease cohort is reused.
    sys.path.insert(0, str(args.lease_package_root/'source'))
    from tools.materialize_southbound_kernel import materialize
    binding = cold['binding']; table = binding['table_name']
    for role, name, internal in (('internal',binding['internal_network'],True),('egress',binding['egress_network'],False)):
        raw = json.loads(execute([args.docker_path,'network','inspect',name]))
        if len(raw) != 1 or raw[0]['Id'] != cold['networkIds'][role] or raw[0]['Internal'] is not internal \
                or raw[0]['EnableIPv6'] or raw[0].get('Containers'):
            raise ValueError('cold empty network changed')
    current = observed(args.nft_path, table)
    if digest(encoded(legacy(current))) != cold['guardHash']: raise ValueError('cold guard ownership drift')
    cfg = {'tableName': table, 'guardedInterfaces': [binding['internal_bridge'],binding['egress_bridge']],
           'existingInterfaces': [], 'staticFlows': [], 'providerFlows': []}
    rules = 'create table inet '+table+'\ncreate table bridge '+table+'\n'+materialize(cfg)['nftRules']
    if private(args.cold_root/'deny-only.nft').decode() != rules: raise ValueError('cold rules drift')
    config = {'schema':'ouf.semantic-deny-boot-guard.v1','tableName':table,'nftPath':args.nft_path,
              'rules':rules,'expectedFootprint':footprint(current)}
    raw = encoded(config)
    profile = {'guardUnit':args.guard_unit,'dockerUnit':args.docker_unit,'runtimeDirectory':args.runtime_directory,
               'pythonPath':args.python_path,'scriptPath':str(args.snapshot_root/'source/scripts/restore_semantic_boot_guard.py'),
               'root':str(args.snapshot_root)}
    unit, drop_in = service(profile, args.snapshot_root/'boot-configuration.json', digest(raw))
    artifacts = {'boot-configuration.json':raw,'guard.service':unit.encode(),'docker-drop-in.conf':drop_in.encode()}
    # Source and snapshot owner/mode proof precedes any metadata write.
    source_hashes = {n:digest(private(args.snapshot_root/'source/scripts'/n)) for n in
                     ('restore_semantic_boot_guard.py','stage_semantic_boot_guard.py')}
    receipt = {'schema':'ouf.semantic-boot-guard-stage.v1','sourceCommit':args.source_commit,
        'leasePackageReceiptHash':digest(package_raw),'coldReceiptHash':digest(cold_raw),'profile':profile,
        'sourceHashes':source_hashes,'artifactHashes':{n:digest(v) for n,v in artifacts.items()},
        'unitInstalled':False,'dockerDropInInstalled':False,'daemonReloadCalled':False,
        'rulesChanged':False,'providerCalls':0,'notReleaseAcceptance':True}
    receipt_path = args.snapshot_root/'boot-stage-receipt.json'
    if args.mode == 'verify':
        if json.loads(private(receipt_path)) != receipt: raise ValueError('stage intent drift')
        for n,value in artifacts.items():
            if private(args.snapshot_root/n) != value: raise ValueError('artifact drift')
    else:
        if receipt_path.exists() or any((args.snapshot_root/n).exists() for n in artifacts): raise ValueError('stage exists reconcile')
        if args.mode == 'apply':
            for n,value in artifacts.items(): write(args.snapshot_root/n,value)
            write(receipt_path,encoded(receipt))
    return receipt


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--mode',required=True,choices=('plan','apply','verify'))
    for opt in ('cold-root','lease-package-root','snapshot-root'): p.add_argument('--'+opt,type=Path,required=True)
    for opt in ('source-commit','lease-source-commit','docker-path','nft-path','python-path','guard-unit','docker-unit','runtime-directory'):
        p.add_argument('--'+opt,required=True)
    args = p.parse_args(argv)
    try:
        operate(args)
        print('SEMANTIC_BOOT_STAGE=PASS MODE='+args.mode+' PRIVATE=true NO_UNIT_INSTALLED=true NO_DOCKER_DROP_IN_INSTALLED=true'+
              ' NO_DAEMON_RELOAD=true NO_RULE_CHANGED=true NO_PROVIDER_CALL=true NOT_RELEASE_ACCEPTANCE=true NO_SECRETS_PRINTED=true')
        if args.mode != 'plan': print('SEMANTIC_BOOT_STAGE_RECEIPT='+str(args.snapshot_root/'boot-stage-receipt.json')+' PRIVATE=true')
        return 0
    except Exception:
        print('SEMANTIC_BOOT_STAGE=BLOCKED DO_NOT_RERUN_BLINDLY=true NO_SECRETS_PRINTED=true')
        return 1


if __name__ == '__main__': raise SystemExit(main())
