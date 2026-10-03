#!/usr/bin/env python3
"""Seal a stopped-only Docker candidate manifest; never create or start containers."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
from scripts import inventory_semantic_provider_candidate_inputs as inputs
from scripts import prepare_semantic_southbound_validator_credentials as validator
from scripts import prepare_semantic_provider_launch_inputs as launch


def query(args, *options):
    return json.loads(inputs.run([args.docker_path, *options]))


def canonical(value):
    if isinstance(value, dict):
        return {k: canonical(v) for k, v in value.items() if k not in ('packets', 'bytes', 'expires')}
    if isinstance(value, list):
        return [canonical(v) for v in value]
    return value


def reserve(network, count):
    entries = network['IPAM']['Config']
    if len(entries) != 1:
        raise inputs.Blocked('SINGLE_IPV4_ALLOCATION_REQUIRED')
    subnet = ipaddress.ip_network(entries[0]['Subnet'])
    if subnet.version != 4 or subnet.prefixlen < 1 or subnet.prefixlen > 30:
        raise inputs.Blocked('BOUNDED_IPV4_ALLOCATION_REQUIRED')
    used = {ipaddress.ip_address(entries[0]['Gateway'])}
    for container in (network.get('Containers') or {}).values():
        if container.get('IPv4Address'):
            used.add(ipaddress.ip_interface(container['IPv4Address']).ip)
    if network['IPAM'].get('Options'):
        raise inputs.Blocked('CUSTOM_IPAM_OPTIONS_UNSUPPORTED')
    if entries[0].get('AuxiliaryAddresses') or entries[0].get('IPRange'):
        raise inputs.Blocked('CUSTOM_ALLOCATION_REQUIRES_EXPLICIT_PROFILE')
    selected = []
    for address in subnet.hosts():
        if address not in used:
            selected.append(str(address))
            if len(selected) == count:
                return selected
    raise inputs.Blocked('AVAILABLE_CANDIDATE_ADDRESSES_UNPROVEN')


def network(args, name, internal, expected_id=None, bridge=None, installation=None):
    rows = query(args, 'network', 'inspect', name)
    if len(rows) != 1:
        raise inputs.Blocked('NETWORK_NOT_UNIQUE')
    row = rows[0]
    if row['Name'] != name or row['Driver'] != 'bridge' or row['Internal'] is not internal or row['EnableIPv6'] \
            or row['IPAM']['Driver'] != 'default' or (expected_id and row['Id'] != expected_id):
        raise inputs.Blocked('CANDIDATE_NETWORK_BINDING_DRIFT')
    if bridge and ((row.get('Options') or {}).get('com.docker.network.bridge.name') != bridge \
            or (row.get('Labels') or {}).get('ouf.cold-network.owner') != installation or row.get('Containers')):
        raise inputs.Blocked('OWNED_EMPTY_NETWORK_REQUIRED')
    return row


def mount(source, target):
    if not target.startswith('/') or '..' in Path(target).parts or ',' in str(source) or ',' in target:
        raise inputs.Blocked('MOUNT_PATH_UNSAFE')
    return {'source': str(source), 'target': target, 'readOnly': True}


def inspect_inputs(args):
    checked = argparse.Namespace(**vars(args))
    checked.mode = 'verify'
    checked.source_commit = args.launch_source_commit
    checked.snapshot_root = args.launch_root
    launch_intent = launch.operate(checked)
    launch_receipt, launch_hash = inputs.private_json(args.launch_root / 'launch-input-receipt.json')
    if launch_receipt != launch_intent:
        raise inputs.Blocked('LAUNCH_RECEIPT_DRIFT')
    trust, _ = inputs.private_json(args.trust_root / 'trust-receipt.json')
    tls, _ = inputs.private_json(args.tls_root / 'tls-runtime-receipt.json')
    binding, _ = inputs.private_json(args.runtime_root / 'binding.json')
    cold, cold_hash = inputs.private_json(args.network_root / 'network-receipt.json')
    if cold['schema'] != 'ouf.semantic-provider-cold-networks.v1' or cold['notReleaseAcceptance'] is not True:
        raise inputs.Blocked('COLD_NETWORK_RECEIPT_INVALID')
    b = cold['binding']
    installation = trust['intent']['installation']
    if b['installation_id'] != installation or binding['routes']['installation'] != installation:
        raise inputs.Blocked('INSTALLATION_BINDING_DRIFT')
    internal = network(args, b['internal_network'], True, cold['networkIds']['internal'], b['internal_bridge'], installation)
    egress = network(args, b['egress_network'], False, cold['networkIds']['egress'], b['egress_bridge'], installation)
    backend = network(args, args.backend_network, True)
    if len({n['Id'] for n in (internal, egress, backend)}) != 3:
        raise inputs.Blocked('DISTINCT_NETWORK_ROLES_REQUIRED')
    ranges = [ipaddress.ip_network(n['IPAM']['Config'][0]['Subnet']) for n in (internal, egress, backend)]
    if any(a.overlaps(c) for i,a in enumerate(ranges) for c in ranges[i+1:]):
        raise inputs.Blocked('CANDIDATE_NETWORK_OVERLAP')
    gateway = query(args, 'inspect', '--type', 'container', args.gateway_container)[0]
    if backend['Name'] not in gateway['NetworkSettings']['Networks'] \
            or gateway['NetworkSettings']['Networks'][backend['Name']]['NetworkID'] != backend['Id']:
        raise inputs.Blocked('BACKEND_NOT_BOUND_TO_LIVE_GATEWAY')
    # Do not serialize gateway environment, mount sources or raw inspection.
    tables = {family: json.loads(inputs.run([args.nft_path, '-j', 'list', 'table', family, b['table_name']]))
              for family in ('inet', 'bridge')}
    if validator.digest(validator.encoded(canonical(tables))) != cold['guardHash']:
        raise inputs.Blocked('COLD_DENY_GUARD_CHANGED_RECONCILE')
    names = inputs.run([args.docker_path, 'ps', '-a', '--format', '{{.Names}}']).splitlines()
    identities = trust['intent']
    for name, hostname in ((args.adapter_container, identities['adapterHostname']),
                           (args.southbound_container, identities['southboundHostname'])):
        if name in names:
            raise inputs.Blocked('CANDIDATE_NAME_EXISTS_RECONCILE')
        if not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', name) or name != hostname:
            raise inputs.Blocked('EXPLICIT_TLS_CONTAINER_IDENTITY_REQUIRED')
    if args.adapter_container == args.southbound_container:
        raise inputs.Blocked('DISTINCT_CANDIDATE_ROLES_REQUIRED')
    internal_ips, egress_ips, backend_ips = reserve(internal, 2), reserve(egress, 2), reserve(backend, 1)
    dns = [str(ipaddress.ip_address(v)) for v in binding['dns']['resolvers'] if ipaddress.ip_address(v).version == 4]
    if binding['dns']['networkIPVersion'] != 4 or not dns:
        raise inputs.Blocked('IPV4_DNS_BINDING_REQUIRED')
    image = identities['adapterImage']
    # Caller never chooses a different gateway image: reuse the verified live image.
    gateway_image = query(args, 'image', 'inspect', identities['gateway']['image'])[0]
    if gateway_image['Id'] != identities['gateway']['image'] or gateway_image['Config']['User'] != identities['gateway']['user']:
        raise inputs.Blocked('GATEWAY_IMAGE_ROLE_DRIFT')
    common = {'restartPolicy':'no', 'publishPorts':[], 'privileged':False, 'capDrop':['ALL'],
              'memoryBytes':args.memory_bytes, 'pidsLimit':args.pids_limit, 'dnsServers':dns,
              'plannedState':'CREATED_STOPPED', 'startAuthorized':False}
    adapter_paths = binding['adapter']
    adapter = dict(common, name=args.adapter_container, image=image['id'], user=image['runtimeUser'],
        readOnlyRoot=True, command=['--configuration',args.adapter_configuration_target], envFile=None,
        mounts=[mount(args.tls_root/'adapter.json', args.adapter_configuration_target),
                mount(args.trust_root/'adapter/server.crt', adapter_paths['tlsCertificateFile']),
                mount(args.trust_root/'adapter/server.key', adapter_paths['tlsPrivateKeyFile']),
                mount(args.trust_root/'adapter/provider-receipt.key', adapter_paths['receiptKeyFile']),
                mount(args.trust_root/'trust-bundle.pem',adapter_paths['provider']['ca_file'])],
        networks=[{'id':internal['Id'],'name':internal['Name'],'ipv4':internal_ips[1]},
                  {'id':egress['Id'],'name':egress['Name'],'ipv4':egress_ips[1]}])
    southbound = dict(common, name=args.southbound_container, image=gateway_image['Id'],
        user=str(identities['gateway']['uid'])+':'+str(identities['gateway']['gid']), readOnlyRoot=False,
        command=[], envFile=str(args.launch_root/'southbound.env'),
        mounts=[mount(args.tls_root/'config.yaml',args.gateway_configuration_target),
                mount(args.tls_root/'apisix.yaml',args.gateway_resources_target),
                mount(args.trust_root/'trust-bundle.pem',binding['routes']['tlsProfile']['trustedCertificateFile'])],
        networks=[{'id':backend['Id'],'name':backend['Name'],'ipv4':backend_ips[0]},
                  {'id':internal['Id'],'name':internal['Name'],'ipv4':internal_ips[0]},
                  {'id':egress['Id'],'name':egress['Name'],'ipv4':egress_ips[0]}])
    for spec in (adapter, southbound):
        if len({m['target'] for m in spec['mounts']}) != len(spec['mounts']):
            raise inputs.Blocked('DUPLICATE_MOUNT_TARGET')
    return {'schema':'ouf.semantic-provider-stopped-manifest.v1', 'sourceCommit':args.source_commit,
        'sourceHashes':{p.name:validator.digest(p.read_bytes()) for p in (Path(__file__),Path(launch.__file__),Path(inputs.__file__),Path(validator.__file__))},
        'installation':installation,'launchReceiptHash':launch_hash,'networkReceiptHash':cold_hash,
        'guardHash':cold['guardHash'],'containers':[southbound,adapter],
        'gatewayPackagedStartupFingerprint':validator.digest(validator.encoded({k:gateway_image['Config'].get(k) for k in ('Entrypoint','Cmd','WorkingDir')})),
        'containersCreated':0,'addressesReserved':False,'startAuthorized':False,'providerCalls':0,
        'notReleaseAcceptance':True}


def operate(args):
    if os.geteuid()!=0:
        raise inputs.Blocked('ROOT_REQUIRED')
    for value in (args.source_commit,args.launch_source_commit,args.validator_source_commit):
        if not re.fullmatch('[0-9a-f]{40}',value):raise inputs.Blocked('SOURCE_BINDING_INVALID')
    if not re.fullmatch('/[A-Za-z0-9_./-]+',args.nft_path) or '..' in Path(args.nft_path).parts:
        raise inputs.Blocked('EXECUTABLE_BINDING_UNSAFE')
    if not 67108864<=args.memory_bytes<=2147483648 or not 32<=args.pids_limit<=1024:
        raise inputs.Blocked('RESOURCE_BOUNDS_INVALID')
    validator.directory(args.snapshot_root.parent)
    if args.mode!='verify' and os.path.lexists(args.snapshot_root):
        raise inputs.Blocked('MANIFEST_ROOT_EXISTS_RECONCILE')
    desired=inspect_inputs(args)
    if args.mode=='plan':return desired
    if args.mode=='verify':
        validator.directory(args.snapshot_root)
        if stat.S_IMODE(args.snapshot_root.stat().st_mode)!=0o700:raise inputs.Blocked('PRIVATE_ROOT_INVALID')
        saved,_=inputs.private_json(args.snapshot_root/'stopped-manifest.json')
        if saved!=desired:raise inputs.Blocked('STOPPED_MANIFEST_DRIFT_NO_OVERWRITE')
        return desired
    args.snapshot_root.mkdir(mode=0o700)
    validator.write(args.snapshot_root/'stopped-manifest.json',validator.encoded(desired))
    if inspect_inputs(args)!=desired:raise inputs.Blocked('MANIFEST_INPUT_CHANGED_DURING_PREPARE')
    return desired


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--mode',required=True,choices=('plan','apply','verify'))
    for name in ('tls-root','trust-root','runtime-root','credential-root','launch-root','network-root','snapshot-root'):
        p.add_argument('--'+name,type=Path,required=True)
    for name in ('source-commit','launch-source-commit','validator-source-commit','gateway-container','iam-container','realm',
                 'docker-path','openssl-path','kcadm-path','nft-path','backend-network','adapter-container','southbound-container',
                 'adapter-configuration-target','gateway-configuration-target','gateway-resources-target'):
        p.add_argument('--'+name,required=True)
    for name in ('memory-bytes','pids-limit','minimum-cert-seconds'):p.add_argument('--'+name,type=int,required=True)
    args=p.parse_args()
    try:
        if not 1<=args.minimum_cert_seconds<=86400:raise inputs.Blocked('CERTIFICATE_WINDOW_INVALID')
        operate(args)
        print('SEMANTIC_PROVIDER_STOPPED_MANIFEST=PASS MODE='+args.mode+
              ' IMAGES_REUSED=true PRIVATE_MOUNTS_RO=true OWNED_NETWORKS_EMPTY=true CURRENT_DENY_GUARD_MATCH=true'+
              ' NO_CONTAINER_CREATED=true NO_ADDRESS_RESERVED=true NO_NETWORK_OR_RULE_CHANGED=true'+
              ' NO_ROUTE_OR_IAM_WRITES=true NO_PROVIDER_CALL=true START_AUTHORIZED=false NOT_RELEASE_ACCEPTANCE=true NO_SECRETS_PRINTED=true')
        if args.mode!='plan':print('SEMANTIC_PROVIDER_STOPPED_MANIFEST_RECEIPT='+str(args.snapshot_root/'stopped-manifest.json')+' PRIVATE=true')
    except Exception as error:
        code=str(error) if isinstance(error,inputs.Blocked) else 'STOPPED_MANIFEST_PREPARATION_FAILED'
        print('SEMANTIC_PROVIDER_STOPPED_MANIFEST=BLOCKED CODE='+code+' DO_NOT_RERUN_BLINDLY=true NO_SECRETS_PRINTED=true')
        raise SystemExit(1) from None

if __name__=='__main__':main()
