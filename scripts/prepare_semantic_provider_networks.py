#!/usr/bin/env python3
"""Create empty dedicated bridges behind a preinstalled deny-only nft guard.

No existing container is attached; no provider/DNS/IAM operation is performed.
Partial failures retain the private intent and guard for explicit reconciliation.
Docker creates its own network rules; custom tables never rewrite shared rules.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess

from scripts import inventory_semantic_provider_network as inventory
from scripts import prepare_semantic_provider_trust as trust
from tools.materialize_southbound_kernel import materialize, name


def execute(command, raw=None):
    result = subprocess.run(command, input=raw, text=True, capture_output=True, timeout=30)
    if result.returncode or len(result.stdout) > 4_000_000:
        raise trust.Blocked('LOCAL_NETWORK_COMMAND_FAILED')
    return result.stdout


def json_command(command):
    return json.loads(execute(command))


def stable(value):
    if isinstance(value, dict):
        return {k: stable(v) for k, v in value.items() if k not in ('packets', 'bytes', 'expires')}
    if isinstance(value, list): return [stable(v) for v in value]
    return value


def encoded(value): return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
def fingerprint(value): return trust.digest(encoded(stable(value)))


def tables(args):
    return {(x['table']['family'], x['table']['name']) for x in
            json_command([args.nft_path, '-j', 'list', 'tables'])['nftables'] if 'table' in x}


def owned(args):
    value = {family: json_command([args.nft_path, '-j', 'list', 'table', family, args.table_name])
            for family in ('inet', 'bridge')}
    expected = {'inet': {'governed_flows', 'guard_input', 'guard_output', 'guard_forward'},
                'bridge': {'governed_bridge_flows', 'guard_bridge_forward'}}
    for family, raw in value.items():
        chains = {v['chain']['name'] for v in raw['nftables'] if 'chain' in v}
        if chains != expected[family]: raise trust.Blocked('GUARD_CHAINS_UNPROVEN')
        for chain in ('governed_flows',) if family == 'inet' else ('governed_bridge_flows',):
            rules = [v['rule'] for v in raw['nftables'] if 'rule' in v and v['rule']['chain'] == chain]
            if not rules or not any('drop' in e for e in rules[-1]['expr']):
                raise trust.Blocked('GUARD_FINAL_DENIAL_UNPROVEN')
    return value


def full_networks(args):
    ids = execute([args.docker_path, 'network', 'ls', '-q', '--no-trunc']).split()
    return sorted((inventory.single([args.docker_path, 'network', 'inspect', nid]) for nid in ids),
                  key=lambda n: n['Id'])


def ranges(networks, routes):
    values = [ipaddress.ip_network(c['Subnet']) for n in networks
              for c in (n['IPAM'].get('Config') or []) if c.get('Subnet')]
    for r in routes:
        if r.get('dst') not in (None, 'default'):
            values.append(ipaddress.ip_network(r['dst']))
    return values


def reject_overlap(selected, baseline):
    for n in selected:
        if n.prefixlen == 0 or any(n.version == old.version and n.overlaps(old) for old in baseline):
            raise trust.Blocked('ALLOCATED_NETWORK_OVERLAP')
    if len(selected) != 2 or selected[0].overlaps(selected[1]):
        raise trust.Blocked('DISTINCT_IPV4_ALLOCATIONS_REQUIRED')


def validate(args):
    if os.geteuid() != 0: raise trust.Blocked('ROOT_REQUIRED')
    if not re.fullmatch('[0-9a-f]{40}', args.source_commit): raise trust.Blocked('IMMUTABLE_SOURCE_REQUIRED')
    if not re.fullmatch('[0-9a-f]{64}', args.expected_snapshot_hash): raise trust.Blocked('TOPOLOGY_HASH_REQUIRED')
    name(args.table_name, 32)
    for bridge in (args.internal_bridge, args.egress_bridge): name(bridge, 15)
    for value in (args.installation_id, args.internal_network, args.egress_network):
        if not re.fullmatch('[A-Za-z][A-Za-z0-9_.-]{0,127}', value):
            raise trust.Blocked('EXPLICIT_SAFE_INSTALLATION_BINDING_REQUIRED')
    if args.internal_bridge == args.egress_bridge or args.internal_network == args.egress_network:
        raise trust.Blocked('DISTINCT_NETWORK_BINDINGS_REQUIRED')
    if not args.snapshot_root.is_absolute() or '..' in args.snapshot_root.parts:
        raise trust.Blocked('ABSOLUTE_SAFE_PATH_REQUIRED')
    trust.ancestors(args.snapshot_root.parent)
    topology = inventory.collect(args)
    if topology['snapshotHash'] != args.expected_snapshot_hash or not topology['bridgeBindingsReady']:
        raise trust.Blocked('EXISTING_ROLE_TOPOLOGY_DRIFT')
    source = Path(__file__).resolve().parents[1]
    binding = {k: getattr(args, k) for k in ('installation_id', 'source_commit', 'expected_snapshot_hash',
              'gateway_container', 'expected_gateway_id', 'semantic_container', 'ingestion_container',
              'internal_network', 'egress_network', 'internal_bridge', 'egress_bridge', 'table_name', 'ipam')}
    binding['sourceHashes'] = {p: trust.digest((source/p).read_bytes()) for p in (
        'scripts/prepare_semantic_provider_networks.py', 'scripts/inventory_semantic_provider_network.py',
        'scripts/prepare_semantic_provider_trust.py', 'tools/materialize_southbound_kernel.py')}
    return binding


def readback(args, ids):
    links = inventory.read_json([args.ip_path, '-json', '-details', 'link', 'show'])
    result = []
    for role, network_name, bridge, internal in (
        ('internal', args.internal_network, args.internal_bridge, True),
        ('egress', args.egress_network, args.egress_bridge, False)):
        raw = inventory.single([args.docker_path, 'network', 'inspect', network_name])
        if raw['Id'] != ids[role] or raw['Name'] != network_name or raw['Driver'] != 'bridge' \
                or raw['Internal'] is not internal or raw['EnableIPv6'] or raw.get('Containers') \
                or raw['IPAM']['Driver'] != 'default' \
                or (raw.get('Labels') or {}).get('ouf.cold-network.owner') != args.installation_id \
                or (raw.get('Options') or {}).get('com.docker.network.bridge.name') != bridge:
            raise trust.Blocked('OWNED_EMPTY_NETWORK_DRIFT')
        fact = inventory.network(args, raw['Id'], links)
        if not fact['bridgeInterfaceObserved'] or len(fact['ipam']) != 1 \
                or ipaddress.ip_network(fact['ipam'][0]['subnet']).version != 4:
            raise trust.Blocked('OWNED_BRIDGE_IPAM_UNPROVEN')
        result.append(fact)
    return result


def operate(args):
    binding = validate(args)
    if args.mode == 'verify':
        trust.ancestors(args.snapshot_root)
        receipt = json.loads(trust.read_file(args.snapshot_root/'network-receipt.json', 0, 0))
        if receipt['binding'] != binding or receipt['guardHash'] != fingerprint(owned(args)):
            raise trust.Blocked('GUARD_OR_INTENT_DRIFT')
        facts = readback(args, receipt['networkIds'])
        if facts != receipt['networks']: raise trust.Blocked('OWNED_NETWORK_ID_CONFIG_DRIFT')
        reject_overlap([ipaddress.ip_network(n['ipam'][0]['subnet']) for n in facts],
                       [ipaddress.ip_network(n) for n in receipt['excludedRanges']])
        return receipt
    if args.snapshot_root.exists() or args.snapshot_root.is_symlink():
        raise trust.Blocked('SNAPSHOT_EXISTS_RECONCILE')
    nets = full_networks(args)
    links = inventory.read_json([args.ip_path, '-json', '-details', 'link', 'show'])
    interfaces = [v['ifname'] for v in links]
    if any(n['Name'] in (args.internal_network, args.egress_network) for n in nets) \
            or set(interfaces) & {args.internal_bridge, args.egress_bridge} \
            or any((family, args.table_name) in tables(args) for family in ('inet', 'bridge')):
        raise trust.Blocked('NEW_EXCLUSIVE_RESOURCE_NAMES_REQUIRED')
    routes = inventory.read_json([args.ip_path, '-json', 'route', 'show', 'table', 'all'])
    excluded = ranges(nets, routes)
    addresses = inventory.read_json([args.ip_path, '-json', 'address', 'show'])
    excluded += [ipaddress.ip_network(str(a['local'])+'/'+str(a['prefixlen']), strict=False)
                 for link in addresses for a in link.get('addr_info', [])]
    rules = materialize({'tableName': args.table_name,
                         'guardedInterfaces': [args.internal_bridge, args.egress_bridge],
                         'existingInterfaces': interfaces, 'staticFlows': [], 'providerFlows': []})['nftRules']
    rules = 'create table inet '+args.table_name+'\ncreate table bridge '+args.table_name+'\n'+rules
    execute([args.nft_path, '-c', '-f', '-'], rules)
    if args.mode == 'plan': return None
    args.snapshot_root.mkdir(mode=0o700)
    trust.write(args.snapshot_root/'network-intent.json', encoded(binding))
    trust.write(args.snapshot_root/'deny-only.nft', rules.encode())
    # Install first: even network creation cannot precede the deny-only guard.
    before = fingerprint(json_command([args.nft_path, '-j', 'list', 'ruleset']))
    execute([args.nft_path, '-f', '-'], rules)
    guard_hash = fingerprint(owned(args))
    ruleset = json_command([args.nft_path, '-j', 'list', 'ruleset'])
    ruleset['nftables'] = [v for v in ruleset['nftables'] if not any(
        isinstance(item, dict) and item.get('family') in ('inet', 'bridge')
        and (item.get('table') == args.table_name or key == 'table' and item.get('name') == args.table_name)
        for key, item in v.items())]
    if fingerprint(ruleset) != before: raise trust.Blocked('CUSTOM_GUARD_SHARED_RULE_DRIFT')
    trust.write(args.snapshot_root/'guard-readback.json', encoded(owned(args)))
    ids = {}
    for role, nname, bridge, internal in (
        ('internal', args.internal_network, args.internal_bridge, True),
        ('egress', args.egress_network, args.egress_bridge, False)):
        command = [args.docker_path, 'network', 'create', '--driver', 'bridge', '--ipam-driver', 'default',
                   '--label', 'ouf.cold-network.owner='+args.installation_id,
                   '--opt', 'com.docker.network.bridge.name='+bridge]
        if internal: command.append('--internal')
        nid = execute(command+[nname]).strip()
        inventory.identifier(nid); ids[role] = nid
        trust.write(args.snapshot_root/('created-'+role+'.json'), encoded({'id': nid, 'name': nname}))
    facts = readback(args, ids)
    reject_overlap([ipaddress.ip_network(n['ipam'][0]['subnet']) for n in facts], excluded)
    if validate(args) != binding or fingerprint(owned(args)) != guard_hash:
        raise trust.Blocked('FINAL_ROLE_OR_GUARD_DRIFT')
    # Preexisting Docker networks and their endpoints must still match exactly.
    after_nets = [n for n in full_networks(args) if n['Id'] not in ids.values()]
    if fingerprint(after_nets) != fingerprint(nets): raise trust.Blocked('EXISTING_NETWORK_DRIFT')
    receipt = {'schema': 'ouf.semantic-provider-cold-networks.v1', 'binding': binding,
               'networkIds': ids, 'networks': facts, 'guardHash': guard_hash,
               'excludedRanges': sorted({str(n) for n in excluded}),
               'guardInstalledBeforeNetworkCreation': True, 'customGuardSharedRulesPreserved': True,
               'dockerManagedNetworkRulesCreated': True, 'runtimeContainersCreated': False,
               'providerCalls': 0, 'packetAcceptanceProven': False, 'notReleaseAcceptance': True}
    trust.write(args.snapshot_root/'network-receipt.json', encoded(receipt))
    return receipt


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--mode', required=True, choices=('plan', 'apply', 'verify'))
    p.add_argument('--snapshot-root', type=Path, required=True)
    for option in ('source-commit', 'installation-id', 'expected-snapshot-hash', 'gateway-container',
                   'expected-gateway-id', 'semantic-container', 'ingestion-container', 'internal-network',
                   'egress-network', 'internal-bridge', 'egress-bridge', 'table-name'):
        p.add_argument('--'+option, required=True)
    p.add_argument('--ipam', required=True, choices=('docker-auto-ipv4',))
    for option in ('docker', 'ip', 'nft'): p.add_argument('--'+option+'-path', default=option)
    args = p.parse_args(argv)
    try:
        receipt = operate(args)
        print('SEMANTIC_PROVIDER_COLD_NETWORKS=PASS MODE='+args.mode+
              ' EMPTY_NETWORKS='+str(len(receipt['networks']) if receipt else 0)+
              ' NO_CONTAINER_ATTACHED=true NO_PROVIDER_CALL=true NO_IAM_OR_ROUTE_WRITES=true'+
              ' PACKET_ACCEPTANCE_NOT_PROVEN=true NOT_RELEASE_ACCEPTANCE=true NO_SECRETS_PRINTED=true')
        if receipt: print('SEMANTIC_PROVIDER_COLD_NETWORK_RECEIPT='+str(args.snapshot_root/'network-receipt.json')+' PRIVATE=true')
        return 0
    except Exception as error:
        code = str(error) if isinstance(error, (trust.Blocked, inventory.Blocked)) else 'NETWORK_PREPARATION_UNPROVEN'
        print('SEMANTIC_PROVIDER_COLD_NETWORKS=BLOCKED CODE='+code+
              ' DO_NOT_RERUN_BLINDLY=true PARTIAL_RESOURCES_RETAINED=true NO_SECRETS_PRINTED=true')
        return 1


if __name__ == '__main__': raise SystemExit(main())
