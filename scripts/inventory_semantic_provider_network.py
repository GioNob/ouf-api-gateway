#!/usr/bin/env python3
"""Read-only Docker bridge facts for an explicitly selected deployment.

No firewall commands, DNS lookups, sockets, exec, credentials or writes.
An observed bridge/subnet is not an installed default-deny policy.
"""
import argparse
import hashlib
import ipaddress
import json
import os
import re
import subprocess


class Blocked(RuntimeError):
    pass


def read_json(command):
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=20)
        if result.returncode or len(result.stdout) > 2_000_000:
            raise Blocked('READ_COMMAND_FAILED')
        return json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, ValueError):
        raise Blocked('READ_COMMAND_UNPROVEN') from None


def single(command):
    value = read_json(command)
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise Blocked('INSPECT_SHAPE_INVALID')
    return value[0]


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9a-f]{64}', value):
        raise Blocked('IMMUTABLE_ID_INVALID')
    return value


def address(value, version):
    if value in ('', None):
        return None
    parsed = ipaddress.ip_address(value)
    if parsed.version != version:
        raise Blocked('ADDRESS_FAMILY_MISMATCH')
    return str(parsed)


def workload(args, role, name):
    raw = single([args.docker_path, 'inspect', '--type', 'container', name])
    cid = identifier(raw['Id'])
    if role == 'gateway' and cid != args.expected_gateway_id:
        raise Blocked('GATEWAY_ID_MISMATCH')
    if not raw['State']['Running']:
        raise Blocked('SELECTED_WORKLOAD_NOT_RUNNING')
    if raw['HostConfig']['NetworkMode'] in ('host', 'none') or raw['HostConfig']['NetworkMode'].startswith('container:'):
        raise Blocked('BRIDGE_WORKLOAD_BINDING_REQUIRED')
    attachments = []
    for nname, net in sorted(raw['NetworkSettings']['Networks'].items()):
        attachments.append({'name': nname, 'id': identifier(net['NetworkID']),
                            'ipv4': address(net.get('IPAddress'), 4),
                            'ipv6': address(net.get('GlobalIPv6Address'), 6)})
    if not attachments:
        raise Blocked('WORKLOAD_NETWORK_MISSING')
    # Never return Config, env, mounts, labels, command or credential data.
    return {'role': role, 'name': name, 'id': cid, 'imageId': raw['Image'],
            'running': True, 'networks': attachments}


def network(args, nid, links):
    raw = single([args.docker_path, 'network', 'inspect', nid])
    if identifier(raw['Id']) != nid or raw['Driver'] != 'bridge':
        raise Blocked('SELECTED_BRIDGE_NETWORK_UNPROVEN')
    ranges = []
    for entry in raw['IPAM'].get('Config') or []:
        subnet = ipaddress.ip_network(entry['Subnet'], strict=True)
        gateway = address(entry.get('Gateway'), subnet.version)
        if gateway and ipaddress.ip_address(gateway) not in subnet:
            raise Blocked('NETWORK_GATEWAY_OUTSIDE_SUBNET')
        ranges.append({'subnet': str(subnet), 'gateway': gateway})
    configured = (raw.get('Options') or {}).get('com.docker.network.bridge.name')
    candidate = configured or ('br-' + nid[:12] if raw['Name'] != 'bridge' else None)
    matches = [link for link in links if link.get('ifname') == candidate
               and (link.get('linkinfo') or {}).get('info_kind') == 'bridge']
    proven = len(matches) == 1
    return {'id': nid, 'name': raw['Name'], 'driver': 'bridge',
            'internal': raw['Internal'], 'ipv6Enabled': raw['EnableIPv6'],
            'ipam': ranges, 'bridgeName': candidate,
            'bridgeNameSource': 'EXPLICIT_DOCKER_OPTION' if configured else 'DOCKER_ID_CONVENTION',
            'bridgeInterfaceObserved': proven,
            'bridgeIfindex': matches[0]['ifindex'] if proven else None}


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def collect(args):
    for name in (args.gateway_container, args.semantic_container, args.ingestion_container):
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', name):
            raise Blocked('WORKLOAD_NAME_INVALID')
    if len({args.gateway_container, args.semantic_container, args.ingestion_container}) != 3:
        raise Blocked('ROLE_BINDINGS_AMBIGUOUS')
    identifier(args.expected_gateway_id)
    roles = [('gateway', args.gateway_container), ('semantic', args.semantic_container),
             ('ingestion', args.ingestion_container)]
    before = [workload(args, role, name) for role, name in roles]
    links = read_json([args.ip_path, '-json', '-details', 'link', 'show'])
    if not isinstance(links, list) or any(not isinstance(link, dict) for link in links):
        raise Blocked('HOST_LINK_SHAPE_INVALID')
    ids = sorted({net['id'] for item in before for net in item['networks']})
    networks = [network(args, nid, links) for nid in ids]
    again_links = read_json([args.ip_path, '-json', '-details', 'link', 'show'])
    after = [workload(args, role, name) for role, name in roles]
    again_networks = [network(args, nid, again_links) for nid in ids]
    if fingerprint([before, networks]) != fingerprint([after, again_networks]):
        raise Blocked('SELECTED_TOPOLOGY_CHANGED')
    for item in before:
        for attachment in item['networks']:
            n = next(n for n in networks if n['id'] == attachment['id'])
            if attachment['name'] != n['name']:
                raise Blocked('NETWORK_NAME_ID_MISMATCH')
            for key in ('ipv4', 'ipv6'):
                if attachment[key] and not any(ipaddress.ip_address(attachment[key]) in ipaddress.ip_network(r['subnet']) for r in n['ipam']):
                    raise Blocked('WORKLOAD_ADDRESS_OUTSIDE_SUBNET')
    return {'schema': 'ouf.semantic-provider-network-inventory.v1', 'readOnly': True,
            'workloads': before, 'networks': networks, 'selectedTopologyStableAcrossReads': True,
            'snapshotHash': fingerprint([before, networks]), 'atomicSnapshotProven': False,
            'bridgeBindingsReady': all(n['bridgeInterfaceObserved'] and n['ipam'] for n in networks),
            'egressDefaultDenyProven': False, 'fqdnPolicyProven': False,
            'tlsTrustProven': False, 'noSecretsPrinted': True, 'providerCalls': 0,
            'notReleaseAcceptance': True}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--docker-path', default='docker')
    parser.add_argument('--ip-path', default='ip')
    for arg in ('gateway-container', 'expected-gateway-id', 'semantic-container', 'ingestion-container'):
        parser.add_argument('--' + arg, required=True)
    args = parser.parse_args(argv)
    try:
        if os.geteuid() != 0:
            raise Blocked('ROOT_REQUIRED')
        result = collect(args)
        print('SEMANTIC_PROVIDER_NETWORK=' + json.dumps(result, sort_keys=True))
        print('SEMANTIC_PROVIDER_NETWORK_INVENTORY=PASS READ_ONLY=true NO_RULE_CHANGED=true NO_CONTAINER_CHANGED=true NO_PROVIDER_CALL=true NO_SECRETS_PRINTED=true')
        return 0
    except Exception as error:
        code = str(error) if isinstance(error, Blocked) else 'INVENTORY_UNPROVEN'
        print('SEMANTIC_PROVIDER_NETWORK_INVENTORY=BLOCKED CODE=' + code + ' NO_SECRETS_PRINTED=true')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
