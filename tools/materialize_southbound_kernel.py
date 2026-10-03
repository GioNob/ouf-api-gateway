"""Compile scoped nftables rules; never resolve DNS or execute/install rules.

Input addresses are operator/registry evidence, not a DNS or FQDN-policy proof.
Only separately selected new interfaces may be guarded. No global ACCEPT,
flush ruleset, conntrack grandfathering or broad Internet CIDR is emitted.
"""
import ipaddress
import re
from urllib.parse import urlsplit


def name(value, maximum):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,' + str(maximum-1) + '}', value):
        raise ValueError('safe explicit kernel binding required')
    return value


def ip(value):
    if not isinstance(value, str):
        raise ValueError('exact IP address required')
    address = ipaddress.ip_address(value)
    if address.is_unspecified or address.is_loopback or address.is_link_local or address.is_multicast or address.is_reserved:
        raise ValueError('forbidden address class')
    return address


def port(value):
    if type(value) is not int or not 1 <= value <= 65535:
        raise ValueError('explicit transport port required')
    return value


def fields(value, expected):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise ValueError('explicit exact kernel configuration required')


def materialize(config, *, empty_provider_sets=False):
    fields(config, ('tableName', 'guardedInterfaces', 'existingInterfaces', 'staticFlows', 'providerFlows'))
    table = name(config['tableName'], 32)
    guarded = config['guardedInterfaces']
    existing = config['existingInterfaces']
    if not isinstance(guarded, list) or not 1 <= len(guarded) <= 8 or len(set(guarded)) != len(guarded):
        raise ValueError('distinct isolated interfaces required')
    if not isinstance(existing, list) or any(not isinstance(v, str) for v in existing):
        raise ValueError('existing interface exclusion evidence required')
    for interface in guarded:
        name(interface, 15)
        if interface in existing:
            raise ValueError('existing shared interface must not be modified')
    static = config['staticFlows']
    providers = config['providerFlows']
    if not isinstance(static, list) or not isinstance(providers, list) or len(static) > 64 or len(providers) > 16:
        raise ValueError('bounded explicit flow registry required')
    rules = []
    sets = []
    for flow in static:
        fields(flow, ('purpose', 'source', 'destination', 'protocol', 'port'))
        if flow['purpose'] not in ('WORKLOAD_GATEWAY', 'GATEWAY_ADAPTER', 'DNS', 'IDENTITY', 'TELEMETRY'):
            raise ValueError('governed infrastructure purpose required')
        source, destination = ip(flow['source']), ip(flow['destination'])
        if source.version != destination.version or flow['protocol'] not in ('tcp', 'udp'):
            raise ValueError('exact same-family transport flow required')
        if flow['protocol'] == 'udp' and flow['purpose'] != 'DNS':
            raise ValueError('UDP is only governed DNS in this profile')
        if flow['purpose'] == 'DNS' and flow['port'] != 53:
            raise ValueError('DNS port profile required')
        p = port(flow['port']); proto = flow['protocol']; family = 'ip' if source.version == 4 else 'ip6'
        # Reverse traffic is accepted only for this exact registered pair/port.
        rules += [f'{family} saddr {source} {family} daddr {destination} {proto} dport {p} ct state {{ new, established }} counter accept',
                  f'{family} saddr {destination} {family} daddr {source} {proto} sport {p} ct state established counter accept']
    for index, flow in enumerate(providers):
        fields(flow, ('endpointRef', 'endpoint', 'source', 'addresses', 'leaseSeconds', 'resolutionEvidenceRef', 'allowedPrivateAddresses'))
        for ref in ('endpointRef', 'resolutionEvidenceRef'):
            name(flow[ref], 128)
        endpoint = urlsplit(flow['endpoint'])
        if endpoint.scheme != 'https' or not endpoint.hostname or endpoint.username or endpoint.password or endpoint.query or endpoint.fragment:
            raise ValueError('governed HTTPS endpoint required')
        p = port(endpoint.port if endpoint.port is not None else 443)
        source = ip(flow['source'])
        addresses = flow['addresses']; private = flow['allowedPrivateAddresses']; lease = flow['leaseSeconds']
        if not isinstance(addresses, list) or not (0 if empty_provider_sets else 1) <= len(addresses) <= 32 or len(set(addresses)) != len(addresses):
            raise ValueError('bounded distinct resolved addresses required')
        if not isinstance(private, list) or any(not isinstance(v, str) for v in private):
            raise ValueError('explicit private destination exception required')
        private_set = {str(ip(v)) for v in private}
        if type(lease) is not int or not 1 <= lease <= 3600:
            raise ValueError('bounded expiring destination lease required')
        selected = []
        for value in addresses:
            address = ip(value)
            if address.version != source.version:
                raise ValueError('one source/address-family per provider flow required')
            # CGNAT and other non-global classes require an exact exception too.
            if not address.is_global and str(address) not in private_set:
                raise ValueError('non-global destination not explicitly registered')
            selected.append(str(address))
        if not empty_provider_sets and not private_set.issubset(set(selected)):
            raise ValueError('unused private destination exception')
        family = 'ip' if source.version == 4 else 'ip6'; set_name = 'provider_' + str(index)
        nft_type = 'ipv4_addr' if source.version == 4 else 'ipv6_addr'
        if empty_provider_sets:
            sets.append(f' set {set_name} {{ type {nft_type}; flags timeout; }}')
        else:
            sets.append(f' set {set_name} {{ type {nft_type}; flags timeout; elements = {{ ' +
                        ', '.join(f'{value} timeout {lease}s' for value in selected) + ' }; }')
        # Check the expiring set on every packet, including established/reply
        # traffic: expiration must not leave an already-open socket admitted.
        rules += [f'{family} saddr {source} {family} daddr @{set_name} tcp dport {p} ct state {{ new, established }} counter accept',
                  f'{family} saddr @{set_name} {family} daddr {source} tcp sport {p} ct state established counter accept']
    interface_set = '{ ' + ', '.join('"'+v+'"' for v in guarded) + ' }'
    lines = ['table inet ' + table + ' {', *sets, ' chain governed_flows {',
             '  ct state invalid counter drop', *('  '+rule for rule in rules), '  counter drop', ' }']
    for hook in ('input', 'output', 'forward'):
        lines += [' chain guard_' + hook + ' {', f'  type filter hook {hook} priority -150; policy accept;']
        # Input/output protect host access as well as routed cross-bridge I/O.
        if hook != 'output':
            lines.append(f'  iifname {interface_set} jump governed_flows')
        if hook != 'input':
            lines.append(f'  oifname {interface_set} jump governed_flows')
        lines.append(' }')
    lines.append('}')
    # Same-bridge frames do not necessarily traverse inet hooks. Native bridge
    # filtering closes that path without changing shared br_netfilter sysctls.
    lines += ['table bridge ' + table + ' {', *sets, ' chain governed_bridge_flows {',
              '  ether type arp counter accept',
              '  ether type ip6 ip6 hoplimit 255 icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } counter accept',
              '  ct state invalid counter drop', *('  '+rule for rule in rules),
              '  counter drop', ' }', ' chain guard_bridge_forward {',
              '  type filter hook forward priority 0; policy accept;',
              f'  meta ibrname {interface_set} jump governed_bridge_flows',
              f'  meta obrname {interface_set} jump governed_bridge_flows', ' }', '}']
    return {'schema': 'ouf.southbound-kernel-plan.v1', 'nftRules': '\n'.join(lines)+'\n',
            'tableName': table, 'tableFamilies': ['inet', 'bridge'],
            'guardedInterfaces': list(guarded), 'installed': False,
            'egressDefaultDenyProven': False, 'fqdnPolicyProven': False,
            'notReleaseAcceptance': True,
            'requirements': ['NEW_ISOLATED_INTERFACE_BINDINGS_READBACK', 'FAIL_CLOSED_DNS_LEASE_REFRESH',
                             'EXCLUSIVE_TABLE_INSTALL_AND_READBACK', 'REAL_DOCKER_PACKET_NEGATIVES',
                             'BRIDGE_FORWARDING_HOOK_PROOF', 'HOST_DNS_PROXY_BOUNDARY',
                             'WORKLOAD_DIRECT_BYPASS_NEGATIVES', 'REBOOT_AND_RESTART_PERSISTENCE']}
