"""Bounded explicit-resolver DNS observations, not admission or DNSSEC proof."""
import hashlib
import ipaddress
import math
import re
import secrets
import socket
import struct
import time
from urllib.parse import urlsplit


class DNSDenied(RuntimeError): pass


def hostname(value):
    if not isinstance(value, str) or len(value) > 253 or not value \
            or any(not re.fullmatch('[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', s) for s in value.split('.')):
        raise DNSDenied('DNS_HOSTNAME_INVALID')
    return value.lower()


def wire_name(value):
    return b''.join(bytes([len(s)])+s.encode('ascii') for s in hostname(value).split('.'))+b'\0'


def name_at(raw, offset):
    labels = []; seen = set(); end = None
    for _ in range(128):
        if offset in seen or offset >= len(raw): raise DNSDenied('DNS_NAME_BOUNDS_OR_CYCLE')
        seen.add(offset); length = raw[offset]; offset += 1
        if length & 0xc0 == 0xc0:
            if offset >= len(raw): raise DNSDenied('DNS_NAME_BOUNDS_OR_CYCLE')
            target = ((length & 0x3f)<<8) | raw[offset]
            if target >= offset-1: raise DNSDenied('DNS_FORWARD_COMPRESSION_POINTER')
            if end is None: end = offset+1
            offset = target; continue
        if length & 0xc0: raise DNSDenied('DNS_LABEL_ENCODING_INVALID')
        if not length:
            result = '.'.join(labels)
            if result: hostname(result)
            return result.lower(), end if end is not None else offset
        if offset+length > len(raw): raise DNSDenied('DNS_NAME_BOUNDS_OR_CYCLE')
        try: labels.append(raw[offset:offset+length].decode('ascii'))
        except UnicodeError: raise DNSDenied('DNS_LABEL_ENCODING_INVALID') from None
        if sum(map(len, labels))+len(labels)-1 > 253: raise DNSDenied('DNS_NAME_BOUNDS_OR_CYCLE')
        offset += length
    raise DNSDenied('DNS_NAME_BOUNDS_OR_CYCLE')


def response(raw, identifier, question, qtype):
    if not 12 <= len(raw) <= 65535: raise DNSDenied('DNS_MESSAGE_SIZE_INVALID')
    ident, flags, qd, an, ns, ar = struct.unpack('!6H', raw[:12])
    if ident != identifier or not flags & 0x8000 or flags & 0x7800 or flags & 0x0040 or flags & 15 or qd != 1 \
            or an+ns+ar > 256: raise DNSDenied('DNS_HEADER_OR_TRANSACTION_INVALID')
    name, offset = name_at(raw, 12)
    if offset+4 > len(raw) or name != hostname(question) or struct.unpack('!HH', raw[offset:offset+4]) != (qtype, 1):
        raise DNSDenied('DNS_QUESTION_MISMATCH')
    offset += 4
    if flags & 0x0200: return {'truncated': True}
    records = []
    for i in range(an+ns+ar):
        owner, offset = name_at(raw, offset)
        if offset+10 > len(raw): raise DNSDenied('DNS_RECORD_BOUNDS_INVALID')
        kind, cls, ttl, length = struct.unpack('!HHIH', raw[offset:offset+10]); offset += 10
        if ttl & 0x80000000: ttl = 0
        end = offset+length
        if end > len(raw): raise DNSDenied('DNS_RECORD_BOUNDS_INVALID')
        data = None
        if cls == 1 and kind in (1, 28):
            if length != (4 if kind == 1 else 16): raise DNSDenied('DNS_ADDRESS_SIZE_INVALID')
            data = str(ipaddress.ip_address(raw[offset:end]))
        elif cls == 1 and kind == 5:
            data, used = name_at(raw, offset)
            if used != end or not data: raise DNSDenied('DNS_CNAME_BOUNDS_INVALID')
        elif cls == 1 and kind == 6:
            _, used = name_at(raw, offset); _, used = name_at(raw, used)
            if used+20 != end: raise DNSDenied('DNS_SOA_BOUNDS_INVALID')
            data = struct.unpack('!5I', raw[used:end])[-1]
        records.append({'owner': owner, 'type': kind, 'class': cls, 'ttl': ttl, 'value': data,
                        'section': 'answer' if i < an else 'authority' if i < an+ns else 'additional'})
        offset = end
    if offset != len(raw): raise DNSDenied('DNS_TRAILING_MESSAGE_DATA')
    return {'truncated': False, 'records': records, 'authenticatedDataFlag': bool(flags & 0x20)}


def exchange(resolver, port, question, qtype, deadline):
    address = ipaddress.ip_address(resolver)
    family = socket.AF_INET if address.version == 4 else socket.AF_INET6
    ident = int.from_bytes(secrets.token_bytes(2), 'big')
    query = struct.pack('!6H', ident, 0x0100, 1, 0, 0, 0)+wire_name(question)+struct.pack('!HH', qtype, 1)
    def remaining():
        value = deadline-time.monotonic()
        if value <= 0: raise DNSDenied('DNS_DEADLINE_EXPIRED')
        return value
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as peer:
            peer.settimeout(remaining()); peer.connect((str(address), port)); peer.send(query)
            raw = peer.recv(65535)
        parsed = response(raw, ident, question, qtype); transport = 'UDP'
        if parsed['truncated']:
            with socket.socket(family, socket.SOCK_STREAM) as peer:
                peer.settimeout(remaining()); peer.connect((str(address), port)); peer.sendall(struct.pack('!H', len(query))+query)
                def read(count):
                    result = bytearray()
                    while len(result) < count:
                        peer.settimeout(remaining()); chunk = peer.recv(count-len(result))
                        if not chunk: raise DNSDenied('DNS_TCP_RESPONSE_INCOMPLETE')
                        result.extend(chunk)
                    return bytes(result)
                length = struct.unpack('!H', read(2))[0]
                if length < 12: raise DNSDenied('DNS_MESSAGE_SIZE_INVALID')
                raw = read(length)
            parsed = response(raw, ident, question, qtype); transport = 'TCP'
            if parsed['truncated']: raise DNSDenied('DNS_TCP_RESPONSE_TRUNCATED')
        parsed.update(transport=transport, responseHash=hashlib.sha256(raw).hexdigest())
        return parsed
    except OSError: raise DNSDenied('DNS_RESOLVER_TRANSPORT_FAILED') from None


def resolve_type(resolver, port, question, qtype, deadline, query=exchange):
    current = hostname(question); seen = set(); chain = []; ttls = []; evidence = []
    for _ in range(9):
        if current in seen: raise DNSDenied('DNS_CNAME_CHAIN_CYCLE')
        parsed = query(resolver, port, current, qtype, deadline)
        evidence.append({'question': current, 'type': 'A' if qtype == 1 else 'AAAA',
                         'transport': parsed['transport'], 'responseHash': parsed['responseHash'],
                         'authenticatedDataFlag': parsed['authenticatedDataFlag']})
        records = parsed['records']; progressed = False
        while True:
            if current in seen: raise DNSDenied('DNS_CNAME_CHAIN_CYCLE')
            aliases = [r for r in records if r['section']=='answer' and r['class']==1 and r['owner']==current and r['type']==5]
            addresses = [r for r in records if r['section']=='answer' and r['class']==1 and r['owner']==current and r['type']==qtype]
            if aliases and addresses: raise DNSDenied('DNS_CNAME_ADDRESS_CONFLICT')
            if addresses:
                ttls.extend(r['ttl'] for r in addresses)
                return {'addresses': sorted({r['value'] for r in addresses}), 'ttls': ttls,
                        'cnameChain': chain, 'messages': evidence, 'negative': False}
            if aliases:
                targets = {r['value'] for r in aliases}
                if len(targets) != 1 or len(chain) >= 8: raise DNSDenied('DNS_CNAME_CHAIN_AMBIGUOUS_OR_LONG')
                seen.add(current); target = next(iter(targets)); ttls.extend(r['ttl'] for r in aliases)
                chain.append({'owner': current, 'target': target}); current = target; progressed = True
                continue
            soa = [r for r in records if r['section']=='authority' and r['class']==1 and r['type']==6 and r['value'] is not None
                   and (r['owner']==current or current.endswith('.'+r['owner']) or r['owner']=='')]
            if soa:
                ttls.extend(min(r['ttl'], r['value']) for r in soa)
                return {'addresses': [], 'ttls': ttls, 'cnameChain': chain, 'messages': evidence, 'negative': True}
            if not progressed: raise DNSDenied('DNS_EMPTY_ANSWER_WITHOUT_NEGATIVE_PROOF')
            break  # CNAME target missing in this message: same selected resolver.
    raise DNSDenied('DNS_CNAME_CHAIN_AMBIGUOUS_OR_LONG')


def observe(endpoint, resolvers, resolver_port, network_version, allowed_cidrs, timeout_seconds, max_lease_seconds, query=exchange):
    parsed = urlsplit(endpoint)
    if parsed.scheme != 'https' or parsed.username or parsed.password or parsed.fragment or parsed.query or not parsed.hostname:
        raise DNSDenied('EXPLICIT_HTTPS_ENDPOINT_REQUIRED')
    host = hostname(parsed.hostname)
    if not 1 <= (parsed.port if parsed.port is not None else 443) <= 65535:
        raise DNSDenied('EXPLICIT_HTTPS_ENDPOINT_REQUIRED')
    try: ipaddress.ip_address(host)
    except ValueError: pass
    else: raise DNSDenied('DNS_DOMAIN_ENDPOINT_REQUIRED')
    if type(resolver_port) is not int or not 1 <= resolver_port <= 65535 or network_version not in (4, 6) \
            or type(network_version) is not int or not isinstance(resolvers, list) or not 1 <= len(resolvers) <= 8 \
            or len(set(resolvers)) != len(resolvers) or type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 30 \
            or type(max_lease_seconds) is not int or not 1 <= max_lease_seconds <= 3600:
        raise DNSDenied('BOUNDED_EXPLICIT_DNS_PROFILE_REQUIRED')
    selected = []; deferred = []
    for raw in resolvers:
        address = ipaddress.ip_address(raw)
        if address.is_unspecified or address.is_multicast: raise DNSDenied('DNS_RESOLVER_ADDRESS_INVALID')
        (selected if address.version == network_version else deferred).append(str(address))
    if not selected: raise DNSDenied('DNS_RESOLVER_FAMILY_MISSING')
    if not isinstance(allowed_cidrs, list): raise DNSDenied('DNS_ADDRESS_POLICY_INVALID')
    networks = [ipaddress.ip_network(c, strict=True) for c in allowed_cidrs]
    started = time.monotonic(); started_wall = time.time(); deadline = started+timeout_seconds
    observations = []; addresses = set(); ttls = []
    for resolver in selected:
        types = {}
        for qtype in (1, 28):
            value = resolve_type(resolver, resolver_port, host, qtype, deadline, query)
            types['A' if qtype == 1 else 'AAAA'] = value; ttls.extend(value['ttls']); addresses.update(value['addresses'])
        observations.append({'resolver': resolver, 'port': resolver_port, 'types': types})
    if not addresses or len(addresses) > 32: raise DNSDenied('BOUNDED_NONEMPTY_PROVIDER_ADDRESS_SET_REQUIRED')
    for raw in addresses:
        address = ipaddress.ip_address(raw)
        if address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified or address.is_reserved:
            raise DNSDenied('DNS_FORBIDDEN_PROVIDER_ADDRESS')
        matches = any(address in network for network in networks)
        if (not address.is_global and not matches) or (networks and not matches):
            raise DNSDenied('DNS_PROVIDER_ADDRESS_POLICY_MISMATCH')
    usable = sorted(raw for raw in addresses if ipaddress.ip_address(raw).version == network_version)
    if not usable: raise DNSDenied('DNS_PROVIDER_FAMILY_MISSING')
    elapsed = time.monotonic()-started
    lease = min(min(ttls), max_lease_seconds)-math.ceil(elapsed)
    if lease < 1: raise DNSDenied('DNS_OBSERVATION_EXPIRED_OR_NONCACHEABLE')
    return {'schema': 'ouf.semantic-provider-dns-observation.v1', 'endpoint': endpoint, 'hostname': host,
        'networkIPVersion': network_version, 'allAddresses': sorted(addresses), 'usableAddresses': usable,
        'deferredResolvers': deferred, 'observations': observations, 'minimumObservedTtlSeconds': min(ttls),
        'remainingLeaseSecondsAtObservation': lease, 'observedAtUnixSeconds': started_wall+elapsed,
        'expiresAtUnixSeconds': started_wall+elapsed+lease, 'dnssecValidated': False,
        'resolverChannelAuthenticated': False, 'kernelLeaseInstalled': False, 'providerCalls': 0,
        'notReleaseAcceptance': True, 'historicalEvidenceOnly': True}
