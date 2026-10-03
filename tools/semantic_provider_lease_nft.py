"""Bounded nft backend: expected structure must come from trusted installation.

No table creation, authority discovery, profile import or automatic adoption.
The installer/supervisor must supply and protect the expected structure hash.
"""
import hashlib
import ipaddress
import json
import re
import subprocess
import time

from tools.materialize_southbound_kernel import materialize


def structure(value):
    if isinstance(value, list): return [structure(v) for v in value]
    if isinstance(value, dict):
        if isinstance(value.get('set'), dict) and 'name' in value['set']:
            return {'set': structure({k: v for k, v in value['set'].items() if k != 'elem'})}
        return {k: structure(v) for k, v in value.items() if k not in ('packets', 'bytes', 'expires')}
    return value


def structure_hash(value):
    return hashlib.sha256(json.dumps(structure(value), sort_keys=True, separators=(',', ':')).encode()).hexdigest()


class NftBackend:
    def __init__(self, command, configuration, expected_structure_hash, read_budget_seconds, *, clock=time.monotonic):
        materialize(configuration, empty_provider_sets=True)
        if not isinstance(command, list) or not command or any(not isinstance(v, str) or not v for v in command):
            raise ValueError('explicit trusted nft command required')
        if not re.fullmatch('[0-9a-f]{64}', expected_structure_hash): raise ValueError('installation structure hash required')
        if type(read_budget_seconds) is not int or not 1 <= read_budget_seconds <= 30:
            raise ValueError('bounded read budget required')
        self.command = list(command); self.table = configuration['tableName']
        self.expected = expected_structure_hash; self.budget = read_budget_seconds; self.clock = clock

    def run(self, arguments, raw=None, timeout=None):
        value = subprocess.run(self.command+arguments, input=raw, capture_output=True, text=True,
                               timeout=self.budget if timeout is None else timeout)
        if value.returncode or len(value.stdout) > 2_000_000: raise RuntimeError('NFT_OPERATION_UNPROVEN')
        return value.stdout

    def tables(self):
        return {family: json.loads(self.run(['-j', 'list', 'table', family, self.table]))
                for family in ('inet', 'bridge')}

    def verify_ownership(self, configuration):
        if configuration['tableName'] != self.table or structure_hash(self.tables()) != self.expected:
            raise RuntimeError('NFT_INSTALLATION_STRUCTURE_DRIFT')

    def apply(self, transaction, deadline):
        remaining = deadline-self.clock()
        if remaining <= 0: raise RuntimeError('NFT_APPLY_DEADLINE_MISSED')
        self.run(['-f', '-'], transaction, timeout=min(remaining, self.budget))

    def read_sets(self, configuration):
        result = {}; raw = self.tables()
        for family, table in raw.items():
            for item in table['nftables']:
                value = item.get('set')
                if value is None: continue
                if value['family'] != family or value['table'] != self.table \
                        or not re.fullmatch('provider_[0-9]+', value['name']) or value.get('flags') != ['timeout']:
                    raise RuntimeError('NFT_SET_BINDING_UNPROVEN')
                index = int(value['name'].split('_')[1]); key = (family, index)
                if index >= len(configuration['providerFlows']) or key in result: raise RuntimeError('NFT_SET_INDEX_UNPROVEN')
                expected_type = 'ipv4_addr' if ipaddress.ip_address(configuration['providerFlows'][index]['source']).version == 4 else 'ipv6_addr'
                if value['type'] != expected_type: raise RuntimeError('NFT_SET_FAMILY_UNPROVEN')
                elements = {}
                for entry in value.get('elem', []):
                    element = entry['elem']; address = str(ipaddress.ip_address(element['val']))
                    ttl = element['expires']
                    if type(ttl) is not int or ttl <= 0 or address in elements: raise RuntimeError('NFT_SET_TTL_UNPROVEN')
                    elements[address] = ttl/1000
                result[key] = elements
        return result
