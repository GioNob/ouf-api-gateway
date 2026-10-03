import contextlib
import io
import json
import os
from pathlib import Path
import socket
import stat
import struct
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tools import semantic_provider_dns as dns
from scripts import inventory_semantic_provider_dns as inventory
from scripts import prepare_semantic_provider_trust as trust


HOST = 'provider.fixture.example'


def record(owner, kind, value, ttl=120, section='answer'):
    return {'owner': owner, 'type': kind, 'class': 1, 'ttl': ttl, 'value': value, 'section': section}


def parsed(records):
    return {'records': records, 'transport': 'UDP', 'responseHash': 'a'*64, 'authenticatedDataFlag': False}


def query(resolver, port, host, qtype, deadline):
    return parsed([record(host, qtype, '93.184.216.34' if qtype==1 else '2001:4860:4860::8888')])


def observe(callback=query, **overrides):
    args = dict(endpoint='https://'+HOST+':443/sparql', resolvers=['127.0.0.1', '::1'], resolver_port=53,
                network_version=4, allowed_cidrs=[], timeout_seconds=3, max_lease_seconds=60, query=callback)
    args.update(overrides); return dns.observe(**args)


class DNSObservationTest(unittest.TestCase):
    def test_all_families_resolvers_ttls_and_cname_chain_no_stale_admission(self):
        calls = []
        def callback(resolver, port, host, kind, deadline):
            calls.append((resolver, host, kind))
            if host==HOST: return parsed([record(host, 5, 'target.fixture.example', 19)])
            return query(resolver, port, host, kind, deadline)
        value = observe(callback, resolvers=['127.0.0.1', '127.0.0.2', '::1'])
        self.assertEqual(len(calls), 8); self.assertEqual(value['minimumObservedTtlSeconds'], 19)
        self.assertLessEqual(value['remainingLeaseSecondsAtObservation'], 19)
        self.assertEqual(len(value['allAddresses']), 2); self.assertEqual(value['usableAddresses'], ['93.184.216.34'])
        self.assertEqual(value['deferredResolvers'], ['::1']); self.assertTrue(value['historicalEvidenceOnly'])
        self.assertFalse(value['kernelLeaseInstalled']); self.assertFalse(value['dnssecValidated'])

    def test_one_unsafe_answer_in_any_family_or_resolver_blocks_whole_observation(self):
        for address in ('::1', '169.254.1.2', '100.64.0.1', '10.2.3.4'):
            def bad(resolver, port, host, kind, deadline):
                if resolver=='127.0.0.2' and kind==(28 if ':' in address else 1):
                    return parsed([record(host, kind, address)])
                return query(resolver, port, host, kind, deadline)
            with self.assertRaises(dns.DNSDenied): observe(bad, resolvers=['127.0.0.1', '127.0.0.2'])
        def private(resolver, port, host, kind, deadline):
            if kind==1: return parsed([record(host, 1, '10.2.3.4')])
            return parsed([record('fixture.example', 6, 20, 30, 'authority')])
        self.assertEqual(observe(private, allowed_cidrs=['10.2.3.4/32'])['usableAddresses'], ['10.2.3.4'])

    def test_nodata_needs_soa_and_minimum_negative_ttl_is_preserved(self):
        def negative(resolver, port, host, kind, deadline):
            return query(resolver, port, host, kind, deadline) if kind==1 else parsed([record('fixture.example', 6, 11, 30, 'authority')])
        value = observe(negative); self.assertEqual(value['minimumObservedTtlSeconds'], 11)
        self.assertTrue(value['observations'][0]['types']['AAAA']['negative'])
        with self.assertRaises(dns.DNSDenied): observe(lambda *a: parsed([]))
        with self.assertRaises(dns.DNSDenied): observe(lambda *a: parsed([record('other.example', 6, 30, 30, 'authority')]))

    def test_conflicting_or_cyclic_cname_and_noncacheable_ttl_fail_closed(self):
        for callback in (lambda r,p,h,k,d: parsed([record(h, 5, h)]),
                         lambda r,p,h,k,d: parsed([record(h, 5, 'other.example'), record(h, k, '93.184.216.34')]),
                         lambda r,p,h,k,d: parsed([record(h, k, '93.184.216.34' if k==1 else '2001:4860:4860::8888', 0)])):
            with self.assertRaises(dns.DNSDenied): observe(callback)

    def test_wire_parser_transaction_question_bounds_and_compression_rejection(self):
        ident = 27; question = dns.wire_name(HOST)+struct.pack('!HH', 1, 1)
        raw = struct.pack('!6H', ident, 0x8180, 1, 1, 0, 0)+question+b'\xc0\x0c'+struct.pack('!HHIH', 1, 1, 120, 4)+socket.inet_aton('93.184.216.34')
        self.assertEqual(dns.response(raw, ident, HOST, 1)['records'][0]['value'], '93.184.216.34')
        for value, qid, host, kind in ((raw, 28, HOST, 1), (raw, ident, 'wrong.example', 1), (raw, ident, HOST, 28),
                                     (raw[:-1], ident, HOST, 1), (raw+b'x', ident, HOST, 1)):
            with self.assertRaises(dns.DNSDenied): dns.response(value, qid, host, kind)
        with self.assertRaises(dns.DNSDenied): dns.name_at(b'\xc0\x00', 0)
        with self.assertRaises(dns.DNSDenied): observe(endpoint='https://user:credential@'+HOST)
        with self.assertRaises(dns.DNSDenied): observe(endpoint='https://127.0.0.1/')

    def test_real_udp_truncation_tcp_fallback_both_address_families_and_cleanup(self):
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); udp.bind(('127.0.0.1', 0)); udp.settimeout(3)
        tcp = socket.socket(); tcp.bind(udp.getsockname()); tcp.listen(); tcp.settimeout(3)
        failures = []; counts = {'udp': 0, 'tcp': 0}
        def recv(peer, size):
            raw = b''
            while len(raw) < size:
                chunk = peer.recv(size-len(raw))
                if not chunk: raise RuntimeError('fixture short read')
                raw += chunk
            return raw
        def udp_worker():
            try:
                for _ in range(2):
                    raw, source = udp.recvfrom(512); ident = struct.unpack('!H', raw[:2])[0]
                    udp.sendto(struct.pack('!6H', ident, 0x8380, 1, 0, 0, 0)+raw[12:], source); counts['udp'] += 1
            except Exception as error: failures.append(type(error).__name__)
        def tcp_worker():
            try:
                for _ in range(2):
                    peer, _ = tcp.accept()
                    with peer:
                        peer.settimeout(3); size = struct.unpack('!H', recv(peer, 2))[0]; raw = recv(peer, size)
                        ident = struct.unpack('!H', raw[:2])[0]; kind = struct.unpack('!H', raw[-4:-2])[0]
                        addr = socket.inet_pton(socket.AF_INET if kind==1 else socket.AF_INET6,
                            '93.184.216.34' if kind==1 else '2001:4860:4860::8888')
                        reply = struct.pack('!6H', ident, 0x8180, 1, 1, 0, 0)+raw[12:]+b'\xc0\x0c'+struct.pack('!HHIH', kind, 1, 120, len(addr))+addr
                        peer.sendall(struct.pack('!H', len(reply))+reply); counts['tcp'] += 1
            except Exception as error: failures.append(type(error).__name__)
        workers = [threading.Thread(target=f, daemon=True) for f in (udp_worker, tcp_worker)]
        for worker in workers: worker.start()
        try:
            value = observe(dns.exchange, resolver_port=udp.getsockname()[1])
            self.assertTrue(all(t['messages'][0]['transport']=='TCP' for t in value['observations'][0]['types'].values()))
        finally:
            for worker in workers: worker.join(4)
            udp.close(); tcp.close()
        self.assertFalse(any(w.is_alive() for w in workers)); self.assertEqual(failures, [])
        self.assertEqual(counts, {'udp': 2, 'tcp': 2})
        print('SEMANTIC_PROVIDER_DNS_CI=PASS REAL_UDP_TCP=true TRUNCATION_FALLBACK=true A_AND_AAAA_CHECKED=true PROVIDER_CALLS=0 NOT_RELEASE_ACCEPTANCE=true')


@unittest.skipUnless(os.geteuid()==0 and os.environ.get('OUF_DNS_ROOT_FIXTURE_PARENT'),
                     'mandatory CI verifies private DNS stage receipt ownership as root')
class DNSPrivateInventoryTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ['OUF_DNS_ROOT_FIXTURE_PARENT']); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); stage = self.root/'runtime'; stage.mkdir(mode=0o700)
        binding = {'adapter': {'provider': {'endpoint': 'https://'+HOST+':443/sparql', 'allowed_cidrs': []}},
                   'dns': {'resolvers': ['127.0.0.1'], 'resolverPort': 53, 'networkIPVersion': 4}}
        raw = json.dumps(binding).encode(); trust.write(stage/'binding.json', raw)
        trust.write(stage/'stage-receipt.json', json.dumps({'bindingHash': inventory.digest(raw), 'runtimeFilesMounted': False,
            'notReleaseAcceptance': True}).encode())
        self.args = SimpleNamespace(mode='plan', runtime_stage_root=stage, snapshot_root=self.root/'dns',
            source_commit='c'*40, timeout_seconds=10, max_lease_seconds=60)

    def test_plan_no_dns_apply_private_readback_and_historical_verify_no_refresh(self):
        with patch.object(dns, 'observe', side_effect=AssertionError('plan must not query DNS')): inventory.operate(self.args)
        self.assertFalse(self.args.snapshot_root.exists()); self.args.mode = 'apply'
        value = observe()
        with patch.object(dns, 'observe', return_value=value) as lookup:
            self.assertEqual(inventory.operate(self.args), value); self.assertEqual(lookup.call_count, 1)
        for name in ('dns-intent.json', 'dns-observation.json', 'dns-receipt.json'):
            info = (self.args.snapshot_root/name).stat(); self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)), (0,0,0o600))
        self.assertEqual(stat.S_IMODE(self.args.snapshot_root.stat().st_mode), 0o700)
        self.args.mode = 'verify'
        with patch.object(dns, 'observe', side_effect=AssertionError('verify is historical, no DNS refresh')):
            self.assertEqual(inventory.operate(self.args), value)
        (self.args.snapshot_root/'dns-observation.json').write_bytes(b'{}')
        with self.assertRaises(trust.Blocked): inventory.operate(self.args)

    def test_staged_binding_drift_partial_failure_and_no_overwrite(self):
        path = self.args.runtime_stage_root/'binding.json'; original = path.read_bytes(); path.write_bytes(b'{}')
        with self.assertRaises(trust.Blocked): inventory.operate(self.args)
        path.write_bytes(original); self.args.mode = 'apply'
        with patch.object(dns, 'observe', side_effect=dns.DNSDenied('DNS_RESOLVER_TRANSPORT_FAILED')):
            with self.assertRaises(dns.DNSDenied): inventory.operate(self.args)
        self.assertTrue((self.args.snapshot_root/'dns-intent.json').exists()); self.assertFalse((self.args.snapshot_root/'dns-receipt.json').exists())
        with self.assertRaisesRegex(trust.Blocked, 'DNS_SNAPSHOT_EXISTS_RECONCILE'): inventory.operate(self.args)

    def test_cli_redacts_unclassified_error(self):
        out = io.StringIO()
        with patch.object(inventory, 'operate', side_effect=RuntimeError('DO-NOT-PRINT-PRIVATE-DATA')), contextlib.redirect_stdout(out):
            with self.assertRaises(SystemExit): inventory.main(['--mode','plan','--runtime-stage-root',str(self.args.runtime_stage_root),
                '--snapshot-root',str(self.args.snapshot_root),'--source-commit','c'*40,'--timeout-seconds','10','--max-lease-seconds','60'])
        self.assertNotIn('DO-NOT-PRINT', out.getvalue()); self.assertIn('NO_SECRETS_PRINTED=true', out.getvalue())


if __name__ == '__main__': unittest.main()
