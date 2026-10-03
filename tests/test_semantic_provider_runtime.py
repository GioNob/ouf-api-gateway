import copy
from dataclasses import asdict
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tests.test_semantic_provider_adapter import binding
from tests.test_semantic_provider_materialization import config as route_config
from tools.materialize_semantic_provider_runtime import compile_plan


def config():
    b = binding(); route = route_config()
    route['upstream']['timeout']['read'] = 25
    route['tlsProfile']['trustedCertificateFile'] = '/runtime/trust.pem'
    provider = asdict(b.provider)
    provider.update(namespace_prefixes=list(provider['namespace_prefixes']), allowed_cidrs=[], ca_file='/runtime/trust.pem')
    admission = asdict(b.admission); admission['tenants'] = list(admission['tenants'])
    return {'routes': route,
        'adapter': {'listenAddress': '0.0.0.0', 'listenPort': 9443, 'maxWorkers': 4,
            'requestTimeoutSeconds': 20, 'searchPath': b.search_path, 'fetchPath': b.fetch_path,
            'provider': provider, 'admission': admission, 'receiptKeyFile': '/runtime/receipt.key',
            'tlsCertificateFile': '/runtime/server.crt', 'tlsPrivateKeyFile': '/runtime/server.key'},
        'tlsIdentities': {'adapterHostname': 'adapter.example', 'southboundHostname': 'southbound.example'},
        'dns': {'resolvers': ['192.0.2.53', '2001:db8::53'], 'networkIPVersion': 4, 'resolverPort': 53}}


class RuntimePlanTest(unittest.TestCase):
    def test_native_pair_consistent_and_no_dns_or_secret_io(self):
        cfg = config(); before = copy.deepcopy(cfg)
        with (patch('socket.getaddrinfo', side_effect=AssertionError('DNS called')),
                patch('tools.semantic_provider_adapter.private_file', side_effect=AssertionError('secret read'))):
            result = compile_plan(cfg)
        self.assertEqual(cfg, before)
        self.assertEqual(result['adapterConfiguration'], cfg['adapter'])
        self.assertFalse(result['installed']); self.assertTrue(result['notReleaseAcceptance'])
        self.assertEqual(result['providerCalls'], 0)
        self.assertEqual(len(result['southboundRoutes']['routes']), 2)
        self.assertEqual(result['dnsBinding']['selectedResolvers'], ['192.0.2.53'])
        self.assertEqual(result['dnsBinding']['deferredResolvers'], ['2001:db8::53'])
        self.assertNotIn('0' * 64, json.dumps(result))
        result['adapterConfiguration']['listenPort'] = 1
        self.assertEqual(cfg, before)

    def test_no_lab_domain_port_or_resolver_defaults(self):
        cfg = config(); cfg['tlsIdentities'] = {'adapterHostname': 'rdf.transport.internal', 'southboundHostname': 'gateway.transport.internal'}
        cfg['adapter']['listenPort'] = 18443; cfg['adapter']['listenAddress'] = '::'
        cfg['routes']['upstream'].update(nodes={'rdf.transport.internal:18443': 1}, upstream_host='rdf.transport.internal')
        cfg['dns'].update(networkIPVersion=6, resolverPort=1053)
        result = compile_plan(cfg)
        self.assertEqual(result['dnsBinding']['selectedResolvers'], ['2001:db8::53'])
        self.assertEqual(result['dnsBinding']['transportPorts'], {'udp': 1053, 'tcp': 1053})
        self.assertEqual(result['adapterConfiguration']['listenPort'], 18443)
        cfg['adapter']['provider'].update(endpoint='https://catalogue.internal:18444/query', allowed_cidrs=['10.8.0.23/32'])
        self.assertEqual(compile_plan(cfg)['adapterConfiguration']['provider']['allowed_cidrs'], ['10.8.0.23/32'])

    def test_all_admission_fields_and_paths_must_match(self):
        for name in ('installation', 'issuer', 'audience', 'workload', 'scope', 'tenants'):
            cfg = config()
            value = ['different-tenant'] if name == 'tenants' else 'https://other.example/realm' if name == 'issuer' else 'different'
            cfg['adapter']['admission'][name] = value
            with self.subTest(name=name), self.assertRaises(ValueError): compile_plan(cfg)
        for name in ('searchPath', 'fetchPath'):
            cfg = config(); cfg['adapter'][name] = '/other/path'
            with self.assertRaises(ValueError): compile_plan(cfg)

    def test_tls_files_identity_node_and_purpose_separation(self):
        cases = [(['tlsIdentities', 'adapterHostname'], 'wrong.example'),
            (['tlsIdentities', 'southboundHostname'], 'adapter.example'),
            (['tlsIdentities', 'adapterHostname'], '127.0.0.1'),
            (['adapter', 'tlsPrivateKeyFile'], '/runtime/../key'),
            (['adapter', 'receiptKeyFile'], '/runtime/server.key'),
            (['adapter', 'provider', 'ca_file'], '/other/trust.pem'),
            (['routes', 'oidcSecretRef'], '$ENV://OUF_SEMANTIC_PROVIDER_OWNER_KEY'),
            (['routes', 'oidcSecretRef'], 'inline-secret')]
        for path, value in cases:
            cfg = config(); target = cfg
            for key in path[:-1]: target = target[key]
            target[path[-1]] = value
            with self.subTest(path=path), self.assertRaises(ValueError): compile_plan(cfg)

    def test_deadlines_sizes_workers_namespaces_and_private_exemptions(self):
        cases = [(['adapter', 'maxWorkers'], True), (['adapter', 'maxWorkers'], 17),
            (['adapter', 'requestTimeoutSeconds'], 10), (['routes', 'upstream', 'timeout', 'read'], 20),
            (['routes', 'maxRequestBytes'], 1024), (['adapter', 'provider', 'max_intent_chars'], 2001),
            (['adapter', 'provider', 'namespace_prefixes'], ['https://vocab.example/', 'unsafe']),
            (['adapter', 'provider', 'namespace_prefixes'], ['https://vocab.example/', 'https://vocab.example/']),
            (['adapter', 'provider', 'allowed_cidrs'], ['0.0.0.0/0']),
            (['adapter', 'provider', 'allowed_cidrs'], ['127.0.0.1/32']),
            (['adapter', 'provider', 'allowed_cidrs'], ['169.254.169.254/32']),
            (['adapter', 'provider', 'endpoint'], 'https://provider.example/sparql?query=x')]
        for path, value in cases:
            cfg = config(); target = cfg
            for key in path[:-1]: target = target[key]
            target[path[-1]] = value
            with self.subTest(path=path), self.assertRaises(ValueError): compile_plan(cfg)

    def test_resolver_metadata_is_not_forwarding_or_connectivity_proof(self):
        for resolvers in [[], ['127.0.0.53'], ['169.254.1.1'], ['0.0.0.0'], ['224.0.0.1'],
                          ['fe80::1%eth0'], ['resolver.example'], ['192.0.2.53'] * 2, ['2001:db8::53']]:
            cfg = config(); cfg['dns']['resolvers'] = resolvers
            with self.subTest(resolvers=resolvers), self.assertRaises(ValueError): compile_plan(cfg)
        cfg = config(); cfg['dns']['networkIPVersion'] = True
        with self.assertRaises(ValueError): compile_plan(cfg)
        cfg = config(); cfg['adapter']['listenAddress'] = '::'
        with self.assertRaises(ValueError): compile_plan(cfg)
        cfg = config(); cfg['dns']['resolvers'] = ['46.38.252.230', '46.38.225.230', '2a03:4000:0:1::e1e6']
        dns = compile_plan(cfg)['dnsBinding']
        self.assertEqual(len(dns['selectedResolvers']), 2)
        self.assertFalse(dns['forwardingPathProven']); self.assertFalse(dns['connectivityProven'])

    def test_cli_rejects_duplicate_unknown_oversized_or_secret_input_redacted(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'config.json'
            for raw in ['{"routes":{},"routes":{}}', '{"secret":"must-not-print"}', 'x' * 65537]:
                path.write_text(raw)
                result = subprocess.run([sys.executable, '-B', '-m', 'tools.materialize_semantic_provider_runtime',
                    '--configuration', str(path)], capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 1)
                self.assertNotIn('must-not-print', result.stdout + result.stderr)
                self.assertNotIn(folder, result.stdout + result.stderr)
                self.assertIn('NO_INSTALLATION=true', result.stdout)
            path.write_text(json.dumps(config()))
            result = subprocess.run([sys.executable, '-B', '-m', 'tools.materialize_semantic_provider_runtime',
                '--configuration', str(path)], capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(json.loads(result.stdout)['installed'])


if __name__ == '__main__': unittest.main()
