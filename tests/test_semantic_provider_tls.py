import copy
import unittest
from unittest.mock import patch

from tests.test_semantic_provider_materialization import config
from tools.materialize_semantic_provider_tls import materialize_tls

# Deliberately synthetic structural PEMs: this pure factory makes no
# cryptographic verification claim. Real valid/invalid TLS is a separate gate.
CERT = '-----BEGIN CERTIFICATE-----\n' + 'A'*128 + '\n-----END CERTIFICATE-----\n'
KEY = '-----BEGIN PRIVATE KEY-----\n' + 'A'*128 + '\n-----END PRIVATE KEY-----\n'


def transport():
    return {'listenAddress': '0.0.0.0', 'listenPort': 10443,
            'serverHostname': 'southbound.example', 'sslResourceId': 'southbound-tls'}


class TLSBootstrapTest(unittest.TestCase):
    def bootstrap(self, route=None, server=None, cert=CERT, key=KEY):
        return materialize_tls(config() if route is None else route,
            transport() if server is None else server, certificate_pem=cert, private_key_pem=key)

    def test_tls_only_exact_sni_bounded_protocols_and_no_auxiliary_listeners(self):
        cfg = config(); before = copy.deepcopy(cfg)
        with patch('socket.getaddrinfo', side_effect=AssertionError('network called')):
            result = self.bootstrap(cfg)
        runtime = result['runtimeConfiguration']; apisix = runtime['apisix']
        self.assertEqual(apisix['node_listen'], [])
        self.assertFalse(apisix['enable_admin']); self.assertFalse(apisix['enable_control'])
        self.assertEqual(apisix['ssl']['listen'], [{'ip': '0.0.0.0', 'port': 10443, 'enable_http3': False}])
        self.assertEqual(apisix['ssl']['ssl_protocols'], 'TLSv1.2 TLSv1.3')
        self.assertNotIn('fallback_sni', apisix['ssl'])
        self.assertNotIn('ssl_cert', apisix['ssl'], 'placeholder paths do not install the real leaf')
        self.assertNotIn('prometheus', runtime['plugins'])
        self.assertEqual(runtime['deployment']['role_data_plane']['config_provider'], 'yaml')
        self.assertEqual(result['resources']['ssls'][0]['snis'], ['southbound.example'])
        self.assertEqual(result['resources']['ssls'][0]['key'], KEY)
        self.assertTrue(result['containsPrivateKey']); self.assertFalse(result['installed'])
        self.assertFalse(result['certificateCryptographicallyVerified'])
        self.assertTrue(result['notReleaseAcceptance']); self.assertEqual(result['providerCalls'], 0)
        self.assertEqual(cfg, before)

    def test_arbitrary_explicit_domains_ports_ipv6_and_references_remain_data(self):
        cfg = config(); server = transport()
        server.update(listenAddress='::', listenPort=19443, serverHostname='gateway.custom.internal', sslResourceId='custom-tls')
        cfg['tlsProfile']['trustedCertificateFile'] = '/custom/trust.pem'
        cfg['oidcSecretRef'] = '$ENV://CUSTOM_OIDC_SECRET'; cfg['receiptKeyEnvironment'] = 'CUSTOM_PROVIDER_RECEIPT'
        result = self.bootstrap(cfg, server)
        self.assertTrue(result['runtimeConfiguration']['apisix']['enable_ipv6'])
        self.assertEqual(result['runtimeConfiguration']['apisix']['ssl']['listen'][0]['port'], 19443)
        self.assertEqual(result['runtimeConfiguration']['nginx_config']['envs'], ['CUSTOM_OIDC_SECRET', 'CUSTOM_PROVIDER_RECEIPT'])
        self.assertIn('proxy_ssl_verify on;', result['runtimeConfiguration']['nginx_config']['http_configuration_snippet'])
        result['resources']['routes'][0]['uri'] = '/mutated'
        self.assertEqual(cfg['searchPath'], '/provider/search')

    def test_wildcards_shared_role_missing_and_invalid_listener_bindings_rejected(self):
        cases = [('serverHostname', '*.example'), ('serverHostname', 'adapter.example'),
                 ('listenAddress', 'dns.example'), ('listenAddress', '224.0.0.1'),
                 ('listenAddress', 'fe80::1'), ('listenPort', True), ('listenPort', 443),
                 ('listenPort', 65536), ('sslResourceId', 'x/y')]
        for name, value in cases:
            server = transport(); server[name] = value
            with self.subTest(name=name), self.assertRaises(ValueError): self.bootstrap(server=server)
        server = transport(); server['httpPort'] = 9080
        with self.assertRaises(ValueError): self.bootstrap(server=server)

    def test_inline_oidc_alias_unverified_role_profile_and_invalid_pem_rejected(self):
        for value in ('inline-secret', '$secret://provider/oidc', '$ENV://OUF_SEMANTIC_PROVIDER_OWNER_KEY'):
            cfg = config(); cfg['oidcSecretRef'] = value
            with self.assertRaises(ValueError): self.bootstrap(route=cfg)
        cfg = config(); cfg['tlsProfile']['role'] = 'NORTHBOUND'
        with self.assertRaises(ValueError): self.bootstrap(route=cfg)
        for cert in ('', CERT+'PRIVATE KEY', 'x'*65537, KEY):
            with self.assertRaises(ValueError): self.bootstrap(cert=cert)
        for key in ('', 'encrypted-key', 'x'*65537, CERT):
            with self.assertRaises(ValueError): self.bootstrap(key=key)


if __name__ == '__main__': unittest.main()
