"""Private APISIX TLS-only bootstrap; returned resources contain a private key.

No CLI, file/network I/O, key generation, installation or northbound modification.
The caller must verify existing trust/leaf/role bindings and protect output files.
"""
import copy
import ipaddress
import re

from tools.materialize_semantic_provider import materialize
from tools.materialize_semantic_provider_runtime import exact, bounded, hostname


class TLSBootstrapDenied(ValueError):
    pass


def materialize_tls(route_binding, transport, *, certificate_pem, private_key_pem):
    exact(transport, ('listenAddress', 'listenPort', 'serverHostname', 'sslResourceId'))
    bounded(transport['listenPort'], 1024, 65535)
    hostname(transport['serverHostname'])
    try:
        address = ipaddress.ip_address(transport['listenAddress'])
    except (ValueError, TypeError):
        raise TLSBootstrapDenied('NUMERIC_TLS_LISTENER_REQUIRED') from None
    if address.is_multicast or address.is_link_local:
        raise TLSBootstrapDenied('TLS_LISTENER_INVALID')
    if not isinstance(transport['sslResourceId'], str) or not re.fullmatch(
            r'[A-Za-z0-9_-]{1,128}', transport['sslResourceId']):
        raise TLSBootstrapDenied('SSL_RESOURCE_ID_REQUIRED')
    # Structural bounds only. Signature, expiry, exact hostname and key-pair
    # verification must be performed by the private installation preparer.
    if not isinstance(certificate_pem, str) or not certificate_pem.isascii() \
            or not 128 <= len(certificate_pem) <= 65536 \
            or not certificate_pem.startswith('-----BEGIN CERTIFICATE-----\n') \
            or not certificate_pem.rstrip().endswith('-----END CERTIFICATE-----') \
            or 'PRIVATE KEY' in certificate_pem:
        raise TLSBootstrapDenied('BOUNDED_SERVER_CERTIFICATE_REQUIRED')
    if not isinstance(private_key_pem, str) or not private_key_pem.isascii() \
            or not 64 <= len(private_key_pem) <= 65536 \
            or not re.fullmatch(r'-----BEGIN ((?:EC |RSA )?PRIVATE KEY)-----\n[A-Za-z0-9+/=\n]+-----END \1-----\s*', private_key_pem):
        raise TLSBootstrapDenied('BOUNDED_SERVER_PRIVATE_KEY_REQUIRED')
    plan = materialize({'routes': []}, route_binding)
    if transport['serverHostname'] == route_binding['upstream']['upstream_host']:
        raise TLSBootstrapDenied('DISTINCT_TLS_ROLE_IDENTITIES_REQUIRED')
    tls = plan['providerTLSRequirement']
    runtime = {'apisix': {
        'node_listen': [], 'enable_admin': False, 'enable_control': False,
        'enable_ipv6': address.version == 6, 'enable_http2': False,
        'ssl': {'enable': True, 'listen': [{'ip': str(address), 'port': transport['listenPort'], 'enable_http3': False}],
                'ssl_protocols': 'TLSv1.2 TLSv1.3', 'ssl_session_tickets': False,
                'ssl_trusted_certificate': tls['apisixSSLTrustedCertificate']}},
        'deployment': {'role': 'data_plane', 'role_data_plane': {'config_provider': 'yaml'}},
        'plugins': ['client-control', 'limit-count', 'openid-connect', 'serverless-pre-function', 'serverless-post-function'],
        'nginx_config': {'envs': [route_binding['oidcSecretRef'].removeprefix('$ENV://'),
                                  route_binding['receiptKeyEnvironment']],
            'http_configuration_snippet': tls['nginxHTTPConfigurationSnippet']}}
    if not re.fullmatch(r'\$ENV://[A-Z][A-Z0-9_]{1,127}', route_binding['oidcSecretRef']) \
            or runtime['nginx_config']['envs'][0] == runtime['nginx_config']['envs'][1]:
        raise TLSBootstrapDenied('DISTINCT_ENV_REFERENCES_REQUIRED')
    resources = {'routes': copy.deepcopy(plan['routes']), 'ssls': [{
        'id': transport['sslResourceId'], 'type': 'server', 'status': 1,
        'snis': [transport['serverHostname']], 'cert': certificate_pem, 'key': private_key_pem,
        'ssl_protocols': ['TLSv1.2', 'TLSv1.3'],
        'labels': {'ouf-managed': 'true', 'ouf-installation': route_binding['installation']}}]}
    # APISIX 3.18 cli/ops.lua sets placeholder cert/key paths unconditionally;
    # the real server certificate is selected by this exact SNI SSL resource.
    return {'runtimeConfiguration': runtime, 'resources': resources,
        'containsPrivateKey': True, 'certificateCryptographicallyVerified': False,
        'installed': False, 'providerCalls': 0, 'notReleaseAcceptance': True}
