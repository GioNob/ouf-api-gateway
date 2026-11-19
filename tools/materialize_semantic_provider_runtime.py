"""Compile matching adapter/route/DNS bindings without installation or network I/O.

This plan is intentionally not an APISIX startup configuration or an egress
installation receipt. No secret value is accepted: only runtime file references.
"""
import argparse
import copy
import ipaddress
import json
from pathlib import Path
import re

from tools.materialize_semantic_provider import materialize
from tools.semantic_provider_adapter import AdapterBinding
from tools.semantic_provider_admission import AdmissionBinding
from tools.semantic_provider_relay import ProviderBinding


class RuntimePlanDenied(ValueError):
    pass


def exact(value, keys):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise RuntimePlanDenied('EXPLICIT_BINDING_REQUIRED')


def bounded(value, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        raise RuntimePlanDenied('BOUND_INVALID')


def hostname(value):
    if not isinstance(value, str) or len(value) > 253 or any(
            not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part)
            for part in value.split('.')):
        raise RuntimePlanDenied('DNS_IDENTITY_INVALID')
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return
    raise RuntimePlanDenied('DNS_IDENTITY_INVALID')


def file_reference(value):
    if not isinstance(value, str) or not re.fullmatch(r'/[A-Za-z0-9_./-]{1,255}', value) \
            or any(part in ('', '.', '..') for part in value.split('/')[1:]):
        raise RuntimePlanDenied('RUNTIME_FILE_REFERENCE_INVALID')


def compile_plan(config):
    exact(config, ('routes', 'adapter', 'tlsIdentities', 'dns'))
    route = config['routes']; adapter = config['adapter']; identities = config['tlsIdentities']
    exact(identities, ('adapterHostname', 'southboundHostname'))
    for value in identities.values():
        hostname(value)
    if identities['adapterHostname'] == identities['southboundHostname']:
        raise RuntimePlanDenied('DISTINCT_ROLE_IDENTITIES_REQUIRED')
    exact(adapter, ('listenAddress', 'listenPort', 'maxWorkers', 'requestTimeoutSeconds',
                    'searchPath', 'fetchPath', 'provider', 'admission', 'receiptKeyFile',
                    'tlsCertificateFile', 'tlsPrivateKeyFile'))
    bounded(adapter['listenPort'], 1024, 65535)
    bounded(adapter['maxWorkers'], 1, 16)
    bounded(adapter['requestTimeoutSeconds'], 1, 60)
    try:
        listener = ipaddress.ip_address(adapter['listenAddress'])
    except (ValueError, TypeError):
        raise RuntimePlanDenied('NUMERIC_LISTENER_REQUIRED') from None
    if listener.is_multicast or listener.is_loopback or listener.is_link_local:
        raise RuntimePlanDenied('ISOLATED_LISTENER_REQUIRED')
    exact(adapter['provider'], ('endpoint', 'namespace_prefixes', 'allowed_cidrs',
          'max_request_bytes', 'max_response_bytes', 'max_intent_chars', 'timeout_seconds', 'ca_file'))
    exact(adapter['admission'], ('installation', 'issuer', 'audience', 'workload', 'scope', 'tenants'))
    bounded(adapter['provider']['max_intent_chars'], 1, 2000)
    # Private installations are supported with exact explicit host exemptions,
    # never a broad subnet/network permit. Governance remains an install gate.
    exemptions = adapter['provider']['allowed_cidrs']
    if not isinstance(exemptions, list) or len(exemptions) > 32:
        raise RuntimePlanDenied('EXACT_DESTINATION_EXEMPTIONS_REQUIRED')
    networks = []
    for value in exemptions:
        if not isinstance(value, str):
            raise RuntimePlanDenied('EXACT_DESTINATION_EXEMPTIONS_REQUIRED')
        network = ipaddress.ip_network(value)
        ip = network.network_address
        if network.prefixlen != network.max_prefixlen or ip.is_loopback or ip.is_unspecified \
                or ip.is_link_local or ip.is_multicast or ip.is_reserved:
            raise RuntimePlanDenied('EXACT_DESTINATION_EXEMPTIONS_REQUIRED')
        networks.append(network)
    if len(set(networks)) != len(networks):
        raise RuntimePlanDenied('DUPLICATE_DESTINATION_EXEMPTION')
    prefixes = adapter['provider']['namespace_prefixes']
    if not isinstance(prefixes, list) or not 1 <= len(prefixes) <= 32 \
            or any(not isinstance(v, str) for v in prefixes) or len(set(prefixes)) != len(prefixes):
        raise RuntimePlanDenied('EXPLICIT_NAMESPACES_REQUIRED')
    tenants = adapter['admission']['tenants']
    if not isinstance(tenants, list) or not 1 <= len(tenants) <= 32 \
            or any(not isinstance(v, str) for v in tenants) or len(set(tenants)) != len(tenants):
        raise RuntimePlanDenied('EXPLICIT_TENANTS_REQUIRED')
    # Native validation, with an ephemeral placeholder only to validate the
    # non-secret shape. Never read, generate, persist or return a receipt key.
    native = AdapterBinding(ProviderBinding(**adapter['provider']),
        AdmissionBinding(**adapter['admission']), adapter['searchPath'], adapter['fetchPath'],
        '0' * 64, adapter['requestTimeoutSeconds'])
    native.validate()
    routes = materialize({'routes': []}, route)
    for name in ('installation', 'issuer', 'audience', 'workload', 'scope', 'tenants'):
        if route[name] != adapter['admission'][name]:
            raise RuntimePlanDenied('ADMISSION_BINDING_MISMATCH')
    for name in ('searchPath', 'fetchPath'):
        if route[name] != adapter[name]:
            raise RuntimePlanDenied('REQUEST_PATH_MISMATCH')
    if route['maxRequestBytes'] != adapter['provider']['max_request_bytes']:
        raise RuntimePlanDenied('REQUEST_BOUND_MISMATCH')
    if adapter['requestTimeoutSeconds'] <= adapter['provider']['timeout_seconds'] \
            or route['upstream']['timeout']['read'] <= adapter['requestTimeoutSeconds']:
        raise RuntimePlanDenied('DEADLINE_ORDER_INVALID')
    adapter_host = identities['adapterHostname']
    if route['upstream']['upstream_host'] != adapter_host \
            or route['upstream']['nodes'] != {adapter_host + ':' + str(adapter['listenPort']): 1}:
        raise RuntimePlanDenied('ADAPTER_TLS_BINDING_MISMATCH')
    if not re.fullmatch(r'\$ENV://[A-Z][A-Z0-9_]{1,127}', route['oidcSecretRef']) \
            or route['oidcSecretRef'] == '$ENV://' + route['receiptKeyEnvironment']:
        raise RuntimePlanDenied('PURPOSE_SEPARATED_ENV_REFERENCES_REQUIRED')
    paths = [adapter[k] for k in ('receiptKeyFile', 'tlsCertificateFile', 'tlsPrivateKeyFile')]
    paths.append(adapter['provider']['ca_file'])
    for path in paths:
        file_reference(path)
    if len(set(paths)) != len(paths):
        raise RuntimePlanDenied('DISTINCT_RUNTIME_FILES_REQUIRED')
    if adapter['provider']['ca_file'] != route['tlsProfile']['trustedCertificateFile']:
        raise RuntimePlanDenied('TRUST_BUNDLE_BINDING_MISMATCH')
    # Independently derived network family is an explicit input, never inferred
    # from certificate names, domain names or the provider's current DNS answers.
    dns = config['dns']; exact(dns, ('resolvers', 'networkIPVersion', 'resolverPort'))
    bounded(dns['resolverPort'], 1, 65535)
    if type(dns['networkIPVersion']) is not int or dns['networkIPVersion'] not in (4, 6):
        raise RuntimePlanDenied('NETWORK_FAMILY_REQUIRED')
    if listener.version != dns['networkIPVersion']:
        raise RuntimePlanDenied('LISTENER_NETWORK_FAMILY_MISMATCH')
    if not isinstance(dns['resolvers'], list) or not 1 <= len(dns['resolvers']) <= 8:
        raise RuntimePlanDenied('RESOLVER_BINDING_REQUIRED')
    addresses = []
    for value in dns['resolvers']:
        if not isinstance(value, str) or '%' in value:
            raise RuntimePlanDenied('EXACT_RESOLVER_IP_REQUIRED')
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            raise RuntimePlanDenied('EXACT_RESOLVER_IP_REQUIRED') from None
        if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local or ip.is_reserved:
            raise RuntimePlanDenied('UNUSABLE_RESOLVER_IP')
        addresses.append(ip)
    if len(set(addresses)) != len(addresses):
        raise RuntimePlanDenied('DUPLICATE_RESOLVER_IP')
    selected = [str(v) for v in addresses if v.version == dns['networkIPVersion']]
    deferred = [str(v) for v in addresses if v.version != dns['networkIPVersion']]
    if not selected:
        raise RuntimePlanDenied('COMPATIBLE_RESOLVER_REQUIRED')
    result = {'schema': 'ouf.semantic-provider-runtime-plan.v1',
        'adapterConfiguration': copy.deepcopy(adapter), 'southboundRoutes': routes,
        'tlsIdentities': copy.deepcopy(identities),
        'dnsBinding': {'networkIPVersion': dns['networkIPVersion'], 'selectedResolvers': selected,
                       'deferredResolvers': deferred,
                       'transportPorts': {'udp': dns['resolverPort'], 'tcp': dns['resolverPort']},
                       'connectivityProven': False, 'forwardingPathProven': False},
        'installationGates': ['TRUST_RECEIPT_AND_LEAF_MOUNTS', 'DEDICATED_SOUTHBOUND_TLS_LISTENER',
            'JAVA_CLIENT_TRUSTSTORE', 'ISOLATED_NETWORK_AND_KERNEL_READBACK',
            'DNS_ALL_ANSWER_TTL_AND_FAIL_CLOSED_REFRESH', 'DOCKER_DNS_FORWARDING_BOUNDARY',
            'PROVIDER_GOVERNANCE_AND_WORKLOAD_ADMISSION', 'RESTART_RENEWAL_AND_PRODUCTION_BYPASS'],
        'installed': False, 'providerCalls': 0, 'notReleaseAcceptance': True}
    if len(json.dumps(result).encode()) > 131072 or len(json.dumps(adapter).encode()) > 32768:
        raise RuntimePlanDenied('CONFIGURATION_TOO_LARGE')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--configuration', required=True)
    args = parser.parse_args()
    try:
        with Path(args.configuration).open('rb') as stream:
            raw = stream.read(65537)
        if len(raw) > 65536:
            raise RuntimePlanDenied('CONFIGURATION_TOO_LARGE')
        def unique(pairs):
            value = {}
            for key, item in pairs:
                if key in value:
                    raise RuntimePlanDenied('DUPLICATE_CONFIGURATION_KEY')
                value[key] = item
            return value
        result = compile_plan(json.loads(raw, object_pairs_hook=unique))
        print(json.dumps(result, sort_keys=True))
    except Exception:
        print('SEMANTIC_PROVIDER_RUNTIME_PLAN=BLOCKED NO_INSTALLATION=true NO_SECRETS_PRINTED=true')
        raise SystemExit(1) from None


if __name__ == '__main__':
    main()
