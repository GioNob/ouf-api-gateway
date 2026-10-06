#!/usr/bin/env python3
"""Prepare public-certificate Java trust only; never start the Semantic app."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
import subprocess
import uuid

from scripts import prepare_semantic_provider_trust as trust


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def private_json(path):
    trust.ancestors(path.parent)
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result: raise trust.Blocked('DUPLICATE_INPUT_KEY')
            result[key] = value
        return result
    raw = trust.read_file(path, 0, 0, limit=131072)
    return json.loads(raw, object_pairs_hook=unique), raw


def cert_set(raw):
    if len(raw) > 2097152 or b'PRIVATE KEY' in raw or b'PrivateKeyEntry' in raw or b'SecretKeyEntry' in raw:
        raise trust.Blocked('PUBLIC_CERTIFICATE_STORE_REQUIRED')
    blocks = re.findall(br'-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\s]+)-----END CERTIFICATE-----', raw)
    if not 1 <= len(blocks) <= 1024: raise trust.Blocked('BOUNDED_CERTIFICATE_STORE_REQUIRED')
    values = {digest(base64.b64decode(re.sub(br'\s', b'', block), validate=True)) for block in blocks}
    if not values: raise trust.Blocked('EMPTY_PUBLIC_TRUST_STORE')
    return values


def semantic(args):
    template = '{"id":{{json .Id}},"image":{{json .Image}},"user":{{json .Config.User}},"running":{{json .State.Running}}}'
    value = json.loads(trust.run([args.docker_path, 'inspect', '--type', 'container', '--format', template, args.semantic_container]).stdout)
    if value['id'] != args.expected_semantic_id or value['image'] != args.semantic_image_id or value['running'] is not True:
        raise trust.Blocked('SEMANTIC_ROLE_ID_IMAGE_OR_RUNNING_DRIFT')
    for field, option in (('uid', '-u'), ('gid', '-g')):
        raw = trust.run([args.docker_path, 'exec', args.semantic_container, 'id', option]).stdout.strip()
        if not re.fullmatch('[1-9][0-9]{0,9}', raw) or int(raw) > 2147483647:
            raise trust.Blocked('NON_ROOT_SEMANTIC_RUNTIME_REQUIRED')
        value[field] = int(raw)
    template = '{"id":{{json .Id}},"revision":{{json (index .Config.Labels "org.opencontainers.image.revision")}}}'
    image = json.loads(trust.run([args.docker_path, 'image', 'inspect', '--format', template, args.semantic_image_id]).stdout)
    if image != {'id': args.semantic_image_id, 'revision': args.semantic_source_commit}:
        raise trust.Blocked('SEMANTIC_IMAGE_SOURCE_DRIFT')
    return value


def inspect_inputs(args):
    saved, raw = private_json(args.trust_root/'trust-receipt.json')
    tls, tls_raw = private_json(args.tls_runtime_root/'tls-runtime-receipt.json')
    if saved.get('verified') is not True or saved.get('notReleaseAcceptance') is not True \
            or tls.get('notReleaseAcceptance') is not True or tls.get('mountsInstalled') is not False \
            or tls.get('trustArtifactsRevalidated') is not True \
            or tls['intent']['trustReceiptHash'] != digest(raw):
        raise trust.Blocked('VERIFIED_UNMOUNTED_TLS_TRUST_BINDING_REQUIRED')
    intent = saved['intent']; hostname = intent['southboundHostname']
    if tls['intent']['listener']['hostname'] != hostname:
        raise trust.Blocked('TLS_HOSTNAME_BINDING_DRIFT')
    ca = trust.read_file(args.trust_root/'ca.crt', 0, 0, private=False, limit=65536)
    trust.ancestors(args.trust_root/'southbound')
    leaf = trust.read_file(args.trust_root/'southbound/server.crt', intent['gateway']['uid'], intent['gateway']['gid'], limit=65536)
    if len(cert_set(ca)) != 1 or len(cert_set(leaf)) != 1:
        raise trust.Blocked('EXACT_CA_AND_LEAF_REQUIRED')
    for name, artifact in [('ca.crt', ca), ('southbound/server.crt', leaf)]:
        if saved['artifactHashes'].get(name) != digest(artifact) or tls['intent']['runtimeTrustHashes'].get(name) != digest(artifact):
            raise trust.Blocked('PUBLIC_TRUST_ARTIFACT_DRIFT')
    ssl.create_default_context(cadata=ca.decode('ascii'))
    trust.run([args.openssl_path, 'verify', '-CAfile', str(args.trust_root/'ca.crt'), '-purpose', 'sslserver',
               '-verify_hostname', hostname, str(args.trust_root/'southbound/server.crt')])
    trust.run([args.openssl_path, 'x509', '-in', str(args.trust_root/'ca.crt'), '-checkend', '3600', '-noout'])
    role = semantic(args)
    return {'trustReceiptHash': digest(raw), 'tlsRuntimeReceiptHash': digest(tls_raw), 'caHash': digest(ca),
            'caCertificateHashes': sorted(cert_set(ca)), 'leafHash': digest(leaf), 'southboundHostname': hostname,
            'installation': intent['installation'], 'semantic': role, 'semanticSourceCommit': args.semantic_source_commit,
            'javaHome': args.java_home, 'runtimeTruststorePath': args.runtime_truststore_path,
            'storeType': 'PKCS12', 'publicCertificateStorePassword': 'changeit'}


# A public-only store password is an integrity-format parameter, not a credential.
# Existing JVM public roots are copied/converted; no private key is imported.
KEYTOOL_SCRIPT = '''set -eu
umask 077
"$1/bin/keytool" -list -rfc -keystore "$1/lib/security/cacerts" -storepass changeit > /out/baseline.pem
"$1/bin/keytool" -importkeystore -noprompt -srckeystore "$1/lib/security/cacerts" -srcstorepass changeit -destkeystore /out/java-truststore.p12 -deststoretype PKCS12 -deststorepass changeit >/dev/null 2>&1
"$1/bin/keytool" -importcert -noprompt -alias "$2" -file /inputs/ca.crt -keystore /out/java-truststore.p12 -storetype PKCS12 -storepass changeit >/dev/null 2>&1
"$1/bin/keytool" -list -rfc -keystore /out/java-truststore.p12 -storetype PKCS12 -storepass changeit > /out/merged.pem
'''


def create_store(args, desired):
    name = 'ouf-java-trust-prepare-'+uuid.uuid4().hex
    command = [args.docker_path, 'run', '--rm', '--pull=never', '--name', name, '--network', 'none',
        '--read-only', '--user', '0:0', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
        '--pids-limit', '64', '--memory', '256m', '--cpus', '1',
        '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=16m',
        '--mount', 'type=bind,source='+str(args.snapshot_root)+',target=/out',
        '--mount', 'type=bind,source='+str(args.trust_root/'ca.crt')+',target=/inputs/ca.crt,readonly',
        '--entrypoint', '/bin/sh', args.semantic_image_id, '-ec', KEYTOOL_SCRIPT, '--', args.java_home,
        'ouf-'+desired['installation']+'-southbound-root']
    try:
        result = subprocess.run(command, capture_output=True, timeout=120)
        if result.returncode: raise trust.Blocked('ISOLATED_KEYTOOL_PREPARATION_FAILED')
    finally:
        trust.run([args.docker_path, 'rm', '-f', name], allow_failure=True)
        remaining = trust.run([args.docker_path, 'ps', '-a', '--filter', 'name=^/'+name+'$', '--format', '{{.ID}}']).stdout.strip()
        if remaining: raise trust.Blocked('ISOLATED_KEYTOOL_CLEANUP_UNPROVEN')


def read_outputs(args, desired):
    baseline = trust.read_file(args.snapshot_root/'baseline.pem', 0, 0, limit=2097152)
    merged = trust.read_file(args.snapshot_root/'merged.pem', 0, 0, limit=2097152)
    before = cert_set(baseline); after = cert_set(merged)
    if after != before | set(desired['caCertificateHashes']) or not set(desired['caCertificateHashes']).isdisjoint(before):
        raise trust.Blocked('JAVA_PUBLIC_ROOT_PRESERVATION_UNPROVEN')
    store = trust.read_file(args.snapshot_root/'java-truststore.p12', desired['semantic']['uid'], desired['semantic']['gid'], limit=2097152)
    if not store: raise trust.Blocked('EMPTY_JAVA_TRUSTSTORE')
    return {'baselineHash': digest(baseline), 'mergedHash': digest(merged), 'truststoreHash': digest(store),
            'baselineCertificateHashes': sorted(before), 'mergedCertificateHashes': sorted(after)}


def operate(args):
    if os.geteuid() != 0: raise trust.Blocked('ROOT_REQUIRED')
    if not re.fullmatch('[a-f0-9]{64}', args.expected_semantic_id) \
            or not re.fullmatch('sha256:[a-f0-9]{64}', args.semantic_image_id) \
            or not re.fullmatch('[a-f0-9]{40}', args.semantic_source_commit) \
            or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', args.semantic_container):
        raise trust.Blocked('IMMUTABLE_SEMANTIC_BINDINGS_REQUIRED')
    for path in (args.trust_root, args.tls_runtime_root, args.snapshot_root):
        if not path.is_absolute() or '..' in path.parts or ',' in str(path): raise trust.Blocked('ABSOLUTE_SAFE_PATH_REQUIRED')
        trust.ancestors(path.parent)
    for path in (args.java_home, args.runtime_truststore_path):
        if not re.fullmatch('/[A-Za-z0-9_./-]+', path) or '..' in Path(path).parts:
            raise trust.Blocked('EXPLICIT_SAFE_JAVA_PATH_REQUIRED')
    desired = inspect_inputs(args)
    options = json.dumps({'jvmSystemProperties': {'javax.net.ssl.trustStore': args.runtime_truststore_path,
        'javax.net.ssl.trustStoreType': 'PKCS12', 'javax.net.ssl.trustStorePassword': 'changeit'},
        'containsCredentials': False, 'containsPrivateKeys': False, 'installed': False}, sort_keys=True).encode()
    if args.mode == 'verify':
        trust.ancestors(args.snapshot_root)
        saved, _ = private_json(args.snapshot_root/'java-trust-receipt.json')
        if saved.get('intent') != desired or saved.get('outputs') != read_outputs(args, desired) \
                or trust.read_file(args.snapshot_root/'java-trust-options.json', desired['semantic']['uid'], desired['semantic']['gid']) != options:
            raise trust.Blocked('JAVA_TRUSTSTORE_BINDING_OR_OUTPUT_DRIFT')
        return desired
    if args.snapshot_root.exists() or args.snapshot_root.is_symlink(): raise trust.Blocked('JAVA_TRUST_ROOT_EXISTS_RECONCILE')
    if args.mode == 'plan': return desired
    args.snapshot_root.mkdir(mode=0o700)
    trust.write(args.snapshot_root/'java-trust-intent.json', json.dumps(desired, sort_keys=True).encode())
    create_store(args, desired)
    # Validate root-owned output first; only the final store is assigned to Semantic.
    trust.read_file(args.snapshot_root/'java-truststore.p12', 0, 0, limit=2097152)
    os.chown(args.snapshot_root/'java-truststore.p12', desired['semantic']['uid'], desired['semantic']['gid'])
    output = read_outputs(args, desired)
    trust.write(args.snapshot_root/'java-trust-options.json', options, desired['semantic']['uid'], desired['semantic']['gid'])
    if inspect_inputs(args) != desired: raise trust.Blocked('JAVA_TRUST_INPUT_CHANGED_DURING_PREPARE')
    trust.write(args.snapshot_root/'java-trust-receipt.json', json.dumps({'intent': desired, 'outputs': output,
        'publicRootsPreserved': True, 'existingPrivateCaAdded': True, 'keytoolContainerCleanupProven': True,
        'runtimeContainersCreated': 0, 'mountsInstalled': False, 'providerCalls': 0,
        'containsPrivateKeys': False, 'notReleaseAcceptance': True}, sort_keys=True).encode())
    return desired


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', required=True, choices=('plan', 'apply', 'verify'))
    for name in ('trust-root', 'tls-runtime-root', 'snapshot-root'): parser.add_argument('--'+name, type=Path, required=True)
    for name in ('semantic-container', 'expected-semantic-id', 'semantic-image-id', 'semantic-source-commit',
                 'java-home', 'runtime-truststore-path'): parser.add_argument('--'+name, required=True)
    parser.add_argument('--docker-path', default='docker'); parser.add_argument('--openssl-path', default='openssl')
    args = parser.parse_args(argv)
    try:
        value = operate(args)
        print('SEMANTIC_PROVIDER_JAVA_TRUST='+json.dumps({'mode': args.mode, 'created': args.mode=='apply',
            'semanticUid': value['semantic']['uid'], 'semanticGid': value['semantic']['gid'],
            'publicRootsPreserved': args.mode!='plan', 'containsPrivateKeys': False, 'noSecretsPrinted': True}, sort_keys=True))
        print('SEMANTIC_PROVIDER_JAVA_TRUST_PREPARE=PASS LIVE_CONTAINERS_UNCHANGED=true NO_RUNTIME_CONTAINER_CREATED=true '
              'NO_MOUNTS_INSTALLED=true NO_NETWORK_OR_RULE_CHANGED=true NO_ROUTE_OR_IAM_WRITES=true '
              'NO_POLICY_PUBLICATION=true NO_PROVIDER_CALL=true NOT_RELEASE_ACCEPTANCE=true NO_SECRETS_PRINTED=true')
        if args.mode != 'plan': print('SEMANTIC_PROVIDER_JAVA_TRUST_RECEIPT='+str(args.snapshot_root/'java-trust-receipt.json')+' PRIVATE=true')
    except Exception as error:
        code = str(error) if isinstance(error, trust.Blocked) and re.fullmatch('[A-Z_]{1,100}', str(error)) else 'JAVA_TRUST_PREPARATION_FAILED'
        print('SEMANTIC_PROVIDER_JAVA_TRUST_PREPARE=BLOCKED CODE='+code+' DO_NOT_RERUN_BLINDLY=true NO_SECRETS_PRINTED=true')
        raise SystemExit(1) from None


if __name__ == '__main__': main()
