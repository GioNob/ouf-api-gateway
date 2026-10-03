#!/usr/bin/env python3
"""Privately prepare TLS startup files from existing artifacts; no runtime start."""
import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import ssl
from types import SimpleNamespace

from scripts import prepare_semantic_provider_trust as trust
from tools.materialize_semantic_provider_runtime import compile_plan
from tools.materialize_semantic_provider_tls import materialize_tls


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def private_json(path):
    trust.ancestors(path.parent)
    raw = trust.read_file(path, 0, 0, limit=131072)
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise trust.Blocked('DUPLICATE_INPUT_KEY')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=unique), raw


def inspect_inputs(args):
    for root in (args.stage_root, args.trust_root):
        trust.ancestors(root)
    stage, stage_raw = private_json(args.stage_root/'stage-receipt.json')
    binding, binding_raw = private_json(args.stage_root/'binding.json')
    saved_plan, plan_raw = private_json(args.stage_root/'runtime-plan.json')
    if stage.get('bindingHash') != digest(binding_raw) or stage.get('planHash') != digest(plan_raw) \
            or stage.get('trustReceiptReference') != str(args.trust_root/'trust-receipt.json') \
            or stage.get('notReleaseAcceptance') is not True or stage.get('runtimeFilesMounted') is not False:
        raise trust.Blocked('STAGED_CONFIGURATION_DRIFT')
    # The original eight compiler/native files must match the prior staged plan.
    source = Path(__file__).resolve().parents[1]
    names = ('tools/materialize_semantic_provider_runtime.py', 'tools/materialize_semantic_provider.py',
             'tools/semantic_provider_adapter.py', 'tools/semantic_provider_admission.py',
             'tools/semantic_provider_relay.py', 'tools/semantic_provider_boundary.py',
             'tools/southbound_security.py', 'tools/lua/admit_semantic_provider.lua')
    if set(stage.get('sourceHashes', {})) != set(names):
        raise trust.Blocked('STAGED_SOURCE_BINDING_MISSING')
    for name in names:
        if digest((source/name).read_bytes()) != stage['sourceHashes'][name]:
            raise trust.Blocked('STAGED_COMPILER_SOURCE_DRIFT')
    if compile_plan(binding) != saved_plan:
        raise trust.Blocked('STAGED_PLAN_CONTRACT_DRIFT')
    receipt, receipt_raw = private_json(args.trust_root/'trust-receipt.json')
    intent = receipt['intent']
    if receipt.get('verified') is not True or receipt.get('notReleaseAcceptance') is not True \
            or receipt.get('mountsInstalled') is not False:
        raise trust.Blocked('VERIFIED_UNMOUNTED_TRUST_REQUIRED')
    identities = binding['tlsIdentities']
    if binding['adapter']['admission']['installation'] != intent['installation'] \
            or identities['adapterHostname'] != intent['adapterHostname'] \
            or identities['southboundHostname'] != intent['southboundHostname']:
        raise trust.Blocked('TRUST_CONFIGURATION_BINDING_MISMATCH')
    image_args = SimpleNamespace(docker_path=args.docker_path, adapter_image_id=args.adapter_image_id,
        adapter_source_commit=args.adapter_source_commit, adapter_uid=intent['adapterUid'], adapter_gid=intent['adapterGid'])
    gateway = trust.gateway(args)
    image = trust.image(image_args)
    if gateway != intent['gateway'] or image != intent['adapterImage']:
        raise trust.Blocked('CURRENT_ROLE_OR_IMAGE_DRIFT')
    hashes = {}; artifacts = {}
    for name in ('ca.crt', 'trust-bundle.pem'):
        raw = trust.read_file(args.trust_root/name, 0, 0, private=False)
        if b'PRIVATE KEY' in raw:
            raise trust.Blocked('PRIVATE_KEY_IN_PUBLIC_TRUST')
        hashes[name] = digest(raw)
    for role, uid, gid, hostname in (
            ('adapter', intent['adapterUid'], intent['adapterGid'], intent['adapterHostname']),
            ('southbound', gateway['uid'], gateway['gid'], intent['southboundHostname'])):
        trust.ancestors(args.trust_root/role)
        for filename in ('server.crt', 'server.key', 'provider-receipt.key'):
            name = role+'/'+filename
            artifacts[name] = trust.read_file(args.trust_root/name, uid, gid, limit=65536)
            hashes[name] = digest(artifacts[name])
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(args.trust_root/role/'server.crt', args.trust_root/role/'server.key')
        trust.run([args.openssl_path, 'verify', '-CAfile', str(args.trust_root/'ca.crt'), '-purpose', 'sslserver',
            '-verify_hostname', hostname, str(args.trust_root/role/'server.crt')])
    if any(receipt['artifactHashes'].get(name) != value for name, value in hashes.items()):
        raise trust.Blocked('EXISTING_RUNTIME_TRUST_ARTIFACT_DRIFT')
    key = artifacts['adapter/provider-receipt.key']
    if not re.fullmatch(b'[0-9a-f]{64}', key) or not hmac.compare_digest(key, artifacts['southbound/provider-receipt.key']):
        raise trust.Blocked('EXISTING_RECEIPT_PAIR_DRIFT')
    # Offline ca.key is deliberately not opened or copied.
    bootstrap = materialize_tls(binding['routes'], {'listenAddress': args.listen_address,
        'listenPort': args.listen_port, 'serverHostname': intent['southboundHostname'],
        'sslResourceId': args.ssl_resource_id},
        certificate_pem=artifacts['southbound/server.crt'].decode('ascii'),
        private_key_pem=artifacts['southbound/server.key'].decode('ascii'))
    desired = {'stageReceiptHash': digest(stage_raw), 'trustReceiptHash': digest(receipt_raw),
        'runtimeTrustHashes': hashes, 'gateway': gateway, 'adapterImage': image,
        'adapterUid': intent['adapterUid'], 'adapterGid': intent['adapterGid'],
        'listener': {'address': args.listen_address, 'port': args.listen_port,
                     'hostname': intent['southboundHostname'], 'sslResourceId': args.ssl_resource_id}}
    return binding, bootstrap, desired


def output_files(binding, bootstrap, desired):
    # JSON is YAML syntax; APISIX's native YAML provider consumes it. #END is
    # required for the watched resource file, which embeds the existing leaf key.
    return {
        'config.yaml': (json.dumps(bootstrap['runtimeConfiguration'], sort_keys=True).encode()+b'\n',
                        desired['gateway']['uid'], desired['gateway']['gid']),
        'apisix.yaml': (json.dumps(bootstrap['resources'], sort_keys=True).encode()+b'\n#END\n',
                        desired['gateway']['uid'], desired['gateway']['gid']),
        'adapter.json': (json.dumps(binding['adapter'], sort_keys=True).encode()+b'\n',
                         desired['adapterUid'], desired['adapterGid'])}


def operate(args):
    if os.geteuid() != 0:
        raise trust.Blocked('ROOT_REQUIRED')
    if not re.fullmatch('[a-f0-9]{64}', args.expected_gateway_id) \
            or not re.fullmatch('sha256:[a-f0-9]{64}', args.adapter_image_id) \
            or not re.fullmatch('[a-f0-9]{40}', args.adapter_source_commit) \
            or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', args.gateway_container):
        raise trust.Blocked('IMMUTABLE_ROLE_BINDINGS_REQUIRED')
    for path in (args.stage_root, args.trust_root, args.snapshot_root):
        if not path.is_absolute() or '..' in path.parts:
            raise trust.Blocked('ABSOLUTE_SAFE_PATH_REQUIRED')
    trust.ancestors(args.snapshot_root.parent)
    binding, bootstrap, desired = inspect_inputs(args)
    files = output_files(binding, bootstrap, desired)
    if args.mode == 'verify':
        trust.ancestors(args.snapshot_root)
        saved, _ = private_json(args.snapshot_root/'tls-runtime-receipt.json')
        if saved.get('intent') != desired:
            raise trust.Blocked('TLS_RUNTIME_BINDING_DRIFT')
        for name, (raw, uid, gid) in files.items():
            current = trust.read_file(args.snapshot_root/name, uid, gid, limit=131072)
            if current != raw or saved.get('outputHashes', {}).get(name) != digest(current):
                raise trust.Blocked('TLS_RUNTIME_FILE_DRIFT')
        return desired
    if args.snapshot_root.exists() or args.snapshot_root.is_symlink():
        raise trust.Blocked('TLS_RUNTIME_ROOT_EXISTS_RECONCILE')
    if args.mode == 'plan':
        return desired
    args.snapshot_root.mkdir(mode=0o700)
    trust.write(args.snapshot_root/'tls-runtime-intent.json', json.dumps(desired, sort_keys=True).encode())
    hashes = {}
    for name, (raw, uid, gid) in files.items():
        trust.write(args.snapshot_root/name, raw, uid, gid)
        if trust.read_file(args.snapshot_root/name, uid, gid, limit=131072) != raw:
            raise trust.Blocked('TLS_RUNTIME_READBACK_DRIFT')
        hashes[name] = digest(raw)
    if inspect_inputs(args)[2] != desired:
        raise trust.Blocked('TLS_RUNTIME_INPUT_CHANGED_DURING_PREPARE')
    saved = {'intent': desired, 'outputHashes': hashes, 'trustArtifactsRevalidated': True,
        'liveRoleMetadataRevalidated': True, 'containsPrivateKey': True,
        'containersCreated': 0, 'mountsInstalled': False, 'providerCalls': 0, 'notReleaseAcceptance': True}
    trust.write(args.snapshot_root/'tls-runtime-receipt.json', json.dumps(saved, sort_keys=True).encode())
    return desired


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', required=True, choices=('plan', 'apply', 'verify'))
    for name in ('stage-root', 'trust-root', 'snapshot-root'):
        parser.add_argument('--'+name, type=Path, required=True)
    for name in ('gateway-container', 'expected-gateway-id', 'adapter-image-id', 'adapter-source-commit',
                 'listen-address', 'ssl-resource-id'):
        parser.add_argument('--'+name, required=True)
    parser.add_argument('--listen-port', type=int, required=True)
    parser.add_argument('--docker-path', default='docker'); parser.add_argument('--openssl-path', default='openssl')
    args = parser.parse_args(argv)
    try:
        desired = operate(args)
        print('SEMANTIC_PROVIDER_TLS_RUNTIME='+json.dumps({'mode': args.mode, 'created': args.mode=='apply',
            'gatewayUid': desired['gateway']['uid'], 'gatewayGid': desired['gateway']['gid'],
            'listenerPort': desired['listener']['port'], 'containsPrivateKey': True, 'noSecretsPrinted': True}, sort_keys=True))
        print('SEMANTIC_PROVIDER_TLS_RUNTIME_PREPARE=PASS NO_CONTAINERS_CREATED=true NO_MOUNTS_INSTALLED=true '
            'NO_NETWORK_OR_RULE_CHANGED=true NO_ROUTE_OR_IAM_WRITES=true NO_POLICY_PUBLICATION=true '
            'NO_PROVIDER_CALL=true NOT_RELEASE_ACCEPTANCE=true NO_SECRETS_PRINTED=true')
        if args.mode != 'plan':
            print('SEMANTIC_PROVIDER_TLS_RUNTIME_RECEIPT='+str(args.snapshot_root/'tls-runtime-receipt.json')+' PRIVATE=true')
    except Exception as error:
        code = str(error) if isinstance(error, trust.Blocked) and re.fullmatch('[A-Z_]{1,100}', str(error)) else 'TLS_RUNTIME_PREPARATION_FAILED'
        print('SEMANTIC_PROVIDER_TLS_RUNTIME_PREPARE=BLOCKED CODE='+code+' DO_NOT_RERUN_BLINDLY=true NO_SECRETS_PRINTED=true')
        raise SystemExit(1) from None


if __name__ == '__main__': main()
