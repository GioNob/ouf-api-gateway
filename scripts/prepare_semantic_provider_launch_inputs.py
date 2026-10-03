#!/usr/bin/env python3
"""Verify private mount inputs and prepare a minimal southbound env-file, without runtime changes."""
import argparse
import hashlib
import hmac
import os
from pathlib import Path
import re
import ssl
import stat
from scripts import inventory_semantic_provider_candidate_inputs as inputs
from scripts import prepare_semantic_southbound_validator_credentials as validator


def private_read(path, uid, gid, limit=131072):
    inputs.file_metadata(path, uid, gid, 0o600, limit=limit)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        raw = os.read(fd, limit + 1)
    finally:
        os.close(fd)
    if len(raw) > limit:
        raise inputs.Blocked('PRIVATE_INPUT_TOO_LARGE')
    return raw


def inspect_inputs(args):
    # Reuse the exact source cohort sealed by the existing validator receipt.
    checked = argparse.Namespace(**vars(args))
    checked.mode = 'verify'
    checked.source_commit = args.validator_source_commit
    credential_intent = validator.operate(checked)
    trust, trust_hash = inputs.private_json(args.trust_root / 'trust-receipt.json')
    tls, tls_hash = inputs.private_json(args.tls_root / 'tls-runtime-receipt.json')
    binding, binding_hash = inputs.private_json(args.runtime_root / 'binding.json')
    role = trust['intent']['gateway']
    artifact_hashes = {}
    macs = []
    for name, uid, gid in (
        ('adapter', trust['intent']['adapterUid'], trust['intent']['adapterGid']),
        ('southbound', role['uid'], role['gid']),
    ):
        for filename in ('server.crt', 'server.key', 'provider-receipt.key'):
            key = name + '/' + filename
            raw = private_read(args.trust_root / key, uid, gid, limit=65536)
            value = validator.digest(raw)
            if value != trust['artifactHashes'][key] or value != tls['intent']['runtimeTrustHashes'][key]:
                raise inputs.Blocked('PRIVATE_TRUST_CONTENT_DRIFT')
            artifact_hashes[key] = value
            if filename == 'provider-receipt.key':
                macs.append(raw)
        # Local SSL parses the leaf and private key and checks their public-key match.
        # It opens no listener and never reads the offline CA private key.
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(args.trust_root / name / 'server.crt', args.trust_root / name / 'server.key')
        except (ssl.SSLError, OSError):
            raise inputs.Blocked('LEAF_PRIVATE_KEY_PAIR_INVALID') from None
    if not re.fullmatch(b'[0-9a-f]{64}', macs[0]) or not hmac.compare_digest(*macs):
        raise inputs.Blocked('PROVIDER_RECEIPT_KEY_PAIR_INVALID')
    for name in ('config.yaml', 'apisix.yaml'):
        raw = private_read(args.tls_root / name, role['uid'], role['gid'])
        if validator.digest(raw) != tls['outputHashes'][name]:
            raise inputs.Blocked('PRIVATE_TLS_RUNTIME_CONTENT_DRIFT')
        artifact_hashes[name] = validator.digest(raw)
    routes = binding['routes']
    match = re.fullmatch(r'\$ENV://([A-Z][A-Z0-9_]{0,127})', routes['oidcSecretRef'])
    mac_name = routes['receiptKeyEnvironment']
    if not match or not re.fullmatch(r'[A-Z][A-Z0-9_]{0,127}', mac_name):
        raise inputs.Blocked('SECRET_ENVIRONMENT_BINDING_INVALID')
    oidc_name = match[1]
    if oidc_name == mac_name or any(name in ('PATH', 'HOME', 'LD_PRELOAD', 'PYTHONPATH') for name in (oidc_name, mac_name)):
        raise inputs.Blocked('SECRET_ENVIRONMENT_BINDING_INVALID')
    if credential_intent['clientProfile']['clientId'] != routes['audience']:
        raise inputs.Blocked('VALIDATOR_ROUTE_CLIENT_DRIFT')
    secret = validator.local_secret(args.credential_root / 'client-secret', role['uid'], role['gid'])
    env = oidc_name.encode() + b'=' + secret + b'\n' + mac_name.encode() + b'=' + macs[1] + b'\n'
    receipt, receipt_hash = inputs.private_json(args.credential_root / 'credential-receipt.json')
    sources = {p.name: validator.digest(p.read_bytes()) for p in (Path(__file__), Path(inputs.__file__), Path(validator.__file__))}
    intent = {
        'schema': 'ouf.semantic-provider-launch-inputs.v1', 'sourceCommit': args.source_commit,
        'validatorSourceCommit': args.validator_source_commit, 'sourceHashes': sources,
        'trustReceiptHash': trust_hash, 'tlsReceiptHash': tls_hash, 'bindingHash': binding_hash,
        'credentialReceiptHash': receipt_hash, 'privateArtifactHashes': artifact_hashes,
        'environmentNames': [oidc_name, mac_name], 'environmentHash': validator.digest(env),
        'leafKeyPairsVerified': True, 'receiptKeyPairVerified': True, 'offlineCaKeyRead': False,
        'containersCreated': 0, 'mountsInstalled': False, 'providerCalls': 0, 'notReleaseAcceptance': True,
    }
    return intent, env


def operate(args):
    if os.geteuid() != 0:
        raise inputs.Blocked('ROOT_REQUIRED')
    for value in (args.source_commit, args.validator_source_commit):
        if not re.fullmatch('[0-9a-f]{40}', value):
            raise inputs.Blocked('SOURCE_BINDING_INVALID')
    validator.directory(args.snapshot_root.parent)
    if args.mode != 'verify' and os.path.lexists(args.snapshot_root):
        raise inputs.Blocked('LAUNCH_INPUT_ROOT_EXISTS_RECONCILE')
    intent, env = inspect_inputs(args)
    if args.mode == 'plan':
        return intent
    if args.mode == 'verify':
        validator.directory(args.snapshot_root)
        if stat.S_IMODE(args.snapshot_root.stat().st_mode) != 0o700:
            raise inputs.Blocked('PRIVATE_ROOT_INVALID')
        saved, _ = inputs.private_json(args.snapshot_root / 'launch-input-receipt.json')
        if saved != intent or not hmac.compare_digest(private_read(args.snapshot_root / 'southbound.env', 0, 0, 4096), env):
            raise inputs.Blocked('LAUNCH_INPUT_CONTENT_DRIFT_NO_OVERWRITE')
        return intent
    args.snapshot_root.mkdir(mode=0o700)
    validator.write(args.snapshot_root / 'southbound.env', env)
    if not hmac.compare_digest(private_read(args.snapshot_root / 'southbound.env', 0, 0, 4096), env):
        raise inputs.Blocked('ENVIRONMENT_PRIVATE_READBACK_FAILED')
    if inspect_inputs(args)[0] != intent:
        raise inputs.Blocked('LAUNCH_INPUT_CHANGED_DURING_PREPARE')
    validator.write(args.snapshot_root / 'launch-input-receipt.json', validator.encoded(intent))
    return intent


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--mode', required=True, choices=('plan', 'apply', 'verify'))
    for name in ('tls-root', 'trust-root', 'runtime-root', 'credential-root', 'snapshot-root'):
        p.add_argument('--' + name, type=Path, required=True)
    for name in ('gateway-container', 'iam-container', 'realm', 'docker-path', 'openssl-path', 'kcadm-path', 'source-commit', 'validator-source-commit'):
        p.add_argument('--' + name, required=True)
    p.add_argument('--minimum-cert-seconds', type=int, required=True)
    args = p.parse_args()
    try:
        if not 1 <= args.minimum_cert_seconds <= 86400:
            raise inputs.Blocked('CERTIFICATE_WINDOW_INVALID')
        operate(args)
        print('SEMANTIC_PROVIDER_LAUNCH_INPUTS=PASS MODE=' + args.mode +
              ' LEAF_KEY_PAIRS_VERIFIED=true RECEIPT_KEY_PAIR_VERIFIED=true OFFLINE_CA_KEY_READ=false'+
              ' PRIVATE_ENV_FILE_CREATED=' + str(args.mode == 'apply').lower() +
              ' NO_CONTAINER_OR_MOUNT_CHANGED=true NO_NETWORK_OR_RULE_CHANGED=true NO_ROUTE_OR_IAM_WRITES=true'+
              ' NO_TOKEN_GRANT_REQUEST=true NO_PROVIDER_CALL=true NOT_RELEASE_ACCEPTANCE=true NO_SECRETS_PRINTED=true')
        if args.mode != 'plan':
            print('SEMANTIC_PROVIDER_LAUNCH_INPUT_RECEIPT=' + str(args.snapshot_root / 'launch-input-receipt.json') + ' PRIVATE=true')
    except Exception as error:
        code = str(error) if isinstance(error, inputs.Blocked) else 'LAUNCH_INPUT_PREPARATION_FAILED'
        print('SEMANTIC_PROVIDER_LAUNCH_INPUTS=BLOCKED CODE=' + code + ' DO_NOT_RERUN_BLINDLY=true NO_SECRETS_PRINTED=true')
        raise SystemExit(1) from None

if __name__ == '__main__':
    main()
