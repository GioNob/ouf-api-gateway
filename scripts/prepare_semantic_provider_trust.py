#!/usr/bin/env python3
"""Prepare private TLS/receipt artifacts only; never mount or activate them."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import stat
import subprocess


class Blocked(RuntimeError):
    pass


def run(command, *, allow_failure=False):
    value = subprocess.run(command, capture_output=True, text=True, timeout=30)
    if value.returncode and not allow_failure:
        raise Blocked('LOCAL_COMMAND_FAILED')
    return value


def ancestors(path):
    for item in (path, *path.parents):
        info = item.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
            raise Blocked('ROOT_ANCESTOR_UNSAFE')


def read_file(path, uid, gid=None, private=True, limit=1048576):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != uid \
                or (gid is not None and info.st_gid != gid) or info.st_size > limit \
                or stat.S_IMODE(info.st_mode) & (0o077 if private else 0o022):
            raise Blocked('ARTIFACT_OWNER_OR_MODE_UNSAFE')
        raw = os.read(fd, limit+1)
        if len(raw) > limit: raise Blocked('ARTIFACT_SIZE_UNSAFE')
        return raw
    finally:
        os.close(fd)


def write(path, raw, uid=0, gid=0):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600); os.fchown(fd, uid, gid)
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    finally:
        os.close(fd)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def gateway(args):
    # Select only non-secret scalar metadata; no env, mounts or command read.
    template = '{"id":{{json .Id}},"image":{{json .Image}},"user":{{json .Config.User}},"running":{{json .State.Running}}}'
    value = json.loads(run([args.docker_path, 'inspect', '--type', 'container', '--format', template, args.gateway_container]).stdout)
    if value['id'] != args.expected_gateway_id or value['running'] is not True:
        raise Blocked('GATEWAY_ID_OR_RUNNING_MISMATCH')
    for field, option in (('uid', '-u'), ('gid', '-g')):
        raw = run([args.docker_path, 'exec', args.gateway_container, 'id', option]).stdout.strip()
        if not re.fullmatch(r'[1-9][0-9]{0,9}', raw) or int(raw) > 2147483647:
            raise Blocked('NON_ROOT_GATEWAY_RUNTIME_REQUIRED')
        value[field] = int(raw)
    return value


def image(args):
    raw = json.loads(run([args.docker_path, 'image', 'inspect', args.adapter_image_id]).stdout)
    if not isinstance(raw, list) or len(raw) != 1: raise Blocked('ADAPTER_IMAGE_UNPROVEN')
    value = raw[0]; config = value['Config']; labels = config.get('Labels') or {}
    if value['Id'] != args.adapter_image_id or config.get('User') != f'{args.adapter_uid}:{args.adapter_gid}' \
            or config.get('Entrypoint') != ['python3', '-B', '-m', 'tools.semantic_provider_adapter'] \
            or labels.get('org.opencontainers.image.revision') != args.adapter_source_commit \
            or labels.get('ouf.component') != 'semantic-provider-transport' \
            or not re.fullmatch(r'[0-9a-f]{64}', labels.get('ouf.payload.sha256', '')):
        raise Blocked('ADAPTER_IMAGE_CONTRACT_MISMATCH')
    return {'id': value['Id'], 'sourceCommit': args.adapter_source_commit,
            'runtimeUser': config['User'], 'payloadHash': labels.get('ouf.payload.sha256')}


def validate(args):
    if os.geteuid() != 0: raise Blocked('ROOT_REQUIRED')
    if not re.fullmatch(r'[0-9a-f]{64}', args.expected_gateway_id) \
            or not re.fullmatch(r'sha256:[0-9a-f]{64}', args.adapter_image_id) \
            or not re.fullmatch(r'[0-9a-f]{40}', args.adapter_source_commit) \
            or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', args.gateway_container):
        raise Blocked('IMMUTABLE_ROLE_BINDINGS_REQUIRED')
    for value in (args.adapter_uid, args.adapter_gid):
        if not 1 <= value <= 2147483647: raise Blocked('NON_ROOT_ADAPTER_IDS_REQUIRED')
    for host in (args.adapter_hostname, args.southbound_hostname):
        if len(host) > 253 or any(not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label) for label in host.split('.')):
            raise Blocked('EXPLICIT_SAFE_DNS_HOSTNAME_REQUIRED')
    if args.adapter_hostname.lower() == args.southbound_hostname.lower():
        raise Blocked('DISTINCT_ROLE_HOSTNAMES_REQUIRED')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', args.installation_id):
        raise Blocked('INSTALLATION_BINDING_REQUIRED')
    if not 1 <= args.server_validity_days <= 365 or not args.server_validity_days < args.ca_validity_days <= 3650:
        raise Blocked('BOUNDED_CERTIFICATE_VALIDITY_REQUIRED')
    for path in (args.snapshot_root, args.public_ca_file):
        if not path.is_absolute() or '..' in path.parts: raise Blocked('ABSOLUTE_SAFE_PATH_REQUIRED')
        ancestors(path.parent)
    # A caller-selected public CA input must never contain a private key.
    public = read_file(args.public_ca_file, 0, private=False)
    if b'PRIVATE KEY' in public: raise Blocked('PUBLIC_CA_INPUT_CONTAINS_PRIVATE_KEY')
    ssl.create_default_context(cadata=public.decode('ascii'))
    run([args.openssl_path, 'version'])
    return public


def desired(args, public):
    return {'installation': args.installation_id, 'gateway': gateway(args), 'adapterImage': image(args),
            'adapterHostname': args.adapter_hostname, 'southboundHostname': args.southbound_hostname,
            'adapterUid': args.adapter_uid, 'adapterGid': args.adapter_gid,
            'caValidityDays': args.ca_validity_days, 'serverValidityDays': args.server_validity_days,
            'publicCaFile': str(args.public_ca_file), 'publicCaHash': digest(public)}


def openssl(args, *options, allow_failure=False):
    return run([args.openssl_path, *map(str, options)], allow_failure=allow_failure)


def verify_artifacts(args, intent):
    root = args.snapshot_root; hashes = {}
    for directory in (root, root/'adapter', root/'southbound'):
        ancestors(directory)
    files = [('ca.key', 0, 0, True), ('ca.crt', 0, 0, False), ('trust-bundle.pem', 0, 0, False)]
    for role, uid, gid in [('adapter', args.adapter_uid, args.adapter_gid),
                           ('southbound', intent['gateway']['uid'], intent['gateway']['gid'])]:
        for filename in ('server.key', 'server.crt', 'provider-receipt.key'):
            files.append((role+'/'+filename, uid, gid, True))
    for filename, uid, gid, private in files:
        hashes[filename] = digest(read_file(root/filename, uid, gid, private=private))
    keys = [read_file(root/role/'provider-receipt.key', uid, gid) for role, uid, gid in
            [('adapter', args.adapter_uid, args.adapter_gid), ('southbound', intent['gateway']['uid'], intent['gateway']['gid'])]]
    if keys[0] != keys[1] or not re.fullmatch(b'[0-9a-f]{64}', keys[0]):
        raise Blocked('PURPOSE_RECEIPT_KEY_PAIR_INVALID')
    for role, hostname in [('adapter', args.adapter_hostname), ('southbound', args.southbound_hostname)]:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(root/role/'server.crt', root/role/'server.key')
        openssl(args, 'verify', '-CAfile', root/'ca.crt', '-purpose', 'sslserver', '-verify_hostname', hostname, root/role/'server.crt')
        bad = openssl(args, 'verify', '-CAfile', root/'ca.crt', '-verify_hostname', 'wrong-'+secrets.token_hex(8)+'.invalid', root/role/'server.crt', allow_failure=True)
        if bad.returncode == 0: raise Blocked('WRONG_HOSTNAME_NOT_DENIED')
    return hashes


def operate(args):
    public = validate(args); intent = desired(args, public); root = args.snapshot_root
    if args.mode == 'verify':
        ancestors(root)
        saved = json.loads(read_file(root/'trust-receipt.json', 0, 0))
        if saved.get('intent') != intent: raise Blocked('TRUST_BINDING_OR_ROLE_DRIFT')
        if verify_artifacts(args, intent) != saved.get('artifactHashes'): raise Blocked('TRUST_ARTIFACT_DRIFT')
        return saved
    if root.exists() or root.is_symlink(): raise Blocked('TRUST_ROOT_EXISTS_RECONCILE')
    if args.mode == 'plan': return {'intent': intent, 'created': False, 'verified': False}
    root.mkdir(mode=0o700)
    write(root/'trust-intent.json', json.dumps(intent, sort_keys=True).encode())
    # OpenSSL writes only inside this exclusive new root, under private umask.
    prior = os.umask(0o077)
    try:
        cn = 'OUF-provider-CA-'+digest(args.installation_id.encode())[:16]
        openssl(args, 'req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
                '-keyout', root/'ca.key', '-x509', '-sha256', '-days', args.ca_validity_days,
                '-subj', '/CN='+cn, '-out', root/'ca.crt',
                '-addext', 'basicConstraints=critical,CA:TRUE,pathlen:0', '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
        for filename in ('ca.key', 'ca.crt'):
            os.chmod(root/filename, 0o600 if filename == 'ca.key' else 0o644); os.chown(root/filename, 0, 0)
        key = secrets.token_hex(32).encode('ascii')
        for role, hostname, uid, gid in [('adapter', args.adapter_hostname, args.adapter_uid, args.adapter_gid),
                ('southbound', args.southbound_hostname, intent['gateway']['uid'], intent['gateway']['gid'])]:
            directory = root/role; directory.mkdir(mode=0o700)
            openssl(args, 'req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
                    '-keyout', directory/'server.key', '-out', directory/'server.csr', '-subj', '/CN='+hostname)
            write(directory/'extensions.cnf', ('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n'
                'extendedKeyUsage=serverAuth\nsubjectAltName=DNS:'+hostname+'\n').encode())
            openssl(args, 'x509', '-req', '-in', directory/'server.csr', '-CA', root/'ca.crt', '-CAkey', root/'ca.key',
                    '-set_serial', secrets.randbits(128)+1, '-sha256', '-days', args.server_validity_days,
                    '-extfile', directory/'extensions.cnf', '-out', directory/'server.crt')
            for filename in ('server.key', 'server.crt'):
                os.chmod(directory/filename, 0o600); os.chown(directory/filename, uid, gid)
            write(directory/'provider-receipt.key', key, uid, gid)
        write(root/'trust-bundle.pem', public.rstrip()+b'\n'+read_file(root/'ca.crt', 0, 0, private=False))
        os.chmod(root/'trust-bundle.pem', 0o644)
    finally:
        os.umask(prior)
    hashes = verify_artifacts(args, intent)
    if desired(args, validate(args)) != intent: raise Blocked('ROLE_OR_CA_INPUT_CHANGED_DURING_PREPARE')
    saved = {'intent': intent, 'artifactHashes': hashes, 'created': True, 'verified': True,
             'notReleaseAcceptance': True, 'mountsInstalled': False}
    write(root/'trust-receipt.json', json.dumps(saved, sort_keys=True).encode())
    return saved


def parser():
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument('--mode', choices=('plan', 'apply', 'verify'), required=True)
    value.add_argument('--docker-path', default='docker'); value.add_argument('--openssl-path', default='openssl')
    for arg in ('gateway-container', 'expected-gateway-id', 'adapter-image-id', 'adapter-source-commit',
                'adapter-hostname', 'southbound-hostname', 'installation-id'):
        value.add_argument('--'+arg, required=True)
    for arg in ('adapter-uid', 'adapter-gid', 'ca-validity-days', 'server-validity-days'):
        value.add_argument('--'+arg, required=True, type=int)
    for arg in ('public-ca-file', 'snapshot-root'):
        value.add_argument('--'+arg, required=True, type=Path)
    return value


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        saved = operate(args)
        print('SEMANTIC_PROVIDER_TRUST='+json.dumps({'mode': args.mode, 'created': args.mode=='apply',
            'verified': saved['verified'], 'adapterHostname': args.adapter_hostname,
            'southboundHostname': args.southbound_hostname, 'gatewayUid': saved['intent']['gateway']['uid'],
            'gatewayGid': saved['intent']['gateway']['gid'], 'noSecretsPrinted': True}, sort_keys=True))
        print('SEMANTIC_PROVIDER_TRUST_PREPARE=PASS NO_CONTAINER_CHANGED=true NO_IAM_WRITES=true NO_ROUTE_WRITES=true NO_POLICY_PUBLICATION=true NO_PROVIDER_CALL=true MOUNTS_NOT_INSTALLED=true NOT_RELEASE_ACCEPTANCE=true NO_SECRETS_PRINTED=true')
        if args.mode != 'plan': print('SEMANTIC_PROVIDER_TRUST_RECEIPT='+str(args.snapshot_root/'trust-receipt.json')+' PRIVATE=true')
        return 0
    except Exception as error:
        code = str(error) if isinstance(error, Blocked) else 'TRUST_PREPARE_UNPROVEN'
        print('SEMANTIC_PROVIDER_TRUST_PREPARE=BLOCKED CODE='+code+' DO_NOT_RERUN_BLINDLY=true NO_SECRETS_PRINTED=true')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
